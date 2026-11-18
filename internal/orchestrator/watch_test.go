package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/report"
	"github.com/agardenat/clotr/internal/watch"
)

type followOnly struct {
	mu   sync.Mutex
	logs []string
}

func (f *followOnly) Host(string, string) (watch.Host, error) { return nil, errors.New("sans ssh") }
func (f *followOnly) Path(string) (string, error)             { return "", errors.New("sans ssh") }
func (f *followOnly) Follow(_ context.Context, _ string, _, cursor json.RawMessage) ([]string, json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.logs)
	if len(cursor) > 0 && string(cursor) != "null" {
		_ = json.Unmarshal(cursor, &n)
	}
	next, _ := json.Marshal(len(f.logs))
	return append([]string(nil), f.logs[n:]...), next, nil
}

func TestWatchPreparesCapturesThenAnalyses(t *testing.T) {
	o, tl := newOrch(t, []string{dagPlan}, nil)
	src := &followOnly{}
	ev := evidence.Open(t.TempDir(), 1)
	o.Watch = watch.New(func(string) (watch.Instance, bool) { return src, true }, ev, audit.Nop())
	o.Watch.Interval = 5 * time.Millisecond
	o.Watch.Scope([]string{"k8s_logs"}, func(string) bool { return true })
	o.Tools.Add(o.Watch.Tool())
	if _, err := o.Watch.Tool().Call(context.Background(), json.RawMessage(`{"kind":"tool","instance":"k8s","tool":"k8s_logs","args":{"pod":"api"},"why":"api"}`)); err != nil {
		t.Fatal(err)
	}
	type out struct {
		rep *Report
		err error
	}
	done := make(chan out)
	go func() {
		rep, err := o.Run(context.Background(), "suivre la connexion à l'api de k8s")
		done <- out{rep, err}
	}()
	for !o.Watch.Waiting() {
		time.Sleep(5 * time.Millisecond)
	}
	src.mu.Lock()
	src.logs = append(src.logs, "401 Unauthorized user=bob")
	src.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if !o.Interrupt() {
		t.Fatal("pendant l'attente, Ctrl-C doit arrêter la capture et réarmer")
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	ids := []string{}
	for _, res := range r.rep.Results {
		ids = append(ids, res.TaskID)
	}
	if !slices.Equal(ids[:2], []string{watchPrepID, watch.TaskID}) || len(ids) != 6 {
		t.Fatalf("résultats : %v", ids)
	}
	capt := r.rep.Results[1]
	if capt.Status != "ok" || !strings.Contains(strings.Join(capt.Findings, "\n"), "1 lignes captées") || !strings.Contains(strings.Join(capt.Findings, "\n"), "[E001]") {
		t.Fatalf("capture : %+v", capt)
	}
	if !strings.Contains(tl.input[watchPrepID], "Préparation d'un suivi en direct") {
		t.Fatalf("objectif de la préparation : %q", tl.input[watchPrepID])
	}
	if in := tl.input["planner"]; !strings.Contains(in, "Suivi en direct : l'action décrite") || !strings.Contains(in, "Résultat de la capture") {
		t.Fatalf("entrée du planner : %q", in)
	}
	for _, id := range []string{"t1", "t4"} {
		if !strings.Contains(tl.input[id], "lignes captées") {
			t.Errorf("%s sans résultat de capture", id)
		}
	}
	for _, task := range r.rep.Plan.Tasks {
		if slices.Contains(task.Tools, watch.ToolName) {
			t.Errorf("%s reçoit %s", task.ID, watch.ToolName)
		}
	}
	if o.reportMode() != report.ModeWatch || !strings.Contains(o.modeRule(), "Suivi en direct : les captures") {
		t.Fatalf("mode %s, consigne %q", o.reportMode(), o.modeRule())
	}
	if !strings.Contains(tl.system["synthesizer"], "# Suivi —") {
		t.Fatal("modèle de rapport watch absent")
	}
	if o.Interrupt() || !o.Runner.Concluding() {
		t.Fatal("hors attente, Ctrl-C doit conclure sans réarmer")
	}
}

func TestWatchWithoutSourceSkipsCapture(t *testing.T) {
	o, _ := newOrch(t, []string{dagPlan}, nil)
	o.Watch = watch.New(func(string) (watch.Instance, bool) { return nil, false }, nil, audit.Nop())
	rep, err := o.Run(context.Background(), "suivre ssh")
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Results[1]; c.TaskID != watch.TaskID || c.Status != "skipped" || len(c.Gaps) == 0 {
		t.Fatalf("%+v", c)
	}
}
