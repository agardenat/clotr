package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/orchestrator"
	"github.com/agardenat/clotr/internal/session"
)

func TestWatchInterruptsConcludesThenCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 2)
	var hook atomic.Pointer[func()]
	var called atomic.Int32
	f := func() { called.Add(1) }
	hook.Store(&f)
	done := make(chan struct{})
	go func() {
		watchInterrupts(ctx, cancel, sigs, &hook)
		close(done)
	}()
	sigs <- os.Interrupt
	time.Sleep(20 * time.Millisecond)
	if called.Load() != 1 || ctx.Err() != nil {
		t.Fatalf("premier ctrl+c: crochet %d, contexte %v", called.Load(), ctx.Err())
	}
	sigs <- os.Interrupt
	<-done
	if called.Load() != 1 || ctx.Err() == nil {
		t.Fatal("second ctrl+c: contexte non annulé")
	}
}

func TestResultSaverWritesAfterEachTask(t *testing.T) {
	dir := t.TempDir()
	save := (&app{}).resultSaver(&session.Session{}, dir)
	for i, id := range []string{"t0", "t1"} {
		save(orchestrator.Result{TaskID: id, Status: "ok", Findings: []string{"vu"}})
		data, err := os.ReadFile(filepath.Join(dir, "results.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got []orchestrator.Result
		if err := json.Unmarshal(data, &got); err != nil || len(got) != i+1 || got[i].TaskID != id {
			t.Fatalf("après %s: %+v %v", id, got, err)
		}
	}
}

func TestWatchInterruptsWithoutHook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	var hook atomic.Pointer[func()]
	sigs <- syscall.SIGTERM
	watchInterrupts(ctx, cancel, sigs, &hook)
	if ctx.Err() == nil {
		t.Fatal("contexte non annulé")
	}
}

func TestIncidentIncompatibleModes(t *testing.T) {
	for _, o := range []*options{{incident: true, direct: directAuto}, {incident: true, chat: true}} {
		if err := cmdRun(context.Background(), o, []string{"x"}, nil); err == nil || !strings.Contains(err.Error(), "--incident") {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}
