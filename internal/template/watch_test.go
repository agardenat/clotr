package template

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

const followStar = `
LOG = ["a", "b", "c"]

def logs(args):
    return "\n".join(LOG)

def follow_logs(args, cursor):
    if cursor == None:
        return {"lines": ["ignorée"], "cursor": {"n": 1}}
    n = cursor["n"]
    return {"lines": [args.get("pod", "?") + ":" + l for l in LOG[n:]], "cursor": {"n": len(LOG)}}

def bad(args, cursor):
    return "texte"

tool(name = "logs", description = "d", schema = {"type": "object"}, fn = logs, follow = follow_logs)
tool(name = "other", description = "d", schema = {"type": "object"}, fn = logs)
tool(name = "broken", description = "d", schema = {"type": "object"}, fn = logs, follow = bad)
`

func TestScriptToolFollow(t *testing.T) {
	tpl := writeTemplate(t, "name: x\ntargets: [{kind: a, name: n1}]\nscript: x.star\n", followStar)
	in, err := NewInstance("k", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Defer(context.Background(), t.TempDir(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if got := in.FollowTools(); !slices.Equal(got, []string{"k_logs", "k_broken"}) {
		t.Fatalf("outils suivables : %v", got)
	}
	ctx := context.Background()
	lines, cur, err := in.Follow(ctx, "k_logs", json.RawMessage(`{"pod":"api"}`), nil)
	if err != nil || string(cur) != `{"n":1}` || len(lines) != 1 {
		t.Fatalf("départ : %v %s %v", lines, cur, err)
	}
	lines, cur, err = in.Follow(ctx, "k_logs", json.RawMessage(`{"pod":"api"}`), cur)
	if err != nil || !slices.Equal(lines, []string{"api:b", "api:c"}) || string(cur) != `{"n":3}` {
		t.Fatalf("suite : %v %s %v", lines, cur, err)
	}
	if _, _, err := in.Follow(ctx, "k_other", nil, nil); err == nil || !strings.Contains(err.Error(), "k_logs") {
		t.Fatalf("outil sans suivi : %v", err)
	}
	if _, _, err := in.Follow(ctx, "k_broken", nil, nil); err == nil || !strings.Contains(err.Error(), "follow") {
		t.Fatalf("résultat invalide : %v", err)
	}
}

func TestFollowRequiresReadLevel(t *testing.T) {
	star := "def f(a):\n    return ''\ndef g(a, c):\n    return {}\ntool(name='t', description='d', schema={'type':'object'}, fn=f, access='exec', follow=g)\n"
	tpl := writeTemplate(t, "name: x\nscript: x.star\n", star)
	if _, err := NewInstance("k", tpl, nil); err == nil || !strings.Contains(err.Error(), "follow") {
		t.Fatalf("follow sur un outil exec accepté : %v", err)
	}
}
