package template

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/gitsync"
)

const startupYAML = `name: x
kind: startup
script: x.star
params:
  repos: {type: list, item: {url: string, dir: string, ref: string}}
`

const startupStar = `
def startup():
    for r in instance.params["repos"]:
        res = git.sync(r["url"], r["dir"], ref = r["ref"])
        if res["status"] not in ("current", "updated", "cloned"):
            print("%s: %s" % (r["dir"], res["reason"]))
`

func parseErr(t *testing.T, yaml, star string) error {
	t.Helper()
	dir := t.TempDir()
	if star != "" {
		if err := os.WriteFile(filepath.Join(dir, "x.star"), []byte(star), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "x.yaml")
	_, err := Parse([]byte(yaml), p)
	return err
}

func TestStartupSpec(t *testing.T) {
	for name, c := range map[string]struct{ yaml, star, want string }{
		"kind inconnu":   {"name: x\nkind: other\nscript: x.star\n", "def startup():\n    pass\n", "kind"},
		"sans script":    {"name: x\nkind: startup\ntargets: [{kind: a}]\n", "", "script"},
		"avec outils":    {startupYAML + "tools: [{kind: dns_resolve}]\n", startupStar, "tools"},
		"git hors start": {"name: x\nscript: x.star\n", "def f():\n    git.sync('u', 'd')\n", "git"},
	} {
		t.Run(name, func(t *testing.T) {
			err := parseErr(t, c.yaml, c.star)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("erreur %v, attendu %q", err, c.want)
			}
		})
	}
	tpl := writeTemplate(t, "name: x\nkind: startup\nscript: x.star\n", "def other():\n    pass\n")
	if _, err := NewInstance("s", tpl, nil); err == nil || !strings.Contains(err.Error(), "startup()") {
		t.Fatalf("fonction startup absente acceptée: %v", err)
	}
}

func TestRunStartup(t *testing.T) {
	tpl := writeTemplate(t, startupYAML, startupStar)
	if !tpl.Startup() {
		t.Fatal("kind startup non reconnu")
	}
	in, err := NewInstance("s", tpl, map[string]any{"repos": []any{
		map[string]any{"url": "git@example.com:conf.git", "dir": ".", "ref": ""},
		map[string]any{"url": "git@example.com:tpl.git", "dir": "templates", "ref": "stable"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	in.SetGitRoots(root)
	var printed []string
	in.Print = func(msg string) { printed = append(printed, msg) }
	var calls []string
	in.gitSync = func(_ context.Context, url, path, ref string) gitsync.Result {
		calls = append(calls, url+" "+path+" "+ref)
		if strings.HasSuffix(url, "tpl.git") {
			return gitsync.Result{URL: url, Path: path, Ref: ref, Status: gitsync.Skipped, Reason: "local changes"}
		}
		return gitsync.Result{URL: url, Path: path, Ref: "main", Status: gitsync.Updated, From: "a", To: "b", Commits: 1}
	}
	res, err := in.RunStartup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git@example.com:conf.git " + root + " ", "git@example.com:tpl.git " + filepath.Join(root, "templates") + " stable"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("appels %q, attendu %q", calls, want)
	}
	if len(res) != 2 || res[0].Status != gitsync.Updated || res[1].Status != gitsync.Skipped {
		t.Fatalf("résultats %+v", res)
	}
	if len(printed) != 1 || !strings.Contains(printed[0], "local changes") {
		t.Fatalf("print %q", printed)
	}
}

func TestGitPathConfined(t *testing.T) {
	tpl := writeTemplate(t, startupYAML, startupStar)
	in, err := NewInstance("s", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.gitPath("."); err == nil {
		t.Fatal("aucune racine : accepté")
	}
	base := t.TempDir()
	conf, tpls, out := filepath.Join(base, "conf"), filepath.Join(base, "tpl"), filepath.Join(base, "out")
	for _, d := range []string{conf, tpls, out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	in.SetGitRoots(conf, tpls)
	for dir, ok := range map[string]bool{
		".":                         true,
		"templates":                 true,
		"a/b":                       true,
		tpls:                        true,
		filepath.Join(tpls, "sub"):  true,
		"../out":                    false,
		"a/../../out":               false,
		out:                         false,
		"":                          false,
		filepath.Join(conf, "link"): false,
	} {
		if dir == filepath.Join(conf, "link") {
			if err := os.Symlink(out, dir); err != nil {
				t.Skip("lien symbolique impossible")
			}
		}
		_, err := in.gitPath(dir)
		if (err == nil) != ok {
			t.Errorf("%q: erreur %v, accepté attendu %v", dir, err, ok)
		}
	}
	if _, err := in.gitPath("link/x"); err == nil {
		t.Error("lien sortant du répertoire accepté")
	}
}

func TestStartupHarness(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"x.yaml": startupYAML,
		"x.star": startupStar,
		"x_test.star": `
def test_sync():
    inst = template.instance(params = {"repos": [{"url": "u1", "dir": ".", "ref": ""}, {"url": "u2", "dir": "templates", "ref": ""}]}, git = {"u2": {"status": "skipped", "reason": "dirty"}})
    res = inst.startup()
    assert.eq([r["status"] for r in res], ["current", "skipped"])
    assert.eq([c["path"] for c in inst.git_calls()], ["/config", "/config/templates"])
`,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, ok := set.Get("x")
	if !ok {
		t.Fatalf("template non chargé: %v", set.Warnings)
	}
	var out strings.Builder
	passed, failed, err := RunTests(context.Background(), tpl, &out)
	if err != nil || failed != 0 || passed != 1 {
		t.Fatalf("%d/%d %v\n%s", passed, failed, err, out.String())
	}
}
