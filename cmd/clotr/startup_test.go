package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const startupConfig = `providers:
  - {name: p, base_url: http://x}
templates: {dir: %TPL%}
startup:
  - {name: conf, template: sync-conf, params: {url: %URL%}, every: 1h}
`

func TestStartupSyncAndRollback(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git absent")
	}
	base := t.TempDir()
	t.Setenv("CLOTR_NO_STARTUP", "")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))
	t.Setenv("LocalAppData", filepath.Join(base, "cache"))
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(base, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "test")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "test@example.com")
	}

	tpl := filepath.Join(base, "templates")
	writeFile(t, filepath.Join(tpl, "sync-conf.yaml"), "name: sync-conf\nkind: startup\nscript: sync-conf.star\nparams:\n  url: {type: string, required: true}\n")
	writeFile(t, filepath.Join(tpl, "sync-conf.star"), "def startup():\n    git.sync(instance.params[\"url\"], \".\")\n")

	bare, work, conf := filepath.Join(base, "conf.git"), filepath.Join(base, "work"), filepath.Join(base, "conf")
	git(t, base, "init", "-q", "--bare", "-b", "main", bare)
	git(t, base, "clone", "-q", bare, work)
	cfgText := strings.NewReplacer("%TPL%", filepath.ToSlash(tpl), "%URL%", filepath.ToSlash(bare)).Replace(startupConfig)
	writeFile(t, filepath.Join(work, "config.yaml"), cfgText)
	git(t, work, "add", ".")
	git(t, work, "commit", "-q", "-m", "init")
	git(t, work, "push", "-q", "origin", "HEAD:main")
	git(t, base, "clone", "-q", filepath.ToSlash(bare), conf)
	path := filepath.Join(conf, "config.yaml")

	push := func(content string) string {
		writeFile(t, filepath.Join(work, "config.yaml"), content)
		git(t, work, "commit", "-q", "-am", "change")
		git(t, work, "push", "-q", "origin", "HEAD:main")
		return git(t, work, "rev-parse", "HEAD")
	}

	head := push(cfgText + "language: fr\n")
	var out strings.Builder
	cfg, err := loadConfig(&options{config: path, ctx: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Language != "fr" || git(t, conf, "rev-parse", "HEAD") != head {
		t.Fatalf("configuration non mise à jour au démarrage (language %q)", cfg.Language)
	}
	once := &options{config: path, ctx: context.Background()}
	for range 2 {
		if _, err := loadConfig(once); err != nil {
			t.Fatal(err)
		}
	}
	if !once.startupDone {
		t.Fatal("étape de démarrage non marquée comme faite")
	}

	push(cfgText + "language: en\n")
	cfg, _ = runStartup(context.Background(), path, cfg, false, false, &out)
	if cfg.Language != "fr" {
		t.Fatal("every ignoré : synchronisation relancée avant l'intervalle")
	}
	if !strings.Contains(out.String(), "configuration (conf): up to date, last checked just now") {
		t.Fatalf("état de la dernière vérification non affiché :\n%s", out.String())
	}
	out.Reset()
	if runStartup(context.Background(), path, cfg, false, true, &out); out.Len() != 0 {
		t.Fatalf("--quiet : %q", out.String())
	}
	cfg, rep := runStartup(context.Background(), path, cfg, true, false, &out)
	if cfg.Language != "en" || rep.failed != 0 || rep.rolledBack {
		t.Fatalf("synchronisation forcée : language %q, %+v\n%s", cfg.Language, rep, out.String())
	}
	out.Reset()
	runStartup(context.Background(), path, cfg, true, false, &out)
	if !strings.Contains(out.String(), "configuration (conf): up to date — ") {
		t.Fatalf("« à jour » non affiché :\n%s", out.String())
	}

	good := git(t, conf, "rev-parse", "HEAD")
	push(cfgText + "language: en\nunknown_key: 1\n")
	out.Reset()
	cfg, rep = runStartup(context.Background(), path, cfg, true, false, &out)
	if !rep.rolledBack || git(t, conf, "rev-parse", "HEAD") != good {
		t.Fatalf("pas de retour arrière : %+v\n%s", rep, out.String())
	}
	if cfg == nil || cfg.Language != "en" || !strings.Contains(out.String(), "unknown_key") {
		t.Fatalf("après retour arrière : %v\n%s", cfg, out.String())
	}
	if line, alert := recentLine("conf", time.Now()); !alert || !strings.Contains(line, "last check failed") || !strings.Contains(line, "update undone") {
		t.Fatalf("échec non mémorisé : %q", line)
	}
	if err := cmdSync(context.Background(), &options{config: path}, &out); err == nil {
		t.Fatal("clotr sync sans erreur après retour arrière")
	}

	writeFile(t, path, cfgText+"language: en\n# local\n")
	out.Reset()
	if _, rep = runStartup(context.Background(), path, cfg, true, false, &out); rep.failed != 0 || !strings.Contains(out.String(), "conf") {
		t.Fatalf("modification locale : %+v\n%s", rep, out.String())
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "# local") {
		t.Fatal("modification locale écrasée")
	}
}

func TestStartupDisabled(t *testing.T) {
	t.Setenv("CLOTR_NO_STARTUP", "")
	if startupDisabled(&options{}) || !startupDisabled(&options{noStartup: true}) {
		t.Fatal("--no-startup")
	}
	t.Setenv("CLOTR_NO_STARTUP", "1")
	if !startupDisabled(&options{}) {
		t.Fatal("CLOTR_NO_STARTUP")
	}
}
