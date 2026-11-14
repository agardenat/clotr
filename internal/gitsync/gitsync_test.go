package gitsync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitEnv(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git absent")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commit(t *testing.T, dir, file, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "add", file)
	run(t, dir, "commit", "-q", "-m", file+" "+content)
	return run(t, dir, "rev-parse", "HEAD")
}

func origin(t *testing.T) (bare, work string) {
	t.Helper()
	root := t.TempDir()
	bare, work = filepath.Join(root, "origin.git"), filepath.Join(root, "work")
	run(t, root, "init", "-q", "--bare", "-b", "main", bare)
	run(t, root, "clone", "-q", bare, work)
	commit(t, work, "a.txt", "1")
	run(t, work, "push", "-q", "origin", "HEAD:main")
	return bare, work
}

func push(t *testing.T, work, file, content string) string {
	t.Helper()
	h := commit(t, work, file, content)
	run(t, work, "push", "-q", "origin", "HEAD:main")
	return h
}

func TestSyncCloneUpdateCurrent(t *testing.T) {
	gitEnv(t)
	bare, work := origin(t)
	dst := filepath.Join(t.TempDir(), "conf", "repo")
	r := Sync(context.Background(), bare, dst, "")
	if r.Status != Cloned || r.To == "" || !r.Changed() {
		t.Fatalf("clone: %+v", r)
	}
	if r = Sync(context.Background(), bare, dst, "main"); r.Status != Current {
		t.Fatalf("à jour: %+v", r)
	}
	push(t, work, "b.txt", "2")
	head := push(t, work, "c.txt", "3")
	r = Sync(context.Background(), bare, dst, "main")
	if r.Status != Updated || r.To != head || r.Commits != 2 || r.From == "" {
		t.Fatalf("mise à jour: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dst, "c.txt")); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := run(t, dst, "rev-parse", "HEAD"); got != r.From {
		t.Fatalf("retour arrière: %s, attendu %s", got, r.From)
	}
	if _, err := os.Stat(filepath.Join(dst, "c.txt")); err == nil {
		t.Fatal("c.txt toujours présent après retour arrière")
	}
}

func TestSyncEmptyDirCloned(t *testing.T) {
	gitEnv(t)
	bare, _ := origin(t)
	dst := t.TempDir()
	if r := Sync(context.Background(), bare, dst, "main"); r.Status != Cloned {
		t.Fatalf("%+v", r)
	}
}

func TestSyncLeavesLocalStateAlone(t *testing.T) {
	gitEnv(t)
	bare, work := origin(t)
	ctx := context.Background()

	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "config.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Sync(ctx, bare, plain, "main"); r.Status != Skipped || !strings.Contains(r.Reason, "git") {
		t.Fatalf("non git: %+v", r)
	}

	dst := filepath.Join(t.TempDir(), "repo")
	Sync(ctx, bare, dst, "main")
	if r := Sync(ctx, "/elsewhere.git", dst, "main"); r.Status != Skipped || !strings.Contains(r.Reason, "/elsewhere.git") {
		t.Fatalf("origin: %+v", r)
	}
	if r := Sync(ctx, bare, dst, "dev"); r.Status != Skipped || !strings.Contains(r.Reason, "dev") {
		t.Fatalf("branche: %+v", r)
	}

	push(t, work, "b.txt", "2")
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Sync(ctx, bare, dst, "main"); r.Status != Skipped {
		t.Fatalf("modifié: %+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.txt")); string(b) != "local" {
		t.Fatal("modification locale écrasée")
	}
	run(t, dst, "checkout", "-q", "--", "a.txt")
	if err := os.WriteFile(filepath.Join(dst, "untracked.env"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Sync(ctx, bare, dst, "main"); r.Status != Updated {
		t.Fatalf("fichier non suivi bloquant: %+v", r)
	}

	commit(t, dst, "local.txt", "x")
	if r := Sync(ctx, bare, dst, "main"); r.Status != Current || r.Reason == "" {
		t.Fatalf("en avance: %+v", r)
	}
	push(t, work, "d.txt", "4")
	if r := Sync(ctx, bare, dst, "main"); r.Status != Skipped {
		t.Fatalf("divergent: %+v", r)
	}
}

func TestSyncUnreachable(t *testing.T) {
	gitEnv(t)
	dst := filepath.Join(t.TempDir(), "repo")
	r := Sync(context.Background(), filepath.Join(t.TempDir(), "absent.git"), dst, "main")
	if r.Status != Failed || r.Reason == "" {
		t.Fatalf("%+v", r)
	}
	if r.Changed() {
		t.Fatal("échec compté comme changement")
	}
	if err := Rollback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
