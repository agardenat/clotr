package gitsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

const (
	Cloned  = "cloned"
	Updated = "updated"
	Current = "current"
	Skipped = "skipped"
	Failed  = "failed"
)

type Result struct {
	URL     string `json:"url"`
	Path    string `json:"path"`
	Ref     string `json:"ref"`
	Status  string `json:"status"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Commits int    `json:"commits,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (r Result) Changed() bool {
	return r.Status == Cloned || r.Status == Updated
}

var Timeout = 60 * time.Second

var gitBin = "git"

func Sync(ctx context.Context, url, path, ref string) Result {
	if ref == "" {
		ref = "main"
	}
	r := Result{URL: url, Path: path, Ref: ref}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	g := runner{ctx: ctx, env: env(ctx)}
	empty, err := emptyDir(path)
	if err != nil {
		return r.fail(err.Error())
	}
	if empty {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return r.fail(err.Error())
		}
		if _, err := g.git("", "clone", "--quiet", "--branch", ref, "--", url, path); err != nil {
			return r.fail(err.Error())
		}
		r.To, _ = g.git(path, "rev-parse", "HEAD")
		r.Status = Cloned
		return r
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err != nil {
		return r.skip(i18n.T("gitsync.not_repo"))
	}
	if origin, err := g.git(path, "remote", "get-url", "origin"); err != nil || origin != url {
		return r.skip(i18n.T("gitsync.origin", origin, url))
	}
	if branch, _ := g.git(path, "symbolic-ref", "--quiet", "--short", "HEAD"); branch != ref {
		return r.skip(i18n.T("gitsync.branch", branch, ref))
	}
	if st, err := g.git(path, "status", "--porcelain", "--untracked-files=no"); err != nil {
		return r.fail(err.Error())
	} else if st != "" {
		return r.skip(i18n.T("gitsync.dirty"))
	}
	from, err := g.git(path, "rev-parse", "HEAD")
	if err != nil {
		return r.fail(err.Error())
	}
	r.From, r.To = from, from
	if _, err := g.git(path, "fetch", "--quiet", "origin", "refs/heads/"+ref); err != nil {
		return r.fail(err.Error())
	}
	remote, err := g.git(path, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return r.fail(err.Error())
	}
	if remote == from {
		r.Status = Current
		return r
	}
	if g.ancestor(path, remote, from) {
		r.Status, r.Reason = Current, i18n.T("gitsync.ahead")
		return r
	}
	if !g.ancestor(path, from, remote) {
		return r.skip(i18n.T("gitsync.diverged"))
	}
	if n, err := g.git(path, "rev-list", "--count", from+".."+remote); err == nil {
		r.Commits, _ = strconv.Atoi(n)
	}
	if _, err := g.git(path, "merge", "--ff-only", "--quiet", remote); err != nil {
		return r.fail(err.Error())
	}
	r.To, r.Status = remote, Updated
	return r
}

func Rollback(ctx context.Context, r Result) error {
	if r.Status != Updated || r.From == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	g := runner{ctx: ctx, env: env(ctx)}
	_, err := g.git(r.Path, "reset", "--hard", "--quiet", r.From)
	return err
}

func (r Result) fail(reason string) Result {
	r.Status, r.Reason = Failed, reason
	return r
}

func (r Result) skip(reason string) Result {
	r.Status, r.Reason = Skipped, reason
	return r
}

func emptyDir(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

type runner struct {
	ctx context.Context
	env []string
}

func (g runner) git(dir string, args ...string) (string, error) {
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	cmd := exec.CommandContext(g.ctx, gitBin, args...)
	cmd.Env = g.env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if g.ctx.Err() != nil {
			return "", i18n.E("gitsync.timeout", Timeout)
		}
		msg := lastLine(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return strings.TrimSpace(out.String()), fmt.Errorf("git %s: %s", args[indexCmd(args)], msg)
	}
	return strings.TrimSpace(out.String()), nil
}

func indexCmd(args []string) int {
	if len(args) > 2 && args[0] == "-C" {
		return 2
	}
	return 0
}

func (g runner) ancestor(dir, a, b string) bool {
	_, err := g.git(dir, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func env(ctx context.Context) []string {
	e := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if os.Getenv("GIT_SSH_COMMAND") == "" && os.Getenv("GIT_SSH") == "" {
		cmd := exec.CommandContext(ctx, gitBin, "config", "--get", "core.sshCommand")
		if out, err := cmd.Output(); err != nil || strings.TrimSpace(string(out)) == "" {
			e = append(e, "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o ConnectTimeout=10")
		}
	}
	return e
}
