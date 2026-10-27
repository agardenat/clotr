package creds

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/x/term"

	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/vault"
)

type Pair struct {
	User string
	Pass string
}

var (
	mu        sync.Mutex
	cache     = map[string]Pair{}
	skipVault = map[string]bool{}
)

var ReadVault = vault.Secret

type Console struct {
	In  *os.File
	Out *os.File
}

func (c *Console) Close() {
	_ = c.In.Close()
	if c.Out != c.In {
		_ = c.Out.Close()
	}
}

var OpenTTY = openConsole

var Suspend func() (resume func())

var ErrNoPrompter = errors.New("creds: prompter unavailable")

var Prompter func(ctx context.Context, in *os.File, question string, secret bool) (string, error)

func Resolve(ctx context.Context, userEnv, passEnv, passVault, label string) (Pair, error) {
	return resolve(ctx, "", userEnv, passEnv, passVault, label, false)
}

func ResolveUser(ctx context.Context, user, passEnv, passVault, label string) (Pair, error) {
	return resolve(ctx, user, "", passEnv, passVault, label, false)
}

func ResolveSecret(ctx context.Context, passEnv, passVault, label string) (Pair, error) {
	return resolve(ctx, "", "", passEnv, passVault, label, true)
}

func Forget(label, user string) {
	mu.Lock()
	defer mu.Unlock()
	delete(cache, userKey(label, user))
	skipVault[label] = true
	if c, ok := cache[label]; ok && c.User == user {
		delete(cache, label)
	}
}

func userKey(label, user string) string {
	return label + "\x00" + user
}

func resolve(ctx context.Context, user, userEnv, passEnv, passVault, label string, secretOnly bool) (Pair, error) {
	p := Pair{User: user}
	if p.User == "" && userEnv != "" {
		p.User = os.Getenv(userEnv)
	}
	if passEnv != "" {
		p.Pass = os.Getenv(passEnv)
	}
	if p.Pass != "" && (secretOnly || p.User != "") {
		return p, nil
	}
	key := label
	if user != "" {
		key = userKey(label, user)
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[key]; ok {
		return c, nil
	}
	if err := ctx.Err(); err != nil {
		return Pair{}, err
	}
	var vaultErr error
	if p.Pass == "" && passVault != "" && !skipVault[label] {
		p.Pass, vaultErr = ReadVault(ctx, passVault)
		if err := ctx.Err(); err != nil {
			return Pair{}, err
		}
		if vaultErr == nil && secretOnly {
			cache[key] = p
			return p, nil
		}
		if vaultErr == nil && p.User == "" {
			path, _, _ := strings.Cut(passVault, "#")
			if u, err := ReadVault(ctx, path+"#username"); err == nil {
				p.User = u
			}
		}
		if vaultErr == nil && p.User != "" {
			cache[key] = p
			cache[userKey(label, p.User)] = p
			return p, nil
		}
	}
	missing := i18n.T("creds.missing", label, orNone(userEnv), orNone(passEnv))
	if secretOnly {
		missing = i18n.T("creds.missing_secret", label, orNone(passEnv))
	}
	if vaultErr != nil {
		missing += i18n.T("creds.vault", passVault, vaultErr)
	}
	tty, err := OpenTTY()
	if err != nil {
		return Pair{}, errors.New(missing)
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return Pair{}, errors.New(missing)
	}
	defer suspend()()
	var notice string
	if vaultErr != nil {
		notice = i18n.T("prompt.vault_failed", label, passVault, vaultErr)
	}
	if p.User == "" && !secretOnly {
		line, err := prompt(ctx, tty, notice+i18n.T("prompt.user", label), false)
		if err != nil {
			return Pair{}, err
		}
		p.User, notice = strings.TrimSpace(line), ""
	}
	if p.Pass == "" {
		question := i18n.T("prompt.password", label, p.User)
		if secretOnly {
			question = i18n.T("prompt.secret", label)
		}
		pass, err := prompt(ctx, tty, notice+question, true)
		if err != nil {
			return Pair{}, err
		}
		p.Pass = pass
	}
	if p.Pass == "" || p.User == "" && !secretOnly {
		return Pair{}, i18n.E("creds.empty", label)
	}
	cache[key] = p
	if !secretOnly {
		cache[userKey(label, p.User)] = p
	}
	return p, nil
}

func suspend() (resume func()) {
	if Prompter != nil || Suspend == nil {
		return func() {}
	}
	return Suspend()
}

func prompt(ctx context.Context, tty *Console, question string, secret bool) (string, error) {
	if Prompter != nil {
		s, err := Prompter(ctx, tty.In, question, secret)
		if !errors.Is(err, ErrNoPrompter) {
			return s, err
		}
	}
	fmt.Fprint(tty.Out, question)
	if !secret {
		return readInterruptible(ctx, tty, func() (string, error) {
			return bufio.NewReader(tty.In).ReadString('\n')
		})
	}
	s, err := readInterruptible(ctx, tty, func() (string, error) {
		b, err := term.ReadPassword(tty.In.Fd())
		return string(b), err
	})
	fmt.Fprintln(tty.Out)
	return s, err
}

func readInterruptible(ctx context.Context, tty *Console, read func() (string, error)) (string, error) {
	state, err := term.GetState(tty.In.Fd())
	if err != nil {
		return "", err
	}
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := read()
		ch <- result{s, err}
	}()
	select {
	case r := <-ch:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return "", r.err
		}
		return r.s, nil
	case <-ctx.Done():
		_ = term.Restore(tty.In.Fd(), state)
		fmt.Fprintln(tty.Out)
		return "", ctx.Err()
	}
}

func Confirm(question string) (bool, error) {
	tty, err := OpenTTY()
	if err != nil {
		return false, err
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return false, i18n.E("creds.notty")
	}
	fmt.Fprint(tty.Out, question)
	line, err := bufio.NewReader(tty.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "o", "oui":
		return true, nil
	}
	return false, nil
}

func Ask(ctx context.Context, question string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	tty, err := OpenTTY()
	if err != nil {
		return "", i18n.E("creds.notty")
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return "", i18n.E("creds.notty")
	}
	defer suspend()()
	return prompt(ctx, tty, question, false)
}

func AskSecret(ctx context.Context, question string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	tty, err := OpenTTY()
	if err != nil {
		return "", i18n.E("creds.notty")
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return "", i18n.E("creds.notty")
	}
	defer suspend()()
	return prompt(ctx, tty, question, true)
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
