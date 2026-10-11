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
)

type Pair struct {
	User string
	Pass string
}

var (
	mu    sync.Mutex
	cache = map[string]Pair{}
)

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

func Resolve(ctx context.Context, userEnv, passEnv, label string) (Pair, error) {
	return resolve(ctx, "", userEnv, passEnv, label)
}

func ResolveUser(ctx context.Context, user, passEnv, label string) (Pair, error) {
	return resolve(ctx, user, "", passEnv, label)
}

func Forget(label, user string) {
	mu.Lock()
	defer mu.Unlock()
	delete(cache, userKey(label, user))
	if c, ok := cache[label]; ok && c.User == user {
		delete(cache, label)
	}
}

func userKey(label, user string) string {
	return label + "\x00" + user
}

func resolve(ctx context.Context, user, userEnv, passEnv, label string) (Pair, error) {
	p := Pair{User: user}
	if p.User == "" && userEnv != "" {
		p.User = os.Getenv(userEnv)
	}
	if passEnv != "" {
		p.Pass = os.Getenv(passEnv)
	}
	if p.User != "" && p.Pass != "" {
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
	tty, err := OpenTTY()
	if err != nil {
		return Pair{}, fmt.Errorf("%s: identifiants absents (variables %s / %s) et aucun terminal pour les saisir", label, orNone(userEnv), orNone(passEnv))
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return Pair{}, fmt.Errorf("%s: identifiants absents (variables %s / %s) et aucun terminal pour les saisir", label, orNone(userEnv), orNone(passEnv))
	}
	if Suspend != nil {
		defer Suspend()()
	}
	if p.User == "" {
		fmt.Fprint(tty.Out, i18n.T("prompt.user", label))
		line, err := readInterruptible(ctx, tty, func() (string, error) {
			return bufio.NewReader(tty.In).ReadString('\n')
		})
		if err != nil {
			return Pair{}, err
		}
		p.User = strings.TrimSpace(line)
	}
	if p.Pass == "" {
		fmt.Fprint(tty.Out, i18n.T("prompt.password", label, p.User))
		pass, err := readInterruptible(ctx, tty, func() (string, error) {
			b, err := term.ReadPassword(tty.In.Fd())
			return string(b), err
		})
		fmt.Fprintln(tty.Out)
		if err != nil {
			return Pair{}, err
		}
		p.Pass = pass
	}
	if p.User == "" || p.Pass == "" {
		return Pair{}, fmt.Errorf("%s: identifiants vides", label)
	}
	cache[key] = p
	cache[userKey(label, p.User)] = p
	return p, nil
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
		return false, fmt.Errorf("aucun terminal")
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

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
