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
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/muesli/cancelreader"

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
	refusals  = map[string]string{}
	lastUser  = map[string]string{}
	described = map[string]bool{}
	accepted  = map[string]string{}
	hostDeny  = map[string]string{}
)

type EmptyError struct{ Label string }

func (e *EmptyError) Error() string { return i18n.T("creds.empty", e.Label) }

func hostKey(label, host string) string {
	return label + "\x01" + host
}

func Accept(label, user, pass string) {
	if user == "" || pass == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	accepted[userKey(label, user)] = pass
}

func RejectOn(label, user, pass, host, reason string) {
	mu.Lock()
	if p, ok := accepted[userKey(label, user)]; ok && pass != "" && p == pass {
		hostDeny[hostKey(label, host)] = reason
		mu.Unlock()
		return
	}
	mu.Unlock()
	Reject(label, user, pass, reason)
}

func Decline(label, host string) {
	mu.Lock()
	defer mu.Unlock()
	hostDeny[hostKey(label, host)] = i18n.T("creds.declined")
}

func HostRefused(label, host string) error {
	mu.Lock()
	defer mu.Unlock()
	if r, ok := hostDeny[hostKey(label, host)]; ok {
		return i18n.E("creds.host_refused", host, label, r)
	}
	return nil
}

type detailKey struct{}

func WithDetail(ctx context.Context, detail string) context.Context {
	return context.WithValue(ctx, detailKey{}, detail)
}

func Refused(label, user, reason string) {
	Forget(label, user)
	mu.Lock()
	defer mu.Unlock()
	refusals[label] = reason
	if user != "" {
		lastUser[label] = user
	}
}

func Reject(label, user, pass, reason string) {
	mu.Lock()
	cur, ok := cache[userKey(label, user)]
	if !ok {
		if c, found := cache[label]; found && c.User == user {
			cur, ok = c, true
		}
	}
	mu.Unlock()
	if ok && cur.Pass != pass {
		return
	}
	Refused(label, user, reason)
}

var ReadVault = vault.Secret

func VaultUserFields(ref string) []string {
	_, field, _ := strings.Cut(ref, "#")
	var fields []string
	if field != "" && field != "password" && strings.Contains(field, "password") {
		fields = append(fields, strings.Replace(field, "password", "username", 1), strings.Replace(field, "password", "user", 1))
	}
	return append(fields, "username")
}

func ReadVaultUser(ctx context.Context, ref string) (string, error) {
	path, _, _ := strings.Cut(ref, "#")
	var err error
	for _, f := range VaultUserFields(ref) {
		var u string
		if u, err = ReadVault(ctx, path+"#"+f); err == nil && u != "" {
			return u, nil
		}
	}
	return "", err
}

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

var ErrNoAnswer = errors.New("creds: no answer")

var promptMu sync.Mutex

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
	delete(accepted, userKey(label, user))
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
			if u, err := ReadVaultUser(ctx, passVault); err == nil {
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
	promptMu.Lock()
	defer promptMu.Unlock()
	defer suspend()()
	var notice string
	if r := refusals[label]; r != "" {
		notice = i18n.T("prompt.refused", r)
		delete(refusals, label)
	}
	if d, _ := ctx.Value(detailKey{}).(string); d != "" && (notice != "" || !described[label]) {
		notice += d + "\n"
		described[label] = true
	}
	if vaultErr != nil {
		notice += i18n.T("prompt.vault_failed", label, passVault, vaultErr)
	}
	if p.User == "" && !secretOnly {
		question := i18n.T("prompt.user", label)
		prev := lastUser[label]
		if prev != "" {
			question = i18n.T("prompt.user_default", label, prev)
		}
		line, err := prompt(ctx, tty, notice+question, false)
		if err != nil {
			return Pair{}, err
		}
		p.User, notice = strings.TrimSpace(line), ""
		if p.User == "" {
			p.User = prev
		}
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
		return Pair{}, &EmptyError{Label: label}
	}
	cache[key] = p
	if !secretOnly {
		cache[userKey(label, p.User)] = p
		lastUser[label] = p.User
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
		var in io.Reader = tty.In
		var cancel func() bool
		if r, err := cancelreader.NewReader(tty.In); err == nil {
			defer r.Close()
			in, cancel = r, r.Cancel
		}
		return readInterruptible(ctx, tty, func() (string, error) {
			return bufio.NewReader(in).ReadString('\n')
		}, cancel)
	}
	s, err := readInterruptible(ctx, tty, func() (string, error) {
		b, err := term.ReadPassword(tty.In.Fd())
		return string(b), err
	}, nil)
	fmt.Fprintln(tty.Out)
	return s, err
}

func readInterruptible(ctx context.Context, tty *Console, read func() (string, error), cancel func() bool) (string, error) {
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
		if cancel != nil && cancel() {
			<-ch
		}
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
	return AskWithin(ctx, question, 0)
}

func AskWithin(ctx context.Context, question string, within time.Duration) (string, error) {
	promptMu.Lock()
	defer promptMu.Unlock()
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
	asked := ctx
	if within > 0 {
		var cancel context.CancelFunc
		asked, cancel = context.WithTimeout(ctx, within)
		defer cancel()
	}
	s, err := prompt(asked, tty, question, false)
	if err != nil && ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
		return "", ErrNoAnswer
	}
	return s, err
}

func AskSecret(ctx context.Context, question string) (string, error) {
	promptMu.Lock()
	defer promptMu.Unlock()
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
