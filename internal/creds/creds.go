package creds

import (
	"bufio"
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

func Resolve(userEnv, passEnv, label string) (Pair, error) {
	p := Pair{}
	if userEnv != "" {
		p.User = os.Getenv(userEnv)
	}
	if passEnv != "" {
		p.Pass = os.Getenv(passEnv)
	}
	if p.User != "" && p.Pass != "" {
		return p, nil
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[label]; ok {
		return c, nil
	}
	tty, err := OpenTTY()
	if err != nil {
		return Pair{}, fmt.Errorf("%s: identifiants absents (variables %s / %s) et aucun terminal pour les saisir", label, orNone(userEnv), orNone(passEnv))
	}
	defer tty.Close()
	if !term.IsTerminal(tty.In.Fd()) {
		return Pair{}, fmt.Errorf("%s: identifiants absents (variables %s / %s) et aucun terminal pour les saisir", label, orNone(userEnv), orNone(passEnv))
	}
	if p.User == "" {
		fmt.Fprint(tty.Out, i18n.T("prompt.user", label))
		line, err := bufio.NewReader(tty.In).ReadString('\n')
		if err != nil && err != io.EOF {
			return Pair{}, err
		}
		p.User = strings.TrimSpace(line)
	}
	if p.Pass == "" {
		fmt.Fprint(tty.Out, i18n.T("prompt.password", label, p.User))
		b, err := term.ReadPassword(tty.In.Fd())
		fmt.Fprintln(tty.Out)
		if err != nil {
			return Pair{}, err
		}
		p.Pass = string(b)
	}
	if p.User == "" || p.Pass == "" {
		return Pair{}, fmt.Errorf("%s: identifiants vides", label)
	}
	cache[label] = p
	return p, nil
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
	if err != nil && err != io.EOF {
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
