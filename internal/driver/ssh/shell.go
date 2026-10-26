//go:build !windows

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/agardenat/clotr/internal/i18n"
)

var shellEscapes = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)|\x1b[()][0-9A-Za-z]|\x1b[=>]")

const (
	shellQuiet = 400 * time.Millisecond
	shellProbe = 3 * time.Second
	shellSeen  = 8 << 10
)

type Shell struct {
	opts ShellOptions
	sem  chan struct{}
	mu   sync.Mutex
	idle []*shellSession
	open int
}

func NewShell(o ShellOptions) (*Shell, error) {
	if len(o.Command) == 0 || o.Command[0] == "" {
		return nil, i18n.E("ssh.shell_start", "command", errors.New("empty"))
	}
	if o.MaxConns <= 0 {
		o.MaxConns = 4
	}
	if o.OpenTimeout <= 0 {
		o.OpenTimeout = 2 * time.Minute
	}
	if o.Ready == nil {
		o.Ready = DefaultShellReady
	}
	if o.Prompt == nil {
		o.Prompt = DefaultShellPrompt
	}
	return &Shell{opts: o, sem: make(chan struct{}, o.MaxConns)}, nil
}

func (s *Shell) Close() {
	s.mu.Lock()
	idle := s.idle
	s.idle = nil
	s.open -= len(idle)
	s.mu.Unlock()
	for _, ss := range idle {
		ss.close()
	}
}

func (s *Shell) ExecInput(ctx context.Context, e Endpoint, cmd, stdin string, maxBytes int) (Result, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	defer func() { <-s.sem }()
	for attempt := 0; ; attempt++ {
		ss, reused, err := s.session(ctx, e.Host)
		if err != nil {
			return Result{}, err
		}
		res, err := ss.run(ctx, cmd, stdin, maxBytes)
		s.release(ss)
		var sc shellClosed
		if errors.As(err, &sc) && reused && attempt == 0 && ctx.Err() == nil {
			continue
		}
		return res, err
	}
}

func (s *Shell) session(ctx context.Context, host string) (*shellSession, bool, error) {
	s.mu.Lock()
	var evict []*shellSession
	var found *shellSession
	kept := s.idle[:0]
	for _, ss := range s.idle {
		switch {
		case ss.isDead():
			evict = append(evict, ss)
			s.open--
		case found == nil && ss.host == host:
			found = ss
		default:
			kept = append(kept, ss)
		}
	}
	s.idle = kept
	if found == nil {
		if s.open >= s.opts.MaxConns && len(s.idle) > 0 {
			evict = append(evict, s.idle[0])
			s.idle = s.idle[1:]
			s.open--
		}
		s.open++
	}
	s.mu.Unlock()
	for _, ss := range evict {
		ss.close()
	}
	if found != nil {
		return found, true, nil
	}
	ss, err := s.start(ctx, host)
	if err != nil {
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
		return nil, false, err
	}
	return ss, false, nil
}

func (s *Shell) release(ss *shellSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss.isDead() {
		s.open--
		go ss.close()
		return
	}
	s.idle = append(s.idle, ss)
}

type shellClosed struct{ host string }

func (e shellClosed) Error() string { return i18n.T("ssh.shell_closed", e.host) }

type shellSession struct {
	host   string
	cmd    *exec.Cmd
	f      *os.File
	chunks chan []byte
	wq     chan []byte
	done   chan struct{}
	buf    []byte
	nonce  string
	seq    int
	mu     sync.Mutex
	dead   bool
	once   sync.Once
}

func (s *Shell) start(ctx context.Context, host string) (*shellSession, error) {
	argv := make([]string, len(s.opts.Command))
	for i, a := range s.opts.Command {
		short, _, _ := strings.Cut(host, ".")
		argv[i] = strings.NewReplacer("%h", host, "%s", short).Replace(a)
	}
	c := exec.Command(argv[0], argv[1:]...)
	f, err := pty.StartWithSize(c, &pty.Winsize{Rows: 50, Cols: 250})
	if err != nil {
		return nil, i18n.E("ssh.shell_start", argv[0], err)
	}
	n := make([]byte, 8)
	_, _ = rand.Read(n)
	ss := &shellSession{host: host, cmd: c, f: f, chunks: make(chan []byte, 256), wq: make(chan []byte, 64), done: make(chan struct{}), nonce: hex.EncodeToString(n)}
	go ss.read()
	go ss.writer()
	if err := ss.handshake(ctx, s.opts, strings.Join(argv, " ")); err != nil {
		ss.close()
		return nil, err
	}
	return ss, nil
}

func (ss *shellSession) read() {
	defer close(ss.chunks)
	for {
		b := make([]byte, 32<<10)
		n, err := ss.f.Read(b)
		if n > 0 {
			ss.chunks <- b[:n]
		}
		if err != nil {
			return
		}
	}
}

func (ss *shellSession) isDead() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.dead
}

func (ss *shellSession) markDead() {
	ss.mu.Lock()
	ss.dead = true
	ss.mu.Unlock()
}

func (ss *shellSession) close() {
	ss.once.Do(func() {
		ss.markDead()
		close(ss.done)
		_ = ss.f.Close()
		if p := ss.cmd.Process; p != nil {
			_ = syscall.Kill(-p.Pid, syscall.SIGHUP)
			kill := time.AfterFunc(3*time.Second, func() { _ = syscall.Kill(-p.Pid, syscall.SIGKILL) })
			go func() {
				_ = ss.cmd.Wait()
				kill.Stop()
			}()
		}
		go func() {
			for range ss.chunks {
			}
		}()
	})
}

func (ss *shellSession) writer() {
	for {
		select {
		case b := <-ss.wq:
			if _, err := ss.f.Write(b); err != nil {
				ss.markDead()
				return
			}
		case <-ss.done:
			return
		}
	}
}

func (ss *shellSession) write(s string) {
	select {
	case ss.wq <- []byte(s):
	case <-ss.done:
	}
}

func (ss *shellSession) next() string {
	ss.seq++
	return ss.nonce + "-" + strconv.Itoa(ss.seq)
}

func (ss *shellSession) handshake(ctx context.Context, o ShellOptions, label string) error {
	deadline := time.Now().Add(o.OpenTimeout)
	var seen []byte
	var quiet <-chan time.Time
	total, asked := 0, -1
	for {
		wait := time.Until(deadline)
		if wait <= 0 {
			return i18n.E("ssh.shell_open", ss.host, o.OpenTimeout, label, lastLines(seen))
		}
		select {
		case b, ok := <-ss.chunks:
			if !ok {
				ss.markDead()
				return i18n.E("ssh.shell_exited", ss.host, lastLines(seen))
			}
			seen = append(seen, b...)
			if len(seen) > shellSeen {
				seen = seen[len(seen)-shellSeen:]
			}
			total += len(b)
			quiet = time.After(shellQuiet)
			continue
		case <-quiet:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			continue
		}
		quiet = nil
		line := lastLine(seen)
		if o.Ready.MatchString(line) {
			break
		}
		if o.Ask != nil && o.Prompt.MatchString(line) && total != asked {
			asked = total
			t0 := time.Now()
			answer, err := o.Ask(ctx, i18n.T("ssh.shell_prompt", ss.host, strings.TrimSpace(line)))
			if err != nil {
				return err
			}
			deadline = deadline.Add(time.Since(t0))
			ss.write(answer + "\r")
		}
	}
	ss.write(" stty raw -echo; exec sh -c 'cat | sh'\r")
	for {
		id := ss.next()
		ss.write(fmt.Sprintf("printf '\\036%s R\\n'\n", id))
		mark := []byte("\x1e" + id + " R\n")
		probe := time.After(shellProbe)
		for {
			if i := bytes.Index(ss.buf, mark); i >= 0 {
				ss.buf = append([]byte(nil), ss.buf[i+len(mark):]...)
				return nil
			}
			if len(ss.buf) > shellSeen {
				ss.buf = ss.buf[len(ss.buf)-shellSeen:]
			}
			wait := time.Until(deadline)
			if wait <= 0 {
				return i18n.E("ssh.shell_open", ss.host, o.OpenTimeout, label, lastLines(ss.buf))
			}
			select {
			case b, ok := <-ss.chunks:
				if !ok {
					ss.markDead()
					return i18n.E("ssh.shell_exited", ss.host, lastLines(ss.buf))
				}
				ss.buf = append(ss.buf, b...)
				continue
			case <-probe:
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				continue
			}
			break
		}
	}
}

func (ss *shellSession) run(ctx context.Context, cmd, stdin string, maxBytes int) (Result, error) {
	id := ss.next()
	src, in := "", " </dev/null"
	if stdin != "" {
		src, in = "printf %s '"+base64.StdEncoding.EncodeToString([]byte(stdin))+"' | base64 -d 2>/dev/null | ", ""
	}
	q := strings.ReplaceAll(cmd, "'", `'\''`)
	ss.write(fmt.Sprintf("{ printf '\\036%[1]s B'; __clotr_e=$(%[2]ssh -c '%[3]s'%[4]s 2>&1 1>&3 3>&-); __clotr_s=$?; printf '\\036%[1]s E%%s\\036%[1]s X%%d\\n' \"$__clotr_e\" \"$__clotr_s\"; } 3>&1 | cat\n", id, src, q, in))
	mark := []byte("\x1e" + id + " ")
	stdout := &limitBuffer{max: maxBytes}
	stderr := &limitBuffer{max: 8 << 10}
	phase := 0
	sink := func(b []byte) {
		switch phase {
		case 1:
			_, _ = stdout.Write(b)
		case 2:
			_, _ = stderr.Write(b)
		}
	}
	for {
		for phase < 3 {
			i := bytes.Index(ss.buf, mark)
			if i < 0 || i+len(mark) >= len(ss.buf) {
				keep := min(len(ss.buf), len(mark))
				if i >= 0 {
					keep = len(ss.buf) - i
				}
				sink(ss.buf[:len(ss.buf)-keep])
				ss.buf = ss.buf[len(ss.buf)-keep:]
				break
			}
			sink(ss.buf[:i])
			typ := ss.buf[i+len(mark)]
			ss.buf = ss.buf[i+len(mark)+1:]
			switch typ {
			case 'B':
				phase = 1
			case 'E':
				phase = 2
			case 'X':
				phase = 3
			}
		}
		if phase == 3 {
			if j := bytes.IndexByte(ss.buf, '\n'); j >= 0 {
				code, err := strconv.Atoi(strings.TrimSpace(string(ss.buf[:j])))
				ss.buf = append([]byte(nil), ss.buf[j+1:]...)
				if err != nil {
					ss.markDead()
					return Result{}, shellClosed{ss.host}
				}
				r := Result{Stdout: stdout.String(), Stderr: stderr.String(), Exit: code, Truncated: stdout.truncated}
				if r.Stderr != "" {
					r.Stderr += "\n"
				}
				return r, nil
			}
		}
		select {
		case b, ok := <-ss.chunks:
			if !ok {
				ss.markDead()
				return Result{}, shellClosed{ss.host}
			}
			ss.buf = append(ss.buf, b...)
		case <-ctx.Done():
			ss.close()
			return Result{}, ctx.Err()
		}
	}
}

func lastLine(b []byte) string {
	s := strings.ReplaceAll(shellEscapes.ReplaceAllString(string(b), ""), "\r", "")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func lastLines(b []byte) string {
	s := strings.ReplaceAll(shellEscapes.ReplaceAllString(string(b), ""), "\r", "")
	lines := strings.Split(strings.TrimRight(s, "\n "), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return Redact(strings.Join(lines, "\n"))
}
