package integrity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

var (
	gitBin     = "git"
	gitTimeout = 30 * time.Second
	maxObject  = 64 << 20
)

type entry struct {
	mode string
	oid  string
}

type repo struct {
	head  string
	files map[string]entry
}

func gitEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			out = append(out, kv)
		}
	}
	return append(out, "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
}

func gitHead(root string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitBin, "-C", root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	head := strings.TrimSpace(string(out))
	if !validOID(head) {
		return "", fmt.Errorf("git rev-parse HEAD: %q", head)
	}
	return head, nil
}

func validOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func objectID(kind string, data []byte, hexLen int) string {
	var h hash.Hash
	if hexLen == 64 {
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

type batch struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	cancel context.CancelFunc
}

func openBatch(root string) (*batch, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	cmd := exec.CommandContext(ctx, gitBin, "-C", root, "cat-file", "--batch")
	cmd.Env = gitEnv()
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	return &batch{cmd: cmd, in: in, out: bufio.NewReader(out), cancel: cancel}, nil
}

func (b *batch) close() {
	b.in.Close()
	b.cmd.Wait()
	b.cancel()
}

func (b *batch) get(oid, kind string) ([]byte, error) {
	if _, err := io.WriteString(b.in, oid+"\n"); err != nil {
		return nil, err
	}
	line, err := b.out.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("git cat-file %s: %w", short(oid), err)
	}
	f := strings.Fields(line)
	if len(f) != 3 || f[0] != oid || f[1] != kind {
		return nil, fmt.Errorf("git cat-file %s: %s", short(oid), strings.TrimSpace(line))
	}
	size, err := strconv.Atoi(f[2])
	if err != nil || size < 0 || size > maxObject {
		return nil, fmt.Errorf("git cat-file %s: %s", short(oid), strings.TrimSpace(line))
	}
	buf := make([]byte, size+1)
	if _, err := io.ReadFull(b.out, buf); err != nil {
		return nil, fmt.Errorf("git cat-file %s: %w", short(oid), err)
	}
	data := buf[:size]
	if objectID(kind, data, len(oid)) != oid {
		return nil, fail(i18n.E("integrity.object", oid))
	}
	return data, nil
}

func loadRepo(root, head string, keys []signer) (*repo, error) {
	b, err := openBatch(root)
	if err != nil {
		return nil, fail(i18n.E("integrity.git", root, err))
	}
	defer b.close()
	raw, err := b.get(head, "commit")
	if err != nil {
		return nil, wrapGit(root, err)
	}
	tree, payload, sig, err := splitCommit(raw, len(head))
	if err != nil {
		return nil, fail(i18n.E("integrity.unsigned", short(head), root, err))
	}
	if sig == nil {
		return nil, fail(i18n.E("integrity.unsigned", short(head), root, i18n.E("integrity.no_signature")))
	}
	if err := verifySignature(sig, payload, keys); err != nil {
		return nil, fail(i18n.E("integrity.unsigned", short(head), root, err))
	}
	r := &repo{head: head, files: map[string]entry{}}
	if err := walkTree(b, tree, "", r.files); err != nil {
		return nil, wrapGit(root, err)
	}
	return r, nil
}

func wrapGit(root string, err error) error {
	if IsError(err) {
		return err
	}
	return fail(i18n.E("integrity.git", root, err))
}

func splitCommit(raw []byte, hexLen int) (tree string, payload, sig []byte, err error) {
	end := bytes.Index(raw, []byte("\n\n"))
	header, rest := raw, []byte(nil)
	if end >= 0 {
		header, rest = raw[:end], raw[end:]
	}
	want := "gpgsig "
	if hexLen == 64 {
		want = "gpgsig-sha256 "
	}
	var kept [][]byte
	var found *bytes.Buffer
	inSig := false
	for i, line := range bytes.Split(header, []byte("\n")) {
		if inSig && len(line) > 0 && line[0] == ' ' {
			found.Write(line[1:])
			found.WriteByte('\n')
			continue
		}
		inSig = false
		switch {
		case bytes.HasPrefix(line, []byte(want)):
			if found != nil {
				return "", nil, nil, errors.New(strings.TrimSpace(want))
			}
			found = &bytes.Buffer{}
			found.Write(line[len(want):])
			found.WriteByte('\n')
			inSig = true
			continue
		case i == 0 && bytes.HasPrefix(line, []byte("tree ")):
			tree = string(line[5:])
		}
		kept = append(kept, line)
	}
	if !validOID(tree) || len(tree) != hexLen {
		return "", nil, nil, fmt.Errorf("tree %q", tree)
	}
	payload = append(bytes.Join(kept, []byte("\n")), rest...)
	if found != nil {
		sig = found.Bytes()
	}
	return tree, payload, sig, nil
}

func walkTree(b *batch, oid, prefix string, files map[string]entry) error {
	data, err := b.get(oid, "tree")
	if err != nil {
		return err
	}
	raw := len(oid) / 2
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp < 0 {
			return fmt.Errorf("tree %s", short(oid))
		}
		nul := bytes.IndexByte(data[sp+1:], 0)
		if nul < 0 || len(data) < sp+1+nul+1+raw {
			return fmt.Errorf("tree %s", short(oid))
		}
		mode := string(data[:sp])
		name := string(data[sp+1 : sp+1+nul])
		id := hex.EncodeToString(data[sp+1+nul+1 : sp+1+nul+1+raw])
		data = data[sp+1+nul+1+raw:]
		if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
			return fmt.Errorf("tree %s: %q", short(oid), name)
		}
		path := prefix + name
		switch mode {
		case "40000":
			if err := walkTree(b, id, path+"/", files); err != nil {
				return err
			}
		case "160000":
		default:
			files[path] = entry{mode: mode, oid: id}
		}
	}
	return nil
}
