package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type skKey struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newSK(t *testing.T) skKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, "ssh:"})
	k, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return skKey{priv: priv, pub: k}
}

func (k skKey) line(opts string) string {
	l := "dev@example.org "
	if opts != "" {
		l += opts + " "
	}
	return l + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.pub)))
}

func (k skKey) sign(payload []byte, flags byte) []byte {
	digest := sha512.Sum512(payload)
	data := append([]byte(sigMagic), ssh.Marshal(signedData{Namespace: sigNamespace, HashAlg: "sha512", Hash: digest[:]})...)
	app := sha256.Sum256([]byte("ssh:"))
	msg := sha256.Sum256(data)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 7)
	signed := append(append(append(app[:], flags), counter...), msg[:]...)
	sig := ssh.Marshal(ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, signed), Rest: append([]byte{flags}, counter...)})
	blob := append([]byte(sigMagic), ssh.Marshal(sigBlob{Version: 1, PublicKey: k.pub.Marshal(), Namespace: sigNamespace, HashAlg: "sha512", Signature: sig})...)
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(sigBegin + "\n")
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n" + sigEnd)
	return []byte(b.String())
}

func git(t *testing.T, dir string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(gitEnv(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git absent")
	}
	dir := t.TempDir()
	git(t, dir, "", "init", "-q", "-b", "main")
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "", "add", "-A")
	return dir
}

func commit(t *testing.T, dir string, sign func([]byte) []byte) string {
	t.Helper()
	tree := git(t, dir, "", "write-tree")
	head := "tree " + tree + "\nauthor t <t@example.org> 1767225600 +0000\ncommitter t <t@example.org> 1767225600 +0000\n"
	msg := "\nmessage\n"
	obj := head + msg
	if sign != nil {
		sig := sign([]byte(obj))
		obj = head + "gpgsig " + strings.ReplaceAll(string(sig), "\n", "\n ") + "\n" + msg
	}
	oid := git(t, dir, obj, "hash-object", "-t", "commit", "-w", "--stdin")
	git(t, dir, "", "update-ref", "HEAD", oid)
	return oid
}

func activate(t *testing.T, keys ...signer) {
	t.Helper()
	mu.Lock()
	prevActive, prevSigners, prevRepos, prevExempt := active, signers, repos, exempt
	active, signers, repos, exempt = true, keys, map[string]*repo{}, false
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		active, signers, repos, exempt = prevActive, prevSigners, prevRepos, prevExempt
		mu.Unlock()
	})
}

func TestReadFileSignedCommit(t *testing.T) {
	k := newSK(t)
	dir := newRepo(t, map[string]string{"a.yaml": "name: a\n", "sub/b.star": "x = 1\n"})
	commit(t, dir, func(p []byte) []byte { return k.sign(p, 0x01) })
	activate(t, signer{key: k.pub})
	for _, f := range []string{"a.yaml", "sub/b.star"} {
		if _, err := ReadFile(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sub/b.star"), []byte("x = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(filepath.Join(dir, "sub/b.star")); !IsError(err) || !strings.Contains(err.Error(), "b.star") {
		t.Fatalf("modified file accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.yaml"), []byte("name: c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(filepath.Join(dir, "c.yaml")); !IsError(err) {
		t.Fatalf("untracked file accepted: %v", err)
	}
	if _, err := ReadFile(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestReadFileFollowsNewHead(t *testing.T) {
	k := newSK(t)
	dir := newRepo(t, map[string]string{"a.yaml": "v1\n"})
	commit(t, dir, func(p []byte) []byte { return k.sign(p, 0x01) })
	activate(t, signer{key: k.pub})
	if _, err := ReadFile(filepath.Join(dir, "a.yaml")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("v2\n"), 0o644)
	git(t, dir, "", "add", "-A")
	commit(t, dir, nil)
	if _, err := ReadFile(filepath.Join(dir, "a.yaml")); !IsError(err) {
		t.Fatalf("unsigned head accepted: %v", err)
	}
	commit(t, dir, func(p []byte) []byte { return k.sign(p, 0x01) })
	if _, err := ReadFile(filepath.Join(dir, "a.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileRefusedSignatures(t *testing.T) {
	k, other := newSK(t), newSK(t)
	cases := []struct {
		name   string
		sign   func([]byte) []byte
		signer signer
		want   string
	}{
		{"unsigned", nil, signer{key: k.pub}, "not signed"},
		{"unknown key", func(p []byte) []byte { return other.sign(p, 0x01) }, signer{key: k.pub}, "signed by a key absent from"},
		{"other payload", func(p []byte) []byte { return k.sign(append(p, 'x'), 0x01) }, signer{key: k.pub}, "invalid signature"},
		{"no touch", func(p []byte) []byte { return k.sign(p, 0x00) }, signer{key: k.pub}, "presence"},
		{"verify required", func(p []byte) []byte { return k.sign(p, 0x01) }, signer{key: k.pub, verifyRequired: true}, "without user verification"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newRepo(t, map[string]string{"a.yaml": "a\n"})
			commit(t, dir, c.sign)
			activate(t, c.signer)
			_, err := ReadFile(filepath.Join(dir, "a.yaml"))
			if !IsError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("expected %s, got %v", c.want, err)
			}
		})
	}
	dir := newRepo(t, map[string]string{"a.yaml": "a\n"})
	commit(t, dir, func(p []byte) []byte { return k.sign(p, 0x05) })
	activate(t, signer{key: k.pub, verifyRequired: true})
	if _, err := ReadFile(filepath.Join(dir, "a.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileOutsideRepo(t *testing.T) {
	activate(t)
	p := filepath.Join(t.TempDir(), "a.yaml")
	os.WriteFile(p, []byte("a"), 0o644)
	if _, err := ReadFile(p); !IsError(err) {
		t.Fatalf("file outside git accepted: %v", err)
	}
}

func TestReadFileInactive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.yaml")
	os.WriteFile(p, []byte("a"), 0o644)
	if b, err := ReadFile(p); err != nil || string(b) != "a" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestParseAllowedSigners(t *testing.T) {
	k := newSK(t)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	plain, _ := ssh.NewPublicKey(edPub)
	plainLine := "dev@example.org " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(plain)))
	got, err := parseAllowedSigners([]byte("# keys\n\n" + k.line(`namespaces="git,file",verify-required`) + "\n" + k.line(`namespaces="file"`) + "\n"))
	if err != nil || len(got) != 1 || !got[0].verifyRequired {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{plainLine, k.line("cert-authority"), k.line(`valid-before="20300101"`), "", "# only\n"} {
		if _, err := parseAllowedSigners([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRelease(t *testing.T) {
	for v, want := range map[string]bool{"v0.93.0": true, "v1.2.3-rc1": true, "dev": false, "v0.93.0-3-gabc1234": false, "v0.93.0-dirty": false, "v0.93.0-3-gabc1234-dirty": false, "abc1234": false} {
		if Release(v) != want {
			t.Errorf("%s: %v", v, !want)
		}
	}
}

func TestInit(t *testing.T) {
	k := newSK(t)
	dir := t.TempDir()
	trust := filepath.Join(dir, "allowed_signers")
	prevLoc, prevOwner, prevExe := trustLoc, ownerOK, exePath
	t.Cleanup(func() {
		trustLoc, ownerOK, exePath = prevLoc, prevOwner, prevExe
		mu.Lock()
		active = false
		mu.Unlock()
	})
	trustLoc = trust
	ownerOK = func(string) error { return nil }
	if m, err := Init("v1.0.0"); m != Off || err != nil {
		t.Fatalf("absent: %v %v", m, err)
	}
	os.WriteFile(trust, []byte(k.line("")+"\n"), 0o644)
	if m, err := Init("dev"); m != Dev || err != nil || Active() {
		t.Fatalf("dev: %v %v", m, err)
	}
	if m, err := Init("v1.0.0"); m != On || err != nil || !Active() {
		t.Fatalf("release: %v %v", m, err)
	}
	Exempt()
	if Active() {
		t.Fatal("exempt still active")
	}
	mu.Lock()
	exempt = false
	mu.Unlock()
	realTrust, _ := filepath.EvalSymlinks(trust)
	ownerOK = func(p string) error {
		if p == realTrust {
			return nil
		}
		return errors.New("writable")
	}
	prevLax := exeLax
	defer func() { exeLax = prevLax }()
	exeLax = false
	if m, err := Init("v1.0.0"); m != Off || err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable exe accepted: %v %v", m, err)
	}
	exeLax = true
	if m, err := Init("v1.0.0"); m != Partial || err == nil || !Active() {
		t.Fatalf("lax: %v %v %v", m, err, Active())
	}
	ownerOK = func(string) error { return errors.New("writable") }
	if _, err := Init("v1.0.0"); err == nil {
		t.Fatal("writable trust root accepted")
	}
}

func TestRealGitSSHSignature(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ssh-keygen -Y sign non garanti")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen absent")
	}
	keyDir := t.TempDir()
	key := filepath.Join(keyDir, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pubLine, _ := os.ReadFile(key + ".pub")
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	dir := newRepo(t, map[string]string{"a.yaml": "a\n"})
	git(t, dir, "", "-c", "gpg.format=ssh", "-c", "user.signingkey="+key, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-q", "-S", "-m", "signed\n\nbody line")
	head, err := gitHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := loadRepo(dir, head, []signer{{key: pub}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.files["a.yaml"]; !ok {
		t.Fatalf("%+v", r.files)
	}
	if _, err := loadRepo(dir, head, []signer{{key: newSK(t).pub}}); !IsError(err) {
		t.Fatalf("other key accepted: %v", err)
	}
}
