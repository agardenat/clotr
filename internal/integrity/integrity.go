package integrity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/agardenat/clotr/internal/i18n"
)

type Mode int

const (
	Off Mode = iota
	Dev
	On
)

type Error struct {
	err error
}

func (e *Error) Error() string { return e.err.Error() }

func (e *Error) Unwrap() error { return e.err }

func fail(err error) error {
	return &Error{err: err}
}

func IsError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

var (
	mu       sync.Mutex
	active   bool
	exempt   bool
	signers  []signer
	repos    = map[string]*repo{}
	trustLoc = TrustFile
	ownerOK  = rootOwned
	exePath  = os.Executable
)

var releaseRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
var describeRe = regexp.MustCompile(`-\d+-g[0-9a-f]{4,}(-dirty)?$|-dirty$`)

func Release(version string) bool {
	return releaseRe.MatchString(version) && !describeRe.MatchString(version)
}

func Init(version string) (Mode, error) {
	if trustLoc == "" {
		return Off, nil
	}
	if _, err := os.Lstat(trustLoc); errors.Is(err, fs.ErrNotExist) {
		return Off, nil
	} else if err != nil {
		return Off, fail(i18n.E("integrity.trust_root", trustLoc, err))
	}
	if !Release(version) {
		return Dev, nil
	}
	data, err := readTrusted(trustLoc)
	if err != nil {
		return Off, fail(i18n.E("integrity.trust_root", trustLoc, err))
	}
	keys, err := parseAllowedSigners(data)
	if err != nil {
		return Off, fail(i18n.E("integrity.trust_root", trustLoc, err))
	}
	exe, err := exePath()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return Off, fail(i18n.E("integrity.exe", exe, err))
	}
	if err := ownerOK(exe); err != nil {
		return Off, fail(i18n.E("integrity.exe", exe, err))
	}
	mu.Lock()
	active, signers, repos = true, keys, map[string]*repo{}
	mu.Unlock()
	return On, nil
}

func Active() bool {
	mu.Lock()
	defer mu.Unlock()
	return active && !exempt
}

func Exempt() {
	mu.Lock()
	exempt = true
	mu.Unlock()
}

func readTrusted(path string) ([]byte, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fail(i18n.E("integrity.not_regular", real))
	}
	if err := ownerOK(real); err != nil {
		return nil, err
	}
	data := make([]byte, st.Size())
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return data, nil
}

func ReadFile(path string) ([]byte, error) {
	if !Active() {
		return os.ReadFile(path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if real, err = filepath.Abs(real); err != nil {
		return nil, err
	}
	root := gitRoot(real)
	if root == "" {
		return nil, fail(i18n.E("integrity.no_repo", path))
	}
	rel, err := filepath.Rel(root, real)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, err
	}
	r, err := verified(root, false)
	if err != nil {
		return nil, err
	}
	if err := r.check(path, root, filepath.ToSlash(rel), data); err == nil {
		return data, nil
	}
	if r, err = verified(root, true); err != nil {
		return nil, err
	}
	if err := r.check(path, root, filepath.ToSlash(rel), data); err != nil {
		return nil, err
	}
	return data, nil
}

func (r *repo) check(path, root, rel string, data []byte) error {
	e, ok := r.files[rel]
	if !ok || (e.mode != "100644" && e.mode != "100755") {
		return fail(i18n.E("integrity.untracked", path, short(r.head), root))
	}
	if objectID("blob", data, len(e.oid)) != e.oid {
		return fail(i18n.E("integrity.modified", path, short(r.head), root))
	}
	return nil
}

func gitRoot(path string) string {
	dir := filepath.Dir(path)
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func verified(root string, refresh bool) (*repo, error) {
	mu.Lock()
	r, ok := repos[root]
	keys := signers
	mu.Unlock()
	if ok && !refresh {
		return r, nil
	}
	head, err := gitHead(root)
	if err != nil {
		return nil, fail(i18n.E("integrity.git", root, err))
	}
	if ok && r.head == head {
		return r, nil
	}
	r, err = loadRepo(root, head, keys)
	if err != nil {
		return nil, err
	}
	mu.Lock()
	repos[root] = r
	mu.Unlock()
	return r, nil
}

func short(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}

func Overlay(path, key string) error {
	return fail(i18n.E("integrity.overlay_key", path, key))
}

func SetActive(on bool) (restore func()) {
	mu.Lock()
	prev, prevExempt := active, exempt
	active, exempt = on, false
	mu.Unlock()
	return func() {
		mu.Lock()
		active, exempt = prev, prevExempt
		mu.Unlock()
	}
}
