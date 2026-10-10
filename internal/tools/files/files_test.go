package files

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func setup(t *testing.T) (*FS, string, string) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "app-site.xml"), []byte("<name>app.replicas</name>\n<value>3</value>\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "bin"), []byte{0, 1, 2}, 0o644)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("app.replicas=1\n"), 0o644)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape"))
	f, _, err := New(&config.Files{Roots: []string{root, "/nonexistent-clotr"}, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return f, root, outside
}

func call(t *testing.T, f *FS, name string, args any) (string, error) {
	data, _ := json.Marshal(args)
	for _, tl := range f.Tools() {
		if tl.Name() == name {
			return tl.Call(context.Background(), data)
		}
	}
	t.Fatalf("outil %s absent", name)
	return "", nil
}

func TestConfinement(t *testing.T) {
	f, root, outside := setup(t)
	for _, p := range []string{filepath.Join(outside, "secret"), filepath.Join(root, "..", filepath.Base(outside), "secret"), filepath.Join(root, "escape"), "relative/path"} {
		if _, err := call(t, f, "fs_read", map[string]any{"path": p}); err == nil {
			t.Errorf("lecture acceptée hors racine: %s", p)
		}
	}
	out, err := call(t, f, "fs_grep", map[string]any{"pattern": "app.replicas", "path": root})
	if err != nil || strings.Contains(out, "escape") || !strings.Contains(out, "app-site.xml:1") {
		t.Fatalf("grep: %q %v", out, err)
	}
}

func TestReadListBinary(t *testing.T) {
	f, root, _ := setup(t)
	out, err := call(t, f, "fs_read", map[string]any{"path": filepath.Join(root, "app-site.xml"), "offset": 2, "limit": 1})
	if err != nil || !strings.Contains(out, "<value>3</value>") || strings.Contains(out, "<name>") {
		t.Fatalf("read: %q %v", out, err)
	}
	if _, err := call(t, f, "fs_read", map[string]any{"path": filepath.Join(root, "sub", "bin")}); err == nil {
		t.Error("binaire accepté")
	}
	out, err = call(t, f, "fs_list", map[string]any{"path": root, "depth": 2})
	if err != nil || !strings.Contains(out, "d "+filepath.Join(root, "sub")+"/") || !strings.Contains(out, "l "+filepath.Join(root, "escape")) {
		t.Fatalf("list: %q %v", out, err)
	}
}
