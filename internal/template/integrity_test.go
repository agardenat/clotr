package template

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agardenat/clotr/internal/integrity"
)

func TestLoadBlocksOnIntegrityError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("name: x\n"), 0o600)
	defer integrity.SetActive(true)()
	if _, err := Load(dir); !integrity.IsError(err) {
		t.Fatalf("expected a blocking integrity error, got %v", err)
	}
	os.Remove(filepath.Join(dir, "x.yaml"))
	os.WriteFile(filepath.Join(dir, "lib.star"), []byte("x = 1\n"), 0o600)
	if _, err := Load(dir); !integrity.IsError(err) {
		t.Fatalf("unverified module accepted: %v", err)
	}
}
