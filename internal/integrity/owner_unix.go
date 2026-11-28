//go:build unix

package integrity

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/agardenat/clotr/internal/i18n"
)

const TrustFile = "/etc/clotr/allowed_signers"

func rootOwned(path string) error {
	p := path
	for {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
			return fail(i18n.E("integrity.not_root", p))
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
