package filelock

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestLockSerializesProcesses(t *testing.T) {
	if os.Getenv("FILELOCK_CHILD") != "" {
		f, err := Open(os.Getenv("FILELOCK_PATH"))
		if err != nil {
			t.Fatal(err)
		}
		for range 200 {
			if err := Lock(f); err != nil {
				t.Fatal(err)
			}
			data, err := ReadLocked(f)
			if err != nil {
				t.Fatal(err)
			}
			n, _ := strconv.Atoi(string(data))
			if err := WriteLocked(f, []byte(strconv.Itoa(n+1))); err != nil {
				t.Fatal(err)
			}
			if err := Unlock(f); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	path := filepath.Join(t.TempDir(), "sub", "counter")
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Go(func() {
			cmd := exec.Command(os.Args[0], "-test.run=^TestLockSerializesProcesses$", "-test.count=1")
			cmd.Env = append(os.Environ(), "FILELOCK_CHILD=1", "FILELOCK_PATH="+path)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs[i] = &childError{err, string(out)}
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "600" {
		t.Fatalf("compteur partagé : %s, attendu 600", data)
	}
}

type childError struct {
	err error
	out string
}

func (e *childError) Error() string { return e.err.Error() + "\n" + e.out }
