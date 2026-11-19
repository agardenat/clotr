package filelock

import (
	"os"
	"path/filepath"
)

func Open(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

func ReadLocked(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	data := make([]byte, st.Size())
	n, err := f.ReadAt(data, 0)
	if n == len(data) {
		err = nil
	}
	return data[:n], err
}

func WriteLocked(f *os.File, data []byte) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err := f.WriteAt(data, 0)
	return err
}
