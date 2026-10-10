package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	Path string
}

func Open(dir, runID string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, runID+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, enc: json.NewEncoder(f), Path: path}, nil
}

func Nop() *Logger {
	return &Logger{}
}

func (l *Logger) Log(kind string, fields map[string]any) {
	if l == nil || l.f == nil {
		return
	}
	rec := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		rec[k] = v
	}
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["kind"] = kind
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(rec)
}

func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
