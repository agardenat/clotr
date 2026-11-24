package creds

import (
	"context"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/vault"
)

var storeRoot string

func UseVaultStore(root string) {
	mu.Lock()
	defer mu.Unlock()
	storeRoot = strings.Trim(strings.TrimSpace(root), "/")
}

var storeRead = func(ctx context.Context, path string) (map[string]string, error) {
	c, err := vault.FromEnv()
	if err != nil {
		return nil, err
	}
	return c.ReadData(ctx, path)
}

var storeWrite = func(ctx context.Context, path string, data map[string]string) error {
	c, err := vault.FromEnv()
	if err != nil {
		return err
	}
	return c.Write(ctx, path, data)
}

var storeDelete = func(ctx context.Context, path string) error {
	c, err := vault.FromEnv()
	if err != nil {
		return err
	}
	return c.Delete(ctx, path)
}

func storePath(root, label string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(label) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	name := strings.TrimRight(b.String(), "-")
	if name == "" {
		name = "default"
	}
	return root + "/" + name
}

func storeLoad(ctx context.Context, label string) (Pair, bool, error) {
	data, err := storeRead(ctx, storePath(storeRoot, label))
	if err != nil || data == nil || data["label"] != label || data["password"] == "" {
		return Pair{}, false, err
	}
	return Pair{User: data["username"], Pass: data["password"]}, true, nil
}

func storeSave(ctx context.Context, label string, p Pair) {
	data := map[string]string{"label": label, "password": p.Pass, "saved_at": time.Now().UTC().Format(time.RFC3339)}
	if p.User != "" {
		data["username"] = p.User
	}
	_ = storeWrite(ctx, storePath(storeRoot, label), data)
}

func storeDrop(label string) {
	mu.Lock()
	root := storeRoot
	mu.Unlock()
	if root == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = storeDelete(ctx, storePath(root, label))
}
