package template

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestVaultSecretOpaque(t *testing.T) {
	seed := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	yaml := "name: x\nscript: x.star\nconnectors: {}\n"
	star := `
def sign(a):
    k = vault.secret("kv/acme/cdp#private-key")
    return {"id": vault.read("kv/acme/cdp#key-id"), "type": crypto.key_type(k), "sig": base64.encode(crypto.sign(k, "msg").signature), "shown": str(k) + " " + ("%s" % k)}

def leak(a):
    return vault.secret("kv/acme/cdp#private-key")

tool(name = "sign", description = "d", schema = {"type": "object"}, fn = sign)
tool(name = "leak", description = "d", schema = {"type": "object"}, fn = leak)
tool(name = "bad", description = "d", schema = {"type": "object"}, fn = lambda a: vault.read("kv/acme/cdp"))

def discover(ctx):
    return {"targets": [{"name": "a", "kind": "a"}]}
`
	tpl := writeTemplate(t, yaml, star)
	in, err := NewInstance("v", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	in.readVault = func(_ context.Context, ref string) (string, error) {
		reads++
		switch ref {
		case "kv/acme/cdp#private-key":
			return seed, nil
		case "kv/acme/cdp#key-id":
			return "key-1", nil
		}
		return "", errors.New("absent")
	}
	tools := instanceTools(t, in)
	out, err := tools["sign"](map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "key-1" || got["type"] != "ed25519" || strings.Contains(out, seed) || got["shown"] != "<secret kv/acme/cdp#private-key> <secret kv/acme/cdp#private-key>" {
		t.Fatalf("sortie : %s", out)
	}
	if _, err := tools["sign"](map[string]any{}); err != nil || reads != 2 {
		t.Fatalf("secret relu : %d lectures, %v", reads, err)
	}
	if out, err := tools["leak"](map[string]any{}); err != nil || strings.Contains(out, seed) || !strings.Contains(out, "secret kv/acme/cdp#private-key") {
		t.Fatalf("secret renvoyé par un outil : %q %v", out, err)
	}
	if _, err := tools["bad"](map[string]any{}); err == nil || !strings.Contains(err.Error(), "path#field") {
		t.Fatalf("référence sans champ : %v", err)
	}
}
