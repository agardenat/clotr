package integrity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/agardenat/clotr/internal/i18n"
)

const (
	sigMagic     = "SSHSIG"
	sigNamespace = "git"
	sigBegin     = "-----BEGIN SSH SIGNATURE-----"
	sigEnd       = "-----END SSH SIGNATURE-----"
	flagVerified = 0x04
)

var skTypes = []string{ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256}

type signer struct {
	key            ssh.PublicKey
	verifyRequired bool
}

func parseAllowedSigners(data []byte) ([]signer, error) {
	var out []signer
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := parseSignerLine(line)
		if err != nil {
			return nil, fail(i18n.E("integrity.signer_line", n+1, err))
		}
		if s != nil {
			out = append(out, *s)
		}
	}
	if len(out) == 0 {
		return nil, fail(i18n.E("integrity.no_signers"))
	}
	return out, nil
}

func parseSignerLine(line string) (*signer, error) {
	rest := skipToken(line)
	key, _, options, _, err := ssh.ParseAuthorizedKey([]byte(rest))
	if err != nil {
		return nil, err
	}
	s := &signer{key: key}
	for _, o := range options {
		name, value, _ := strings.Cut(o, "=")
		switch strings.ToLower(name) {
		case "verify-required":
			s.verifyRequired = true
		case "namespaces":
			if !containsNamespace(strings.Trim(value, `"`)) {
				return nil, nil
			}
		default:
			return nil, fail(i18n.E("integrity.signer_option", name))
		}
	}
	if !isSK(key.Type()) {
		return nil, fail(i18n.E("integrity.signer_key_type", key.Type()))
	}
	return s, nil
}

func skipToken(line string) string {
	quoted := false
	for i, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case !quoted && (r == ' ' || r == '\t'):
			return strings.TrimSpace(line[i:])
		}
	}
	return ""
}

func containsNamespace(list string) bool {
	for _, ns := range strings.Split(list, ",") {
		if strings.TrimSpace(ns) == sigNamespace {
			return true
		}
	}
	return false
}

func isSK(t string) bool {
	for _, k := range skTypes {
		if t == k {
			return true
		}
	}
	return false
}

type sigBlob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

type signedData struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

func decodeArmor(armored []byte) ([]byte, error) {
	s := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(s, sigBegin) || !strings.HasSuffix(s, sigEnd) {
		return nil, errors.New("SSH signature armor")
	}
	body := strings.Join(strings.Fields(s[len(sigBegin):len(s)-len(sigEnd)]), "")
	return base64.StdEncoding.DecodeString(body)
}

func verifySignature(armored, payload []byte, keys []signer) error {
	raw, err := decodeArmor(armored)
	if err != nil {
		return fail(i18n.E("integrity.bad_signature", err))
	}
	if !bytes.HasPrefix(raw, []byte(sigMagic)) {
		return fail(i18n.E("integrity.bad_signature", errors.New("magic")))
	}
	var blob sigBlob
	if err := ssh.Unmarshal(raw[len(sigMagic):], &blob); err != nil {
		return fail(i18n.E("integrity.bad_signature", err))
	}
	if blob.Version != 1 {
		return fail(i18n.E("integrity.bad_signature", fmt.Errorf("version %d", blob.Version)))
	}
	if blob.Namespace != sigNamespace {
		return fail(i18n.E("integrity.namespace", blob.Namespace, sigNamespace))
	}
	pub, err := ssh.ParsePublicKey(blob.PublicKey)
	if err != nil {
		return fail(i18n.E("integrity.bad_signature", err))
	}
	var match *signer
	for i := range keys {
		if bytes.Equal(keys[i].key.Marshal(), pub.Marshal()) {
			match = &keys[i]
			break
		}
	}
	if match == nil {
		return fail(i18n.E("integrity.unknown_signer", trustLoc))
	}
	var digest []byte
	switch blob.HashAlg {
	case "sha256":
		h := sha256.Sum256(payload)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(payload)
		digest = h[:]
	default:
		return fail(i18n.E("integrity.bad_signature", fmt.Errorf("hash %q", blob.HashAlg)))
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(blob.Signature, &sig); err != nil {
		return fail(i18n.E("integrity.bad_signature", err))
	}
	data := append([]byte(sigMagic), ssh.Marshal(signedData{Namespace: blob.Namespace, Reserved: blob.Reserved, HashAlg: blob.HashAlg, Hash: digest})...)
	if err := match.key.Verify(data, &sig); err != nil {
		return fail(i18n.E("integrity.bad_signature", err))
	}
	if match.verifyRequired && (len(sig.Rest) < 1 || sig.Rest[0]&flagVerified == 0) {
		return fail(i18n.E("integrity.no_presence"))
	}
	return nil
}
