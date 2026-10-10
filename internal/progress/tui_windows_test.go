//go:build windows

package progress

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCaptureStderr(t *testing.T) {
	orig := os.Stderr
	defer func() { os.Stderr = orig }()
	out, pipe, restore := captureStderr(os.Stderr)
	if pipe == nil || restore == nil || out != orig {
		t.Fatal("capture non installée")
	}
	fmt.Fprintln(os.Stderr, "W1008 warning from client-go")
	buf := make([]byte, 256)
	n, _ := pipe.Read(buf)
	if !strings.Contains(string(buf[:n]), "client-go") {
		t.Fatalf("ligne non capturée: %q", buf[:n])
	}
	restore()
	if os.Stderr != orig {
		t.Fatal("os.Stderr non restauré")
	}
}
