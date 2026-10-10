//go:build !windows

package progress

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCaptureStderr(t *testing.T) {
	origR, origW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer origR.Close()
	tui := &TUI{}
	out, pipe := captureStderr(origW, tui)
	if pipe == nil || tui.restore == nil {
		t.Fatal("capture non installée")
	}
	fmt.Fprintln(origW, "W1008 warning from client-go")
	buf := make([]byte, 256)
	n, _ := pipe.Read(buf)
	if !strings.Contains(string(buf[:n]), "client-go") {
		t.Fatalf("ligne non capturée: %q", buf[:n])
	}
	fmt.Fprintln(out, "board frame")
	n, _ = origR.Read(buf)
	if !strings.Contains(string(buf[:n]), "board frame") {
		t.Fatalf("sortie du tableau détournée: %q", buf[:n])
	}
	tui.restore()
	fmt.Fprintln(origW, "after restore")
	n, _ = origR.Read(buf)
	if !strings.Contains(string(buf[:n]), "after restore") {
		t.Fatalf("restauration: %q", buf[:n])
	}
}
