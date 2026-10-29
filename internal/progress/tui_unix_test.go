//go:build !windows

package progress

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestCaptureStderr(t *testing.T) {
	origR, origW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer origR.Close()
	out, pipe, restore := captureStderr(origW)
	if pipe == nil || restore == nil {
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
	restore()
	fmt.Fprintln(origW, "after restore")
	n, _ = origR.Read(buf)
	if !strings.Contains(string(buf[:n]), "after restore") {
		t.Fatalf("restauration: %q", buf[:n])
	}
}

func TestQuietInput(t *testing.T) {
	ptm, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptm.Close()
	defer tty.Close()
	echo := func() bool {
		tio, err := unix.IoctlGetTermios(int(tty.Fd()), ioctlGetTermios)
		if err != nil {
			t.Fatal(err)
		}
		return tio.Lflag&unix.ECHO != 0
	}
	if !echo() {
		t.Fatal("écho désactivé au départ")
	}
	restore := quietInput(tty)
	if echo() {
		t.Fatal("écho actif pendant le tableau : une frappe décale le rendu")
	}
	if _, err := ptm.Write([]byte("\r\r")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	discardInput(tty)
	if _, err := ptm.Write([]byte("y\r")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := tty.Read(buf)
	if err != nil || string(buf[:n]) != "y\n" {
		t.Fatalf("frappes antérieures à la question non écartées : %q %v", buf[:n], err)
	}
	restore()
	if !echo() {
		t.Fatal("écho non rétabli à la fermeture")
	}
}
