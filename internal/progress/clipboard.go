package progress

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func clipboardCommands() [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"pbcopy"}}
	case "windows":
		return [][]string{{"clip.exe"}}
	}
	var cmds [][]string
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		cmds = append(cmds, []string{"wl-copy"})
	}
	if os.Getenv("DISPLAY") != "" {
		cmds = append(cmds, []string{"xclip", "-selection", "clipboard"}, []string{"xsel", "--clipboard", "--input"})
	}
	return cmds
}

func copyExternal(text string) string {
	for _, c := range clipboardCommands() {
		path, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, path, c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		err = cmd.Run()
		cancel()
		if err == nil {
			return c[0]
		}
	}
	return "OSC 52"
}
