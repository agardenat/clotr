package export

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

const MaxBytes = 100 << 20

const pdfTimeout = 3 * time.Minute

const convertMacro = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">
Sub Convert(src As String, dst As String)
  Dim load(0) As New com.sun.star.beans.PropertyValue
  load(0).Name = "Hidden"
  load(0).Value = True
  doc = StarDesktop.loadComponentFromURL(ConvertToURL(src), "_blank", 0, load())
  For pass = 1 To 2
    doc.getTextFields().refresh()
    idx = doc.getDocumentIndexes()
    For i = 0 To idx.getCount() - 1
      idx.getByIndex(i).update()
    Next i
  Next pass
  Dim store(0) As New com.sun.star.beans.PropertyValue
  store(0).Name = "FilterName"
  store(0).Value = "writer_pdf_Export"
  doc.storeToURL(ConvertToURL(dst), store())
  doc.close(True)
  StarDesktop.terminate()
End Sub
</script:module>
`

func officeCandidates() []string {
	switch runtime.GOOS {
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
			if d := os.Getenv(env); d != "" {
				out = append(out, filepath.Join(d, "LibreOffice", "program", "soffice.exe"))
			}
		}
		return out
	case "darwin":
		return []string{"/Applications/LibreOffice.app/Contents/MacOS/soffice"}
	}
	return nil
}

func Office() (string, error) {
	for _, name := range []string{"soffice", "libreoffice"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range officeCandidates() {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", i18n.E("export.no_office")
}

func fileURL(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

func PDF(ctx context.Context, docx []byte) ([]byte, error) {
	bin, err := Office()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "clotr-pdf-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "report.docx")
	dst := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(src, docx, 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, pdfTimeout)
	defer cancel()
	profile := "-env:UserInstallation=" + fileURL(filepath.Join(dir, "profile"))
	var out bytes.Buffer
	init := exec.CommandContext(ctx, bin, "--headless", "--norestore", "--terminate_after_init", profile)
	init.Stdout, init.Stderr = &out, &out
	runErr := init.Run()
	if runErr == nil {
		runErr = os.WriteFile(filepath.Join(dir, "profile", "user", "basic", "Standard", "Module1.xba"), []byte(convertMacro), 0o600)
	}
	if runErr == nil {
		macro := `macro:///Standard.Module1.Convert("` + src + `","` + dst + `")`
		cmd := exec.CommandContext(ctx, bin, "--headless", "--invisible", "--norestore", "--nologo", "--nodefault", "--nolockcheck", profile, macro)
		cmd.Stdout, cmd.Stderr = &out, &out
		runErr = cmd.Run()
	}
	data, err := os.ReadFile(dst)
	if err != nil || len(data) == 0 {
		msg := strings.TrimSpace(out.String())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			msg = i18n.T("export.office_timeout", pdfTimeout)
		} else if runErr != nil && msg == "" {
			msg = runErr.Error()
		} else if msg == "" {
			msg = i18n.T("export.office_empty")
		}
		return nil, i18n.E("export.office_failed", msg)
	}
	return data, nil
}
