package markdown

import (
	"os"
	"strings"

	"charm.land/glamour/v2"
	"charm.land/glamour/v2/styles"
)

func Style(dark bool) string {
	if s := os.Getenv("GLAMOUR_STYLE"); s != "" {
		return s
	}
	if dark {
		return styles.DarkStyle
	}
	return styles.LightStyle
}

func Render(md string, width int, dark bool) string {
	r, err := glamour.NewTermRenderer(glamour.WithStylePath(Style(dark)), glamour.WithWordWrap(max(width-4, 20)), glamour.WithTableWrap(true))
	if err != nil {
		return md
	}
	out, err := r.Render(md)
	if err != nil {
		return md
	}
	return strings.Trim(out, "\n")
}
