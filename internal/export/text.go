package export

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"golang.org/x/text/encoding/charmap"

	"github.com/agardenat/clotr/internal/i18n"
)

const (
	minSegment = 8
	minChunk   = 20
	maxChunks  = 4
	readable   = 0.2
)

type Doc struct {
	Text     string
	Headings []string
}

func Read(format string, data []byte) (Doc, error) {
	switch format {
	case "docx":
		return docxDoc(data)
	case "pdf":
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return Doc{}, i18n.E("export.not_format", format)
		}
		return Doc{Text: pdfText(data)}, nil
	}
	return Doc{}, i18n.E("export.format", format)
}

var headingStyle = regexp.MustCompile(`(?i)heading|titre|title`)

func docxDoc(data []byte) (Doc, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Doc{}, i18n.E("export.not_format", "docx")
	}
	parts := map[string]*zip.File{}
	for _, f := range zr.File {
		dir, name := path.Split(f.Name)
		if dir == "word/" && path.Ext(name) == ".xml" {
			parts[strings.TrimSuffix(name, ".xml")] = f
		}
	}
	if parts["document"] == nil {
		return Doc{}, i18n.E("export.not_format", "docx")
	}
	styles := map[string]bool{}
	if f := parts["styles"]; f != nil {
		if err := readPart(f, func(d *xml.Decoder) error { return headingStyles(d, styles) }); err != nil {
			return Doc{}, err
		}
	}
	var doc Doc
	var b strings.Builder
	order := []string{"document"}
	for name := range parts {
		if name == "footnotes" || name == "endnotes" || strings.HasPrefix(name, "header") || strings.HasPrefix(name, "footer") {
			order = append(order, name)
		}
	}
	slices.Sort(order[1:])
	for _, name := range order {
		err := readPart(parts[name], func(d *xml.Decoder) error {
			return paragraphs(d, func(text string, heading bool) {
				b.WriteString(text)
				b.WriteByte('\n')
				if heading && name == "document" {
					doc.Headings = append(doc.Headings, text)
				}
			}, styles)
		})
		if err != nil {
			return Doc{}, err
		}
	}
	doc.Text = b.String()
	if doc.Headings == nil {
		doc.Headings = []string{}
	}
	return doc, nil
}

func readPart(f *zip.File, fn func(*xml.Decoder) error) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return fn(xml.NewDecoder(io.LimitReader(rc, MaxBytes)))
}

func attr(e xml.StartElement, local string) string {
	for _, a := range e.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func headingStyles(d *xml.Decoder, out map[string]bool) error {
	id := ""
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if e, ok := tok.(xml.StartElement); ok {
			switch e.Name.Local {
			case "style":
				id = attr(e, "styleId")
			case "name":
				if id != "" && headingStyle.MatchString(attr(e, "val")) {
					out[id] = true
				}
			case "outlineLvl":
				if id != "" {
					out[id] = true
				}
			}
		}
	}
}

func paragraphs(d *xml.Decoder, emit func(text string, heading bool), styles map[string]bool) error {
	var b strings.Builder
	inText, heading, depth := 0, false, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "p":
				depth++
				if depth == 1 {
					b.Reset()
					heading = false
				}
			case "t":
				inText++
			case "pStyle":
				v := attr(t, "val")
				heading = heading || styles[v] || headingStyle.MatchString(v)
			case "outlineLvl":
				heading = true
			case "tab":
				b.WriteByte(' ')
			case "br":
				b.WriteByte('\n')
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inText--
			case "p":
				depth--
				if depth == 0 {
					emit(b.String(), heading)
				} else {
					b.WriteByte('\n')
				}
			}
		case xml.CharData:
			if inText > 0 {
				b.Write(t)
			}
		}
	}
}

var (
	streamRe = regexp.MustCompile(`(?s)stream\r?\n`)
	filterRe = regexp.MustCompile(`/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)`)
	nameRe   = regexp.MustCompile(`/([A-Za-z0-9]+)`)
)

func pdfText(data []byte) string {
	var b strings.Builder
	for _, loc := range streamRe.FindAllIndex(data, -1) {
		if loc[0] > 0 && isNameChar(data[loc[0]-1]) {
			continue
		}
		end := bytes.Index(data[loc[1]:], []byte("endstream"))
		if end < 0 {
			continue
		}
		body := data[loc[1] : loc[1]+end]
		head := data[max(0, loc[0]-2048):loc[0]]
		if i := bytes.LastIndex(head, []byte(" obj")); i >= 0 {
			head = head[i:]
		}
		dec, ok := decodeStream(body, head)
		if ok {
			contentText(dec, &b)
		}
	}
	return b.String()
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func decodeStream(body, head []byte) ([]byte, bool) {
	var filters []string
	if m := filterRe.FindSubmatch(head); m != nil {
		for _, n := range nameRe.FindAllSubmatch(m[1], -1) {
			filters = append(filters, string(n[1]))
		}
	}
	out := body
	for _, f := range filters {
		switch f {
		case "ASCII85Decode", "A85":
			s := bytes.TrimSpace(out)
			s = bytes.TrimPrefix(s, []byte("<~"))
			if i := bytes.Index(s, []byte("~>")); i >= 0 {
				s = s[:i]
			}
			s = bytes.Map(func(r rune) rune {
				if unicode.IsSpace(r) {
					return -1
				}
				return r
			}, s)
			dst := make([]byte, 4*len(s)/5+4)
			n, _, err := ascii85.Decode(dst, s, true)
			if err != nil {
				return nil, false
			}
			out = dst[:n]
		case "ASCIIHexDecode", "AHx":
			s := bytes.Map(func(r rune) rune {
				if unicode.IsSpace(r) || r == '>' {
					return -1
				}
				return r
			}, out)
			if len(s)%2 == 1 {
				s = append(s, '0')
			}
			dst := make([]byte, len(s)/2)
			if _, err := hex.Decode(dst, s); err != nil {
				return nil, false
			}
			out = dst
		case "FlateDecode", "Fl":
			zr, err := zlib.NewReader(bytes.NewReader(out))
			if err != nil {
				return nil, false
			}
			dec, err := io.ReadAll(io.LimitReader(zr, MaxBytes))
			if err != nil && len(dec) == 0 {
				return nil, false
			}
			out = dec
		default:
			return nil, false
		}
	}
	return out, true
}

func contentText(s []byte, b *strings.Builder) {
	inText := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			for i < len(s) && s[i] != '\n' && s[i] != '\r' {
				i++
			}
		case c == 'B' && i+1 < len(s) && s[i+1] == 'T' && boundary(s, i, 2):
			inText = true
			i++
		case c == 'E' && i+1 < len(s) && s[i+1] == 'T' && boundary(s, i, 2):
			inText = false
			b.WriteByte('\n')
			i++
		case c == '(' && inText:
			var raw []byte
			raw, i = literal(s, i)
			b.WriteString(winAnsi(raw))
		case c == '<' && inText && (i+1 >= len(s) || s[i+1] != '<'):
			j := bytes.IndexByte(s[i:], '>')
			if j < 0 {
				return
			}
			hexs := bytes.Map(func(r rune) rune {
				if unicode.IsSpace(r) {
					return -1
				}
				return r
			}, s[i+1:i+j])
			if len(hexs)%2 == 1 {
				hexs = append(hexs, '0')
			}
			dst := make([]byte, len(hexs)/2)
			if _, err := hex.Decode(dst, hexs); err == nil {
				b.WriteString(winAnsi(dst))
			}
			i += j
		}
	}
}

func boundary(s []byte, i, n int) bool {
	delim := func(c byte) bool {
		return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '[' || c == ']' || c == '(' || c == ')' || c == '<' || c == '>' || c == '/'
	}
	return (i == 0 || delim(s[i-1])) && (i+n >= len(s) || delim(s[i+n]))
}

func literal(s []byte, i int) ([]byte, int) {
	var out []byte
	depth := 0
	for i++; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			i++
			if i >= len(s) {
				return out, i
			}
			switch e := s[i]; e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b', 'f':
			case '\r', '\n':
				if e == '\r' && i+1 < len(s) && s[i+1] == '\n' {
					i++
				}
			default:
				if e >= '0' && e <= '7' {
					v := 0
					k := 0
					for ; k < 3 && i+k < len(s) && s[i+k] >= '0' && s[i+k] <= '7'; k++ {
						v = v*8 + int(s[i+k]-'0')
					}
					out = append(out, byte(v))
					i += k - 1
				} else {
					out = append(out, e)
				}
			}
		case '(':
			depth++
			out = append(out, c)
		case ')':
			if depth == 0 {
				return out, i
			}
			depth--
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out, i
}

func winAnsi(b []byte) string {
	s, err := charmap.Windows1252.NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(s)
}

var webURL = regexp.MustCompile(`https?://\S+`)

func norm(s string) string {
	s = webURL.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func words(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len([]rune(w)) >= 4 {
			out[w] = true
		}
	}
	return out
}

func readableText(md, doc string) bool {
	want := words(md)
	if len(want) == 0 {
		return true
	}
	have := words(doc)
	n := 0
	for w := range want {
		if have[w] {
			n++
		}
	}
	return float64(n) >= readable*float64(len(want))
}

type Report struct {
	Checked   bool
	Missing   []string
	Moved     []string
	Flat      []string
	Artifacts []string
}

func (r Report) Issues() int {
	return len(r.Missing) + len(r.Moved) + len(r.Flat) + len(r.Artifacts)
}

var artifacts = []string{`\n`, `\t`, "**", "```", "]("}

func Compare(md string, d Doc) Report {
	segs := Segments(md)
	var all strings.Builder
	for _, s := range segs {
		all.WriteString(s.Text)
		all.WriteByte(' ')
	}
	if !readableText(all.String(), d.Text) {
		return Report{}
	}
	r := Report{Checked: true}
	hay := norm(d.Text)
	from := 0
	for _, s := range segs {
		n := norm(s.Text)
		if _, _, ok := locate(n, hay, 0); !ok {
			r.Missing = append(r.Missing, clip(s.Text, 200))
			continue
		}
		if len(n) >= minChunk {
			_, end, ok := locate(n, hay, from)
			if !ok {
				r.Moved = append(r.Moved, clip(s.Text, 200))
				continue
			}
			from = end
		}
		if s.Heading && d.Headings != nil && !slices.ContainsFunc(d.Headings, func(h string) bool { return strings.Contains(norm(h), n) }) {
			r.Flat = append(r.Flat, clip(s.Text, 200))
		}
	}
	for _, a := range artifacts {
		if strings.Count(d.Text, a) > strings.Count(all.String(), a) {
			r.Artifacts = append(r.Artifacts, a)
		}
	}
	var texts []string
	for _, s := range segs {
		texts = append(texts, s.Text)
	}
	for _, m := range lineMarkers {
		if lineStarts(strings.Split(d.Text, "\n"), m) > lineStarts(texts, m) {
			r.Artifacts = append(r.Artifacts, fmt.Sprintf("%q en début de ligne", m))
		}
	}
	return r
}

var lineMarkers = []string{"- ", "* ", "+ ", "# ", "## ", "### ", "| ", "> "}

func lineStarts(lines []string, m string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), m) {
			n++
		}
	}
	return n
}

func locate(n, hay string, from int) (int, int, bool) {
	start := -1
	for k := 0; k <= maxChunks && from <= len(hay); k++ {
		if i := strings.Index(hay[from:], n); i >= 0 {
			if start < 0 {
				start = from + i
			}
			return start, from + i + len(n), true
		}
		lo, hi := 0, len(n)
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if strings.Contains(hay[from:], n[:mid]) {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		for lo > 0 && !isRuneStart(n, lo) {
			lo--
		}
		if lo < minChunk {
			return 0, 0, false
		}
		at := from + strings.Index(hay[from:], n[:lo])
		if start < 0 {
			start = at
		}
		n, from = n[lo:], at+lo
	}
	return 0, 0, false
}

func isRuneStart(s string, i int) bool {
	return i >= len(s) || s[i]&0xC0 != 0x80
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

type Segment struct {
	Text    string
	Heading bool
}

func Segments(md string) []Segment {
	src := []byte(md)
	doc := goldmark.New(goldmark.WithExtensions(extension.Table, extension.Strikethrough)).Parser().Parse(text.NewReader(src))
	var out []Segment
	add := func(s string, heading bool) {
		if s = strings.TrimSpace(s); len(norm(s)) >= minSegment || (heading && norm(s) != "") {
			out = append(out, Segment{Text: s, Heading: heading})
		}
	}
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n.Kind() {
		case ast.KindHeading, ast.KindParagraph, ast.KindTextBlock, east.KindTableCell:
			add(inline(n, src), n.Kind() == ast.KindHeading)
			return ast.WalkSkipChildren, nil
		case ast.KindFencedCodeBlock, ast.KindCodeBlock:
			lines := n.Lines()
			for i := 0; i < lines.Len(); i++ {
				seg := lines.At(i)
				add(string(seg.Value(src)), false)
			}
			return ast.WalkSkipChildren, nil
		}
		return ast.WalkContinue, nil
	})
	return out
}

func inline(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch t := c.(type) {
		case *ast.Text:
			b.Write(t.Segment.Value(src))
			if t.SoftLineBreak() || t.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(t.Value)
		case *ast.CodeSpan:
			for g := t.FirstChild(); g != nil; g = g.NextSibling() {
				if tx, ok := g.(*ast.Text); ok {
					b.Write(tx.Segment.Value(src))
				}
			}
			return ast.WalkSkipChildren, nil
		case *ast.AutoLink, *ast.RawHTML, *ast.Image:
			return ast.WalkSkipChildren, nil
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}
