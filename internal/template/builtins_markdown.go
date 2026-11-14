package template

import (
	"strconv"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

var markdownModule = &starlarkstruct.Module{
	Name: "markdown",
	Members: starlark.StringDict{
		"blocks": starlark.NewBuiltin("markdown.blocks", builtinMarkdownBlocks),
		"inline": starlark.NewBuiltin("markdown.inline", builtinMarkdownInline),
	},
}

var mdParser = goldmark.New(goldmark.WithExtensions(extension.Table, extension.Linkify, extension.TaskList)).Parser()

type mdStyle struct {
	bold, italic, code, strike bool
	url                        string
}

type mdRun struct {
	text  string
	style mdStyle
	br    bool
}

type mdConv struct {
	src []byte
	out []starlark.Value
}

func builtinMarkdownBlocks(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var md string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &md); err != nil {
		return nil, err
	}
	c := &mdConv{src: []byte(md)}
	doc := mdParser.Parse(text.NewReader(c.src))
	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		c.block(n, 0)
	}
	return starlark.NewList(c.out), nil
}

func builtinMarkdownInline(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var md string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &md); err != nil {
		return nil, err
	}
	c := &mdConv{src: []byte(md)}
	doc := mdParser.Parse(text.NewReader(c.src))
	var runs []mdRun
	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		if len(runs) > 0 {
			runs = append(runs, mdRun{br: true})
		}
		runs = append(runs, c.inlines(n, mdStyle{})...)
	}
	return runsValue(runs), nil
}

func mdStruct(fields starlark.StringDict) starlark.Value {
	return starlarkstruct.FromStringDict(starlark.String("markdown.block"), fields)
}

func runsValue(runs []mdRun) *starlark.List {
	runs = mergeRuns(runs)
	out := make([]starlark.Value, len(runs))
	for i, r := range runs {
		out[i] = starlarkstruct.FromStringDict(starlark.String("markdown.run"), starlark.StringDict{
			"text":   starlark.String(r.text),
			"bold":   starlark.Bool(r.style.bold),
			"italic": starlark.Bool(r.style.italic),
			"code":   starlark.Bool(r.style.code),
			"strike": starlark.Bool(r.style.strike),
			"url":    starlark.String(r.style.url),
			"br":     starlark.Bool(r.br),
		})
	}
	return starlark.NewList(out)
}

func mergeRuns(runs []mdRun) []mdRun {
	var out []mdRun
	for _, r := range runs {
		if !r.br && r.text == "" {
			continue
		}
		if n := len(out); n > 0 && !r.br && !out[n-1].br && out[n-1].style == r.style {
			out[n-1].text += r.text
			continue
		}
		out = append(out, r)
	}
	return out
}

func plainText(runs []mdRun) string {
	var sb strings.Builder
	for _, r := range runs {
		if r.br {
			sb.WriteByte('\n')
		} else {
			sb.WriteString(r.text)
		}
	}
	return sb.String()
}

func (c *mdConv) emit(kind string, fields starlark.StringDict) {
	fields["type"] = starlark.String(kind)
	c.out = append(c.out, mdStruct(fields))
}

func (c *mdConv) textFields(runs []mdRun) starlark.StringDict {
	return starlark.StringDict{"text": starlark.String(plainText(mergeRuns(runs))), "runs": runsValue(runs)}
}

func (c *mdConv) lines(n ast.Node) string {
	var sb strings.Builder
	l := n.Lines()
	for i := 0; i < l.Len(); i++ {
		seg := l.At(i)
		sb.Write(seg.Value(c.src))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (c *mdConv) block(n ast.Node, quote int) {
	switch t := n.(type) {
	case *ast.Heading:
		f := c.textFields(c.inlines(t, mdStyle{}))
		f["level"] = starlark.MakeInt(t.Level)
		c.emit("heading", f)
	case *ast.Paragraph, *ast.TextBlock:
		if img, ok := c.soleImage(n); ok {
			c.emit("image", starlark.StringDict{"src": starlark.String(img.Destination), "title": starlark.String(img.Title), "alt": starlark.String(plainText(c.inlines(img, mdStyle{})))})
			return
		}
		f := c.textFields(c.inlines(n, mdStyle{}))
		if quote > 0 {
			f["level"] = starlark.MakeInt(quote)
			c.emit("quote", f)
			return
		}
		c.emit("para", f)
	case *ast.Blockquote:
		for k := n.FirstChild(); k != nil; k = k.NextSibling() {
			c.block(k, quote+1)
		}
	case *ast.List:
		c.list(t, 1, quote)
	case *ast.FencedCodeBlock:
		c.emit("code", starlark.StringDict{"text": starlark.String(c.lines(t)), "lang": starlark.String(t.Language(c.src))})
	case *ast.CodeBlock:
		c.emit("code", starlark.StringDict{"text": starlark.String(c.lines(t)), "lang": starlark.String("")})
	case *ast.ThematicBreak:
		c.emit("rule", starlark.StringDict{})
	case *ast.HTMLBlock:
		c.emit("html", starlark.StringDict{"text": starlark.String(c.lines(t))})
	case *east.Table:
		c.table(t)
	default:
		for k := n.FirstChild(); k != nil; k = k.NextSibling() {
			c.block(k, quote)
		}
	}
}

func (c *mdConv) soleImage(n ast.Node) (*ast.Image, bool) {
	var img *ast.Image
	for k := n.FirstChild(); k != nil; k = k.NextSibling() {
		switch t := k.(type) {
		case *ast.Image:
			if img != nil {
				return nil, false
			}
			img = t
		case *ast.Text:
			continue
		default:
			return nil, false
		}
	}
	if img == nil {
		return nil, false
	}
	for k := n.FirstChild(); k != nil; k = k.NextSibling() {
		if t, ok := k.(*ast.Text); ok && strings.TrimSpace(string(t.Segment.Value(c.src))) != "" {
			return nil, false
		}
	}
	return img, true
}

func (c *mdConv) list(l *ast.List, level, quote int) {
	kind := "bullet"
	if l.IsOrdered() {
		kind = "numbered"
	}
	num := l.Start
	for item := l.FirstChild(); item != nil; item = item.NextSibling() {
		var runs []mdRun
		var rest []ast.Node
		var nested []*ast.List
		checked := starlark.Value(starlark.None)
		for k := item.FirstChild(); k != nil; k = k.NextSibling() {
			switch t := k.(type) {
			case *ast.Paragraph, *ast.TextBlock:
				if box, ok := k.FirstChild().(*east.TaskCheckBox); ok {
					checked = starlark.Bool(box.IsChecked)
				}
				if len(runs) > 0 {
					runs = append(runs, mdRun{br: true})
				}
				runs = append(runs, c.inlines(k, mdStyle{})...)
			case *ast.List:
				nested = append(nested, t)
			default:
				rest = append(rest, k)
			}
		}
		f := c.textFields(runs)
		f["level"] = starlark.MakeInt(level)
		f["quote"] = starlark.MakeInt(quote)
		f["checked"] = checked
		marker := ""
		if l.IsOrdered() {
			marker = strconv.Itoa(num) + string(l.Marker)
			num++
		}
		f["marker"] = starlark.String(marker)
		c.emit(kind, f)
		for _, k := range rest {
			c.block(k, quote)
		}
		for _, sub := range nested {
			c.list(sub, level+1, quote)
		}
	}
}

func (c *mdConv) table(t *east.Table) {
	cells := func(row ast.Node) *starlark.List {
		var out []starlark.Value
		for cell := row.FirstChild(); cell != nil; cell = cell.NextSibling() {
			runs := c.inlines(cell, mdStyle{})
			out = append(out, starlarkstruct.FromStringDict(starlark.String("markdown.cell"), c.textFields(runs)))
		}
		return starlark.NewList(out)
	}
	var header starlark.Value = starlark.NewList(nil)
	var rows []starlark.Value
	for row := t.FirstChild(); row != nil; row = row.NextSibling() {
		switch row.(type) {
		case *east.TableHeader:
			header = cells(row)
		case *east.TableRow:
			rows = append(rows, cells(row))
		}
	}
	align := make([]starlark.Value, len(t.Alignments))
	for i, a := range t.Alignments {
		s := ""
		switch a {
		case east.AlignLeft:
			s = "left"
		case east.AlignRight:
			s = "right"
		case east.AlignCenter:
			s = "center"
		}
		align[i] = starlark.String(s)
	}
	c.emit("table", starlark.StringDict{"header": header, "rows": starlark.NewList(rows), "align": starlark.NewList(align)})
}

func unescape(b []byte) string {
	return string(util.ResolveEntityNames(util.ResolveNumericReferences(util.UnescapePunctuations(b))))
}

func (c *mdConv) inlines(n ast.Node, st mdStyle) []mdRun {
	var out []mdRun
	for k := n.FirstChild(); k != nil; k = k.NextSibling() {
		out = append(out, c.inline(k, st)...)
	}
	return out
}

func (c *mdConv) inline(n ast.Node, st mdStyle) []mdRun {
	switch t := n.(type) {
	case *ast.Text:
		out := []mdRun{{text: unescape(t.Segment.Value(c.src)), style: st}}
		switch {
		case t.HardLineBreak():
			out = append(out, mdRun{br: true})
		case t.SoftLineBreak():
			out = append(out, mdRun{text: " ", style: st})
		}
		return out
	case *ast.String:
		return []mdRun{{text: string(t.Value), style: st}}
	case *ast.CodeSpan:
		var sb strings.Builder
		for k := t.FirstChild(); k != nil; k = k.NextSibling() {
			switch g := k.(type) {
			case *ast.Text:
				sb.Write(g.Segment.Value(c.src))
			case *ast.String:
				sb.Write(g.Value)
			}
		}
		s := st
		s.code = true
		return []mdRun{{text: sb.String(), style: s}}
	case *ast.Emphasis:
		s := st
		if t.Level >= 2 {
			s.bold = true
		} else {
			s.italic = true
		}
		return c.inlines(t, s)
	case *east.Strikethrough:
		s := st
		s.strike = true
		return c.inlines(t, s)
	case *ast.Link:
		s := st
		s.url = string(t.Destination)
		return c.inlines(t, s)
	case *ast.AutoLink:
		s := st
		u := string(t.URL(c.src))
		if t.AutoLinkType == ast.AutoLinkEmail && !strings.HasPrefix(strings.ToLower(u), "mailto:") {
			u = "mailto:" + u
		}
		s.url = u
		return []mdRun{{text: string(t.Label(c.src)), style: s}}
	case *ast.Image:
		alt := plainText(c.inlines(t, st))
		if alt == "" {
			alt = string(t.Destination)
		}
		return []mdRun{{text: alt, style: st}}
	case *ast.RawHTML:
		var sb strings.Builder
		for i := 0; i < t.Segments.Len(); i++ {
			seg := t.Segments.At(i)
			sb.Write(seg.Value(c.src))
		}
		raw := sb.String()
		if br := strings.ToLower(strings.ReplaceAll(raw, " ", "")); br == "<br>" || br == "<br/>" {
			return []mdRun{{br: true}}
		}
		return []mdRun{{text: raw, style: st}}
	case *east.TaskCheckBox:
		return nil
	}
	if n.HasChildren() {
		return c.inlines(n, st)
	}
	return []mdRun{{text: string(n.Text(c.src)), style: st}}
}
