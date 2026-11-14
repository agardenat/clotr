package template

import (
	"fmt"
	"strings"

	"github.com/beevik/etree"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const xmlDeclaration = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

var xmlModule = &starlarkstruct.Module{
	Name: "xml",
	Members: starlark.StringDict{
		"parse":    starlark.NewBuiltin("xml.parse", builtinXMLParse),
		"fragment": starlark.NewBuiltin("xml.fragment", builtinXMLFragment),
		"element":  starlark.NewBuiltin("xml.element", builtinXMLElement),
		"encode":   starlark.NewBuiltin("xml.encode", builtinXMLEncode),
		"escape":   starlark.NewBuiltin("xml.escape", builtinXMLEscape),
	},
}

type xmlElement struct {
	e *etree.Element
}

var (
	_ starlark.HasAttrs   = (*xmlElement)(nil)
	_ starlark.Comparable = (*xmlElement)(nil)
)

func wrapElement(e *etree.Element) starlark.Value {
	if e == nil {
		return starlark.None
	}
	return &xmlElement{e: e}
}

func wrapElements(es []*etree.Element) *starlark.List {
	out := make([]starlark.Value, len(es))
	for i, e := range es {
		out[i] = &xmlElement{e: e}
	}
	return starlark.NewList(out)
}

func (x *xmlElement) String() string        { return "xml.element(" + x.e.FullTag() + ")" }
func (x *xmlElement) Type() string          { return "xml.element" }
func (x *xmlElement) Freeze()               {}
func (x *xmlElement) Truth() starlark.Bool  { return true }
func (x *xmlElement) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: xml.element") }

func (x *xmlElement) CompareSameType(op syntax.Token, y starlark.Value, _ int) (bool, error) {
	same := x.e == y.(*xmlElement).e
	switch op {
	case syntax.EQL:
		return same, nil
	case syntax.NEQ:
		return !same, nil
	}
	return false, fmt.Errorf("xml.element: operator %s not supported", op)
}

var xmlElementAttrs = []string{"add_next", "add_prev", "append", "attrs", "children", "copy", "encode", "find", "findall", "get", "index", "insert", "parent", "prepend", "remove", "set", "set_text", "tag", "text", "text_content", "unset"}

func (x *xmlElement) AttrNames() []string { return xmlElementAttrs }

func (x *xmlElement) Attr(name string) (starlark.Value, error) {
	e := x.e
	switch name {
	case "tag":
		return starlark.String(e.FullTag()), nil
	case "text":
		return starlark.String(e.Text()), nil
	case "parent":
		return wrapElement(e.Parent()), nil
	case "children":
		return wrapElements(e.ChildElements()), nil
	}
	fn := x.method(name)
	if fn == nil {
		return nil, nil
	}
	return starlark.NewBuiltin("xml.element."+name, fn), nil
}

type builtinFn = func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)

func (x *xmlElement) method(name string) builtinFn {
	e := x.e
	switch name {
	case "get":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var key string
			var dflt starlark.Value = starlark.None
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &key, "default?", &dflt); err != nil {
				return nil, err
			}
			if a := e.SelectAttr(key); a != nil {
				return starlark.String(a.Value), nil
			}
			return dflt, nil
		}
	case "set":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var key, val string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &key, "value", &val); err != nil {
				return nil, err
			}
			e.CreateAttr(key, val)
			return starlark.None, nil
		}
	case "unset":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var key string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &key); err != nil {
				return nil, err
			}
			e.RemoveAttr(key)
			return starlark.None, nil
		}
	case "attrs":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			d := starlark.NewDict(len(e.Attr))
			for _, a := range e.Attr {
				_ = d.SetKey(starlark.String(a.FullKey()), starlark.String(a.Value))
			}
			return d, nil
		}
	case "set_text":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var s string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &s); err != nil {
				return nil, err
			}
			e.SetText(s)
			return starlark.None, nil
		}
	case "text_content":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			var sb strings.Builder
			textContent(e, &sb)
			return starlark.String(sb.String()), nil
		}
	case "find", "findall":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var path string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &path); err != nil {
				return nil, err
			}
			p, err := etree.CompilePath(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", b.Name(), err)
			}
			if name == "find" {
				return wrapElement(e.FindElementPath(p)), nil
			}
			return wrapElements(e.FindElementsPath(p)), nil
		}
	case "index":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			p := e.Parent()
			if p == nil {
				return starlark.None, nil
			}
			for i, c := range p.ChildElements() {
				if c == e {
					return starlark.MakeInt(i), nil
				}
			}
			return starlark.None, nil
		}
	case "append", "prepend", "add_next", "add_prev":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if len(kwargs) > 0 {
				return nil, fmt.Errorf("%s: unexpected keyword arguments", b.Name())
			}
			els, err := elementArgs(b.Name(), args)
			if err != nil {
				return nil, err
			}
			for i, c := range els {
				if c == e || isAncestor(c, e) {
					return nil, fmt.Errorf("%s: an element cannot contain itself", b.Name())
				}
				switch name {
				case "append":
					e.AddChild(c)
				case "prepend":
					e.InsertChildAt(i, c)
				default:
					p := e.Parent()
					if p == nil {
						return nil, fmt.Errorf("%s: element without parent", b.Name())
					}
					ref := e
					if i > 0 {
						ref = els[i-1]
					}
					at := ref.Index()
					if name == "add_next" || i > 0 {
						at++
					}
					p.InsertChildAt(at, c)
				}
			}
			return starlark.None, nil
		}
	case "insert":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var idx int
			var child *xmlElement
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "index", &idx, "child", &child); err != nil {
				return nil, err
			}
			if child.e == e || isAncestor(child.e, e) {
				return nil, fmt.Errorf("%s: an element cannot contain itself", b.Name())
			}
			kids := e.ChildElements()
			if idx < 0 {
				idx = max(0, len(kids)+idx)
			}
			if idx >= len(kids) {
				e.AddChild(child.e)
			} else {
				e.InsertChildAt(kids[idx].Index(), child.e)
			}
			return starlark.None, nil
		}
	case "remove":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			if p := e.Parent(); p != nil {
				p.RemoveChild(e)
			}
			return starlark.None, nil
		}
	case "copy":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			return &xmlElement{e: e.Copy()}, nil
		}
	case "encode":
		return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			return starlark.String(encodeElement(e)), nil
		}
	}
	return nil
}

func isAncestor(a, e *etree.Element) bool {
	for p := e.Parent(); p != nil; p = p.Parent() {
		if p == a {
			return true
		}
	}
	return false
}

func elementArgs(name string, args starlark.Tuple) ([]*etree.Element, error) {
	var out []*etree.Element
	var add func(v starlark.Value) error
	add = func(v starlark.Value) error {
		switch t := v.(type) {
		case *xmlElement:
			out = append(out, t.e)
		case *starlark.List:
			for i := 0; i < t.Len(); i++ {
				if err := add(t.Index(i)); err != nil {
					return err
				}
			}
		case starlark.Tuple:
			for _, it := range t {
				if err := add(it); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%s: want xml.element or list of them, got %s", name, v.Type())
		}
		return nil
	}
	for _, a := range args {
		if err := add(a); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func textContent(e *etree.Element, sb *strings.Builder) {
	for _, t := range e.Child {
		switch c := t.(type) {
		case *etree.CharData:
			sb.WriteString(c.Data)
		case *etree.Element:
			textContent(c, sb)
		}
	}
}

func encodeElement(e *etree.Element) string {
	doc := etree.NewDocument()
	doc.WriteSettings = etree.WriteSettings{CanonicalText: true, CanonicalAttrVal: true}
	doc.AddChild(e.Copy())
	s, _ := doc.WriteToString()
	return s
}

func dataArg(name string, v starlark.Value) ([]byte, error) {
	switch t := v.(type) {
	case starlark.String:
		return []byte(string(t)), nil
	case starlark.Bytes:
		return []byte(string(t)), nil
	}
	return nil, fmt.Errorf("%s: want string or bytes, got %s", name, v.Type())
}

func builtinXMLParse(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	raw, err := dataArg(b.Name(), data)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", b.Name(), err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("%s: no root element", b.Name())
	}
	doc.RemoveChild(root)
	return &xmlElement{e: root}, nil
}

func builtinXMLFragment(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString("<fragment>" + text + "</fragment>"); err != nil {
		return nil, fmt.Errorf("%s: %w", b.Name(), err)
	}
	kids := doc.Root().ChildElements()
	for _, k := range kids {
		doc.Root().RemoveChild(k)
	}
	return wrapElements(kids), nil
}

func builtinXMLElement(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tag string
	var attrs *starlark.Dict
	var text starlark.Value = starlark.None
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "tag", &tag, "attrs?", &attrs, "text?", &text); err != nil {
		return nil, err
	}
	e := etree.NewElement(tag)
	if attrs != nil {
		for _, it := range attrs.Items() {
			k, ok1 := starlark.AsString(it[0])
			v, ok2 := starlark.AsString(it[1])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("%s: attrs must map strings to strings", b.Name())
			}
			e.CreateAttr(k, v)
		}
	}
	if s, ok := starlark.AsString(text); ok {
		e.SetText(s)
	} else if text != starlark.None {
		return nil, fmt.Errorf("%s: text must be a string", b.Name())
	}
	return &xmlElement{e: e}, nil
}

func builtinXMLEncode(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var el *xmlElement
	declaration := true
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "element", &el, "declaration?", &declaration); err != nil {
		return nil, err
	}
	s := encodeElement(el.e)
	if declaration {
		s = xmlDeclaration + s
	}
	return starlark.Bytes(s), nil
}

func builtinXMLEscape(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &s); err != nil {
		return nil, err
	}
	return starlark.String(xmlEscaper.Replace(s)), nil
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
