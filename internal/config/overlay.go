package config

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/agardenat/clotr/internal/i18n"
)

const removeTag = "!remove"

var identityKeys = []string{"name", "alias"}

func LocalDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "local")
}

func readOverlay(path string, target any) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, i18n.E("config.local", path, err)
	}
	return data, nil
}

func mergeYAML(base, over []byte) ([]byte, error) {
	var b, o yaml.Node
	if err := yaml.Unmarshal(base, &b); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(over, &o); err != nil {
		return nil, err
	}
	if len(o.Content) == 0 {
		return base, nil
	}
	if len(b.Content) == 0 {
		return yaml.Marshal(clean(o.Content[0]))
	}
	return yaml.Marshal(mergeNode(b.Content[0], o.Content[0]))
}

func mergeNode(b, o *yaml.Node) *yaml.Node {
	if b.Kind == yaml.AliasNode && b.Alias != nil {
		b = b.Alias
	}
	switch {
	case b.Kind == yaml.MappingNode && o.Kind == yaml.MappingNode:
		out := &yaml.Node{Kind: yaml.MappingNode, Tag: b.Tag, Anchor: b.Anchor, Content: slices.Clone(b.Content)}
		for i := 0; i+1 < len(o.Content); i += 2 {
			k, v := o.Content[i], o.Content[i+1]
			j := mapIndex(out, k.Value)
			switch {
			case isNull(v):
				if j >= 0 {
					out.Content = slices.Delete(out.Content, j, j+2)
				}
			case j >= 0:
				out.Content[j+1] = mergeNode(out.Content[j+1], v)
			default:
				out.Content = append(out.Content, k, clean(v))
			}
		}
		return out
	case b.Kind == yaml.SequenceNode && o.Kind == yaml.SequenceNode:
		key := identity(b, o)
		if key == "" {
			return clean(o)
		}
		out := &yaml.Node{Kind: yaml.SequenceNode, Tag: b.Tag, Anchor: b.Anchor, Content: slices.Clone(b.Content)}
		for _, item := range o.Content {
			id := field(item, key)
			j := slices.IndexFunc(out.Content, func(n *yaml.Node) bool { return field(n, key) == id })
			switch {
			case item.Tag == removeTag:
				if j >= 0 {
					out.Content = slices.Delete(out.Content, j, j+1)
				}
			case j >= 0:
				out.Content[j] = mergeNode(out.Content[j], item)
			default:
				out.Content = append(out.Content, clean(item))
			}
		}
		return out
	}
	return clean(o)
}

func clean(n *yaml.Node) *yaml.Node {
	out := *n
	if n.Tag == removeTag {
		out.Tag = ""
	}
	out.Content = nil
	for i, c := range n.Content {
		if n.Kind == yaml.SequenceNode && c.Tag == removeTag {
			continue
		}
		if n.Kind == yaml.MappingNode && i%2 == 1 && isNull(c) {
			out.Content = out.Content[:len(out.Content)-1]
			continue
		}
		out.Content = append(out.Content, clean(c))
	}
	return &out
}

func identity(b, o *yaml.Node) string {
	items := append(slices.Clone(b.Content), o.Content...)
	if len(items) == 0 {
		return ""
	}
	for _, key := range identityKeys {
		if !slices.ContainsFunc(items, func(n *yaml.Node) bool { return field(n, key) == "" }) {
			return key
		}
	}
	return ""
}

func field(n *yaml.Node, key string) string {
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if n.Kind != yaml.MappingNode {
		return ""
	}
	if j := mapIndex(n, key); j >= 0 && n.Content[j+1].Kind == yaml.ScalarNode {
		return n.Content[j+1].Value
	}
	return ""
}

func mapIndex(n *yaml.Node, key string) int {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}
