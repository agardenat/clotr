package template

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/tools"
)

type kind struct {
	ssh   bool
	build func(in *Instance, name, desc string) tools.Tool
}

var kinds = map[string]kind{
	"inventory": {false, inventoryTool},
	"ssh_list":  {true, sshListTool},
	"ssh_read":  {true, sshReadTool},
	"ssh_tail":  {true, sshTailTool},
	"ssh_grep":  {true, sshGrepTool},
	"ssh_disk":  {true, sshDiskTool},
	"log_stats": {true, logStatsTool},
}

type fnTool struct {
	name, desc string
	schema     string
	call       func(ctx context.Context, raw json.RawMessage) (string, error)
}

func (t fnTool) Name() string            { return t.name }
func (t fnTool) Description() string     { return t.desc }
func (t fnTool) Schema() json.RawMessage { return json.RawMessage(t.schema) }
func (t fnTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	return t.call(ctx, raw)
}

func (in *Instance) Tools() []tools.Tool {
	var out []tools.Tool
	if in.script != nil {
		for _, st := range in.script.tools {
			out = append(out, in.scriptToolAdapter(st))
		}
	}
	for _, ts := range in.T.Tools {
		out = append(out, kinds[ts.Kind].build(in, in.Name+"_"+ts.ToolName(), ts.Description))
	}
	for i, t := range out {
		out[i] = activatingTool{t, in}
	}
	return out
}

type activatingTool struct {
	tools.Tool
	in *Instance
}

func (t activatingTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	if err := t.in.ensure(); err != nil {
		return "", err
	}
	return t.Tool.Call(ctx, raw)
}

func (in *Instance) scriptToolAdapter(st *scriptTool) tools.Tool {
	name := in.Name + "_" + st.name
	desc := ""
	if s, ok := st.desc.(starlark.String); ok {
		desc = string(s)
	} else if fn, ok := st.desc.(starlark.Callable); ok {
		v, err := in.call(context.Background(), st.name, fn)
		if err != nil {
			desc = "(description indisponible : " + scriptErr(err).Error() + ")"
		} else if s, ok := starlark.AsString(v); ok {
			desc = s
		}
	}
	return fnTool{
		name:   name,
		desc:   desc,
		schema: string(st.schema),
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			if len(raw) == 0 {
				raw = json.RawMessage("{}")
			}
			args, err := jsonToStarlark(raw)
			if err != nil {
				return "", fmt.Errorf("arguments JSON invalides: %w", err)
			}
			if _, ok := args.(*starlark.Dict); !ok {
				return "", fmt.Errorf("arguments: objet JSON attendu")
			}
			v, err := in.call(ctx, st.name, st.fn, args)
			if err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				return "", scriptErr(err)
			}
			if s, ok := v.(starlark.String); ok {
				return string(s), nil
			}
			b, err := starlarkJSON(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}
}

func (in *Instance) targetNames() string {
	var n []string
	for _, t := range in.Reachable() {
		n = append(n, t.Name)
	}
	return strings.Join(n, ", ")
}

func withDesc(desc, def string) string {
	if desc != "" {
		return desc
	}
	return def
}

func inventoryTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, fmt.Sprintf("Inventaire découvert de l'instance %s : cibles (%s), statut, hôtes (nom, IP, groupe, état, rôles) et données de découverte.\nSans argument : résumé par cible. Avec target : détail complet de la cible ; host filtre les hôtes.", in.Name, in.targetNames())),
		schema: `{"type":"object","properties":{"target":{"type":"string","description":"nom de la cible"},"host":{"type":"string","description":"nom complet, nom court ou IP"}}}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct{ Target, Host string }](raw)
			if err != nil {
				return "", err
			}
			inv := in.inv
			if a.Target == "" && a.Host == "" {
				type sum struct {
					Name    string `json:"name"`
					Kind    string `json:"kind"`
					Status  string `json:"status,omitempty"`
					Error   string `json:"error,omitempty"`
					Summary string `json:"summary,omitempty"`
					Hosts   int    `json:"hosts"`
				}
				var out []sum
				for _, t := range inv.Targets {
					out = append(out, sum{t.Name, t.Kind, t.Status, t.Error, t.Summary, len(t.Hosts)})
				}
				b, _ := json.Marshal(map[string]any{"discovered_at": inv.DiscoveredAt, "lines": inv.Lines, "targets": out, "warnings": inv.Warnings})
				return string(b), nil
			}
			var targets []*Target
			if a.Target != "" {
				t, err := in.target(a.Target)
				if err != nil {
					return "", err
				}
				targets = []*Target{t}
			} else {
				targets = inv.Targets
			}
			var out []*Target
			for _, t := range targets {
				c := *t
				if a.Host != "" {
					c.Hosts = nil
					for _, h := range t.Hosts {
						if strings.EqualFold(h.Name, a.Host) || h.IP == a.Host || strings.EqualFold(strings.SplitN(h.Name, ".", 2)[0], a.Host) {
							c.Hosts = append(c.Hosts, h)
						}
					}
					if len(c.Hosts) == 0 {
						continue
					}
				}
				out = append(out, &c)
			}
			b, _ := json.Marshal(out)
			return string(b), nil
		},
	}
}

const (
	maxRead      = 64 << 10
	maxLines     = 1000
	statsDefault = 4 << 20
	statsMax     = 16 << 20
)

func clamp(v, def, lo, hi int) int {
	if v == 0 {
		v = def
	}
	return max(lo, min(v, hi))
}

const hostProps = `"target":{"type":"string","description":"cible (optionnel si l'hôte est unique)"},"host":{"type":"string","description":"FQDN, nom court ou IP d'un hôte de l'inventaire"}`

func (in *Instance) pathsDesc() string {
	return fmt.Sprintf("Chemins autorisés : %s ; refusés : %s.", strings.Join(in.T.SSHPaths.Allow, ", "), strings.Join(in.T.SSHPaths.Deny, ", "))
}

func sshListTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Liste un répertoire sur un hôte en SSH (lecture seule, find) : type (f/d/l), taille, date de modification, chemin.\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"répertoire absolu"},"depth":{"type":"integer","description":"profondeur (défaut 1, max 4)"},"sort":{"type":"string","enum":["name","size","mtime"],"description":"tri : size (plus gros d'abord), mtime (plus récents d'abord)"}},"required":["host","path"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target, Host, Path, Sort string
				Depth                    int
			}](raw)
			if err != nil {
				return "", err
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			res, err := in.remote(ctx, name, t, h, in.builder().List(p, clamp(a.Depth, 1, 1, 4), 500, a.Sort), maxRead)
			if err != nil {
				return "", err
			}
			return format(res)
		},
	}
}

func sshReadTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Lit un fichier texte sur un hôte en SSH (lecture seule), en entier (64 Kio max) ou une plage de lignes. Les valeurs de secrets (password, secret, token…) sont masquées.\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"fichier absolu"},"from_line":{"type":"integer"},"to_line":{"type":"integer"}},"required":["host","path"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target   string `json:"target"`
				Host     string `json:"host"`
				Path     string `json:"path"`
				FromLine int    `json:"from_line"`
				ToLine   int    `json:"to_line"`
			}](raw)
			if err != nil {
				return "", err
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			res, err := in.remote(ctx, name, t, h, in.builder().Read(p, max(a.FromLine, 0), max(a.ToLine, 0), maxRead), maxRead+1024)
			if err != nil {
				return "", err
			}
			return format(res)
		},
	}
}

func sshTailTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Dernières lignes d'un fichier (log) sur un hôte en SSH (lecture seule).\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"fichier absolu"},"lines":{"type":"integer","description":"nombre de lignes (défaut 200, max 1000)"}},"required":["host","path"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target, Host, Path string
				Lines              int
			}](raw)
			if err != nil {
				return "", err
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			res, err := in.remote(ctx, name, t, h, in.builder().Tail(p, clamp(a.Lines, 200, 1, maxLines)), maxRead*4)
			if err != nil {
				return "", err
			}
			return format(res)
		},
	}
}

func sshGrepTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Recherche une expression régulière étendue (grep -E) dans un fichier ou, avec recursive, un répertoire, sur un hôte en SSH (lecture seule). Les fichiers binaires et les fichiers refusés sont ignorés.\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"fichier ou répertoire absolu"},"pattern":{"type":"string","description":"expression régulière étendue"},"ignore_case":{"type":"boolean"},"recursive":{"type":"boolean"},"max_matches":{"type":"integer","description":"correspondances max par fichier (défaut 50, max 500)"}},"required":["host","path","pattern"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target     string `json:"target"`
				Host       string `json:"host"`
				Path       string `json:"path"`
				Pattern    string `json:"pattern"`
				IgnoreCase bool   `json:"ignore_case"`
				Recursive  bool   `json:"recursive"`
				MaxMatches int    `json:"max_matches"`
			}](raw)
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(a.Pattern) == "" || strings.ContainsAny(a.Pattern, "\n\r\x00") {
				return "", fmt.Errorf("pattern invalide")
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			res, err := in.remote(ctx, name, t, h, in.builder().Grep(p, a.Pattern, a.IgnoreCase, a.Recursive, clamp(a.MaxMatches, 50, 1, 500), in.rules.ExcludeGlobs(), maxRead), maxRead+1024)
			if err != nil {
				return "", err
			}
			if res.Exit == 1 && strings.TrimSpace(res.Stdout) == "" {
				return "aucune correspondance", nil
			}
			return format(res, 1)
		},
	}
}

func sshDiskTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Volumétrie d'un répertoire sur un hôte en SSH (lecture seule) : occupation du système de fichiers (df), taille des sous-répertoires triée (du), nombre de fichiers. Point d'entrée pour un problème de volume de logs ou de disque.\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"répertoire absolu, ex: /var/log"},"depth":{"type":"integer","description":"profondeur du du (défaut 2, max 4)"}},"required":["host","path"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target, Host, Path string
				Depth              int
			}](raw)
			if err != nil {
				return "", err
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			res, err := in.remote(ctx, name, t, h, in.builder().Disk(p, clamp(a.Depth, 2, 1, 4), 40), maxRead)
			if err != nil {
				return "", err
			}
			return format(res)
		},
	}
}

func logStatsTool(in *Instance, name, desc string) tools.Tool {
	return fnTool{
		name:   name,
		desc:   withDesc(desc, "Statistiques d'un fichier de log sur un hôte en SSH (lecture seule), calculées sur sa fin (4 Mio par défaut) : taille, période couverte, débit (lignes et octets par heure), répartition par niveau et par heure, loggers les plus bavards, messages les plus répétés (normalisés). À utiliser pour expliquer un volume de logs anormal, plutôt que de multiplier les grep.\n"+in.pathsDesc()),
		schema: `{"type":"object","properties":{` + hostProps + `,"path":{"type":"string","description":"fichier de log absolu"},"sample_mb":{"type":"integer","description":"taille de l'échantillon en Mio (défaut 4, max 16)"},"top":{"type":"integer","description":"nombre de loggers/messages (défaut 15, max 40)"}},"required":["host","path"]}`,
		call: func(ctx context.Context, raw json.RawMessage) (string, error) {
			a, err := tools.Decode[struct {
				Target   string `json:"target"`
				Host     string `json:"host"`
				Path     string `json:"path"`
				SampleMB int    `json:"sample_mb"`
				Top      int    `json:"top"`
			}](raw)
			if err != nil {
				return "", err
			}
			t, h, err := in.findHost(a.Target, a.Host)
			if err != nil {
				return "", err
			}
			p, err := in.rules.Check(a.Path)
			if err != nil {
				return "", err
			}
			sample := clamp(a.SampleMB<<20, statsDefault, 1<<20, statsMax)
			res, err := in.remote(ctx, name, t, h, in.builder().StatTail(p, sample), sample+4096)
			if err != nil {
				return "", err
			}
			if res.Exit != 0 {
				return format(res)
			}
			head, body, _ := strings.Cut(res.Stdout, "\n")
			f := strings.Fields(head)
			if len(f) != 2 {
				return "", fmt.Errorf("stat inattendu: %q", head)
			}
			size, _ := strconv.ParseInt(f[0], 10, 64)
			mt, _ := strconv.ParseInt(f[1], 10, 64)
			return fmt.Sprintf("%s\n%s", p, LogStats(body, size, time.Unix(mt, 0), len(body), size > int64(len(body)), clamp(a.Top, 15, 5, 40))), nil
		},
	}
}
