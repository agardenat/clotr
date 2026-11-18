package watch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._:-]+$`)

func (s *Store) Tool() tools.Tool {
	return sourceTool{s: s}
}

type sourceTool struct {
	s *Store
}

func (sourceTool) Name() string { return ToolName }

func (t sourceTool) Description() string {
	d := "Déclare une source à suivre en direct pendant l'attente : clotr la lit en boucle, sans toi, dès que l'action est reproduite, et archive tout ce qui arrive (une preuve par source). kind file : fichier de log d'un hôte en SSH (instance, host, path absolu autorisé par l'instance, lu à partir de sa taille au début de l'attente, rotations suivies) ; kind journal : journal systemd d'un hôte (unit, ou kernel=true pour les messages du noyau dont l'OOM killer ; sans les deux : tout le journal) ; kind sample : relevé périodique de l'état d'un hôte (probe memory : free et processus par mémoire ; cpu : charge et processus par CPU ; connections : ss -s et connexions TCP), toutes les every secondes (défaut 15) ; kind tool : outil d'une instance qui accepte le suivi (tool, args comme pour l'outil)."
	if followable, _ := t.s.scope(); len(followable) > 0 {
		d += " Outils qui acceptent le suivi : " + strings.Join(followable, ", ") + "."
	} else {
		d += " Aucun outil n'accepte le suivi dans ce run : kind tool indisponible."
	}
	return d + " filter : expression régulière des lignes affichées en direct à l'utilisateur (message d'erreur, identifiant de l'action) ; toutes les lignes sont archivées quel que soit le filtre. why : rôle de la source dans l'action suivie. Une source refusée (chemin hors des chemins autorisés, fichier absent, droit manquant) renvoie une erreur : corrige ou choisis une autre source."
}

func (sourceTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"kind":{"type":"string","enum":["file","journal","sample","tool"]},"instance":{"type":"string","description":"nom de l'instance (sans suffixe d'outil)"},"target":{"type":"string","description":"cible de l'instance, si le nom d'hôte est ambigu"},"host":{"type":"string","description":"hôte (file, journal, sample)"},"path":{"type":"string","description":"fichier absolu (file)"},"unit":{"type":"string","description":"unité systemd (journal)"},"kernel":{"type":"boolean","description":"messages du noyau (journal)"},"probe":{"type":"string","enum":["memory","cpu","connections"],"description":"relevé (sample)"},"every":{"type":"integer","description":"secondes entre deux relevés (sample, défaut 15)"},"tool":{"type":"string","description":"outil suivable, nom complet (tool)"},"args":{"type":"object","description":"arguments de l'outil (tool)"},"filter":{"type":"string","description":"expression régulière des lignes affichées en direct"},"why":{"type":"string","description":"rôle de la source dans l'action suivie"}},"required":["kind","instance","why"]}`)
}

func (t sourceTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Kind     string          `json:"kind"`
		Instance string          `json:"instance"`
		Target   string          `json:"target"`
		Host     string          `json:"host"`
		Path     string          `json:"path"`
		Unit     string          `json:"unit"`
		Kernel   bool            `json:"kernel"`
		Probe    string          `json:"probe"`
		Every    int             `json:"every"`
		Tool     string          `json:"tool"`
		Args     json.RawMessage `json:"args"`
		Filter   string          `json:"filter"`
		Why      string          `json:"why"`
	}](raw)
	if err != nil {
		return "", err
	}
	s := t.s
	if s.Waiting() {
		return "", errors.New("capture déjà en cours : plus aucune source ne peut être ajoutée")
	}
	followable, inScope := s.scope()
	inst, ok := s.lookup(a.Instance)
	if ok && inScope != nil {
		ok = inScope(a.Instance)
	}
	if !ok {
		return "", fmt.Errorf("instance %q inconnue ou sans suivi possible dans ce run", a.Instance)
	}
	src := &Source{Instance: a.Instance, Kind: a.Kind, Filter: strings.TrimSpace(a.Filter), Why: strings.Join(strings.Fields(a.Why), " "), Task: tools.CallerFrom(ctx).Task, inst: inst}
	if src.Filter != "" {
		if src.re, err = regexp.Compile(src.Filter); err != nil {
			return "", fmt.Errorf("filter invalide : %w", err)
		}
	}
	switch a.Kind {
	case KindFile, KindJour, KindProbe:
		if src.host, err = inst.Host(a.Target, a.Host); err != nil {
			return "", err
		}
		src.Host = src.host.Name()
	case KindTool:
		if strings.TrimSpace(a.Tool) == "" {
			return "", errors.New("tool requis pour kind tool")
		}
		if !slices.Contains(followable, a.Tool) || !strings.HasPrefix(a.Tool, a.Instance+"_") {
			return "", fmt.Errorf("outil %q sans suivi pour l'instance %s (outils suivables : %s)", a.Tool, a.Instance, strings.Join(followable, ", "))
		}
		src.Tool, src.Args = a.Tool, compact(a.Args)
	default:
		return "", fmt.Errorf("kind %q invalide (file, journal, sample, tool)", a.Kind)
	}
	var state string
	switch a.Kind {
	case KindFile:
		if src.Path, err = inst.Path(a.Path); err != nil {
			return "", err
		}
		if strings.HasSuffix(src.Path, ".gz") {
			return "", errors.New("fichier compressé : il n'évolue plus, suis le fichier courant")
		}
		res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Stat(src.Path) }, 1024)
		if err = runErr(res, err); err != nil {
			return "", err
		}
		size, _, _ := parseStat(res.Stdout)
		state = fmt.Sprintf("taille actuelle %d octets", size)
	case KindJour:
		if a.Unit != "" && !unitRe.MatchString(a.Unit) {
			return "", fmt.Errorf("unit %q invalide", a.Unit)
		}
		src.Unit, src.Kernel = a.Unit, a.Kernel
		res, err := src.host.Run(ctx, ToolName, func(b ssh.Builder) string { return b.Journal(src.Unit, src.Kernel, "", 0) }, 64<<10)
		if err = runErr(res, err); err != nil {
			return "", err
		}
		state = "journal lisible"
	case KindProbe:
		if _, ok := ssh.Probe(a.Probe); !ok {
			return "", fmt.Errorf("probe %q invalide (%s)", a.Probe, strings.Join(ssh.Probes(), ", "))
		}
		src.Probe = a.Probe
		src.Every = defaultEvery
		if a.Every > 0 {
			src.Every = max(time.Duration(a.Every)*time.Second, s.Interval)
		}
		state = fmt.Sprintf("relevé toutes les %s", src.Every)
	case KindTool:
		if _, _, err := inst.Follow(ctx, src.Tool, src.Args, nil); err != nil {
			return "", err
		}
		state = "suivi accepté par l'outil"
	}
	got, added := s.add(src)
	if !added {
		return fmt.Sprintf("source déjà déclarée (%s : %s)", got.ID, got.Label()), nil
	}
	s.audit.Log("watch_source", map[string]any{"id": got.ID, "task": got.Task, "instance": got.Instance, "kind": got.Kind, "label": got.Label(), "filter": got.Filter, "why": got.Why})
	s.Events.Emit(progress.Event{Task: got.Task, Kind: "source", Detail: i18n.T("watch.source", got.ID, got.Label(), got.Why)})
	return fmt.Sprintf("source %s enregistrée : %s (%s) ; la capture commencera au début de l'attente", got.ID, got.Label(), state), nil
}

func compact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage("{}")
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}
