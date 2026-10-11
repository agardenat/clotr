package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/tools"
)

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

type Cluster struct {
	Dyn    dynamic.Interface
	Core   kubernetes.Interface
	Disc   discovery.DiscoveryInterface
	Mapper meta.RESTMapper
}

type Factory func(contextName string) (*Cluster, error)

type K8s struct {
	allowed      []string
	defaultCtx   string
	factory      Factory
	mu           sync.Mutex
	clusters     map[string]*Cluster
	probes       map[string]*probeState
	probeTimeout time.Duration
	now          func() time.Time
}

type probeState struct {
	once sync.Once
	err  error
}

const defaultProbeTimeout = 5 * time.Second

func New(cfg *config.K8s) (*K8s, error) {
	timeout := cfg.Timeout.Duration
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.Kubeconfig != "" {
		rules.ExplicitPath = cfg.Kubeconfig
	}
	raw, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("k8s: kubeconfig: %w", err)
	}
	allowed := cfg.Contexts
	if len(allowed) == 0 {
		if raw.CurrentContext == "" {
			return nil, errors.New("k8s: aucun contexte configuré ni current-context")
		}
		allowed = []string{raw.CurrentContext}
	}
	for _, c := range allowed {
		if _, ok := raw.Contexts[c]; !ok {
			return nil, fmt.Errorf("k8s: contexte %q absent du kubeconfig", c)
		}
	}
	def := allowed[0]
	if slices.Contains(allowed, raw.CurrentContext) {
		def = raw.CurrentContext
	}
	factory := func(name string) (*Cluster, error) {
		cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: name})
		rc, err := cc.ClientConfig()
		if err != nil {
			return nil, err
		}
		rc.Timeout = timeout
		rc.UserAgent = "clotr"
		rc.QPS, rc.Burst = 20, 40
		dyn, err := dynamic.NewForConfig(rc)
		if err != nil {
			return nil, err
		}
		core, err := kubernetes.NewForConfig(rc)
		if err != nil {
			return nil, err
		}
		disc := memory.NewMemCacheClient(core.Discovery())
		mapper := restmapper.NewShortcutExpander(restmapper.NewDeferredDiscoveryRESTMapper(disc), disc, func(string) {})
		return &Cluster{Dyn: dyn, Core: core, Disc: disc, Mapper: mapper}, nil
	}
	return NewWithFactory(allowed, def, factory), nil
}

func NewWithFactory(allowed []string, def string, f Factory) *K8s {
	return &K8s{allowed: allowed, defaultCtx: def, factory: f, clusters: map[string]*Cluster{}, probes: map[string]*probeState{}, probeTimeout: defaultProbeTimeout, now: time.Now}
}

func (k *K8s) use(ctx context.Context, name string) (*Cluster, error) {
	if name == "" {
		name = k.defaultCtx
	}
	c, err := k.cluster(name)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	st, ok := k.probes[name]
	if !ok {
		st = &probeState{}
		k.probes[name] = st
	}
	k.mu.Unlock()
	st.once.Do(func() { st.err = k.probe(ctx, c, k.probeTimeout) })
	if st.err != nil {
		return nil, fmt.Errorf("contexte %s injoignable pour ce run: %w", name, st.err)
	}
	return c, nil
}

func (k *K8s) unreachable() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for _, name := range k.allowed {
		if st, ok := k.probes[name]; ok && st.err != nil {
			out = append(out, name)
		}
	}
	return out
}

func (k *K8s) probe(ctx context.Context, c *Cluster, timeout time.Duration) error {
	rc := c.Core.Discovery().RESTClient()
	if rc == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := rc.Get().AbsPath("/version").Do(pctx).Raw()
	if pctx.Err() != nil {
		return fmt.Errorf("pas de réponse en %s", timeout)
	}
	return err
}

func (k *K8s) Contexts() ([]string, string) {
	return k.allowed, k.defaultCtx
}

func (k *K8s) cluster(name string) (*Cluster, error) {
	if name == "" {
		name = k.defaultCtx
	}
	if !slices.Contains(k.allowed, name) {
		return nil, fmt.Errorf("contexte %q non autorisé (autorisés: %s)", name, strings.Join(k.allowed, ", "))
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if c, ok := k.clusters[name]; ok {
		return c, nil
	}
	c, err := k.factory(name)
	if err != nil {
		return nil, fmt.Errorf("contexte %s: %w", name, err)
	}
	k.clusters[name] = c
	return c, nil
}

func (c *Cluster) resolve(res string) (schema.GroupVersionResource, bool, error) {
	gr := schema.ParseGroupResource(strings.ToLower(strings.TrimSpace(res)))
	gvr, err := c.Mapper.ResourceFor(gr.WithVersion(""))
	if err != nil {
		return gvr, false, fmt.Errorf("ressource %q inconnue: %w", res, err)
	}
	gvk, err := c.Mapper.KindFor(gvr)
	if err != nil {
		return gvr, false, err
	}
	mapping, err := c.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return gvr, false, err
	}
	return gvr, mapping.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

func (k *K8s) Tools() []tools.Tool {
	return []tools.Tool{contextsTool{k}, apiResourcesTool{k}, listTool{k}, getTool{k}, logsTool{k}, eventsTool{k}, topTool{k}}
}

const ctxProp = `"context":{"type":"string","description":"contexte kubeconfig, défaut: contexte par défaut"}`

func schemaOf(props string, required ...string) json.RawMessage {
	req, _ := json.Marshal(required)
	if len(required) == 0 {
		req = []byte("[]")
	}
	return json.RawMessage(`{"type":"object","properties":{` + ctxProp + props + `},"required":` + string(req) + `}`)
}

type contextsTool struct{ k *K8s }

func (contextsTool) Name() string { return "k8s_contexts" }
func (contextsTool) Description() string {
	return "Liste les contextes Kubernetes autorisés et le contexte par défaut."
}
func (contextsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t contextsTool) Call(context.Context, json.RawMessage) (string, error) {
	out := fmt.Sprintf("autorisés: %s\ndéfaut: %s\n", strings.Join(t.k.allowed, ", "), t.k.defaultCtx)
	if down := t.k.unreachable(); len(down) > 0 {
		out += "injoignables pour ce run: " + strings.Join(down, ", ") + "\n"
	}
	return out, nil
}

type apiResourcesTool struct{ k *K8s }

func (apiResourcesTool) Name() string { return "k8s_api_resources" }
func (apiResourcesTool) Description() string {
	return "Liste les types de ressources listables du cluster (nom, shortnames, groupe/version, kind, namespaced), CRD incluses."
}
func (apiResourcesTool) Schema() json.RawMessage { return schemaOf("") }

func (t apiResourcesTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context string `json:"context"`
	}](raw)
	if err != nil {
		return "", err
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	lists, err := c.Disc.ServerPreferredResources()
	var b strings.Builder
	if err != nil {
		fmt.Fprintf(&b, "[découverte partielle: %v]\n", err)
	}
	var lines []string
	for _, l := range lists {
		for _, r := range l.APIResources {
			if strings.Contains(r.Name, "/") || !slices.Contains(r.Verbs, "list") {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%t", r.Name, strings.Join(r.ShortNames, ","), l.GroupVersion, r.Kind, r.Namespaced))
		}
	}
	sort.Strings(lines)
	b.WriteString("NAME\tSHORTNAMES\tAPIVERSION\tKIND\tNAMESPACED\n")
	b.WriteString(strings.Join(lines, "\n"))
	return b.String(), nil
}

type listTool struct{ k *K8s }

func (listTool) Name() string { return "k8s_list" }
func (listTool) Description() string {
	return "Liste des objets Kubernetes (lecture seule). namespace vide = tous les namespaces. output: summary (défaut, une ligne par objet avec statut), names, yaml (objets complets, coûteux). fields: chemins pointés à extraire pour chaque objet (ex: [\"spec.strategy.type\",\"spec.template.spec.containers\"]) — à préférer au yaml pour comparer un attribut sur tous les objets en un seul appel."
}
func (listTool) Schema() json.RawMessage {
	return schemaOf(`,"resource":{"type":"string","description":"ex: pods, deploy, nodes, ingresses.networking.k8s.io"},"namespace":{"type":"string"},"label_selector":{"type":"string"},"field_selector":{"type":"string"},"limit":{"type":"integer","description":"défaut 200, max 1000"},"output":{"type":"string","enum":["summary","names","yaml"]},"fields":{"type":"array","items":{"type":"string"},"description":"chemins pointés à extraire, ex: spec.replicas, spec.strategy.type"}`, "resource")
}

func (t listTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context       string           `json:"context"`
		Resource      string           `json:"resource"`
		Namespace     string           `json:"namespace"`
		LabelSelector string           `json:"label_selector"`
		FieldSelector string           `json:"field_selector"`
		Limit         int64            `json:"limit"`
		Output        string           `json:"output"`
		Fields        tools.StringList `json:"fields"`
	}](raw)
	if err != nil {
		return "", err
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	gvr, namespaced, err := c.resolve(args.Resource)
	if err != nil {
		return "", err
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 1000)
	var ri dynamic.ResourceInterface = c.Dyn.Resource(gvr)
	if namespaced && args.Namespace != "" {
		ri = c.Dyn.Resource(gvr).Namespace(args.Namespace)
	}
	list, err := ri.List(ctx, metav1.ListOptions{LabelSelector: args.LabelSelector, FieldSelector: args.FieldSelector, Limit: limit})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	switch {
	case len(args.Fields) > 0:
		for i := range list.Items {
			b.WriteString(ExtractFields(&list.Items[i], args.Fields) + "\n")
		}
	case args.Output == "names":
		for _, it := range list.Items {
			b.WriteString(qualified(&it) + "\n")
		}
	case args.Output == "yaml":
		for i := range list.Items {
			out, err := toYAML(&list.Items[i])
			if err != nil {
				return "", err
			}
			b.WriteString("---\n")
			b.Write(out)
		}
	default:
		now := t.k.now()
		for i := range list.Items {
			b.WriteString(Summarize(&list.Items[i], now) + "\n")
		}
	}
	if len(list.Items) == 0 {
		b.WriteString("aucun objet\n")
	}
	if list.GetContinue() != "" {
		fmt.Fprintf(&b, "[résultats limités à %d objets: affiner namespace/selector]\n", limit)
	}
	return b.String(), nil
}

type getTool struct{ k *K8s }

func (getTool) Name() string { return "k8s_get" }
func (getTool) Description() string {
	return "Récupère un objet Kubernetes complet en YAML (managedFields retirés, valeurs des Secrets masquées)."
}
func (getTool) Schema() json.RawMessage {
	return schemaOf(`,"resource":{"type":"string"},"name":{"type":"string"},"namespace":{"type":"string"}`, "resource", "name")
}

func (t getTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context   string `json:"context"`
		Resource  string `json:"resource"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}](raw)
	if err != nil {
		return "", err
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	gvr, namespaced, err := c.resolve(args.Resource)
	if err != nil {
		return "", err
	}
	var ri dynamic.ResourceInterface = c.Dyn.Resource(gvr)
	if namespaced {
		if args.Namespace == "" {
			return "", errors.New("namespace requis pour cette ressource")
		}
		ri = c.Dyn.Resource(gvr).Namespace(args.Namespace)
	}
	obj, err := ri.Get(ctx, args.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	out, err := toYAML(obj)
	return string(out), err
}

type logsTool struct{ k *K8s }

func (logsTool) Name() string { return "k8s_logs" }
func (logsTool) Description() string {
	return "Récupère les dernières lignes de logs d'un conteneur de pod (previous=true pour le conteneur précédent après crash)."
}
func (logsTool) Schema() json.RawMessage {
	return schemaOf(`,"namespace":{"type":"string"},"pod":{"type":"string"},"container":{"type":"string"},"tail_lines":{"type":"integer","description":"défaut 200, max 2000"},"since_seconds":{"type":"integer"},"previous":{"type":"boolean"}`, "namespace", "pod")
}

func (t logsTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context      string `json:"context"`
		Namespace    string `json:"namespace"`
		Pod          string `json:"pod"`
		Container    string `json:"container"`
		TailLines    int64  `json:"tail_lines"`
		SinceSeconds int64  `json:"since_seconds"`
		Previous     bool   `json:"previous"`
	}](raw)
	if err != nil {
		return "", err
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	tail := args.TailLines
	if tail <= 0 {
		tail = 200
	}
	tail = min(tail, 2000)
	limitBytes := int64(512 << 10)
	opts := &corev1.PodLogOptions{Container: args.Container, TailLines: &tail, Previous: args.Previous, LimitBytes: &limitBytes}
	if args.SinceSeconds > 0 {
		opts.SinceSeconds = &args.SinceSeconds
	}
	data, err := c.Core.CoreV1().Pods(args.Namespace).GetLogs(args.Pod, opts).DoRaw(ctx)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "aucun log", nil
	}
	return string(data), nil
}

type eventsTool struct{ k *K8s }

func (eventsTool) Name() string { return "k8s_events" }
func (eventsTool) Description() string {
	return "Liste les événements Kubernetes triés du plus récent au plus ancien. type: Warning (défaut) ou all. namespace vide = tous."
}
func (eventsTool) Schema() json.RawMessage {
	return schemaOf(`,"namespace":{"type":"string"},"type":{"type":"string","enum":["Warning","Normal","all"]},"object":{"type":"string","description":"filtre sur le nom de l'objet concerné"},"limit":{"type":"integer","description":"défaut 100"}`)
}

func (t eventsTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context   string `json:"context"`
		Namespace string `json:"namespace"`
		Type      string `json:"type"`
		Object    string `json:"object"`
		Limit     int    `json:"limit"`
	}](raw)
	if err != nil {
		return "", err
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	var selectors []string
	switch args.Type {
	case "", "Warning":
		selectors = append(selectors, "type=Warning")
	case "Normal":
		selectors = append(selectors, "type=Normal")
	}
	if args.Object != "" {
		selectors = append(selectors, "involvedObject.name="+args.Object)
	}
	list, err := c.Core.CoreV1().Events(args.Namespace).List(ctx, metav1.ListOptions{FieldSelector: strings.Join(selectors, ",")})
	if err != nil {
		return "", err
	}
	evs := list.Items
	sort.SliceStable(evs, func(i, j int) bool { return eventTime(&evs[i]).After(eventTime(&evs[j])) })
	limit := args.Limit
	if limit <= 0 {
		limit = 100
	}
	now := t.k.now()
	var b strings.Builder
	for i, e := range evs {
		if i >= limit {
			fmt.Fprintf(&b, "[%d événements supplémentaires omis]\n", len(evs)-limit)
			break
		}
		count := ""
		if e.Count > 1 {
			count = fmt.Sprintf(" (x%d)", e.Count)
		}
		fmt.Fprintf(&b, "%s ago\t%s\t%s\t%s/%s\t%s: %s%s\n", age(eventTime(&e), now), e.Type, e.Namespace, e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Reason, strings.TrimSpace(e.Message), count)
	}
	if len(evs) == 0 {
		b.WriteString("aucun événement\n")
	}
	return b.String(), nil
}

func eventTime(e *corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	case e.Series != nil && !e.Series.LastObservedTime.IsZero():
		return e.Series.LastObservedTime.Time
	}
	return e.CreationTimestamp.Time
}

type topTool struct{ k *K8s }

func (topTool) Name() string { return "k8s_top" }
func (topTool) Description() string {
	return "Consommation CPU (millicores) / mémoire (Mi) instantanée des nodes ou pods via metrics.k8s.io (metrics-server requis)."
}
func (topTool) Schema() json.RawMessage {
	return schemaOf(`,"kind":{"type":"string","enum":["nodes","pods"]},"namespace":{"type":"string"}`, "kind")
}

func (t topTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Context   string `json:"context"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
	}](raw)
	if err != nil {
		return "", err
	}
	if args.Kind != "nodes" && args.Kind != "pods" {
		return "", errors.New("kind doit valoir nodes ou pods")
	}
	c, err := t.k.use(ctx, args.Context)
	if err != nil {
		return "", err
	}
	gvr := schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: args.Kind}
	var ri dynamic.ResourceInterface = c.Dyn.Resource(gvr)
	if args.Kind == "pods" && args.Namespace != "" {
		ri = c.Dyn.Resource(gvr).Namespace(args.Namespace)
	}
	list, err := ri.List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("metrics.k8s.io indisponible: %w", err)
	}
	type row struct {
		name     string
		cpu, mem int64
	}
	var rows []row
	for _, it := range list.Items {
		var usages []map[string]any
		if args.Kind == "nodes" {
			if u, ok, _ := unstructured.NestedMap(it.Object, "usage"); ok {
				usages = append(usages, u)
			}
		} else {
			cs, _, _ := unstructured.NestedSlice(it.Object, "containers")
			for _, c := range cs {
				if m, ok := c.(map[string]any); ok {
					if u, ok := m["usage"].(map[string]any); ok {
						usages = append(usages, u)
					}
				}
			}
		}
		r := row{name: qualified(&it)}
		for _, u := range usages {
			r.cpu += quantity(u["cpu"]).MilliValue()
			r.mem += quantity(u["memory"]).Value()
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].cpu > rows[j].cpu })
	var b strings.Builder
	b.WriteString("NAME\tCPU(m)\tMEMORY(Mi)\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s\t%d\t%d\n", r.name, r.cpu, r.mem>>20)
	}
	return b.String(), nil
}

func quantity(v any) *resource.Quantity {
	s, _ := v.(string)
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return resource.NewQuantity(0, resource.DecimalSI)
	}
	return &q
}

func qualified(u *unstructured.Unstructured) string {
	if ns := u.GetNamespace(); ns != "" {
		return ns + "/" + u.GetName()
	}
	return u.GetName()
}

func age(t, now time.Time) string {
	if t.IsZero() {
		return "?"
	}
	return duration.HumanDuration(now.Sub(t))
}

func sanitize(u *unstructured.Unstructured) {
	unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	if ann := u.GetAnnotations(); ann != nil {
		if _, ok := ann[lastApplied]; ok {
			delete(ann, lastApplied)
			u.SetAnnotations(ann)
		}
	}
	if u.GetKind() == "Secret" && u.GroupVersionKind().Group == "" {
		for _, field := range []string{"data", "stringData"} {
			m, ok, _ := unstructured.NestedMap(u.Object, field)
			if !ok {
				continue
			}
			for k, v := range m {
				s, _ := v.(string)
				m[k] = fmt.Sprintf("<masqué: %d caractères>", len(s))
			}
			_ = unstructured.SetNestedMap(u.Object, m, field)
		}
	}
}

func toYAML(u *unstructured.Unstructured) ([]byte, error) {
	c := u.DeepCopy()
	sanitize(c)
	return yaml.Marshal(c.Object)
}

func Summarize(u *unstructured.Unstructured, now time.Time) string {
	parts := []string{qualified(u), "age=" + age(u.GetCreationTimestamp().Time, now)}
	add := func(k string, v any) {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	obj := u.Object
	if phase, ok, _ := unstructured.NestedString(obj, "status", "phase"); ok {
		add("phase", phase)
	}
	if u.GetKind() == "Pod" {
		summarizePod(obj, add)
	}
	for _, p := range [][]string{{"spec", "strategy", "type"}, {"spec", "updateStrategy", "type"}} {
		if v, ok, _ := unstructured.NestedString(obj, p...); ok {
			add("strategy", v)
		}
	}
	for _, f := range [][2]string{{"spec", "replicas"}, {"status", "readyReplicas"}, {"status", "availableReplicas"}, {"status", "updatedReplicas"}, {"status", "desiredNumberScheduled"}, {"status", "numberReady"}, {"status", "numberUnavailable"}} {
		if v, ok, _ := unstructured.NestedFieldNoCopy(obj, f[0], f[1]); ok {
			add(f[1], v)
		}
	}
	if u.GetKind() == "Node" {
		if v, ok, _ := unstructured.NestedString(obj, "status", "nodeInfo", "kubeletVersion"); ok {
			add("kubelet", v)
		}
		if v, ok, _ := unstructured.NestedBool(obj, "spec", "unschedulable"); ok && v {
			add("unschedulable", true)
		}
	}
	conds, _, _ := unstructured.NestedSlice(obj, "status", "conditions")
	var cs []string
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		s := fmt.Sprintf("%v=%v", m["type"], m["status"])
		if r, ok := m["reason"].(string); ok && r != "" && m["status"] != "True" {
			s += "(" + r + ")"
		}
		cs = append(cs, s)
	}
	if len(cs) > 0 {
		add("conditions", strings.Join(cs, ","))
	}
	return strings.Join(parts, " ")
}

func ExtractFields(u *unstructured.Unstructured, fields []string) string {
	parts := []string{qualified(u)}
	for _, f := range fields {
		path := strings.Split(strings.Trim(strings.TrimPrefix(f, "."), "."), ".")
		v, ok, _ := unstructured.NestedFieldNoCopy(u.Object, path...)
		var s string
		switch {
		case !ok:
			s = "<absent>"
		default:
			switch x := v.(type) {
			case string, bool, int64, float64:
				s = fmt.Sprint(x)
			default:
				data, _ := json.Marshal(x)
				s = string(data)
				if len(s) > 300 {
					s = s[:300] + "…"
				}
			}
		}
		parts = append(parts, f+"="+s)
	}
	return strings.Join(parts, " ")
}

func summarizePod(obj map[string]any, add func(string, any)) {
	if node, ok, _ := unstructured.NestedString(obj, "spec", "nodeName"); ok {
		add("node", node)
	}
	statuses, _, _ := unstructured.NestedSlice(obj, "status", "containerStatuses")
	ready, restarts := 0, int64(0)
	var reasons []string
	for _, s := range statuses {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if r, _ := m["ready"].(bool); r {
			ready++
		}
		restarts += toInt64(m["restartCount"])
		for _, key := range []string{"state", "lastState"} {
			st, _ := m[key].(map[string]any)
			for _, phase := range []string{"waiting", "terminated"} {
				if d, ok := st[phase].(map[string]any); ok {
					if r, _ := d["reason"].(string); r != "" && r != "Completed" {
						reasons = append(reasons, fmt.Sprintf("%v:%s/%s", m["name"], key, r))
					}
				}
			}
		}
	}
	add("ready", fmt.Sprintf("%d/%d", ready, len(statuses)))
	add("restarts", restarts)
	if len(reasons) > 0 {
		add("reasons", strings.Join(reasons, ","))
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
