package k8s

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func obj(apiVersion, kind, ns, name string, extra map[string]any) *unstructured.Unstructured {
	o := map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":              name,
			"creationTimestamp": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"managedFields":     []any{map[string]any{"manager": "kubectl"}},
			"annotations":       map[string]any{lastApplied: "{}", "keep": "yes"},
		},
	}
	if ns != "" {
		o["metadata"].(map[string]any)["namespace"] = ns
	}
	for k, v := range extra {
		o[k] = v
	}
	return &unstructured.Unstructured{Object: o}
}

func newK8s(t *testing.T) *K8s {
	pods := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	nodes := schema.GroupVersionResource{Version: "v1", Resource: "nodes"}
	podMetrics := schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Version: "v1"}})
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Secret"}, meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Node"}, meta.RESTScopeRoot)
	objs := []runtime.Object{
		obj("v1", "Pod", "app", "web-1", map[string]any{
			"spec": map[string]any{"nodeName": "n1"},
			"status": map[string]any{
				"phase": "Running",
				"containerStatuses": []any{map[string]any{
					"name": "web", "ready": false, "restartCount": int64(7),
					"state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
				}},
				"conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "ContainersNotReady"}},
			},
		}),
		obj("v1", "Secret", "app", "db", map[string]any{"data": map[string]any{"password": "c2VjcmV0"}}),
		obj("v1", "Node", "", "n1", map[string]any{"status": map[string]any{"nodeInfo": map[string]any{"kubeletVersion": "v1.34.1"}}}),
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		pods: "PodList", secrets: "SecretList", nodes: "NodeList", podMetrics: "PodMetricsList",
	}, objs...)
	metrics := obj("metrics.k8s.io/v1beta1", "PodMetrics", "app", "web-1", map[string]any{
		"containers": []any{map[string]any{"name": "web", "usage": map[string]any{"cpu": "250m", "memory": "128Mi"}}},
	})
	if err := dyn.Tracker().Create(podMetrics, metrics, "app"); err != nil {
		t.Fatal(err)
	}
	core := kfake.NewSimpleClientset(&corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "e1", Namespace: "app"},
		Type:           "Warning",
		Reason:         "BackOff",
		Message:        "Back-off restarting failed container",
		Count:          12,
		LastTimestamp:  metav1.NewTime(now.Add(-time.Minute)),
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
	})
	k := NewWithFactory([]string{"prod"}, "prod", func(string) (*Cluster, error) {
		return &Cluster{Dyn: dyn, Core: core, Disc: core.Discovery(), Mapper: mapper}, nil
	})
	k.now = func() time.Time { return now }
	return k
}

func call(t *testing.T, k *K8s, name, args string) (string, error) {
	for _, tl := range k.Tools() {
		if tl.Name() == name {
			return tl.Call(context.Background(), []byte(args))
		}
	}
	t.Fatalf("outil %s absent", name)
	return "", nil
}

func TestListSummary(t *testing.T) {
	k := newK8s(t)
	out, err := call(t, k, "k8s_list", `{"resource":"pods","namespace":"app"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"app/web-1", "age=120m", "phase=Running", "node=n1", "ready=0/1", "restarts=7", "web:state/CrashLoopBackOff", "Ready=False(ContainersNotReady)"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary sans %q: %s", want, out)
		}
	}
	out, err = call(t, k, "k8s_list", `{"resource":"nodes"}`)
	if err != nil || !strings.Contains(out, "n1") || !strings.Contains(out, "kubelet=v1.34.1") {
		t.Fatalf("nodes: %q %v", out, err)
	}
}

func TestGetSanitized(t *testing.T) {
	k := newK8s(t)
	out, err := call(t, k, "k8s_get", `{"resource":"secret","namespace":"app","name":"db"}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "c2VjcmV0") || !strings.Contains(out, "masqué") {
		t.Errorf("secret non masqué: %s", out)
	}
	if strings.Contains(out, "managedFields") || strings.Contains(out, lastApplied) || !strings.Contains(out, "keep: \"yes\"") {
		t.Errorf("sanitize: %s", out)
	}
	if _, err := call(t, k, "k8s_get", `{"resource":"pods","name":"web-1"}`); err == nil {
		t.Error("namespace manquant accepté")
	}
}

func TestContextRestriction(t *testing.T) {
	k := newK8s(t)
	if _, err := call(t, k, "k8s_list", `{"context":"other","resource":"pods"}`); err == nil || !strings.Contains(err.Error(), "non autorisé") {
		t.Fatalf("contexte non autorisé accepté: %v", err)
	}
}

func TestEventsLogsTop(t *testing.T) {
	k := newK8s(t)
	out, err := call(t, k, "k8s_events", `{"namespace":"app"}`)
	if err != nil || !strings.Contains(out, "Pod/web-1") || !strings.Contains(out, "(x12)") {
		t.Fatalf("events: %q %v", out, err)
	}
	out, err = call(t, k, "k8s_logs", `{"namespace":"app","pod":"web-1"}`)
	if err != nil || out == "" {
		t.Fatalf("logs: %q %v", out, err)
	}
	out, err = call(t, k, "k8s_top", `{"kind":"pods","namespace":"app"}`)
	if err != nil || !strings.Contains(out, "app/web-1\t250\t128") {
		t.Fatalf("top: %q %v", out, err)
	}
}

func TestNoWriteVerbs(t *testing.T) {
	k := newK8s(t)
	c, _ := k.cluster("")
	fake := c.Dyn.(*dynfake.FakeDynamicClient)
	for _, name := range []string{"k8s_list", "k8s_get", "k8s_top"} {
		args := map[string]string{"k8s_list": `{"resource":"pods"}`, "k8s_get": `{"resource":"nodes","name":"n1"}`, "k8s_top": `{"kind":"pods"}`}[name]
		_, _ = call(t, k, name, args)
	}
	for _, a := range fake.Actions() {
		if v := a.GetVerb(); v != "list" && v != "get" {
			t.Errorf("verbe inattendu: %s", v)
		}
	}
	coreFake := c.Core.(*kfake.Clientset)
	_, _ = call(t, k, "k8s_events", `{}`)
	_, _ = call(t, k, "k8s_logs", `{"namespace":"app","pod":"web-1"}`)
	for _, a := range coreFake.Actions() {
		if v := a.GetVerb(); v != "list" && v != "get" {
			t.Errorf("verbe inattendu: %s", v)
		}
	}
}

func TestProbeRemovesUnreachable(t *testing.T) {
	base := newK8s(t)
	k := NewWithFactory([]string{"down", "prod"}, "down", func(name string) (*Cluster, error) {
		if name == "down" {
			return nil, fmt.Errorf("proxyconnect: connection refused")
		}
		return base.cluster("prod")
	})
	failures := k.Probe(context.Background(), time.Second)
	ctxs, def := k.Contexts()
	if len(failures) != 1 || !strings.Contains(failures[0], "down") || len(ctxs) != 1 || def != "prod" {
		t.Fatalf("failures=%v ctxs=%v def=%s", failures, ctxs, def)
	}
	if _, err := call(t, k, "k8s_list", `{"context":"down","resource":"pods"}`); err == nil {
		t.Fatal("contexte retiré encore utilisable")
	}
}

func TestListFields(t *testing.T) {
	k := newK8s(t)
	out, err := call(t, k, "k8s_list", `{"resource":"pods","fields":"spec.nodeName, status.phase, spec.missing, status.containerStatuses"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"app/web-1", "spec.nodeName=n1", "status.phase=Running", "spec.missing=<absent>", `status.containerStatuses=[{"name":"web"`} {
		if !strings.Contains(out, want) {
			t.Errorf("sans %q: %s", want, out)
		}
	}
}
