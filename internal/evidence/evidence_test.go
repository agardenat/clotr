package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreAndAnnex(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	s := Open(dir, 2)
	a := s.Add("t1", "prod_ssh_tail", `{"path":"/var/log/x"}`, "ligne 1\nligne 2", nil)
	b := s.Add("t2", "prod_api_get", `{}`, "", errors.New("HTTP 404"))
	if a != "E2.001" || b != "E2.002" {
		t.Fatalf("ids: %s %s", a, b)
	}
	data, err := os.ReadFile(filepath.Join(dir, a+".txt"))
	if err != nil || !strings.Contains(string(data), "outil: prod_ssh_tail") || !strings.HasSuffix(string(data), "ligne 1\nligne 2") {
		t.Fatalf("fichier: %q %v", data, err)
	}
	report := "Constat [E2.001], puis E2.001 et E9.999. Rien pour t1."
	annex := s.Annex(report, "Annexe", "inconnue", filepath.Base)
	if !strings.Contains(annex, "**E2.001** · t1 · `prod_ssh_tail`") || !strings.Contains(annex, "`E2.001.txt`") || !strings.Contains(annex, "**E9.999** : inconnue") || strings.Contains(annex, "E2.002") {
		t.Fatalf("annexe:\n%s", annex)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	list, err := Load(dir)
	if err != nil || len(list) != 2 || list[1].Error != "HTTP 404" {
		t.Fatalf("index: %+v %v", list, err)
	}
	re, err := Reopen(dir, 2)
	if err != nil || !strings.Contains(re.Annex("[E2.001]", "A", "x", filepath.Base), "`prod_ssh_tail`") || re.Len() != 2 {
		t.Fatalf("réouverture: %v", err)
	}
	if Open(dir, 1).Annex("rien", "A", "x", filepath.Base) != "" {
		t.Error("annexe sans citation")
	}
}

func TestReadTool(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "evidence"), 1)
	id := s.Add("t1", "prod_ssh_tail", `{}`, "a INFO\nb ERROR x\nc INFO\nd ERROR y", nil)
	tool := s.Tool()
	out, err := tool.Call(context.Background(), json.RawMessage(`{"id":"[`+id+`]","pattern":"ERROR"}`))
	if err != nil || !strings.Contains(out, "2 lignes sur 4") || !strings.Contains(out, "2: b ERROR x") || strings.Contains(out, "INFO") {
		t.Fatalf("pattern: %v\n%s", err, out)
	}
	out, err = tool.Call(context.Background(), json.RawMessage(`{"id":"`+id+`","offset":3,"lines":1}`))
	if err != nil || !strings.Contains(out, "3: c INFO") || strings.Contains(out, "d ERROR") {
		t.Fatalf("plage: %v\n%s", err, out)
	}
	out, err = tool.Call(context.Background(), json.RawMessage(`{"id":"`+id+`","exclude":"^(a|c) "}`))
	if err != nil || !strings.Contains(out, "2 lignes sur 4") || strings.Contains(out, "INFO") {
		t.Fatalf("exclude: %v\n%s", err, out)
	}
	out, err = tool.Call(context.Background(), json.RawMessage(`{"id":"`+id+`","pattern":"ERROR","exclude":"y$"}`))
	if err != nil || !strings.Contains(out, "1 lignes sur 4") || !strings.Contains(out, "2: b ERROR x") {
		t.Fatalf("pattern + exclude: %v\n%s", err, out)
	}
	if _, err := tool.Call(context.Background(), json.RawMessage(`{"id":"`+id+`","pattern":"^(?!a)"}`)); err == nil || !strings.Contains(err.Error(), "utiliser exclude") {
		t.Fatalf("lookahead: %v", err)
	}
	if _, err := tool.Call(context.Background(), json.RawMessage(`{"id":"E999"}`)); err == nil {
		t.Fatal("preuve inconnue acceptée")
	}
}

func TestImportAndSearchAcrossTurns(t *testing.T) {
	root := t.TempDir()
	t1 := Open(filepath.Join(root, "001", "evidence"), 1)
	id1 := t1.Add("t1", "prod_ssh_list", `{"host":"master1","path":"/var/log/app"}`, "f 1234567890 archive/app_queue.log", nil)
	t1.Add("t2", "prod_api_get", `{"path":"/clusters/x/services"}`, "{}", nil)
	if err := t1.Save(); err != nil {
		t.Fatal(err)
	}
	cur := Open(filepath.Join(root, "002", "evidence"), 2)
	if err := cur.Import(filepath.Join(root, "001", "evidence")); err != nil {
		t.Fatal(err)
	}
	if cur.Len() != 0 {
		t.Fatal("les preuves importées ne doivent pas compter dans le tour courant")
	}
	out, err := cur.SearchTool().Call(context.Background(), json.RawMessage(`{"terms":["app","master1","inexistant"],"content":"app_queue"}`))
	if err != nil || !strings.HasPrefix(out, "1 preuves correspondent (sur 2") || !strings.Contains(out, id1) {
		t.Fatalf("recherche: %v\n%s", err, out)
	}
	if out, err := cur.Tool().Call(context.Background(), json.RawMessage(`{"id":"`+id1+`"}`)); err != nil || !strings.Contains(out, "1234567890") {
		t.Fatalf("relecture d'un tour précédent: %v %s", err, out)
	}
	if !strings.Contains(cur.Annex("voir ["+id1+"]", "A", "x", filepath.Base), "prod_ssh_list") {
		t.Fatal("annexe sans la preuve du tour précédent")
	}
}

func TestBeginNextTurn(t *testing.T) {
	root := t.TempDir()
	s := Open("", 1)
	s.Begin(filepath.Join(root, "001"), 1)
	id1 := s.Add("t1", "k8s_list", "{}", "a", nil)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s.Begin(filepath.Join(root, "002"), 2)
	id2 := s.Add("direct", "k8s_list", "{}", "b", nil)
	if id1 != "E001" || id2 != "E2.001" || s.Len() != 1 || !s.Has(id1) {
		t.Fatalf("ids %s %s, len %d", id1, id2, s.Len())
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	list, err := Load(filepath.Join(root, "002"))
	if err != nil || len(list) != 1 || list[0].ID != id2 {
		t.Fatalf("index du tour 2: %+v %v", list, err)
	}
	if !strings.Contains(s.Annex("["+id1+"] ["+id2+"]", "A", "x", filepath.Base), "E001.txt") {
		t.Fatal("preuve du tour 1 absente de l'annexe")
	}
}
