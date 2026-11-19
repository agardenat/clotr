package cve

import (
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/i18n"
)

func TestRecap(t *testing.T) {
	defer i18n.SetReport(i18n.Report())
	i18n.SetReport("fr")
	md := `> CVE-2026-11111 et CVE-2026-22222 sur le client

# CVE-2026-11111 — openjdk

## 1. Verdict

- **Touchée** [E001]

## 2. La vulnérabilité

fiche

---

## 3. Actifs positifs

**🔴 vm-a** (hôte, RHEL 9)

- **Trouvé** : openjdk 17.0.1 [E010][E011]
- **Test déterminant** : java -version
- **Autres vérifications** : rpm -qa
- **Preuves** : [E010][E011]

- **vm-a** : exposé à internet [E012], priorité immédiate

## 4. Actifs indéterminés

**vm-b** : accès refusé

## 5. Actifs négatifs

vm-c corrigé

---

## 6. Plan d'action

1. **vm-a**
   - Correctif : openjdk 17.0.9 [E013]

## 7. Limites de l'analyse

- **vm-b** non inspecté

# CVE-2026-22222 — libfoo

## 3. Actifs positifs

Aucun actif positif.

## 6. Plan d'action

Aucune action : aucun actif positif.
`
	got := Recap(md)
	for _, want := range []string{
		"# Récapitulatif CVE-2026-11111, CVE-2026-22222",
		"## CVE-2026-11111 — openjdk",
		"### Actifs positifs\n\n**🔴 vm-a** (hôte, RHEL 9)",
		"- **Trouvé** : openjdk 17.0.1\n",
		"priorité immédiate",
		"### Corrections proposées\n\n1. **vm-a**\n   - Correctif : openjdk 17.0.9",
		"## CVE-2026-22222 — libfoo\n\nAucun actif positif.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("absent : %q\n%s", want, got)
		}
	}
	for _, absent := range []string{"[E0", "Verdict", "fiche", "vm-b", "vm-c", "Limites", "---", "Aucune action", "Test déterminant", "Autres vérifications", "Preuves"} {
		if strings.Contains(got, absent) {
			t.Errorf("présent : %q\n%s", absent, got)
		}
	}
	if Recap("# Rapport sans CVE\n\n## 3. x\n") != "" {
		t.Error("récapitulatif d'un rapport sans sujet CVE")
	}
}
