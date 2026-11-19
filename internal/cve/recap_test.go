package cve

import (
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/i18n"
)

const recapReport = `> CVE-2026-11111 et CVE-2026-22222 sur le client

# CVE-2026-11111 — openjdk

## 1. Verdict

- **Touchée** [E001]

## 3. Actifs positifs

| | Actif | Exposition | Corrigé dans |
|---|---|---|---|
| 🚨 | vm-a | internet | 17.0.9 |
| 🚨 | vm-d | limitée | 17.0.9 |

**🚨 vm-a** (hôte, RHEL 9)

- **Trouvé** : openjdk 17.0.1 [E010][E011]
- **Exposition** : **exposée** : port 8443 publié [E012]
- **Test déterminant** : java -version

**🟡 vm-d** (hôte, RHEL 9)

- **Trouvé** : openjdk 17.0.2 [E014]
- **Exposition** : **neutralisée par la configuration** : module jmx non chargé [E015]

## 4. Actifs indéterminés

**❓ vm-b** (hôte)

- **Ce qui manque** : accès SSH refusé [E020]

## 6. Plan d'action

1. **vm-a**
   - Pourquoi positif : openjdk 17.0.1, dans la plage touchée < 17.0.9 [E010]
   - Mitigation immédiate : filtrer le port 8443 | ou couper le service
   - Correctif : openjdk 17.0.9 [E013]
     par le dépôt RHEL
   - Vérification : java -version
2. **vm-d**
   - **Mitigation immédiate** : aucune, service interne
   - **Correctif définitif** : openjdk 17.0.9

## 7. Limites de l'analyse

- **vm-b** non inspecté

# CVE-2026-22222 — libfoo

## 3. Actifs positifs

Aucun actif positif.

## 6. Plan d'action

Aucune action : aucun actif positif.
`

func TestRecap(t *testing.T) {
	defer i18n.SetReport(i18n.Report())
	i18n.SetReport("fr")
	got := Recap(recapReport)
	want := `# Récapitulatif CVE-2026-11111, CVE-2026-22222

| CVE | Actif(s) | En l'état | Pourquoi positif | Mitigation immédiate | Correctif définitif (fix / patch) |
|---|---|---|---|---|---|
| CVE-2026-11111 | vm-a | 🚨 exposée : port 8443 publié | openjdk 17.0.1, dans la plage touchée < 17.0.9 | filtrer le port 8443 \| ou couper le service | openjdk 17.0.9 par le dépôt RHEL |
| CVE-2026-11111 | vm-d | 🟡 neutralisée par la configuration : module jmx non chargé | openjdk 17.0.2 | aucune, service interne | openjdk 17.0.9 |

Sans actif positif : CVE-2026-22222.

## ❓ Indéterminés (non vérifiés)

| CVE | Actif(s) | Ce qui manque |
|---|---|---|
| CVE-2026-11111 | vm-b | accès SSH refusé |
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRecapEnglishLabels(t *testing.T) {
	defer i18n.SetReport(i18n.Report())
	i18n.SetReport("en")
	md := "# CVE-2026-33333 — foo\n\n## 6. Action plan\n\n1. **web-1**\n   - Why positive: foo 1.2 in the affected range\n   - Immediate mitigation: none\n   - Fix: upgrade to foo 1.3\n"
	got := Recap(md)
	if !strings.Contains(got, "| CVE-2026-33333 | web-1 | — | foo 1.2 in the affected range | none | upgrade to foo 1.3 |") || !strings.Contains(got, "| CVE | Asset(s) | As is | Why positive | Immediate mitigation | Permanent fix (fix / patch) |") {
		t.Fatalf("got:\n%s", got)
	}
}

func TestRecapNone(t *testing.T) {
	if Recap("# Rapport\n\ntexte") != "" {
		t.Fatal("recap without CVE subject")
	}
}

func TestExposureIcons(t *testing.T) {
	defer i18n.SetReport(i18n.Report())
	i18n.SetReport("fr")
	finds := []Finding{
		{Status: Vulnerable, Exposure: Exposed},
		{Status: Vulnerable, Exposure: Limited},
		{Status: Vulnerable, Exposure: Neutralized},
		{Status: Vulnerable, Exposure: Unmeasured},
		{Status: Unknown},
	}
	var icons []string
	for _, f := range finds {
		icons = append(icons, f.Icon())
	}
	if got := strings.Join(icons, ""); got != "🚨🟠🟡🚨❓" {
		t.Fatalf("icons %q", got)
	}
	v := verdict(finds)
	for _, want := range []string{"🚨 1 exposé(s)", "🚨 1 exposition non mesurée", "🟠 1 à exposition limitée", "🟡 1 neutralisé(s) par la configuration"} {
		if !strings.Contains(v, want) {
			t.Errorf("verdict sans %q :\n%s", want, v)
		}
	}
}
