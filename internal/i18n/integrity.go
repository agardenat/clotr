package i18n

func init() {
	add(integrityMsgs)
}

var integrityMsgs = map[string]msg{
	"integrity.dev":             {"development build: integrity check of templates and configuration disabled although %s exists", "build de développement : contrôle d'intégrité des templates et de la configuration désactivé malgré %s"},
	"integrity.trust_root":      {"integrity: %s: %v", "intégrité : %s : %v"},
	"integrity.not_root":        {"%s is not owned by root or is writable by group or others", "%s n'appartient pas à root ou est modifiable par le groupe ou les autres"},
	"integrity.not_regular":     {"%s is not a regular file", "%s n'est pas un fichier ordinaire"},
	"integrity.exe":             {"integrity: the clotr executable %s can be replaced without root (%v): install clotr in a location owned by root (package .deb/.rpm)", "intégrité : l'exécutable clotr %s est remplaçable sans root (%v) : installer clotr dans un emplacement appartenant à root (paquet .deb/.rpm)"},
	"integrity.no_signers":      {"no signing key", "aucune clé de signature"},
	"integrity.signer_line":     {"line %d: %v", "ligne %d : %v"},
	"integrity.signer_key_type": {"key type %s refused: only security keys (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com) are accepted", "type de clé %s refusé : seules les clés matérielles (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com) sont acceptées"},
	"integrity.signer_option":   {"option %q not supported", "option %q non prise en charge"},
	"integrity.no_repo":         {"integrity: %s is not in a git clone: only the files of a signed commit are read", "intégrité : %s n'est pas dans un clone git : seuls les fichiers d'un commit signé sont lus"},
	"integrity.untracked":       {"integrity: %s is not in signed commit %s of %s", "intégrité : %s ne figure pas dans le commit signé %s de %s"},
	"integrity.modified":        {"integrity: %s differs from signed commit %s of %s", "intégrité : %s diffère du commit signé %s de %s"},
	"integrity.unsigned":        {"integrity: commit %s of %s: %v", "intégrité : commit %s de %s : %v"},
	"integrity.git":             {"integrity: %s: %v", "intégrité : %s : %v"},
	"integrity.no_signature":    {"not signed", "non signé"},
	"integrity.bad_signature":   {"invalid signature: %v", "signature invalide : %v"},
	"integrity.unknown_signer":  {"signed by a key absent from %s", "signé par une clé absente de %s"},
	"integrity.no_presence":     {"signature without user verification while the key requires verify-required", "signature sans vérification de l'utilisateur alors que la clé exige verify-required"},
	"integrity.namespace":       {"signature namespace %q, expected %q", "espace de noms de signature %q, attendu %q"},
	"integrity.object":          {"object %s: content does not match its identifier", "objet %s : contenu différent de son identifiant"},
	"integrity.overlay_key":     {"%s: %s cannot be set in the personal overlay while the integrity check is active", "%s : %s ne peut pas être défini dans la surcharge personnelle quand le contrôle d'intégrité est actif"},
}
