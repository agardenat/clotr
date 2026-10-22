package access

import (
	"strings"
	"testing"
)

func sh(s string) []string { return []string{"sh", "-c", s} }

func TestReadOnlyAccepted(t *testing.T) {
	ok := [][]string{
		{"php", "-v"},
		{"/usr/local/bin/php-fpm8.2", "-v"},
		{"php", "-m"},
		{"apachectl", "-M"},
		{"rpm", "-qa"},
		{"rpm", "-q", "php-cli"},
		{"dpkg", "-l", "php8.2-fpm"},
		{"dpkg-query", "-W", "-f=${Package} ${Version}", "php*"},
		{"apk", "info", "-v"},
		{"pip3", "list"},
		{"find", "/", "-xdev", "-name", "php*", "-type", "f"},
		{"ls", "-la", "/usr/local/bin"},
		{"cat", "/etc/os-release"},
		{"frobnicate", "--version"},
		{"ldconfig", "-p"},
		sh("rpm -qa | grep -i php"),
		sh("php -i 2>/dev/null | grep -E 'session.upload_progress|fatal_error_backtraces' || true"),
		sh("ls /usr/bin /usr/local/bin /usr/sbin 2>/dev/null | grep -i php; find / -xdev -name 'php*' -type f 2>/dev/null | head -40"),
		sh("cat /etc/os-release 2>/dev/null | head -3; command -v rpm || echo no-rpm; command -v dpkg-query || echo no-dpkg"),
		sh("for b in php php8.2 php-fpm; do command -v $b; done"),
		sh("V=$(php -v 2>&1 | head -1); echo \"$V\""),
		sh("if [ -x /usr/sbin/php-fpm ]; then /usr/sbin/php-fpm -v; fi >/dev/null 2>&1"),
	}
	for _, argv := range ok {
		if err := ReadOnly(argv); err != nil {
			t.Errorf("%q refusé : %v", argv, err)
		}
	}
}

func TestReadOnlyRefused(t *testing.T) {
	refused := map[string][]string{
		"awk":               sh("dpkg -l | awk '{print $2}'"),
		"redirection":       sh("php -v > /tmp/out"),
		"append":            sh("echo x >> /etc/hosts"),
		"find -delete":      {"find", "/tmp", "-name", "x", "-delete"},
		"find -exec":        sh("find / -name php -exec rm {} \\;"),
		"sort -o":           {"sort", "-o", "/etc/passwd2", "x"},
		"sort -ro":          {"sort", "-ro", "out", "x"},
		"uniq out":          {"uniq", "in", "out"},
		"rpm -i":            {"rpm", "-i", "x.rpm"},
		"rpm erase":         {"rpm", "-qa", "-e", "php"},
		"dpkg -i":           {"dpkg", "-i", "x.deb"},
		"apk add":           {"apk", "add", "php"},
		"pip install":       {"pip", "install", "x"},
		"php -r":            {"php", "-r", "echo 1;"},
		"python -c":         {"python3", "-c", "print(1)"},
		"curl post":         {"curl", "-X", "POST", "http://x"},
		"sed":               sh("sed -i s/a/b/ /etc/php.ini"),
		"rm":                sh("ls; rm -rf /tmp/x"),
		"background":        sh("sleep 100 &"),
		"function":          sh("f() { rm -rf /; }; f"),
		"variable program":  sh("X=rm; $X -rf /"),
		"relative program":  {"./evil", "--version"},
		"subst":             sh("echo $(rm -rf /tmp/x)"),
		"proc out":          sh("ls > >(tee /tmp/x)"),
		"secret":            {"cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		"environ":           sh("cat /proc/1/environ"),
		"date set":          {"date", "-s", "2020-01-01"},
		"nested shell":      sh("bash -c 'rm -rf /'"),
		"xargs":             sh("ls | xargs rm"),
		"env":               {"env"},
		"tee":               sh("ls | tee /tmp/x"),
		"rw redirect":       sh("cat <> /etc/hosts"),
		"dup file":          sh("ls >& /tmp/x"),
		"versioned other":   {"nginx", "-s", "stop"},
		"apachectl restart": {"apachectl", "restart"},
		"ldconfig":          {"ldconfig"},
		"hostname set":      {"hostname", "evil"},
		"control char":      {"ls", "a\nb"},
		"computed program":  sh("$(command -v php) -v"),
	}
	for name, argv := range refused {
		if err := ReadOnly(argv); err == nil {
			t.Errorf("%s : %q accepté", name, argv)
		}
	}
	if err := ReadOnly(sh("sed -n 1p /etc/php.ini")); err == nil || !strings.Contains(err.Error(), "sed") {
		t.Fatalf("raison: %v", err)
	}
}
