package access

import (
	"strings"
	"testing"
)

func sh(s string) []string { return []string{"sh", "-c", s} }

func TestReadOnlyAccepted(t *testing.T) {
	ok := [][]string{
		{"node", "-p", "process.versions.brotli"},
		{"node", "-p", "process.version"},
		{"nodejs", "--print", "process.versions['openssl']"},
		{"node", "-e", "console.log(process.versions.brotli)"},
		sh("node --version; node -p 'process.versions.brotli'"),
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
		{"ss", "-tnp"},
		{"netstat", "-antp"},
		{"crontab", "-l"},
		{"crontab", "-u", "www-data", "-l"},
		{"systemctl", "list-timers", "--all"},
		{"systemctl", "status", "litellm"},
		{"journalctl", "-u", "litellm", "--since", "2026-10-20"},
		{"ip", "addr", "show"},
		{"ip", "route"},
		{"lsof", "-i", "-P", "-n"},
		sh("ls -ld /data /data/* ; id; echo ---; findmnt -no SOURCE,FSTYPE /data"),
		{"lsblk", "-f"},
		{"date"},
		{"date", "+%F %T %z"},
		{"date", "-u"},
		{"date", "-d", "@1793874021", "+%F %T %z"},
		{"date", "-ud", "@1793874021"},
		{"date", "-d@1793874021"},
		{"date", "--date=@1793874021", "+%s"},
		{"date", "--date", "2026-11-05 11:20:21", "+%s"},
		{"date", "-r", "/etc/hostname"},
		{"date", "-Iseconds"},
		{"date", "--iso-8601=seconds"},
		{"date", "-R"},
		{"namei", "-l", "/var/lib/demo/manifests"},
		{"sudo", "-n", "namei", "-l", "/var/lib/demo/manifests"},
		{"snap", "list"},
		{"flatpak", "list", "--app"},
		{"ldd", "/usr/bin/node"},
		sh("snap list 2>/dev/null | grep -i node; flatpak info org.example.App"),
		sh("pip3 show litellm 2>/dev/null; find / -xdev -path '*site-packages/litellm*' -name '*.pth' 2>/dev/null | head"),
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
		"node -p code":       {"node", "-p", "require('fs').writeFileSync('/tmp/x','')"},
		"node -e sans print": {"node", "-e", "process.versions.brotli"},
		"node -p double":     {"node", "-p", "process.version", "x"},
		"awk":                sh("dpkg -l | awk '{print $2}'"),
		"redirection":        sh("php -v > /tmp/out"),
		"append":             sh("echo x >> /etc/hosts"),
		"find -delete":       {"find", "/tmp", "-name", "x", "-delete"},
		"snap install":       {"snap", "install", "node"},
		"flatpak update":     {"flatpak", "update", "-y"},
		"find -exec":         sh("find / -name php -exec rm {} \\;"),
		"sort -o":            {"sort", "-o", "/etc/passwd2", "x"},
		"sort -ro":           {"sort", "-ro", "out", "x"},
		"uniq out":           {"uniq", "in", "out"},
		"rpm -i":             {"rpm", "-i", "x.rpm"},
		"rpm erase":          {"rpm", "-qa", "-e", "php"},
		"dpkg -i":            {"dpkg", "-i", "x.deb"},
		"apk add":            {"apk", "add", "php"},
		"pip install":        {"pip", "install", "x"},
		"php -r":             {"php", "-r", "echo 1;"},
		"python -c":          {"python3", "-c", "print(1)"},
		"curl post":          {"curl", "-X", "POST", "http://x"},
		"sed":                sh("sed -i s/a/b/ /etc/php.ini"),
		"rm":                 sh("ls; rm -rf /tmp/x"),
		"background":         sh("sleep 100 &"),
		"function":           sh("f() { rm -rf /; }; f"),
		"variable program":   sh("X=rm; $X -rf /"),
		"relative program":   {"./evil", "--version"},
		"subst":              sh("echo $(rm -rf /tmp/x)"),
		"proc out":           sh("ls > >(tee /tmp/x)"),
		"secret":             {"cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		"environ":            sh("cat /proc/1/environ"),
		"date set":           {"date", "-s", "2020-01-01"},
		"date set attached":  {"date", "-s@1"},
		"date set cluster":   {"date", "-us", "2020-01-01"},
		"date set cluster2":  {"date", "-us@1"},
		"date set long":      {"date", "--set=2020-01-01"},
		"date set abbrev":    {"date", "--se=2020-01-01"},
		"date positional":    {"date", "010112002020"},
		"date after dashes":  {"date", "--", "010112002020"},
		"date date then pos": {"date", "-d", "@1", "010112002020"},
		"date unknown long":  {"date", "--frobnicate"},
		"date attached pos":  {"date", "-dbar", "010112002020"},
		"sudo date set":      {"sudo", "-n", "date", "-s@1"},
		"nested shell":       sh("bash -c 'rm -rf /'"),
		"xargs":              sh("ls | xargs rm"),
		"env":                {"env"},
		"tee":                sh("ls | tee /tmp/x"),
		"rw redirect":        sh("cat <> /etc/hosts"),
		"dup file":           sh("ls >& /tmp/x"),
		"versioned other":    {"nginx", "-s", "stop"},
		"apachectl restart":  {"apachectl", "restart"},
		"ldconfig":           {"ldconfig"},
		"hostname set":       {"hostname", "evil"},
		"control char":       {"ls", "a\nb"},
		"ss kill":            {"ss", "-K", "dst", "1.2.3.4"},
		"crontab edit":       {"crontab", "-r"},
		"crontab file":       {"crontab", "/tmp/x"},
		"systemctl stop":     {"systemctl", "stop", "litellm"},
		"systemctl opt stop": {"systemctl", "--now", "disable", "x"},
		"journal vacuum":     {"journalctl", "--vacuum-time=1d"},
		"ip add":             {"ip", "addr", "add", "1.2.3.4/32", "dev", "eth0"},
		"ip link down":       {"ip", "link", "set", "eth0", "down"},
		"computed program":   sh("$(command -v php) -v"),
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

func TestReadOnlyTrustingScript(t *testing.T) {
	script := sh("node --version; brotli --dump-version | head -1")
	if ReadOnly(script) == nil {
		t.Fatal("brotli --dump-version accepté sans fiche")
	}
	if err := ReadOnlyTrusting(script, []string{"brotli --dump-version"}); err != nil {
		t.Fatal(err)
	}
	if ReadOnlyTrusting(sh("brotli --dump-version > /tmp/x"), []string{"brotli --dump-version"}) == nil {
		t.Fatal("redirection acceptée")
	}
	if ReadOnlyTrusting(sh("brotli --dump-version -o /tmp/x"), []string{"brotli --dump-version"}) == nil {
		t.Fatal("arguments ajoutés acceptés")
	}
}

func TestReadOnlySudo(t *testing.T) {
	ok := [][]string{
		{"sudo", "-n", "journalctl", "-u", "demo", "--since", "2020-01-01", "--no-pager"},
		{"sudo", "du", "-sh", "/var"},
		{"/usr/bin/sudo", "-n", "ls", "/root"},
		{"sudo", "-n", "sh", "-c", "du -sh /var | sort -h; uptime"},
		sh("sudo -n du -sh /var 2>/dev/null | tail -2; sudo journalctl -n 5"),
		sh("sudo -n sh -c 'journalctl -n 5 | wc -l'"),
	}
	for _, argv := range ok {
		if err := ReadOnly(argv); err != nil {
			t.Errorf("%q : %v", argv, err)
		}
	}
	refused := [][]string{
		{"sudo"},
		{"sudo", "-n"},
		{"sudo", "-n", "-u", "demo", "ls"},
		{"sudo", "-i", "--version"},
		{"sudo", "-n", "A=b", "--version"},
		{"sudo", "-n", "rm", "-rf", "/tmp/x"},
		{"sudo", "-n", "journalctl", "--since", "2020-01-01", "--vacuum-time=1s"},
		{"sudo", "-n", "cat", "/etc/shadow"},
		{"sudo", "-n", "sh", "-c", "du -sh / > /tmp/x"},
		{"sudo", "-n", "sh", "-c", "ls; rm /tmp/x"},
		sh("sudo -n rm /tmp/x"),
		sh("sudo $X ls"),
		sh("$X -n ls /tmp; sudo -n sh -c 'rm /tmp/x'"),
	}
	for _, argv := range refused {
		if err := ReadOnly(argv); err == nil {
			t.Errorf("%q accepté", argv)
		}
	}
}

func TestReadOnlyAllowingPatterns(t *testing.T) {
	rules, err := CompileCommands(Rules{
		Allow: []string{"demo-stat *", "demo-stat * *", "sleep *", "demo-all **"},
		Deny:  []string{"demo-stat -w **", "demo-stat * -w", "demo-all --purge **"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ok := [][]string{
		{"demo-stat", "a"},
		{"sudo", "-n", "demo-stat", "a", "b"},
		sh("demo-stat a; sleep 5; demo-stat b | grep x"),
		sh("sudo -n demo-stat a b 2>/dev/null | tail -1"),
		{"sudo", "-n", "sh", "-c", "demo-stat a; sleep 1"},
		sh("for i in 1 2; do demo-all x; done"),
	}
	for _, argv := range ok {
		if err := ReadOnlyAllowing(argv, nil, rules); err != nil {
			t.Errorf("%q : %v", argv, err)
		}
	}
	refused := [][]string{
		{"demo-stat", "a", "b", "c"},
		{"demo-stat", "-w", "a"},
		{"sudo", "-n", "demo-stat", "a", "-w"},
		sh("demo-stat -w a"),
		sh("sudo -n demo-stat a -w"),
		sh("demo-all --purge x"),
		sh("demo-stat $X"),
		sh("demo-stat a > /tmp/x"),
		sh("demo-stat a &"),
		sh("demo-stat a; rm /tmp/x"),
		sh("/tmp/demo-stat a"),
		sh("demo-all /tmp/token"),
	}
	for _, argv := range refused {
		if err := ReadOnlyAllowing(argv, nil, rules); err == nil {
			t.Errorf("%q accepté", argv)
		}
	}
	if err := ReadOnly(sh("demo-stat a")); err == nil {
		t.Fatal("motif appliqué sans règles")
	}
}

func TestReadOnlyKubectl(t *testing.T) {
	ok := [][]string{
		{"kubectl", "get", "nodes", "-o", "wide"},
		{"kubectl", "--kubeconfig=/etc/demo/admin.yaml", "get", "nodes"},
		{"kubectl", "--kubeconfig", "/etc/demo/admin.yaml", "-n", "demo", "get", "pods", "-A"},
		{"/opt/demo/bin/kubectl", "-A", "get", "pods"},
		{"kubectl", "describe", "node", "demo"},
		{"kubectl", "logs", "demo", "-n", "demo", "--tail=50", "-c", "main"},
		{"kubectl", "top", "nodes"},
		{"kubectl", "version"},
		{"kubectl", "cluster-info"},
		{"kubectl", "auth", "can-i", "list", "pods"},
		{"oc", "get", "pods"},
		{"sudo", "-n", "kubectl", "get", "nodes"},
		sh("kubectl get pods -A | grep -v Running | wc -l"),
		sh("sudo -n kubectl get events -A | tail -20"),
	}
	for _, argv := range ok {
		if err := ReadOnly(argv); err != nil {
			t.Errorf("%q : %v", argv, err)
		}
	}
	refused := [][]string{
		{"kubectl"},
		{"kubectl", "-n", "demo"},
		{"kubectl", "delete", "pod", "demo"},
		{"kubectl", "apply", "-f", "demo.yaml"},
		{"kubectl", "exec", "demo", "--", "ls"},
		{"kubectl", "cp", "a", "b"},
		{"kubectl", "-n", "get", "delete", "pod", "demo"},
		{"kubectl", "--server=http://demo", "get", "pods"},
		{"kubectl", "--as=admin", "get", "pods"},
		{"kubectl", "get", "pods", "--as=admin"},
		{"kubectl", "get", "secrets", "-A"},
		{"kubectl", "get", "pods,secrets", "-o", "yaml"},
		{"kubectl", "describe", "secret", "demo"},
		{"kubectl", "get", "--raw=/api/v1/pods"},
		{"kubectl", "get", "pods", "-w"},
		{"kubectl", "get", "pods", "--watch"},
		{"kubectl", "logs", "demo", "-f"},
		{"kubectl", "logs", "demo", "--follow"},
		{"kubectl", "get", "pods", "-v=9"},
		{"kubectl", "cluster-info", "dump"},
		{"kubectl", "auth", "reconcile", "-f", "demo.yaml"},
		{"kubectl", "config", "view", "--raw"},
		sh("kubectl get pods; kubectl delete pod demo"),
		sh("kubectl $X pods"),
	}
	for _, argv := range refused {
		if err := ReadOnly(argv); err == nil {
			t.Errorf("%q accepté", argv)
		}
	}
}
