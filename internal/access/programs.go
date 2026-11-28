package access

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/benhoyt/goawk/lexer"
	"github.com/benhoyt/goawk/parser"
)

type flags struct {
	short    string
	shortVal string
	long     map[string]bool
	longVal  map[string]bool
}

type opt struct {
	name  string
	value string
}

type parsed struct {
	opts     []opt
	operands []string
}

func (p parsed) has(names ...string) bool {
	return slices.ContainsFunc(p.opts, func(o opt) bool { return slices.Contains(names, o.name) })
}

func (p parsed) values(names ...string) []string {
	var out []string
	for _, o := range p.opts {
		if slices.Contains(names, o.name) {
			out = append(out, o.value)
		}
	}
	return out
}

func refusedOption(prog, s string) error {
	return fmt.Errorf("%s %s : option non admise en lecture seule", prog, s)
}

func (f flags) parse(prog string, rest []arg) (parsed, error) {
	var p parsed
	next := func(i *int, name string) (string, error) {
		if *i+1 >= len(rest) {
			return "", fmt.Errorf("%s %s : valeur manquante", prog, name)
		}
		*i++
		if !rest[*i].lit {
			return "", fmt.Errorf("%s : argument non littéral", prog)
		}
		return rest[*i].s, nil
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !a.lit {
			return p, fmt.Errorf("%s : argument non littéral", prog)
		}
		s := a.s
		switch {
		case s == "--":
			for _, r := range rest[i+1:] {
				if !r.lit {
					return p, fmt.Errorf("%s : argument non littéral", prog)
				}
				p.operands = append(p.operands, r.s)
			}
			return p, nil
		case strings.HasPrefix(s, "--"):
			name, val, attached := strings.Cut(s[2:], "=")
			switch {
			case f.long[name] && !attached:
				p.opts = append(p.opts, opt{name: "--" + name})
			case f.longVal[name]:
				if !attached {
					v, err := next(&i, s)
					if err != nil {
						return p, err
					}
					val = v
				}
				p.opts = append(p.opts, opt{"--" + name, val})
			default:
				return p, refusedOption(prog, s)
			}
		case len(s) > 1 && s[0] == '-':
			for j := 1; j < len(s); j++ {
				c := s[j]
				switch {
				case strings.IndexByte(f.shortVal, c) >= 0:
					val := s[j+1:]
					if val == "" {
						v, err := next(&i, "-"+string(c))
						if err != nil {
							return p, err
						}
						val = v
					}
					p.opts = append(p.opts, opt{"-" + string(c), val})
					j = len(s)
				case strings.IndexByte(f.short, c) >= 0:
					p.opts = append(p.opts, opt{name: "-" + string(c)})
				default:
					return p, refusedOption(prog, s)
				}
			}
		default:
			p.operands = append(p.operands, s)
		}
	}
	return p, nil
}

type programCheck func(prog string, rest []arg) error

var programChecks map[string]programCheck

func init() {
	programChecks = map[string]programCheck{
		"sysctl":              checkSysctl,
		"lsmod":               noArgs,
		"getenforce":          noArgs,
		"sestatus":            onlyFlags(flags{short: "vb"}),
		"swapon":              onlyFlags(flags{short: "s", long: set("show", "summary", "noheadings", "bytes", "raw", "verbose"), longVal: set("show")}),
		"vgs":                 lvmReport,
		"pvs":                 lvmReport,
		"lvs":                 lvmReport,
		"vgdisplay":           lvmDisplay,
		"pvdisplay":           lvmDisplay,
		"lvdisplay":           lvmDisplay,
		"hostnamectl":         ctlStatus("status", "show"),
		"timedatectl":         ctlStatus("status", "show", "timesync-status", "show-timesync", "list-timezones"),
		"localectl":           ctlStatus("status", "list-locales", "list-keymaps", "list-x11-keymap-models", "list-x11-keymap-layouts"),
		"mount":               checkMount,
		"showmount":           checkShowmount,
		"rpcinfo":             checkRpcinfo,
		"nfsstat":             onlyFlags(flags{short: "scnm234rvVlZ", shortVal: "o", long: set("server", "client", "nfs", "rpc", "mounts", "all", "verbose", "list"), longVal: set("auto")}),
		"vmstat":              bounded(flags{short: "afmnsdDwtyV", shortVal: "SpcC", long: set("active", "forks", "slabs", "one-header", "stats", "disk", "disk-sum", "wide", "timestamp", "no-first", "version"), longVal: set("partition", "unit")}),
		"iostat":              bounded(flags{short: "cdhkmNtxyzsVH", shortVal: "jopg", long: set("human", "compact", "pretty", "dec", "short"), longVal: set("dec")}),
		"mpstat":              bounded(flags{short: "AuTHnV", shortVal: "PNoI", long: set("dec")}),
		"sar":                 checkSar,
		"top":                 checkTop,
		"dmesg":               checkDmesg,
		"nft":                 checkNft,
		"iptables":            checkIptables,
		"ip6tables":           checkIptables,
		"iptables-legacy":     checkIptables,
		"ip6tables-legacy":    checkIptables,
		"iptables-nft":        checkIptables,
		"ip6tables-nft":       checkIptables,
		"iptables-save":       onlyFlags(flags{short: "cV", shortVal: "tM", long: set("counters", "version"), longVal: set("table", "modprobe")}),
		"ip6tables-save":      onlyFlags(flags{short: "cV", shortVal: "tM", long: set("counters", "version"), longVal: set("table", "modprobe")}),
		"update-alternatives": checkAlternatives,
		"alternatives":        checkAlternatives,
		"systemd-analyze":     checkSystemdAnalyze,
		"crictl":              checkCrictl,
		"docker":              checkContainers,
		"podman":              checkContainers,
		"nerdctl":             checkContainers,
		"pcs":                 checkPcs,
		"corosync-cfgtool":    onlyFlags(flags{short: "s"}),
		"corosync-quorumtool": onlyFlags(flags{short: "slpieH"}),
		"crm_mon":             checkCrmMon,
		"datadog-agent":       firstOperand("version", "status", "health", "hostname"),
		"unzip":               checkUnzip,
		"zipinfo":             anything,
		"tar":                 checkTar,
		"nginx":               checkNginx,
		"httpd":               checkHttpd,
		"apache2":             checkHttpd,
		"apachectl":           checkHttpd,
		"apache2ctl":          checkHttpd,
		"sshd":                checkSshd,
		"sleep":               checkSleep,
		"ping":                checkPing,
		"ping6":               checkPing,
		"nc":                  checkNc,
		"ncat":                checkNc,
		"dig":                 anything,
		"host":                anything,
		"nslookup":            checkNslookup,
		"fuser":               withOperands(flags{short: "vmMua46s", shortVal: "n", long: set("verbose", "mount", "ismountpoint", "user", "all", "silent", "ipv4", "ipv6"), longVal: set("namespace")}),
		"curl":                checkCurl,
		"wget":                checkWget,
		"sed":                 checkSed,
		"awk":                 checkAwk,
		"gawk":                checkAwk,
		"mawk":                checkAwk,
		"nawk":                checkAwk,
		"xargs":               checkXargs,
		"tail":                checkTail,
		"ps":                  checkPs,
		"getent":              checkGetent,
	}
}

func anything(string, []arg) error { return nil }

func noArgs(prog string, rest []arg) error {
	if len(rest) > 0 {
		return refusedOption(prog, rest[0].s)
	}
	return nil
}

func onlyFlags(f flags) programCheck {
	return func(prog string, rest []arg) error {
		p, err := f.parse(prog, rest)
		if err != nil {
			return err
		}
		if len(p.operands) > 0 {
			return fmt.Errorf("%s %s : argument non admis en lecture seule", prog, p.operands[0])
		}
		return nil
	}
}

func withOperands(f flags) programCheck {
	return func(prog string, rest []arg) error {
		_, err := f.parse(prog, rest)
		return err
	}
}

func firstOperand(verbs ...string) programCheck {
	return func(prog string, rest []arg) error {
		if len(rest) == 0 || !rest[0].lit || !slices.Contains(verbs, rest[0].s) {
			return fmt.Errorf("%s : seuls %s sont admis", prog, strings.Join(verbs, ", "))
		}
		for _, a := range rest {
			if !a.lit {
				return fmt.Errorf("%s : argument non littéral", prog)
			}
		}
		return nil
	}
}

func checkSysctl(prog string, rest []arg) error {
	p, err := flags{short: "aAXnNebh", shortVal: "r", long: set("all", "values", "names", "binary", "help", "version"), longVal: set("pattern")}.parse(prog, rest)
	if err != nil {
		return err
	}
	for _, o := range p.operands {
		if strings.Contains(o, "=") {
			return fmt.Errorf("sysctl %s modifie un paramètre du noyau", o)
		}
	}
	return nil
}

var lvmFlags = flags{short: "avP", shortVal: "oOS", long: set("all", "noheadings", "nosuffix", "nameprefixes", "rows", "unbuffered", "aligned", "verbose", "readonly", "binary", "headings"), longVal: set("options", "sort", "select", "separator", "units", "reportformat", "configreport")}

func lvmReport(prog string, rest []arg) error {
	_, err := lvmFlags.parse(prog, rest)
	return err
}

func lvmDisplay(prog string, rest []arg) error {
	_, err := flags{short: "acCmsv", shortVal: "S", long: set("all", "colon", "columns", "maps", "short", "verbose", "noheadings", "nosuffix", "readonly"), longVal: set("options", "sort", "select", "separator", "units")}.parse(prog, rest)
	return err
}

func ctlStatus(verbs ...string) programCheck {
	f := flags{short: "a", shortVal: "p", long: set("no-pager", "no-ask-password", "all", "value", "static", "transient", "pretty", "monitor"), longVal: set("property", "json")}
	return func(prog string, rest []arg) error {
		p, err := f.parse(prog, rest)
		if err != nil {
			return err
		}
		if len(p.operands) > 0 && !slices.Contains(verbs, p.operands[0]) {
			return fmt.Errorf("%s %s modifie l'état ou n'est pas reconnue", prog, p.operands[0])
		}
		if p.has("--monitor") {
			return fmt.Errorf("%s --monitor : suivi sans fin", prog)
		}
		return nil
	}
}

func checkMount(prog string, rest []arg) error {
	p, err := flags{short: "lvh", shortVal: "tO", long: set("show-labels", "verbose", "help", "version"), longVal: set("types", "test-opts")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 0 {
		return fmt.Errorf("mount %s monte un système de fichiers", p.operands[0])
	}
	return nil
}

func checkShowmount(prog string, rest []arg) error {
	p, err := flags{short: "eadv", long: set("exports", "all", "directories", "no-headers", "version")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 1 {
		return fmt.Errorf("showmount : un seul hôte")
	}
	return nil
}

func checkRpcinfo(prog string, rest []arg) error {
	p, err := flags{short: "psml"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 1 {
		return fmt.Errorf("rpcinfo : un seul hôte")
	}
	return nil
}

var numericArg = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func bounded(f flags) programCheck {
	return func(prog string, rest []arg) error {
		p, err := f.parse(prog, rest)
		if err != nil {
			return err
		}
		return boundedCount(prog, p.operands)
	}
}

func boundedCount(prog string, operands []string) error {
	n := 0
	for _, o := range operands {
		if numericArg.MatchString(o) {
			n++
		}
	}
	if n == 1 {
		return fmt.Errorf("%s : un intervalle sans nombre de mesures ne se termine pas", prog)
	}
	return nil
}

func checkSar(prog string, rest []arg) error {
	p, err := flags{short: "AbBdFHhSuvWwyrqtzpV", shortVal: "fseIinmP", long: set("human", "dec", "iface", "fs", "sadc", "help", "pretty"), longVal: set("dec", "dev", "iface", "fs", "sadc")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if p.has("-o") {
		return fmt.Errorf("sar -o écrit un fichier")
	}
	return boundedCount(prog, p.operands)
}

func checkTop(prog string, rest []arg) error {
	p, err := flags{short: "bcHiSs1e", shortVal: "ndpuUowOE"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-b") || !p.has("-n") {
		return fmt.Errorf("top : seul le mode -b -n N se termine")
	}
	return nil
}

func checkDmesg(prog string, rest []arg) error {
	_, err := flags{short: "dekHPrSTtuxkL", shortVal: "fls", long: set("decode", "kernel", "human", "nopager", "raw", "ctime", "notime", "show-delta", "userspace", "reltime", "since", "until", "time-format", "syslog", "color", "json", "force-prefix"), longVal: set("facility", "level", "buffer-size", "since", "until", "time-format", "color", "file")}.parse(prog, rest)
	return err
}

func checkNft(prog string, rest []arg) error {
	p, err := flags{short: "anNsjtyupTe", long: set("handle", "numeric", "stateless", "json", "terse", "numeric-priority", "numeric-protocol", "numeric-time", "echo", "reversedns", "service", "guid")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) == 0 || p.operands[0] != "list" {
		return fmt.Errorf("nft : seul list est en lecture seule")
	}
	return nil
}

func checkIptables(prog string, rest []arg) error {
	p, err := flags{short: "LSnvxw", shortVal: "tW", long: set("list", "list-rules", "numeric", "verbose", "exact", "line-numbers", "version"), longVal: set("table", "wait-interval")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-L", "-S", "--list", "--list-rules", "--version") {
		return fmt.Errorf("%s : seuls -L et -S sont en lecture seule", prog)
	}
	if len(p.operands) > 2 {
		return fmt.Errorf("%s : trop d'arguments pour une consultation", prog)
	}
	return nil
}

func checkAlternatives(prog string, rest []arg) error {
	p, err := flags{long: set("get-selections", "version", "help", "verbose", "quiet"), longVal: set("list", "display", "query")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 0 || !p.has("--list", "--display", "--query", "--get-selections", "--version") {
		return fmt.Errorf("%s : seuls --list, --display, --query et --get-selections sont en lecture seule", prog)
	}
	return nil
}

var analyzeRead = set("cat-config", "blame", "critical-chain", "time", "security", "unit-paths", "calendar", "timespan", "timestamp", "dump", "verify", "condition", "syscall-filter", "filesystems", "log-level", "log-target", "service-watchdogs")

func checkSystemdAnalyze(prog string, rest []arg) error {
	p, err := flags{long: set("no-pager", "user", "system", "global", "man", "generators", "recursive-errors", "quiet", "no-legend"), longVal: set("root", "image", "offline", "threshold", "security-policy", "json", "iterations", "base-time", "unit", "fuzz", "order", "require")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) == 0 {
		return nil
	}
	if !analyzeRead[p.operands[0]] {
		return fmt.Errorf("systemd-analyze %s n'est pas une consultation", p.operands[0])
	}
	if len(p.operands) > 1 && (p.operands[0] == "log-level" || p.operands[0] == "log-target" || p.operands[0] == "service-watchdogs") {
		return fmt.Errorf("systemd-analyze %s avec argument modifie l'état", p.operands[0])
	}
	return nil
}

var crictlRead = set("ps", "pods", "images", "img", "inspect", "inspectp", "inspecti", "info", "version", "stats", "statsp", "imagefsinfo", "logs", "metricdescs", "metricsp")

func checkCrictl(prog string, rest []arg) error {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i].s, "-") {
		s := rest[i].s
		name, _, attached := strings.Cut(s, "=")
		switch {
		case slices.Contains([]string{"-r", "--runtime-endpoint", "--runtime", "-i", "--image-endpoint", "-t", "--timeout", "-c", "--config"}, name):
			if !attached {
				i++
			}
		case s == "-D" || s == "--debug":
		default:
			return refusedOption(prog, s)
		}
		i++
	}
	if i >= len(rest) || !crictlRead[rest[i].s] {
		return fmt.Errorf("crictl : seules les consultations sont admises")
	}
	for _, a := range rest[i:] {
		if !a.lit {
			return fmt.Errorf("%s : argument non littéral", prog)
		}
		if rest[i].s == "logs" && (a.s == "-f" || a.s == "--follow") {
			return fmt.Errorf("crictl logs %s : suivi sans fin", a.s)
		}
	}
	return nil
}

var containerRead = set("ps", "images", "inspect", "version", "info", "logs", "stats", "top", "port", "history")
var containerGroups = map[string]map[string]bool{
	"image":     set("ls", "list", "inspect", "history"),
	"container": set("ls", "list", "inspect", "logs", "top", "port", "stats"),
	"volume":    set("ls", "list", "inspect"),
	"network":   set("ls", "list", "inspect"),
	"system":    set("df", "info"),
	"pod":       set("ps", "ls", "list", "inspect", "stats", "top"),
}

func checkContainers(prog string, rest []arg) error {
	for _, a := range rest {
		if !a.lit {
			return fmt.Errorf("%s : argument non littéral", prog)
		}
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0].s, "-") {
		return fmt.Errorf("%s : option globale non admise", prog)
	}
	verb, after := rest[0].s, rest[1:]
	if sub, ok := containerGroups[verb]; ok {
		if len(after) == 0 || !sub[after[0].s] {
			return fmt.Errorf("%s %s : seules les consultations sont admises", prog, verb)
		}
		verb, after = after[0].s, after[1:]
	} else if !containerRead[verb] {
		return fmt.Errorf("%s %s n'est pas une consultation", prog, verb)
	}
	for _, a := range after {
		if verb == "logs" && (a.s == "-f" || a.s == "--follow" || strings.HasPrefix(a.s, "--follow=")) {
			return fmt.Errorf("%s logs %s : suivi sans fin", prog, a.s)
		}
	}
	if verb == "stats" && !slices.ContainsFunc(after, func(a arg) bool { return a.s == "--no-stream" }) {
		return fmt.Errorf("%s stats sans --no-stream ne se termine pas", prog)
	}
	return nil
}

func checkPcs(prog string, rest []arg) error {
	var ops []string
	for _, a := range rest {
		if !a.lit {
			return fmt.Errorf("%s : argument non littéral", prog)
		}
		if strings.HasPrefix(a.s, "-") {
			if a.s != "--full" && a.s != "--debug" {
				return refusedOption(prog, a.s)
			}
			continue
		}
		ops = append(ops, a.s)
	}
	switch {
	case len(ops) >= 1 && ops[0] == "status":
	case len(ops) == 1 && ops[0] == "config", len(ops) == 2 && ops[0] == "config" && ops[1] == "show":
	case len(ops) >= 2 && set("cluster", "resource", "stonith", "constraint", "property", "quorum", "node")[ops[0]] && set("status", "config", "show", "list")[ops[1]]:
	default:
		return fmt.Errorf("pcs : seules les consultations (status, config) sont admises")
	}
	return nil
}

func checkCrmMon(prog string, rest []arg) error {
	p, err := flags{short: "1rfAntoRjcQ", long: set("one-shot", "inactive", "failcounts", "show-node-attributes", "group-by-node", "timing-details", "operations", "show-detail", "tickets", "brief", "pending", "fence-history", "neg-locations", "watch-fencing")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-1", "--one-shot") {
		return fmt.Errorf("crm_mon : seul -1 se termine")
	}
	return nil
}

func checkUnzip(prog string, rest []arg) error {
	p, err := flags{short: "lvZqtp"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-l", "-v", "-Z", "-p") {
		return fmt.Errorf("unzip : seuls -l, -v, -Z et -p (vers la sortie standard) n'écrivent pas de fichier")
	}
	return nil
}

func checkTar(prog string, rest []arg) error {
	r := slices.Clone(rest)
	if len(r) > 0 && r[0].lit && !strings.HasPrefix(r[0].s, "-") {
		r[0].s = "-" + r[0].s
	}
	p, err := flags{short: "tvzjJ", shortVal: "f", long: set("list", "verbose", "gzip", "bzip2", "xz", "zstd", "wildcards", "numeric-owner", "full-time"), longVal: set("file")}.parse(prog, r)
	if err != nil {
		return err
	}
	if !p.has("-t", "--list") {
		return fmt.Errorf("tar : seul -t liste sans extraire")
	}
	return nil
}

func checkNginx(prog string, rest []arg) error {
	p, err := flags{short: "TtVvq", shortVal: "cp"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 0 || !p.has("-T", "-t", "-V", "-v") {
		return fmt.Errorf("nginx : seuls -t, -T, -v et -V sont en lecture seule")
	}
	return nil
}

func checkHttpd(prog string, rest []arg) error {
	r := rest
	if (prog == "apachectl" || prog == "apache2ctl") && len(r) == 1 && r[0].lit && set("configtest", "-t", "-S", "-M", "-V", "-v", "status", "fullstatus")[r[0].s] {
		return nil
	}
	p, err := flags{short: "vVSMlLtT", shortVal: "Df"}.parse(prog, r)
	if err != nil {
		return err
	}
	if len(p.operands) > 0 || !p.has("-v", "-V", "-S", "-M", "-l", "-L", "-t", "-T") {
		return fmt.Errorf("%s : seuls -v, -V, -S, -M, -l, -L, -t et -D DUMP_* sont en lecture seule", prog)
	}
	for _, d := range p.values("-D") {
		if !strings.HasPrefix(d, "DUMP_") {
			return fmt.Errorf("%s -D %s : seuls les DUMP_* sont admis", prog, d)
		}
	}
	return nil
}

func checkSshd(prog string, rest []arg) error {
	p, err := flags{short: "TtGV", shortVal: "Cf"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) > 0 || !p.has("-T", "-t", "-G", "-V") {
		return fmt.Errorf("sshd : seuls -T, -t, -G et -V sont en lecture seule")
	}
	return nil
}

var sleepArg = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[smhd]?$`)

func checkSleep(prog string, rest []arg) error {
	if len(rest) == 0 {
		return fmt.Errorf("sleep sans durée")
	}
	for _, a := range rest {
		if !a.lit || !sleepArg.MatchString(a.s) {
			return fmt.Errorf("sleep %s : durée non reconnue", a.s)
		}
	}
	return nil
}

func checkPing(prog string, rest []arg) error {
	p, err := flags{short: "qn46DOvU", shortVal: "cWwisIt"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-c") {
		return fmt.Errorf("%s sans -c ne se termine pas", prog)
	}
	if len(p.operands) != 1 {
		return fmt.Errorf("%s : un seul hôte", prog)
	}
	return checkHost(prog, p.operands[0])
}

func checkNc(prog string, rest []arg) error {
	p, err := flags{short: "zvnu46", shortVal: "w"}.parse(prog, rest)
	if err != nil {
		return err
	}
	if !p.has("-z") {
		return fmt.Errorf("%s : seul -z (test de port) est admis", prog)
	}
	if len(p.operands) == 0 || len(p.operands) > 2 {
		return fmt.Errorf("%s : un hôte et un port", prog)
	}
	return checkHost(prog, p.operands[0])
}

func checkNslookup(prog string, rest []arg) error {
	for _, a := range rest {
		if !a.lit {
			return fmt.Errorf("%s : argument non littéral", prog)
		}
		if !strings.HasPrefix(a.s, "-") {
			return nil
		}
	}
	return fmt.Errorf("nslookup sans nom lit l'entrée standard")
}

var metadataHosts = set("metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.azure.internal")

var linkLocal = []*net.IPNet{mustCIDR("169.254.0.0/16"), mustCIDR("fe80::/10"), mustCIDR("fd00:ec2::254/128"), mustCIDR("100.100.100.200/32")}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

var numericLabel = regexp.MustCompile(`^(0[xX][0-9a-fA-F]*|[0-9]+)$`)

func checkHost(prog, host string) error {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if metadataHosts[h] {
		return fmt.Errorf("%s %s : service de métadonnées du fournisseur cloud", prog, host)
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range linkLocal {
			if n.Contains(ip) {
				return fmt.Errorf("%s %s : adresse lien-local ou de métadonnées", prog, host)
			}
		}
		return nil
	}
	numeric := h != ""
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		numeric = numeric && numericLabel.MatchString(l)
	}
	if numeric {
		return fmt.Errorf("%s %s : adresse numérique non standard", prog, host)
	}
	return nil
}

func checkURL(prog, raw string) error {
	s := raw
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%s %s : URL illisible", prog, raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s %s : seuls http et https sont admis", prog, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%s : identifiants dans l'URL", prog)
	}
	return checkHost(prog, u.Hostname())
}

var curlFlags = flags{
	short:    "sSkILvfi46g",
	shortVal: "mwHAxXoDer",
	long:     set("silent", "show-error", "insecure", "head", "location", "verbose", "fail", "fail-with-body", "include", "http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3", "compressed", "ipv4", "ipv6", "no-progress-meter", "globoff", "tlsv1", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "ssl-no-revoke", "no-buffer", "path-as-is", "no-keepalive", "trace-time", "styled-output", "no-styled-output"),
	longVal:  set("max-time", "connect-timeout", "write-out", "header", "user-agent", "resolve", "connect-to", "proxy", "noproxy", "request", "output", "dump-header", "cacert", "capath", "max-redirs", "retry", "retry-delay", "retry-max-time", "range", "referer", "interface", "url", "ciphers", "tls-max", "proto-default"),
}

func checkCurl(prog string, rest []arg) error {
	p, err := curlFlags.parse(prog, rest)
	if err != nil {
		return err
	}
	for _, m := range p.values("-X", "--request") {
		if m != "GET" && m != "HEAD" {
			return fmt.Errorf("curl -X %s : seules GET et HEAD sont admises", m)
		}
	}
	for _, o := range p.values("-o", "--output", "-D", "--dump-header") {
		if o != "/dev/null" && o != "-" {
			return fmt.Errorf("curl : écriture vers %q", o)
		}
	}
	for _, w := range p.values("-w", "--write-out") {
		if strings.Contains(w, "%output{") || strings.HasPrefix(w, "@") {
			return fmt.Errorf("curl -w : écriture ou lecture de fichier")
		}
	}
	for _, h := range p.values("-H", "--header") {
		if strings.HasPrefix(h, "@") {
			return fmt.Errorf("curl -H @ : lecture de fichier")
		}
	}
	urls := append(p.values("--url"), p.operands...)
	if len(urls) == 0 {
		return fmt.Errorf("curl sans URL")
	}
	for _, u := range urls {
		if err := checkURL(prog, u); err != nil {
			return err
		}
	}
	for _, x := range p.values("-x", "--proxy") {
		if err := checkURL(prog, x); err != nil {
			return err
		}
	}
	return nil
}

func checkWget(prog string, rest []arg) error {
	p, err := flags{short: "qSv46", shortVal: "OTtU", long: set("quiet", "spider", "server-response", "no-check-certificate", "no-proxy", "inet4-only", "inet6-only", "no-verbose", "verbose"), longVal: set("output-document", "timeout", "tries", "header", "user-agent", "max-redirect", "method")}.parse(prog, rest)
	if err != nil {
		return err
	}
	for _, m := range p.values("--method") {
		if m != "GET" && m != "HEAD" {
			return fmt.Errorf("wget --method %s : seules GET et HEAD sont admises", m)
		}
	}
	out := p.values("-O", "--output-document")
	if !p.has("--spider") && (len(out) == 0 || slices.ContainsFunc(out, func(o string) bool { return o != "-" && o != "/dev/null" })) {
		return fmt.Errorf("wget : seuls -O - et --spider n'écrivent pas de fichier")
	}
	if len(p.operands) == 0 {
		return fmt.Errorf("wget sans URL")
	}
	for _, u := range p.operands {
		if err := checkURL(prog, u); err != nil {
			return err
		}
	}
	return nil
}

func checkSed(prog string, rest []arg) error {
	p, err := flags{short: "nErsuz", shortVal: "el", long: set("quiet", "silent", "regexp-extended", "separate", "unbuffered", "null-data", "posix", "debug", "sandbox"), longVal: set("expression", "line-length")}.parse(prog, rest)
	if err != nil {
		return err
	}
	scripts := p.values("-e", "--expression")
	if len(scripts) == 0 {
		if len(p.operands) == 0 {
			return fmt.Errorf("sed sans script")
		}
		scripts = p.operands[:1]
	}
	for _, s := range scripts {
		if err := sedScript(s); err != nil {
			return err
		}
	}
	return nil
}

func sedScript(s string) error {
	i := 0
	skipBlank := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	regexEnd := func(d byte) error {
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2
				continue
			case '\n':
				return fmt.Errorf("sed : expression non terminée")
			case d:
				i++
				return nil
			}
			i++
		}
		return fmt.Errorf("sed : expression non terminée")
	}
	address := func() error {
		switch {
		case i < len(s) && s[i] >= '0' && s[i] <= '9':
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '~') {
				i++
			}
		case i < len(s) && s[i] == '$':
			i++
		case i < len(s) && s[i] == '/':
			i++
			if err := regexEnd('/'); err != nil {
				return err
			}
			for i < len(s) && (s[i] == 'I' || s[i] == 'M') {
				i++
			}
		case i+1 < len(s) && s[i] == '\\':
			d := s[i+1]
			i += 2
			if err := regexEnd(d); err != nil {
				return err
			}
			for i < len(s) && (s[i] == 'I' || s[i] == 'M') {
				i++
			}
		}
		return nil
	}
	toEnd := func() {
		for i < len(s) && s[i] != '\n' && s[i] != ';' && s[i] != '}' {
			i++
		}
	}
	for i < len(s) {
		for i < len(s) && strings.IndexByte(" \t\n;", s[i]) >= 0 {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '#' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if err := address(); err != nil {
			return err
		}
		skipBlank()
		if i < len(s) && s[i] == ',' {
			i++
			skipBlank()
			if i < len(s) && (s[i] == '+' || s[i] == '~') {
				i++
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
			} else if err := address(); err != nil {
				return err
			}
			skipBlank()
		}
		if i < len(s) && s[i] == '!' {
			i++
			skipBlank()
		}
		if i >= len(s) {
			return fmt.Errorf("sed : commande manquante")
		}
		c := s[i]
		i++
		switch c {
		case 'p', 'P', 'd', 'D', 'q', 'Q', '=', 'l', 'n', 'N', 'g', 'G', 'h', 'H', 'x', 'z', 'F', '{', '}':
			if c == 'q' || c == 'Q' || c == 'l' {
				skipBlank()
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
			}
		case 'b', 't', 'T', ':':
			toEnd()
		case 'a', 'i', 'c':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case 's', 'y':
			if i >= len(s) || s[i] == '\\' || s[i] == '\n' {
				return fmt.Errorf("sed %c : délimiteur non admis", c)
			}
			d := s[i]
			i++
			if err := regexEnd(d); err != nil {
				return err
			}
			if err := regexEnd(d); err != nil {
				return err
			}
			for i < len(s) && strings.IndexByte(" \t\n;}", s[i]) < 0 {
				f := s[i]
				if c == 'y' || strings.IndexByte("gpiImM0123456789", f) < 0 {
					return fmt.Errorf("sed %c : drapeau %q non admis (écriture ou exécution)", c, f)
				}
				i++
			}
		default:
			return fmt.Errorf("sed : commande %q non admise (écriture, lecture de fichier ou exécution)", c)
		}
	}
	return nil
}

func checkAwk(prog string, rest []arg) error {
	p, err := flags{shortVal: "Fv", long: set("posix", "traditional", "re-interval", "characters-as-bytes", "sandbox"), longVal: set("field-separator", "assign")}.parse(prog, rest)
	if err != nil {
		return err
	}
	if len(p.operands) == 0 {
		return fmt.Errorf("%s sans programme", prog)
	}
	for _, v := range append(p.values("-v", "--assign"), p.operands[1:]...) {
		if name, _, ok := strings.Cut(v, "="); ok && strings.EqualFold(name, "ENVIRON") {
			return fmt.Errorf("%s : ENVIRON non admis", prog)
		}
	}
	return awkProgram(prog, p.operands[0])
}

var awkOperandEnd = map[lexer.Token]bool{lexer.NAME: true, lexer.NUMBER: true, lexer.STRING: true, lexer.REGEX: true, lexer.RPAREN: true, lexer.RBRACKET: true, lexer.INCR: true, lexer.DECR: true}

func awkProgram(prog, src string) error {
	if _, err := parser.ParseProgram([]byte(src), nil); err != nil {
		return fmt.Errorf("%s : programme illisible : %v", prog, err)
	}
	lx := lexer.NewLexer([]byte(src))
	prev := lexer.NEWLINE
	inPrint, depth := false, 0
	for {
		_, tok, val := lx.Scan()
		if (tok == lexer.DIV || tok == lexer.DIV_ASSIGN) && !awkOperandEnd[prev] {
			_, tok, val = lx.ScanRegex()
		}
		switch tok {
		case lexer.EOF:
			return nil
		case lexer.ILLEGAL:
			return fmt.Errorf("%s : programme illisible : %s", prog, val)
		case lexer.GETLINE, lexer.F_SYSTEM, lexer.F_CLOSE, lexer.F_FFLUSH, lexer.PIPE, lexer.APPEND:
			return fmt.Errorf("%s : %s non admis (fichier, commande ou flux)", prog, tok)
		case lexer.NAME:
			if val == "ENVIRON" {
				return fmt.Errorf("%s : ENVIRON non admis", prog)
			}
		case lexer.PRINT, lexer.PRINTF:
			inPrint, depth = true, 0
		case lexer.LPAREN, lexer.LBRACKET:
			depth++
		case lexer.RPAREN, lexer.RBRACKET:
			depth--
		case lexer.NEWLINE, lexer.SEMICOLON, lexer.RBRACE, lexer.LBRACE:
			inPrint = false
		case lexer.GREATER:
			if inPrint && depth <= 0 {
				return fmt.Errorf("%s : print > écrit un fichier", prog)
			}
		}
		prev = tok
	}
}

var metaPrograms = set("ls", "stat", "file", "getfacl", "lsattr", "readlink", "realpath", "namei", "du", "sha1sum", "sha256sum", "sha512sum", "md5sum", "wc")

func innerCommand(prog string, inner []arg, extra map[string]bool) error {
	if len(inner) == 0 {
		return fmt.Errorf("%s sans commande", prog)
	}
	if !inner[0].lit {
		return fmt.Errorf("%s : commande non littérale", prog)
	}
	name := path.Base(inner[0].s)
	if !metaPrograms[name] && !extra[name] {
		return fmt.Errorf("%s %s : seules les commandes de métadonnées (ls, stat, sha256sum…) sont admises", prog, name)
	}
	return readOnlyCall(inner)
}

func findExec(rest []arg) error {
	for i := 0; i < len(rest); i++ {
		if rest[i].s != "-exec" && rest[i].s != "-execdir" {
			continue
		}
		j := i + 1
		for j < len(rest) && rest[j].s != ";" && rest[j].s != "+" {
			j++
		}
		if j >= len(rest) {
			return fmt.Errorf("find %s sans ; ni +", rest[i].s)
		}
		if err := innerCommand("find "+rest[i].s, rest[i+1:j], nil); err != nil {
			return err
		}
		i = j
	}
	return nil
}

var xargsAttached = regexp.MustCompile(`^(-[nLPs][0-9]+|--(max-args|max-lines|max-procs|delimiter|max-chars)=.+)$`)

func checkXargs(prog string, rest []arg) error {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i].s, "-") {
		s := rest[i].s
		switch {
		case slices.Contains([]string{"-0", "-r", "-t", "--null", "--no-run-if-empty", "--verbose", "-x", "--exit"}, s):
		case slices.Contains([]string{"-n", "-L", "-P", "-d", "-s", "-I"}, s):
			i++
		case xargsAttached.MatchString(s):
		default:
			return refusedOption(prog, s)
		}
		i++
	}
	return innerCommand(prog, rest[i:], set("grep", "egrep", "fgrep", "zgrep"))
}

func checkTail(prog string, rest []arg) error {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !a.lit {
			continue
		}
		s := a.s
		switch {
		case s == "--follow" || strings.HasPrefix(s, "--follow=") || s == "--retry":
			return fmt.Errorf("tail %s : suivi sans fin", s)
		case strings.HasPrefix(s, "--"):
		case len(s) > 1 && s[0] == '-':
			for j := 1; j < len(s); j++ {
				c := s[j]
				if c == 'f' || c == 'F' {
					return fmt.Errorf("tail %s : suivi sans fin", s)
				}
				if c == 'n' || c == 'c' || c == 's' {
					if j == len(s)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return nil
}

var (
	psValue   = set("-p", "-u", "-U", "-g", "-G", "-o", "-O", "-C", "-t", "-q", "-s", "--pid", "--user", "--User", "--group", "--Group", "--format", "--sort", "--ppid", "--sid", "--tty", "p", "U", "t", "o", "O", "k", "q")
	bsdLetter = regexp.MustCompile(`^[a-zA-Z]+$`)
)

func checkPs(prog string, rest []arg) error {
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		if psValue[s] {
			i++
			continue
		}
		if !strings.HasPrefix(s, "-") && strings.ContainsRune(s, 'e') && (i == 0 || !psValue[rest[i-1].s]) && bsdLetter.MatchString(s) {
			return fmt.Errorf("ps %s : affiche l'environnement des processus", s)
		}
	}
	return nil
}

func checkGetent(prog string, rest []arg) error {
	for _, a := range rest {
		if strings.HasPrefix(a.s, "-") {
			continue
		}
		if a.s == "shadow" || a.s == "gshadow" || !a.lit {
			return fmt.Errorf("getent %s : base des mots de passe", a.s)
		}
		return nil
	}
	return nil
}

var (
	nodeProcess = set("version", "versions", "arch", "platform", "release", "config", "features")
	nodeModules = set("zlib", "crypto", "tls", "http2", "os", "buffer")
)

type jsTok struct {
	kind byte
	s    string
}

func jsTokens(src string) ([]jsTok, error) {
	var out []jsTok
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					return nil, fmt.Errorf("échappement non admis")
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("chaîne non terminée")
			}
			out = append(out, jsTok{'s', src[i+1 : j]})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			out = append(out, jsTok{'n', src[i:j]})
			i = j
		case c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(src) && (src[j] == '_' || src[j] == '$' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			out = append(out, jsTok{'i', src[i:j]})
			i = j
		case strings.IndexByte(".()[]+,;", c) >= 0:
			out = append(out, jsTok{c, string(c)})
			i++
		default:
			return nil, fmt.Errorf("caractère %q non admis", c)
		}
	}
	return out, nil
}

type jsParser struct {
	t []jsTok
	i int
}

func (p *jsParser) peek() jsTok {
	if p.i < len(p.t) {
		return p.t[p.i]
	}
	return jsTok{}
}

func (p *jsParser) eat(kind byte, s string) bool {
	t := p.peek()
	if t.kind == kind && (s == "" || t.s == s) {
		p.i++
		return true
	}
	return false
}

func (p *jsParser) expr() error {
	if err := p.unary(); err != nil {
		return err
	}
	for p.eat('+', "") {
		if err := p.unary(); err != nil {
			return err
		}
	}
	return nil
}

func (p *jsParser) unary() error {
	if p.eat('i', "typeof") {
		return p.unary()
	}
	return p.primary()
}

func (p *jsParser) primary() error {
	t := p.peek()
	switch {
	case p.eat('s', "") || p.eat('n', ""):
		return nil
	case p.eat('(', ""):
		if err := p.expr(); err != nil {
			return err
		}
		if !p.eat(')', "") {
			return fmt.Errorf("parenthèse non fermée")
		}
		return nil
	case t.kind == 'i' && t.s == "JSON":
		p.i++
		if !p.eat('.', "") || !p.eat('i', "stringify") || !p.eat('(', "") {
			return fmt.Errorf("seul JSON.stringify est admis")
		}
		if err := p.expr(); err != nil {
			return err
		}
		if p.eat(',', "") {
			if !p.eat('i', "null") || !p.eat(',', "") || !p.eat('n', "") {
				return fmt.Errorf("JSON.stringify : arguments non admis")
			}
		}
		if !p.eat(')', "") {
			return fmt.Errorf("parenthèse non fermée")
		}
		return nil
	case t.kind == 'i' && t.s == "process":
		p.i++
		if !p.eat('.', "") || !nodeProcess[p.peek().s] || !p.eat('i', "") {
			return fmt.Errorf("seuls process.version, versions, arch, platform, release, config et features sont admis")
		}
		return p.accessors()
	case t.kind == 'i' && t.s == "require":
		p.i++
		if !p.eat('(', "") || !nodeModules[p.peek().s] || !p.eat('s', "") || !p.eat(')', "") {
			return fmt.Errorf("require : seuls les modules intégrés %s sont admis", "zlib, crypto, tls, http2, os, buffer")
		}
		return p.accessors()
	}
	return fmt.Errorf("expression %q non admise", t.s)
}

func (p *jsParser) accessors() error {
	for {
		switch {
		case p.eat('.', ""):
			if !p.eat('i', "") {
				return fmt.Errorf("propriété attendue")
			}
		case p.eat('[', ""):
			if !p.eat('s', "") || !p.eat(']', "") {
				return fmt.Errorf("seul un nom de propriété littéral est admis entre crochets")
			}
		default:
			if p.peek().kind == '(' {
				return fmt.Errorf("appel de fonction non admis")
			}
			return nil
		}
	}
}

func nodeExpression(src string, wrapped bool) error {
	toks, err := jsTokens(src)
	if err != nil {
		return err
	}
	p := &jsParser{t: toks}
	if wrapped {
		if !p.eat('i', "console") || !p.eat('.', "") || !p.eat('i', "log") || !p.eat('(', "") {
			return fmt.Errorf("seul console.log(...) est admis avec -e")
		}
	}
	if err := p.expr(); err != nil {
		return err
	}
	if wrapped && !p.eat(')', "") {
		return fmt.Errorf("parenthèse non fermée")
	}
	p.eat(';', "")
	if p.i != len(p.t) {
		return fmt.Errorf("expression non admise après %q", p.t[p.i-1].s)
	}
	return nil
}
