package sysprobe

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/driver/ssh"
)

const (
	System      = "system"
	CPU         = "cpu"
	Memory      = "memory"
	Disk        = "disk"
	Network     = "network"
	Connections = "connections"

	MaxBytes    = 4 << 20
	filesPerPID = 20
	mark        = "@@ "
)

var sectionCmd = map[string]string{
	"uptime":    "cat /proc/uptime",
	"conf":      "getconf PAGESIZE; getconf CLK_TCK",
	"stat":      "cat /proc/stat",
	"loadavg":   "cat /proc/loadavg",
	"pressure":  "grep -H '' /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io",
	"meminfo":   "cat /proc/meminfo",
	"vmstat":    "cat /proc/vmstat",
	"diskstats": "cat /proc/diskstats",
	"blocks":    "ls -1 /sys/block",
	"dm":        "grep -H '' /sys/block/dm-*/dm/name",
	"df":        "$T df -P -l -k",
	"dfi":       "$T df -P -l -i",
	"netdev":    "cat /proc/net/dev",
	"snmp":      "cat /proc/net/snmp",
	"netstat":   "cat /proc/net/netstat",
	"sockstat":  "cat /proc/net/sockstat",
	"conntrack": "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max",
	"filenr":    "cat /proc/sys/fs/file-nr",
	"pids":      `cat /proc/[0-9]*/stat | awk '{p=$1; sub(/^.*\) /,""); print p, $1, $10, $12, $13, $22, $40}'`,
	"dtasks":    `L=$(grep -l ') D ' /proc/[0-9]*/task/[0-9]*/stat); echo "total $(echo "$L" | grep -c /)"; for f in $(echo "$L" | head -n 50); do d=${f%/stat}; printf '%s|%s|%s|' "$d" "$(cat $d/wchan)" "$(head -n 8 $d/stack | awk '{printf "%s ", $2}')"; head -c 160 $f; echo; done`,
	"delayacct": "cat /proc/sys/kernel/task_delayacct",
	"nfs":       "awk '/^device /{n=($0 ~ / with fstype nfs/)} n' /proc/self/mountstats",
	"mounts":    "cat /proc/self/mounts",
	"pidio":     "grep -H -E '^(rchar|wchar|read_bytes|write_bytes)' /proc/[0-9]*/io",
	"ps":        "ps -eo pid=,user:32=,args= | cut -c1-200",
	"ss":        "ss -s",
	"sstan":     "ss -tan",
}

var order = []string{"uptime", "conf", "stat", "loadavg", "pressure", "meminfo", "vmstat", "diskstats", "blocks", "dm", "df", "dfi", "netdev", "snmp", "netstat", "sockstat", "conntrack", "filenr", "pids", "dtasks", "delayacct", "nfs", "mounts", "pidio", "ps", "ss", "sstan"}

var (
	cpuSections  = []string{"loadavg", "pressure", "pids", "dtasks", "ps"}
	memSections  = []string{"meminfo", "vmstat", "pressure", "pids", "ps"}
	diskSections = []string{"diskstats", "blocks", "dm", "df", "dfi", "mounts", "nfs", "pressure", "pids", "dtasks", "delayacct", "pidio", "ps"}
	netSections  = []string{"netdev", "snmp", "netstat", "sockstat", "conntrack", "ss"}
)

func sections(probe string) []string {
	var out []string
	switch probe {
	case CPU:
		out = cpuSections
	case Memory:
		out = memSections
	case Disk:
		out = diskSections
	case Network:
		out = netSections
	case Connections:
		out = append(slices.Clone(netSections), "sstan")
	case System:
		out = slices.Concat(cpuSections, memSections, diskSections, netSections, []string{"filenr"})
	default:
		return nil
	}
	all := []string{"uptime", "conf", "stat"}
	for _, s := range out {
		if !slices.Contains(all, s) {
			all = append(all, s)
		}
	}
	return all
}

func Names() []string {
	return []string{System, CPU, Memory, Disk, Network, Connections}
}

func Valid(probe string) bool {
	return sections(probe) != nil
}

func Script(probe string) (string, bool) {
	secs := sections(probe)
	if secs == nil {
		return "", false
	}
	var b strings.Builder
	b.WriteString("T=; command -v timeout >/dev/null 2>&1 && T='timeout 5'; ")
	for _, s := range secs {
		b.WriteString("echo '" + mark + s + "'; { " + sectionCmd[s] + "; } 2>/dev/null; ")
	}
	b.WriteString("exit 0")
	return b.String(), true
}

func Command(probe string, b ssh.Builder) (string, bool) {
	s, ok := Script(probe)
	if !ok {
		return "", false
	}
	return b.Shell(s), true
}

type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal float64
}

func (c cpuTimes) total() float64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

type psi struct {
	avg10, avg60 float64
	total        float64
}

type disk struct {
	reads, rsect, rms, writes, wsect, wms, inflight, ioms, weighted float64
}

type iface struct {
	rxBytes, rxPkts, rxErrs, rxDrop, txBytes, txPkts, txErrs, txDrop float64
}

type fsUse struct {
	dev, mount       string
	sizeKB, usedKB   int64
	pct, inodePct    int
	hasInode, hasPct bool
}

type proc struct {
	state                              string
	majflt, utime, stime, rssPg, blkio float64
}

type ioc struct {
	rchar, wchar, rb, wb float64
}

type dtask struct {
	pid               int
	tid, wchan, stack string
	comm              string
}

type nfsOp struct {
	ops, trans, timeouts, queue, rtt, exec float64
}

type nfsMount struct {
	dev, fstype string
	bytes       []float64
	ops         map[string]nfsOp
	opOrder     []string
}

type mount struct {
	dev, path, fstype string
}

type pinfo struct {
	user, args string
}

type Snapshot struct {
	Took time.Duration

	seen      map[string]bool
	uptime    float64
	pageSize  float64
	clkTck    float64
	ncpu      int
	cpu       cpuTimes
	hasCPU    bool
	ctxt      float64
	intr      float64
	running   int64
	blocked   int64
	load      [3]float64
	tasks     string
	psi       map[string]psi
	mem       map[string]int64
	vm        map[string]float64
	disks     map[string]disk
	diskOrder []string
	blocks    map[string]bool
	dm        map[string]string
	ifaces    map[string]iface
	ifOrder   []string
	snmp      map[string]float64
	sock      map[string]int64
	conntrack []int64
	filenr    []int64
	fs        []fsUse
	procs     map[int]proc
	io        map[int]ioc
	dtasks    []dtask
	dtotal    int
	delayacct int
	nfs       map[string]*nfsMount
	nfsOrder  []string
	mounts    []mount
	ps        map[int]pinfo
	ss        string
	sstan     string
}

func (s *Snapshot) has(sec string) bool {
	return s != nil && s.seen[sec]
}

func Parse(out string) *Snapshot {
	s := &Snapshot{seen: map[string]bool{}, pageSize: 4096, clkTck: 100, delayacct: -1}
	body := map[string][]string{}
	cur := ""
	for _, l := range strings.Split(out, "\n") {
		if name, ok := strings.CutPrefix(l, mark); ok {
			cur = strings.TrimSpace(name)
			if _, known := sectionCmd[cur]; known {
				body[cur] = nil
			} else {
				cur = ""
			}
			continue
		}
		if cur != "" {
			body[cur] = append(body[cur], l)
		}
	}
	for _, name := range order {
		lines, ok := body[name]
		if !ok {
			continue
		}
		lines = trimEmpty(lines)
		if len(lines) == 0 {
			continue
		}
		s.seen[name] = true
		parseSection(s, name, lines)
	}
	return s
}

func trimEmpty(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func num(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func inum(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func parseSection(s *Snapshot, name string, lines []string) {
	switch name {
	case "uptime":
		if f := strings.Fields(lines[0]); len(f) > 0 {
			s.uptime = num(f[0])
		}
	case "conf":
		if len(lines) > 0 && num(lines[0]) > 0 {
			s.pageSize = num(lines[0])
		}
		if len(lines) > 1 && num(lines[1]) > 0 {
			s.clkTck = num(lines[1])
		}
	case "stat":
		parseStat(s, lines)
	case "loadavg":
		f := strings.Fields(lines[0])
		for i := 0; i < 3 && i < len(f); i++ {
			s.load[i] = num(f[i])
		}
		if len(f) > 3 {
			s.tasks = f[3]
		}
	case "pressure":
		s.psi = map[string]psi{}
		for _, l := range lines {
			file, rest, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			f := strings.Fields(rest)
			if len(f) == 0 {
				continue
			}
			var p psi
			for _, kv := range f[1:] {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "avg10":
					p.avg10 = num(v)
				case "avg60":
					p.avg60 = num(v)
				case "total":
					p.total = num(v)
				}
			}
			s.psi[file[strings.LastIndexByte(file, '/')+1:]+" "+f[0]] = p
		}
	case "meminfo":
		s.mem = map[string]int64{}
		for _, l := range lines {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			f := strings.Fields(v)
			if len(f) > 0 {
				s.mem[k] = inum(f[0])
			}
		}
	case "vmstat":
		s.vm = map[string]float64{}
		for _, l := range lines {
			if f := strings.Fields(l); len(f) == 2 {
				s.vm[f[0]] = num(f[1])
			}
		}
	case "diskstats":
		s.disks = map[string]disk{}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) < 14 {
				continue
			}
			s.disks[f[2]] = disk{reads: num(f[3]), rsect: num(f[5]), rms: num(f[6]), writes: num(f[7]), wsect: num(f[9]), wms: num(f[10]), inflight: num(f[11]), ioms: num(f[12]), weighted: num(f[13])}
			s.diskOrder = append(s.diskOrder, f[2])
		}
	case "blocks":
		s.blocks = map[string]bool{}
		for _, l := range lines {
			if l = strings.TrimSpace(l); l != "" {
				s.blocks[l] = true
			}
		}
	case "dm":
		s.dm = map[string]string{}
		for _, l := range lines {
			file, name, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			parts := strings.Split(file, "/")
			if len(parts) >= 4 {
				s.dm[parts[3]] = strings.TrimSpace(name)
			}
		}
	case "df", "dfi":
		parseDF(s, name == "dfi", lines)
	case "netdev":
		s.ifaces = map[string]iface{}
		for _, l := range lines {
			name, rest, ok := strings.Cut(l, ":")
			if !ok || strings.Contains(name, "|") {
				continue
			}
			f := strings.Fields(rest)
			if len(f) < 12 {
				continue
			}
			n := strings.TrimSpace(name)
			s.ifaces[n] = iface{rxBytes: num(f[0]), rxPkts: num(f[1]), rxErrs: num(f[2]), rxDrop: num(f[3]), txBytes: num(f[8]), txPkts: num(f[9]), txErrs: num(f[10]), txDrop: num(f[11])}
			s.ifOrder = append(s.ifOrder, n)
		}
	case "snmp", "netstat":
		if s.snmp == nil {
			s.snmp = map[string]float64{}
		}
		for i := 0; i+1 < len(lines); i += 2 {
			hk, hv, ok1 := strings.Cut(lines[i], ":")
			vk, vv, ok2 := strings.Cut(lines[i+1], ":")
			if !ok1 || !ok2 || hk != vk {
				i--
				continue
			}
			keys, vals := strings.Fields(hv), strings.Fields(vv)
			for j := range min(len(keys), len(vals)) {
				s.snmp[hk+"."+keys[j]] = num(vals[j])
			}
		}
	case "sockstat":
		s.sock = map[string]int64{}
		for _, l := range lines {
			proto, rest, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			f := strings.Fields(rest)
			for j := 0; j+1 < len(f); j += 2 {
				s.sock[proto+"."+f[j]] = inum(f[j+1])
			}
		}
	case "conntrack":
		if len(lines) >= 2 {
			s.conntrack = []int64{inum(lines[0]), inum(lines[1])}
		}
	case "filenr":
		f := strings.Fields(lines[0])
		if len(f) >= 3 {
			s.filenr = []int64{inum(f[0]), inum(f[2])}
		}
	case "pids":
		s.procs = map[int]proc{}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) < 6 {
				continue
			}
			pid, err := strconv.Atoi(f[0])
			if err != nil {
				continue
			}
			p := proc{state: f[1], majflt: num(f[2]), utime: num(f[3]), stime: num(f[4]), rssPg: num(f[5])}
			if len(f) > 6 {
				p.blkio = num(f[6])
			}
			s.procs[pid] = p
		}
	case "dtasks":
		parseDTasks(s, lines)
	case "delayacct":
		s.delayacct = int(inum(lines[0]))
	case "nfs":
		parseNFS(s, lines)
	case "mounts":
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) >= 3 {
				s.mounts = append(s.mounts, mount{dev: f[0], path: unescapeMount(f[1]), fstype: f[2]})
			}
		}
	case "pidio":
		s.io = map[int]ioc{}
		for _, l := range lines {
			file, kv, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			parts := strings.Split(file, "/")
			if len(parts) < 3 {
				continue
			}
			pid, err := strconv.Atoi(parts[2])
			if err != nil {
				continue
			}
			k, v, _ := strings.Cut(kv, ":")
			c := s.io[pid]
			switch strings.TrimSpace(k) {
			case "rchar":
				c.rchar = num(v)
			case "wchar":
				c.wchar = num(v)
			case "read_bytes":
				c.rb = num(v)
			case "write_bytes":
				c.wb = num(v)
			}
			s.io[pid] = c
		}
	case "ps":
		s.ps = map[int]pinfo{}
		for _, l := range lines {
			l = strings.TrimSpace(l)
			p, rest, ok := strings.Cut(l, " ")
			if !ok {
				continue
			}
			pid, err := strconv.Atoi(p)
			if err != nil {
				continue
			}
			rest = strings.TrimSpace(rest)
			user, args, _ := strings.Cut(rest, " ")
			s.ps[pid] = pinfo{user: user, args: strings.TrimSpace(args)}
		}
	case "ss":
		s.ss = strings.Join(lines, "\n")
	case "sstan":
		s.sstan = strings.Join(lines, "\n")
	}
}

func parseStat(s *Snapshot, lines []string) {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch {
		case f[0] == "cpu" && len(f) >= 9:
			s.cpu = cpuTimes{user: num(f[1]), nice: num(f[2]), system: num(f[3]), idle: num(f[4]), iowait: num(f[5]), irq: num(f[6]), softirq: num(f[7]), steal: num(f[8])}
			s.hasCPU = true
		case strings.HasPrefix(f[0], "cpu"):
			s.ncpu++
		case f[0] == "ctxt":
			s.ctxt = num(f[1])
		case f[0] == "intr":
			s.intr = num(f[1])
		case f[0] == "procs_running":
			s.running = inum(f[1])
		case f[0] == "procs_blocked":
			s.blocked = inum(f[1])
		}
	}
}

var pseudoFS = []string{"tmpfs", "devtmpfs", "overlay", "shm", "none", "udev", "squashfs"}

func parseDF(s *Snapshot, inodes bool, lines []string) {
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		dev, mount := f[0], strings.Join(f[5:], " ")
		if slices.Contains(pseudoFS, dev) || strings.HasPrefix(dev, "/dev/loop") {
			continue
		}
		pct, err := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		ok := err == nil
		i := slices.IndexFunc(s.fs, func(u fsUse) bool { return u.mount == mount })
		if i < 0 {
			if inodes {
				continue
			}
			s.fs = append(s.fs, fsUse{dev: dev, mount: mount})
			i = len(s.fs) - 1
		}
		if inodes {
			s.fs[i].inodePct, s.fs[i].hasInode = pct, ok
			continue
		}
		s.fs[i].sizeKB, s.fs[i].usedKB = inum(f[1]), inum(f[2])
		s.fs[i].pct, s.fs[i].hasPct = pct, ok
	}
}

func (s *Snapshot) Check() error {
	if !s.hasCPU || s.uptime <= 0 {
		return errors.New("compteurs du noyau illisibles (/proc/stat, /proc/uptime) : relevé possible seulement sur un hôte Linux")
	}
	return nil
}

func (s *Snapshot) Describe() string {
	d := fmt.Sprintf("%d vCPU", s.ncpu)
	if t := s.mem["MemTotal"]; t > 0 {
		d += ", mémoire " + kib(t)
	}
	return d + ", démarré depuis " + fmtDur(s.uptime)
}

func (s *Snapshot) Since(prev *Snapshot) string {
	if prev == nil || s.uptime <= prev.uptime {
		return "?"
	}
	return fmt.Sprintf("%.1f s", s.uptime-prev.uptime)
}

func parseDTasks(s *Snapshot, lines []string) {
	for _, l := range lines {
		if n, ok := strings.CutPrefix(l, "total "); ok {
			s.dtotal = int(inum(n))
			continue
		}
		f := strings.SplitN(l, "|", 4)
		if len(f) < 4 {
			continue
		}
		parts := strings.Split(f[0], "/")
		if len(parts) < 5 {
			continue
		}
		pid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		t := dtask{pid: pid, tid: parts[4], wchan: strings.TrimSpace(f[1]), stack: strings.TrimSpace(f[2]), comm: f[3]}
		if i, j := strings.IndexByte(f[3], '('), strings.LastIndex(f[3], ") D "); i >= 0 && j > i {
			t.comm = f[3][i+1 : j]
		}
		if t.wchan == "0" {
			t.wchan = ""
		}
		s.dtasks = append(s.dtasks, t)
	}
	if s.dtotal < len(s.dtasks) {
		s.dtotal = len(s.dtasks)
	}
}

func parseNFS(s *Snapshot, lines []string) {
	s.nfs = map[string]*nfsMount{}
	var cur *nfsMount
	perOp := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if rest, ok := strings.CutPrefix(t, "device "); ok {
			dev, after, _ := strings.Cut(rest, " mounted on ")
			path, fstype, _ := strings.Cut(after, " with fstype ")
			fstype, _, _ = strings.Cut(fstype, " ")
			cur = &nfsMount{dev: dev, fstype: fstype, ops: map[string]nfsOp{}}
			path = unescapeMount(path)
			s.nfs[path] = cur
			s.nfsOrder = append(s.nfsOrder, path)
			perOp = false
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "bytes:"):
			for _, v := range strings.Fields(strings.TrimPrefix(t, "bytes:")) {
				cur.bytes = append(cur.bytes, num(v))
			}
		case t == "per-op statistics":
			perOp = true
		case perOp:
			name, rest, ok := strings.Cut(t, ":")
			f := strings.Fields(rest)
			if !ok || len(f) < 8 {
				continue
			}
			cur.ops[name] = nfsOp{ops: num(f[0]), trans: num(f[1]), timeouts: num(f[2]), queue: num(f[5]), rtt: num(f[6]), exec: num(f[7])}
			cur.opOrder = append(cur.opOrder, name)
		}
	}
}

func unescapeMount(p string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(p)
}

func FilesScript(pids []int) string {
	var b strings.Builder
	for _, pid := range pids {
		fmt.Fprintf(&b, "echo '%sfiles %d'; { find /proc/%d/fd -maxdepth 1 -type l -printf '%%l\\n' | grep '^/' | grep -v -E '^/(dev|proc|sys)/' | sort | uniq -c | sort -rn | head -n %d; } 2>/dev/null; ", mark, pid, pid, filesPerPID)
	}
	b.WriteString("exit 0")
	return b.String()
}

func FilesCommand(pids []int, b ssh.Builder) string {
	return b.Shell(FilesScript(pids))
}

type fileUse struct {
	count int
	path  string
}

func ParseFiles(out string) map[int][]fileUse {
	res := map[int][]fileUse{}
	pid := -1
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(l, mark+"files "); ok {
			n, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				pid = -1
				continue
			}
			pid = n
			res[pid] = nil
			continue
		}
		t := strings.TrimSpace(l)
		if pid < 0 || t == "" {
			continue
		}
		c, path, ok := strings.Cut(t, " ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(c)
		if err != nil {
			continue
		}
		res[pid] = append(res[pid], fileUse{count: n, path: path})
	}
	return res
}
