package sysprobe

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

const (
	alertBusy       = 90.0
	alertIowait     = 20.0
	alertSteal      = 10.0
	alertLoad       = 2.0
	alertPSISome    = 20.0
	alertPSIFull    = 5.0
	alertMemAvail   = 5.0
	alertSwap       = 10.0
	alertMajflt     = 100.0
	alertDiskUtil   = 90.0
	alertAwait      = 50.0
	alertFS         = 95
	alertRetrans    = 2.0
	alertRetransMin = 100.0
	alertNetDrop    = 10.0
	alertTable      = 90.0
	alertResponse   = 5 * time.Second

	topN      = 10
	topIfaces = 8
	maxHot    = 8
	hotDisk   = 3
	hotApp    = 2
	hotRate   = 1 << 20
)

func Legend() string {
	return fmt.Sprintf("seuils d'alerte (signalement en direct, pas une conclusion) : CPU occupé ≥ %.0f %%, iowait ≥ %.0f %%, steal ≥ %.0f %%, charge ≥ %.0f × vCPU, tâches en attente d'E/S (procs_blocked) ≥ max(2, vCPU/4), pression some ≥ %.0f %% ou full ≥ %.0f %%, mémoire disponible < %.0f %%, swap ≥ %.0f pages/s, OOM killer, récupération directe de mémoire, défauts majeurs ≥ %.0f/s, disque occupé ≥ %.0f %% ou attente ≥ %.0f ms (aussi par opération NFS), expirations NFS, système de fichiers ou inodes ≥ %d %%, pertes réseau ≥ %.0f/s (le noyau compte aussi en pertes les trames d'un protocole non géré, d'où un bruit de fond), erreurs réseau, retransmissions TCP ≥ %.0f %%, files d'écoute débordées, erreurs de tampon UDP, conntrack ou descripteurs de fichiers ≥ %.0f %%, réponse de l'hôte ≥ %s. Pression (PSI) : part du temps où des tâches attendent la ressource (some : au moins une, full : toutes). Occupation d'un disque : part du temps avec au moins une E/S en cours ; un SSD, un NVMe ou un volume réseau traite des E/S en parallèle et peut afficher 100 %% sans être saturé : juger sur l'attente et la file.",
		alertBusy, alertIowait, alertSteal, alertLoad, alertPSISome, alertPSIFull, alertMemAvail, alertSwap, alertMajflt, alertDiskUtil, alertAwait, alertFS, alertNetDrop, alertRetrans, alertTable, alertResponse)
}

type Alert struct {
	Key  string
	Args []any
}

func (a Alert) Text(lang string) string {
	return i18n.In(lang, "probe.alert."+a.Key, a.Args...)
}

type Report struct {
	Lines  []string
	Alerts []Alert
	Hot    []int
	sum    []Alert
}

func (r *Report) line(format string, args ...any) {
	r.Lines = append(r.Lines, fmt.Sprintf(format, args...))
}

func (r *Report) alert(key string, args ...any) {
	r.Alerts = append(r.Alerts, Alert{Key: key, Args: args})
}

func (r *Report) summary(key string, args ...any) {
	r.sum = append(r.sum, Alert{Key: key, Args: args})
}

func (r Report) Summary(lang string) string {
	parts := make([]string, 0, len(r.sum))
	for _, s := range r.sum {
		parts = append(parts, i18n.In(lang, "probe.sum."+s.Key, s.Args...))
	}
	return strings.Join(parts, " · ")
}

func (r Report) AlertLine(lang string) string {
	parts := make([]string, 0, len(r.Alerts))
	for _, a := range r.Alerts {
		parts = append(parts, a.Text(lang))
	}
	return strings.Join(parts, " ; ")
}

func (r Report) Text() string {
	lines := r.Lines
	if len(r.Alerts) > 0 {
		lines = append(slices.Clone(lines), "⚠ au-delà des seuils : "+r.AlertLine("fr"))
	}
	return strings.Join(lines, "\n")
}

type differ struct {
	prev, cur *Snapshot
	dt        float64
	probe     string
	r         Report
}

func (d *differ) rate(a, b float64) float64 {
	if d.dt <= 0 || b < a {
		return 0
	}
	return (b - a) / d.dt
}

func (d *differ) delta(a, b float64) float64 {
	if b < a {
		return 0
	}
	return b - a
}

func (d *differ) wants(probes ...string) bool {
	return d.probe == System || slices.Contains(probes, d.probe)
}

func Diff(prev, cur *Snapshot, probe string) Report {
	d := &differ{prev: prev, cur: cur, probe: probe}
	if prev != nil && cur.uptime > 0 && prev.uptime > 0 {
		d.dt = cur.uptime - prev.uptime
		if d.dt <= 0 {
			d.r.line("hôte redémarré depuis le relevé précédent (uptime %s) : débits recalculés à partir de ce relevé", fmtDur(cur.uptime))
			d.r.alert("reboot")
		}
	}
	if d.dt <= 0 {
		d.prev, d.dt = nil, 0
	}
	if d.wants(CPU, Memory, Disk) {
		d.cpu()
		d.load()
	}
	d.pressure()
	if d.wants(Memory) {
		d.memory()
	}
	if d.wants(Disk) {
		d.disks()
		d.filesystems()
		d.netMounts()
		d.nfs()
	}
	if d.wants(Network, Connections) {
		d.network()
		d.tcp()
		d.sockets()
	}
	if d.wants() {
		d.files()
	}
	if d.wants(CPU, Memory, Disk) {
		d.processes()
	}
	if d.wants(Network, Connections) && cur.ss != "" {
		d.r.line("ss -s :")
		d.block(cur.ss)
	}
	if probe == Connections && cur.sstan != "" {
		d.r.line("connexions TCP (ss -tan) :")
		d.block(cur.sstan)
	}
	if cur.Took >= alertResponse {
		d.r.alert("slow", cur.Took.Seconds())
	}
	return d.r
}

func (d *differ) block(text string) {
	for _, l := range strings.Split(text, "\n") {
		d.r.Lines = append(d.r.Lines, "  "+l)
	}
}

func (d *differ) missing(sec, what string) bool {
	if d.cur.has(sec) {
		return false
	}
	d.r.line("%s : indisponible sur cet hôte", what)
	return true
}

func (d *differ) cpu() {
	c := d.cur
	if !c.hasCPU {
		d.r.line("cpu : /proc/stat illisible")
		return
	}
	if d.prev == nil || !d.prev.hasCPU {
		d.r.line("cpu (%d vCPU) : répartition calculée à partir du relevé suivant", c.ncpu)
		return
	}
	p := d.prev.cpu
	t := cpuTimes{user: d.delta(p.user, c.cpu.user), nice: d.delta(p.nice, c.cpu.nice), system: d.delta(p.system, c.cpu.system), idle: d.delta(p.idle, c.cpu.idle), iowait: d.delta(p.iowait, c.cpu.iowait), irq: d.delta(p.irq, c.cpu.irq), softirq: d.delta(p.softirq, c.cpu.softirq), steal: d.delta(p.steal, c.cpu.steal)}
	tot := t.total()
	if tot <= 0 {
		return
	}
	pc := func(v float64) float64 { return v / tot * 100 }
	busy := pc(t.user + t.nice + t.system + t.irq + t.softirq)
	d.r.line("cpu (%d vCPU) : occupé %.1f %% (user %.1f, nice %.1f, system %.1f, irq %.1f, softirq %.1f) · iowait %.1f %% · steal %.1f %% · idle %.1f %%", c.ncpu, busy, pc(t.user), pc(t.nice), pc(t.system), pc(t.irq), pc(t.softirq), pc(t.iowait), pc(t.steal), pc(t.idle))
	d.r.summary("cpu", busy, pc(t.iowait), pc(t.steal))
	if busy >= alertBusy {
		d.r.alert("busy", busy)
	}
	if pc(t.iowait) >= alertIowait {
		d.r.alert("iowait", pc(t.iowait))
	}
	if pc(t.steal) >= alertSteal {
		d.r.alert("steal", pc(t.steal))
	}
}

func (d *differ) load() {
	c := d.cur
	if !c.has("loadavg") {
		return
	}
	per := 0.0
	if c.ncpu > 0 {
		per = c.load[0] / float64(c.ncpu)
	}
	s := fmt.Sprintf("charge : %.2f sur 1 min, %.2f sur 5 min, %.2f sur 15 min (%.2f par vCPU) · tâches exécutables %d · tâches en attente d'E/S (procs_blocked) %d", c.load[0], c.load[1], c.load[2], per, c.running, c.blocked)
	if d.prev != nil {
		s += fmt.Sprintf(" · commutations de contexte %.0f/s · interruptions %.0f/s", d.rate(d.prev.ctxt, c.ctxt), d.rate(d.prev.intr, c.intr))
	}
	d.r.Lines = append(d.r.Lines, s)
	if c.ncpu > 0 && per >= alertLoad {
		d.r.alert("load", c.load[0], c.ncpu)
	}
	if c.blocked >= int64(max(2, c.ncpu/4)) {
		d.r.alert("blocked", c.blocked)
	}
}

func (d *differ) pressure() {
	var res []string
	if d.wants(CPU) {
		res = append(res, "cpu")
	}
	if d.wants(Memory) {
		res = append(res, "memory")
	}
	if d.wants(Disk) {
		res = append(res, "io")
	}
	if len(res) == 0 {
		return
	}
	if d.missing("pressure", "pression (PSI)") {
		return
	}
	var parts []string
	for _, r := range res {
		var vals []string
		for _, kind := range []string{"some", "full"} {
			if r == "cpu" && kind == "full" {
				continue
			}
			k := r + " " + kind
			p, ok := d.cur.psi[k]
			if !ok {
				continue
			}
			v := p.avg10
			if d.prev != nil {
				if q, ok := d.prev.psi[k]; ok {
					v = min(d.rate(q.total, p.total)/1e4, 100)
				}
			}
			vals = append(vals, fmt.Sprintf("%s %.1f %% (avg10 %.1f, avg60 %.1f)", kind, v, p.avg10, p.avg60))
			switch {
			case kind == "some" && v >= alertPSISome:
				d.r.alert("psi_some", r, v)
			case kind == "full" && v >= alertPSIFull:
				d.r.alert("psi_full", r, v)
			}
		}
		if len(vals) > 0 {
			parts = append(parts, r+" "+strings.Join(vals, ", "))
		}
	}
	if len(parts) > 0 {
		label := "sur l'intervalle"
		if d.prev == nil {
			label = "avg10"
		}
		d.r.line("pression (%s) : %s", label, strings.Join(parts, " · "))
	}
}

func sumPrefix(m map[string]float64, prefix string) float64 {
	var t float64
	for k, v := range m {
		if strings.HasPrefix(k, prefix) && !strings.Contains(k, "throttle") {
			t += v
		}
	}
	return t
}

func (d *differ) memory() {
	c := d.cur
	if d.missing("meminfo", "mémoire") {
		return
	}
	m := c.mem
	total := m["MemTotal"]
	avail, ok := m["MemAvailable"]
	if !ok {
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	pct := 0.0
	if total > 0 {
		pct = float64(avail) / float64(total) * 100
	}
	d.r.line("mémoire : disponible %s sur %s (%.1f %%) · libre %s · cache %s · tampons %s · anonyme %s · partagée %s · sale %s · en écriture %s · slab %s (non récupérable %s) · engagée %s pour une limite de %s",
		kib(avail), kib(total), pct, kib(m["MemFree"]), kib(m["Cached"]), kib(m["Buffers"]), kib(m["AnonPages"]), kib(m["Shmem"]), kib(m["Dirty"]), kib(m["Writeback"]), kib(m["Slab"]), kib(m["SUnreclaim"]), kib(m["Committed_AS"]), kib(m["CommitLimit"]))
	if hp := m["HugePages_Total"]; hp > 0 {
		d.r.line("huge pages : %d au total, %d libres (%s chacune)", hp, m["HugePages_Free"], kib(m["Hugepagesize"]))
	}
	d.r.summary("mem", pct)
	if total > 0 && pct < alertMemAvail {
		d.r.alert("mem", pct)
	}
	swapLine := fmt.Sprintf("swap : utilisé %s sur %s", kib(m["SwapTotal"]-m["SwapFree"]), kib(m["SwapTotal"]))
	if !c.has("vmstat") {
		d.r.Lines = append(d.r.Lines, swapLine)
		return
	}
	v := c.vm
	if d.prev == nil || d.prev.vm == nil {
		d.r.Lines = append(d.r.Lines, swapLine)
		if n, ok := v["oom_kill"]; ok {
			d.r.line("OOM killer : %.0f processus tués depuis le démarrage", n)
		}
		return
	}
	p := d.prev.vm
	in, out := d.rate(p["pswpin"], v["pswpin"]), d.rate(p["pswpout"], v["pswpout"])
	d.r.line("%s · entrées %.1f pages/s · sorties %.1f pages/s", swapLine, in, out)
	if in+out > 0 {
		d.r.summary("swap", in+out)
	}
	if in+out >= alertSwap {
		d.r.alert("swap", in+out)
	}
	maj := d.rate(p["pgmajfault"], v["pgmajfault"])
	stall := d.rate(sumPrefix(p, "allocstall"), sumPrefix(v, "allocstall"))
	s := fmt.Sprintf("pagination : défauts majeurs %.1f/s · défauts %.0f/s · pages analysées par kswapd %.0f/s · par récupération directe %.0f/s · blocages d'allocation (récupération directe) %.1f/s · refautes du working set %.0f/s",
		maj, d.rate(p["pgfault"], v["pgfault"]), d.rate(sumPrefix(p, "pgscan_kswapd"), sumPrefix(v, "pgscan_kswapd")), d.rate(sumPrefix(p, "pgscan_direct"), sumPrefix(v, "pgscan_direct")), stall, d.rate(sumPrefix(p, "workingset_refault"), sumPrefix(v, "workingset_refault")))
	if n, ok := v["oom_kill"]; ok {
		oom := d.delta(p["oom_kill"], n)
		s += fmt.Sprintf(" · OOM killer +%.0f (%.0f depuis le démarrage)", oom, n)
		if oom > 0 {
			d.r.alert("oom", oom)
		}
	}
	d.r.Lines = append(d.r.Lines, s)
	if maj >= alertMajflt {
		d.r.alert("majflt", maj)
	}
	if stall > 0 {
		d.r.alert("reclaim", stall)
	}
}

var skipDisk = []string{"loop", "ram", "zram", "sr", "fd"}

func (d *differ) diskName(n string) string {
	if dm, ok := d.cur.dm[n]; ok && dm != "" {
		return n + " (" + dm + ")"
	}
	return n
}

func (d *differ) disks() {
	c := d.cur
	if d.missing("diskstats", "disques") {
		return
	}
	var names []string
	for _, n := range c.diskOrder {
		if c.blocks != nil && !c.blocks[n] {
			continue
		}
		if slices.ContainsFunc(skipDisk, func(p string) bool { return strings.HasPrefix(n, p) }) {
			continue
		}
		names = append(names, n)
	}
	if d.prev == nil || d.prev.disks == nil {
		d.r.line("disques (%s) : débits calculés à partir du relevé suivant", strings.Join(names, ", "))
		for _, n := range names {
			if f := c.disks[n].inflight; f > 0 {
				d.r.line("  %s : %.0f E/S en cours", d.diskName(n), f)
			}
		}
		return
	}
	d.r.line("disques :")
	var idle []string
	best, bestUtil, bestAwait := "", -1.0, 0.0
	for _, n := range names {
		a, b := d.prev.disks[n], c.disks[n]
		dr, dw := d.delta(a.reads, b.reads), d.delta(a.writes, b.writes)
		r, w := dr/d.dt, dw/d.dt
		if r+w == 0 && b.inflight == 0 {
			idle = append(idle, n)
			continue
		}
		rAwait, wAwait := 0.0, 0.0
		if dr > 0 {
			rAwait = d.delta(a.rms, b.rms) / dr
		}
		if dw > 0 {
			wAwait = d.delta(a.wms, b.wms) / dw
		}
		util := min(d.delta(a.ioms, b.ioms)/(d.dt*10), 100)
		queue := d.delta(a.weighted, b.weighted) / (d.dt * 1000)
		d.r.line("  %s : %.1f lectures/s %.1f écritures/s · %s/s lus %s/s écrits · attente moyenne lecture %.1f ms écriture %.1f ms · occupation %.0f %% · file moyenne %.2f · en cours %.0f",
			d.diskName(n), r, w, bytes(d.rate(a.rsect, b.rsect)*512), bytes(d.rate(a.wsect, b.wsect)*512), rAwait, wAwait, util, queue, b.inflight)
		if util > bestUtil {
			best, bestUtil, bestAwait = n, util, max(rAwait, wAwait)
		}
		if util >= alertDiskUtil {
			d.r.alert("disk_util", n, util)
		}
		if aw := max(rAwait, wAwait); aw >= alertAwait && r+w >= 1 {
			d.r.alert("disk_await", n, aw)
		}
	}
	if len(idle) > 0 {
		d.r.line("  sans E/S sur l'intervalle : %s", strings.Join(idle, ", "))
	}
	if best != "" {
		d.r.summary("disk", best, bestUtil, bestAwait)
	}
}

func (d *differ) filesystems() {
	c := d.cur
	if d.missing("df", "systèmes de fichiers") {
		return
	}
	d.r.line("systèmes de fichiers locaux :")
	for _, f := range c.fs {
		s := fmt.Sprintf("  %s (%s) : %s utilisés sur %s", f.mount, f.dev, kib(f.usedKB), kib(f.sizeKB))
		if f.hasPct {
			s += fmt.Sprintf(" (%d %%)", f.pct)
			if f.pct >= alertFS {
				d.r.alert("fs", f.mount, f.pct)
			}
		}
		if f.hasInode {
			s += fmt.Sprintf(", inodes %d %%", f.inodePct)
			if f.inodePct >= alertFS {
				d.r.alert("inodes", f.mount, f.inodePct)
			}
		}
		d.r.Lines = append(d.r.Lines, s)
	}
}

type ifRate struct {
	name                                 string
	rx, tx, rxp, txp, rxe, txe, rxd, txd float64
}

func (d *differ) network() {
	c := d.cur
	if d.missing("netdev", "interfaces réseau") {
		return
	}
	if d.prev == nil || d.prev.ifaces == nil {
		d.r.line("interfaces réseau : débits calculés à partir du relevé suivant")
		return
	}
	var active []ifRate
	idle := 0
	for _, n := range c.ifOrder {
		if n == "lo" {
			continue
		}
		a, ok := d.prev.ifaces[n]
		if !ok {
			continue
		}
		b := c.ifaces[n]
		x := ifRate{name: n, rx: d.rate(a.rxBytes, b.rxBytes) * 8 / 1e6, tx: d.rate(a.txBytes, b.txBytes) * 8 / 1e6, rxp: d.rate(a.rxPkts, b.rxPkts), txp: d.rate(a.txPkts, b.txPkts), rxe: d.rate(a.rxErrs, b.rxErrs), txe: d.rate(a.txErrs, b.txErrs), rxd: d.rate(a.rxDrop, b.rxDrop), txd: d.rate(a.txDrop, b.txDrop)}
		if x.rxp+x.txp+x.rxe+x.txe+x.rxd+x.txd == 0 {
			idle++
			continue
		}
		active = append(active, x)
	}
	slices.SortStableFunc(active, func(a, b ifRate) int { return cmp.Compare(b.rx+b.tx, a.rx+a.tx) })
	d.r.line("interfaces réseau (%d actives, %d sans trafic) :", len(active), idle)
	var rest ifRate
	others := 0
	for i, x := range active {
		bad := x.rxe+x.txe+x.rxd+x.txd > 0
		if bad {
			if x.rxd+x.txd >= alertNetDrop {
				d.r.alert("net_drop", x.name, x.rxd+x.txd)
			}
			if x.rxe+x.txe > 0 {
				d.r.alert("net_err", x.name, x.rxe+x.txe)
			}
		}
		if i >= topIfaces && !bad {
			others++
			rest.rx, rest.tx, rest.rxp, rest.txp = rest.rx+x.rx, rest.tx+x.tx, rest.rxp+x.rxp, rest.txp+x.txp
			continue
		}
		s := fmt.Sprintf("  %s : reçu %.2f Mbit/s %.0f paquets/s · émis %.2f Mbit/s %.0f paquets/s", x.name, x.rx, x.rxp, x.tx, x.txp)
		if bad {
			s += fmt.Sprintf(" · erreurs reçu %.1f/s émis %.1f/s · pertes reçu %.1f/s émis %.1f/s", x.rxe, x.txe, x.rxd, x.txd)
		}
		d.r.Lines = append(d.r.Lines, s)
	}
	if others > 0 {
		d.r.line("  %d autres interfaces actives, sans erreur ni perte : reçu %.2f Mbit/s %.0f paquets/s · émis %.2f Mbit/s %.0f paquets/s au total", others, rest.rx, rest.rxp, rest.tx, rest.txp)
	}
	if len(active) > 0 {
		d.r.summary("net", active[0].name, active[0].rx, active[0].tx)
	}
}

func (d *differ) tcp() {
	c := d.cur
	if d.missing("snmp", "compteurs TCP/UDP") {
		return
	}
	v := c.snmp
	if d.prev == nil || d.prev.snmp == nil {
		d.r.line("tcp : %.0f connexions établies ; débits calculés à partir du relevé suivant", v["Tcp.CurrEstab"])
		return
	}
	p := d.prev.snmp
	r := func(k string) float64 { return d.rate(p[k], v[k]) }
	dl := func(k string) float64 { return d.delta(p[k], v[k]) }
	out := dl("Tcp.OutSegs")
	pct := 0.0
	if out > 0 {
		pct = dl("Tcp.RetransSegs") / out * 100
	}
	d.r.line("tcp : %.0f connexions établies · ouvertures actives %.1f/s passives %.1f/s · échecs de connexion %.1f/s · connexions réinitialisées %.1f/s · resets émis %.1f/s · segments reçus %.0f/s émis %.0f/s · retransmissions %.1f/s (%.2f %% des segments émis) · segments reçus en erreur %.1f/s",
		v["Tcp.CurrEstab"], r("Tcp.ActiveOpens"), r("Tcp.PassiveOpens"), r("Tcp.AttemptFails"), r("Tcp.EstabResets"), r("Tcp.OutRsts"), r("Tcp.InSegs"), r("Tcp.OutSegs"), r("Tcp.RetransSegs"), pct, r("Tcp.InErrs"))
	if pct > 0 {
		d.r.summary("retrans", pct)
	}
	if pct >= alertRetrans && out >= alertRetransMin {
		d.r.alert("retrans", pct)
	}
	labels := []struct{ key, label string }{
		{"TcpExt.ListenOverflows", "files d'écoute débordées"},
		{"TcpExt.ListenDrops", "SYN rejetés à l'écoute"},
		{"TcpExt.TCPTimeouts", "expirations de retransmission"},
		{"TcpExt.TCPSynRetrans", "SYN retransmis"},
		{"TcpExt.TCPAbortOnTimeout", "connexions abandonnées par expiration"},
		{"TcpExt.TCPAbortOnMemory", "connexions abandonnées faute de mémoire"},
		{"TcpExt.TCPMemoryPressures", "entrées en pression mémoire TCP"},
		{"TcpExt.TCPBacklogDrop", "segments perdus (backlog plein)"},
		{"TcpExt.PruneCalled", "élagages de file de réception"},
		{"Udp.InErrors", "datagrammes UDP reçus en erreur"},
		{"Udp.RcvbufErrors", "UDP tampon de réception plein"},
		{"Udp.SndbufErrors", "UDP tampon d'émission plein"},
		{"Udp.NoPorts", "UDP vers un port fermé"},
	}
	var parts []string
	for _, l := range labels {
		if n := dl(l.key); n > 0 {
			parts = append(parts, fmt.Sprintf("%s +%.0f", l.label, n))
		}
	}
	if len(parts) > 0 {
		d.r.line("compteurs TCP/UDP non nuls sur l'intervalle : %s", strings.Join(parts, " · "))
	}
	if n := dl("TcpExt.ListenOverflows") + dl("TcpExt.ListenDrops"); n > 0 {
		d.r.alert("listen", n)
	}
	if n := dl("Udp.RcvbufErrors") + dl("Udp.SndbufErrors"); n > 0 {
		d.r.alert("udp", n)
	}
}

func (d *differ) sockets() {
	c := d.cur
	if c.has("sockstat") {
		s := c.sock
		d.r.line("sockets : %d utilisées · tcp %d ouvertes, %d orphelines, %d en time-wait, %d allouées, mémoire %d pages · udp %d ouvertes", s["sockets.used"], s["TCP.inuse"], s["TCP.orphan"], s["TCP.tw"], s["TCP.alloc"], s["TCP.mem"], s["UDP.inuse"])
	}
	if len(c.conntrack) == 2 && c.conntrack[1] > 0 {
		pct := float64(c.conntrack[0]) / float64(c.conntrack[1]) * 100
		d.r.line("conntrack : %d entrées sur %d (%.1f %%)", c.conntrack[0], c.conntrack[1], pct)
		if pct >= alertTable {
			d.r.alert("conntrack", pct)
		}
	}
}

func (d *differ) files() {
	c := d.cur
	if len(c.filenr) != 2 || c.filenr[1] <= 0 {
		return
	}
	pct := float64(c.filenr[0]) / float64(c.filenr[1]) * 100
	d.r.line("descripteurs de fichiers : %d alloués sur %d (%.2f %%)", c.filenr[0], c.filenr[1], pct)
	if pct >= alertTable {
		d.r.alert("files", pct)
	}
}

func (d *differ) processes() {
	c := d.cur
	if !c.has("pids") {
		return
	}
	var running, zombie int
	for _, p := range c.procs {
		switch p.state {
		case "R":
			running++
		case "Z":
			zombie++
		}
	}
	d.r.line("processus : %d (en exécution %d, zombies %d)", len(c.procs), running, zombie)
	if d.wants(CPU) && d.prev != nil && d.prev.procs != nil {
		var items []ranked
		for pid, p := range c.procs {
			q, ok := d.prev.procs[pid]
			if !ok {
				continue
			}
			v := d.rate(q.utime+q.stime, p.utime+p.stime) / c.clkTck * 100
			if v >= 0.5 {
				items = append(items, ranked{pid: pid, v: v})
			}
		}
		if items = top(items, topN); len(items) > 0 {
			d.r.line("processus par CPU (100 %% = un vCPU) :")
			for _, it := range items {
				d.r.line("  %.0f %% · %s", it.v, d.who(it.pid))
			}
		}
	}
	if d.wants(Memory) {
		var items []ranked
		for pid, p := range c.procs {
			if p.rssPg <= 0 {
				continue
			}
			maj := 0.0
			if d.prev != nil {
				if q, ok := d.prev.procs[pid]; ok {
					maj = d.rate(q.majflt, p.majflt)
				}
			}
			items = append(items, ranked{pid: pid, v: p.rssPg * c.pageSize, w: maj})
		}
		if items = top(items, topN); len(items) > 0 {
			d.r.line("processus par mémoire résidente :")
			for _, it := range items {
				s := "  " + bytes(it.v)
				if d.prev != nil {
					s += fmt.Sprintf(", défauts majeurs %.1f/s", it.w)
				}
				d.r.Lines = append(d.r.Lines, s+" · "+d.who(it.pid))
			}
		}
	}
	if d.wants(CPU, Disk) {
		d.blocked()
	}
	if d.wants(Disk) {
		d.ioWait()
		d.processIO()
	}
}

var waitHints = []struct{ prefix, hint string }{
	{"rpc_", "NFS/RPC"},
	{"nfs", "NFS"},
	{"cifs", "CIFS/SMB"},
	{"smb", "CIFS/SMB"},
	{"fuse", "FUSE"},
	{"ceph", "Ceph"},
	{"jbd2", "journal ext4"},
	{"ext4", "ext4"},
	{"xfs", "XFS"},
	{"btrfs", "Btrfs"},
	{"blk_", "couche bloc"},
	{"io_schedule", "E/S bloc"},
	{"folio_wait", "attente de page (lecture disque ou réseau)"},
	{"wait_on_page", "attente de page (lecture disque ou réseau)"},
	{"balance_dirty_pages", "écriture bridée (trop de pages sales)"},
	{"rwsem", "verrou noyau"},
	{"mutex", "verrou noyau"},
}

func waitHint(t dtask) string {
	for _, sym := range append([]string{t.wchan}, strings.Fields(t.stack)...) {
		for _, h := range waitHints {
			if strings.HasPrefix(sym, h.prefix) {
				return h.hint
			}
		}
	}
	return ""
}

func (t dtask) where() string {
	w := t.wchan
	if t.stack != "" {
		if w != "" {
			w += " ; "
		}
		w += "pile " + t.stack
	}
	if w == "" {
		w = "point d'attente illisible (root requis)"
	}
	if h := waitHint(t); h != "" {
		w += " [" + h + "]"
	}
	return w
}

func (d *differ) blocked() {
	c := d.cur
	if !c.has("dtasks") {
		d.r.line("threads bloqués en E/S (état D) : aucun")
		return
	}
	pids := map[int]bool{}
	hints := map[string]int{}
	for _, t := range c.dtasks {
		pids[t.pid] = true
		key := t.wchan
		if key == "" {
			key = "?"
		}
		if h := waitHint(t); h != "" {
			key += " [" + h + "]"
		}
		hints[key]++
	}
	s := fmt.Sprintf("threads bloqués en E/S (état D) : %d", c.dtotal)
	if c.dtotal > len(c.dtasks) {
		s += fmt.Sprintf(" (détail des %d premiers)", len(c.dtasks))
	}
	keys := slices.SortedFunc(maps.Keys(hints), func(a, b string) int {
		if x := cmp.Compare(hints[b], hints[a]); x != 0 {
			return x
		}
		return cmp.Compare(a, b)
	})
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, hints[k]))
	}
	d.r.Lines = append(d.r.Lines, s+" · points d'attente noyau : "+strings.Join(parts, ", "))
	d.r.line("processus dont des threads sont bloqués en E/S (thread, nom, point d'attente) :")
	for _, pid := range slices.Sorted(maps.Keys(pids)) {
		var ts []string
		for _, t := range c.dtasks {
			if t.pid == pid {
				ts = append(ts, fmt.Sprintf("%s %s : %s", t.tid, t.comm, t.where()))
			}
		}
		d.r.line("  %s · %s", d.who(pid), strings.Join(ts, " | "))
		d.hot(pid)
	}
}

func (d *differ) hot(pid int) {
	if !slices.Contains(d.r.Hot, pid) && len(d.r.Hot) < maxHot {
		d.r.Hot = append(d.r.Hot, pid)
	}
}

func (d *differ) ioWait() {
	c := d.cur
	switch {
	case !c.has("delayacct") || c.delayacct < 0:
		return
	case c.delayacct == 0:
		d.r.line("temps d'attente d'E/S par processus non mesuré : comptage des délais désactivé sur l'hôte (sysctl kernel.task_delayacct = 0)")
		return
	}
	if d.prev == nil || d.prev.procs == nil {
		return
	}
	var items []ranked
	for pid, p := range c.procs {
		q, ok := d.prev.procs[pid]
		if !ok {
			continue
		}
		if v := d.rate(q.blkio, p.blkio) / c.clkTck * 100; v >= 1 {
			items = append(items, ranked{pid: pid, v: v})
		}
	}
	if items = top(items, topN); len(items) > 0 {
		d.r.line("processus par temps d'attente d'E/S (delayacct, 100 %% = un thread bloqué en continu) :")
		for _, it := range items {
			d.r.line("  %.0f %% · %s", it.v, d.who(it.pid))
			d.hot(it.pid)
		}
	}
}

func (d *differ) processIO() {
	c := d.cur
	if !c.has("pidio") || len(c.io)*2 < len(c.procs) {
		d.r.line("E/S par processus : /proc/<pid>/io lisible seulement pour les processus du compte de connexion (sudo absent sur cette instance) : classement partiel")
	}
	if d.prev == nil || d.prev.io == nil || c.io == nil {
		return
	}
	var disk, app []ranked
	rates := map[int]ioc{}
	for pid, b := range c.io {
		a, ok := d.prev.io[pid]
		if !ok {
			continue
		}
		x := ioc{rchar: d.rate(a.rchar, b.rchar), wchar: d.rate(a.wchar, b.wchar), rb: d.rate(a.rb, b.rb), wb: d.rate(a.wb, b.wb)}
		rates[pid] = x
		if x.rb+x.wb > 0 {
			disk = append(disk, ranked{pid: pid, v: x.rb + x.wb})
		}
		if x.rchar+x.wchar > 0 {
			app = append(app, ranked{pid: pid, v: x.rchar + x.wchar})
		}
	}
	line := func(it ranked) string {
		x := rates[it.pid]
		return fmt.Sprintf("  disque %s/s lus %s/s écrits · applicatif %s/s lus %s/s écrits · %s", bytes(x.rb), bytes(x.wb), bytes(x.rchar), bytes(x.wchar), d.who(it.pid))
	}
	if disk = top(disk, topN); len(disk) > 0 {
		d.r.line("processus par E/S disque (octets réellement lus ou écrits sur un périphérique bloc) :")
		for i, it := range disk {
			d.r.Lines = append(d.r.Lines, line(it))
			if i < hotDisk && it.v >= hotRate {
				d.hot(it.pid)
			}
		}
	}
	if app = top(app, topN); len(app) > 0 {
		d.r.line("processus par lectures et écritures applicatives (appels read/write, cache, NFS et sockets compris) :")
		for i, it := range app {
			d.r.Lines = append(d.r.Lines, line(it))
			if i < hotApp && it.v >= hotRate {
				d.hot(it.pid)
			}
		}
	}
}

var netFS = []string{"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs"}

func isNetFS(t string) bool {
	return slices.Contains(netFS, t) || strings.HasPrefix(t, "fuse")
}

func (d *differ) netMounts() {
	var out []string
	for _, m := range d.cur.mounts {
		if isNetFS(m.fstype) {
			out = append(out, fmt.Sprintf("%s (%s, %s)", m.path, m.fstype, m.dev))
		}
	}
	if len(out) > 0 {
		d.r.line("systèmes de fichiers réseau ou FUSE montés : %s", strings.Join(out, " · "))
	}
}

var nfsMain = []string{"READ", "WRITE", "COMMIT", "GETATTR", "LOOKUP", "ACCESS", "OPEN", "CLOSE", "READDIR", "READDIRPLUS", "SETATTR", "CREATE", "REMOVE", "LOCK"}

func (d *differ) nfs() {
	c := d.cur
	if len(c.nfs) == 0 {
		return
	}
	if d.prev == nil || d.prev.nfs == nil {
		d.r.line("NFS : %d montages (%s) ; opérations calculées à partir du relevé suivant", len(c.nfsOrder), strings.Join(c.nfsOrder, ", "))
		return
	}
	d.r.line("NFS par montage (opérations/s, attente moyenne par opération : aller-retour serveur et exécution totale côté client) :")
	for _, path := range c.nfsOrder {
		m, p := c.nfs[path], d.prev.nfs[path]
		if p == nil {
			d.r.line("  %s (%s) : monté depuis le relevé précédent", path, m.dev)
			continue
		}
		var parts []string
		var totalOps, timeouts, retrans float64
		var slowest string
		slowExec := 0.0
		for _, name := range m.opOrder {
			a, b := p.ops[name], m.ops[name]
			n := d.delta(a.ops, b.ops)
			totalOps += n
			timeouts += d.delta(a.timeouts, b.timeouts)
			retrans += max(d.delta(a.trans, b.trans)-n, 0)
			if n == 0 {
				continue
			}
			rtt, exec := d.delta(a.rtt, b.rtt)/n, d.delta(a.exec, b.exec)/n
			if slices.Contains(nfsMain, name) || exec >= alertAwait {
				parts = append(parts, fmt.Sprintf("%s %.1f/s (aller-retour %.1f ms, exécution %.1f ms)", name, n/d.dt, rtt, exec))
			}
			if n/d.dt >= 1 && exec > slowExec {
				slowest, slowExec = name, exec
			}
		}
		s := fmt.Sprintf("  %s (%s, %s) : %.1f opérations/s", path, m.fstype, m.dev, totalOps/d.dt)
		if len(m.bytes) >= 6 && len(p.bytes) >= 6 {
			s += fmt.Sprintf(" · lu sur le serveur %s/s écrit %s/s", bytes(d.rate(p.bytes[4], m.bytes[4])), bytes(d.rate(p.bytes[5], m.bytes[5])))
		}
		if timeouts > 0 || retrans > 0 {
			s += fmt.Sprintf(" · expirations +%.0f retransmissions +%.0f", timeouts, retrans)
		}
		if len(parts) > 0 {
			s += " · " + strings.Join(parts, " · ")
		}
		d.r.Lines = append(d.r.Lines, s)
		if slowExec >= alertAwait {
			d.r.alert("nfs_slow", path, slowest, slowExec)
		}
		if timeouts > 0 {
			d.r.alert("nfs_timeout", path, timeouts)
		}
	}
}

func (d *differ) who(pid int) string {
	if p, ok := d.cur.ps[pid]; ok {
		return fmt.Sprintf("%d %s : %s", pid, p.user, p.args)
	}
	return fmt.Sprintf("%d (terminé ou nom illisible)", pid)
}

type ranked struct {
	pid int
	v   float64
	w   float64
}

func top(items []ranked, n int) []ranked {
	slices.SortStableFunc(items, func(a, b ranked) int {
		if c := cmp.Compare(b.v, a.v); c != 0 {
			return c
		}
		return cmp.Compare(a.pid, b.pid)
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

func (s *Snapshot) mountOf(path string) (mount, bool) {
	var best mount
	found := false
	for _, m := range s.mounts {
		if (path == m.path || strings.HasPrefix(path, strings.TrimSuffix(m.path, "/")+"/")) && len(m.path) >= len(best.path) {
			best, found = m, true
		}
	}
	return best, found
}

func FilesText(snap *Snapshot, files map[int][]fileUse, pids []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "fichiers ouverts par les processus en tête des E/S ou bloqués (%d chemins au plus par processus, par nombre de descripteurs ; système de fichiers du chemin) :\n", filesPerPID)
	d := &differ{cur: snap}
	for _, pid := range pids {
		list, ok := files[pid]
		switch {
		case !ok:
			fmt.Fprintf(&b, "  %s : descripteurs illisibles\n", d.who(pid))
			continue
		case len(list) == 0:
			fmt.Fprintf(&b, "  %s : aucun fichier ouvert hors /dev, /proc, /sys (ou descripteurs illisibles sans root)\n", d.who(pid))
			continue
		}
		fmt.Fprintf(&b, "  %s :\n", d.who(pid))
		for _, f := range list {
			where := ""
			if m, ok := snap.mountOf(f.path); ok {
				where = fmt.Sprintf(" (%s sur %s)", m.fstype, m.path)
			}
			fmt.Fprintf(&b, "    %d × %s%s\n", f.count, f.path, where)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func bytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f Gio", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f Mio", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f Kio", b/(1<<10))
	}
	return fmt.Sprintf("%.0f o", b)
}

func kib(k int64) string {
	return bytes(float64(k) * 1024)
}

func fmtDur(sec float64) string {
	return (time.Duration(sec) * time.Second).String()
}
