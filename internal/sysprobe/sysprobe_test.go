package sysprobe

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/driver/ssh"
)

type fx struct {
	uptime                                           float64
	user, system, idle, iowait, steal                int
	sdaReads, sdaRms, sdaWrites, sdaWms, sdaIo, sdaW int
	sdaInflight                                      int
	avail                                            int
	pswpout, oom, allocstall, majflt                 int
	ioSome, ioFull                                   int
	rx, rxDrop                                       int
	outSegs, retrans, overflows                      int
	utime42, blkio42, nfsReadOps, nfsExec            int
	read42                                           int
	withPID7, withPID99, withPSI                     bool
}

func (f fx) out() string {
	var b strings.Builder
	sec := func(name, body string) { fmt.Fprintf(&b, "@@ %s\n%s\n", name, body) }
	sec("uptime", fmt.Sprintf("%.2f 5000.00", f.uptime))
	sec("conf", "4096\n100")
	sec("stat", fmt.Sprintf("cpu  %d 0 %d %d %d 0 0 %d 0 0\ncpu0 1 0 1 1 0 0 0 0 0 0\ncpu1 1 0 1 1 0 0 0 0 0 0\nctxt 1000\nintr 500 0 0\nprocs_running 3\nprocs_blocked 5", f.user, f.system, f.idle, f.iowait, f.steal))
	sec("loadavg", "6.50 4.00 2.00 3/200 999")
	if f.withPSI {
		sec("pressure", fmt.Sprintf("/proc/pressure/cpu:some avg10=1.00 avg60=0.50 avg300=0.10 total=100\n/proc/pressure/cpu:full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n/proc/pressure/io:some avg10=40.00 avg60=30.00 avg300=10.00 total=%d\n/proc/pressure/io:full avg10=8.00 avg60=5.00 avg300=1.00 total=%d\n/proc/pressure/memory:some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n/proc/pressure/memory:full avg10=0.00 avg60=0.00 avg300=0.00 total=0", f.ioSome, f.ioFull))
	} else {
		sec("pressure", "")
	}
	sec("meminfo", fmt.Sprintf("MemTotal:        8000000 kB\nMemFree:          100000 kB\nMemAvailable:     %d kB\nBuffers:           10000 kB\nCached:           300000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1000000 kB\nDirty:              1000 kB\nHugePages_Total:       0", f.avail))
	sec("vmstat", fmt.Sprintf("pswpin 0\npswpout %d\npgmajfault %d\npgfault 100\nallocstall_normal %d\nallocstall_movable 0\npgscan_direct %d\npgscan_direct_throttle 99\noom_kill %d", f.pswpout, f.majflt, f.allocstall, f.allocstall*10, f.oom))
	sec("diskstats", fmt.Sprintf("   8       0 sda %d 0 %d %d %d 0 %d %d %d %d %d 0 0 0 0\n   8       1 sda1 5 0 5 5 5 0 5 5 0 5 5\n 253       0 dm-0 10 0 10 10 10 0 10 10 0 10 10\n   7       0 loop0 99 0 99 99 0 0 0 0 0 9 9",
		f.sdaReads, f.sdaReads*8, f.sdaRms, f.sdaWrites, f.sdaWrites*8, f.sdaWms, f.sdaInflight, f.sdaIo, f.sdaW))
	sec("blocks", "dm-0\nloop0\nsda")
	sec("dm", "/sys/block/dm-0/dm/name:vg-data")
	sec("df", "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/sda1         10000000   9600000    400000      96% /\ntmpfs               100000         0    100000       0% /run\n/dev/mapper/vg-data 5000000 1000000 4000000 20% /srv/my data")
	sec("dfi", "Filesystem      Inodes  IUsed   IFree IUse% Mounted on\n/dev/sda1       100000  10000   90000   10% /\n/dev/mapper/vg-data 100 99 1 99% /srv/my data")
	sec("netdev", fmt.Sprintf("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n  eth0: %d 1000 0 %d 0 0 0 0 200 100 0 0 0 0 0 0\n  eth1: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", f.rx, f.rxDrop))
	sec("snmp", fmt.Sprintf("Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\nTcp: 1 200 120000 -1 10 20 0 0 42 1000 %d %d 0 0 0\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\nUdp: 1 0 0 1 0 0 0 0 0", f.outSegs, f.retrans))
	sec("netstat", fmt.Sprintf("TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 %d %d", f.overflows, f.overflows))
	sec("sockstat", "sockets: used 300\nTCP: inuse 50 orphan 1 tw 20 alloc 60 mem 5\nUDP: inuse 3 mem 1")
	sec("conntrack", "95\n100")
	sec("filenr", "1000\t0\t100000")
	pids := fmt.Sprintf("1 S 0 10 10 100 0\n42 R 3 %d 0 25000 %d", f.utime42, f.blkio42)
	io := fmt.Sprintf("/proc/1/io:rchar: 0\n/proc/1/io:read_bytes: 0\n/proc/1/io:write_bytes: 0\n/proc/42/io:rchar: %d\n/proc/42/io:wchar: 0\n/proc/42/io:read_bytes: %d\n/proc/42/io:write_bytes: 0", f.read42*3, f.read42)
	ps := "    1 root                             /sbin/init\n   42 alice                            java -jar app.jar --name my app"
	if f.withPID7 {
		pids += "\n7 D 0 5 5 10"
		io += "\n/proc/7/io:read_bytes: 0\n/proc/7/io:write_bytes: 0"
		ps += "\n    7 bob   rsync -a /src /dst"
	}
	if f.withPID99 {
		pids += "\n99 S 0 1 1 10"
	}
	sec("pids", pids)
	sec("dtasks", "total 3\n/proc/42/task/43|rpc_wait_bit_killable|rpc_wait_bit_killable __rpc_execute nfs4_call_sync |43 (java worker) D 1 42\n/proc/42/task/44|0||44 (java gc) D 1 42")
	sec("delayacct", "1")
	sec("mounts", "/dev/sda1 / ext4 rw 0 0\nsrv:/export /mnt/nfs\\040data nfs4 rw 0 0\n/dev/mapper/vg-data /srv/my\\040data xfs rw 0 0\nproc /proc proc rw 0 0")
	sec("nfs", fmt.Sprintf("device srv:/export mounted on /mnt/nfs\\040data with fstype nfs4 statvers=1.1\n\topts:\trw,vers=4.2\n\tbytes:\t0 0 0 0 %d 0 0 0\n\tper-op statistics\n\t        NULL: 1 1 0 44 24 0 0 0 0\n\t        READ: %d %d %d 0 0 0 %d %d 0\n\t     GETATTR: 10 10 0 0 0 0 10 12 0", f.nfsReadOps*1000, f.nfsReadOps, f.nfsReadOps, f.nfsReadOps/1000, f.nfsExec/2, f.nfsExec))
	sec("pidio", io)
	sec("ps", ps)
	sec("ss", "Total: 300\nTCP:   80 (estab 42, closed 10, orphaned 1, timewait 20)")
	sec("sstan", "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\nESTAB  0      0      10.0.0.1:22      10.0.0.9:51000")
	return b.String()
}

var base = fx{uptime: 1000, user: 1000, system: 500, idle: 8000, sdaReads: 100, sdaRms: 100, sdaWrites: 200, sdaWms: 400, sdaIo: 1000, sdaW: 2000, avail: 200000, ioSome: 1000000, ioFull: 100000, rx: 1000, outSegs: 1000, retrans: 10, utime42: 100, withPID7: true, withPSI: true}

func next() fx {
	f := base
	f.uptime += 10
	f.user += 300
	f.system += 100
	f.idle += 50
	f.iowait += 400
	f.steal += 150
	f.sdaReads += 500
	f.sdaRms += 30000
	f.sdaWrites += 100
	f.sdaWms += 1000
	f.sdaIo += 9500
	f.sdaW += 40000
	f.sdaInflight = 7
	f.pswpout += 500
	f.oom++
	f.allocstall += 20
	f.majflt += 2000
	f.ioSome += 5000000
	f.ioFull += 1000000
	f.rx += 125000000
	f.rxDrop += 200
	f.outSegs += 10000
	f.retrans += 500
	f.overflows += 3
	f.utime42 += 1500
	f.blkio42 += 500
	f.nfsReadOps += 2000
	f.nfsExec += 2000 * 80
	f.read42 += 100 << 20
	f.withPID7, f.withPID99 = false, true
	return f
}

func keys(r Report) []string {
	var out []string
	for _, a := range r.Alerts {
		out = append(out, a.Key)
	}
	return out
}

func TestDiffSystem(t *testing.T) {
	a, b := Parse(base.out()), Parse(next().out())
	r := Diff(a, b, System)
	text := r.Text()
	for _, want := range []string{
		"cpu (2 vCPU) : occupé 40.0 %",
		"iowait 40.0 % · steal 15.0 %",
		"(3.25 par vCPU)",
		"io some 50.0 % (avg10 40.0, avg60 30.0), full 10.0 %",
		"disponible 195.3 Mio sur 7.6 Gio (2.5 %)",
		"sorties 50.0 pages/s",
		"défauts majeurs 200.0/s",
		"blocages d'allocation (récupération directe) 2.0/s",
		"pages analysées par kswapd 0/s · par récupération directe 20/s",
		"OOM killer +1 (1 depuis le démarrage)",
		"  sda : 50.0 lectures/s 10.0 écritures/s",
		"attente moyenne lecture 60.0 ms écriture 10.0 ms · occupation 95 % · file moyenne 4.00 · en cours 7",
		"sans E/S sur l'intervalle : dm-0",
		"/ (/dev/sda1) : 9.2 Gio utilisés sur 9.5 Gio (96 %), inodes 10 %",
		"/srv/my data (/dev/mapper/vg-data)",
		"eth0 : reçu 100.00 Mbit/s",
		"pertes reçu 20.0/s",
		"1 sans trafic",
		"42 connexions établies",
		"retransmissions 50.0/s (5.00 % des segments émis)",
		"files d'écoute débordées +3",
		"conntrack : 95 entrées sur 100 (95.0 %)",
		"threads bloqués en E/S (état D) : 3 (détail des 2 premiers) · points d'attente noyau : ? ×1, rpc_wait_bit_killable [NFS/RPC] ×1",
		"42 alice : java -jar app.jar --name my app · 43 java worker : rpc_wait_bit_killable ; pile rpc_wait_bit_killable __rpc_execute nfs4_call_sync [NFS/RPC] | 44 java gc : point d'attente illisible (root requis)",
		"50 % · 42 alice",
		"systèmes de fichiers réseau ou FUSE montés : /mnt/nfs data (nfs4, srv:/export)",
		"/mnt/nfs data (nfs4, srv:/export) : 200.0 opérations/s · lu sur le serveur 195.3 Kio/s écrit 0 o/s · expirations +2 retransmissions +0 · READ 200.0/s (aller-retour 40.0 ms, exécution 80.0 ms)",
		"150 % · 42 alice : java -jar app.jar --name my app",
		"disque 10.0 Mio/s lus 0 o/s écrits · applicatif 30.0 Mio/s lus 0 o/s écrits · 42 alice",
		"ss -s :",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("absent : %q\n%s", want, text)
		}
	}
	for _, bad := range []string{"loop0", "  sda1 :", "tmpfs", "  lo :", "ESTAB"} {
		if strings.Contains(text, bad) {
			t.Errorf("présent à tort : %q", bad)
		}
	}
	got := strings.Join(keys(r), ",")
	for _, k := range []string{"iowait", "steal", "load", "blocked", "psi_some", "psi_full", "mem", "swap", "oom", "reclaim", "majflt", "disk_util", "disk_await", "fs", "inodes", "net_drop", "retrans", "listen", "conntrack", "nfs_slow", "nfs_timeout"} {
		if !strings.Contains(","+got+",", ","+k+",") {
			t.Errorf("alerte %s absente : %s", k, got)
		}
	}
	if strings.Contains(","+got+",", ",busy,") || strings.Contains(","+got+",", ",files,") || strings.Contains(","+got+",", ",slow,") {
		t.Errorf("alerte en trop : %s", got)
	}
	sum := r.Summary("fr")
	for _, want := range []string{"cpu 40 % (iowait 40 %, steal 15 %)", "mémoire disponible 2 %", "sda occupé 95 % 60 ms", "eth0 reçu 100.0", "retransmissions 5.0 %"} {
		if !strings.Contains(sum, want) {
			t.Errorf("résumé sans %q : %s", want, sum)
		}
	}
	for _, l := range []string{"en", "fr"} {
		if out := r.AlertLine(l) + r.Summary(l); strings.Contains(out, "%!") {
			t.Errorf("format %s : %s", l, out)
		}
	}
	if en := r.AlertLine("en"); !strings.Contains(en, "sda busy 95%") {
		t.Errorf("alertes en anglais : %s", en)
	}
}

func TestDiffPerProbe(t *testing.T) {
	a, b := Parse(base.out()), Parse(next().out())
	cases := map[string]struct{ want, not []string }{
		CPU:         {[]string{"cpu (2 vCPU)", "processus par CPU", "pression (sur l'intervalle) : cpu some", "thread, nom, point d'attente"}, []string{"disques", "mémoire :", "interfaces réseau", "processus par mémoire", "io some", "NFS par montage"}},
		Memory:      {[]string{"mémoire :", "processus par mémoire résidente", "memory some"}, []string{"disques", "processus par CPU", "interfaces réseau"}},
		Disk:        {[]string{"disques :", "systèmes de fichiers locaux", "processus par E/S disque", "io some"}, []string{"mémoire :", "interfaces réseau", "processus par CPU"}},
		Network:     {[]string{"interfaces réseau", "tcp :", "sockets :", "conntrack", "ss -s"}, []string{"cpu (", "disques", "processus", "ESTAB"}},
		Connections: {[]string{"interfaces réseau", "connexions TCP (ss -tan)", "ESTAB  0      0      10.0.0.1:22"}, []string{"cpu ("}},
	}
	for probe, c := range cases {
		text := Diff(a, b, probe).Text()
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s : absent %q\n%s", probe, w, text)
			}
		}
		for _, n := range c.not {
			if strings.Contains(text, n) {
				t.Errorf("%s : présent à tort %q", probe, n)
			}
		}
	}
}

func TestFirstSampleAndReboot(t *testing.T) {
	b := Parse(next().out())
	first := Diff(nil, b, System)
	text := first.Text()
	for _, want := range []string{"répartition calculée à partir du relevé suivant", "débits calculés à partir du relevé suivant", "sda : 7 E/S en cours", "io some 40.0 % (avg10", "OOM killer : 1 processus tués depuis le démarrage", "42 connexions établies"} {
		if !strings.Contains(text, want) {
			t.Errorf("premier relevé sans %q\n%s", want, text)
		}
	}
	a := Parse(base.out())
	rb := Diff(b, a, System)
	if keys(rb)[0] != "reboot" || !strings.Contains(rb.Text(), "hôte redémarré") {
		t.Errorf("redémarrage non signalé : %v", keys(rb))
	}
	if regexp.MustCompile(`[^\w]-[0-9]`).MatchString(rb.Text()) {
		t.Errorf("valeur négative :\n%s", rb.Text())
	}
}

func TestMissingSections(t *testing.T) {
	f := next()
	f.withPSI = false
	out := strings.Replace(f.out(), "@@ conntrack\n95\n100\n", "@@ conntrack\n\n", 1)
	out = strings.ReplaceAll(out, "/proc/42/io:", "/proc/x/io:")
	b := Parse(out)
	r := Diff(Parse(base.out()), b, System)
	text := r.Text()
	if !strings.Contains(text, "pression (PSI) : indisponible") {
		t.Errorf("PSI absente non signalée\n%s", text)
	}
	if strings.Contains(text, "conntrack") {
		t.Errorf("conntrack absent affiché")
	}
	if !strings.Contains(text, "classement partiel") {
		t.Errorf("E/S par processus partielles non signalées")
	}
	b.Took = 6 * time.Second
	if k := keys(Diff(nil, b, Network)); !strings.Contains(strings.Join(k, ","), "slow") {
		t.Errorf("réponse lente non signalée : %v", k)
	}
	if Parse("").Check() == nil {
		t.Error("sortie vide acceptée")
	}
}

func TestScriptAndCommand(t *testing.T) {
	if _, ok := Script("gpu"); ok || Valid("gpu") {
		t.Fatal("sonde inconnue acceptée")
	}
	s, _ := Script(Network)
	if strings.Contains(s, "/proc/[0-9]*/stat") || !strings.Contains(s, "@@ netdev") || !strings.HasSuffix(s, "exit 0") {
		t.Errorf("script network : %s", s)
	}
	s, _ = Script(Connections)
	if !strings.Contains(s, "ss -tan") {
		t.Error("connections sans ss -tan")
	}
	s, _ = Script(System)
	if strings.Contains(s, "ss -tan") || !strings.Contains(s, "file-nr") {
		t.Errorf("script system : %s", s)
	}
	cmd, _ := Command(Disk, ssh.Builder{Sudo: true})
	if !strings.HasPrefix(cmd, "sudo -n sh -c '") || strings.Count(cmd, "sudo") != 1 {
		t.Errorf("commande : %s", cmd)
	}
}

func TestLocalHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc requis")
	}
	run := func() *Snapshot {
		s, _ := Script(System)
		out, err := exec.Command("sh", "-c", s).Output()
		if err != nil {
			t.Fatal(err)
		}
		snap := Parse(string(out))
		if err := snap.Check(); err != nil {
			t.Fatal(err)
		}
		return snap
	}
	a := run()
	time.Sleep(200 * time.Millisecond)
	text := Diff(a, run(), System).Text()
	for _, want := range []string{"cpu (", "charge :", "mémoire :", "disques", "interfaces réseau", "tcp :", "processus :"} {
		if !strings.Contains(text, want) {
			t.Errorf("relevé local sans %q\n%s", want, text)
		}
	}
}

func TestHotAndFiles(t *testing.T) {
	a, b := Parse(base.out()), Parse(next().out())
	r := Diff(a, b, Disk)
	if fmt.Sprint(r.Hot) != "[42]" {
		t.Fatalf("processus en tête : %v", r.Hot)
	}
	if Diff(a, b, Network).Hot != nil {
		t.Error("processus en tête pour network")
	}
	sc := FilesScript([]int{42, 7})
	if !strings.Contains(sc, "find /proc/42/fd -maxdepth 1 -type l -printf '%l\\n'") || !strings.Contains(sc, "@@ files 7") {
		t.Errorf("script : %s", sc)
	}
	files := ParseFiles("@@ files 42\n      3 /mnt/nfs data/big.parquet\n      1 /var/log/app.log\n@@ files 7\n")
	text := FilesText(b, files, []int{42, 7, 1})
	for _, want := range []string{
		"42 alice : java -jar app.jar --name my app :\n    3 × /mnt/nfs data/big.parquet (nfs4 sur /mnt/nfs data)\n    1 × /var/log/app.log (ext4 sur /)",
		"7 (terminé ou nom illisible) : aucun fichier ouvert",
		"1 root : /sbin/init : descripteurs illisibles",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("absent %q\n%s", want, text)
		}
	}
}

func TestDelayAcctOff(t *testing.T) {
	out := strings.Replace(next().out(), "@@ delayacct\n1\n", "@@ delayacct\n0\n", 1)
	text := Diff(Parse(base.out()), Parse(out), Disk).Text()
	if !strings.Contains(text, "kernel.task_delayacct = 0") || strings.Contains(text, "delayacct, 100 %") {
		t.Errorf("delayacct désactivé :\n%s", text)
	}
}
