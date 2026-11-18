package drawio

import (
	"bytes"
	"compress/flate"
	"container/heap"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/beevik/etree"
)

type Options struct {
	SpreadX float64
	SpreadY float64
}

type Result struct {
	Edges  int
	Failed []string
}

const (
	sharedTrunkCells = 8
	step             = 6.0
	margin           = 12.0
	labelPad         = 4.0
	maxStates        = 300000
	canvasPad        = 40.0
)

type box struct{ x, y, w, h float64 }

type pt struct{ x, y float64 }

type cellKey struct{ i, j int }

type dir struct{ dx, dy int }

var dirs = []dir{{1, 0}, {-1, 0}, {0, 1}, {0, -1}}

type flowKey struct {
	to   bool
	node string
	text string
}

type keySet map[flowKey]bool

func (k keySet) meets(o keySet) bool {
	for x := range o {
		if k[x] {
			return true
		}
	}
	return false
}

type port struct {
	at  pt
	d   dir
	rel pt
}

type router struct {
	cells      map[string]*etree.Element
	geo        map[string]*etree.Element
	boxes      map[string]box
	labels     map[string]box
	containers map[string]bool
	owner      map[cellKey]bool
	border     map[cellKey]byte
	usedH      map[cellKey]keySet
	usedV      map[cellKey]keySet
	portKeys   map[string]keySet
	gw, gh     int
}

func Route(data []byte, opt Options) ([]byte, *Result, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, nil, fmt.Errorf("drawio: %w", err)
	}
	diagrams := doc.FindElements("//diagram")
	if len(diagrams) == 0 {
		if doc.FindElement("//mxGraphModel") == nil {
			return nil, nil, fmt.Errorf("drawio: no diagram")
		}
	}
	for _, d := range diagrams {
		if d.FindElement("mxGraphModel") != nil {
			continue
		}
		model, err := inflate(strings.TrimSpace(d.Text()))
		if err != nil {
			return nil, nil, fmt.Errorf("drawio: %w", err)
		}
		sub := etree.NewDocument()
		if err := sub.ReadFromString(model); err != nil {
			return nil, nil, fmt.Errorf("drawio: %w", err)
		}
		d.SetText("")
		d.AddChild(sub.Root())
	}
	res := &Result{}
	for _, m := range doc.FindElements("//mxGraphModel") {
		r, err := routeModel(m, opt)
		if err != nil {
			return nil, nil, err
		}
		res.Edges += r.Edges
		res.Failed = append(res.Failed, r.Failed...)
	}
	doc.Indent(2)
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, nil, err
	}
	return out, res, nil
}

func inflate(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "", err
	}
	return url.QueryUnescape(string(b))
}

func styleMap(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		out[k] = v
	}
	return out
}

func setStyle(e *etree.Element, kv ...string) {
	parts := strings.Split(e.SelectAttrValue("style", ""), ";")
	set := map[string]bool{}
	for i := 0; i < len(kv); i += 2 {
		set[kv[i]] = true
	}
	var keep []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		k, _, _ := strings.Cut(p, "=")
		if !set[k] {
			keep = append(keep, p)
		}
	}
	for i := 0; i < len(kv); i += 2 {
		keep = append(keep, kv[i]+"="+kv[i+1])
	}
	e.CreateAttr("style", strings.Join(keep, ";")+";")
}

func num(e *etree.Element, name string) float64 {
	if e == nil {
		return 0
	}
	f, _ := strconv.ParseFloat(e.SelectAttrValue(name, "0"), 64)
	return f
}

func fmtNum(f float64) string {
	return strconv.FormatFloat(math.Round(f*100)/100, 'f', -1, 64)
}

var (
	tagRe = regexp.MustCompile(`<[^>]+>`)
	brRe  = regexp.MustCompile(`(?i)<br\s*/?>`)
)

func text(e *etree.Element) string {
	v := brRe.ReplaceAllString(e.SelectAttrValue("value", ""), "\n")
	v = tagRe.ReplaceAllString(v, "")
	for _, r := range [][2]string{{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&nbsp;", " "}, {"&quot;", "\""}} {
		v = strings.ReplaceAll(v, r[0], r[1])
	}
	return strings.TrimSpace(v)
}

func routeModel(m *etree.Element, opt Options) (*Result, error) {
	if opt.SpreadX <= 0 {
		opt.SpreadX = 1
	}
	if opt.SpreadY <= 0 {
		opt.SpreadY = 1
	}
	r := &router{
		cells: map[string]*etree.Element{}, geo: map[string]*etree.Element{}, boxes: map[string]box{}, labels: map[string]box{},
		containers: map[string]bool{}, owner: map[cellKey]bool{}, border: map[cellKey]byte{},
		usedH: map[cellKey]keySet{}, usedV: map[cellKey]keySet{}, portKeys: map[string]keySet{},
	}
	var vertices, edges []*etree.Element
	for _, c := range m.FindElements(".//mxCell") {
		if c.SelectAttrValue("visible", "1") == "0" {
			continue
		}
		id := c.SelectAttrValue("id", "")
		r.cells[id] = c
		r.geo[id] = c.SelectElement("mxGeometry")
		switch {
		case c.SelectAttrValue("vertex", "") == "1" && r.geo[id] != nil:
			vertices = append(vertices, c)
			if styleMap(c.SelectAttrValue("style", ""))["container"] == "1" {
				r.containers[id] = true
			}
		case c.SelectAttrValue("edge", "") == "1":
			edges = append(edges, c)
		}
	}
	for _, c := range vertices {
		id := c.SelectAttrValue("id", "")
		g := r.geo[id]
		if g.SelectAttr("x") != nil {
			g.CreateAttr("x", fmtNum(num(g, "x")*opt.SpreadX))
		}
		if g.SelectAttr("y") != nil {
			g.CreateAttr("y", fmtNum(num(g, "y")*opt.SpreadY))
		}
		if r.containers[id] {
			g.CreateAttr("width", fmtNum(num(g, "width")*opt.SpreadX))
			g.CreateAttr("height", fmtNum(num(g, "height")*opt.SpreadY))
			if _, ok := styleMap(c.SelectAttrValue("style", ""))["rounded"]; ok {
				setStyle(c, "absoluteArcSize", "1", "arcSize", "24")
			}
		}
	}
	minX, minY := math.Inf(1), math.Inf(1)
	for _, c := range vertices {
		id := c.SelectAttrValue("id", "")
		b := r.abs(id)
		r.boxes[id] = b
		minX, minY = math.Min(minX, b.x), math.Min(minY, b.y)
	}
	if dx, dy := canvasPad-minX, canvasPad-minY; dx > 0 || dy > 0 {
		dx, dy = math.Max(dx, 0), math.Max(dy, 0)
		for _, c := range vertices {
			id := c.SelectAttrValue("id", "")
			if p := c.SelectAttrValue("parent", ""); r.geo[p] == nil || r.cells[p].SelectAttrValue("vertex", "") != "1" {
				g := r.geo[id]
				g.CreateAttr("x", fmtNum(num(g, "x")+dx))
				g.CreateAttr("y", fmtNum(num(g, "y")+dy))
			}
		}
		for _, c := range vertices {
			id := c.SelectAttrValue("id", "")
			r.boxes[id] = r.abs(id)
		}
	}
	maxX, maxY := 0.0, 0.0
	for id, b := range r.boxes {
		maxX, maxY = math.Max(maxX, b.x+b.w), math.Max(maxY, b.y+b.h)
		if !r.containers[id] {
			if lb, ok := imageLabel(r.cells[id], b); ok {
				r.labels[id] = lb
				maxY = math.Max(maxY, lb.y+lb.h)
			}
		}
	}
	r.gw, r.gh = int((maxX+canvasPad)/step)+1, int((maxY+canvasPad)/step)+1
	for id, b := range r.boxes {
		if r.containers[id] {
			r.markBorder(b)
			if t := text(r.cells[id]); t != "" {
				tw, th := measure(t, fontSize(r.cells[id], 12))
				r.block(box{b.x + 10, b.y + 4, tw + 4, th + 4}, 4)
			}
			continue
		}
		r.block(b, margin)
		if lb, ok := r.labels[id]; ok {
			r.block(lb, labelPad)
		}
	}
	sort.SliceStable(edges, func(i, j int) bool { return r.span(edges[i]) < r.span(edges[j]) })
	res := &Result{Edges: len(edges)}
	var placed []box
	labelledCells := map[string]map[cellKey]bool{}
	for _, e := range edges {
		src, dst := e.SelectAttrValue("source", ""), e.SelectAttrValue("target", "")
		if _, ok := r.boxes[src]; !ok {
			continue
		}
		if _, ok := r.boxes[dst]; !ok {
			continue
		}
		t := text(e)
		keys := keySet{{true, dst, t}: true, {false, src, t}: true}
		start, path, end, ok := r.search(src, dst, keys)
		if !ok {
			res.Failed = append(res.Failed, e.SelectAttrValue("id", ""))
			continue
		}
		r.portKeys[portID(src, start.rel)] = mergeKeys(r.portKeys[portID(src, start.rel)], keys)
		r.portKeys[portID(dst, end.rel)] = mergeKeys(r.portKeys[portID(dst, end.rel)], keys)
		for i := 0; i+1 < len(path); i++ {
			a, b := path[i], path[i+1]
			used := r.usedV
			if a.j == b.j {
				used = r.usedH
			}
			for _, k := range []cellKey{a, b} {
				used[k] = mergeKeys(used[k], keys)
			}
		}
		corners := corner(path)
		pts := make([]pt, len(corners))
		for i, k := range corners {
			pts[i] = pt{float64(k.i) * step, float64(k.j) * step}
		}
		g := r.geo[e.SelectAttrValue("id", "")]
		if g == nil {
			g = e.CreateElement("mxGeometry")
			g.CreateAttr("relative", "1")
			g.CreateAttr("as", "geometry")
		}
		for _, a := range g.SelectElements("Array") {
			g.RemoveChild(a)
		}
		arr := g.CreateElement("Array")
		arr.CreateAttr("as", "points")
		for _, p := range pts {
			mp := arr.CreateElement("mxPoint")
			mp.CreateAttr("x", fmtNum(p.x))
			mp.CreateAttr("y", fmtNum(p.y))
		}
		setStyle(e, "edgeStyle", "none", "rounded", "1", "arcSize", "8",
			"exitX", fmtRel(start.rel.x), "exitY", fmtRel(start.rel.y), "exitPerimeter", "0",
			"entryX", fmtRel(end.rel.x), "entryY", fmtRel(end.rel.y), "entryPerimeter", "0")
		if t == "" {
			continue
		}
		shared := 0
		for _, k := range path {
			if labelledCells[t][k] {
				shared++
			}
		}
		if shared >= sharedTrunkCells {
			setStyle(e, "noLabel", "1")
			continue
		}
		if labelledCells[t] == nil {
			labelledCells[t] = map[cellKey]bool{}
		}
		for _, k := range path {
			labelledCells[t][k] = true
		}
		full := append(append([]pt{start.at}, pts...), end.at)
		if pos, rect, ok := r.labelPos(full, t, fontSize(e, 9), placed); ok {
			placed = append(placed, rect)
			g.CreateAttr("x", fmtNum(pos))
			g.CreateAttr("y", "0")
			g.CreateAttr("relative", "1")
		}
	}
	m.CreateAttr("pageWidth", strconv.Itoa(int(float64(r.gw)*step)))
	m.CreateAttr("pageHeight", strconv.Itoa(int(float64(r.gh)*step)))
	return res, nil
}

func mergeKeys(a, b keySet) keySet {
	if a == nil {
		a = keySet{}
	}
	for k := range b {
		a[k] = true
	}
	return a
}

func portID(node string, rel pt) string {
	return node + "|" + fmtRel(rel.x) + "|" + fmtRel(rel.y)
}

func fmtRel(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func fontSize(e *etree.Element, def float64) float64 {
	if f, err := strconv.ParseFloat(styleMap(e.SelectAttrValue("style", ""))["fontSize"], 64); err == nil && f > 0 {
		return f
	}
	return def
}

func (r *router) abs(id string) box {
	g := r.geo[id]
	x, y := num(g, "x"), num(g, "y")
	p := r.cells[id].SelectAttrValue("parent", "")
	for i := 0; i < 50; i++ {
		c, ok := r.cells[p]
		if !ok || c.SelectAttrValue("vertex", "") != "1" || r.geo[p] == nil {
			break
		}
		x += num(r.geo[p], "x")
		y += num(r.geo[p], "y")
		p = c.SelectAttrValue("parent", "")
	}
	return box{x, y, num(g, "width"), num(g, "height")}
}

func (r *router) span(e *etree.Element) float64 {
	a, b := r.boxes[e.SelectAttrValue("source", "")], r.boxes[e.SelectAttrValue("target", "")]
	return math.Abs(a.x-b.x) + math.Abs(a.y-b.y)
}

func (r *router) cellsOf(b box, pad float64) []cellKey {
	x0, y0 := int(math.Floor((b.x-pad)/step)), int(math.Floor((b.y-pad)/step))
	x1, y1 := int(math.Floor((b.x+b.w+pad)/step))+1, int(math.Floor((b.y+b.h+pad)/step))+1
	var out []cellKey
	for i := max(0, x0); i <= min(r.gw-1, x1); i++ {
		for j := max(0, y0); j <= min(r.gh-1, y1); j++ {
			out = append(out, cellKey{i, j})
		}
	}
	return out
}

func (r *router) block(b box, pad float64) {
	for _, k := range r.cellsOf(b, pad) {
		r.owner[k] = true
	}
}

func (r *router) markBorder(b box) {
	for _, yy := range []float64{b.y, b.y + b.h} {
		j := int(math.Round(yy / step))
		for i := int(b.x / step); i <= int((b.x+b.w)/step); i++ {
			for d := -1; d <= 1; d++ {
				r.border[cellKey{i, j + d}] = 'h'
			}
		}
	}
	for _, xx := range []float64{b.x, b.x + b.w} {
		i := int(math.Round(xx / step))
		for j := int(b.y / step); j <= int((b.y+b.h)/step); j++ {
			for d := -1; d <= 1; d++ {
				r.border[cellKey{i + d, j}] = 'v'
			}
		}
	}
}

func snap(v float64) float64 { return math.Round(v/step) * step }

func (r *router) ports(id string) []port {
	b := r.boxes[id]
	var raw []port
	add := func(x, y float64, d dir) { raw = append(raw, port{pt{x, y}, d, pt{}}) }
	if r.containers[id] {
		for _, f := range []float64{0.5, 0.3, 0.7} {
			add(b.x+b.w*f, b.y, dir{0, -1})
			add(b.x+b.w*f, b.y+b.h, dir{0, 1})
			add(b.x, b.y+b.h*f, dir{-1, 0})
			add(b.x+b.w, b.y+b.h*f, dir{1, 0})
		}
	} else {
		for _, f := range []float64{0.5, 0.3, 0.7, 0.15, 0.85} {
			add(b.x+b.w*f, b.y, dir{0, -1})
		}
		for _, f := range []float64{0.5, 0.25, 0.75} {
			add(b.x, b.y+b.h*f, dir{-1, 0})
			add(b.x+b.w, b.y+b.h*f, dir{1, 0})
			if _, below := r.labels[id]; !below {
				add(b.x+b.w*f, b.y+b.h, dir{0, 1})
			}
		}
	}
	var out []port
	for _, p := range raw {
		if p.d.dy == 0 {
			p.at.y = snap(p.at.y)
		} else {
			p.at.x = snap(p.at.x)
		}
		rx, ry := 0.5, 0.5
		if b.w > 0 {
			rx = (p.at.x - b.x) / b.w
		}
		if b.h > 0 {
			ry = (p.at.y - b.y) / b.h
		}
		if rx < 0 || rx > 1 || ry < 0 || ry > 1 {
			continue
		}
		p.rel = pt{rx, ry}
		out = append(out, p)
	}
	return out
}

func (r *router) launch(id string, p port) cellKey {
	far := margin + step
	if r.containers[id] {
		far = step * 2
	}
	x, y := p.at.x, p.at.y
	if p.d == (dir{0, 1}) {
		if lb, ok := r.labels[id]; ok {
			y = lb.y + lb.h
		}
	}
	return cellKey{int(math.Round((x + float64(p.d.dx)*far) / step)), int(math.Round((y + float64(p.d.dy)*far) / step))}
}

type state struct {
	k cellKey
	d dir
}

type item struct {
	f, g float64
	s    state
}

type pq []item

func (q pq) Len() int                 { return len(q) }
func (q pq) Less(i, j int) bool       { return q[i].f < q[j].f }
func (q pq) Swap(i, j int)            { q[i], q[j] = q[j], q[i] }
func (q *pq) Push(x any)              { *q = append(*q, x.(item)) }
func (q *pq) Pop() any                { o := *q; it := o[len(o)-1]; *q = o[:len(o)-1]; return it }
func centered(rel pt) bool            { return math.Abs(rel.x-0.5) < 0.1 || math.Abs(rel.y-0.5) < 0.1 }
func foreign(u keySet, k keySet) bool { return len(u) > 0 && !u.meets(k) }

func (r *router) portPenalty(id string, p port, keys keySet) float64 {
	pen := 0.0
	if !centered(p.rel) {
		pen = 6
	}
	if u, ok := r.portKeys[portID(id, p.rel)]; ok && !u.meets(keys) {
		pen += 60
	}
	return pen
}

func (r *router) search(src, dst string, keys keySet) (port, []cellKey, port, bool) {
	type goal struct {
		pen  float64
		need dir
		p    port
	}
	type origin struct {
		p port
	}
	goals := map[cellKey]goal{}
	var gx, gy float64
	for _, p := range r.ports(dst) {
		k := r.launch(dst, p)
		goals[k] = goal{r.portPenalty(dst, p, keys), dir{-p.d.dx, -p.d.dy}, p}
		gx += float64(k.i)
		gy += float64(k.j)
	}
	if len(goals) == 0 {
		return port{}, nil, port{}, false
	}
	gx /= float64(len(goals))
	gy /= float64(len(goals))
	best := map[state]float64{}
	prev := map[state]state{}
	starts := map[state]origin{}
	endpoints := map[cellKey]bool{}
	for k := range goals {
		endpoints[k] = true
	}
	q := &pq{}
	for _, p := range r.ports(src) {
		k := r.launch(src, p)
		endpoints[k] = true
		s := state{k, p.d}
		pen := r.portPenalty(src, p, keys)
		if old, ok := best[s]; ok && old <= pen {
			continue
		}
		best[s] = pen
		starts[s] = origin{p}
		heap.Push(q, item{pen, pen, s})
	}
	closed := map[state]bool{}
	for q.Len() > 0 && len(closed) < maxStates {
		it := heap.Pop(q).(item)
		s := it.s
		if closed[s] {
			continue
		}
		closed[s] = true
		if gl, ok := goals[s.k]; ok {
			_ = gl
			var path []cellKey
			cur := s
			for {
				path = append(path, cur.k)
				if o, ok := starts[cur]; ok {
					for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
						path[i], path[j] = path[j], path[i]
					}
					return o.p, path, gl.p, true
				}
				cur = prev[cur]
			}
		}
		for _, nd := range dirs {
			if nd.dx == -s.d.dx && nd.dy == -s.d.dy {
				continue
			}
			nk := cellKey{s.k.i + nd.dx, s.k.j + nd.dy}
			if nk.i < 0 || nk.j < 0 || nk.i >= r.gw || nk.j >= r.gh {
				continue
			}
			if r.owner[nk] && !endpoints[nk] {
				continue
			}
			c := r.stepCost(nk, s.d, nd, keys)
			if gl, ok := goals[nk]; ok {
				c += gl.pen
				if nd != gl.need {
					c += 12
				}
			}
			ns := state{nk, nd}
			ng := it.g + c
			if closed[ns] {
				continue
			}
			if old, ok := best[ns]; ok && old <= ng {
				continue
			}
			best[ns] = ng
			prev[ns] = s
			h := math.Abs(float64(nk.i)-gx) + math.Abs(float64(nk.j)-gy)
			heap.Push(q, item{ng + h*1.2, ng, ns})
		}
	}
	return port{}, nil, port{}, false
}

func (r *router) stepCost(nk cellKey, d, nd dir, keys keySet) float64 {
	c := 1.0
	if nd != d {
		c += 14
	}
	horizontal := nd.dy == 0
	if b, ok := r.border[nk]; ok {
		if (b == 'h') == horizontal {
			c += 30
		} else {
			c += 4
		}
	}
	same, cross := r.usedH, r.usedV
	near := func(o int) cellKey { return cellKey{nk.i, nk.j + o} }
	if !horizontal {
		same, cross = r.usedV, r.usedH
		near = func(o int) cellKey { return cellKey{nk.i + o, nk.j} }
	}
	if u := same[nk]; len(u) > 0 {
		if u.meets(keys) {
			c -= 0.6
		} else {
			c += 60
		}
	}
	for _, w := range []struct {
		o int
		c float64
	}{{1, 18}, {2, 8}} {
		if foreign(same[near(w.o)], keys) || foreign(same[near(-w.o)], keys) {
			c += w.c
		}
	}
	if foreign(cross[nk], keys) {
		c += 6
	}
	return c
}

func corner(path []cellKey) []cellKey {
	if len(path) < 2 {
		return path
	}
	out := []cellKey{path[0]}
	for i := 1; i+1 < len(path); i++ {
		a, b, c := path[i-1], path[i], path[i+1]
		if (b.i-a.i != c.i-b.i) || (b.j-a.j != c.j-b.j) {
			out = append(out, b)
		}
	}
	return append(out, path[len(path)-1])
}

func overlap(a, b box) bool {
	return a.x < b.x+b.w && b.x < a.x+a.w && a.y < b.y+b.h && b.y < a.y+a.h
}

func (r *router) labelPos(full []pt, t string, fs float64, placed []box) (float64, box, bool) {
	total := 0.0
	for i := 0; i+1 < len(full); i++ {
		total += math.Abs(full[i+1].x-full[i].x) + math.Abs(full[i+1].y-full[i].y)
	}
	if total == 0 {
		return 0, box{}, false
	}
	lw, lh := measure(t, fs)
	lw, lh = lw+6, lh+2
	found := false
	var bestPos, bestScore float64
	var bestRect box
	acc := 0.0
	for i := 0; i+1 < len(full); i++ {
		a, b := full[i], full[i+1]
		ln := math.Abs(b.x-a.x) + math.Abs(b.y-a.y)
		need := lh + 10
		if a.y == b.y {
			need = lw + 10
		}
		if ln >= need {
			for _, f := range []float64{0.5, 0.3, 0.7} {
				mx, my := a.x+(b.x-a.x)*f, a.y+(b.y-a.y)*f
				rect := box{mx - lw/2, my - lh/2, lw, lh}
				hit := 0.0
				for _, k := range r.cellsOf(rect, 0) {
					if r.owner[k] {
						hit++
					}
					if _, ok := r.border[k]; ok {
						hit++
					}
				}
				for _, o := range placed {
					if overlap(rect, o) {
						hit += 50
					}
				}
				score := hit*10 - ln*0.05
				if !found || score < bestScore {
					found, bestScore, bestPos, bestRect = true, score, acc+ln*f, rect
				}
			}
		}
		acc += ln
	}
	if !found {
		return 0, box{}, false
	}
	return bestPos/total*2 - 1, bestRect, true
}
