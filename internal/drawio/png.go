package drawio

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	stddraw "image/draw"
	_ "image/jpeg"
	"image/png"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/beevik/etree"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"
)

const (
	maxPixels  = 40_000_000
	pageBorder = 20.0
)

var (
	fontOnce sync.Once
	fontData *opentype.Font
	fontErr  error
	faces    sync.Map
)

func face(size float64) (font.Face, error) {
	fontOnce.Do(func() { fontData, fontErr = opentype.Parse(goregular.TTF) })
	if fontErr != nil {
		return nil, fontErr
	}
	key := math.Round(size * 4)
	if f, ok := faces.Load(key); ok {
		return f.(font.Face), nil
	}
	f, err := opentype.NewFace(fontData, &opentype.FaceOptions{Size: key / 4, DPI: 72, Hinting: font.HintingNone})
	if err != nil {
		return nil, err
	}
	faces.Store(key, f)
	return f, nil
}

type canvas struct {
	img   *image.RGBA
	scale float64
	ox    float64
	oy    float64
}

func (c *canvas) px(p pt) (float32, float32) {
	return float32((p.x - c.ox) * c.scale), float32((p.y - c.oy) * c.scale)
}

func (c *canvas) fill(col color.Color, build func(r *vector.Rasterizer)) {
	b := c.img.Bounds()
	r := vector.NewRasterizer(b.Dx(), b.Dy())
	build(r)
	r.Draw(c.img, b, image.NewUniform(col), image.Point{})
}

func (c *canvas) polygon(r *vector.Rasterizer, pts []pt) {
	if len(pts) < 3 {
		return
	}
	x, y := c.px(pts[0])
	r.MoveTo(x, y)
	for _, p := range pts[1:] {
		x, y := c.px(p)
		r.LineTo(x, y)
	}
	r.ClosePath()
}

func roundRect(b box, radius float64) []pt {
	radius = math.Min(radius, math.Min(b.w, b.h)/2)
	if radius <= 0 {
		return []pt{{b.x, b.y}, {b.x + b.w, b.y}, {b.x + b.w, b.y + b.h}, {b.x, b.y + b.h}, {b.x, b.y}}
	}
	var out []pt
	arc := func(cx, cy, a0 float64) {
		for i := 0; i <= 8; i++ {
			a := a0 + float64(i)*math.Pi/16
			out = append(out, pt{cx + radius*math.Cos(a), cy + radius*math.Sin(a)})
		}
	}
	arc(b.x+b.w-radius, b.y+radius, -math.Pi/2)
	arc(b.x+b.w-radius, b.y+b.h-radius, 0)
	arc(b.x+radius, b.y+b.h-radius, math.Pi/2)
	arc(b.x+radius, b.y+radius, math.Pi)
	return append(out, out[0])
}

func (c *canvas) stroke(col color.Color, width float64, path []pt, dash []float64) {
	if len(path) < 2 || width <= 0 {
		return
	}
	segs := [][2]pt{}
	for i := 0; i+1 < len(path); i++ {
		segs = append(segs, [2]pt{path[i], path[i+1]})
	}
	if len(dash) > 0 {
		segs = dashed(segs, dash)
	}
	hw := width / 2
	bounds := c.img.Bounds()
	var area image.Rectangle
	var quads [][]pt
	for _, s := range segs {
		a, b := s[0], s[1]
		dx, dy := b.x-a.x, b.y-a.y
		l := math.Hypot(dx, dy)
		if l == 0 {
			continue
		}
		nx, ny := -dy/l*hw, dx/l*hw
		ex, ey := dx/l*hw, dy/l*hw
		q := []pt{{a.x + nx - ex, a.y + ny - ey}, {b.x + nx + ex, b.y + ny + ey}, {b.x - nx + ex, b.y - ny + ey}, {a.x - nx - ex, a.y - ny - ey}}
		quads = append(quads, q)
		area = area.Union(c.pixelBox(q))
	}
	area = area.Intersect(bounds)
	if area.Empty() {
		return
	}
	mask := image.NewAlpha(area)
	for _, q := range quads {
		box := c.pixelBox(q).Intersect(area)
		if box.Empty() {
			continue
		}
		r := vector.NewRasterizer(box.Dx(), box.Dy())
		x, y := c.px(q[0])
		r.MoveTo(x-float32(box.Min.X), y-float32(box.Min.Y))
		for _, p := range q[1:] {
			x, y := c.px(p)
			r.LineTo(x-float32(box.Min.X), y-float32(box.Min.Y))
		}
		r.ClosePath()
		tmp := image.NewAlpha(image.Rect(0, 0, box.Dx(), box.Dy()))
		r.Draw(tmp, tmp.Bounds(), image.Opaque, image.Point{})
		for yy := 0; yy < box.Dy(); yy++ {
			for xx := 0; xx < box.Dx(); xx++ {
				v := tmp.AlphaAt(xx, yy).A
				if v == 0 {
					continue
				}
				pt := image.Point{box.Min.X + xx, box.Min.Y + yy}
				if v > mask.AlphaAt(pt.X, pt.Y).A {
					mask.SetAlpha(pt.X, pt.Y, color.Alpha{A: v})
				}
			}
		}
	}
	stddraw.DrawMask(c.img, area, image.NewUniform(col), image.Point{}, mask, area.Min, stddraw.Over)
}

func (c *canvas) pixelBox(q []pt) image.Rectangle {
	minX, minY := math.Inf(1), math.Inf(1)
	maxX, maxY := math.Inf(-1), math.Inf(-1)
	for _, p := range q {
		x, y := c.px(p)
		minX, minY = math.Min(minX, float64(x)), math.Min(minY, float64(y))
		maxX, maxY = math.Max(maxX, float64(x)), math.Max(maxY, float64(y))
	}
	return image.Rect(int(math.Floor(minX))-1, int(math.Floor(minY))-1, int(math.Ceil(maxX))+2, int(math.Ceil(maxY))+2)
}

func dashed(segs [][2]pt, pattern []float64) [][2]pt {
	var out [][2]pt
	idx, left, on := 0, pattern[0], true
	for _, s := range segs {
		a, b := s[0], s[1]
		l := math.Hypot(b.x-a.x, b.y-a.y)
		pos := 0.0
		for pos < l {
			n := math.Min(left, l-pos)
			if on {
				f0, f1 := pos/l, (pos+n)/l
				out = append(out, [2]pt{{a.x + (b.x-a.x)*f0, a.y + (b.y-a.y)*f0}, {a.x + (b.x-a.x)*f1, a.y + (b.y-a.y)*f1}})
			}
			pos += n
			left -= n
			if left <= 1e-9 {
				idx = (idx + 1) % len(pattern)
				left, on = pattern[idx], !on
			}
		}
	}
	return out
}

func parseColor(s string) (color.RGBA, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "none", "default":
		return color.RGBA{}, false
	case "white":
		return color.RGBA{255, 255, 255, 255}, true
	case "black":
		return color.RGBA{0, 0, 0, 255}, true
	}
	s = strings.TrimPrefix(s, "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || len(s) != 6 {
		return color.RGBA{}, false
	}
	return color.RGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 255}, true
}

func floatStyle(st map[string]string, k string, def float64) float64 {
	if f, err := strconv.ParseFloat(st[k], 64); err == nil {
		return f
	}
	return def
}

func (c *canvas) text(s string, size float64, col color.Color, x, y float64, align string, bg color.Color) error {
	f, err := face(size * c.scale)
	if err != nil {
		return err
	}
	lines := strings.Split(s, "\n")
	m := f.Metrics()
	lh := float64(m.Height.Round()) / c.scale
	ascent := float64(m.Ascent.Round()) / c.scale
	for i, l := range lines {
		w := float64(font.MeasureString(f, l).Round()) / c.scale
		lx := x
		switch align {
		case "center":
			lx = x - w/2
		case "right":
			lx = x - w
		}
		ly := y + float64(i)*lh
		if bg != nil {
			b := box{lx - 2, ly - 1, w + 4, lh + 2}
			c.fill(bg, func(r *vector.Rasterizer) { c.polygon(r, roundRect(b, 0)) })
		}
		px, py := c.px(pt{lx, ly + ascent})
		d := font.Drawer{Dst: c.img, Src: image.NewUniform(col), Face: f, Dot: fixed.Point26_6{X: fixed.I(int(math.Round(float64(px)))), Y: fixed.I(int(math.Round(float64(py))))}}
		d.DrawString(l)
	}
	return nil
}

func measure(s string, size float64) (float64, float64) {
	f, err := face(size)
	if err != nil {
		return float64(len([]rune(s))) * size * 0.58, size * 1.35
	}
	w := 0.0
	lines := strings.Split(s, "\n")
	for _, l := range lines {
		w = math.Max(w, float64(font.MeasureString(f, l).Round()))
	}
	return w, float64(f.Metrics().Height.Round()) * float64(len(lines))
}

func decodeImage(src string) (image.Image, error) {
	data, ok := strings.CutPrefix(src, "data:")
	if !ok {
		return nil, fmt.Errorf("image not embedded")
	}
	meta, payload, ok := strings.Cut(data, ",")
	if !ok {
		return nil, fmt.Errorf("image data URI")
	}
	var raw []byte
	var err error
	if strings.HasSuffix(meta, ";base64") || strings.HasPrefix(meta, "image/png") || strings.HasPrefix(meta, "image/jpeg") {
		raw, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			if p, uerr := url.PathUnescape(payload); uerr == nil {
				raw, err = base64.StdEncoding.DecodeString(p)
			}
		}
	} else {
		var s string
		s, err = url.PathUnescape(payload)
		raw = []byte(s)
	}
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	return img, err
}

func PNG(data []byte, scale float64) ([]byte, error) {
	if scale <= 0 {
		scale = 2
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("drawio: %w", err)
	}
	m := doc.FindElement("//mxGraphModel")
	if m == nil {
		d := doc.FindElement("//diagram")
		if d == nil {
			return nil, fmt.Errorf("drawio: no diagram")
		}
		model, err := inflate(strings.TrimSpace(d.Text()))
		if err != nil {
			return nil, fmt.Errorf("drawio: %w", err)
		}
		sub := etree.NewDocument()
		if err := sub.ReadFromString(model); err != nil {
			return nil, fmt.Errorf("drawio: %w", err)
		}
		m = sub.Root()
	}
	r := &router{cells: map[string]*etree.Element{}, geo: map[string]*etree.Element{}, boxes: map[string]box{}, labels: map[string]box{}, containers: map[string]bool{}}
	var order []*etree.Element
	for _, c := range m.FindElements(".//mxCell") {
		if c.SelectAttrValue("visible", "1") == "0" {
			continue
		}
		id := c.SelectAttrValue("id", "")
		r.cells[id] = c
		r.geo[id] = c.SelectElement("mxGeometry")
		order = append(order, c)
	}
	type edgeDraw struct {
		e    *etree.Element
		path []pt
	}
	var edges []edgeDraw
	minX, minY, maxX, maxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	grow := func(b box) {
		minX, minY = math.Min(minX, b.x), math.Min(minY, b.y)
		maxX, maxY = math.Max(maxX, b.x+b.w), math.Max(maxY, b.y+b.h)
	}
	for _, c := range order {
		id := c.SelectAttrValue("id", "")
		if c.SelectAttrValue("vertex", "") != "1" || r.geo[id] == nil {
			continue
		}
		b := r.abs(id)
		r.boxes[id] = b
		grow(b)
		if lb, ok := imageLabel(c, b); ok {
			grow(lb)
		}
	}
	for _, c := range order {
		if c.SelectAttrValue("edge", "") != "1" {
			continue
		}
		p := r.edgePath(c)
		if len(p) < 2 {
			continue
		}
		edges = append(edges, edgeDraw{c, p})
		for _, q := range p {
			grow(box{q.x, q.y, 0, 0})
		}
	}
	if math.IsInf(minX, 0) {
		return nil, fmt.Errorf("drawio: empty diagram")
	}
	minX, minY, maxX, maxY = minX-pageBorder, minY-pageBorder, maxX+pageBorder, maxY+pageBorder
	w, h := int(math.Ceil((maxX-minX)*scale)), int(math.Ceil((maxY-minY)*scale))
	if w*h > maxPixels {
		s := math.Sqrt(float64(maxPixels) / float64(w*h))
		scale *= s
		w, h = int(math.Ceil((maxX-minX)*scale)), int(math.Ceil((maxY-minY)*scale))
	}
	cv := &canvas{img: image.NewRGBA(image.Rect(0, 0, w, h)), scale: scale, ox: minX, oy: minY}
	stddraw.Draw(cv.img, cv.img.Bounds(), image.White, image.Point{}, stddraw.Src)
	black := color.RGBA{0x33, 0x33, 0x33, 255}
	for _, c := range order {
		id := c.SelectAttrValue("id", "")
		if c.SelectAttrValue("vertex", "") != "1" || r.geo[id] == nil {
			continue
		}
		st := styleMap(c.SelectAttrValue("style", ""))
		b := r.boxes[id]
		if st["shape"] == "image" {
			if img, err := decodeImage(st["image"]); err == nil {
				x0, y0 := cv.px(pt{b.x, b.y})
				x1, y1 := cv.px(pt{b.x + b.w, b.y + b.h})
				xdraw.CatmullRom.Scale(cv.img, image.Rect(int(x0), int(y0), int(x1), int(y1)), img, img.Bounds(), xdraw.Over, nil)
			}
			if t := text(c); t != "" {
				col, ok := parseColor(st["fontColor"])
				if !ok {
					col = black
				}
				if err := cv.text(t, floatStyle(st, "fontSize", 11), col, b.x+b.w/2, b.y+b.h+2, "center", nil); err != nil {
					return nil, err
				}
			}
			continue
		}
		radius := 0.0
		if st["rounded"] == "1" {
			if st["absoluteArcSize"] == "1" {
				radius = floatStyle(st, "arcSize", 20) / 2
			} else {
				radius = math.Min(b.w, b.h) * floatStyle(st, "arcSize", 10) / 100
			}
		}
		outline := roundRect(b, radius)
		if col, ok := parseColor(st["fillColor"]); ok {
			cv.fill(col, func(rz *vector.Rasterizer) { cv.polygon(rz, outline) })
		}
		_, plain := st["text"]
		if col, ok := parseColor(st["strokeColor"]); ok || (st["strokeColor"] == "" && !plain) {
			if !ok {
				col = black
			}
			var dash []float64
			sw := floatStyle(st, "strokeWidth", 1)
			if st["dashed"] == "1" {
				dash = []float64{3 * sw, 3 * sw}
				if p := strings.Fields(st["dashPattern"]); len(p) >= 2 {
					dash = nil
					for _, x := range p {
						f, _ := strconv.ParseFloat(x, 64)
						dash = append(dash, f*sw)
					}
				}
			}
			cv.stroke(col, sw, outline, dash)
		}
		if t := text(c); t != "" {
			col, ok := parseColor(st["fontColor"])
			if !ok {
				col = black
			}
			fs := floatStyle(st, "fontSize", 12)
			x, align := b.x+b.w/2, "center"
			switch st["align"] {
			case "left":
				x, align = b.x+floatStyle(st, "spacingLeft", 0)+2, "left"
			case "right":
				x, align = b.x+b.w-floatStyle(st, "spacingRight", 0)-2, "right"
			}
			y := b.y + floatStyle(st, "spacingTop", 0) + 2
			if st["verticalAlign"] != "top" {
				_, th := measure(t, fs)
				y = b.y + b.h/2 - th/2
			}
			if err := cv.text(t, fs, col, x, y, align, nil); err != nil {
				return nil, err
			}
		}
	}
	type label struct {
		t     string
		fs    float64
		at    pt
		col   color.Color
		bg    color.Color
		color color.Color
	}
	var labels []label
	for _, ed := range edges {
		st := styleMap(ed.e.SelectAttrValue("style", ""))
		col, ok := parseColor(st["strokeColor"])
		if !ok {
			col = black
		}
		sw := floatStyle(st, "strokeWidth", 1)
		var dash []float64
		if st["dashed"] == "1" {
			dash = []float64{3 * sw, 3 * sw}
		}
		path := ed.path
		if st["endArrow"] != "none" {
			path = append([]pt(nil), path...)
			n := len(path)
			a, b := path[n-2], path[n-1]
			l := math.Hypot(b.x-a.x, b.y-a.y)
			size := 6 + 2*sw
			if l > 0 {
				ux, uy := (b.x-a.x)/l, (b.y-a.y)/l
				path[n-1] = pt{b.x - ux*size*0.8, b.y - uy*size*0.8}
				tip := b
				base := pt{b.x - ux*size, b.y - uy*size}
				cv.fill(col, func(rz *vector.Rasterizer) {
					cv.polygon(rz, []pt{tip, {base.x - uy*size*0.45, base.y + ux*size*0.45}, {b.x - ux*size*0.7, b.y - uy*size*0.7}, {base.x + uy*size*0.45, base.y - ux*size*0.45}})
				})
			}
		}
		cv.stroke(col, sw, smooth(path, 4), dash)
		if st["noLabel"] == "1" {
			continue
		}
		if t := text(ed.e); t != "" {
			pos := 0.0
			if g := ed.e.SelectElement("mxGeometry"); g != nil {
				pos = num(g, "x")
			}
			bg, ok := parseColor(st["labelBackgroundColor"])
			var bgc color.Color = color.White
			if ok {
				bgc = bg
			}
			fc, ok := parseColor(st["fontColor"])
			if !ok {
				fc = black
			}
			labels = append(labels, label{t: t, fs: floatStyle(st, "fontSize", 11), at: along(ed.path, pos), bg: bgc, color: fc})
		}
	}
	for _, l := range labels {
		_, th := measure(l.t, l.fs)
		if err := cv.text(l.t, l.fs, l.color, l.at.x, l.at.y-th/2, "center", l.bg); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, cv.img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func imageLabel(c *etree.Element, b box) (box, bool) {
	t := text(c)
	if t == "" || styleMap(c.SelectAttrValue("style", ""))["verticalLabelPosition"] != "bottom" {
		return box{}, false
	}
	fs := fontSize(c, 11)
	w, h := measure(t, fs)
	return box{b.x + b.w/2 - w/2, b.y + b.h, w, h + 4}, true
}

func (r *router) edgePath(e *etree.Element) []pt {
	src, okS := r.boxes[e.SelectAttrValue("source", "")]
	dst, okT := r.boxes[e.SelectAttrValue("target", "")]
	g := e.SelectElement("mxGeometry")
	var pts []pt
	if g != nil {
		for _, p := range g.FindElements("Array/mxPoint") {
			pts = append(pts, pt{num(p, "x"), num(p, "y")})
		}
		if !okS {
			if p := g.FindElement("mxPoint[@as='sourcePoint']"); p != nil {
				pts = append([]pt{{num(p, "x"), num(p, "y")}}, pts...)
			}
		}
		if !okT {
			if p := g.FindElement("mxPoint[@as='targetPoint']"); p != nil {
				pts = append(pts, pt{num(p, "x"), num(p, "y")})
			}
		}
	}
	st := styleMap(e.SelectAttrValue("style", ""))
	attach := func(b box, kx, ky string, toward pt) pt {
		x, ex := strconv.ParseFloat(st[kx], 64)
		y, ey := strconv.ParseFloat(st[ky], 64)
		if ex == nil && ey == nil {
			return pt{b.x + b.w*x, b.y + b.h*y}
		}
		return border(b, toward)
	}
	center := func(b box) pt { return pt{b.x + b.w/2, b.y + b.h/2} }
	if okS {
		toward := center(dst)
		if len(pts) > 0 {
			toward = pts[0]
		}
		pts = append([]pt{attach(src, "exitX", "exitY", toward)}, pts...)
	}
	if okT {
		toward := center(src)
		if len(pts) > 0 {
			toward = pts[len(pts)-1]
		}
		pts = append(pts, attach(dst, "entryX", "entryY", toward))
	}
	return pts
}

func border(b box, toward pt) pt {
	cx, cy := b.x+b.w/2, b.y+b.h/2
	dx, dy := toward.x-cx, toward.y-cy
	if dx == 0 && dy == 0 {
		return pt{cx, cy}
	}
	sx, sy := math.Inf(1), math.Inf(1)
	if dx != 0 {
		sx = (b.w / 2) / math.Abs(dx)
	}
	if dy != 0 {
		sy = (b.h / 2) / math.Abs(dy)
	}
	s := math.Min(sx, sy)
	return pt{cx + dx*s, cy + dy*s}
}

func along(path []pt, rel float64) pt {
	total := 0.0
	for i := 0; i+1 < len(path); i++ {
		total += math.Hypot(path[i+1].x-path[i].x, path[i+1].y-path[i].y)
	}
	target := (rel + 1) / 2 * total
	for i := 0; i+1 < len(path); i++ {
		a, b := path[i], path[i+1]
		l := math.Hypot(b.x-a.x, b.y-a.y)
		if target <= l || i+2 == len(path) {
			f := 0.0
			if l > 0 {
				f = math.Min(target/l, 1)
			}
			return pt{a.x + (b.x-a.x)*f, a.y + (b.y-a.y)*f}
		}
		target -= l
	}
	return path[0]
}

func smooth(path []pt, radius float64) []pt {
	if len(path) < 3 {
		return path
	}
	path = straight(path)
	if len(path) < 3 {
		return path
	}
	out := []pt{path[0]}
	for i := 1; i+1 < len(path); i++ {
		a, b, c := path[i-1], path[i], path[i+1]
		l1, l2 := math.Hypot(b.x-a.x, b.y-a.y), math.Hypot(c.x-b.x, c.y-b.y)
		r := math.Min(radius, math.Min(l1, l2)/2)
		if r <= 0 {
			out = append(out, b)
			continue
		}
		p0 := pt{b.x + (a.x-b.x)/l1*r, b.y + (a.y-b.y)/l1*r}
		p2 := pt{b.x + (c.x-b.x)/l2*r, b.y + (c.y-b.y)/l2*r}
		for k := 0; k <= 4; k++ {
			t := float64(k) / 4
			out = append(out, pt{(1-t)*(1-t)*p0.x + 2*(1-t)*t*b.x + t*t*p2.x, (1-t)*(1-t)*p0.y + 2*(1-t)*t*b.y + t*t*p2.y})
		}
	}
	return append(out, path[len(path)-1])
}

func straight(path []pt) []pt {
	out := []pt{path[0]}
	for i := 1; i < len(path); i++ {
		p := path[i]
		if p == out[len(out)-1] {
			continue
		}
		if len(out) >= 2 && i+1 <= len(path) {
			a, b := out[len(out)-2], out[len(out)-1]
			if math.Abs((b.x-a.x)*(p.y-b.y)-(b.y-a.y)*(p.x-b.x)) < 1e-6 && (b.x-a.x)*(p.x-b.x)+(b.y-a.y)*(p.y-b.y) >= 0 {
				out[len(out)-1] = p
				continue
			}
		}
		out = append(out, p)
	}
	return out
}
