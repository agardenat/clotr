package drawio

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"image"
	"image/png"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

const model = `<mxGraphModel><root>
<mxCell id="0"/><mxCell id="1" parent="0"/>
<mxCell id="net" value="network" style="rounded=1;container=1;" vertex="1" parent="1"><mxGeometry x="20" y="40" width="560" height="420" as="geometry"/></mxCell>
<mxCell id="a" value="Source A" style="shape=image;verticalLabelPosition=bottom;fontSize=11;" vertex="1" parent="net"><mxGeometry x="40" y="60" width="48" height="48" as="geometry"/></mxCell>
<mxCell id="b" value="Middle B" style="shape=image;verticalLabelPosition=bottom;fontSize=11;" vertex="1" parent="net"><mxGeometry x="250" y="60" width="48" height="48" as="geometry"/></mxCell>
<mxCell id="c" value="Target C" style="shape=image;verticalLabelPosition=bottom;fontSize=11;" vertex="1" parent="net"><mxGeometry x="460" y="60" width="48" height="48" as="geometry"/></mxCell>
<mxCell id="d" value="Source D" style="shape=image;verticalLabelPosition=bottom;fontSize=11;" vertex="1" parent="net"><mxGeometry x="40" y="300" width="48" height="48" as="geometry"/></mxCell>
<mxCell id="e" value="Source E" style="shape=image;verticalLabelPosition=bottom;fontSize=11;" vertex="1" parent="net"><mxGeometry x="250" y="300" width="48" height="48" as="geometry"/></mxCell>
<mxCell id="e1" value="TCP" style="edgeStyle=orthogonalEdgeStyle;" edge="1" parent="1" source="a" target="c"><mxGeometry relative="1" as="geometry"/></mxCell>
<mxCell id="e2" value="SYNC" style="edgeStyle=orthogonalEdgeStyle;" edge="1" parent="1" source="d" target="c"><mxGeometry relative="1" as="geometry"/></mxCell>
<mxCell id="e3" value="SYNC" style="edgeStyle=orthogonalEdgeStyle;" edge="1" parent="1" source="e" target="c"><mxGeometry relative="1" as="geometry"/></mxCell>
</root></mxGraphModel>`

func wrap(diagram string) []byte {
	return []byte(`<mxfile><diagram name="p" id="p">` + diagram + `</diagram></mxfile>`)
}

func routed(t *testing.T, data []byte, opt Options) (*etree.Document, *Result) {
	t.Helper()
	out, res, err := Route(data, opt)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatal(err)
	}
	return doc, res
}

func edgePoints(t *testing.T, r *router, e *etree.Element) []pt {
	t.Helper()
	src, dst := r.boxes[e.SelectAttrValue("source", "")], r.boxes[e.SelectAttrValue("target", "")]
	st := styleMap(e.SelectAttrValue("style", ""))
	at := func(b box, kx, ky string) pt {
		var x, y float64
		for _, v := range []struct {
			s string
			f *float64
		}{{st[kx], &x}, {st[ky], &y}} {
			if _, err := parseF(v.s, v.f); err != nil {
				t.Fatalf("%s : %v", e.SelectAttrValue("id", ""), err)
			}
		}
		return pt{b.x + b.w*x, b.y + b.h*y}
	}
	pts := []pt{at(src, "exitX", "exitY")}
	for _, p := range e.FindElements("mxGeometry/Array/mxPoint") {
		pts = append(pts, pt{num(p, "x"), num(p, "y")})
	}
	return append(pts, at(dst, "entryX", "entryY"))
}

func parseF(s string, f *float64) (float64, error) {
	v, err := strconvParse(s)
	*f = v
	return v, err
}

func reload(t *testing.T, doc *etree.Document) *router {
	t.Helper()
	r := &router{cells: map[string]*etree.Element{}, geo: map[string]*etree.Element{}, boxes: map[string]box{}, labels: map[string]box{}, containers: map[string]bool{}}
	for _, c := range doc.FindElements("//mxCell") {
		id := c.SelectAttrValue("id", "")
		r.cells[id] = c
		r.geo[id] = c.SelectElement("mxGeometry")
		if styleMap(c.SelectAttrValue("style", ""))["container"] == "1" {
			r.containers[id] = true
		}
	}
	for id, c := range r.cells {
		if c.SelectAttrValue("vertex", "") == "1" {
			r.boxes[id] = r.abs(id)
			if lb, ok := imageLabel(c, r.boxes[id]); ok {
				r.labels[id] = lb
			}
		}
	}
	return r
}

func crosses(a, b pt, o box) bool {
	if a.x == b.x {
		lo, hi := min(a.y, b.y), max(a.y, b.y)
		return a.x > o.x && a.x < o.x+o.w && hi > o.y && lo < o.y+o.h
	}
	lo, hi := min(a.x, b.x), max(a.x, b.x)
	return a.y > o.y && a.y < o.y+o.h && hi > o.x && lo < o.x+o.w
}

func TestRouteAvoidsObjects(t *testing.T) {
	doc, res := routed(t, wrap(model), Options{SpreadX: 1.5, SpreadY: 1.2})
	if res.Edges != 3 || len(res.Failed) != 0 {
		t.Fatalf("résultat %+v", res)
	}
	r := reload(t, doc)
	for _, e := range doc.FindElements("//mxCell[@edge='1']") {
		id := e.SelectAttrValue("id", "")
		if st := styleMap(e.SelectAttrValue("style", "")); st["edgeStyle"] != "none" {
			t.Fatalf("%s : style %v", id, st)
		}
		pts := edgePoints(t, r, e)
		if len(pts) < 3 {
			t.Fatalf("%s : sans points de passage", id)
		}
		for i := 0; i+1 < len(pts); i++ {
			a, b := pts[i], pts[i+1]
			if a.x != b.x && a.y != b.y {
				t.Fatalf("%s : segment oblique %v → %v", id, a, b)
			}
			for nid, bx := range r.boxes {
				if r.containers[nid] {
					continue
				}
				if (i == 0 && nid == e.SelectAttrValue("source", "")) || (i == len(pts)-2 && nid == e.SelectAttrValue("target", "")) {
					continue
				}
				if crosses(a, b, bx) {
					t.Fatalf("%s traverse %s : %v → %v", id, nid, a, b)
				}
				if lb, ok := r.labels[nid]; ok && crosses(a, b, lb) {
					t.Fatalf("%s traverse le libellé de %s : %v → %v", id, nid, a, b)
				}
			}
		}
	}
	if g := r.geo["net"]; num(g, "width") != 840 || num(g, "height") != 504 {
		t.Fatalf("groupe non élargi : %v × %v", num(g, "width"), num(g, "height"))
	}
}

func TestRouteSharedLabel(t *testing.T) {
	doc, _ := routed(t, wrap(model), Options{SpreadX: 1.5, SpreadY: 1.2})
	hidden := 0
	for _, id := range []string{"e2", "e3"} {
		e := doc.FindElement("//mxCell[@id='" + id + "']")
		if styleMap(e.SelectAttrValue("style", ""))["noLabel"] == "1" {
			hidden++
		}
	}
	if hidden != 1 {
		t.Fatalf("un seul libellé SYNC attendu, %d masqués", hidden)
	}
	if e := doc.FindElement("//mxCell[@id='e1']"); styleMap(e.SelectAttrValue("style", ""))["noLabel"] == "1" {
		t.Fatal("libellé TCP masqué")
	}
}

func TestRouteCompressed(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(url.QueryEscape(model)))
	_ = w.Close()
	doc, res := routed(t, wrap(base64.StdEncoding.EncodeToString(buf.Bytes())), Options{})
	if res.Edges != 3 || doc.FindElement("//diagram/mxGraphModel") == nil {
		t.Fatalf("diagramme compressé non relu : %+v", res)
	}
}

func TestRouteInvalid(t *testing.T) {
	for _, in := range []string{"pas du xml", "<mxfile/>"} {
		if _, _, err := Route([]byte(in), Options{}); err == nil || !strings.Contains(err.Error(), "drawio") {
			t.Fatalf("%q : erreur attendue, obtenu %v", in, err)
		}
	}
}

func strconvParse(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

func TestPNG(t *testing.T) {
	icon := base64.StdEncoding.EncodeToString(tinyPNG(t))
	m := strings.ReplaceAll(model, `shape=image;`, `shape=image;image=data:image/png,`+icon+`;`)
	m = strings.Replace(m, `<mxCell id="0"/>`, `<mxCell id="0"/><mxCell style="text;html=1;" vertex="1" parent="1" visible="0"><mxGeometry x="-500" y="-500" width="1" height="1" as="geometry"/></mxCell>`, 1)
	out, _, err := Route(wrap(m), Options{SpreadX: 1.5, SpreadY: 1.2})
	if err != nil {
		t.Fatal(err)
	}
	data, err := PNG(out, 2)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() < 1600 || b.Dx() > 1800 || b.Dy() < 1000 || b.Dy() > 1200 {
		t.Fatalf("taille %v : cellule masquée prise en compte ou échelle fausse", b)
	}
	orange := 0
	for y := 0; y < b.Dy(); y += 2 {
		for x := 0; x < b.Dx(); x += 2 {
			r, g, bl, _ := img.At(x, y).RGBA()
			if r>>8 > 200 && g>>8 < 80 && bl>>8 < 80 {
				orange++
			}
		}
	}
	if orange == 0 {
		t.Fatal("icônes absentes du rendu")
	}
}

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		if i%4 == 0 || i%4 == 3 {
			img.Pix[i] = 255
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
