package gate

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

// record is one name in a fake zone: a CNAME, or addresses, or an rcode.
type record struct {
	cname string
	addrs []string
	rcode int
	// stop makes the resolver answer this CNAME without chasing it.
	stop bool
	// big makes the UDP answer truncated, so the gate asks over TCP.
	big bool
}

// zone answers queries the way a recursive resolver does: the whole CNAME
// chain, then the final name's records or its rcode. It counts queries.
type zone struct {
	mu      *sync.Mutex
	names   map[string]record
	queries *[]string
}

func newZone(names map[string]record) zone {
	return zone{mu: &sync.Mutex{}, names: names, queries: &[]string{}}
}

func (z zone) asked() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(*z.queries)
}

// lookup finds a name's record, or the nearest wildcard above it ("*.x").
func (z zone) lookup(name string) (record, bool) {
	if r, ok := z.names[name]; ok {
		return r, true
	}
	for parent := name; strings.Contains(parent, "."); {
		_, parent, _ = strings.Cut(parent, ".")
		if r, ok := z.names["*."+parent]; ok {
			return r, true
		}
	}
	return record{}, false
}

func appendName(b []byte, name string) []byte {
	for l := range strings.SplitSeq(name, ".") {
		b = append(append(b, byte(len(l))), l...)
	}
	return append(b, 0)
}

func (z zone) exchange(_ context.Context, _ string, q []byte, tcp bool) ([]byte, error) {
	name, off, err := readName(q, 12)
	if err != nil {
		return nil, err
	}
	qt := dnsType(binary.BigEndian.Uint16(q[off:]))
	z.mu.Lock()
	*z.queries = append(*z.queries, name+"/"+map[dnsType]string{typeA: "A", typeAAAA: "AAAA"}[qt]+map[bool]string{true: "/tcp"}[tcp])
	z.mu.Unlock()
	var answers [][]byte
	rcode := 0
	truncated := false
	cur := name
	for range 20 {
		rec, ok := z.lookup(cur)
		if !ok {
			rcode = rcodeNXDomain
			break
		}
		if rec.big && !tcp {
			truncated = true
		}
		if rec.rcode != 0 {
			rcode = rec.rcode
			break
		}
		if rec.cname != "" {
			rr := appendName(nil, cur)
			rr = binary.BigEndian.AppendUint16(rr, uint16(typeCNAME))
			rr = binary.BigEndian.AppendUint16(rr, 1)
			rr = binary.BigEndian.AppendUint32(rr, 60)
			target := appendName(nil, rec.cname)
			rr = binary.BigEndian.AppendUint16(rr, uint16(len(target)))
			answers = append(answers, append(rr, target...))
			if rec.stop {
				break
			}
			cur = rec.cname
			continue
		}
		for _, a := range rec.addrs {
			addr := netip.MustParseAddr(a)
			if (qt == typeA) != addr.Is4() {
				continue
			}
			rr := appendName(nil, cur)
			rr = binary.BigEndian.AppendUint16(rr, uint16(qt))
			rr = binary.BigEndian.AppendUint16(rr, 1)
			rr = binary.BigEndian.AppendUint32(rr, 60)
			raw := addr.AsSlice()
			rr = binary.BigEndian.AppendUint16(rr, uint16(len(raw)))
			answers = append(answers, append(rr, raw...))
		}
		break
	}
	out := make([]byte, 12)
	copy(out, q[:2])
	out[2] = 0x81 // QR, RD
	if truncated {
		out[2] |= 0x02
		answers = nil
	}
	out[3] = 0x80 | byte(rcode)
	binary.BigEndian.PutUint16(out[4:], 1)
	binary.BigEndian.PutUint16(out[6:], uint16(len(answers)))
	out = append(out, q[12:off+4]...)
	for _, a := range answers {
		out = append(out, a...)
	}
	return out, nil
}

func TestDNSWire(t *testing.T) {
	q, err := dnsQuery(0x1234, "www.example.com", typeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	if name, off, err := readName(q, 12); err != nil || name != "www.example.com" || binary.BigEndian.Uint16(q[off:]) != uint16(typeAAAA) {
		t.Fatalf("question %q %v", name, err)
	}
	for _, bad := range []string{"", "a..b", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com"} {
		if _, err := dnsQuery(1, bad, typeA); err == nil {
			t.Errorf("%q encoded", bad)
		}
	}
	// A compressed answer: the CNAME's owner points at the question.
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	msg = appendName(msg, "www.example.com")
	msg = append(msg, 0, 1, 0, 1)
	msg = append(msg, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 'c', 'd', 'n', 0xc0, 16) // www.example.com CNAME cdn.example.com
	msg = append(msg, 0xc0, byte(len(msg)-6), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7)
	m, err := parseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	if m.id != 0x1234 || m.qname != "www.example.com" || len(m.answers) != 2 || m.answers[0].target != "cdn.example.com" ||
		m.answers[1].name != "cdn.example.com" || m.answers[1].addr != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("%+v", m)
	}
	// A pointer forwards, or to itself, is refused: a message cannot loop.
	loop := slices.Clone(msg[:12])
	loop = append(loop, 0xc0, 12, 0, 1, 0, 1)
	if _, err := parseDNS(loop); err == nil {
		t.Error("a self-pointing name parsed")
	}
	for i := range len(msg) - 1 {
		if _, err := parseDNS(msg[:i]); err == nil && i < len(msg)-16 {
			t.Errorf("a message cut at %d parsed", i)
		}
	}
	if a := nameserver([]byte("# x\nsearch corp.example\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n")); a != netip.MustParseAddr("192.0.2.53") {
		t.Errorf("nameserver %s", a)
	}
}

// Each outcome a discovery lookup can have (docs/spec/scope.md,
// "Discovery"; E4 test 8).
func TestLookupOutcomes(t *testing.T) {
	names := map[string]record{
		"www.example.com":      {cname: "cdn.example.net"},
		"cdn.example.net":      {addrs: []string{"198.51.100.7", "2001:db8::7"}},
		"shop.example.com":     {cname: "gone.myshopify.example"},
		"mail.example.com":     {cname: "relay.example.net"},
		"relay.example.net":    {},
		"bare.example.com":     {},
		"broken.example.com":   {rcode: rcodeServFail},
		"refused.example.com":  {rcode: rcodeRefused},
		"loop1.example.com":    {cname: "loop2.example.com"},
		"loop2.example.com":    {cname: "loop1.example.com"},
		"partial.example.com":  {cname: "far.example.net", stop: true},
		"far.example.net":      {addrs: []string{"198.51.100.8"}},
		"big.example.com":      {addrs: []string{"198.51.100.9"}, big: true},
		"long0.example.com":    {cname: "long1.example.com"},
		"dangling.example.com": {cname: "stale.example.com"},
	}
	for i := 1; i <= 9; i++ {
		names["long"+string(rune('0'+i))+".example.com"] = record{cname: "long" + string(rune('0'+i+1)) + ".example.com"}
	}
	for _, tc := range []struct {
		name, outcome string
		chain         []string
		addrs         int
	}{
		{"www.example.com", "addresses", []string{"cdn.example.net"}, 2},
		{"shop.example.com", "nxdomain", []string{"gone.myshopify.example"}, 0},
		{"dangling.example.com", "nxdomain", []string{"stale.example.com"}, 0},
		{"mail.example.com", "nodata", []string{"relay.example.net"}, 0},
		{"bare.example.com", "nodata", nil, 0},
		{"nothere.example.com", "nxdomain", nil, 0},
		{"broken.example.com", "servfail", nil, 0},
		{"refused.example.com", "refused", nil, 0},
		{"loop1.example.com", "loop", nil, 0},
		{"long0.example.com", "loop", nil, 0},
		{"partial.example.com", "addresses", []string{"far.example.net"}, 1},
		{"big.example.com", "addresses", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.zone = newZone(names)
			l := w.gate().lookup(context.Background(), Entry{RequestID: "g1"}, tc.name)
			if l.Outcome != Outcome(tc.outcome) || len(l.Addrs) != tc.addrs || tc.chain != nil && !slices.Equal(l.Chain, tc.chain) {
				t.Errorf("%+v", l)
			}
			if l.Insufficient() != (tc.outcome != "addresses" && tc.outcome != "nxdomain" && tc.outcome != "nodata") {
				t.Errorf("insufficient: %v", l.Insufficient())
			}
			for _, q := range w.zone.asked() {
				if strings.HasSuffix(strings.Split(q, "/")[0], ".") || strings.Contains(q, "corp.") {
					t.Errorf("query %q", q)
				}
			}
		})
	}
	w := newWorld(t)
	w.zone = newZone(names)
	w.gate().lookup(context.Background(), Entry{RequestID: "g1"}, "big.example.com")
	if q := w.zone.asked(); !slices.Contains(q, "big.example.com/A/tcp") {
		t.Errorf("a truncated answer was not asked again over TCP: %v", q)
	}
}

// A discovery lookup names only a name under a root and no exclude; the
// control name under invalid. is the one exception; refusals send nothing.
func TestResolveAdmission(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{"www.example.com": {addrs: []string{"198.51.100.7"}}})
	w.scope.excluded = map[string]string{"domain:legacy.example.com": "exclude[0]"}
	g := w.gate()
	ctx := context.Background()
	for name, want := range map[string]string{
		"www.example.com":                  "sent",
		"a.legacy.example.com":             "refused:excluded",
		"example.org":                      "refused:out_of_scope",
		"q7c2x9k1m3p5r8t0w4yz.invalid":     "sent",
		"WWW.example.com":                  "refused:bind",
		"www.example.com.attacker.example": "refused:out_of_scope",
		"under_score.example.com":          "refused:bind",
	} {
		if got := g.Resolve(ctx, Resolve{Asset: "domain:example.com", Name: name, Stage: "scope"}); got.Decision != want {
			t.Errorf("%s: %+v", name, got)
		}
	}
	for _, q := range w.zone.asked() {
		if strings.Contains(q, "legacy") || strings.Contains(q, "example.org") || strings.Contains(q, "attacker") {
			t.Errorf("a refused name was queried: %s", q)
		}
	}
	uses, _ := g.Egress()
	if len(uses) != 1 || uses[0].Source != "dns" || uses[0].Host != "192.0.2.53" || uses[0].Requests != len(w.zone.asked()) {
		t.Errorf("egress %+v, %d queries", uses, len(w.zone.asked()))
	}
	var dnsLines int
	for _, e := range w.audit.entries(t) {
		if e.Event == "dns" {
			dnsLines++
			if e.DestIP != "192.0.2.53" {
				t.Errorf("a dns line without the resolver: %+v", e)
			}
		}
	}
	if dnsLines != len(w.zone.asked()) {
		t.Errorf("%d dns lines for %d queries", dnsLines, len(w.zone.asked()))
	}
}

// A chain that enters an excluded name stops there: the gate sends no
// query for it, whether or not the resolver followed it, and a request
// through it is refused (docs/spec/scope.md, "Discovery", "Addresses").
func TestChainIntoAnExclude(t *testing.T) {
	for _, stop := range []bool{true, false} {
		w := newWorld(t)
		w.zone = newZone(map[string]record{
			"shop.example.com":     {cname: "x.legacy.example.com", stop: stop},
			"x.legacy.example.com": {addrs: []string{"198.51.100.60"}},
		})
		w.scope.excluded = map[string]string{"domain:legacy.example.com": "exclude[0]"}
		g := w.gate()
		r := g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: "shop.example.com", Stage: "scope"})
		if r.Lookup.Outcome != "excluded" || r.Lookup.ExcludedBy != "exclude[0]" {
			t.Errorf("stop %v: discovery %+v", stop, r.Lookup)
		}
		res := g.Send(context.Background(), web("https", "shop.example.com", "/"))
		if res.Decision != "refused:excluded" || res.Reason != "excluded_by_operator" || w.dials.Load() != 0 {
			t.Errorf("stop %v: send %+v, %d dials", stop, res, w.dials.Load())
		}
		for _, q := range w.zone.asked() {
			if strings.HasPrefix(q, "x.legacy.") {
				t.Errorf("stop %v: the gate queried the excluded name: %s", stop, q)
			}
		}
	}
}

// With no nameserver to ask, a lookup is not sent: not counted, not a
// control, and its line says why.
func TestResolveWithoutAResolver(t *testing.T) {
	w := newWorld(t)
	g := w.gate()
	g.nameserver = netip.Addr{}
	r := g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: "x.invalid", Stage: "scope", Control: true})
	uses, _ := g.Egress()
	if r.Decision != "unavailable:no_resolver" || len(uses) != 0 || len(w.zone.asked()) != 0 ||
		g.egress.controls != 0 || g.egress.invalid || g.egress.dns != 0 {
		t.Errorf("%+v, uses %+v", r, uses)
	}
	if !strings.Contains(w.audit.String(), `"decision":"unavailable:no_resolver"`) {
		t.Errorf("audit log:\n%s", w.audit.String())
	}
}
