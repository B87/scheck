package gate

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

// record is one name in a fake zone: a CNAME, or addresses, or an rcode.
type record struct {
	cname    string
	addrs    []string
	rcode    int
	failType dnsType // only this record type returns SERVFAIL
	// stop makes the resolver answer this CNAME without chasing it.
	stop bool
	// big makes the UDP answer truncated, so the gate asks over TCP.
	big bool
	// hidden answers an address query for this CNAME, when its target does
	// not exist, with NXDOMAIN and no CNAME, as a DNS host may answer for
	// an in-zone target (Cloudflare, docs/eval/lab-0.0.2-domain.md); only
	// a CNAME query shows it.
	hidden bool
	txt    [][]string
	mx     []mxRecord
	ns     []string
}

type mxRecord struct {
	pref   uint16
	target string
}

// zone answers queries the way a recursive resolver does: the whole CNAME
// chain, then the final name's records or its rcode. It counts queries.
type zone struct {
	mu      *sync.Mutex
	names   map[string]record
	queries *[]string
	// compact answers a name that does not exist with NOERROR and no
	// record, as a DNSSEC-signed zone with compact denial of existence
	// does through a public resolver.
	compact bool
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

// rr encodes one answer record.
func rr(name string, t dnsType, data []byte) []byte {
	b := appendName(nil, name)
	b = binary.BigEndian.AppendUint16(b, uint16(t))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 60)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func (z zone) exchange(_ context.Context, _ string, q []byte, tcp bool) ([]byte, error) {
	name, off, err := readName(q, 12)
	if err != nil {
		return nil, err
	}
	qt := dnsType(binary.BigEndian.Uint16(q[off:]))
	z.mu.Lock()
	*z.queries = append(*z.queries, name+"/"+qt.String()+map[bool]string{true: "/tcp"}[tcp])
	z.mu.Unlock()
	var answers [][]byte
	rcode := 0
	truncated := false
	missing := func() {
		if !z.compact {
			rcode = rcodeNXDomain
		}
	}
	cur := name
	for range 20 {
		rec, ok := z.lookup(cur)
		if !ok {
			missing()
			break
		}
		if rec.big && !tcp {
			truncated = true
		}
		if rec.failType == qt {
			rcode = rcodeServFail
			break
		}
		if rec.rcode != 0 {
			rcode = rec.rcode
			break
		}
		if rec.cname != "" {
			if _, exists := z.lookup(rec.cname); rec.hidden && !exists && (qt == typeA || qt == typeAAAA) {
				// The CNAMEs before this one stay, as a resolver keeps them.
				rcode = rcodeNXDomain
				break
			}
			answers = append(answers, rr(cur, typeCNAME, appendName(nil, rec.cname)))
			if qt == typeCNAME || rec.stop {
				break
			}
			cur = rec.cname
			continue
		}
		switch qt {
		case typeA, typeAAAA:
			for _, a := range rec.addrs {
				addr := netip.MustParseAddr(a)
				if (qt == typeA) == addr.Is4() {
					answers = append(answers, rr(cur, qt, addr.AsSlice()))
				}
			}
		case typeTXT:
			for _, strs := range rec.txt {
				var data []byte
				for _, s := range strs {
					data = append(append(data, byte(len(s))), s...)
				}
				answers = append(answers, rr(cur, typeTXT, data))
			}
		case typeMX:
			for _, m := range rec.mx {
				answers = append(answers, rr(cur, typeMX, appendName(binary.BigEndian.AppendUint16(nil, m.pref), m.target)))
			}
		case typeNS:
			for _, n := range rec.ns {
				answers = append(answers, rr(cur, typeNS, appendName(nil, n)))
			}
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

// TXT, MX and NS answers decode (docs/spec/scope.md, "The resolver"): a TXT
// record's strings kept apart, an MX's preference and target, a null MX's
// target as the root. A TXT string running past its record, a target
// running past its record and a label holding a dot are refused.
func TestDNSRecordWire(t *testing.T) {
	msg := func(t dnsType, records ...[]byte) []byte {
		b := []byte{0, 1, 0x81, 0x80, 0, 1, 0, byte(len(records)), 0, 0, 0, 0}
		b = appendName(b, "example.com")
		b = binary.BigEndian.AppendUint16(b, uint16(t))
		b = append(b, 0, 1)
		for _, r := range records {
			b = append(b, r...)
		}
		return b
	}
	txt := []byte("\x0fv=spf1 include:\x14_spf.google.com ~all")
	m, err := parseDNS(msg(typeTXT, rr("example.com", typeTXT, txt), rr("example.com", typeTXT, []byte("\x00"))))
	if err != nil || len(m.answers) != 2 || !slices.Equal(m.answers[0].txt, []string{"v=spf1 include:", "_spf.google.com ~all"}) ||
		!slices.Equal(m.answers[1].txt, []string{""}) {
		t.Fatalf("TXT %+v %v", m, err)
	}
	m, err = parseDNS(msg(typeMX, rr("example.com", typeMX, appendName([]byte{0, 10}, "aspmx.l.google.com")), rr("example.com", typeMX, []byte{0, 0, 0})))
	if err != nil || len(m.answers) != 2 || m.answers[0].pref != 10 || m.answers[0].target != "aspmx.l.google.com" ||
		m.answers[1].pref != 0 || m.answers[1].target != "" {
		t.Fatalf("MX %+v %v", m, err)
	}
	m, err = parseDNS(msg(typeNS, rr("example.com", typeNS, appendName(nil, "ns1.dns-host.example"))))
	if err != nil || len(m.answers) != 1 || m.answers[0].target != "ns1.dns-host.example" {
		t.Fatalf("NS %+v %v", m, err)
	}
	for name, bad := range map[string][]byte{
		"a TXT string past its record": msg(typeTXT, rr("example.com", typeTXT, []byte("\x05abc"))),
		"an empty TXT record":          msg(typeTXT, rr("example.com", typeTXT, nil)),
		"a short MX":                   msg(typeMX, rr("example.com", typeMX, []byte{0, 1})),
		"an MX target past its record": msg(typeMX, append(rr("example.com", typeMX, []byte{0, 1, 3, 'm', 'x'}), 0)),
		"a label holding a dot":        msg(typeNS, rr("example.com", typeNS, []byte("\x05a.b.c\x00"))),
	} {
		if _, err := parseDNS(bad); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

// Names scheck builds take no underscore label but _dmarc first and one
// _domainkey after a selector; names read from answers may hold them
// anywhere (docs/spec/scope.md, "The resolver").
func TestRecordAndAnswerNames(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com": true, "_dmarc.example.com": true, "s1._domainkey.example.com": true,
		"s1.2024._domainkey.example.com": true, "_spf.example.com": false, "x._dmarc.example.com": false,
		"_domainkey.example.com": false, "a._domainkey._domainkey.example.com": false, "s_1._domainkey.example.com": false,
		"_dmarc.s1._domainkey.example.com": false, "_dmarc._domainkey.example.com": false,
	} {
		if _, err := recordName(name); (err == nil) != want {
			t.Errorf("recordName(%q): %v", name, err)
		}
	}
	for name, want := range map[string]bool{
		"_spf.google.com": true, "a_b.example.com": true, "x.__.example.com": true, "-a.example.com": false, "a.123": false, "a..b": false,
	} {
		if _, err := answerName(name); (err == nil) != want {
			t.Errorf("answerName(%q): %v", name, err)
		}
	}
	if _, err := dnsName("_spf.google.com"); err == nil {
		t.Error("a host name took an underscore")
	}
}

// A records read: TXT records with their strings apart, a DKIM selector
// followed through its CNAME, MX with a null MX, NS, and a truncated TXT
// answer asked again over TCP. A string redact_extra matches is redacted
// in the result and in the audit line.
func TestReadRecords(t *testing.T) {
	w := newWorld(t)
	w.extra = []string{"zebrafish"}
	w.zone = newZone(map[string]record{
		"example.com": {txt: [][]string{{"v=spf1 include:_spf.google.com ", "~all"}, {"zebrafish-verification=1"}, {"v=spf1 ip4:zebra", "fish.example -all"}, {"api_token=xyzzebr", "afish rest"}},
			mx: []mxRecord{{10, "aspmx.l.google.com"}}, ns: []string{"ns1.dns-host.example", "ns2.dns-host.example"}},
		"_dmarc.example.com":            {txt: [][]string{{"v=DMARC1; p=none"}}, big: true},
		"s1._domainkey.example.com":     {cname: "s1.domainkey.u123.esp.example"},
		"s1.domainkey.u123.esp.example": {txt: [][]string{{"v=DKIM1; k=rsa; p=MIGf"}}},
		"nomail.example.com":            {mx: []mxRecord{{0, ""}}},
	})
	g := w.gate()
	read := func(name, typ string) RecordSet {
		return g.ReadRecords(context.Background(), Records{Asset: "domain:example.com", Name: name, Type: typ, Stage: "observe"})
	}
	apex := read("example.com", "TXT")
	// The third record splits the redacted value across its two strings;
	// the fourth splits it where its first part already matches a rule of
	// its own: the record is redacted once, with one marker.
	if len(apex.TXT) != 4 || strings.Contains(apex.TXT[3], "afish") || strings.Count(apex.TXT[3], "[REDACTED:") != 1 ||
		!strings.HasSuffix(apex.TXT[3], " rest") {
		t.Errorf("a split record whose first part matches %q", apex.TXT)
	}
	if apex.Decision != "sent" || apex.Outcome != OutcomeRecords ||
		apex.TXT[0] != "v=spf1 include:_spf.google.com ~all" ||
		strings.Contains(apex.TXT[1], "zebrafish") || !strings.Contains(apex.TXT[1], "[REDACTED:") ||
		strings.Contains(apex.TXT[2], "zebrafish") || !strings.Contains(apex.TXT[2], "[REDACTED:") {
		t.Errorf("apex TXT %+v", apex)
	}
	if d := read("_dmarc.example.com", "TXT"); d.Outcome != OutcomeRecords || len(d.TXT) != 1 || d.TXT[0] != "v=DMARC1; p=none" {
		t.Errorf("DMARC %+v", d)
	}
	if !slices.Contains(w.zone.asked(), "_dmarc.example.com/TXT/tcp") {
		t.Errorf("a truncated TXT answer was not asked again over TCP: %v", w.zone.asked())
	}
	if k := read("s1._domainkey.example.com", "TXT"); k.Outcome != OutcomeRecords || !slices.Equal(k.Chain, []string{"s1.domainkey.u123.esp.example"}) ||
		len(k.TXT) != 1 || k.TXT[0] != "v=DKIM1; k=rsa; p=MIGf" {
		t.Errorf("DKIM %+v", k)
	}
	if mx := read("example.com", "MX"); mx.Outcome != OutcomeRecords || !slices.Equal(mx.MX, []MX{{10, "aspmx.l.google.com"}}) {
		t.Errorf("MX %+v", mx)
	}
	if mx := read("nomail.example.com", "MX"); !slices.Equal(mx.MX, []MX{{0, ""}}) {
		t.Errorf("null MX %+v", mx)
	}
	if ns := read("example.com", "NS"); !slices.Equal(ns.NS, []string{"ns1.dns-host.example", "ns2.dns-host.example"}) {
		t.Errorf("NS %+v", ns)
	}
	if none := read("s2._domainkey.example.com", "TXT"); none.Outcome != OutcomeNXDomain || none.Insufficient() {
		t.Errorf("a missing selector %+v", none)
	}
	// The audit line holds the record as the read does: one marker,
	// redacted once.
	marked := 0
	for _, e := range w.audit.entries(t) {
		for _, a := range e.Answers {
			if strings.Contains(a, "zebrafish") || strings.Contains(a, "afish rest") {
				t.Errorf("audit answer %q", a)
			}
			if strings.Contains(a, `"api_token=`) {
				marked++
				if !strings.HasSuffix(a, `"`+apex.TXT[3]+`"`) {
					t.Errorf("audit answer %q, the read kept %q", a, apex.TXT[3])
				}
			}
		}
	}
	if marked != 1 {
		t.Errorf("%d audit answers for the split record", marked)
	}
}

// A records read is admitted as a discovery lookup is, with the names
// scheck builds: refusals send nothing.
func TestReadRecordsAdmission(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{"example.com": {txt: [][]string{{"v=spf1 -all"}}}})
	w.scope.excluded = map[string]string{"domain:legacy.example.com": "exclude[0]"}
	g := w.gate()
	for _, tc := range []struct{ name, typ, want string }{
		{"example.com", "TXT", "sent"},
		{"_dmarc.example.com", "TXT", "sent"},
		{"_spf.example.com", "TXT", "refused:bind"},
		{"example.com", "A", "refused:bind"},
		{"Example.com", "TXT", "refused:bind"},
		{"_dmarc.legacy.example.com", "TXT", "refused:excluded"},
		{"_dmarc.example.org", "TXT", "refused:out_of_scope"},
	} {
		if got := g.ReadRecords(context.Background(), Records{Asset: "domain:example.com", Name: tc.name, Type: tc.typ}); got.Decision != tc.want {
			t.Errorf("%s %s: %+v", tc.name, tc.typ, got)
		}
	}
	for _, q := range w.zone.asked() {
		if strings.Contains(q, "_spf") || strings.Contains(q, "legacy") || strings.Contains(q, "example.org") || strings.Contains(q, "/A") {
			t.Errorf("a refused read was queried: %s", q)
		}
	}
	g = w.gate()
	g.nameserver = netip.Addr{}
	if got := g.ReadRecords(context.Background(), Records{Asset: "domain:example.com", Name: "example.com", Type: "TXT"}); got.Decision != "unavailable:no_resolver" {
		t.Errorf("no resolver: %+v", got)
	}
}

// What the lab's DNS host does (docs/eval/lab-0.0.2-domain.md): an address
// query for an in-zone CNAME whose target does not exist is answered
// NXDOMAIN with no CNAME, and the gate's CNAME query finds the dangling
// record; under compact denial of existence a name that does not exist is
// NOERROR with no record, so the same chain ends in NODATA.
func TestHiddenCNAMEAndCompactDenial(t *testing.T) {
	names := map[string]record{
		"old.example.com":  {cname: "gone.example.com", hidden: true},
		"shop.example.com": {cname: "shops.saas.example", hidden: true},
		"www.example.com":  {addrs: []string{"198.51.100.7"}},
		// Two hops: the provider's DNS host hides its own CNAME.
		"app.example.com":   {cname: "cust.saas.example"},
		"cust.saas.example": {cname: "gone.saas.example", hidden: true},
	}
	for _, tc := range []struct {
		compact       bool
		name, outcome string
		chain         []string
	}{
		{false, "old.example.com", "nxdomain", []string{"gone.example.com"}},
		{true, "old.example.com", "nodata", []string{"gone.example.com"}},
		{false, "shop.example.com", "nxdomain", []string{"shops.saas.example"}},
		{true, "nothere.example.com", "nodata", nil},
		{false, "nothere.example.com", "nxdomain", nil},
		{true, "www.example.com", "addresses", nil},
		{false, "app.example.com", "nxdomain", []string{"cust.saas.example", "gone.saas.example"}},
		{true, "app.example.com", "nodata", []string{"cust.saas.example", "gone.saas.example"}},
	} {
		w := newWorld(t)
		w.zone = newZone(names)
		w.zone.compact = tc.compact
		l := w.gate().lookup(context.Background(), Entry{RequestID: "g1"}, tc.name)
		if string(l.Outcome) != tc.outcome || !slices.Equal(l.Chain, tc.chain) {
			t.Errorf("compact %v %s: %+v", tc.compact, tc.name, l)
		}
		// The name whose CNAME the address queries did not show.
		hiddenAt := tc.name
		if len(tc.chain) > 1 {
			hiddenAt = tc.chain[len(tc.chain)-2]
		}
		cnameAsked := slices.Contains(w.zone.asked(), hiddenAt+"/CNAME")
		if cnameAsked != (tc.outcome != "addresses") {
			t.Errorf("compact %v %s: queries %v", tc.compact, tc.name, w.zone.asked())
		}
	}
}

// An SPF record's include: and redirect= targets, as answered: a qualifier
// is allowed on include only, a macro or a name that is not one is no
// target, and anything but a v=spf1 record has none.
func TestSPFTargets(t *testing.T) {
	for record, want := range map[string][][2]string{
		"v=spf1 include:_spf.google.com ~all":                    {{"include", "_spf.google.com"}},
		"V=SPF1 -Include:A.Example.com. redirect=_spf.b.example": {{"include", "a.example.com"}, {"redirect", "_spf.b.example"}},
		"v=spf1 include:%{d}.spf.example ip4:192.0.2.0/24 -all":  nil,
		"v=spf1 include:not_a..name ~redirect=x.example -all":    nil,
		"v=DMARC1; p=none":          nil,
		"v=spf10 include:x.example": nil,
	} {
		if got := spfTargets(record); !slices.Equal(got, want) {
			t.Errorf("%q: %v", record, got)
		}
	}
}

// The names the company's records point at are looked up by their index in
// an answer this gate gave, as answered and outside the roots, each once;
// an excluded one is refused unasked; an SPF evaluation sends at most ten
// include: or redirect= reads; a target redact_extra matches is followed
// and never printed (docs/spec/scope.md, "Third-party sources").
func TestFollowTargets(t *testing.T) {
	w := newWorld(t)
	w.extra = []string{"zebrafish"}
	names := map[string]record{
		"example.com": {txt: [][]string{{"v=spf1 include:_spf.esp.example include:zebrafish.example -all"}},
			mx: []mxRecord{{10, "mx.mailhost.example"}, {20, "mx.gone-host.example"}, {30, "mx.legacy.example.com"}},
			ns: []string{"ns1.dns-host.example"}},
		"mx.mailhost.example":  {addrs: []string{"198.51.100.25"}},
		"ns1.dns-host.example": {addrs: []string{"198.51.100.53"}},
		"_spf.esp.example":     {txt: [][]string{{"v=spf1 include:spf0.esp.example ~all"}}},
		"zebrafish.example":    {txt: [][]string{{"v=spf1 ip4:192.0.2.1 -all"}}},
	}
	// A chain of includes longer than SPF's limit.
	for i := range 12 {
		names[fmt.Sprintf("spf%d.esp.example", i)] = record{txt: [][]string{{fmt.Sprintf("v=spf1 include:spf%d.esp.example -all", i+1)}}}
	}
	w.zone = newZone(names)
	w.scope.excluded = map[string]string{"domain:legacy.example.com": "exclude[0]"}
	g := w.gate()
	ctx := context.Background()
	asset := "domain:example.com"
	mx := g.ReadRecords(ctx, Records{Asset: asset, Name: "example.com", Type: "MX"})
	if !slices.Equal(mx.Targets, []Target{{"mx.mailhost.example", "mx"}, {"mx.gone-host.example", "mx"}, {"mx.legacy.example.com", "mx"}}) {
		t.Fatalf("MX targets %+v", mx.Targets)
	}
	follow := func(from string, i int) RecordSet {
		return g.FollowTarget(ctx, Follow{Asset: asset, Stage: "recon", From: from, Index: i})
	}
	if r := follow(mx.RequestID, 0); r.Outcome != OutcomeAddresses || len(r.Addrs) != 1 || r.FinalInRoot {
		t.Errorf("MX 0 %+v", r)
	}
	if r := follow(mx.RequestID, 1); r.Outcome != OutcomeNXDomain {
		t.Errorf("a dangling MX %+v", r)
	}
	if r := follow(mx.RequestID, 2); r.Decision != "refused:excluded" {
		t.Errorf("an excluded MX %+v", r)
	}
	for name, f := range map[string]Follow{
		"followed twice":   {Asset: asset, From: mx.RequestID, Index: 0},
		"out of range":     {Asset: asset, From: mx.RequestID, Index: 3},
		"another asset":    {Asset: "domain:example.org", From: mx.RequestID, Index: 1},
		"an invented read": {Asset: asset, From: "g999999", Index: 0},
	} {
		if r := g.FollowTarget(ctx, f); r.Decision != "refused:bind" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	txt := g.ReadRecords(ctx, Records{Asset: asset, Name: "example.com", Type: "TXT"})
	if len(txt.Targets) != 2 || txt.Targets[0] != (Target{"_spf.esp.example", "include"}) ||
		strings.Contains(txt.Targets[1].Name, "zebrafish") || txt.Targets[1].Via != "include" {
		t.Fatalf("TXT targets %+v", txt.Targets)
	}
	if r := follow(txt.RequestID, 1); r.Outcome != OutcomeRecords || len(r.TXT) != 1 {
		t.Errorf("a redacted include %+v", r)
	}
	// The include tree: each read's own targets, until SPF's limit.
	from, sent := txt.RequestID, 1
	for {
		r := follow(from, 0)
		if r.Decision != "sent" {
			if r.Decision != "refused:spf_budget" || sent != maxSPFLookups {
				t.Errorf("after %d reads: %+v", sent, r)
			}
			break
		}
		sent++
		from = r.RequestID
	}
	for _, q := range w.zone.asked() {
		if strings.Contains(q, "legacy") || strings.Contains(q, fmt.Sprintf("spf%d.", maxSPFLookups-2)) {
			t.Errorf("queried %s", q)
		}
	}
	for _, e := range w.audit.entries(t) {
		if strings.Contains(fmt.Sprint(e.Params, e.Answers, e.Detail), "zebrafish") {
			t.Errorf("audit %+v", e)
		}
	}
}

// An SPF evaluation is a domain's: reading its TXT again does not renew
// its lookups; _dmarc and a DKIM selector's TXT point at nothing, whatever
// they hold; and a domain with two SPF records, which SPF calls broken,
// points at nothing either.
func TestSPFEvaluationIsTheDomains(t *testing.T) {
	w := newWorld(t)
	names := map[string]record{
		"example.com":               {txt: [][]string{{"v=spf1 include:i0.esp.example -all"}}},
		"_dmarc.example.com":        {txt: [][]string{{"v=spf1 include:vendor.example -all"}}},
		"s1._domainkey.example.com": {txt: [][]string{{"v=spf1 include:vendor.example -all"}}},
		"two.example.com":           {txt: [][]string{{"v=spf1 include:a.example -all"}, {"v=spf1 include:b.example -all"}}},
	}
	for i := range 12 {
		names[fmt.Sprintf("i%d.esp.example", i)] = record{txt: [][]string{{fmt.Sprintf("v=spf1 include:i%d.esp.example -all", i+1)}}}
	}
	w.zone = newZone(names)
	g := w.gate()
	ctx := context.Background()
	read := func(name string) RecordSet {
		return g.ReadRecords(ctx, Records{Asset: "domain:example.com", Name: name, Type: "TXT"})
	}
	for _, name := range []string{"_dmarc.example.com", "s1._domainkey.example.com", "two.example.com"} {
		if r := read(name); len(r.Targets) != 0 {
			t.Errorf("%s points at %+v", name, r.Targets)
		}
	}
	// Two reads of the domain share one budget of ten.
	sent := 0
	for range 2 {
		from := read("example.com").RequestID
		for {
			r := g.FollowTarget(ctx, Follow{Asset: "domain:example.com", From: from, Index: 0})
			if r.Decision != DecisionSent {
				if r.Decision != "refused:spf_budget" {
					t.Errorf("refused %+v", r)
				}
				break
			}
			sent++
			from = r.RequestID
		}
	}
	if sent != maxSPFLookups {
		t.Errorf("%d include reads across two reads of the domain", sent)
	}
}
