package web

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
)

// fakeGate answers from fixed record sets and records what was asked.
type fakeGate struct {
	records map[string]gate.RecordSet // "name/TYPE"
	follows map[string]gate.RecordSet // "from/index"
	asked   []string
	n       int
}

func (f *fakeGate) id() string { f.n++; return "g" + strconv.Itoa(f.n) }

func (f *fakeGate) Send(_ context.Context, r gate.Request) gate.Result {
	f.asked = append(f.asked, fmt.Sprintf("%s %s %s", r.Op, r.Params["scheme"], r.Params["host"]))
	return gate.Result{RequestID: f.id(), Decision: gate.DecisionSent, Response: &gate.Response{Status: 200, Body: []byte("<html>")}}
}

func (f *fakeGate) ReadRecords(_ context.Context, r gate.Records) gate.RecordSet {
	key := r.Name + "/" + r.Type
	f.asked = append(f.asked, "read "+key)
	rs, ok := f.records[key]
	if !ok {
		rs = gate.RecordSet{Decision: gate.DecisionSent, Outcome: gate.OutcomeNXDomain}
	}
	rs.RequestID = key
	return rs
}

func (f *fakeGate) FollowTarget(_ context.Context, fl gate.Follow) gate.RecordSet {
	key := fl.From + "/" + strconv.Itoa(fl.Index)
	f.asked = append(f.asked, "follow "+key)
	rs, ok := f.follows[key]
	if !ok {
		rs = gate.RecordSet{Decision: gate.DecisionSent, Outcome: gate.OutcomeNXDomain}
	}
	rs.RequestID = key
	return rs
}

func spf(record string, includes ...string) gate.RecordSet {
	rs := gate.RecordSet{Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{record}}
	for _, inc := range includes {
		rs.Targets = append(rs.Targets, gate.Target{Name: inc, Via: "include"})
	}
	return rs
}

// The collector reads each mail domain's TXT, DMARC, MX and declared DKIM
// selectors, the root's NS, follows every MX and NS target and the SPF
// include tree, and reads the front page of each name Scope chose over
// https and http; nothing else (docs/spec/web-collector.md, "Reads").
func TestCollectReads(t *testing.T) {
	g := &fakeGate{
		records: map[string]gate.RecordSet{
			"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
				TXT:     []string{"v=spf1 include:_spf.esp.example ~all", "site-verification=abc123"},
				Targets: []gate.Target{{Name: "_spf.esp.example", Via: "include"}}},
			"_dmarc.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
				TXT: []string{"v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=50", "not dmarc"}},
			"s1._domainkey.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"v=DKIM1; k=rsa; p=MIGf; n=note"}},
			"example.com/MX": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, MX: []gate.MX{{Pref: 10, Target: "mx.example.net"}},
				Targets: []gate.Target{{Name: "mx.example.net", Via: "mx"}}},
			"example.com/NS": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, NS: []string{"ns1.dns.example"},
				Targets: []gate.Target{{Name: "ns1.dns.example", Via: "ns"}}},
		},
		follows: map[string]gate.RecordSet{"example.com/TXT/0": spf("v=spf1 ip4:192.0.2.0/24 ~all")},
	}
	ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Stage: "recon",
		Mail:  []MailDomain{{Name: "example.com", Selectors: []string{"s1"}}, {Name: "news.example.com"}},
		Names: []string{"example.com", "www.example.com"}})
	want := []string{
		"read example.com/TXT", "follow example.com/TXT/0", "read _dmarc.example.com/TXT", "read example.com/MX",
		"follow example.com/MX/0", "read s1._domainkey.example.com/TXT",
		"read news.example.com/TXT", "read _dmarc.news.example.com/TXT", "read news.example.com/MX",
		"read example.com/NS", "follow example.com/NS/0",
	}
	reads := slices.DeleteFunc(slices.Clone(g.asked), func(s string) bool { return s[:4] == "web." })
	if !slices.Equal(reads, want) {
		t.Errorf("reads\n%q\nwant\n%q", reads, want)
	}
	// One handshake per name: the https read's; https before http.
	webReads := slices.DeleteFunc(slices.Clone(g.asked), func(s string) bool { return s[:4] != "web." })
	if !slices.Equal(webReads, []string{"web.front https example.com", "web.front http example.com",
		"web.front https www.example.com", "web.front http www.example.com"}) {
		t.Errorf("web reads %q", webReads)
	}
	if m := ev.Mail[0]; len(m.SPF) != 1 || !m.SPFComplete || len(m.MXTargets) != 1 || len(m.DKIM) != 1 || m.DKIM[0].Selector != "s1" {
		t.Errorf("mail %+v", m)
	}
	// Only the fields rules read are kept: SPF records, DMARC policy tags
	// and whether a report address is named, DKIM tags.
	m := ev.Mail[0]
	if !slices.Equal(m.TXT.TXT, []string{"v=spf1 include:_spf.esp.example ~all"}) || m.DMARC.TXT != nil ||
		len(m.DMARCRecords) != 1 || !m.DMARCRecords[0].RUA || m.DMARCRecords[0].Tags["p"] != "none" || m.DMARCRecords[0].Tags["pct"] != "50" ||
		m.DMARCRecords[0].Tags["rua"] != "" || m.DKIM[0].Read.TXT != nil || len(m.DKIM[0].Keys) != 1 ||
		m.DKIM[0].Keys[0].Tags["p"] != "MIGf" || m.DKIM[0].Keys[0].Tags["n"] != "" {
		t.Errorf("kept %+v", m)
	}
	if len(ev.NSTargets) != 1 || len(ev.Sites) != 2 || ev.Sites[1].HTTPS.Status != 200 {
		t.Errorf("evidence %+v", ev)
	}
}

// The include tree is read depth first until SPF's limit of lookups: an
// eleventh DNS-querying term stops it, incomplete; more than one SPF record
// is no tree.
func TestCollectSPFLimit(t *testing.T) {
	g := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": spf("v=spf1 a mx include:i0.example -all", "i0.example")},
		follows: map[string]gate.RecordSet{}}
	from := "example.com/TXT"
	for i := range 12 {
		g.follows[from+"/0"] = spf(fmt.Sprintf("v=spf1 include:i%d.example", i+1), fmt.Sprintf("i%d.example", i+1))
		from += "/0"
	}
	ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
	// a, mx and the includes of the root and its first seven reads make
	// ten terms; the eighth read's include is the eleventh, not read.
	if m := ev.Mail[0]; m.SPFComplete || len(m.SPF) != 8 {
		t.Errorf("%d reads, complete %v", len(m.SPF), m.SPFComplete)
	}
	two := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
		TXT: []string{"v=spf1 include:a.example -all", "v=spf1 -all"}, Targets: []gate.Target{{Name: "a.example", Via: "include"}}}}}
	if ev := Collect(context.Background(), two, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}}); len(ev.Mail[0].SPF) != 0 {
		t.Errorf("two SPF records: %+v", ev.Mail[0].SPF)
	}
}

// The tree is complete only when nothing in it is unknown: a failed read
// of the domain or of an include, or an include the gate gave no target
// for (a macro), leaves it incomplete.
func TestCollectSPFUnknowns(t *testing.T) {
	for name, tc := range map[string]struct {
		txt     gate.RecordSet
		follows map[string]gate.RecordSet
	}{
		"the domain's TXT timed out": {gate.RecordSet{Decision: gate.DecisionSent, Outcome: gate.OutcomeTimeout}, nil},
		"an include failed": {spf("v=spf1 include:a.example -all", "a.example"),
			map[string]gate.RecordSet{"example.com/TXT/0": {Decision: gate.DecisionSent, Outcome: gate.OutcomeServFail}}},
		"a macro include": {spf("v=spf1 include:%{d}.spf.example -all"), nil},
	} {
		g := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": tc.txt}, follows: tc.follows}
		ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
		if ev.Mail[0].SPFComplete {
			t.Errorf("%s: complete", name)
		}
	}
}

// Only a record beginning v=DMARC1 is a DMARC record, and a repeated tag
// makes it malformed; only a record with p=, and v=DKIM1 first if it has a
// version, is a DKIM key, any other record there counted, not kept
// (RFC 7489 §6.3, RFC 6376 §3.6.1).
func TestCollectTagRecords(t *testing.T) {
	g := &fakeGate{records: map[string]gate.RecordSet{
		"_dmarc.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{
			"junk; p=reject", "; v=DMARC1; p=reject", "v=dmarc1; p=reject", "v=DMARC1; p=reject; p=none",
			"v=DMARC1;p=quarantine;rua=;", "V = DMARC1; p=none; rua=mailto:x@example.com"}},
		"s1._domainkey.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{
			"hello", "v=DKIM2; p=abc", "k=rsa; v=DKIM1; p=abc", "v=DKIM1; p=abc; p=def", "k=rsa; p=MIGf", "v=DKIM1; k=ed25519; p=xyz"}},
	}}
	ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com",
		Mail: []MailDomain{{Name: "example.com", Selectors: []string{"s1"}}}})
	m := ev.Mail[0]
	if len(m.DMARCRecords) != 3 || !m.DMARCRecords[0].Malformed || m.DMARCRecords[0].Tags != nil ||
		m.DMARCRecords[1].Tags["p"] != "quarantine" || m.DMARCRecords[1].RUA ||
		m.DMARCRecords[2].Tags["p"] != "none" || !m.DMARCRecords[2].RUA {
		t.Errorf("DMARC %+v", m.DMARCRecords)
	}
	k := m.DKIM[0]
	if k.Other != 3 || len(k.Keys) != 3 || !k.Keys[0].Malformed || k.Keys[1].Tags["p"] != "MIGf" || k.Keys[2].Tags["k"] != "ed25519" {
		t.Errorf("DKIM %+v", k)
	}
	// DKIM tag names are case-sensitive, and a part that is not a tag
	// breaks a key; a marked record is counted apart, since it may have
	// been a key or a DMARC record.
	g = &fakeGate{records: map[string]gate.RecordSet{
		"_dmarc.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"v=DMARC1[REDACTED:extra:0:12 bytes]"}},
		"s1._domainkey.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{
			"P=abc", "V=DKIM1; P=abc", "junk; p=abc", "p=a; P=b", "v=DKIM1; [REDACTED:extra:0:9 bytes]"}},
	}}
	ev = Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com",
		Mail: []MailDomain{{Name: "example.com", Selectors: []string{"s1"}}}})
	m, k = ev.Mail[0], ev.Mail[0].DKIM[0]
	if len(m.DMARCRecords) != 0 || m.DMARCMarked != 1 {
		t.Errorf("a marked DMARC record %+v", m)
	}
	if k.Other != 2 || k.Marked != 1 || len(k.Keys) != 2 || !k.Keys[0].Malformed || k.Keys[1].Malformed || k.Keys[1].Tags["P"] != "" {
		t.Errorf("DKIM %+v", k)
	}
}

// A redacted record where the SPF record would be leaves whether there is
// one unknown; a deadline in any read marks the evidence cut.
func TestCollectUnknowns(t *testing.T) {
	g := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
		TXT: []string{"[REDACTED:extra:30 bytes]"}}, "example.com/MX": {Decision: "refused:deadline"}}}
	ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
	if ev.Mail[0].SPFComplete || !ev.Cut() {
		t.Errorf("complete %v, cut %v", ev.Mail[0].SPFComplete, ev.Cut())
	}
	// A record whose marker comes after text no SPF record begins with
	// was never one.
	token := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
		TXT: []string{"v=spf1 -all", "site-verification=[REDACTED:extra:0:9 bytes]"}}}}
	if ev := Collect(context.Background(), token, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}}); !ev.Mail[0].SPFComplete {
		t.Error("a marked verification token made SPF unknown")
	}
	if ev := Collect(context.Background(), &fakeGate{}, Domain{Asset: "domain:example.com", Name: "example.com"}); ev.Cut() {
		t.Error("cut with no deadline")
	}
	// A lookup the deadline ended in flight is cut too.
	inflight := &fakeGate{records: map[string]gate.RecordSet{"example.com/NS": {Decision: gate.DecisionSent, Outcome: gate.OutcomeDeadline}}}
	if ev := Collect(context.Background(), inflight, Domain{Asset: "domain:example.com", Name: "example.com"}); !ev.Cut() {
		t.Error("a lookup ended in flight is not cut")
	}
	// A marked record beside the SPF record leaves the tree unknown.
	beside := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords,
		TXT: []string{"v=spf1 ip4:192.0.2.1 -all", "[REDACTED:extra:0:20 bytes] ip4:192.0.2.2 -all"}}}}
	if ev := Collect(context.Background(), beside, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}}); ev.Mail[0].SPFComplete {
		t.Error("complete beside a marked record")
	}
}

func TestLookups(t *testing.T) {
	for record, want := range map[string]int{
		"v=spf1 -all": 0, "v=spf1 a mx ptr exists:%{i}.x.example include:a.example redirect=b.example": 6,
		"v=spf1 +a/24 -mx:mail.example ~include:c.example ip4:192.0.2.1 ?all": 3, "": 0, "v=spf1 all a:x.example": 0,
	} {
		if got := Lookups(record); got != want {
			t.Errorf("Lookups(%q) = %d; want %d", record, got, want)
		}
	}
}
