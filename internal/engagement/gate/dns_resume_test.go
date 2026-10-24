package gate

import (
	"context"
	"strings"
	"testing"
)

func TestDNSResumeStillAdmitsAndRebuildsFollowups(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{
		"example.com":               {txt: [][]string{{"v=spf1 include:_spf.vendor.example -all"}}},
		"_spf.vendor.example":       {txt: [][]string{{"v=spf1 -all"}}},
		"s1._domainkey.example.com": {cname: "s1.vendor.example"},
		"s1.vendor.example":         {txt: [][]string{{"v=DKIM1; p=MIGf"}}},
	})
	req := Records{Asset: "domain:example.com", Name: "example.com", Type: "TXT"}
	first := w.gate()
	owner := first.ReadRecords(context.Background(), req)
	if f := first.FollowTarget(context.Background(), Follow{Asset: req.Asset, From: owner.RequestID, Index: 0}); f.Decision != DecisionSent {
		t.Fatal(f)
	}
	keyreq := Records{Asset: req.Asset, Name: "s1._domainkey.example.com", Type: "TXT"}
	first.ReadRecords(context.Background(), keyreq)
	w.prior = first.Successes()
	second := w.gate()
	owner = second.ReadRecords(context.Background(), req)
	if owner.Decision != DecisionReused {
		t.Fatal(owner)
	}
	if f := second.FollowTarget(context.Background(), Follow{Asset: req.Asset, From: owner.RequestID, Index: 0}); f.Decision != DecisionReused {
		t.Fatal(f)
	}
	if f := second.FollowTarget(context.Background(), Follow{Asset: req.Asset, From: owner.RequestID, Index: 0}); f.Decision != "refused:bind" {
		t.Fatal(f)
	}
	// Every reused include still consumes this evaluation's live budget.
	third := w.gate()
	owner = third.ReadRecords(context.Background(), req)
	third.spfLookups[req.Asset+" example.com"] = maxSPFLookups
	if f := third.FollowTarget(context.Background(), Follow{Asset: req.Asset, From: owner.RequestID, Index: 0}); f.Decision != "refused:spf_budget" {
		t.Fatal(f)
	}
	w.scope.excluded = map[string]string{"domain:_spf.vendor.example": "exclude[0]", "domain:s1.vendor.example": "exclude[1]"}
	excluded := w.gate()
	if r := excluded.ReadRecords(context.Background(), req); r.Decision == DecisionReused {
		t.Fatal("owner with excluded target reused", r)
	}
	if r := excluded.ReadRecords(context.Background(), keyreq); r.Outcome != OutcomeExcluded || r.Decision == DecisionReused {
		t.Fatal(r)
	}
}

func TestDNSResumeNeverKeepsFailedOrMarkedEvidence(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{"example.com": {txt: [][]string{{"v=spf1 ip4:internal.example.net -all"}}}, "_dmarc.example.com": {rcode: rcodeServFail}})
	g := w.gate()
	g.ReadRecords(context.Background(), Records{Asset: "domain:example.com", Name: "example.com", Type: "TXT"})
	g.ReadRecords(context.Background(), Records{Asset: "domain:example.com", Name: "_dmarc.example.com", Type: "TXT"})
	if len(g.Successes()) != 0 {
		t.Fatal(g.Successes())
	}
}

func TestDNSProjectionPreservesTagStructure(t *testing.T) {
	for _, tc := range []struct{ name, record, want string }{
		{"s._domainkey.example.com", "V=DKIM1; P=MIGf", "unknown_"},
		{"s._domainkey.example.com", ";v=DKIM1;p=MIGf", "other;v=DKIM1;p=MIGf"},
		{"_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:private@example.com", "v=DMARC1;p=reject;rua=present"},
	} {
		got := projectTXT(tc.name, []string{tc.record})
		if len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Fatal(got)
		}
	}
}

func TestDNSResumeReusesSuccessfulAddressFollowups(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{
		"example.com":       {mx: []mxRecord{{10, "mx.vendor.example"}}, ns: []string{"ns.vendor.example"}},
		"mx.vendor.example": {addrs: []string{"198.51.100.25"}},
		"ns.vendor.example": {addrs: []string{"198.51.100.53"}},
	})
	ctx := context.Background()
	first := w.gate()
	for _, typ := range []string{"MX", "NS"} {
		r := first.ReadRecords(ctx, Records{Asset: "domain:example.com", Name: "example.com", Type: typ})
		f := first.FollowTarget(ctx, Follow{Asset: "domain:example.com", From: r.RequestID, Index: 0})
		if f.Outcome != OutcomeAddresses || f.Decision != DecisionSent || len(f.Addrs) != 1 {
			t.Fatal(f)
		}
	}
	w.prior = first.Successes()
	second := w.gate()
	for _, typ := range []string{"MX", "NS"} {
		r := second.ReadRecords(ctx, Records{Asset: "domain:example.com", Name: "example.com", Type: typ})
		f := second.FollowTarget(ctx, Follow{Asset: "domain:example.com", From: r.RequestID, Index: 0})
		if r.Decision != DecisionReused || f.Decision != DecisionReused || f.Outcome != OutcomeAddresses || len(f.Addrs) != 1 {
			t.Fatal(r, f)
		}
	}
}

func TestDNSResumeRegradesTargetRootPlacement(t *testing.T) {
	w := newWorld(t)
	w.zone = newZone(map[string]record{"example.com": {mx: []mxRecord{{10, "mail.vendor.example"}}}})
	ctx := context.Background()
	read := func(g *Gate) RecordSet {
		r := g.ReadRecords(ctx, Records{Asset: "domain:example.com", Name: "example.com", Type: "MX"})
		return g.FollowTarget(ctx, Follow{Asset: "domain:example.com", From: r.RequestID, Index: 0})
	}
	first := w.gate()
	if f := read(first); f.FinalInRoot || f.Outcome != OutcomeNXDomain {
		t.Fatal(f)
	}
	w.prior = first.Successes()
	w.scope.roots = append(w.scope.roots, "domain:vendor.example")
	second := w.gate()
	if f := read(second); !f.FinalInRoot || f.Decision != DecisionReused {
		t.Fatal(f)
	}
	w.prior = second.Successes()
	w.scope.roots = []string{"domain:example.com"}
	if f := read(w.gate()); f.FinalInRoot || f.Decision != DecisionReused {
		t.Fatal(f)
	}
}
