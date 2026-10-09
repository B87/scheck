package web

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func mailFixture() MailEvidence {
	txt := sent("records")
	txt.RequestID = "spf-root"
	txt.TXT = []string{"v=spf1 ip4:192.0.2.1 -all"}
	dmarc := sent("records")
	dmarc.RequestID = "dmarc-root"
	return MailEvidence{Domain: "example.com", TXT: txt, DMARC: dmarc, DMARCRecords: []DMARC{{Tags: map[string]string{"v": "DMARC1", "p": "reject"}}}, MX: sent("nodata"), SPFComplete: true}
}
func mailInput(m MailEvidence) Input {
	return Input{Root: "example.com", Asset: "domain:example.com", MailContext: []MailContext{{Domain: m.Domain, Senders: []MailSender{{Service: "google-workspace", Selectors: []string{"google"}}}}}, Evidence: Evidence{Mail: []MailEvidence{m}, NS: sent("nodata")}}
}
func keyFixture(bits int) DKIMKey {
	// Synthetic public modulus only: no private key, randomness or network.
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(31))
	der, _ := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	return DKIMKey{Tags: map[string]string{"p": base64.StdEncoding.EncodeToString(der)}}
}
func selector(k DKIMKey) SelectorRead {
	return SelectorRead{Selector: "google", Read: sent("records"), Keys: []DKIMKey{k}}
}
func emailJudgment(t *testing.T, in Input, id, key string) Judgment {
	t.Helper()
	for _, j := range Judge(in) {
		if j.ID == id && (key == "" || j.Subject.Key == key) {
			return j
		}
	}
	t.Fatalf("missing %s on %s", id, key)
	return Judgment{}
}
func wantVerdict(t *testing.T, in Input, id, want string) Judgment {
	t.Helper()
	j := emailJudgment(t, in, id, "")
	if j.Verdict != want {
		t.Fatalf("%s = %+v, want %s", id, j, want)
	}
	return j
}

// emailOutcomes joins the catalog-wide invariant: all three independently
// asserted outcomes for every email rule, not just a count of returned values.
func emailOutcomes(t *testing.T) []Judgment {
	t.Helper()
	var out []Judgment
	for _, id := range finding.WebIDs() {
		if !strings.HasPrefix(id, "email.") {
			continue
		}
		for _, want := range []string{Fired, Disproved, Abstained} {
			m := mailFixture()
			in := mailInput(m)
			switch id {
			case finding.IDEmailDMARCNotEnforced:
				if want == Fired {
					m.DMARCRecords = nil
				}
			case finding.IDEmailDMARCPartial:
				if want == Fired {
					m.DMARCRecords[0].Tags["pct"] = "25"
				}
			case finding.IDEmailDMARCSubdomainsOpen:
				if want == Fired {
					m.DMARCRecords[0].Tags["sp"] = "none"
				}
			case finding.IDEmailNoMailSpoofable:
				in.MailContext = []MailContext{{Domain: m.Domain, NoMail: true}}
				if want == Disproved {
					m.TXT.TXT = []string{"v=spf1 -all"}
				}
			case finding.IDEmailSPFMissing:
				if want == Fired {
					m.TXT.TXT = nil
					m.TXT.Outcome = "nodata"
				}
			case finding.IDEmailSPFInvalid:
				if want == Fired {
					m.TXT.TXT = []string{"v=spf1 -all", "v=spf1 ~all"}
				}
			case finding.IDEmailSPFPermitsAnyone:
				if want == Fired {
					m.TXT.TXT = []string{"v=spf1 +all"}
				}
			case finding.IDEmailSPFUndeclaredSender:
				m.TXT.TXT = []string{"v=spf1 include:sendgrid.net -all"}
				r := sent("records")
				r.TXT = []string{"v=spf1 ip4:192.0.2.1 -all"}
				r.RequestID = "spf-sg"
				m.SPF = []TargetRead{{Owner: m.Domain, From: m.TXT.RequestID, Name: "sendgrid.net", Via: "include", RecordRead: r}}
				if want == Disproved {
					in.MailContext[0].Senders[0].Service = "Twilio SendGrid"
				}
			case finding.IDEmailDKIMMissing:
				m.DKIM = []SelectorRead{selector(keyFixture(2048))}
				if want == Fired {
					m.DKIM[0].Keys = nil
					m.DKIM[0].Read.Outcome = "nxdomain"
				}
			case finding.IDEmailDKIMKeyBreakable:
				bits := 2048
				if want == Fired {
					bits = 512
				}
				m.DKIM = []SelectorRead{selector(keyFixture(bits))}
			case finding.IDEmailDKIMKey1024:
				bits := 2048
				if want == Fired {
					bits = 1024
				}
				m.DKIM = []SelectorRead{selector(keyFixture(bits))}
			}
			if want == Abstained {
				m.TXT = sent("servfail")
				m.DMARC = sent("servfail")
				m.SPFComplete = false
				m.DKIM = []SelectorRead{{Selector: "google", Read: sent("servfail")}}
			}
			in.Evidence.Mail = []MailEvidence{m}
			j := wantVerdict(t, in, id, want)
			if j.Asset != in.Asset || j.Subject.Kind != string(finding.SubjectOf(id)) {
				t.Fatalf("subject/asset of %s: %+v", id, j)
			}
			if want == Abstained && j.Reason == "" {
				t.Fatalf("no abstention reason for %s", id)
			}
			out = append(out, j)
		}
	}
	return out
}
func TestEmailOutcomes(t *testing.T) { emailOutcomes(t) }

func TestDMARCPolicyStates(t *testing.T) {
	for _, tc := range []struct {
		name              string
		tags              map[string]string
		not, partial, sub string
	}{
		{"none", map[string]string{"p": "none"}, Fired, "", ""},
		{"missing policy", map[string]string{}, Fired, "", ""},
		{"invalid policy", map[string]string{"p": "bogus"}, Fired, "", ""},
		{"zero", map[string]string{"p": "reject", "pct": "0"}, Fired, "", ""},
		{"testing", map[string]string{"p": "reject", "t": "y"}, Fired, "", ""},
		{"partial", map[string]string{"p": "reject", "pct": "1"}, Disproved, Fired, Disproved},
		{"full", map[string]string{"p": "REJECT", "pct": "100", "t": "n"}, Disproved, Disproved, Disproved},
		{"bad percentage", map[string]string{"p": "reject", "pct": "101"}, Abstained, Abstained, Abstained},
		{"signed percentage", map[string]string{"p": "reject", "pct": "+1"}, Abstained, Abstained, Abstained},
		{"overlong percentage", map[string]string{"p": "reject", "pct": "0001"}, Abstained, Abstained, Abstained},
		{"bad testing", map[string]string{"p": "reject", "t": "unknown"}, Abstained, Abstained, Abstained},
		{"np", map[string]string{"p": "reject", "np": "none"}, Disproved, Disproved, Fired},
		{"bad sp", map[string]string{"p": "reject", "sp": "bogus"}, Disproved, Disproved, Abstained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mailFixture()
			m.DMARCRecords[0].Tags = tc.tags
			in := mailInput(m)
			for id, want := range map[string]string{finding.IDEmailDMARCNotEnforced: tc.not, finding.IDEmailDMARCPartial: tc.partial, finding.IDEmailDMARCSubdomainsOpen: tc.sub} {
				if want != "" {
					wantVerdict(t, in, id, want)
				} else {
					for _, j := range Judge(in) {
						if j.ID == id {
							t.Fatalf("unexpected applicable rule: %+v", j)
						}
					}
				}
			}
			if tc.name == "testing" || tc.name == "zero" {
				if !strings.Contains(emailJudgment(t, in, finding.IDEmailDMARCNotEnforced, "").Excerpt, "quarantine") {
					t.Fatal("missing downgrade wording")
				}
			}
		})
	}
	for _, change := range []func(*MailEvidence){
		func(m *MailEvidence) { m.DMARCMarked = 1 },
		func(m *MailEvidence) { m.DMARCRecords[0].Tags["p"] = "[REDACTED:extra:0:6 bytes]" },
	} {
		m := mailFixture()
		change(&m)
		wantVerdict(t, mailInput(m), finding.IDEmailDMARCNotEnforced, Abstained)
	}
	m := mailFixture()
	m.DMARCRecords = append(m.DMARCRecords, m.DMARCRecords[0])
	wantVerdict(t, mailInput(m), finding.IDEmailDMARCNotEnforced, Fired)
}

func TestDMARCInheritanceAndSuffixSnapshot(t *testing.T) {
	for name, want := range map[string]string{"example.com": "example.com", "mail.example.co.uk": "example.co.uk", "co.uk": "", "a.b.ck": "a.b.ck", "www.ck": "www.ck", "a.www.ck": "www.ck", "user.github.io": "user.github.io", "sub.example.unknownsuffix": "", "a.xn--55qx5d.cn": "a.xn--55qx5d.cn"} {
		if got := organizationalDomain(name); got != want {
			t.Errorf("org(%s)=%s want %s", name, got, want)
		}
	}
	data, _ := suffixData.ReadFile("data/public_suffix_list.dat")
	if !strings.Contains(string(data), "COMMIT: "+PublicSuffixVersion) {
		t.Fatal("unpinned PSL")
	}
	m := mailFixture()
	m.Domain = "mail.example.com"
	m.DMARCRecords = nil
	m.DMARC.Outcome = "nodata"
	in := mailInput(m)
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Abstained)
	parent := mailFixture()
	parent.DMARC.RequestID = "parent-policy"
	parent.DMARCRecords[0].Tags["sp"] = "reject"
	in.MailPolicies = []MailEvidence{parent}
	j := wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Disproved)
	if !slices.Contains(j.Reads, "parent-policy") || !slices.Contains(j.Reads, "dmarc-root") {
		t.Fatalf("lost inherited attribution: %+v", j)
	}
	wantVerdict(t, in, finding.IDEmailDMARCSubdomainsOpen, Abstained)
	parent.DMARCRecords[0].Tags["sp"] = "none"
	in.MailPolicies = []MailEvidence{parent}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Fired)
	m.DMARCRecords = []DMARC{{Tags: map[string]string{"p": "reject"}}}
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Disproved)
}

func TestMailUseAndNoMail(t *testing.T) {
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 -all"}
	m.MX.MX = []gate.MX{{Target: ".", Pref: 0}}
	in := mailInput(m)
	in.MailContext = nil
	wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Disproved)
	if !strings.Contains(MailNotes(in)[0].Detail, "shows no signs") {
		t.Fatal(MailNotes(in))
	}
	m.MX.MX = []gate.MX{{Target: "mx.example.com"}}
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Disproved)
	m.MX = sent("servfail")
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Abstained)
	in.MailContext = []MailContext{{Domain: m.Domain, NoMail: true}}
	m.DMARC = sent("servfail")
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Abstained)
	m.TXT.TXT = []string{"v=spf1 +all"}
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Fired)
	wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Fired)
	if !slices.ContainsFunc(MailNotes(in), func(n MailNote) bool { return strings.Contains(n.Detail, "Declared no mail, but") }) {
		t.Fatal("missing contradiction note")
	}
	in.Doubt = "unavailable:resolver_rewrites"
	for _, j := range Judge(in) {
		if strings.HasPrefix(j.ID, "email.") && (j.Verdict != Abstained || j.Reason != in.Doubt) {
			t.Fatal(j)
		}
	}
}

func TestDKIMRecognition(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		k                    DKIMKey
		missing, weak, small string
	}{
		{"rsa512", keyFixture(512), Disproved, Fired, Disproved},
		{"rsa1024", keyFixture(1024), Disproved, Disproved, Fired},
		{"rsa2048", keyFixture(2048), Disproved, Disproved, Disproved},
		{"ed25519", DKIMKey{Tags: map[string]string{"k": "ed25519", "p": base64.StdEncoding.EncodeToString(make([]byte, 32))}}, Disproved, Disproved, Disproved},
		{"short ed25519", DKIMKey{Tags: map[string]string{"k": "ed25519", "p": "AAAA"}}, Abstained, Abstained, Abstained},
		{"revoked", DKIMKey{Tags: map[string]string{"p": ""}}, Fired, Abstained, Abstained},
		{"invalid DER", DKIMKey{Tags: map[string]string{"p": "AAAA"}}, Abstained, Abstained, Abstained},
		{"bad base64", DKIMKey{Tags: map[string]string{"p": "bad@@"}}, Abstained, Abstained, Abstained},
		{"unsupported", DKIMKey{Tags: map[string]string{"k": "future", "p": "AAAA"}}, Abstained, Abstained, Abstained},
		{"malformed", DKIMKey{Malformed: true}, Abstained, Abstained, Abstained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mailFixture()
			m.DKIM = []SelectorRead{selector(tc.k)}
			in := mailInput(m)
			wantVerdict(t, in, finding.IDEmailDKIMMissing, tc.missing)
			wantVerdict(t, in, finding.IDEmailDKIMKeyBreakable, tc.weak)
			wantVerdict(t, in, finding.IDEmailDKIMKey1024, tc.small)
		})
	}
	for _, tc := range []SelectorRead{
		{Selector: "google", Read: sent("records"), Marked: 1},
		{Selector: "google", Read: sent("records"), Keys: []DKIMKey{keyFixture(512), keyFixture(2048)}},
	} {
		m := mailFixture()
		m.DKIM = []SelectorRead{tc}
		wantVerdict(t, mailInput(m), finding.IDEmailDKIMMissing, Abstained)
	}
	m := mailFixture()
	in := mailInput(m)
	in.MailContext[0].Senders[0].Selectors = nil
	j := wantVerdict(t, in, finding.IDEmailDKIMMissing, Abstained)
	if j.Reason != "unavailable:dkim_selector" || !strings.Contains(j.Subject.Label, "no selector given") {
		t.Fatal(j)
	}
}

func TestInheritedDMARCNonexistentPolicy(t *testing.T) {
	m := mailFixture()
	m.Domain = "unused.example.com"
	m.DMARCRecords = nil
	m.DMARC.Outcome = "nxdomain"
	m.TXT = sent("nxdomain")
	m.MX = sent("nxdomain")
	parent := mailFixture()
	parent.DMARCRecords[0].Tags["sp"] = "reject"
	parent.DMARCRecords[0].Tags["np"] = "none"
	in := mailInput(m)
	in.MailPolicies = []MailEvidence{parent}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Fired)
	m.TXT = sent("servfail")
	m.MX = sent("servfail")
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Abstained)
	m.MX = sent("nodata")
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailDMARCNotEnforced, Disproved)
}

// A discarded tag name/fragment can hide pct, t or another relevant field.
// Persisted reduced evidence must retain that uncertainty before any judgment.
func TestCollectedMailPreservesMarkersBeforeReducingTags(t *testing.T) {
	for _, fragment := range []string{"[REDACTED:extra:0:5 bytes]", "unknown=[REDACTED:extra:0:5 bytes]", "p[REDACTED:extra:0:3 bytes]=none"} {
		g := &fakeGate{records: map[string]gate.RecordSet{
			"example.com/TXT":                   spf("v=spf1 -all"),
			"_dmarc.example.com/TXT":            {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"v=DMARC1; p=reject; " + fragment}},
			"google._domainkey.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"v=DKIM1; p=" + keyFixture(512).Tags["p"] + "; " + fragment}},
		}}
		ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com", Selectors: []string{"google"}}}})
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var saved Evidence
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		m := saved.Mail[0]
		if m.DMARCMarked != 1 || m.DKIM[0].Marked != 1 {
			t.Fatalf("lost marked capture: %+v", m)
		}
		in := mailInput(m)
		for _, id := range []string{finding.IDEmailDMARCNotEnforced, finding.IDEmailDKIMMissing, finding.IDEmailDKIMKeyBreakable} {
			j := wantVerdict(t, in, id, Abstained)
			if j.Reason != "unavailable:redacted" {
				t.Fatal(j)
			}
		}
	}
}

func TestEmailUncollectedReadsNeverBecomeAbsence(t *testing.T) {
	m := MailEvidence{Domain: "example.com"}
	in := mailInput(m) // A declared selector has no read at all.
	for _, j := range Judge(in) {
		if strings.HasPrefix(j.ID, "email.") && (j.Verdict != Abstained || j.Reason == "") {
			t.Fatalf("uncollected evidence became a judgment: %+v", j)
		}
	}
	in.MailContext = []MailContext{{Domain: m.Domain, NoMail: true}}
	wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Abstained)
}

func TestMarkedDMARCVersionUsesTagWhitespace(t *testing.T) {
	for _, prefix := range []string{"\tv=DMARC", " \tv \t= \tDMARC", "\r\nv=DMARC", "\tv"} {
		for _, marker := range []string{"[REDACTED:extra:0:1 bytes]", "[TRUNCATED:1 bytes]"} {
			g := &fakeGate{records: map[string]gate.RecordSet{"_dmarc.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{prefix + marker + "; p=reject"}}}}
			ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
			if ev.Mail[0].DMARCMarked != 1 {
				t.Fatalf("lost marker in %q: %+v", prefix+marker, ev.Mail[0])
			}
			wantVerdict(t, mailInput(ev.Mail[0]), finding.IDEmailDMARCNotEnforced, Abstained)
		}
	}
	// Whitespace cannot make an SPF version possible where the selector
	// itself rejects it: the two protocols have different grammars.
	if couldBe(" v=spf[REDACTED:extra:0:1 bytes] -all", "v=spf1") || !couldBe("v=spf[REDACTED:extra:0:1 bytes] -all", "v=spf1") {
		t.Fatal("SPF prefix grammar changed")
	}
}
