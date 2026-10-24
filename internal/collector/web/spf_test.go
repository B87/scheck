package web

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestSPFOrderedTerms(t *testing.T) {
	for _, tc := range []struct {
		record                  string
		invalid, broad, unknown bool
	}{
		{"v=spf1 all", false, true, false},
		{"v=spf1 +all", false, true, false},
		{"v=spf1 ~all", false, false, false},
		{"v=spf1 -all +all ip4:0.0.0.0/0", false, false, false},
		{"v=spf1 redirect=unread.example -all", false, false, false},
		{"v=spf1 ip4:10.0.0.0/8 -all", false, true, false},
		{"v=spf1 ip4:10.0.0.0/9 -all", false, false, false},
		{"v=spf1 -ip4:0.0.0.0/0 ?all", false, false, false},
		{"v=spf1 ip6:2000::/16 -all", false, true, false},
		{"v=spf1 ~ip6:::/0 -all", false, false, false},
		{"v=spf1 ip4:999.1.1.1 -all", true, false, false},
		{"v=spf1 ip4:192.0.2.1/33 -all", true, false, false},
		{"v=spf1 ip6:192.0.2.1 -all", true, false, false},
		{"v=spf1 a/24//64 mx:mail.example.com//64 -all", false, false, false},
		{"v=spf1 a/33 -all", true, false, false},
		{"v=spf1 a//129 -all", true, false, false},
		{"v=spf1 future:x -all", true, false, false},
		{"v=spf1 future=value -all", false, false, false},
		{"v=spf1 include: -all", true, false, false},
		{"v=spf1 exists:%{i}.spf.example.com -all", false, false, true},
	} {
		t.Run(tc.record, func(t *testing.T) {
			m := mailFixture()
			m.TXT.TXT = []string{tc.record}
			s := inspectSPF(m)
			if (len(s.errors) > 0) != tc.invalid || s.broad != tc.broad || !s.complete != tc.unknown {
				t.Fatalf("%s: %+v", tc.record, s)
			}
		})
	}
}

func TestSPFDependencyEvidence(t *testing.T) {
	child := func(from, name, record string) TargetRead {
		r := sent("records")
		r.RequestID = name
		r.TXT = []string{record}
		return TargetRead{From: from, Name: name, Via: "include", RecordRead: r}
	}
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 include:sendgrid.net -all"}
	m.SPFComplete = false
	in := mailInput(m)
	wantVerdict(t, in, finding.IDEmailSPFInvalid, Abstained)
	wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Abstained)
	m.SPF = []TargetRead{child(m.TXT.RequestID, "sendgrid.net", "v=spf1 +all")}
	m.SPFComplete = true
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Fired)
	for _, qualifier := range []string{"-", "?", "~"} {
		m.TXT.TXT = []string{"v=spf1 " + qualifier + "include:sendgrid.net -all"}
		in.Evidence.Mail = []MailEvidence{m}
		wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Disproved)
		for _, j := range Judge(in) {
			if j.ID == finding.IDEmailSPFUndeclaredSender && j.Verdict == Fired {
				t.Fatalf("negative include: %+v", j)
			}
		}
	}
	m.TXT.TXT = []string{"v=spf1 include:sendgrid.net -all"}
	m.SPF[0].TXT = nil
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFInvalid, Fired)
	m.SPF[0].RecordRead = sent("servfail")
	m.SPFComplete = false
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFInvalid, Abstained)
	m.TXT.TXT = []string{"v=spf1 " + strings.Repeat("a ", 11) + "include:sendgrid.net -all"}
	in.Evidence.Mail = []MailEvidence{m}
	j := wantVerdict(t, in, finding.IDEmailSPFInvalid, Fired)
	if !strings.Contains(j.Excerpt, "at least") || j.Reason == "" {
		t.Fatal(j)
	}
	m.TXT.TXT = []string{"v=spf1 redirect=sendgrid.net"}
	m.SPF = []TargetRead{child(m.TXT.RequestID, "sendgrid.net", "v=spf1 +all")}
	m.SPF[0].Via = "redirect"
	m.SPFComplete = true
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Fired)
	m.SPF[0].SPFMarked = true
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, Abstained)
	// A partial root record count cannot imply SPF absence or a single record.
	m = mailFixture()
	m.TXT.TXT = nil
	m.TXT.SPFMarked = true
	in.Evidence.Mail = []MailEvidence{m}
	wantVerdict(t, in, finding.IDEmailSPFMissing, Abstained)
	wantVerdict(t, in, finding.IDEmailSPFInvalid, Abstained)
	// Three observed void reads are affirmative even without A/MX/exists reads.
	m = mailFixture()
	var terms []string
	for i := range 3 {
		name := fmt.Sprintf("i%d.example.net", i)
		terms = append(terms, "include:"+name)
		r := child(m.TXT.RequestID, name, "")
		r.TXT = nil
		r.Outcome = "nodata"
		m.SPF = append(m.SPF, r)
	}
	m.TXT.TXT = []string{"v=spf1 " + strings.Join(terms, " ") + " -all"}
	in.Evidence.Mail = []MailEvidence{m}
	j = wantVerdict(t, in, finding.IDEmailSPFInvalid, Fired)
	if !strings.Contains(j.Excerpt, "3 void lookups") {
		t.Fatal(j)
	}
}

func TestSPFServiceComparison(t *testing.T) {
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 include:_spf.google.com -all"}
	r := sent("records")
	r.RequestID = "google"
	r.TXT = []string{"v=spf1 include:sendgrid.net -all"}
	sg := sent("records")
	sg.TXT = []string{"v=spf1 ip4:192.0.2.1 -all"}
	m.SPF = []TargetRead{{From: m.TXT.RequestID, Name: "_spf.google.com", Via: "include", RecordRead: r}, {From: "google", Name: "sendgrid.net", Via: "include", RecordRead: sg}}
	in := mailInput(m)
	for _, alias := range []string{"google-workspace", "Google Workspace", "G Suite"} {
		in.MailContext[0].Senders[0].Service = alias
		wantVerdict(t, in, finding.IDEmailSPFUndeclaredSender, Disproved)
		for _, j := range Judge(in) {
			if j.ID == finding.IDEmailSPFUndeclaredSender && j.Verdict == Fired {
				t.Fatalf("provider implementation became another service: %+v", j)
			}
		}
	}
	in.MailContext[0].Senders[0].Service = "not-google-workspace"
	wantVerdict(t, in, finding.IDEmailSPFUndeclaredSender, Fired)
	if _, ok := senderIncludes["evil._spf.google.com"]; ok {
		t.Fatal("non-exact provider mapping")
	}
	in.MailContext = nil
	wantVerdict(t, in, finding.IDEmailSPFUndeclaredSender, Abstained)
	m.TXT.TXT = []string{"v=spf1 include:unknown.example.com ip4:192.0.2.1 -all"}
	m.SPF = nil
	in = mailInput(m)
	if !slices.ContainsFunc(MailNotes(in), func(n MailNote) bool { return strings.Contains(n.Detail, "ip4:192.0.2.1") }) {
		t.Fatal("unmapped terms not listed")
	}
}

func TestSPFCollectSkipsUnreachableTargetsAndKeepsMarkedCounts(t *testing.T) {
	for _, record := range []string{"v=spf1 -all include:unread.example", "v=spf1 redirect=unread.example -all"} {
		g := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": spf(record, "unread.example")}}
		if strings.Contains(record, "redirect=") {
			r := g.records["example.com/TXT"]
			r.Targets[0].Via = "redirect"
			g.records["example.com/TXT"] = r
		}
		ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
		if len(ev.Mail[0].SPF) != 0 || !ev.Mail[0].SPFComplete {
			t.Fatalf("unreachable read: %+v", ev.Mail[0])
		}
	}
	g := &fakeGate{records: map[string]gate.RecordSet{"example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"[REDACTED:extra:0:6 bytes] -all"}}}}
	ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
	if !ev.Mail[0].TXT.SPFMarked || len(ev.Mail[0].TXT.TXT) != 0 {
		t.Fatalf("lost marked count: %+v", ev.Mail[0])
	}
	wantVerdict(t, mailInput(ev.Mail[0]), finding.IDEmailSPFMissing, Abstained)
}

func TestSPFDoesNotAuthorizeAfterErrorsOrTerminalIncludes(t *testing.T) {
	for _, tc := range []struct {
		root, child string
		outcome     string
		want        string
	}{
		{"v=spf1 include:child.example +all", "", "nxdomain", Abstained},
		{"v=spf1 include:child.example +all", "", "servfail", Abstained},
		{"v=spf1 -include:child.example +all", "v=spf1 +all", "records", Disproved},
		{"v=spf1 include:child.example -all", "v=spf1 -all", "records", Disproved},
		{"v=spf1 ip4:0.0.0.0/0 include:child.example -all", "", "servfail", Fired},
	} {
		t.Run(tc.root+tc.outcome+tc.child, func(t *testing.T) {
			m := mailFixture()
			m.TXT.TXT = []string{tc.root}
			r := sent(tc.outcome)
			r.TXT = spfOnly([]string{tc.child})
			m.SPF = []TargetRead{{From: m.TXT.RequestID, Name: "child.example", Via: "include", RecordRead: r}}
			in := mailInput(m)
			wantVerdict(t, in, finding.IDEmailSPFPermitsAnyone, tc.want)
			if tc.child == "v=spf1 -all" {
				in.MailContext = nil
				wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Fired)
				if inspectSPF(m).authorizes {
					t.Fatal("deny-only include classified as sending")
				}
			}
		})
	}
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 -all totallybogus"}
	wantVerdict(t, mailInput(m), finding.IDEmailSPFInvalid, Fired)
}

func TestSPFEarlierDenialsLeaveLaterGrantsUncertain(t *testing.T) {
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 -ip4:10.0.0.0/8 ip4:10.0.0.0/8 -all"}
	wantVerdict(t, mailInput(m), finding.IDEmailSPFPermitsAnyone, Abstained)
	in := mailInput(m)
	in.MailContext = nil
	wantVerdict(t, in, finding.IDEmailNoMailSpoofable, Abstained)
	m.TXT.TXT = []string{"v=spf1 -include:child.example include:child.example -all"}
	r := sent("records")
	r.RequestID = "child"
	r.TXT = []string{"v=spf1 ip4:10.0.0.0/8 -all"}
	m.SPF = []TargetRead{{From: m.TXT.RequestID, Name: "child.example", Via: "include", RecordRead: r}, {From: m.TXT.RequestID, Name: "child.example", Via: "include", RecordRead: r}}
	wantVerdict(t, mailInput(m), finding.IDEmailSPFPermitsAnyone, Abstained)
	for _, record := range []string{"v=spf1 -all redirect=@@@", "v=spf1 -all exp=@@@", "v=spf1 a: -all", "v=spf1 all:"} {
		m := mailFixture()
		m.TXT.TXT = []string{record}
		wantVerdict(t, mailInput(m), finding.IDEmailSPFInvalid, Fired)
	}
}

func TestSPFNegativeIncludePropagatesUncertainChild(t *testing.T) {
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 -include:x.example ip4:10.0.0.0/8 -all"}
	r := sent("records")
	r.RequestID = "x"
	r.TXT = []string{"v=spf1 -ip4:192.0.2.0/24 ip4:10.0.0.0/8 -all"}
	m.SPF = []TargetRead{{From: m.TXT.RequestID, Name: "x.example", Via: "include", RecordRead: r}}
	wantVerdict(t, mailInput(m), finding.IDEmailSPFPermitsAnyone, Abstained)
}

func TestSPFVersionSelectionAtCollection(t *testing.T) {
	for record, valid := range map[string]bool{"v=spf1 -all": true, "V=SpF1 -all": true, " v=spf1 -all": false, "\tv=spf1 -all": false, "v=spf1\t-all": false, "v=spf1\n-all": false, "v=spf1\u00a0-all": false, "v=spf10 -all": false} {
		t.Run(record, func(t *testing.T) {
			g := &fakeGate{records: map[string]gate.RecordSet{
				"example.com/TXT":        {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{record}},
				"_dmarc.example.com/TXT": {Decision: gate.DecisionSent, Outcome: gate.OutcomeRecords, TXT: []string{"v=DMARC1; p=reject"}},
			}}
			ev := Collect(context.Background(), g, Domain{Asset: "domain:example.com", Name: "example.com", Mail: []MailDomain{{Name: "example.com"}}})
			m := ev.Mail[0]
			if (len(m.TXT.TXT) == 1) != valid {
				t.Fatalf("selection %q: %+v", record, m.TXT)
			}
			in := mailInput(m)
			in.MailContext = []MailContext{{Domain: m.Domain, NoMail: true}}
			want := Fired
			if valid {
				want = Disproved
			}
			wantVerdict(t, in, finding.IDEmailNoMailSpoofable, want)
		})
	}
}

func TestSPFIncludeSubjectsCanonicalizeAndDeduplicate(t *testing.T) {
	m := mailFixture()
	m.TXT.TXT = []string{"v=spf1 include:sendgrid.net include:SENDGRID.NET. -all"}
	r := sent("records")
	r.RequestID = "sg"
	r.TXT = []string{"v=spf1 ip4:192.0.2.1 -all"}
	m.SPF = []TargetRead{{From: m.TXT.RequestID, Name: "sendgrid.net", Via: "include", RecordRead: r}, {From: m.TXT.RequestID, Name: "sendgrid.net", Via: "include", RecordRead: r}}
	count := 0
	for _, j := range Judge(mailInput(m)) {
		if j.ID == finding.IDEmailSPFUndeclaredSender && j.Verdict == Fired {
			count++
			if j.Subject.Key != "example.com/include:sendgrid.net" {
				t.Fatal(j)
			}
		}
	}
	if count != 1 {
		t.Fatalf("equivalent targets produced %d findings", count)
	}
}
