package engagement

import (
	"os"
	"strings"
	"testing"
	"time"

	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
)

func TestQuestionConsumersExist(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range Questions() {
		if q.ID == "" || strings.TrimSpace(q.Prompt) == "" || len(q.Consumers) == 0 {
			t.Errorf("question %q is incomplete", q.ID)
		}
		if seen[q.ID] {
			t.Errorf("question %s is declared twice", q.ID)
		}
		seen[q.ID] = true
		for _, c := range q.Consumers {
			if c.ID == "" || !contains(MergedSlices, c.Slice) {
				t.Errorf("%s consumer %+v is not a merged slice", q.ID, c)
			}
			proveConsumer(t, c.ID)
		}
	}
}

func proveConsumer(t *testing.T, id string) {
	t.Helper()
	switch id {
	case "report.header.trigger", "report.header.operator", "coverage.not_applicable":
		proveReportConsumers(t)
	case "run.directory":
		dir, err := CreateRunDir(t.TempDir(), "acme", time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC))
		if err != nil || !strings.Contains(dir.Path, "engagements/acme/") {
			t.Fatalf("run directory: %v %v", dir, err)
		}
	case "engagement.timezone":
		if _, err := Parse("e.yaml", []byte(minimal), testOpts); err != nil {
			t.Fatal(err)
		}
	case "scope.roots", "scope.exclude":
		res, err := Parse("e.yaml", []byte(minimal+"exclude:\n  - domain: legacy.example.com\n"), testOpts)
		if err != nil || len(res.Roots) == 0 || len(res.Exclude) != 1 {
			t.Fatalf("scope: %v %v", res, err)
		}
	case "github.deploys_to":
		res, err := Parse("e.yaml", []byte(minimal+"assets:\n  shop:\n    repo: github:example-org/shop\n    deploys_to: production\n"), testOpts)
		var to string
		for _, a := range res.Assets {
			if a.Name == "shop" {
				to = a.DeploysTo
			}
		}
		if err != nil || to != "production" {
			t.Fatalf("deploys_to: %v %v", res.Assets, err)
		}
		for _, id := range []string{finding.IDGitHubDefaultBranchUnprotected, finding.IDGitHubRepositoryWorkflowWrite, finding.IDGitHubWritableDeployKey, finding.IDGitHubPRTargetUnsafe} {
			if _, ok := finding.Lookup(id); !ok {
				t.Errorf("finding %s is gone", id)
			}
		}
	case "host.reach", "host.jump":
		res, err := Parse("e.yaml", []byte(minimal+"assets:\n  shop:\n    host: deploy@203.0.113.5\n    jump: ops@198.51.100.7\n"), testOpts)
		var jump string
		for _, a := range res.Assets {
			if a.Name == "shop" {
				jump = a.Jump
			}
		}
		if err != nil || jump != "ops@198.51.100.7" {
			t.Fatalf("jump: %q %v", jump, err)
		}
	case "host.context.exposure":
		def, ok := finding.Lookup(finding.IDPasswordAuthEnabled)
		if !ok {
			t.Fatal("password auth finding is gone")
		}
		f := finding.Finding{ID: def.ID, Category: def.Category, SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity, Status: finding.StatusOpen}
		out, _ := (finding.Grader{Context: &operator.Structured{Exposure: "internet"}, Origins: map[string]string{"exposure": "assets.shop.context.exposure"}}).Grade(f)
		if out.Severity != finding.SevHigh {
			t.Fatalf("exposure did not raise password auth: %s", out.Severity)
		}
	case "host.context.environment":
		def, _ := finding.Lookup(finding.IDPasswordAuthEnabled)
		f := finding.Finding{ID: def.ID, Category: def.Category, SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity, Status: finding.StatusOpen}
		out, _ := (finding.Grader{Context: &operator.Structured{Environment: "dev"}, Origins: map[string]string{"environment": "assets.shop.context.environment"}}).Grade(f)
		if out.Severity != finding.SevLow {
			t.Fatalf("dev did not lower password auth: %s", out.Severity)
		}
	default:
		if _, ok := finding.Lookup(id); !ok {
			t.Errorf("no consumer %s", id)
		}
	}
}

func proveReportConsumers(t *testing.T) {
	t.Helper()
	in := ereport.Input{Name: "acme", Operator: "Dani", Trigger: "incident", NotUsed: []string{"cloud"}, Started: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	rep := ereport.Build(in)
	var b strings.Builder
	if err := ereport.WriteText(&b, rep, ereport.Options{Width: 80}); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	if !strings.Contains(text, "This is not incident response") || !strings.Contains(text, "For Dani") {
		t.Fatalf("header missing trigger or operator:\n%s", text)
	}
	var cloud string
	for _, row := range rep.Coverage {
		if row.Area == "cloud" {
			cloud = row.Mark
		}
	}
	if cloud != "not_applicable" {
		t.Fatalf("not_used cloud mark %q", cloud)
	}
}

func TestBrightcartAnswersBecomeAValidFile(t *testing.T) {
	// Answers are Dani's, from the Brightcart interview. Wrong beliefs stay:
	// the two extra domains send no mail, 2-step is only some accounts, the
	// GitHub organization may not be the company's, and the email spellings
	// were guessed. Incomplete answers are refused rather than invented.
	f := &File{}
	script := []struct{ id, answer string }{
		{"trigger", "an incident"},
		{"name", "brightcart-2026-q4"},
		{"operator", "Dani, IT and operations"},
		{"timezone", "Europe/London"},
		{"roots", "domain: brightcart.co.uk\ndomain: brightcart.com\ndomain: bright-cart.co.uk\nsaas: google-workspace:brightcart.co.uk\nsaas: github:brightcart-dev"},
		{"mail", "domain: brightcart.co.uk\nservice: Google Workspace\n\ndomain: brightcart.co.uk\nservice: Mailchimp\n\ndomain: brightcart.co.uk\nservice: the server, I think\n\nnomail: brightcart.com\nnomail: bright-cart.co.uk"},
		{"people", "handle: dani\nkind: employee\nworkspace: dani@brightcart.co.uk\n\nhandle: sam\nkind: employee\nworkspace: sam@brightcart.co.uk\n\nhandle: leo\nkind: employee\nworkspace: leo@brightcart.co.uk\n\nhandle: bookkeeper\nkind: contractor\norg: freelance, they work for themselves\n\nhandle: agency\nkind: contractor\norg: the web agency that builds the shop"},
		{"admins", "where: google-workspace:brightcart.co.uk\nhandles: dani, sam"},
		{"mfa", "where: google-workspace:brightcart.co.uk\nenforced: some accounts\n\nwhere: github:brightcart-dev\nenforced: I do not know"},
		{"exposed", "url: https://www.brightcart.co.uk\naudience: internet\nreason: the shop, customers buy there\n\nurl: https://brightcart.co.uk\naudience: internet\nreason: I think this is the same shop"},
		{"not_used", "cloud"},
	}
	for _, step := range script {
		if err := Apply(f, step.id, step.answer); err != nil {
			t.Fatalf("%s: %v", step.id, err)
		}
	}
	if err := Apply(f, "left", "handle: dani\nleft: July 2026"); err == nil || !strings.Contains(err.Error(), "YYYY-MM-DD") {
		t.Fatalf("a month without a day should be refused, got %v", err)
	}
	if err := Apply(f, "people", "handle: orders\nkind: I think this is a Google group, not a login"); err == nil {
		t.Fatal("a group described as a login was accepted")
	}
	if err := Apply(f, "not_used", "email"); err == nil || !strings.Contains(err.Error(), "already covered") {
		t.Fatalf("email beside a domain: %v", err)
	}
	if err := Apply(f, "not_used", "identity"); err == nil || !strings.Contains(err.Error(), "cannot be marked") {
		t.Fatalf("identity: %v", err)
	}
	raw, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, FileHeader) || strings.Contains(text, "mailboxes:") || strings.Contains(text, "\nrole:") || strings.Contains(text, "matters_most:") || strings.Contains(text, "secrets:") {
		t.Fatalf("encoded file:\n%s", text)
	}
	res, err := Parse("brightcart.yaml", raw, testOpts)
	if err != nil {
		t.Fatalf("init output does not validate:\n%s\n%v", text, err)
	}
	if res.Engagement.Trigger != "incident" || res.Engagement.Operator != "Dani, IT and operations" {
		t.Fatalf("header %+v", res.Engagement)
	}
	if len(res.Mail.NoMail) != 2 || len(res.Mail.Senders) == 0 || len(res.Mail.Senders[0].DKIMSelectors) != 0 {
		t.Fatalf("mail %+v", res.Mail)
	}
	if res.Access.MFA[0].Enforced != "some" || res.NotUsed[0] != "cloud" {
		t.Fatalf("mfa/not_used %+v %+v", res.Access.MFA, res.NotUsed)
	}
	if len(Explanations(f)) != 2 {
		t.Fatal("workspace explanations were not printed")
	}
}

func TestBrightcartFixtureKeepsTheUnparsedAnswers(t *testing.T) {
	raw, err := os.ReadFile("testdata/init/brightcart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("brightcart.yaml", raw, testOpts); err == nil {
		t.Fatal("Dani's own wording was accepted as an engagement file")
	}
}

func TestCredentialAnswerIsRefused(t *testing.T) {
	f := &File{}
	token := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	err := Apply(f, "operator", "pat "+token)
	if err == nil || !strings.Contains(err.Error(), "detector github-token") || strings.Contains(err.Error(), token) {
		t.Fatalf("got %v", err)
	}
	if f.Engagement.Operator != "" {
		t.Fatal("the credential was kept")
	}
}

func TestMFANoneIsStoredAndABareNoneIsRefused(t *testing.T) {
	f := &File{Roots: []Locator{{SaaS: "google-workspace:example.com"}}, People: map[string]Person{
		"dani": {Kind: "employee", Workspace: []string{"dani@example.com"}},
	}}
	if err := Apply(f, "mfa", "where: google-workspace:example.com\nenforced: none"); err != nil {
		t.Fatal(err)
	}
	if f.Access.MFA[0].Enforced != "none" {
		t.Fatalf("enforced %q", f.Access.MFA[0].Enforced)
	}
	if err := Apply(f, "mfa", "none"); err == nil {
		t.Fatal("a bare none was stored as if it named a tenant")
	}
}

func TestHostRootStillAsksHowToReachIt(t *testing.T) {
	f := &File{Roots: []Locator{{Host: "deploy@203.0.113.5"}}}
	var reach Question
	for _, q := range Questions() {
		if q.ID == "reach" {
			reach = q
		}
	}
	if reach.Answered(f) {
		t.Fatal("a host root with no asset skipped the reach question")
	}
}

func TestAcceptanceNeedsADateWithinAYear(t *testing.T) {
	base := minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n    - {id: sshd.password_auth_enabled, asset: deploy@203.0.113.5, reason: r, accepted_by: alice"
	if _, err := Parse("e.yaml", []byte(base+"}\n"), testOpts); err == nil || !strings.Contains(err.Error(), "date") {
		t.Fatalf("missing date: %v", err)
	}
	if _, err := Parse("e.yaml", []byte(base+", date: 2020-01-01, expires: 2024-01-01}\n"), testOpts); err == nil || !strings.Contains(err.Error(), "365") {
		t.Fatalf("over a year: %v", err)
	}
	// A lapsed acceptance still loads. The report leaves the finding open.
	if _, err := Parse("e.yaml", []byte(base+", date: 2020-01-01, expires: 2020-06-01}\n"), testOpts); err != nil {
		t.Fatal(err)
	}
}

func TestNotUsedRefusesAreasARootCovers(t *testing.T) {
	file := minimal + "not_used: [email, cicd, identity]\n"
	_, err := Parse("e.yaml", []byte(file), testOpts)
	if err == nil {
		t.Fatal("expected refusals")
	}
	msg := err.Error()
	for _, want := range []string{"email is already covered by domain:example.com", "cicd is already covered by saas:github:example-org", "identity cannot be marked not applicable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %s", want, msg)
		}
	}
	if _, err := Parse("e.yaml", []byte(minimal+"not_used: [cloud]\n"), testOpts); err != nil {
		t.Fatal(err)
	}
	hostUnderDomain := `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - domain: example.com
assets:
  web: {host: web.example.com}
not_used: [hosts]
`
	_, err = Parse("e.yaml", []byte(hostUnderDomain), testOpts)
	if err == nil || !strings.Contains(err.Error(), "hosts is already covered by assets.web") {
		t.Fatalf("host asset: %v", err)
	}
}

// A service's audience is never airgapped, and external is never not
// applicable beside a host declared internet-facing: both exit 3 at intake
// (docs/spec/engagement.md, "Exposure vocabulary", "Validation").
func TestServiceAudienceAndExternalNotUsed(t *testing.T) {
	file := `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - host: 203.0.113.5
assets:
  web:
    host: 203.0.113.5
    context:
      exposure: internet
      expected_services:
        - {port: 8080, proto: tcp, audience: airgapped}
not_used: [external]
`
	_, err := Parse("e.yaml", []byte(file), testOpts)
	if err == nil {
		t.Fatal("expected refusals")
	}
	for _, want := range []string{"a service's audience is localhost, lan, vpn or internet; airgapped describes a host",
		"external is marked not applicable, but assets.web.context.exposure declares that host internet-facing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %s", want, err)
		}
	}
}

// The interview refuses the contradiction at the answer, in either order,
// so scheck init never ends with a file intake refuses.
func TestInterviewRefusesExternalBesideAnInternetHost(t *testing.T) {
	f := File{Assets: map[string]Asset{"web": {Host: "203.0.113.5", Context: &HostContext{Exposure: "internet"}}}}
	if err := Apply(&f, "not_used", "external"); err == nil || !strings.Contains(err.Error(), "assets.web.context.exposure declares that host internet-facing") {
		t.Fatalf("not_used after context: %v", err)
	}
	f = File{Assets: map[string]Asset{"web": {Host: "203.0.113.5"}}, NotUsed: []string{"external"}}
	if err := Apply(&f, "context", "name: web\nexposure: internet"); err == nil || !strings.Contains(err.Error(), "not_used: external") {
		t.Fatal("context after not_used accepted")
	}
}
