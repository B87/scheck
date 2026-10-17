package engagement

import (
	"os"
	"strings"
	"testing"
	"time"

	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/engagement/severity"
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
	case "severity.data_matters_most", "plan.github_tier4":
		proveMattersMost(t, id)
	case "report.rank_tiebreak", "report.matters_most_readout":
		in := ereport.Input{Name: "acme", Started: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC),
			Assets:          []ereport.AssetInput{{Name: "shop", ID: "host:203.0.113.5:22", Kind: "host", Status: "not_collected", Reason: "failed"}},
			DataMattersMost: []string{"host:203.0.113.5:22"},
			MattersMost:     []ereport.MatterInput{{Key: "data.matters_most[0]", Asset: "host:203.0.113.5:22", What: "orders"}}}
		rep := ereport.Build(in)
		if len(rep.Summary.MattersMost) != 1 || rep.Summary.MattersMost[0].Outcome != "not_read" {
			t.Fatalf("readout %+v", rep.Summary.MattersMost)
		}
	default:
		if _, ok := finding.Lookup(id); !ok {
			t.Errorf("no consumer %s", id)
		}
	}
}

// proveMattersMost resolves an answered data.matters_most entry into the
// severity table's declaration and the GitHub selection's tier 4 source.
func proveMattersMost(t *testing.T, id string) {
	t.Helper()
	res, err := Parse("e.yaml", []byte(minimal+"assets:\n  shop:\n    repo: github:example-org/shop\ndata:\n  matters_most:\n    - {what: orders, asset: shop}\n"), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: res, zone: time.UTC}
	switch id {
	case "severity.data_matters_most":
		d := r.declarations()
		if len(d.MattersMost) != 1 || d.MattersMost[0].Asset != "repo:github:example-org/shop" {
			t.Fatalf("declarations %+v", d.MattersMost)
		}
		c := severity.GradeHost(finding.IDPasswordAuthEnabled, finding.SevMedium, "host:203.0.113.5:22",
			severity.Declarations{MattersMost: []severity.Matter{{Asset: "host:203.0.113.5:22", Key: "data.matters_most[0]"}}})
		if c == nil || c.Severity != finding.SevHigh {
			t.Fatalf("host access finding not raised: %+v", c)
		}
	case "plan.github_tier4":
		var org ResolvedAsset
		for _, a := range res.Assets {
			if a.ID == "saas:github:example-org" {
				org = a
			}
		}
		c := r.githubContext(org)
		if len(c.MattersMost) != 1 || c.MattersMost[0].Key != "data.matters_most[0]" {
			t.Fatalf("github context %+v", c.MattersMost)
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

// The data.matters_most question offers hosts, Workspace tenants, GitHub
// organizations, repositories, url sites and cloud roots in that order,
// never a domain or an excluded asset, and writes the asset's name or the
// root as written (docs/spec/engagement.md, "The `data.matters_most`
// question").
func TestMattersMostOffersInGroupOrder(t *testing.T) {
	f := &File{
		Roots: []Locator{{Cloud: "gcp:acme-prod"}, {URL: "https://shop.example.com/"}, {Domain: "example.com"},
			{SaaS: "github:acme"}, {SaaS: "google-workspace:example.com"}, {Host: "deploy@203.0.113.5"}, {URL: "https://old.example.com/"}},
		Exclude: []Locator{{URL: "https://old.example.com/"}},
		Assets: map[string]Asset{
			"shop":      {Locator: Locator{Host: "deploy@203.0.113.5"}},
			"shop-repo": {Locator: Locator{Repo: "github:acme/shop"}, DeploysTo: "production"},
		},
	}
	q, _ := questionByID("matters_most")
	text := q.Text(f)
	want := "  1. shop (host: deploy@203.0.113.5)\n" +
		"  2. saas: google-workspace:example.com\n" +
		"  3. saas: github:acme (GitHub organization: its members and admins)\n" +
		"  4. shop-repo (repo: github:acme/shop)\n" +
		"  5. url: https://shop.example.com/\n" +
		"  6. cloud: gcp:acme-prod\n" +
		"Picking an organization covers its members and admins. To cover a repository's code, pick the repository.\n"
	if !strings.Contains(text, want) || strings.Contains(text, "domain:") || strings.Contains(text, "old.example.com") {
		t.Fatalf("offer:\n%s", text)
	}
	if err := Apply(f, "matters_most", "1: customer orders\n3: who can push code\n4: the shop's code\n6: invoices"); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, d := range f.Data.MattersMost {
		got = append(got, d.Asset+"="+d.What)
	}
	if strings.Join(got, ",") != "shop=customer orders,github:acme=who can push code,shop-repo=the shop's code,gcp:acme-prod=invoices" {
		t.Fatalf("written %v", got)
	}
	if q.Answered(f) == false {
		t.Fatal("an answered matters_most is asked again")
	}
	// Intake refuses an excluded root; the offer only had to skip it.
	f.Roots, f.Exclude = f.Roots[:6], nil
	f.Engagement.Name, f.Engagement.Timezone, f.Engagement.Trigger = "acme", "Europe/Madrid", "routine"
	raw, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("e.yaml", raw, testOpts); err != nil {
		t.Fatalf("written file does not validate: %v\n%s", err, raw)
	}
}

func TestMattersMostRefusesBadLines(t *testing.T) {
	base := func() *File {
		return &File{Roots: []Locator{{Domain: "example.com"}, {SaaS: "github:acme"}, {Host: "deploy@203.0.113.5"}}, Exclude: []Locator{{Repo: "github:acme/secret"}},
			Assets: map[string]Asset{"api": {Locator: Locator{Repo: "github:acme/api"}}}}
	}
	for answer, want := range map[string]string{
		"customer orders":                     "Write each line as a number, a colon and a few words, for example `2: customer orders and invoices`.",
		"two: orders":                         "Write each line as a number, a colon and a few words",
		"2:":                                  "Say in a few words what data number 2 holds, for example `2: customer orders and invoices`.",
		"9: orders":                           "There is no number 9 here; pick from 1 to 3.",
		"example.com: orders":                 "A domain is not offered: pick the site (url) or server that holds the data.",
		"domain: example.com":                 "A domain is not offered",
		"1: a\n1: b":                          "1 is listed twice; give one line per number and put both descriptions on it.",
		"1: " + strings.Repeat("x", 121):      "120 characters",
		"repo: github:other/x: code":          "github:other/x is not under a GitHub organization you listed under roots.",
		"repo: github:acme/api: code":         "github:acme/api is already listed as number 3; pick that number.",
		"repo: github:acme/Bad_Name: code":    "`Bad_Name` cannot be used as a name here.",
		"1: ok\n9: orders":                    "There is no number 9 here",
		"repo: github:acme/secret: card data": "github:acme/secret is excluded (repo:github:acme/secret), so scheck reads nothing in it; it cannot be picked.",
		"repo: github:acme/pay: cards\nrepo: github:acme/pay: refunds": "github:acme/pay is listed twice; give one line per repository and put both descriptions on it.",
		"repo: github:acme/pay:": "Say in a few words what data github:acme/pay holds, for example `repo: github:acme/pay: customer orders and invoices`.",
	} {
		f := base()
		err := Apply(f, "matters_most", answer)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", answer, err, want)
		}
		if len(f.Data.MattersMost) != 0 || len(f.Assets) != 1 {
			t.Errorf("%q: a refused answer wrote %+v %+v", answer, f.Data.MattersMost, f.Assets)
		}
	}
}

// A repository not listed, under a declared organization, becomes an
// assets entry named from its last segment; a name already used is
// refused.
func TestMattersMostRepoLine(t *testing.T) {
	f := &File{Roots: []Locator{{SaaS: "github:acme"}}, Assets: map[string]Asset{"billing": {Locator: Locator{Host: "deploy@203.0.113.5"}}}}
	f.Roots = append(f.Roots, Locator{Host: "deploy@203.0.113.5"})
	if err := Apply(f, "matters_most", "repo: github:acme/billing: invoices"); err == nil || !strings.Contains(err.Error(), "`billing` cannot be used as a name here") {
		t.Fatalf("collision: %v", err)
	}
	if err := Apply(f, "matters_most", "repo: github:acme/payments: card tokens\n2: who pushes"); err != nil {
		t.Fatal(err)
	}
	if f.Assets["payments"].Repo != "github:acme/payments" || f.Data.MattersMost[0].Asset != "payments" || f.Data.MattersMost[1].Asset != "github:acme" {
		t.Fatalf("assets %+v matters %+v", f.Assets, f.Data.MattersMost)
	}
	f.Engagement.Name, f.Engagement.Timezone, f.Engagement.Trigger = "acme", "Europe/Madrid", "routine"
	raw, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("e.yaml", raw, testOpts); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
}

// Nothing offerable (a domain only) skips the question.
func TestMattersMostSkippedWithNothingToOffer(t *testing.T) {
	q, _ := questionByID("matters_most")
	if !q.Answered(&File{Roots: []Locator{{Domain: "example.com"}, {Network: "203.0.113.0/28"}}}) {
		t.Fatal("asked with nothing to offer")
	}
	if q.Answered(&File{Roots: []Locator{{URL: "https://shop.example.com/"}}}) {
		t.Fatal("a url root was not offered")
	}
}

// A service line takes an optional audience as its third word; a host
// may declare several; airgapped is refused; a missing audience is noted.
func TestContextServiceAudience(t *testing.T) {
	f := &File{Assets: map[string]Asset{"web": {Locator: Locator{Host: "203.0.113.5"}}}}
	notes, err := Answer(f, "context", "name: web\nexposure: internet\nservice: 443 tcp internet the shop\nservice: 5432 tcp localhost postgres\nservice: 8080 tcp the admin panel")
	if err != nil {
		t.Fatal(err)
	}
	got := f.Assets["web"].Context.ExpectedServices
	if len(got) != 3 || got[0].Audience != "internet" || got[0].Purpose != "the shop" || got[1].Audience != "localhost" ||
		got[2].Audience != "" || got[2].Purpose != "the admin panel" {
		t.Fatalf("services %+v", got)
	}
	if len(notes) != 1 || notes[0] != "No audience given for 8080/tcp: scheck will check that it is listening, but not whether it listens more widely than it should." {
		t.Fatalf("notes %q", notes)
	}
	f = &File{Assets: map[string]Asset{"web": {Locator: Locator{Host: "203.0.113.5"}}}}
	if _, err := Answer(f, "context", "name: web\nservice: 5432 tcp airgapped db"); err == nil || !strings.Contains(err.Error(), "airgapped describes a host") {
		t.Fatalf("airgapped: %v", err)
	}
}

// The same port twice is refused in the interview, not later by intake
// after every answer is lost, and the refused answer changes nothing, so
// typing it again on one line is taken.
func TestContextServiceDeclaredTwiceIsRefused(t *testing.T) {
	f := &File{Roots: []Locator{{Host: "203.0.113.5"}}, Assets: map[string]Asset{"web": {Locator: Locator{Host: "203.0.113.5"}}}}
	f.Engagement.Name, f.Engagement.Timezone, f.Engagement.Trigger = "acme", "Europe/Madrid", "routine"
	twice := "name: web\nservice: 443 tcp internet the shop\nservice: 22 tcp lan ssh for the office\nservice: 22 tcp vpn ssh for the msp"
	if _, err := Answer(f, "context", twice); err == nil || err.Error() != "22/tcp is declared twice on web; give one service line per port and put both audiences' words on it." {
		t.Fatalf("refusal: %v", err)
	}
	if c := f.Assets["web"].Context; c != nil {
		t.Fatalf("a refused answer changed the file: %+v", c)
	}
	if _, err := Answer(f, "context", "name: web\nservice: 443 tcp internet the shop\nservice: 22 tcp vpn ssh for the office and the msp"); err != nil {
		t.Fatal(err)
	}
	if _, err := Answer(f, "context", "name: web\nservice: 22 tcp lan ssh"); err == nil || !strings.HasPrefix(err.Error(), "22/tcp is declared twice on web;") {
		t.Fatalf("a port already declared by an earlier answer: %v", err)
	}
	if got := f.Assets["web"].Context.ExpectedServices; len(got) != 2 {
		t.Fatalf("a refused answer changed the services: %+v", got)
	}
	out, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("engagement.yaml", out, testOpts); err != nil {
		t.Fatalf("intake refuses what the interview wrote: %v", err)
	}
}

// Dani's answer from the client interview of 2026-10-16, kept as typed: a
// person where an audience goes ("MSP and Leo only") is no audience, so the
// line is kept with the whole rest as its purpose and the note says what
// will not be judged; a guessed database port is taken as declared.
func TestBrightcartServiceAnswerKeepsWhatDaniTyped(t *testing.T) {
	f := &File{Assets: map[string]Asset{"app": {Locator: Locator{Host: "deploy@203.0.113.5"}}}}
	notes, err := Answer(f, "context", "name: app\nexposure: internet\nenvironment: prod\n"+
		"service: 443 tcp internet the shop website\nservice: 80 tcp internet the shop website\n"+
		"service: 22 tcp MSP and Leo only, ssh\nservice: 3306 tcp localhost the shop database i think\n"+
		"service: 25 tcp internet order emails, the shop sends them from the server")
	if err != nil {
		t.Fatal(err)
	}
	got := f.Assets["app"].Context.ExpectedServices
	if len(got) != 5 || got[2].Audience != "" || got[2].Purpose != "MSP and Leo only, ssh" || got[3].Audience != "localhost" {
		t.Fatalf("services %+v", got)
	}
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "No audience given for 22/tcp:") {
		t.Fatalf("notes %q", notes)
	}
	f.Roots = []Locator{{Host: "deploy@203.0.113.5"}, {SaaS: "google-workspace:brightcart.co.uk"}, {SaaS: "github:brightcart-dev"}}
	if err := Apply(f, "matters_most", "1: the shop, customer orders and addresses\n2: staff email, customer service and invoices"); err != nil {
		t.Fatal(err)
	}
	if f.Data.MattersMost[0].Asset != "app" || f.Data.MattersMost[1].Asset != "google-workspace:brightcart.co.uk" {
		t.Fatalf("%+v", f.Data.MattersMost)
	}
}
