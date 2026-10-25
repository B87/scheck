package compare

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/internal/engagement/report"
	hostreport "github.com/b87/scheck/internal/report"
)

var update = flag.Bool("update", false, "rewrite the lab reports and the golden comparisons")

// labRuns builds two runs of one engagement three weeks apart, with one of
// everything a re-test has to tell apart. A real lab pair replaces it when
// the lab exists (docs/ROADMAP.md, G7); until then this is the committed
// pair the goldens are pinned on.
func labRuns() (e, l *lab) {
	e = newLab("0.0.3", time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
	l = newLab("0.0.3", time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC))
	for _, r := range []*lab{e, l} {
		r.Engagement.Operator = new("alice")
		r.Run.Command = "scheck run /work/acme.yaml"
		r.asset("host:203.0.113.6:22", "web", "host", "collected", "M-web")
		r.asset("saas:google-workspace:example.com", "workspace", "saas", "collected", "C-acme")
		r.principal("saas:google-workspace:example.com", "admin@example.com")
		r.asset("repo:github:example-org/api", "api", "repo", "collected", "")
	}
	e.asset("host:203.0.113.5:22", "deploy", "host", "collected", "M-deploy")
	l.asset("host:203.0.113.9:22", "deploy", "host", "collected", "M-deploy")
	e.asset("host:203.0.113.20:22", "db1", "host", "collected", "M-image")
	e.asset("host:203.0.113.21:22", "db2", "host", "collected", "M-image")
	l.asset("host:203.0.113.22:22", "db1", "host", "collected", "M-image")
	l.asset("host:203.0.113.21:22", "db2", "host", "collected", "M-image")
	e.asset("repo:github:example-org/shop", "shop", "repo", "collected", "")
	shop := l.asset("repo:github:example-org/shop", "shop", "repo", "failed", "")
	shop.Reason, shop.Detail = "insufficient_permission:contents", "the token cannot read this repository"
	e.Engagement.Source.Path, l.Engagement.Source.Path = new("/work/acme.yaml"), new("/work/acme.yaml")
	l.Exit.Code = 1
	l.Engagement.Source.SHA256 = "bbbb"

	const (
		deployE = "host:203.0.113.5:22"
		deployL = "host:203.0.113.9:22"
		web     = "host:203.0.113.6:22"
		ws      = "saas:google-workspace:example.com"
		api     = "repo:github:example-org/api"
		shopID  = "repo:github:example-org/shop"
	)
	title := func(f *report.Finding, t string) *report.Finding { f.Title = t; return f }
	area := func(f *report.Finding, a string) *report.Finding { f.Area = a; return f }

	// Moved with its host: still open.
	title(e.find("sshd.password_auth_enabled", deployE, "", "high"), "SSH accepts passwords")
	title(l.find("sshd.password_auth_enabled", deployL, "", "high"), "SSH accepts passwords")
	// Fixed: the firewall rule decided on a complete read and found nothing.
	title(e.find("fw.no_firewall_active", web, "", "medium"), "The firewall allows inbound traffic by default")
	l.notMatched("fw.no_firewall_active", web)
	// Fixed, low: counted at default verbosity.
	title(e.find("updates.pending", web, "", "low"), "Package updates are pending")
	l.notMatched("updates.pending", web)
	// Not confirmed: an identity finding reads declarations (who is a person
	// or a service account), and the engagement file changed between the runs.
	title(area(e.find("identity.unattributed_admin", ws, "bob@example.com", "high"), "identity"), "A Workspace account has no 2-step verification")
	// Renamed: the same account by provider id.
	ea := title(area(e.find("identity.unattributed_admin", ws, "alice@example.com", "high"), "identity"), "A Workspace account has no 2-step verification")
	ea.Subject.ProviderID = "u-41"
	la := title(area(l.find("identity.unattributed_admin", ws, "alice.smith@example.com", "high"), "identity"), "A Workspace account has no 2-step verification")
	la.Subject.ProviderID = "u-41"
	l.rule("identity.unattributed_admin", ws, "matched", false)
	// Not re-checked: the repository could not be read this time.
	title(area(e.find("github.history_credential", shopID, "aws:AKIA@0a1b2c3d4e5f", "high"), "secrets"), "A credential is in the repository's history")
	// Fixed in the secrets area: the caveat about revocation stays.
	title(area(e.find("github.history_credential", api, "aws:AKIA@9f8e7d6c5b4a", "high"), "secrets"), "A credential is in the repository's history")
	l.notMatched("github.history_credential", api)
	// Two hosts of one image: no identity, so one is not re-checked and
	// the other is reported for the first time.
	title(e.find("sshd.root_login_enabled", "host:203.0.113.20:22", "", "medium"), "SSH allows root to sign in")
	title(l.find("sshd.root_login_enabled", "host:203.0.113.22:22", "", "medium"), "SSH allows root to sign in")
	// Lowered by a declaration, not by anything read.
	title(e.find("db.listens_unfiltered", web, "5432/tcp", "high"), "A database listens without a firewall")
	lf := title(l.find("db.listens_unfiltered", web, "5432/tcp", "info"), "A database listens without a firewall")
	lf.SeverityBase = "high"
	lf.Adjustments = []report.Adjustment{adj("exposed_on_purpose", "to_info", "acme.yaml", "assets.web.context.exposure")}
	// Accepted before, expired now: open again.
	exp := "2026-10-10"
	ef := title(e.find("svc.sensitive_listens_unfiltered", web, "6379/tcp", "high"), "A sensitive service listens without a firewall")
	ef.Status, ef.Acceptance = "accepted", acceptance("carol", &exp)
	title(l.find("svc.sensitive_listens_unfiltered", web, "6379/tcp", "high"), "A sensitive service listens without a firewall")
	l.Acceptances = []report.Acceptance{{Entry: "acme.yaml intent.accepted_risks[0]", ID: "svc.sensitive_listens_unfiltered", Asset: "web", AcceptedBy: "carol", Expires: &exp, Outcome: "expired", Findings: []report.Key{{ID: "svc.sensitive_listens_unfiltered", Asset: web, Subject: new("6379/tcp")}}}}
	// Accepted since.
	title(e.find("sshd.password_auth_exposed", web, "", "medium"), "SSH allows many authentication attempts")
	af := title(l.find("sshd.password_auth_exposed", web, "", "medium"), "SSH allows many authentication attempts")
	far := "2027-01-31"
	af.Status, af.Acceptance = "accepted", acceptance("dave", &far)
	// New: the earlier run decided this rule on a complete read.
	e.notMatched("accounts.shadow_permissions_unexpected", deployE)
	title(l.find("accounts.shadow_permissions_unexpected", deployL, "", "high"), "The kernel is past its end of support")
	return e, l
}

func writeReport(t *testing.T, dir string, r *report.Report) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := report.WriteJSON(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readReport(t *testing.T, dir string) Input {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := report.ReadJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return Input{Report: r, SHA256: dir, RunRecordChecked: true}
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "engagement-comparison-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("engagement-comparison-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("engagement-comparison-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validateJSON(t *testing.T, s *jsonschema.Schema, raw []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("comparison does not match its schema: %v", err)
	}
}

// The comparison is a contract like the report: text and JSON are pinned per
// case. Regenerate with `go test ./internal/engagement/compare -update` and
// read the diff: a change here is a change to what an operator reads.
func TestGoldenComparison(t *testing.T) {
	root := filepath.Join("testdata", "lab")
	if *update {
		e, l := labRuns()
		for name, r := range map[string]*report.Report{"earlier": e.Report, "later": l.Report} {
			writeReport(t, filepath.Join(root, name), r)
		}
	}
	c, err := Compare(readReport(t, filepath.Join(root, "earlier")), readReport(t, filepath.Join(root, "later")))
	if err != nil {
		t.Fatal(err)
	}
	var js bytes.Buffer
	if err := WriteJSON(&js, c); err != nil {
		t.Fatal(err)
	}
	validateJSON(t, schema(t), js.Bytes())
	golden := func(name string, got []byte) {
		t.Helper()
		p := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, got, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
		want, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from the golden (run with -update and read the diff):\n%s", name, got)
		}
	}
	golden("lab.json", js.Bytes())
	for name, v := range map[string]int{"lab.txt": 0, "lab-v.txt": 1} {
		var b bytes.Buffer
		if err := WriteText(&b, c, hostreport.Options{Verbose: v, Width: 100}); err != nil {
			t.Fatal(err)
		}
		golden(name, b.Bytes())
	}
	// What the pair is for.
	want := map[string]Category{}
	_ = want
	checks := []struct {
		id    string
		asset string
		cat   Category
	}{
		{"sshd.password_auth_enabled", "host:203.0.113.9:22", StillOpen},
		{"fw.no_firewall_active", "host:203.0.113.6:22", Fixed},
		{"accounts.shadow_permissions_unexpected", "host:203.0.113.9:22", New},
		{"svc.sensitive_listens_unfiltered", "host:203.0.113.6:22", Reopened},
		{"sshd.password_auth_exposed", "host:203.0.113.6:22", AcceptedSince},
		{"sshd.root_login_enabled", "host:203.0.113.22:22", FirstReported},
		{"sshd.root_login_enabled", "host:203.0.113.20:22", NotRechecked},
	}
	for _, ck := range checks {
		found := false
		for _, i := range c.Instances {
			r := i.Later
			if r == nil {
				r = i.Earlier
			}
			if i.ID == ck.id && r.Asset == ck.asset {
				found = true
				if i.Category != ck.cat {
					t.Errorf("%s on %s: %s, want %s", ck.id, ck.asset, i.Category, ck.cat)
				}
			}
		}
		if !found {
			t.Errorf("%s on %s is not in the comparison", ck.id, ck.asset)
		}
	}
}
