package engagement

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/hostasset"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/target/fixture"
)

const dbHost = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - host: deploy@203.0.113.5
assets:
  db:
    host: 203.0.113.5
    elevate: sudo
    context:
      exposure: internet
      expected_services:
        - port: 5432
          proto: tcp
          audience: lan
`

// A database open to every address on a host with no firewall is judged in
// Analyze from the host's facts: one finding on its port, raised for the
// declared internet exposure and the contradicted audience, stopped at its
// ceiling, citing each fact (docs/spec/engagement.md, R1).
func TestAnOpenDatabaseIsReportedFromTheHostsFacts(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(dbHost), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := filepath.Abs(filepath.Join("testdata", "db-open"))
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		fx, err := fixture.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(dbHost), Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range out.Report.Findings {
		if f.ID != finding.IDDBListensUnfiltered {
			continue
		}
		got = append(got, *f.Key.Subject)
		if f.Severity != "high" || f.Rule.Kind != "multi_fact" || len(f.Evidence) < 5 {
			t.Errorf("finding %+v", f)
		}
	}
	if len(got) != 1 || got[0] != "5432/tcp" {
		t.Fatalf("db findings on %v, want one on 5432/tcp", got)
	}
	for _, row := range out.Report.Coverage {
		if row.Area == "data" && (row.Mark != "partial" || len(row.SubItems) == 0) {
			t.Errorf("data row %+v", row)
		}
	}
}

// An acceptance naming the port accepts that instance through the report,
// as a network collector's is accepted, and is never handed to the host
// grader or named as not applied; a posture finding's acceptance on the
// same host still goes to the grader.
func TestAnOpenDatabaseIsAcceptedBySubject(t *testing.T) {
	raw := dbHost + `people:
  alice: {kind: employee}
intent:
  accepted_risks:
    - {id: db.listens_unfiltered, asset: db, subject: 5432/tcp, reason: replica sync, accepted_by: alice, date: 2026-10-01, expires: 2027-06-01}
    - {id: updates.pending, asset: db, reason: patch window, accepted_by: alice, date: 2026-10-01, expires: 2027-06-01}
`
	res, err := Parse("engagement.yaml", []byte(raw), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := filepath.Abs(filepath.Join("testdata", "db-open"))
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		fx, err := fixture.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(raw), Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Warnings) != 0 {
		t.Errorf("warnings %v", out.Warnings)
	}
	outcomes := map[string]string{}
	for _, a := range out.Report.Acceptances {
		outcomes[a.ID] = a.Outcome
	}
	if outcomes[finding.IDDBListensUnfiltered] != "applied" {
		t.Errorf("acceptance outcomes %v", outcomes)
	}
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDDBListensUnfiltered && (f.Status != finding.StatusAccepted || f.Acceptance == nil || f.Acceptance.CoversEveryInstance) {
			t.Errorf("finding %+v", f)
		}
	}
	// The host's own rule settles it: it found no pending update.
	if outcomes[finding.IDUpdatesPending] != "not_matched" {
		t.Errorf("the posture acceptance was not settled by the host: %v", outcomes)
	}
}

// An account with no password that sshd lets in is reported from the
// host's facts as one critical finding listing it, ranked first, while the
// host-local finding on the same account stays under Findings only
// (docs/spec/engagement.md, R2).
func TestAnEmptyPasswordOverSSHIsReportedFromTheHostsFacts(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(dbHost), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := filepath.Abs(filepath.Join("testdata", "ssh-empty-password"))
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		fx, err := fixture.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(dbHost), Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range out.Report.Findings {
		ids[f.ID] = true
		if f.ID == finding.IDEmptyPasswordRemote && (f.Severity != "critical" || f.Affected == nil || f.Affected.Listed[0] != "alice") {
			t.Errorf("finding %+v", f)
		}
	}
	if !ids[finding.IDEmptyPasswordRemote] || !ids[finding.IDEmptyPassword] {
		t.Fatalf("findings %v", ids)
	}
	for _, item := range out.Report.Summary.Items {
		if slices.Contains(item.IDs, finding.IDEmptyPassword) {
			t.Errorf("the host-local finding is ranked beside the one sshd makes remote: %+v", out.Report.Summary.Items)
		}
	}
}

// R2 is about the host as a whole: an acceptance naming a subject is
// refused at intake, never left to look applied or "found nothing".
func TestAnEmptyPasswordOverSSHIsAcceptedWithoutASubject(t *testing.T) {
	raw := dbHost + `people:
  alice: {kind: employee}
intent:
  accepted_risks:
    - {id: accounts.empty_password_remote, asset: db, subject: alice, reason: r, accepted_by: alice, date: 2026-10-01, expires: 2027-06-01}
`
	if _, err := Parse("engagement.yaml", []byte(raw), testOpts); err == nil || !strings.Contains(err.Error(), "remove subject") {
		t.Fatalf("a subject on a whole-host finding: %v", err)
	}
}

// A host named in data.matters_most: Analyze raises its host access
// posture finding one step after the host collector's table, and the
// readout counts every finding the answer raises on it, moved or already
// at the top (docs/spec/engagement.md, "Severity in context"; report.md,
// "Data that matters most").
func TestDataMattersMostRaisesAHostsAccessFindings(t *testing.T) {
	raw := strings.Replace(dbHost, "exposure: internet", "exposure: lan", 1) + "data:\n  matters_most:\n    - {what: orders, asset: db}\n"
	res, err := Parse("engagement.yaml", []byte(raw), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := filepath.Abs(filepath.Join("testdata", "ssh-empty-password"))
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		fx, err := fixture.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(raw), Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	var raised bool
	for _, f := range out.Report.Findings {
		if f.ID != finding.IDPasswordAuthEnabled {
			continue
		}
		raised = f.Severity == "high" && f.SeverityBase == "medium" && len(f.Adjustments) == 1 &&
			f.Adjustments[0].Rule == "data_matters_most" && f.Adjustments[0].By == "engagement" && f.Adjustments[0].Source.Key == "data.matters_most[0]"
		if !raised {
			t.Errorf("password auth %+v", f)
		}
	}
	if !raised {
		t.Fatal("no password auth finding")
	}
	mm := out.Report.Summary.MattersMost
	if len(mm) != 1 || mm[0].Outcome != "raised" || mm[0].Raised != 3 || mm[0].Name != "db" || mm[0].Undecided != 0 {
		t.Fatalf("readout %+v", mm)
	}
}
