package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	_ "github.com/b87/scheck/internal/check/all" // the real catalog
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	hostreport "github.com/b87/scheck/internal/report"
)

var started = time.Date(2026, 10, 7, 7, 12, 3, 0, time.UTC)

// envelope loads a committed host report golden: the host collector's
// output for a recorded fixture, which this package reads and never makes.
func envelope(t *testing.T, name string) hostreport.Envelope {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "report", "testdata", "golden", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env hostreport.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func hostAsset(t *testing.T, fixture, name string) AssetInput {
	t.Helper()
	env := envelope(t, fixture)
	// One clock: the host's collection starts when the run does.
	env.Run.Started = started
	return AssetInput{Name: name, ID: "host:" + name + ":22", Kind: "host", Root: true, Status: "collected",
		Host: &HostInput{Envelope: env, User: "deploy"}}
}

// oneHost is a --host engagement on one fixture.
func oneHost(t *testing.T, fixture string) Input {
	t.Helper()
	return Input{Version: "test", Name: "host-" + fixture, FromHost: true, SHA256: strings.Repeat("0", 64),
		Rerun: "scheck run --host deploy@" + fixture + " (with the same flags)",
		Zone:  time.UTC, Started: started, Finished: started.Add(7 * time.Minute), Assets: []AssetInput{hostAsset(t, fixture, fixture)}}
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "engagement-report-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("engagement-report-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("engagement-report-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, s *jsonschema.Schema, r *Report) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(doc); err != nil {
		t.Fatalf("the report does not validate against docs/engagement-report-schema.json:\n%v", err)
	}
}

func row(t *testing.T, r *Report, area string) Row {
	t.Helper()
	for _, row := range r.Coverage {
		if row.Area == area {
			return row
		}
	}
	t.Fatalf("no coverage row %s", area)
	return Row{}
}

func subItem(t *testing.T, row Row, name string) SubItem {
	t.Helper()
	for _, si := range row.SubItems {
		if si.Name == name {
			return si
		}
	}
	t.Fatalf("no sub-item %s in %s", name, row.Area)
	return SubItem{}
}

func reasons(rs []ReasonDetail) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Reason)
	}
	return out
}

// Every shape this package builds validates against the schema as
// committed, for each recorded platform and for each way a run ends.
func TestReportsValidateAgainstTheSchema(t *testing.T) {
	s := schema(t)
	for _, fx := range []string{"ubuntu", "fedora", "macos"} {
		t.Run(fx, func(t *testing.T) { validate(t, s, Build(oneHost(t, fx))) })
	}
	t.Run("root without collector", func(t *testing.T) { validate(t, s, Build(withGitHubRoot(t))) })
	t.Run("lost session", func(t *testing.T) { validate(t, s, Build(lostSession(t))) })
	t.Run("refused host", func(t *testing.T) { validate(t, s, Build(refusedHost(t))) })
	t.Run("acceptances", func(t *testing.T) { validate(t, s, Build(withAcceptances(t))) })
}

// A host domain is marked from the rules that decided, never from the
// checks that ran: on Linux no rule judges the firewall or the listeners,
// so those rows say "not judged", and the package managers that are
// not installed do not lower Software updates when apt answered
// (docs/spec/engagement.md, "Coverage").
func TestHostCoverageComesFromRules(t *testing.T) {
	r := Build(oneHost(t, "ubuntu"))
	hosts := row(t, r, "hosts")
	if hosts.Mark != "partial" {
		t.Fatalf("Hosts on Ubuntu is %s; with no rule for the firewall it can only be partial", hosts.Mark)
	}
	for _, name := range []string{"Firewall", "Network exposure"} {
		si := subItem(t, hosts, name)
		if si.Mark != "not_assessed" || !slices.Equal(reasons(si.Reasons), []string{"no_rule"}) {
			t.Errorf("%s: %s %v, want not_assessed no_rule", name, si.Mark, si.Reasons)
		}
	}
	if si := subItem(t, hosts, "Software updates"); si.Mark != "assessed" {
		t.Errorf("Software updates is %s %v: dnf and zypper missing must not lower it when apt decided", si.Mark, si.Reasons)
	}
	if si := subItem(t, hosts, "Logging and audit"); si.Mark != "not_assessed" || !slices.Equal(reasons(si.Reasons), []string{"unavailable:exit_error"}) {
		t.Errorf("Logging and audit: %s %v", si.Mark, si.Reasons)
	}
	for _, si := range hosts.SubItems {
		for _, p := range []string{"Host identity", "Operating system", "Session and shell", "Text utilities"} {
			if si.Name == p {
				t.Errorf("%s carries no rule and is not coverage", p)
			}
		}
	}
	for _, area := range []string{"identity", "secrets", "cloud", "email"} {
		if got := row(t, r, area); got.Mark != "not_assessed" || !slices.Equal(reasons(got.Reasons), []string{"not_declared"}) {
			t.Errorf("%s: %s %v, want not_assessed not_declared", area, got.Mark, got.Reasons)
		}
	}
	for _, area := range []string{"endpoints", "application_logic", "processes", "lookalike_domains"} {
		if row(t, r, area).Mark != "outside_scheck" {
			t.Errorf("%s must print as outside scheck on every run", area)
		}
	}
	if r.Summary.Areas != (AreaCounts{Partial: 1, NotAssessed: 9, Total: 10}) {
		t.Errorf("area counts %+v", r.Summary.Areas)
	}
	if r.Exit.Code != 0 || len(r.Findings) != 0 {
		t.Errorf("Ubuntu fixture: exit %d with %d findings, want 0 and none", r.Exit.Code, len(r.Findings))
	}
	if a := r.Assets[0]; a.Checks == nil || a.Checks.Planned != 33 || a.Checks.NotRun != 0 {
		t.Errorf("checks %+v", a.Checks)
	}
}

// The updates family's assessment is decided and complete when apt
// answered, so a later run may read its absence as fixed.
func TestFamiliesDecideOnOneMember(t *testing.T) {
	r := Build(oneHost(t, "ubuntu"))
	for _, a := range r.Assessments {
		if a.ID != finding.IDUpdatesPending {
			continue
		}
		if a.Status != finding.NotMatched || !a.Complete || len(a.Reads) != 3 {
			t.Fatalf("updates.pending: %+v", a)
		}
		return
	}
	t.Fatal("no updates.pending assessment")
}

func withGitHubRoot(t *testing.T) Input {
	in := oneHost(t, "macos")
	in.FromHost, in.Path = false, "engagement.yaml"
	in.Rerun = "scheck run engagement.yaml"
	in.Assets = append(in.Assets, AssetInput{Name: "example-org", ID: "saas:github:example-org", Kind: "saas", Root: true,
		Status: "not_collected", Reason: "collector_not_built", Detail: "no collector reads saas assets in this build"})
	return in
}

// A declared root with no collector leaves the run incomplete, whatever
// the findings, and its areas say so (docs/spec/engagement.md, "Exit codes").
func TestARootWithoutCollectorExitsTwo(t *testing.T) {
	r := Build(withGitHubRoot(t))
	if r.Exit.Code != 2 {
		t.Fatalf("exit %d, want 2", r.Exit.Code)
	}
	if len(r.Incomplete) != 1 || r.Incomplete[0].Reason != "collector_not_built" || r.Incomplete[0].Asset != "saas:github:example-org" {
		t.Fatalf("incomplete %+v", r.Incomplete)
	}
	for _, area := range []string{"identity", "secrets", "cicd"} {
		got := row(t, r, area)
		if got.Mark != "not_assessed" || !slices.Equal(reasons(got.Reasons), []string{"collector_not_built"}) || got.Population.InScope != 1 {
			t.Errorf("%s: %s %v", area, got.Mark, got.Reasons)
		}
	}
	codes := []int{}
	for _, e := range r.Exit.Reasons {
		codes = append(codes, e.Code)
	}
	if !slices.Equal(codes, []int{2, 1}) {
		t.Errorf("exit reasons %v: the open finding must still be named beside the incomplete root", r.Exit.Reasons)
	}
}

// lostSession drops the macOS fixture's last checks as a session lost
// mid-run would.
func lostSession(t *testing.T) Input {
	in := oneHost(t, "macos")
	a := &in.Assets[0]
	env := &a.Host.Envelope
	for id := range env.Facts {
		a.Host.Planned = append(a.Host.Planned, id)
	}
	cut := []string{"sshd.config", "fs.world_writable"}
	for _, id := range cut {
		delete(env.Facts, id)
	}
	for i, as := range env.Assessments {
		if slices.Contains(cut, as.Check) {
			env.Assessments[i].Status, env.Assessments[i].Reason = finding.NotAssessed, "check-not-run"
		}
	}
	a.Status, a.Reason, a.Detail = "incomplete", "failed", "the connection was lost before every baseline check ran: EOF"
	a.Host.Lost = "EOF"
	return in
}

// A lost session is incomplete with reason failed; the checks after the
// loss are not run, never unavailable, and what was read is kept.
func TestALostSessionIsNotRunNotUnavailable(t *testing.T) {
	r := Build(lostSession(t))
	if r.Exit.Code != 2 || len(r.Incomplete) != 1 {
		t.Fatalf("exit %d, incomplete %+v", r.Exit.Code, r.Incomplete)
	}
	s := r.Incomplete[0]
	if s.Reason != "failed" || s.Effect == nil || s.Effect.ChecksNotRun != 2 || !s.Effect.Kept {
		t.Fatalf("shortfall %+v effect %+v", s, s.Effect)
	}
	ssh := subItem(t, row(t, r, "hosts"), "SSH server")
	if ssh.Mark != "not_assessed" || !slices.Equal(reasons(ssh.Reasons), []string{"failed"}) {
		t.Errorf("SSH server after the loss: %s %v, want not_assessed failed", ssh.Mark, ssh.Reasons)
	}
	if !slices.Contains(reasons(row(t, r, "hosts").Reasons), "failed") {
		t.Error("the Hosts row must name the lost connection")
	}
	if len(r.Findings) == 0 {
		t.Error("findings read before the loss are kept and assessed")
	}
}

func refusedHost(t *testing.T) Input {
	in := oneHost(t, "macos")
	in.FromHost, in.Path = false, "engagement.yaml"
	in.Rerun = "scheck run engagement.yaml"
	in.Assets = append(in.Assets, AssetInput{Name: "deploy", ID: "host:203.0.113.5:22", Kind: "host", Root: true,
		Status: "refused", Reason: "refused", Detail: "host key for 203.0.113.5 changed"})
	return in
}

// A host that refused us exits 3, and every other asset is still reported.
func TestARefusedHostExitsThreeAndKeepsTheOthers(t *testing.T) {
	r := Build(refusedHost(t))
	if r.Exit.Code != 3 || len(r.Refused) != 1 || r.Refused[0].AssetName != "deploy" {
		t.Fatalf("exit %d refused %+v", r.Exit.Code, r.Refused)
	}
	if len(r.Findings) == 0 {
		t.Error("the other host's findings must still be reported")
	}
	hosts := row(t, r, "hosts")
	if hosts.Population.InScope != 2 || hosts.Population.Read != 1 || !slices.Contains(reasons(hosts.Reasons), "refused") {
		t.Errorf("Hosts row %+v", hosts)
	}
}

// The macOS fixture has an open medium firewall finding and a low updates
// one: one item ranks, the low one is counted below it, and a baseline
// host exits 1.
func TestRankingAndThreshold(t *testing.T) {
	r := Build(oneHost(t, "macos"))
	if len(r.Summary.Items) != 1 || r.Summary.Items[0].IDs[0] != finding.IDAppFirewallDisabled {
		t.Fatalf("items %+v", r.Summary.Items)
	}
	if r.Summary.Below.Low != 1 || r.Exit.Code != 1 {
		t.Errorf("below %+v exit %d", r.Summary.Below, r.Exit.Code)
	}
	if th := r.Exit.Thresholds["host:macos:22"]; th.Severity != "medium" || th.Basis != "profile:baseline" {
		t.Errorf("threshold %+v", th)
	}
	f := r.Findings[0]
	if f.AcceptTemplate == nil || f.AcceptTemplate.AcceptedBy != "" || f.AcceptTemplate.Reason != "" ||
		f.AcceptTemplate.Expires != "2027-04-05" || !f.AcceptTemplate.NeedsPeople || f.AcceptTemplate.Asset != "macos" {
		t.Errorf("paste %+v: empty reason and accepted_by, 180 days for medium, needs people on --host", f.AcceptTemplate)
	}
	for _, e := range f.Evidence {
		if e.Kind != "observed" || e.Principal != "deploy" || e.CollectedAt == nil {
			t.Errorf("evidence %+v", e)
		}
	}
}

func withAcceptances(t *testing.T) Input {
	in := oneHost(t, "macos")
	in.FromHost, in.Path, in.People, in.Rerun = false, "engagement.yaml", true, "scheck run engagement.yaml"
	in.Candidates = []Candidate{{Handle: "alice", Why: "employee"}}
	env := &in.Assets[0].Host.Envelope
	for i, f := range env.Findings {
		if f.ID == finding.IDUpdatesPending {
			env.Findings[i].Status, env.Findings[i].AcceptedReason = finding.StatusAccepted, "patch window"
		}
	}
	id := "host:macos:22"
	in.Acceptances = []AcceptanceInput{
		{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDUpdatesPending, Asset: "macos", AssetID: id,
			Reason: "patch window", AcceptedBy: "alice", Expires: "2026-10-19"},
		{Entry: "engagement.yaml intent.accepted_risks[1]", ID: finding.IDFileVaultOff, Asset: "macos", AssetID: id,
			Reason: "old", AcceptedBy: "alice"},
		{Entry: "engagement.yaml intent.accepted_risks[2]", ID: finding.IDAppFirewallDisabled, Asset: "macos", AssetID: id,
			Reason: "lapsed", AcceptedBy: "alice", Expires: "2026-10-01"},
		{Entry: "engagement.yaml intent.accepted_risks[3]", ID: finding.IDAppFirewallDisabled, Asset: "macos", AssetID: id,
			Subject: "22/tcp", Reason: "one port", AcceptedBy: "alice", Expires: "2027-01-01"},
		// sshd.config needs root on macOS, so its rules could not decide.
		{Entry: "engagement.yaml intent.accepted_risks[4]", ID: finding.IDPasswordAuthEnabled, Asset: "macos", AssetID: id,
			Reason: "keys only", AcceptedBy: "alice", Expires: "2027-01-01"},
	}
	return in
}

// Each acceptance ends as one outcome, and only a rule that decided on
// complete evidence may say "likely fixed" (docs/spec/engagement.md,
// "Acceptances").
func TestAcceptanceOutcomes(t *testing.T) {
	r := Build(withAcceptances(t))
	want := []string{"applied", "not_matched", "expired", "not_applied", "rule_not_decided"}
	for i, a := range r.Acceptances {
		if a.Outcome != want[i] {
			t.Errorf("%s: %s (%s), want %s", a.Entry, a.Outcome, a.Why, want[i])
		}
	}
	notes := map[string]bool{}
	for _, n := range r.Notes {
		notes[n.Kind+" "+n.Source] = true
	}
	for _, k := range []string{
		"acceptance_expiring engagement.yaml intent.accepted_risks[0]",
		"acceptance_not_matched engagement.yaml intent.accepted_risks[1]",
		"acceptance_not_applied engagement.yaml intent.accepted_risks[3]",
		"acceptance_rule_not_decided engagement.yaml intent.accepted_risks[4]",
	} {
		if !notes[k] {
			t.Errorf("missing note %q in %v", k, r.Notes)
		}
	}
	// An entry that is likely fixed is not also nagged for having no expiry.
	if notes["acceptance_without_expiry engagement.yaml intent.accepted_risks[1]"] {
		t.Error("a likely-fixed entry is also told it has no expiry")
	}
	for _, f := range r.Findings {
		switch f.ID {
		case finding.IDUpdatesPending:
			if f.Acceptance == nil || f.Acceptance.AcceptedBy != "alice" || f.AcceptTemplate != nil || !f.Acceptance.CoversEveryInstance {
				t.Errorf("accepted finding %+v", f)
			}
		case finding.IDAppFirewallDisabled:
			if f.AcceptTemplate == nil || f.AcceptTemplate.NeedsPeople || len(f.AcceptTemplate.AcceptedByCandidates) != 1 {
				t.Errorf("open finding's paste %+v", f.AcceptTemplate)
			}
		}
	}
	if r.Summary.Below.Accepted != 1 {
		t.Errorf("below %+v", r.Summary.Below)
	}
}

// An acceptance's date is read in engagement.timezone against the
// collection time: in Madrid, 2026-10-07 has ended at 22:30 UTC.
func TestExpiryIsReadInTheEngagementZone(t *testing.T) {
	madrid, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Skip("no tz database")
	}
	in := withAcceptances(t)
	in.Zone, in.Started = madrid, time.Date(2026, 10, 19, 22, 30, 0, 0, time.UTC)
	if got := Build(in).Acceptances[0].Outcome; got != "expired" {
		t.Errorf("2026-10-19 in Madrid at 00:30 on the 20th: %s, want expired", got)
	}
	in.Zone = time.UTC
	if got := Build(in).Acceptances[0].Outcome; got != "applied" {
		t.Errorf("2026-10-19 in UTC at 22:30 the same day: %s, want applied", got)
	}
}

// A family whose only applicable member could not decide is not assessed:
// a member that is not applicable is no answer about the host.
func TestNotApplicableIsNoAnswer(t *testing.T) {
	in := oneHost(t, "ubuntu")
	env := &in.Assets[0].Host.Envelope
	for i, as := range env.Assessments {
		if as.Finding != finding.IDUpdatesPending {
			continue
		}
		if as.Check == "pkg.apt_upgradable" {
			env.Assessments[i].Status, env.Assessments[i].Reason = finding.NotAssessed, "check-unavailable:exit_error"
		} else {
			env.Assessments[i].Status, env.Assessments[i].Reason = finding.NotApplicable, "check-not-in-platform-catalog"
		}
	}
	r := Build(in)
	for _, a := range r.Assessments {
		if a.ID == finding.IDUpdatesPending && (a.Status != finding.NotAssessed || a.Complete) {
			t.Errorf("updates.pending: %+v, want not_assessed and incomplete", a)
		}
	}
	if si := subItem(t, row(t, r, "hosts"), "Software updates"); si.Mark != "not_assessed" || si.Population.InScope != 1 {
		t.Errorf("Software updates: %s %+v", si.Mark, si.Population)
	}
}

// A marker-shaped string a target printed is never counted as a
// redaction: the runner's own count bounds what the markers may claim.
func TestForgedMarkersAreNotCounted(t *testing.T) {
	in := oneHost(t, "ubuntu")
	env := &in.Assets[0].Host.Envelope
	o := env.Observations["sshd.config#1"]
	o.Output = "banner [REDACTED:extra:0:9 bytes] [REDACTED:aws-access-key:20 bytes]"
	env.Observations["sshd.config#1"] = o
	r := Build(in)
	if r.Redaction.Operator.Matches != 0 || len(r.Redaction.Builtin) != 0 {
		t.Errorf("forged markers counted: %+v", r.Redaction)
	}
	o.Redactions = 1
	env.Observations["sshd.config#1"] = o
	r = Build(in)
	if r.Redaction.Builtin["unattributed"] != 1 || r.Redaction.Operator.Matches != 0 {
		t.Errorf("one real redaction, two markers: %+v, want it unattributed", r.Redaction)
	}
}

// Days are counted as calendar dates: a spring-forward night does not make
// ten days nine.
func TestDaysCountCalendarDates(t *testing.T) {
	madrid, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Skip("no tz database")
	}
	at := time.Date(2027, 3, 22, 9, 0, 0, 0, madrid)
	if got := calendarDays(at, "2027-04-01", madrid); got != 10 {
		t.Errorf("22 March to 1 April across the DST change: %d days, want 10", got)
	}
}

// A refused host's commands are in the report's trace: the canary it sent
// touched the host.
func TestARefusedHostKeepsItsTrace(t *testing.T) {
	in := refusedHost(t)
	in.Assets[1].Trace = []policy.AuditEntry{{CheckID: "sys.canary", Decision: "denied:canary", Time: started}}
	r := Build(in)
	if tr := r.Assets[1].Trace; len(tr) != 1 || tr[0].Check != "sys.canary" {
		t.Errorf("trace %+v", tr)
	}
}

// A collected host with no domain the report can place is not "checked".
func TestHostsRowNeedsSubItems(t *testing.T) {
	in := oneHost(t, "ubuntu")
	in.Assets[0].Host.Envelope.Host.Platform = "plan9"
	r := Build(in)
	if got := row(t, r, "hosts"); got.Mark == "assessed" || len(got.Reasons) == 0 {
		t.Errorf("Hosts is %s with %d sub-items and reasons %v", got.Mark, len(got.SubItems), got.Reasons)
	}
	validate(t, schema(t), r)
}

// The run status names only what was read; a non-root asset no collector
// reads is named apart, and a run with more than five ranked items says so.
func TestStatusNamesOnlyWhatWasRead(t *testing.T) {
	in := oneHost(t, "ubuntu")
	in.Assets = append(in.Assets, AssetInput{Name: "shop", ID: "url:https://203.0.113.5/", Kind: "url", Root: false,
		Status: "not_collected", Reason: "collector_not_built"})
	var buf bytes.Buffer
	r := Build(in)
	if r.Exit.Code != 0 {
		t.Fatalf("exit %d: a non-root asset without a collector does not make the run incomplete", r.Exit.Code)
	}
	if err := WriteText(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, "every system you listed") || !strings.Contains(out, "Not read: shop") {
		t.Errorf("status:\n%s", out)
	}
	buf.Reset()
	r = Build(manyFindings(t))
	if len(r.Summary.Items) != 5 || r.Summary.More != 1 {
		t.Fatalf("items %d, more %d", len(r.Summary.Items), r.Summary.More)
	}
	if err := WriteText(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, "Nothing else open") || !strings.Contains(out, "1 more open at medium or above") {
		t.Errorf("summary:\n%s", out)
	}
}

// A rule over a sampled read (a depth-capped find) answers, but never on
// complete evidence: an absence there is not an absence on the host, so an
// acceptance of it is never called "likely fixed".
func TestASampledReadIsNeverComplete(t *testing.T) {
	in := withAcceptances(t)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDWorldWritablePresent,
		Asset: "macos", AssetID: "host:macos:22", Reason: "old", AcceptedBy: "alice"}}
	r := Build(in)
	for _, a := range r.Assessments {
		if a.ID == finding.IDWorldWritablePresent && (a.Status != finding.NotMatched || a.Complete) {
			t.Errorf("world-writable: %+v, want not_matched and incomplete", a)
		}
	}
	if got := r.Acceptances[0]; got.Outcome != "rule_not_decided" || !strings.Contains(got.Why, "only part of what is there") {
		t.Errorf("acceptance %+v", got)
	}
}
