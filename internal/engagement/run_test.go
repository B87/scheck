package engagement

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target/fixture"
)

func TestHostEngagementName(t *testing.T) {
	cases := map[string]string{
		"deploy@203.0.113.5":      "host-203-0-113-5",
		"deploy@203.0.113.5:2222": "host-203-0-113-5-2222",
		"203.0.113.5:22":          "host-203-0-113-5",
		"local":                   "host-local",
		"ops@Web.Example.com":     "host-web-example-com",
		"root@[2001:db8::1]:2200": "host-2001-db8--1-2200",
		"a@" + strings.Repeat("x", 30) + "." + strings.Repeat("y", 30) + ".example.com:2222": "host-" + strings.Repeat("x", 30) + "-" + strings.Repeat("y", 22) + "-2222",
	}
	for loc, want := range cases {
		res, raw, err := ForHost(loc, HostFlags{}, testOpts)
		if err != nil {
			t.Errorf("%s: %v", loc, err)
			continue
		}
		if res.Engagement.Name != want {
			t.Errorf("%s: name %q, want %q", loc, res.Engagement.Name, want)
		}
		// What --write-engagement writes reads back as the same engagement.
		again, err := Parse("written.yaml", raw, testOpts)
		if err != nil {
			t.Errorf("%s: the written engagement does not validate: %v\n%s", loc, err, raw)
			continue
		}
		if again.Engagement != res.Engagement || len(again.Assets) != 1 {
			t.Errorf("%s: re-read %+v", loc, again)
		}
	}
}

func TestForHostCarriesTheFlagsAndNothingElse(t *testing.T) {
	res, raw, err := ForHost("deploy@203.0.113.5", HostFlags{Identity: "~/.ssh/deploy", KnownHosts: "~/acme/known_hosts",
		Timeout: "10m0s", Elevate: "sudo", Profile: "hardened"}, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	a := res.Assets[0]
	if len(res.Assets) != 1 || a.Name != "host-203-0-113-5" || a.User != "deploy" || a.Identity != "~/.ssh/deploy" ||
		a.KnownHosts != "~/acme/known_hosts" || a.Timeout != "10m0s" || a.Elevate != "sudo" || a.Profile != "hardened" || a.Context != nil {
		t.Fatalf("asset = %+v", a)
	}
	if res.Engagement.Timezone == "" || res.Engagement.Timezone == "Local" || res.Timeout() != DefaultTimeout || res.Defaults.Profile != "baseline" {
		t.Fatalf("engagement = %+v, timeout %v", res.Engagement, res.Timeout())
	}
	for _, absent := range []string{"people", "intent", "context", "redact_extra"} {
		if strings.Contains(string(raw), absent+":") {
			t.Errorf("the built engagement holds %s:\n%s", absent, raw)
		}
	}
}

func TestForHostRefusesWithoutQuoting(t *testing.T) {
	_, _, err := ForHost("deploy:hunter2@203.0.113.5", HostFlags{}, testOpts)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
	_, _, err = ForHost("deploy@203.0.113.5", HostFlags{Profile: "paranoid"}, testOpts)
	if err == nil || !strings.HasPrefix(err.Error(), "--profile: ") {
		t.Fatalf("err = %v, want it to name --profile", err)
	}
	_, _, err = ForHost("local", HostFlags{KnownHosts: "/kh"}, testOpts)
	if err == nil || !strings.HasPrefix(err.Error(), "--known-hosts: ") {
		t.Fatalf("err = %v, want it to name --known-hosts", err)
	}
}

func TestRunDirIsPrivateAndLocked(t *testing.T) {
	state := t.TempDir()
	started := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	d, err := CreateRunDir(state, "acme", started)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(state, "engagements", "acme", "2026-10-07T09:00:00Z"); d.Path != want {
		t.Fatalf("path %s, want %s", d.Path, want)
	}
	if fi, _ := os.Stat(d.Path); fi.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode %v", fi.Mode().Perm())
	}
	if _, err := CreateRunDir(state, "acme", started); !errors.Is(err, ErrLocked) {
		t.Fatalf("second run on a locked directory: %v, want ErrLocked", err)
	}
	if err := d.Write("evidence/x.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d.File("evidence/x.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
	d.Close()
	if _, err := CreateRunDir(state, "acme", started); err == nil || errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), "already holds a run") {
		t.Fatalf("finished run directory: %v", err)
	}
}

const hostAndGitHub = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - host: deploy@203.0.113.5
  - saas: github:example-org
assets:
  web:
    host: 203.0.113.5
    elevate: sudo
`

// fixtureCollect collects every host from a recorded fixture.
func fixtureCollect(t *testing.T, name string, calls *int) func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
	return func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		*calls++
		fx, err := fixture.Load(filepath.Join("..", "..", "testdata", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
}

// A host root and a github root: the host is collected and assessed, the
// github root is recorded as not collected, and the run is incomplete
// (docs/ROADMAP.md, E1b "Done when").
func TestRunCollectsTheHostAndRecordsWhatHasNoCollector(t *testing.T) {
	raw := []byte(hostAndGitHub)
	res, err := Parse("engagement.yaml", raw, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	calls := 0
	out, err := Run(context.Background(), res, RunOptions{Raw: raw, Dir: dir, Collect: fixtureCollect(t, "ubuntu", &calls)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != "report" || calls != 1 {
		t.Fatalf("stage %s, %d collections", out.Stage, calls)
	}
	if len(out.Incomplete) != 1 || Describe(out.Incomplete[0]) != "saas:github:example-org: collector_not_built" || len(out.Refused) != 0 {
		t.Fatalf("incomplete = %+v", out.Incomplete)
	}
	if out.ExitCode() != 2 || out.Report == nil || out.Document != out.Report {
		t.Fatalf("exit %d; the report is the run's last document", out.ExitCode())
	}
	for _, f := range []string{"engagement.yaml", "scope.json", "recon.json", "plan.json", "findings.json", "audit.jsonl",
		"evidence/web.json", "report.json", "report.txt"} {
		if _, err := os.Stat(dir.File(f)); err != nil {
			t.Errorf("run directory lacks %s", f)
		}
	}
	if got, _ := os.ReadFile(dir.File("engagement.yaml")); string(got) != hostAndGitHub {
		t.Errorf("engagement.yaml is not the file as read (it has no redact_extra to mask)")
	}
	var findings FindingsDoc
	b, _ := os.ReadFile(dir.File("findings.json"))
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatal(err)
	}
	web, gh := findings.Assets[0], findings.Assets[1]
	if web.Name != "web" || web.Status != StatusCollected || len(web.Assessments) == 0 || web.Evidence != "evidence/web.json" || web.Threshold != "medium" {
		t.Errorf("web = %+v", web)
	}
	if gh.ID != "saas:github:example-org" || gh.Status != StatusNotCollected || gh.Reason != ReasonCollectorNotBuilt {
		t.Errorf("github = %+v", gh)
	}
	// plan.json names each host's planned and disabled checks, so it
	// reconciles with audit.jsonl.
	var plan PlanDoc
	pb, _ := os.ReadFile(dir.File("plan.json"))
	if err := json.Unmarshal(pb, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Hosts) != 1 || plan.Hosts[0].Name != "web" || len(plan.Hosts[0].Planned) == 0 {
		t.Errorf("plan.json hosts = %+v", plan.Hosts)
	}
	if len(findings.Incomplete) != 1 || findings.Incomplete[0].Asset != "saas:github:example-org" ||
		findings.Incomplete[0].Reason != ReasonCollectorNotBuilt {
		t.Errorf("findings.json incomplete = %+v: {asset, reason, detail}, as the report carries it", findings.Incomplete)
	}
	// The report's trace for the host is its audit.jsonl lines, the canary
	// or first check first.
	audit, _ := os.ReadFile(dir.File("audit.jsonl"))
	trace := out.Report.Assets[0].Trace
	if len(trace) == 0 || len(trace) != strings.Count(string(audit), "\n") {
		t.Errorf("trace has %d entries, audit.jsonl %d lines", len(trace), strings.Count(string(audit), "\n"))
	}
	if out.Open != findings.Open || out.Open != web.Open {
		t.Errorf("open %d, findings.json %d, web %d", out.Open, findings.Open, web.Open)
	}
}

func TestStopAfterEndsTheRunThere(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(hostAndGitHub), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	calls := 0
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(hostAndGitHub), Dir: dir, StopAfter: "scope", Collect: fixtureCollect(t, "ubuntu", &calls)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != "scope" || calls != 0 || len(out.Incomplete) != 0 {
		t.Fatalf("stage %s, %d collections, incomplete %+v", out.Stage, calls, out.Incomplete)
	}
	if _, err := os.Stat(dir.File("recon.json")); err == nil {
		t.Error("recon.json written after --stop-after scope")
	}
	if _, err := Run(context.Background(), res, RunOptions{StopAfter: "facts"}); err == nil {
		t.Error("--stop-after facts ran")
	}
}

// What this build cannot reach is refused before any target is contacted.
func TestScopeRefusesBeforeContact(t *testing.T) {
	for name, file := range map[string]string{
		"jump":    strings.Replace(hostAndGitHub, "elevate: sudo", "jump: ops@198.51.100.7", 1),
		"no user": strings.Replace(hostAndGitHub, "deploy@203.0.113.5", "203.0.113.5", 1),
	} {
		res, err := Parse("engagement.yaml", []byte(file), testOpts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		calls := 0
		_, err = Run(context.Background(), res, RunOptions{Collect: fixtureCollect(t, "ubuntu", &calls)})
		if _, ok := errors.AsType[*Refusal](err); !ok || calls != 0 {
			t.Errorf("%s: err %v after %d collections, want a refusal before any", name, err, calls)
		}
	}
}

// A host that never answered is recorded as failed and the run goes on;
// a usage error from the collector stops it.
func TestCollectorFailures(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(hostAndGitHub), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	unreachable := func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
		return nil, &hostasset.Error{Err: errors.New("ssh: dial 203.0.113.5:22: i/o timeout")}
	}
	out, err := Run(context.Background(), res, RunOptions{Collect: unreachable})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Incomplete) != 2 || !strings.HasPrefix(Describe(out.Incomplete[0]), "web: failed: ssh: dial") {
		t.Fatalf("incomplete = %+v", out.Incomplete)
	}
}

const twoHosts = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - host: deploy@203.0.113.5
  - host: ops@203.0.113.6
`

// A host that refuses us (host key, authentication, canary) is recorded,
// the others are still collected, and every stage is written: nothing read
// from a client's host is discarded because another host refused.
func TestARefusedHostDoesNotDiscardTheOthers(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(twoHosts), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	calls := 0
	fromFixture := fixtureCollect(t, "ubuntu", &calls)
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		if o.Host == "203.0.113.5" {
			return nil, &hostasset.Error{Usage: true, Err: errors.New("ssh: 203.0.113.5 is not in /kh (access refused)")}
		}
		return fromFixture(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(twoHosts), Dir: dir, Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Refused) != 1 || !strings.HasPrefix(Describe(out.Refused[0]), "host:203.0.113.5:22: ssh: 203.0.113.5 is not in") || calls != 1 {
		t.Fatalf("refused %+v after %d collections", out.Refused, calls)
	}
	if out.ExitCode() != 3 || len(out.Report.Findings) == 0 && len(out.Report.Assessments) == 0 {
		t.Errorf("exit %d; the other host must still be assessed", out.ExitCode())
	}
	var findings FindingsDoc
	b, _ := os.ReadFile(dir.File("findings.json"))
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatal(err)
	}
	if findings.Assets[0].Status != StatusRefused || findings.Assets[0].Reason != ReasonRefused ||
		findings.Assets[1].Status != StatusCollected || findings.Assets[1].Evidence == "" {
		t.Fatalf("findings.json assets = %+v", findings.Assets)
	}
}

// The run directory's copy of the file never holds a redact_extra pattern:
// each entry is a marker, and a pattern's match elsewhere (a comment) is
// redacted. The header names the original, and the copy still validates.
func TestEngagementCopyMasksRedactExtra(t *testing.T) {
	file := strings.Replace(hostAndGitHub, "roots:", "# codename project-tangerine, never write it out\nroots:", 1) +
		"redact_extra: [\"project-tangerine\", 'tanger[i]ne-[0-9]+']\n"
	res, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, err := Run(context.Background(), res, RunOptions{Raw: []byte(file), Dir: dir, StopAfter: "intake"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dir.File("engagement.yaml"))
	for _, absent := range []string{"tangerine", "tanger[i]ne"} {
		if strings.Contains(string(got), absent) {
			t.Errorf("the copy holds %q:\n%s", absent, got)
		}
	}
	for _, want := range []string{"[REDACTED:redact_extra:17 bytes]", "[REDACTED:redact_extra:18 bytes]", "[REDACTED:extra:0:17 bytes]", "its sha256 is in each stage document's source"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the copy lacks %q:\n%s", want, got)
		}
	}
	// Masked, it is still an engagement file.
	if _, err := Parse("copy.yaml", got, testOpts); err != nil {
		t.Errorf("the masked copy does not validate: %v", err)
	}
}

// The asset's context and the accepted risks naming it reach the host
// collector; nothing else does.
func TestHostOptionsCarryTheAssetOnly(t *testing.T) {
	file := hostAndGitHub + `    known_hosts: /kh
    timeout: 1m
    disable_checks: [fs.suid]
    deny_paths: [/srv/secret]
    context:
      exposure: internet
      expected_services:
        - {port: 443, proto: tcp, purpose: web, audience: internet}
redact_extra: ["tanger[i]ne"]
people:
  cto: {kind: employee}
intent:
  accepted_risks:
    - {id: sshd.password_auth_enabled, asset: web, reason: legacy, accepted_by: cto}
    - {id: sshd.password_auth_enabled, asset: web, subject: x, reason: narrower, accepted_by: cto}
    - {id: custom:vendor-vpn, asset: web, reason: vendor, accepted_by: cto}
`
	res, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	var got hostasset.Options
	capture := func(_ context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		got = o
		return nil, &hostasset.Error{Err: errors.New("stop")}
	}
	started := time.Date(2026, 10, 7, 7, 12, 3, 0, time.UTC)
	out, err := Run(context.Background(), res, RunOptions{StopAfter: "analyze", Started: started, Collect: capture})
	if err != nil {
		t.Fatal(err)
	}
	findings := out.Document.(*FindingsDoc)
	// Acceptances are graded at the collection time, in engagement.timezone.
	if !got.Now.Equal(started) {
		t.Errorf("graded at %v, want the run's start", got.Now)
	}
	if _, err := time.LoadLocation("Europe/Madrid"); err == nil {
		if z := got.Context.AcceptedRisks[0].Zone; z == nil || z.String() != "Europe/Madrid" {
			t.Errorf("acceptance read in %v, want engagement.timezone Europe/Madrid", z)
		}
	}
	if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "intent.accepted_risks[1] (sshd.password_auth_enabled on web, subject x) not applied") ||
		len(findings.AcceptancesNotApplied) != 1 {
		t.Errorf("warnings %q, findings.json %q", out.Warnings, findings.AcceptancesNotApplied)
	}
	c := got.Context
	if got.Host != "203.0.113.5" || got.Port != 22 || got.User != "deploy" || got.Elevate != "sudo" || got.Profile != "baseline" ||
		got.KnownHosts != "/kh" || got.RunTimeout != time.Minute || len(got.DisableChecks) != 1 || len(got.DenyPaths) != 1 ||
		len(got.RedactExtra) != 1 || c == nil || c.Exposure != "internet" || len(c.ExpectedServices) != 1 ||
		len(c.AcceptedRisks) != 1 || c.AcceptedRisks[0].Reason != "legacy" || c.AcceptedRisks[0].Source != "engagement.yaml intent.accepted_risks[0]" {
		t.Fatalf("options = %+v, context %+v", got, c)
	}
}

// A canary mismatch's echo is attacker-influenced: recon.json and the
// report's JSON keep it apart from the detail, and report.txt never prints it.
func TestCanaryEchoStaysOutOfTheText(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(twoHosts), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	calls := 0
	fromFixture := fixtureCollect(t, "ubuntu", &calls)
	echo := `"\x1b]0;owned\x07"`
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		if o.Host == "203.0.113.5" {
			_ = o.Audit.Log(policy.AuditEntry{CheckID: "sys.canary", Decision: "denied:canary"})
			return nil, &hostasset.Error{Usage: true, Kind: "canary", Err: errors.New("ssh canary mismatch"), Echo: echo}
		}
		return fromFixture(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(twoHosts), Dir: dir, Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	if out.Report.Refused[0].Echo != echo || strings.Contains(out.Report.Refused[0].Detail, "owned") || out.Report.Refused[0].Kind != "canary" {
		t.Errorf("refused %+v: the echo belongs in its own field", out.Report.Refused[0])
	}
	// The refused host was touched by the canary: its trace says so.
	if tr := out.Report.Assets[0].Trace; len(tr) != 1 || tr[0].Check != "sys.canary" || tr[0].Decision != "denied:canary" {
		t.Errorf("refused host's trace %+v", tr)
	}
	txt, _ := os.ReadFile(dir.File("report.txt"))
	js, _ := os.ReadFile(dir.File("report.json"))
	if strings.Contains(string(txt), "owned") || !strings.Contains(string(js), "owned") {
		t.Error("the echo must be in report.json only")
	}
}

// Under --no-persist nothing is written, and the report still carries each
// host's command trace.
func TestNoPersistKeepsTheTraceInTheReport(t *testing.T) {
	res, err := Parse("engagement.yaml", []byte(hostAndGitHub), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	out, err := Run(context.Background(), res, RunOptions{Collect: fixtureCollect(t, "ubuntu", &calls)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Assets[0].Trace) == 0 || out.Report.Run.Directory != nil {
		t.Errorf("trace %d entries, directory %v", len(out.Report.Assets[0].Trace), out.Report.Run.Directory)
	}
}

// The paste a --host report prints validates once the engagement is
// written to a file and someone is added under people (docs/ROADMAP.md, E2
// "Done when").
func TestHostPasteValidatesAgainstTheWrittenFile(t *testing.T) {
	res, raw, err := ForHost("deploy@203.0.113.5", HostFlags{}, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	out, err := Run(context.Background(), res, RunOptions{Raw: raw, Collect: fixtureCollect(t, "macos", &calls)})
	if err != nil {
		t.Fatal(err)
	}
	var tmpl *ereport.AcceptTemplate
	for _, f := range out.Report.Findings {
		if f.AcceptTemplate != nil {
			tmpl = f.AcceptTemplate
			break
		}
	}
	if tmpl == nil || !tmpl.NeedsPeople {
		t.Fatalf("paste %+v: a --host engagement has no people", tmpl)
	}
	file := string(raw) + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n" +
		"    - {id: " + tmpl.ID + ", asset: " + tmpl.Asset + ", reason: patch window, accepted_by: alice, expires: " + tmpl.Expires + "}\n"
	written, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatalf("the pasted entry does not validate:\n%s\n%v", file, err)
	}
	if id, ok := written.AssetID(tmpl.Asset); !ok || id != res.Assets[0].ID {
		t.Errorf("asset %q resolves to %q, want %s", tmpl.Asset, id, res.Assets[0].ID)
	}
}
