package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
)

var update = flag.Bool("update", false, "rewrite the golden engagement reports")

// canaryRefused is a host whose remote shell altered the canary: refused,
// its echo kept for the JSON only.
func canaryRefused(t *testing.T) Input {
	in := refusedHost(t)
	in.Assets[1].Detail = "ssh canary mismatch: the remote shell returned 31 bytes, not the canary (exit 0)"
	in.Assets[1].Echo = "\"\\x1b[2Jowned \\x1b]0;title\\x07\""
	in.Assets[1].Refusal = "canary"
	in.Assets[1].Trace = []policy.AuditEntry{{CheckID: "sys.canary", Decision: "denied:canary", Time: started}}
	in.Directory = "/state/engagements/example/2026-10-07T07:12:03Z"
	return in
}

// jumpRefused is a host behind a jump host whose key is unknown, beside a
// host that was read through a jump host: the hop is named, nothing ran
// on it, and the refused host was never contacted.
func jumpRefused(t *testing.T) Input {
	in := refusedHost(t)
	in.Assets[0].Via = "ops@bastion.example.com:22"
	in.Assets[1].Via = "ops@bastion.example.com:22"
	in.Assets[1].Detail = "ssh: jump host bastion.example.com:22: host key unknown (jump host)"
	in.Assets[1].Refusal = "jump_host_key_unknown"
	// Both went through the jump host; only the first got past it.
	in.Assets[0].JumpContact, in.Assets[1].JumpContact, in.Assets[1].Contact = "connected", "connected", ""
	// The jump host is written as a name, which this machine resolved.
	in.Egress = &EgressInput{SSHResolved: []string{"bastion.example.com"}}
	return in
}

// The engagement report is a contract like the host report
// (docs/spec/host-collector.md §9): text and JSON are pinned per case.
// Regenerate with `go test ./internal/engagement/report -update` and read
// the diff: a change here is a change to what an operator reads.
func TestGoldenReports(t *testing.T) {
	s := schema(t)
	cases := map[string]func(*testing.T) Input{
		"host-ubuntu": func(t *testing.T) Input { return oneHost(t, "ubuntu") },
		"host-macos": func(t *testing.T) Input {
			// A host written as a name: SSH asked the system's resolver.
			in := oneHost(t, "macos")
			in.Egress = &EgressInput{SSHResolved: []string{"macos"}}
			return in
		},
		"root-without-collector":            withGitHubRoot,
		"github-alerts-fired":               githubAlertsFiredReport,
		"github-alerts-disproved":           githubAlertsDisprovedReport,
		"github-alerts-abstained":           githubAlertsAbstainedReport,
		"github-inventory":                  githubInventoryReport,
		"github-ci-fired":                   githubCIFiredReport,
		"github-ci-disproved":               githubCIDisprovedReport,
		"github-ci-abstained":               githubCIAbstainedReport,
		"github-access-fired":               githubAccessFiredReport,
		"github-access-disproved":           githubAccessDisprovedReport,
		"github-access-abstained":           githubAccessAbstainedReport,
		"github-inventory-partial":          githubPartialInventoryReport,
		"github-inventory-principal-change": githubChangedPrincipalReport,
		"github-inventory-with-web":         githubAndWebInventoryReport,
		"domain-root":                       withDomainRoot,
		"takeover-root":                     withTakeoverRoot,
		"email-root":                        withEmailRoot,
		"web-root":                          withWebRoot,
		"restricted-internet":               func(t *testing.T) Input { return restrictedReport(t, "internet", false) },
		"restricted-unknown":                func(t *testing.T) Input { return restrictedReport(t, "", false) },
		"restricted-vpn":                    func(t *testing.T) Input { return restrictedReport(t, "vpn", false) },
		"restricted-resumed":                func(t *testing.T) Input { return restrictedReport(t, "internet", true) },
		"lost-session":                      lostSession,
		"refused-host":                      canaryRefused,
		"jump-refused":                      jumpRefused,
		"unreachable-host":                  unreachableHost,
		"many-findings":                     manyFindings,
		"context":                           withContext,
		"acceptances":                       withAcceptances,
		"resumed": func(t *testing.T) Input {
			// A resumed run: its first session asked a DNS resolver and
			// reached the host, then ended before recording all it sent;
			// this session kept the host, and a record it kept was edited
			// by hand.
			in := oneHost(t, "ubuntu")
			in.Resumed, in.EditedByHand = true, []string{"evidence/deploy.collection.json"}
			in.Assets[0].Kept = true
			in.Directory = "/home/ops/.local/state/scheck/engagements/acme/2026-10-07T07:12:03Z"
			in.Egress = &EgressInput{Unrecorded: []time.Time{in.Started},
				Sources:  []SourceInput{{Source: "dns", Operator: "your network", Host: "192.0.2.53", Requests: 4}},
				Contacts: []HostContact{{ID: in.Assets[0].ID, Status: "collected", Contact: "connected"}}}
			return in
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			in := mk(t)
			if in.Egress == nil {
				in.Egress = &EgressInput{}
			}
			// What the run passes on from the gate.
			in.Egress.UserAgent = "scheck/test (security self-assessment)"
			r := Build(in)
			validate(t, s, r)
			for _, v := range []int{0, 1} {
				var txt bytes.Buffer
				if err := WriteText(&txt, r, Options{Verbose: v}); err != nil {
					t.Fatal(err)
				}
				suffix := map[int]string{0: ".txt", 1: "-v.txt"}[v]
				compareGolden(t, name+suffix, txt.String())
			}
			var js bytes.Buffer
			if err := WriteJSON(&js, r, false); err != nil {
				t.Fatal(err)
			}
			compareGolden(t, name+".json", elideEnvelopes(t, js.Bytes()))
		})
	}
}

// elideEnvelopes replaces each embedded host envelope by its schema
// version: internal/report pins the envelope's own goldens, and repeating
// them here would add bulk and no signal.
func elideEnvelopes(t *testing.T, raw []byte) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, a := range doc["assets"].([]any) {
		asset := a.(map[string]any)
		if env, ok := asset["envelope"].(map[string]any); ok {
			asset["envelope"] = map[string]any{"schema_version": env["schema_version"], "elided": "pinned by internal/report goldens"}
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out) + "\n"
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden; run with -update and read the diff.\n--- got ---\n%s", name, got)
	}
}

// The text report never prints a reason or mark token, never prints the
// canary echo, and escapes every control character a target sent
// (docs/spec/report.md, "Words, not tokens", "What never appears").
func TestTextIsWordsAndSafe(t *testing.T) {
	for _, mk := range []func(*testing.T) Input{withGitHubRoot, lostSession, canaryRefused, withAcceptances,
		func(t *testing.T) Input { return oneHost(t, "ubuntu") }} {
		r := Build(mk(t))
		var buf bytes.Buffer
		if err := WriteText(&buf, r, Options{}); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		for _, token := range []string{"not_assessed", "no_rule", "not_declared", "collector_not_built", "insufficient_permission",
			"unavailable:", "limit_reached", "outside_scheck", "partial"} {
			if strings.Contains(out, token) {
				t.Errorf("%s: the text prints the token %q", r.Engagement.Name, token)
			}
		}
		if strings.Contains(out, "owned") || strings.ContainsRune(out, '\x1b') || strings.ContainsRune(out, '\x07') {
			t.Errorf("%s: the canary echo or a control character reached the text", r.Engagement.Name)
		}
		for l := range strings.SplitSeq(out, "\n") {
			if len([]rune(l)) > 100 {
				t.Errorf("%s: line over 100 columns: %q", r.Engagement.Name, l)
			}
		}
	}
}

// unreachableHost is a declared host that never answered: failed before
// contact, exit 2, worded as unreachable, never as a lost connection.
func unreachableHost(t *testing.T) Input {
	in := oneHost(t, "ubuntu")
	in.FromHost, in.Path, in.Rerun = false, "engagement.yaml", "scheck run engagement.yaml"
	in.Assets = append(in.Assets, AssetInput{Name: "deploy", ID: "host:203.0.113.5:22", Kind: "host", Root: true,
		Status: "failed", Reason: "failed", Detail: "ssh: dial 203.0.113.5:22: i/o timeout (host unreachable)", Profile: "baseline",
		Contact: "unreached"})
	return in
}

// manyFindings has six open finding ids at medium or above, each with the
// evidence its own rule reads: five rank, and the summary says one more does.
// The empty password is the rule's own output over edited captures, since an
// injected `backup NP` once showed a finding its fixture's shell disproves.
func manyFindings(t *testing.T) Input {
	in := oneHost(t, "ubuntu")
	env := &in.Assets[0].Host.Envelope
	f, a := ruleFinding(t, finding.IDEmptyPassword, map[string]string{
		"accounts.passwd_status": "root L 2026-09-11 0 99999 7 -1\nops NP 2026-09-11 0 99999 7 -1",
		"accounts.passwd":        "root:x:0:0:root:/root:/bin/bash\nops:x:1001:1001::/home/ops:/bin/bash",
	})
	env.Findings = append(env.Findings, f)
	// Its assessment comes from the same run, so the report does not say the
	// rule was disproved beside the finding it raised. The fact sheet still
	// summarizes the fixture's captures, in which every account is locked.
	for i := range env.Assessments {
		if env.Assessments[i].Finding == finding.IDEmptyPassword {
			env.Assessments[i] = a
		}
	}
	for _, f := range []struct{ id, check, excerpt string }{
		{finding.IDShadowPermissions, "accounts.shadow_meta", "-rw-r--rw-:646:root:shadow"},
		{finding.IDRootLoginEnabled, "sshd.config", "permitrootlogin yes"},
		{finding.IDPasswordAuthEnabled, "sshd.config", "passwordauthentication yes"},
		{finding.IDWorldWritablePresent, "fs.world_writable", "/opt/app/uploads"},
		{finding.IDSELinuxDisabled, "mac.sestatus", "SELinux status: disabled"},
	} {
		def, _ := finding.Lookup(f.id)
		env.Findings = append(env.Findings, finding.Finding{ID: f.id, Title: def.Title, Category: def.Category,
			SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity, Adjustments: []finding.Adjustment{}, Status: finding.StatusOpen,
			Source: finding.SourceRule, Confidence: finding.ConfidenceHigh, Platform: "linux",
			Evidence: []finding.Evidence{{Observation: f.check + "#1", Check: f.check, Excerpt: f.excerpt}},
			Impact:   def.Impact, Remediation: def.Remediation})
	}
	return in
}

// withContext is an engagement file that exercises the context path: an
// incident trigger, a host declared internet-facing (its firewall finding
// raised), narrowing, an operator redaction rule, data that matters most, an
// acceptance with no expiry, a declared tool no collector reads and an
// exclude.
func withContext(t *testing.T) Input {
	in := oneHost(t, "macos")
	in.FromHost, in.Path, in.Rerun, in.People = false, "engagement.yaml", "scheck run engagement.yaml", true
	in.Operator, in.Trigger, in.RedactExtra = "platform-team", "incident", 1
	in.Candidates = []Candidate{{Handle: "alice", Why: "employee"}}
	in.DataMattersMost = []string{"host:macos:22"}
	in.OtherTools = []string{"stripe"}
	in.Excludes = []string{"repo:github:example-org/old"}
	in.Declarations = []Declaration{{Area: "data", Source: "engagement.yaml data.backups[0]",
		Detail: "backups declared in a nightly snapshot (gcp:example-backups), not verified"}}
	a := &in.Assets[0]
	a.Host.Disabled = []Entry{{Value: "fs.suid", Source: "engagement.yaml assets.macos.disable_checks[0]"}}
	env := &a.Host.Envelope
	for i, f := range env.Findings {
		switch f.ID {
		case finding.IDAppFirewallDisabled:
			env.Findings[i].Severity = finding.SevHigh
			env.Findings[i].Adjustments = []finding.Adjustment{{Rule: "exposure:internet",
				Source: "engagement.yaml assets.macos#context.exposure", Delta: "+1"}}
		case finding.IDUpdatesPending:
			env.Findings[i].Status, env.Findings[i].AcceptedReason = finding.StatusAccepted, "the vendor ships updates monthly"
		}
	}
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDUpdatesPending,
		Asset: "macos", AssetID: "host:macos:22", Reason: "the vendor ships updates monthly", AcceptedBy: "alice"}}
	return in
}

// ruleFinding runs the posture rules over the given captures and returns the
// finding id they raise and its assessment, so a golden shows what a rule
// really produces.
func ruleFinding(t *testing.T, id string, raw map[string]string) (finding.Finding, finding.Assessment) {
	t.Helper()
	sheet := &baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{}}
	for cid, out := range raw {
		c, ok := check.Lookup(cid, check.Linux)
		if !ok {
			t.Fatalf("%s is not a Linux catalog id", cid)
		}
		parsed, err := check.Parse(c, []byte(out))
		if err != nil {
			t.Fatal(err)
		}
		sheet.Results[cid] = runner.Result{CheckID: cid, Status: runner.StatusOK, Attempted: true, Raw: out,
			Parsed: parsed, Observation: cid + "#1"}
	}
	res := finding.Evaluate(finding.Input{Sheet: sheet})
	for _, f := range res.Findings {
		if f.ID != id {
			continue
		}
		for _, a := range res.Assessments {
			if a.Finding == id {
				return f, a
			}
		}
	}
	t.Fatalf("the rules raised no %s over %v", id, raw)
	return finding.Finding{}, finding.Assessment{}
}
