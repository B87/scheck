package finding

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the real catalog the rules are bound to
	"github.com/b87/scheck/internal/runner"
)

// sheet builds a fact sheet by running the catalog's own parser over the raw
// output a check would have produced, so a rule test exercises the parser it
// depends on rather than a hand-built value.
func sheet(t *testing.T, platform check.Platform, raw map[string]string) *baseline.FactSheet {
	t.Helper()
	fs := &baseline.FactSheet{Platform: platform, Results: map[string]runner.Result{}}
	for id, out := range raw {
		c, ok := check.Lookup(id, platform)
		if !ok {
			t.Fatalf("%s is not a catalog id on %s", id, platform)
		}
		parsed, err := check.Parse(c, []byte(out))
		if err != nil {
			fs.Results[id] = runner.Result{CheckID: id, Status: runner.StatusUnavailable,
				Attempted: true, Reason: "parse error: " + err.Error(), ReasonCode: "parse_error"}
			continue
		}
		fs.Results[id] = runner.Result{CheckID: id, Status: runner.StatusOK, Attempted: true, Raw: out, Parsed: parsed}
	}
	fs.Order = append(fs.Order, "")
	return fs
}

func assessmentFor(res Result, findingID, checkID string) (Assessment, bool) {
	for _, a := range res.Assessments {
		if a.Finding == findingID && a.Check == checkID {
			return a, true
		}
	}
	return Assessment{}, false
}

// Every rule in the seed table (docs/SPEC.md §7.5) needs three fixtures: one
// where it fires, one where the evidence disproves it, and one where the
// evidence does not settle the question. The third is the one that matters:
// an answer scheck does not recognise is never read as a pass.
func TestEveryRuleFiresDisprovesAndAbstains(t *testing.T) {
	cases := []struct {
		finding   string
		check     string
		platform  check.Platform
		fires     string
		disproves string
		abstains  string
	}{
		{IDFileVaultOff, "disk.fdesetup", check.MacOS,
			"FileVault is Off.", "FileVault is On.",
			"Deferred enablement appears to be active for user alice."},
		{IDSIPDisabled, "integrity.csrutil", check.MacOS,
			"System Integrity Protection status: disabled.",
			"System Integrity Protection status: enabled.",
			"System Integrity Protection status: unknown (custom configuration)."},
		{IDGatekeeperDisabled, "integrity.spctl", check.MacOS,
			"assessments disabled", "assessments enabled", "developer mode enabled"},
		{IDAppFirewallDisabled, "fw.global", check.MacOS,
			"Firewall is disabled. (State = 0)", "Firewall is enabled. (State = 1)",
			"Firewall state could not be determined"},
		{IDRemoteLoginEnabled, "remote.login", check.MacOS,
			"Remote Login: On", "Remote Login: Off", "Remote Login: unknown"},
		{IDNTPDisabled, "time.ntp", check.MacOS,
			"Network Time: Off", "Network Time: On", "Network Time: unsupported"},
		{IDPasswordAuthEnabled, "sshd.config", check.Linux,
			"passwordauthentication yes", "passwordauthentication no", "passwordauthentication maybe"},
		{IDRootLoginEnabled, "sshd.config", check.Linux,
			"permitrootlogin yes", "permitrootlogin prohibit-password", "permitrootlogin sometimes"},
		{IDEmptyPassword, "accounts.passwd_status", check.Linux,
			"root L 2026-09-11\nalice NP 2026-09-11", "root L 2026-09-11\nalice P 2026-09-11",
			"root L 2026-09-11\nalice ?? 2026-09-11"},
		{IDShadowPermissions, "accounts.shadow_meta", check.Linux,
			"-rw-rw-rw-:666:root:root:577", "-rw-r-----:640:root:shadow:577",
			"-rw-r-----:rwx:root:shadow:577"},
		{IDSELinuxDisabled, "mac.sestatus", check.Linux,
			"SELinux status:                 disabled", "SELinux status:                 enabled",
			"SELinux status:                 unsupported"},
		{IDAuditdInactive, "log.auditd", check.Linux, "inactive", "active", "Failed to connect to bus"},
		{IDNTPUnsynced, "time.timedatectl", check.Linux,
			"NTPSynchronized=no", "NTPSynchronized=yes", "NTPSynchronized=n/a"},
		{IDUpdatesPending, "pkg.apt_upgradable", check.Linux,
			"Listing...\nbash/noble-updates 5.2-2 arm64 [upgradable from: 5.2-1]",
			"Listing...", "Listing...\n[TRUNCATED:2048 bytes]"},
		{IDUpdatesPending, "pkg.dnf_check_update", check.Linux,
			"zstd.aarch64 1.5.7-1.fc40 updates", "", "[TRUNCATED:2048 bytes]"},
		{IDUpdatesPending, "pkg.zypper_lp", check.Linux,
			"Repository | Name | Current | Available\n-----------+------+---------+----------\nrepo-oss | bash | 5.2-1 | 5.2-2",
			"No updates found.", "[TRUNCATED:2048 bytes]"},
		{IDUpdatesPending, "pkg.softwareupdate", check.MacOS,
			"Software Update found the following new or updated software:\n* Label: Safari-27\n\tTitle: Safari, Version: 27.0,",
			"No new software available.", "[TRUNCATED:2048 bytes]"},
		{IDWorldWritablePresent, "fs.world_writable", check.Linux,
			"/opt/shared", "", "[TRUNCATED:900 bytes]"},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.finding+" "+tc.check] = true
		for _, step := range []struct {
			name string
			raw  string
			want string
		}{
			{"fires", tc.fires, Matched},
			{"disproves", tc.disproves, NotMatched},
			{"abstains", tc.abstains, NotAssessed},
		} {
			t.Run(tc.finding+"/"+tc.check+"/"+step.name, func(t *testing.T) {
				res := Evaluate(Input{Sheet: sheet(t, tc.platform, map[string]string{tc.check: step.raw})})
				a, ok := assessmentFor(res, tc.finding, tc.check)
				if !ok {
					t.Fatalf("no assessment for %s via %s", tc.finding, tc.check)
				}
				if a.Status != step.want {
					t.Fatalf("status %q (%s), want %q", a.Status, a.Reason, step.want)
				}
				found := 0
				for _, f := range res.Findings {
					if f.ID == tc.finding {
						found++
						if f.Source != SourceRule || f.Confidence != "high" || !f.Open() {
							t.Errorf("rule finding shape: %+v", f)
						}
						if len(f.Evidence) == 0 || f.Evidence[0].Check != tc.check || f.Evidence[0].Excerpt == "" {
							t.Errorf("evidence must name the check and the excerpt: %+v", f.Evidence)
						}
					}
				}
				if (found > 0) != (step.want == Matched) {
					t.Errorf("%d findings for status %s", found, a.Status)
				}
			})
		}
	}
	// Every rule in the compiled-in table is covered by the cases above; a
	// new rule without fixtures fails here rather than shipping untested.
	for _, r := range Rules() {
		if !seen[r.Finding+" "+r.Check] {
			t.Errorf("rule %s via %s has no firing/non-firing/insufficient fixtures", r.Finding, r.Check)
		}
	}
}

// Evidence that is missing, refused, incomplete or unreadable leaves a rule
// not assessed — never matched and never passed (docs/SPEC.md §7.5).
func TestInsufficientEvidenceIsNeverAPass(t *testing.T) {
	const id = IDPasswordAuthEnabled
	cases := []struct {
		name   string
		result runner.Result
		want   string
		reason string
	}{
		{"unavailable", runner.Result{Status: runner.StatusUnavailable, Reason: "requires elevated read", ReasonCode: "requires_elevation"},
			NotAssessed, "check-unavailable:requires_elevation"},
		{"denied", runner.Result{Status: runner.StatusDenied, Reason: "deny-path: /etc/ssh", ReasonCode: "path_denied"},
			NotAssessed, "check-denied:path_denied"},
		{"parse error", runner.Result{Status: runner.StatusUnavailable, Reason: "parse error: x", ReasonCode: "parse_error"},
			NotAssessed, "check-unavailable:parse_error"},
		{"key absent", runner.Result{Status: runner.StatusOK, Parsed: map[string]string{"port": "22"}},
			NotAssessed, "key-absent"},
		{"redacted value", runner.Result{Status: runner.StatusOK, Parsed: map[string]string{"passwordauthentication": "[REDACTED:kv-secret:3 bytes]"}},
			NotAssessed, "value-redacted-or-truncated"},
		{"unknown value", runner.Result{Status: runner.StatusOK, Parsed: map[string]string{"passwordauthentication": "sometimes"}},
			NotAssessed, "unrecognized-value"},
		{"wrong shape", runner.Result{Status: runner.StatusOK, Parsed: []string{"passwordauthentication yes"}},
			NotAssessed, "unexpected-parsed-shape"},
		{"disproved", runner.Result{Status: runner.StatusOK, Parsed: map[string]string{"passwordauthentication": "no"}},
			NotMatched, "recognized-other-value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &baseline.FactSheet{Platform: check.Linux, Results: map[string]runner.Result{"sshd.config": tc.result}}
			res := Evaluate(Input{Sheet: fs})
			a, _ := assessmentFor(res, id, "sshd.config")
			if a.Status != tc.want || a.Reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", a.Status, a.Reason, tc.want, tc.reason)
			}
			if len(res.Findings) != 0 {
				t.Fatalf("insufficient evidence produced a finding: %+v", res.Findings)
			}
		})
	}
}

// A truncated capture can still prove an existential condition, but never
// its absence (docs/SPEC.md §7.5).
func TestPartialEvidenceProvesPresenceNotAbsence(t *testing.T) {
	present := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{
		"fs.world_writable": "/opt/shared\n[TRUNCATED:400 bytes]"})})
	a, _ := assessmentFor(present, IDWorldWritablePresent, "fs.world_writable")
	if a.Status != Matched {
		t.Errorf("a complete matching line in partial output still proves presence: %+v", a)
	}
	absent := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{
		"fs.world_writable": "[TRUNCATED:400 bytes]"})})
	a, _ = assessmentFor(absent, IDWorldWritablePresent, "fs.world_writable")
	if a.Status != NotAssessed || a.Reason != "partial-output" {
		t.Errorf("absence claimed from partial output: %+v", a)
	}
}

// Applicability must be known: a rule whose check does not exist on this
// platform is not applicable, a rule whose check was disabled or never ran is
// not assessed, and neither is a pass (docs/SPEC.md §7.5).
func TestApplicabilityAndDisabledChecks(t *testing.T) {
	// disk.fdesetup is macOS-only, so its rule cannot apply to a Linux host.
	// The platform gate omits it; a rule bound to a check the platform
	// catalog lacks would be not_applicable.
	linux := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{"sshd.config": "passwordauthentication no"})})
	if _, ok := assessmentFor(linux, IDFileVaultOff, "disk.fdesetup"); ok {
		t.Error("a macOS rule was assessed on a Linux host")
	}
	if a, _ := assessmentFor(linux, IDNTPUnsynced, "time.timedatectl"); a.Status != NotAssessed || a.Reason != "check-not-run" {
		t.Errorf("a check that never ran: %+v", a)
	}
	disabled := Evaluate(Input{
		Sheet:    sheet(t, check.Linux, map[string]string{"sshd.config": "passwordauthentication yes"}),
		Disabled: []string{"sshd.config"},
	})
	a, _ := assessmentFor(disabled, IDPasswordAuthEnabled, "sshd.config")
	if a.Status != NotAssessed || a.Reason != "check-disabled-by-config" {
		t.Fatalf("disabled check: %+v", a)
	}
	if len(disabled.Findings) != 0 {
		t.Fatal("a disabled check still produced a finding")
	}
}

// Two package managers on one host are two rules behind one finding id: the
// finding appears once, with both excerpts as evidence.
func TestSameFindingFromTwoChecksMergesEvidence(t *testing.T) {
	res := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{
		"pkg.apt_upgradable":   "Listing...\nbash/noble 5.2-2 arm64 [upgradable from: 5.2-1]",
		"pkg.dnf_check_update": "zstd.aarch64 1.5.7-1.fc40 updates",
	})})
	n := 0
	for _, f := range res.Findings {
		if f.ID == IDUpdatesPending {
			n++
			if len(f.Evidence) != 2 {
				t.Errorf("want both checks as evidence, got %+v", f.Evidence)
			}
		}
	}
	if n != 1 {
		t.Errorf("finding id emitted %d times", n)
	}
}

// Severity comes from the table, the profile decides what fails the run, and
// info never does (docs/SPEC.md §7.2, §8).
func TestSeverityThresholdsPerProfile(t *testing.T) {
	if Threshold(check.ProfileBaseline) != SevMedium || Threshold(check.ProfileHardened) != SevLow {
		t.Fatal("profile thresholds")
	}
	fs := []Finding{
		{ID: "a", Severity: SevLow, Status: StatusOpen},
		{ID: "b", Severity: SevInfo, Status: StatusOpen},
	}
	if n := OpenAtOrAbove(fs, Threshold(check.ProfileBaseline)); n != 0 {
		t.Errorf("baseline counted %d findings below medium", n)
	}
	if n := OpenAtOrAbove(fs, Threshold(check.ProfileHardened)); n != 1 {
		t.Errorf("hardened should count the low finding, got %d", n)
	}
	fs = append(fs, Finding{ID: "c", Severity: SevCritical, Status: StatusAccepted})
	if n := OpenAtOrAbove(fs, Threshold(check.ProfileBaseline)); n != 0 {
		t.Errorf("an accepted finding must not set the exit code, got %d", n)
	}
}

// Findings are ordered by severity so the worst thing is the first thing read.
func TestFindingsSortedBySeverity(t *testing.T) {
	res := Evaluate(Input{Sheet: sheet(t, check.MacOS, map[string]string{
		"disk.fdesetup":      "FileVault is Off.",
		"fw.global":          "Firewall is disabled. (State = 0)",
		"remote.login":       "Remote Login: On",
		"pkg.softwareupdate": "* Label: Safari-27\n\tTitle: Safari, Version: 27.0,",
	})})
	var got []string
	for _, f := range res.Findings {
		got = append(got, string(f.Severity))
	}
	want := "high medium low info"
	if strings.Join(got, " ") != want {
		t.Errorf("order %v, want %s", got, want)
	}
}

// A marker line is a record of removed bytes, never a line of output: it must
// not satisfy an existential predicate (docs/SPEC.md §4.2, §7.5).
func TestTruncationMarkerIsNotEvidence(t *testing.T) {
	res := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{
		"fs.world_writable": "[TRUNCATED:900 bytes]"})})
	if len(res.Findings) != 0 {
		t.Fatalf("a truncation marker was read as a world-writable path: %+v", res.Findings)
	}
	// A line whose content was partly redacted still proves the path exists.
	redacted := Evaluate(Input{Sheet: sheet(t, check.Linux, map[string]string{
		"fs.world_writable": "/opt/backup-[REDACTED:aws-access-key:20 bytes]/dump"})})
	a, _ := assessmentFor(redacted, IDWorldWritablePresent, "fs.world_writable")
	if a.Status != Matched {
		t.Fatalf("a redacted path is still a path: %+v", a)
	}
	if !strings.Contains(redacted.Findings[0].Evidence[0].Excerpt, "[REDACTED:") {
		t.Errorf("the excerpt must carry the marker: %q", redacted.Findings[0].Evidence[0].Excerpt)
	}
}
