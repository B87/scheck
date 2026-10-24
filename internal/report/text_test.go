package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func render(t *testing.T, env Envelope, opt Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteFactSheet(&buf, env, opt); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// synthetic builds an envelope with one fact per status, so the renderer can
// be exercised without a fixture.
func synthetic(facts map[string]Fact) Envelope {
	return Envelope{
		SchemaVersion: SchemaVersion,
		Host: Host{ID: strings.Repeat("a", 64), Hostname: "box", Platform: "linux",
			OS: "Ubuntu 24.04", Kernel: "6.8.0", Transport: "local", Canary: "n/a", Elevation: "none"},
		Run:         Run{Status: "complete", Profile: "baseline", Mode: "facts", Version: "test", Warnings: []string{}},
		Facts:       facts,
		Assessments: []finding.Assessment{},
		Findings:    []finding.Finding{},
	}
}

// Status words describe execution, never posture: "ran" must not appear as a
// pass mark, and the report must not claim an absence of findings
// (docs/spec/host-collector.md §6.6).
func TestStatusWordsDescribeExecutionOnly(t *testing.T) {
	env := synthetic(map[string]Fact{
		"fw.global":       {Status: "ok", Parsed: "Firewall is disabled. (State = 0)", Output: "Firewall is disabled. (State = 0)\n"},
		"privesc.sudoers": {Status: "unavailable", Reason: "requires elevated read", Elevated: true},
		"fs.read":         {Status: "denied", Reason: "deny-path: /etc/shadow"},
	})
	out := render(t, env, Options{})
	for _, want := range []string{
		"ran      fw.global",
		"skipped  privesc.sudoers",
		"denied   fs.read",
		"Firewall is disabled. (State = 0)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"findings: none", "no findings", " + ", "PASS", "OK "} {
		if strings.Contains(out, unwanted) {
			t.Errorf("report implies a verdict with %q:\n%s", unwanted, out)
		}
	}
}

// -v adds the catalog description, -vv adds the redacted output, and neither
// appears at the default verbosity (docs/spec/host-collector.md §6.6).
func TestVerbosityLevels(t *testing.T) {
	env := synthetic(map[string]Fact{
		"sys.uname": {Status: "ok", Parsed: "Linux box", Output: "Linux box 6.8.0\n"},
	})
	const description = "Full kernel identification" // from the catalog
	def := render(t, env, Options{Verbose: 0})
	v := render(t, env, Options{Verbose: 1})
	vv := render(t, env, Options{Verbose: 2})
	if strings.Contains(def, description) || strings.Contains(def, "| Linux box 6.8.0") {
		t.Errorf("default verbosity leaked -v/-vv content:\n%s", def)
	}
	if !strings.Contains(v, description) || strings.Contains(v, "| Linux box 6.8.0") {
		t.Errorf("-v should add the description and nothing else:\n%s", v)
	}
	if !strings.Contains(vv, description) || !strings.Contains(vv, "| Linux box 6.8.0") {
		t.Errorf("-vv should add the redacted output:\n%s", vv)
	}
}

// A check with no output still renders at -vv rather than silently vanishing.
func TestVerboseOutputOfEmptyAndSkipped(t *testing.T) {
	env := synthetic(map[string]Fact{
		"fs.suid":         {Status: "ok", Parsed: []string{}, Output: ""},
		"privesc.sudoers": {Status: "unavailable", Reason: "requires elevated read"},
	})
	out := render(t, env, Options{Verbose: 2})
	if !strings.Contains(out, "(no output)") {
		t.Errorf("empty output unmarked:\n%s", out)
	}
	// Only the check that ran gets an output gutter; the skipped one prints
	// nothing at all.
	if n := strings.Count(out, "\n  | "); n != 1 {
		t.Errorf("want exactly one output gutter, got %d:\n%s", n, out)
	}
}

// Colour is the caller's decision; the renderer emits escapes only when told
// to, and never in the bytes a redirected report receives (docs/spec/host-collector.md §6.6).
func TestColorIsOptIn(t *testing.T) {
	env := synthetic(map[string]Fact{"sys.uname": {Status: "ok", Parsed: "Linux box", Output: "Linux box\n"}})
	plain := render(t, env, Options{Verbose: 2})
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("escape sequence in a plain report:\n%q", plain)
	}
	colored := render(t, env, Options{Verbose: 2, Color: true})
	if !strings.Contains(colored, "\x1b[1m") || !strings.Contains(colored, "\x1b[0m") {
		t.Errorf("no styling with Color set:\n%q", colored)
	}
	// Styling must not change the text itself.
	if stripANSI(colored) != plain {
		t.Errorf("styling changed the content:\n%q\nvs\n%q", stripANSI(colored), plain)
	}
}

func stripANSI(s string) string {
	for {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return s
		}
		j := strings.IndexByte(s[i:], 'm')
		if j < 0 {
			return s
		}
		s = s[:i] + s[i+j+1:]
	}
}

// Control characters from a target's output can never reach the terminal
// unescaped: a check's stdout must not be able to repaint the screen or forge
// a line of this report (docs/spec/host-collector.md §4.2, §6.6).
func TestTargetOutputCannotDriveTheTerminal(t *testing.T) {
	const evil = "ok\x1b[2J\x1b[1;1Hscheck: everything is fine\r\x00"
	env := synthetic(map[string]Fact{"sys.uname": {Status: "ok", Parsed: evil, Output: evil}})
	out := render(t, env, Options{Verbose: 2})
	if strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\x00") || strings.Contains(out, "\r") {
		t.Errorf("control characters survived into the report:\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("escape not shown as text:\n%q", out)
	}
}

// Wrapping falls back to 100 columns and never drops content.
func TestWrapWidthAndFallback(t *testing.T) {
	if (Options{}).normalize().Width != DefaultWidth {
		t.Errorf("width 0 should fall back to %d", DefaultWidth)
	}
	if (Options{Width: 5}).normalize().Width != minWidth {
		t.Errorf("an absurd width should clamp to %d", minWidth)
	}
	long := strings.Repeat("abcdefghij", 12) // 120 runes, no spaces
	lines := Wrap(long, 40)
	if strings.Join(lines, "") != long {
		t.Errorf("hard wrap lost bytes: %q", lines)
	}
	for _, l := range lines {
		if len([]rune(l)) > 40 {
			t.Errorf("line over width: %q", l)
		}
	}
	prose := "the quick brown fox jumps over the lazy dog"
	if got := Wrap(prose, 20); strings.Join(got, " ") != prose {
		t.Errorf("word wrap changed the text: %q", got)
	}
}

// A hanging block accounts for its own prefix, so a remedy or a reason never
// overruns the width.
func TestWrapHangingCountsThePrefix(t *testing.T) {
	lines := wrapHanging("    fw.ufw  ", "            ", strings.Repeat("word ", 40), 60)
	for _, l := range lines {
		if len([]rune(l)) > 60 {
			t.Errorf("hanging line over width (%d): %q", len([]rune(l)), l)
		}
	}
	if !strings.HasPrefix(lines[0], "    fw.ufw  ") {
		t.Errorf("prefix lost: %q", lines[0])
	}
}

// Domains render as human labels while check ids stay verbatim, because the
// id is the join key into explain, the audit log and the JSON.
func TestDomainLabels(t *testing.T) {
	env := synthetic(map[string]Fact{"privesc.sudoers": {Status: "ok", Parsed: []string{"x"}}})
	out := render(t, env, Options{})
	if !strings.Contains(out, "Privilege escalation") || !strings.Contains(out, "privesc.sudoers") {
		t.Errorf("want label and id:\n%s", out)
	}
	if strings.Contains(out, "[privesc]") {
		t.Errorf("raw domain slug rendered as a heading:\n%s", out)
	}
	if got := DomainLabel("nonesuch"); got != "nonesuch" {
		t.Errorf("unknown domain should render its slug, got %q", got)
	}
}

// A check id the catalog does not know still appears, under "Other".
func TestUnknownCheckStillListed(t *testing.T) {
	out := render(t, synthetic(map[string]Fact{"retired.check": {Status: "ok", Parsed: "x"}}), Options{})
	if !strings.Contains(out, "Other") || !strings.Contains(out, "retired.check") {
		t.Errorf("unknown check dropped:\n%s", out)
	}
}

// A redaction or truncation marker is the only record that bytes were removed
// (docs/spec/host-collector.md §4.2), so wrapping must not break one in half.
func TestWrapKeepsMarkersWhole(t *testing.T) {
	const marker = "[REDACTED:aws-access-key:20 bytes]"
	line := "Linux box 6.8 key=" + marker + " tail"
	for width := 20; width <= 60; width++ {
		for _, l := range Wrap(line, width) {
			if strings.Contains(l, "[REDACTED") && !strings.Contains(l, marker) && len([]rune(marker)) <= width {
				t.Fatalf("width %d split the marker: %q", width, l)
			}
		}
	}
	// A marker wider than the column is still cut rather than dropped.
	for _, l := range Wrap(line, 16) {
		if strings.Contains(l, "REDACTED") {
			return
		}
	}
	t.Error("marker vanished at a width narrower than itself")
}

func TestFailedOutputVisibleAndUnattemptedOutputHidden(t *testing.T) {
	env := synthetic(map[string]Fact{
		"os.release":      {Status: "unavailable", Reason: "parse error: malformed input", Attempted: true, Output: "MALFORMED_EVIDENCE", Stderr: "diagnostic"},
		"privesc.sudoers": {Status: "unavailable", Reason: "requires elevated read"},
	})
	out := render(t, env, Options{Verbose: 2})
	for _, want := range []string{"| MALFORMED_EVIDENCE", "| stderr:", "| diagnostic"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(out, "(no output)") {
		t.Fatal("unattempted check rendered evidence")
	}
}
