package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/engagement/hostasset"
	"github.com/b87/scheck/internal/target/fixture"
	"github.com/b87/scheck/internal/version"
)

// hermetic gives a test its own home, config and state directories and
// working directory, so no run reads the developer's configuration or
// writes into their state directory. It returns the state directory.
func hermetic(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "home", ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Chdir(dir)
	return filepath.Join(dir, "state", "scheck")
}

// Every gate a test of this package builds has a dialer and a resolver that
// fail at once: no test reaches crt.sh, a website or a DNS server, whether
// or not it calls hermetic (AGENTS.md, "Testing rules"). What a gate does
// with an answer is the gate's own tests'.
func init() {
	offline := errors.New("no network in tests")
	newGate = func(cfg gate.Config) (*gate.Gate, error) {
		cfg.Net = &gate.Net{
			Dial:       func(context.Context, string, string) (net.Conn, error) { return nil, offline },
			Nameserver: netip.MustParseAddr("192.0.2.53"),
			Exchange:   func(context.Context, string, []byte, bool) ([]byte, error) { return nil, offline },
		}
		return gate.New(cfg)
	}
}

// collectFrom makes every host asset collect from fx, never a real host,
// and counts the collections.
func collectFrom(t *testing.T, fx func() *fixture.Target) *int {
	t.Helper()
	calls := 0
	prev := collectHost
	collectHost = func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		calls++
		o.Target = fx()
		return hostasset.Collect(ctx, o)
	}
	t.Cleanup(func() { collectHost = prev })
	return &calls
}

// fixturesDir is resolved when the package loads, before any test changes
// directory.
var fixturesDir, _ = filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures"))

func recorded(t *testing.T, name string) func() *fixture.Target {
	return func() *fixture.Target {
		fx, err := fixture.Load(filepath.Join(fixturesDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return fx
	}
}

// runEngagement executes `scheck run` with args and returns stdout, the
// error the process would print, and its exit code.
func runEngagement(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"run"}, args...))
	err := root.Execute()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return out.String(), msg, exitCodeOf(err)
}

// runEngagementStderr is runEngagement returning what it wrote to stderr.
func runEngagementStderr(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"run"}, args...))
	err := root.Execute()
	return out.String(), stderr.String(), exitCodeOf(err)
}

const validEngagement = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - host: deploy@203.0.113.5
redact_extra: ["project-tangerine"]
assets:
  deploy:
    host: 203.0.113.5
    elevate: sudo
    disable_checks: [fs.suid]
`

func TestRunStopAfterIntakePrintsTheResolvedFile(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)

	out, msg, code := runEngagement(t, path, "--stop-after", "intake")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	for _, want := range []string{"valid; 1 root, 1 asset, nothing contacted", "id: host:203.0.113.5:22", "user: deploy", "elevate: sudo", "profile: baseline", "redact_extra_patterns: 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tangerine") {
		t.Errorf("a redact_extra pattern was printed:\n%s", out)
	}

	out, msg, code = runEngagement(t, path, "--stop-after", "intake", "--format", "json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	var doc struct {
		Assets []struct {
			Name, ID, Elevate string
		} `json:"assets"`
		RedactPatterns int `json:"redact_extra_patterns"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(doc.Assets) != 1 || doc.Assets[0].ID != "host:203.0.113.5:22" || doc.Assets[0].Elevate != "sudo" || doc.RedactPatterns != 1 {
		t.Fatalf("json = %+v", doc)
	}
	if strings.Contains(out, "tangerine") {
		t.Errorf("a redact_extra pattern was printed:\n%s", out)
	}
	if *calls != 0 {
		t.Errorf("intake contacted a host %d times", *calls)
	}
}

// --stop-after scope prints each web asset's first-party evidence and every
// exclude, an operator-written unit escaped, and contacts nothing.
func TestRunStopAfterScopePrintsEvidenceAndExcludes(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - domain: example.com
  - url: https://app.example.net/
  - host: deploy@203.0.113.5
  - saas: google-workspace:example.com
exclude:
  - url: https://shop.example.com/checkout/
  - {saas: google-workspace:example.com, org_unit: "/Bo\e[31mard"}
people:
  alice: {kind: employee, workspace: [alice@example.com]}
assets:
  blog:
    domain: blog.example.com
    first_party: {confirmed_by: alice, date: 2026-10-07, target: blog.example-hosting.net}
`)
	prev := runClock
	runClock = func() time.Time { return time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { runClock = prev })
	out, msg, code := runEngagement(t, path, "--stop-after", "scope")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	for _, want := range []string{"FIRST-PARTY EVIDENCE", "url root", "host root", "operator confirmed (alice, 2026-10-07)",
		"exclude[0]  url:https://shop.example.com/checkout/  never contacted",
		"exclude[1]  saas:google-workspace:example.com  organizational unit /Bo\\x1b[31mard and every unit under it"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("an escape sequence from the file was printed raw")
	}
	if *calls != 0 {
		t.Errorf("%d hosts collected", *calls)
	}
}

func TestRunRefusesWhatThisBuildDoesNotRun(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	writeFile(t, path, validEngagement)
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"unknown stage", []string{path, "--stop-after", "facts"}, "must be one of intake|scope|recon|plan|check|analyze|report"},
		{"reach flag on a file", []string{path, "--sudo"}, "--sudo is accepted only with --host"},
		{"timeout on a file", []string{path, "--timeout", "1m"}, "--timeout is accepted only with --host"},
		{"context flag", []string{path, "--context", "x.yaml"}, "context is assets.<name>.context"},
		{"audit log", []string{path, "--audit-log", "a.jsonl"}, "the run directory holds audit.jsonl"},
		{"model flag", []string{path, "--provider", "mock"}, "--provider is not available for scheck run"},
		{"jump without a user", []string{"--host", "deploy@203.0.113.5", "--jump", "198.51.100.7"}, "has no SSH user: write it as user@198.51.100.7"},
		{"jump on local", []string{"--host", "local", "--jump", "ops@198.51.100.7"}, "--jump"},
		{"file and host", []string{path, "--host", "local"}, "an engagement file or --host, not both"},
		{"neither", nil, "one engagement file, or --host LOCATOR"},
		{"write without host", []string{path, "--write-engagement", filepath.Join(dir, "x.yaml")}, "it needs --host"},
		{"write with an output flag", []string{"--host", "local", "--write-engagement", filepath.Join(dir, "y.yaml"), "--out", filepath.Join(dir, "r.json")}, "do not apply to it"},
		{"bad host", []string{"--host", "deploy:hunter2@203.0.113.5"}, "never carries a password"},
		{"bad profile", []string{"--host", "local", "--profile", "paranoid"}, "--profile: "},
		{"missing file", []string{filepath.Join(dir, "nope.yaml")}, "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, msg, code := runEngagement(t, tc.args...)
			if code != exitUsage || !strings.Contains(msg, tc.msg) || out != "" {
				t.Fatalf("exit %d, %q, stdout %q; want exit 3 and %q", code, msg, out, tc.msg)
			}
			if strings.Contains(msg, "hunter2") {
				t.Fatalf("the password was printed: %s", msg)
			}
		})
	}
	if *calls != 0 {
		t.Errorf("a refused run contacted a host %d times", *calls)
	}
}

func TestRunInvalidFileNamesEveryErrorAndNeverTheCredential(t *testing.T) {
	hermetic(t)
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement+"    identity: AKIAIOSFODNN7EXAMPLE\ncolour: blue\n")
	out, msg, code := runEngagement(t, path, "--stop-after", "intake")
	if code != exitUsage || out != "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	for _, want := range []string{"(2 errors)", path + ":14:assets.deploy.identity: holds a value shaped like a credential (detector aws-access-key)", path + ":15:colour: unknown key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("the credential was printed:\n%s", msg)
	}
}

// runDir returns the one run directory under state for engagement name.
func runDir(t *testing.T, state, name string) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(state, "engagements", name, "*"))
	if len(dirs) != 1 {
		t.Fatalf("run directories: %q", dirs)
	}
	return dirs[0]
}

// A host run writes every stage's output into a private run directory, and
// --format json prints the engagement report as written to report.json.
func TestRunOnAHostWritesTheRunDirectory(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)

	out, msg, code := runEngagement(t, path, "--format", "json")
	dir := runDir(t, state, "acme")
	written, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out != string(written) {
		t.Errorf("stdout is not report.json")
	}
	var rep struct {
		Exit   struct{ Code int } `json:"exit"`
		Assets []struct {
			Name  string            `json:"name"`
			Trace []json.RawMessage `json:"trace"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(written, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].Name != "deploy" || len(rep.Assets[0].Trace) == 0 || rep.Exit.Code != code {
		t.Fatalf("report.json: %+v, exit %d", rep, code)
	}
	var doc engagement.FindingsDoc
	b, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	want := exitOK
	if doc.Open > 0 {
		want = exitFindings
	}
	if code != want || *calls != 1 {
		t.Fatalf("exit %d (%s) after %d collections; findings.json has %d open", code, msg, *calls, doc.Open)
	}
	if a := doc.Assets[0]; a.Name != "deploy" || a.Status != "collected" || len(a.Assessments) == 0 {
		t.Fatalf("asset = %+v", a)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode %v", fi.Mode().Perm())
	}
	for _, f := range []string{"engagement.yaml", "scope.json", "recon.json", "plan.json", "findings.json", "audit.jsonl",
		"evidence/deploy.json", "report.json", "report.txt"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, err, fi)
		}
	}
	if audit, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl")); !bytes.Contains(audit, []byte(`"check":"sys.uname"`)) {
		t.Errorf("audit.jsonl does not record the run's commands")
	}

	// The text summary names the asset and the run directory.
	out, _, _ = runEngagement(t, path, "--stop-after", "recon", "--no-persist")
	if !strings.Contains(out, "deploy  host:203.0.113.5:22  collected") || !strings.Contains(out, "not persisted (--no-persist)") {
		t.Errorf("recon summary:\n%s", out)
	}
}

// A secret on the host and a string matching redact_extra are absent from
// every file in the run directory and from stdout, and their markers are
// present (docs/ROADMAP.md, E1b "Done when"). The pattern is a literal, as
// clients write them, so the run directory's engagement.yaml is held to the
// same rule.
func TestRunSeededSecretNeverReachesTheRunDirectory(t *testing.T) {
	state := hermetic(t)
	collectFrom(t, func() *fixture.Target {
		return fixture.New(check.Linux,
			fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux box 6.8 key=AKIAIOSFODNN7EXAMPLE codename=project-tangerine\n"},
			fixture.Exec{Argv: []string{"cat", "/etc/machine-id"}, Stdout: "0123456789abcdef0123456789abcdef\n"},
			fixture.Exec{Argv: []string{"uname", "-n"}, Stdout: "box\n"},
		)
	})
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)

	out, msg, code := runEngagement(t, path, "--format", "json")
	if code == exitUsage {
		t.Fatalf("exit 3: %s", msg)
	}
	text, _, _ := runEngagement(t, path, "--stop-after", "recon", "--no-persist")
	outputs := map[string]string{"stdout": out, "text": text}
	markers := map[string]bool{}
	err := filepath.WalkDir(runDir(t, state, "acme"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		outputs[filepath.Base(p)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range outputs {
		for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "project-tangerine"} {
			if strings.Contains(s, secret) {
				t.Errorf("%s holds %s", name, secret)
			}
		}
		for _, m := range []string{"[REDACTED:aws-access-key:20 bytes]", "[REDACTED:extra:0:17 bytes]"} {
			if strings.Contains(s, m) {
				markers[m+" in "+name] = true
			}
		}
	}
	for _, want := range []string{"recon.json", "deploy.json", "report.json", "stdout"} {
		for _, m := range []string{"[REDACTED:aws-access-key:20 bytes]", "[REDACTED:extra:0:17 bytes]"} {
			if !markers[m+" in "+want] {
				t.Errorf("%s lacks %s", want, m)
			}
		}
	}
	// The report counts what was redacted and never names a pattern.
	var rep struct {
		Redaction struct {
			Builtin  map[string]int `json:"builtin"`
			Operator struct{ Rules, Matches int }
		} `json:"redaction"`
	}
	if err := json.Unmarshal([]byte(outputs["report.json"]), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Redaction.Builtin["aws-access-key"] == 0 || rep.Redaction.Operator.Rules != 1 || rep.Redaction.Operator.Matches == 0 {
		t.Errorf("redaction counts %+v", rep.Redaction)
	}
	if !strings.Contains(outputs["report.txt"], "Your redact_extra rules:") {
		t.Errorf("report.txt does not count the operator's redactions:\n%s", outputs["report.txt"])
	}
}

// An engagement with a host root and a github root exits 2 with the host's
// findings written.
func TestRunHostAndGitHubIsIncompleteWithFindings(t *testing.T) {
	state := hermetic(t)
	collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, strings.Replace(validEngagement, "  - host: deploy@203.0.113.5\n", "  - host: deploy@203.0.113.5\n  - saas: github:example-org\n", 1))
	out, msg, code := runEngagement(t, path)
	if code != exitIncomplete || !strings.Contains(msg, "saas:github:example-org: collector_not_built") {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if !strings.Contains(out, "INCOMPLETE: saas:github:example-org (GitHub organization): this version of scheck does not read it.") {
		t.Errorf("report:\n%s", out)
	}
	var doc engagement.FindingsDoc
	b, err := os.ReadFile(filepath.Join(runDir(t, state, "acme"), "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Assets) != 2 || doc.Assets[0].Status != "collected" || len(doc.Assets[0].Assessments) == 0 {
		t.Fatalf("findings.json = %+v", doc.Assets)
	}
}

func TestRunOnALockedRunDirectoryExits3(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	started := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	prev := runClock
	runClock = func() time.Time { return started }
	t.Cleanup(func() { runClock = prev })
	held, err := engagement.CreateRunDir(state, "acme", started)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)
	_, msg, code := runEngagement(t, path)
	if code != exitUsage || !strings.Contains(msg, "is locked by another run") || *calls != 0 {
		t.Fatalf("exit %d after %d collections: %s", code, *calls, msg)
	}
}

// A run cut by a transport failure or a timeout exits 2; a canary mismatch
// exits 3, as in 0.0.1.
func TestRunFailuresSetTheExitCode(t *testing.T) {
	hermetic(t)
	prev := collectHost
	t.Cleanup(func() { collectHost = prev })

	collectHost = func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
		return nil, &hostasset.Error{Err: errors.New("ssh: dial 203.0.113.5:22: connection refused (host unreachable)")}
	}
	_, msg, code := runEngagement(t, "--host", "deploy@203.0.113.5", "--no-persist")
	if code != exitIncomplete || !strings.Contains(msg, "host-203-0-113-5: failed: ssh: dial") {
		t.Fatalf("unreachable: exit %d: %s", code, msg)
	}

	collectHost = func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
		return nil, &hostasset.Error{Usage: true, Err: errors.New("ssh canary mismatch")}
	}
	out, msg, code := runEngagement(t, "--host", "deploy@203.0.113.5", "--no-persist")
	if code != exitUsage || !strings.Contains(msg, "refused:") || !strings.Contains(out, "REFUSED: host-203-0-113-5: ssh canary mismatch.") {
		t.Fatalf("canary: exit %d: %s\n%s", code, msg, out)
	}

	collectFrom(t, func() *fixture.Target {
		return fixture.New(check.Linux, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux\n", Sleep: time.Second})
	})
	_, msg, code = runEngagement(t, "--host", "local", "--timeout", "50ms", "--no-persist")
	if code != exitIncomplete || !strings.Contains(msg, "host-local: limit_reached") {
		t.Fatalf("timeout: exit %d: %s", code, msg)
	}
}

// What this build cannot reach is refused before a run directory exists,
// so a refused run leaves nothing behind.
func TestRunPreflightLeavesNoRunDirectory(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	_, msg, code := runEngagement(t, "--host", "203.0.113.5")
	if code != exitUsage || !strings.Contains(msg, "has no SSH user") || *calls != 0 {
		t.Fatalf("exit %d after %d collections: %s", code, *calls, msg)
	}
	if _, err := os.Stat(filepath.Join(state, "engagements")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused run created %s: %v", filepath.Join(state, "engagements"), err)
	}
}

// --write-engagement writes the --host engagement, contacts nothing and
// never overwrites; the file it writes runs as the same engagement.
func TestRunWriteEngagement(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	args := []string{"--host", "deploy@203.0.113.5:2222", "--sudo", "--profile", "hardened", "--identity", "~/.ssh/deploy", "--write-engagement", path}
	if _, msg, code := runEngagement(t, args...); code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("written file: %v %v", err, fi)
	}
	if _, msg, code := runEngagement(t, args...); code != exitUsage || !strings.Contains(msg, "exists") {
		t.Fatalf("overwrite: exit %d: %s", code, msg)
	}
	withReach := filepath.Join(t.TempDir(), "reach.yaml")
	if _, msg, code := runEngagement(t, "--host", "deploy@203.0.113.5", "--known-hosts", "~/acme/known_hosts", "--timeout", "10m", "--write-engagement", withReach); code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if b, _ := os.ReadFile(withReach); !strings.Contains(string(b), "known_hosts: ~/acme/known_hosts") || !strings.Contains(string(b), "timeout: 10m0s") {
		t.Errorf("--known-hosts and --timeout are not in the written file:\n%s", b)
	}
	out, msg, code := runEngagement(t, path, "--stop-after", "intake")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	for _, want := range []string{"name: host-203-0-113-5-2222", "id: host:203.0.113.5:2222", "elevate: sudo", "profile: hardened", "identity: ~/.ssh/deploy", "timeout: 1h0m0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("resolved lacks %q:\n%s", want, out)
		}
	}
	if *calls != 0 {
		t.Errorf("contacted a host %d times", *calls)
	}
}

// A configuration file where 0.0.1 read one stops the run, naming each key
// and its new home and never a value. The two paths that contact nothing,
// which are how its keys move into a file, warn instead.
func TestRunRefusesALegacyConfigFile(t *testing.T) {
	hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	writeFile(t, "scheck.yaml", "deny_paths: [/srv/private]\nredact_extra: [\"acme-secret-codename\"]\ncolour: blue\n")
	if _, msg, code := runEngagement(t, "--host", "local", "--write-engagement", "e.yaml"); code != exitOK {
		t.Fatalf("--write-engagement: exit %d: %s", code, msg)
	}
	if _, msg, code := runEngagement(t, "e.yaml", "--stop-after", "intake"); code != exitOK {
		t.Fatalf("--stop-after intake: exit %d: %s", code, msg)
	}
	_, msg, code := runEngagement(t, "--host", "local")
	if code != exitUsage || *calls != 0 {
		t.Fatalf("exit %d after %d collections: %s", code, *calls, msg)
	}
	for _, want := range []string{"scheck.yaml:", "deny_paths -> assets.<name>.deny_paths", "redact_extra -> redact_extra", "colour -> not read", "delete or rename the file"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "acme-secret-codename") || strings.Contains(msg, "/srv/private") {
		t.Errorf("a value was printed:\n%s", msg)
	}
}

// A --host local run sends nothing to a third party and nothing over SSH:
// the report's "What left this machine" says none, the one local run and
// the model line (E4 test 23).
func TestRunLocalEgress(t *testing.T) {
	hermetic(t)
	collectFrom(t, recorded(t, "ubuntu"))
	out, _, _, _ := runCLI(t, "run", "--host", "local", "--no-persist")
	i := strings.Index(out, "WHAT LEFT THIS MACHINE")
	if i < 0 {
		t.Fatalf("no egress block:\n%s", out)
	}
	block := out[i:]
	block = block[:strings.Index(block, "\n\n")]
	for _, want := range []string{"Third-party services:\n    none", "servers: this machine, read in place.",
		"Nothing was sent to an AI model provider.", "Nothing was sent to the makers of scheck", "stored nowhere"} {
		if !strings.Contains(block, want) {
			t.Errorf("egress lacks %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "SSH session") || strings.Contains(block, "User-Agent") || strings.Contains(block, "identified itself") {
		t.Errorf("egress claims a contact that never happened:\n%s", block)
	}
}

// --no-persist with a root the gate would send for exits 3 before any
// contact: no host reached, no gate built, no run directory; a --host run
// keeps it (docs/spec/scope.md, "Audit"; E4 test 22).
func TestNoPersistRefusesANetworkRoot(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	gates := 0
	prev := newGate
	newGate = func(cfg gate.Config) (*gate.Gate, error) { gates++; return prev(cfg) }
	t.Cleanup(func() { newGate = prev })
	for _, root := range []string{"domain: example.com", "url: https://www.example.com/", "network: 198.51.100.0/24",
		"saas: github:example-org", "repo: github:example-org/shop", "asset"} {
		path := filepath.Join(t.TempDir(), "engagement.yaml")
		body := "schema: 1\nengagement: {name: acme, timezone: Europe/Madrid, trigger: routine}\nroots:\n  - " + root +
			"\n  - host: deploy@203.0.113.5\n"
		if root == "asset" {
			// A url asset under a host root is sent for too.
			body = "schema: 1\nengagement: {name: acme, timezone: Europe/Madrid, trigger: routine}\nroots:\n  - host: deploy@203.0.113.5\n" +
				"assets:\n  site:\n    url: https://203.0.113.5/\n"
		}
		writeFile(t, path, body)
		_, msg, code := runEngagement(t, path, "--no-persist")
		if code != exitUsage || !strings.Contains(msg, "--no-persist cannot be used when scheck sends network requests") {
			t.Errorf("%s: exit %d: %s", root, code, msg)
		}
	}
	if *calls != 0 || gates != 0 {
		t.Errorf("%d hosts reached, %d gates built", *calls, gates)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("a refused run left the state directory: %v", err)
	}
	if _, _, msg, code := runCLI(t, "run", "--host", "deploy@203.0.113.5", "--no-persist"); code == exitUsage || *calls != 1 {
		t.Errorf("--host with --no-persist: exit %d, %d hosts: %s", code, *calls, msg)
	}
}

// `scheck run DIR` resumes the run in DIR: a host the first session
// collected completely is kept, the report says it was resumed, and a flag
// that would put the resume elsewhere is refused.
func TestRunResumesARunDirectory(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	prevVersion := version.Version
	version.Version = "v0.0.2"
	t.Cleanup(func() { version.Version = prevVersion })
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	writeFile(t, path, validEngagement)
	if _, msg, code := runEngagement(t, path); code == exitUsage || *calls != 1 {
		t.Fatalf("first session: exit %d after %d collections: %s", code, *calls, msg)
	}
	dir := runDir(t, state, "acme")

	for _, flags := range [][]string{{"--no-persist"}, {"--state-dir", t.TempDir()}, {"--host", "local"},
		{"--write-engagement", filepath.Join(t.TempDir(), "e.yaml")}} {
		if _, msg, code := runEngagement(t, append([]string{dir}, flags...)...); code != exitUsage || !strings.Contains(msg, "do not apply") {
			t.Errorf("%v: exit %d: %s", flags, code, msg)
		}
	}
	out, stderr, code := runEngagementStderr(t, dir, "--format", "json")
	if code == exitUsage || *calls != 1 {
		t.Fatalf("resume: exit %d after %d collections: %s", code, *calls, stderr)
	}
	// The safeguard against a run.json edited with its hashes: the file
	// read, by the path it was read from, and its hash, every time.
	sum := sha256.Sum256([]byte(validEngagement))
	if want := "with " + path + " (sha256 " + hex.EncodeToString(sum[:]) + ")"; !strings.Contains(stderr, "resuming ") || !strings.Contains(stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, stderr)
	}
	var rep struct {
		Run struct {
			Resumed   bool    `json:"resumed"`
			Directory *string `json:"directory"`
		} `json:"run"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	// The run directory as resolved: the path typed may pass through a link.
	real, _ := filepath.EvalSymlinks(dir)
	if !rep.Run.Resumed || rep.Run.Directory == nil || *rep.Run.Directory != real {
		t.Errorf("run %+v", rep.Run)
	}
	if dirs, _ := filepath.Glob(filepath.Join(state, "engagements", "acme", "*")); len(dirs) != 1 {
		t.Errorf("a resume made another run directory: %v", dirs)
	}
	// A file that no longer loads is still named by the path it was read
	// from: a parse error names it as typed.
	writeFile(t, path, "schema: 1\nnot an engagement\n")
	if _, stderr, code := runEngagementStderr(t, dir); code != exitUsage || !strings.Contains(stderr, "with "+path+"\n") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
}

// An engagement file named --host, typed by a relative path, is a file run:
// its resume reads that file from its absolute path, says so, and keeps the
// host it collected.
func TestRunResumesAFileNamedHost(t *testing.T) {
	state := hermetic(t)
	calls := collectFrom(t, recorded(t, "ubuntu"))
	prevVersion := version.Version
	version.Version = "v0.0.2"
	t.Cleanup(func() { version.Version = prevVersion })
	t.Chdir(t.TempDir())
	writeFile(t, "--host", validEngagement)
	command := func(out string) string {
		t.Helper()
		var rep struct {
			Run struct {
				Command string `json:"command"`
			} `json:"run"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		return rep.Run.Command
	}
	out, msg, code := runEngagement(t, "--format", "json", "--", "--host")
	if code == exitUsage || *calls != 1 {
		t.Fatalf("first session: exit %d after %d collections: %s", code, *calls, msg)
	}
	// The command to run it again names the file, never the flag.
	if got := command(out); got != "scheck run ./--host" {
		t.Errorf("first session's command %q", got)
	}
	dir := runDir(t, state, "acme")
	t.Chdir(t.TempDir())
	out, stderr, code := runEngagementStderr(t, dir, "--format", "json")
	if code == exitUsage || *calls != 1 {
		t.Fatalf("resume: exit %d after %d collections: %s", code, *calls, stderr)
	}
	if !strings.Contains(stderr, string(filepath.Separator)+"--host (sha256 ") || strings.Contains(stderr, "the engagement --host built") {
		t.Errorf("the resume did not read the file named --host:\n%s", stderr)
	}
	// From another directory, by the absolute path it was read from.
	if got := command(out); !strings.HasPrefix(got, "scheck run /") || !strings.HasSuffix(got, string(filepath.Separator)+"--host") {
		t.Errorf("the resume's command %q", got)
	}
}
