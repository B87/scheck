package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/fixture"
)

func testCatalog(t *testing.T) {
	t.Helper()
	check.Reset()
	t.Cleanup(check.Reset)
	pathParam := []check.Param{{Name: "path", Kind: check.KindPath}}
	check.Register(
		check.Check{ID: "sys.canary", Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Canary: true, Argv: []string{"printf", "%s", "a'b"}},
		check.Check{ID: "fs.realpath", Platform: check.Any, Domain: check.DomainFS, Parser: check.ParseRaw, PathUse: check.PathMetadata, Argv: []string{"realpath", "{path}"}, Params: pathParam},
		check.Check{ID: "fs.stat", Platform: check.Any, Domain: check.DomainFS, Parser: check.ParseRaw, PathUse: check.PathMetadata, Argv: []string{"stat", "-c", "%a:%U", "{path}"}, Params: pathParam},
		check.Check{ID: "text.cat", Platform: check.Any, Domain: check.DomainText, Parser: check.ParseLines, PathUse: check.PathContent, Argv: []string{"cat", "{path}"}, Params: pathParam},
		check.Check{ID: "sys.uname", Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseLines, Baseline: true, Argv: []string{"uname", "-a"}},
		check.Check{ID: "sshd.config", Platform: check.Any, Domain: check.DomainSSHD, Parser: check.ParseKV, Baseline: true, Elevated: true, Argv: []string{"sshd", "-T"}},
		check.Check{ID: "sys.slow", Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, Argv: []string{"slow"}},
		check.Check{ID: "svc.enabled", Platform: check.Any, Domain: check.DomainSys, Parser: check.ParseRaw, ExitOK: check.AnyExit, Argv: []string{"systemctl", "is-enabled", "sshd"}},
		check.Check{ID: "pkg.json", Platform: check.Any, Domain: check.DomainUpdates, Parser: check.ParseJSON, Argv: []string{"pkgjson"}},
		check.Check{ID: "host.uuid", Platform: check.Any, Domain: check.DomainHost, Parser: check.ParseRaw, Argv: []string{"ioreg"}, Extract: `"IOPlatformUUID" = "([0-9A-F-]+)"`},
	)
	if vs := check.Validate(check.All()); len(vs) != 0 {
		t.Fatalf("test catalog invalid: %v", vs)
	}
}

type harness struct {
	r     *Runner
	fx    *fixture.Target
	audit *bytes.Buffer
}

func newHarness(t *testing.T, elevate Elevation, execs ...fixture.Exec) *harness {
	t.Helper()
	testCatalog(t)
	fx := fixture.New(target.Linux, execs...)
	red, _ := policy.NewRedactor(nil)
	b := policy.DefaultBudgets()
	b.PerCheckHard = 100 * time.Millisecond
	b.PerCheckOutput = 200
	var audit bytes.Buffer
	return &harness{
		fx:    fx,
		audit: &audit,
		r: &Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: b,
			Audit: policy.NewAudit(&audit), Elevate: elevate, Log: t.Logf},
	}
}

func (h *harness) entries(t *testing.T) []policy.AuditEntry {
	t.Helper()
	var out []policy.AuditEntry
	for _, l := range bytes.Split(bytes.TrimSpace(h.audit.Bytes()), []byte("\n")) {
		var e policy.AuditEntry
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatalf("bad audit line %s: %v", l, err)
		}
		out = append(out, e)
	}
	return out
}

func TestRunAllowedCheck(t *testing.T) {
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux host 6.8\n"})
	res := h.r.Run(context.Background(), "sys.uname", nil)
	if res.Status != StatusOK || res.Parsed.([]string)[0] != "Linux host 6.8" {
		t.Fatalf("%+v", res)
	}
	e := h.entries(t)
	if len(e) != 1 || e[0].Decision != "run" || e[0].OutputHash == "" || *e[0].ExitCode != 0 {
		t.Errorf("audit: %+v", e)
	}
}

func TestRunUnknownIDIsDeniedAndAudited(t *testing.T) {
	h := newHarness(t, ElevateNone)
	res := h.r.Run(context.Background(), "nope.nope", nil)
	if res.Status != StatusDenied {
		t.Fatalf("%+v", res)
	}
	if e := h.entries(t); e[0].Decision != "denied:unknown_check" {
		t.Errorf("audit: %+v", e)
	}
	if len(h.fx.Calls) != 0 {
		t.Error("something reached the target")
	}
}

func TestRunDeniedPathNeverExecutes(t *testing.T) {
	h := newHarness(t, ElevateNone,
		fixture.Exec{Argv: []string{"realpath", "/usr/bin/id"}, Stdout: "/usr/bin/id\n"},
		fixture.Exec{Argv: []string{"cat", "/usr/bin/id"}, Stdout: "ELF"})
	res := h.r.Run(context.Background(), "text.cat", map[string]string{"path": "/usr/bin/id"})
	if res.Status != StatusDenied || !strings.Contains(res.Reason, policy.RuleNotAllowed) {
		t.Fatalf("%+v", res)
	}
	for _, call := range h.fx.Calls {
		if call[0] == "cat" {
			t.Fatal("denied path was read")
		}
	}
	e := h.entries(t)
	if last := e[len(e)-1]; last.Decision != "denied:"+policy.RuleNotAllowed {
		t.Errorf("audit: %+v", e)
	}
}

func TestRunHostileParamDeniedBeforeAnyExec(t *testing.T) {
	h := newHarness(t, ElevateNone)
	for _, p := range []string{"/etc/../usr/bin/id", "/etc/passwd;id", "/etc/*", "relative"} {
		res := h.r.Run(context.Background(), "text.cat", map[string]string{"path": p})
		if res.Status != StatusDenied {
			t.Errorf("%q accepted: %+v", p, res)
		}
	}
	if len(h.fx.Calls) != 0 {
		t.Errorf("target was contacted: %v", h.fx.Calls)
	}
	for _, e := range h.entries(t) {
		if e.Decision != "denied:param" {
			t.Errorf("audit: %+v", e)
		}
	}
}

func TestRunSensitivePathBecomesStat(t *testing.T) {
	h := newHarness(t, ElevateNone,
		fixture.Exec{Argv: []string{"realpath", "/etc/shadow"}, Stdout: "/etc/shadow\n"},
		fixture.Exec{Argv: []string{"stat", "-c", "%a:%U", "/etc/shadow"}, Stdout: "640:root\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/shadow"}, Stdout: "root:$6$hash:..."})
	res := h.r.Run(context.Background(), "text.cat", map[string]string{"path": "/etc/shadow"})
	if res.Status != StatusOK || res.RanAs != "fs.stat" || !strings.Contains(res.Reason, "metadata-only") || res.Raw != "640:root\n" {
		t.Fatalf("%+v", res)
	}
	for _, call := range h.fx.Calls {
		if call[0] == "cat" {
			t.Fatal("sensitive content was read")
		}
	}
	// fs.stat on a sensitive path is fine as-is: metadata is what it returns.
	res = h.r.Run(context.Background(), "fs.stat", map[string]string{"path": "/etc/shadow"})
	if res.Status != StatusOK || res.RanAs != "fs.stat" {
		t.Fatalf("%+v", res)
	}
}

func TestRunSymlinkEscapeIsJudgedOnResolvedPath(t *testing.T) {
	h := newHarness(t, ElevateNone,
		fixture.Exec{Argv: []string{"realpath", "/etc/innocent"}, Stdout: "/root/.ssh/id_rsa\n"},
		fixture.Exec{Argv: []string{"stat", "-c", "%a:%U", "/root/.ssh/id_rsa"}, Stdout: "600:root\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/innocent"}, Stdout: "-----BEGIN OPENSSH PRIVATE KEY-----"})
	res := h.r.Run(context.Background(), "text.cat", map[string]string{"path": "/etc/innocent"})
	if res.Status != StatusOK || res.RanAs != "fs.stat" || !strings.Contains(res.Reason, "ssh_identity") {
		t.Fatalf("%+v", res)
	}
	h2 := newHarness(t, ElevateNone,
		fixture.Exec{Argv: []string{"realpath", "/etc/innocent2"}, Stdout: "/usr/bin/id\n"})
	res = h2.r.Run(context.Background(), "text.cat", map[string]string{"path": "/etc/innocent2"})
	if res.Status != StatusDenied {
		t.Fatalf("symlink out of the allowed tree was accepted: %+v", res)
	}
}

func TestRunTimeoutIsUnavailable(t *testing.T) {
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"slow"}, Sleep: 5 * time.Second})
	res := h.r.Run(context.Background(), "sys.slow", nil)
	if res.Status != StatusUnavailable || !strings.HasPrefix(res.Reason, "timeout") {
		t.Fatalf("%+v", res)
	}
	if e := h.entries(t); !strings.HasPrefix(e[0].Decision, "unavailable:timeout") {
		t.Errorf("audit: %+v", e)
	}
}

func TestRunMissingBinaryIsUnavailable(t *testing.T) {
	h := newHarness(t, ElevateNone)
	res := h.r.Run(context.Background(), "sys.uname", nil)
	if res.Status != StatusUnavailable || res.Reason != "not found: uname" || res.ExitCode != target.CodeNotFound {
		t.Fatalf("%+v", res)
	}
}

func TestRunElevation(t *testing.T) {
	// none: no exec at all.
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"sshd", "-T"}, Stdout: "port 22\n"})
	res := h.r.Run(context.Background(), "sshd.config", nil)
	if res.Status != StatusUnavailable || res.Reason != "requires elevated read" || len(h.fx.Calls) != 0 {
		t.Fatalf("none: %+v calls=%v", res, h.fx.Calls)
	}
	if e := h.entries(t); e[0].Decision != "unavailable:requires_elevation" {
		t.Errorf("audit: %+v", e)
	}
	// sudo: prefix applied.
	h = newHarness(t, ElevateSudo, fixture.Exec{Argv: []string{"sudo", "-n", "--", "sshd", "-T"}, Stdout: "port 22\npasswordauthentication yes\n"})
	res = h.r.Run(context.Background(), "sshd.config", nil)
	if res.Status != StatusOK || !res.Elevated || res.Parsed.(map[string]string)["passwordauthentication"] != "yes" {
		t.Fatalf("sudo: %+v", res)
	}
	// sudo refused (no NOPASSWD): degrades to unavailable, never prompts.
	h = newHarness(t, ElevateSudo, fixture.Exec{Argv: []string{"sudo", "-n", "--", "sshd", "-T"}, Code: 1, Stderr: "sudo: a password is required\n"})
	res = h.r.Run(context.Background(), "sshd.config", nil)
	if res.Status != StatusUnavailable || res.Reason != "sudo: sudo: a password is required" {
		t.Fatalf("sudo refused: %+v", res)
	}
	// root: no prefix.
	h = newHarness(t, ElevateRoot, fixture.Exec{Argv: []string{"sshd", "-T"}, Stdout: "port 22\n"})
	if res = h.r.Run(context.Background(), "sshd.config", nil); res.Status != StatusOK || !res.Elevated {
		t.Fatalf("root: %+v", res)
	}
	// Non-elevated checks never get the prefix.
	h = newHarness(t, ElevateSudo, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "x\n"})
	if res = h.r.Run(context.Background(), "sys.uname", nil); res.Status != StatusOK || res.Elevated {
		t.Fatalf("plain under sudo: %+v", res)
	}
}

func TestRunExitCodes(t *testing.T) {
	h := newHarness(t, ElevateNone,
		fixture.Exec{Argv: []string{"uname", "-a"}, Code: 2, Stderr: "uname: boom\n"},
		fixture.Exec{Argv: []string{"systemctl", "is-enabled", "sshd"}, Code: 1, Stdout: "disabled\n"})
	res := h.r.Run(context.Background(), "sys.uname", nil)
	if res.Status != StatusUnavailable || res.Reason != "exit 2: uname: boom" {
		t.Fatalf("%+v", res)
	}
	res = h.r.Run(context.Background(), "svc.enabled", nil)
	if res.Status != StatusOK || res.ExitCode != 1 || res.Raw != "disabled\n" {
		t.Fatalf("AnyExit: %+v", res)
	}
}

func TestRunRedactsBeforeAuditAndTruncates(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	big := strings.Repeat("x ", 95) + secret + " " + strings.Repeat("y", 500)
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: big})
	res := h.r.Run(context.Background(), "sys.uname", nil)
	if strings.Contains(res.Raw, secret) || res.Redactions != 1 || !strings.Contains(res.Raw, "[REDACTED:aws-access-key:20 bytes]") {
		t.Fatalf("secret leaked or unmarked: %q", res.Raw)
	}
	if !res.Truncated || !strings.Contains(res.Raw, "[TRUNCATED:") {
		t.Fatalf("not truncated: %q", res.Raw)
	}
	if strings.Contains(h.audit.String(), secret) {
		t.Fatal("secret in audit log")
	}
	if e := h.entries(t); e[0].OutputHash != policy.OutputHash([]byte(res.Raw)) {
		t.Error("audit hash is not of the redacted output")
	}
}

func TestRunParseErrorKeepsRaw(t *testing.T) {
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"pkgjson"}, Stdout: "{not json"})
	res := h.r.Run(context.Background(), "pkg.json", nil)
	if res.Status != StatusUnavailable || !strings.HasPrefix(res.Reason, "parse error") || res.Raw != "{not json" {
		t.Fatalf("%+v", res)
	}
}

func TestRunExtractKeepsOnlyTheMatch(t *testing.T) {
	h := newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"ioreg"}, Stdout: "  \"IOPlatformSerialNumber\" = \"SERIAL123\"\n  \"IOPlatformUUID\" = \"AFCC3024-054E-5B1D-9CDE-9FF60BF8E219\"\n"})
	res := h.r.Run(context.Background(), "host.uuid", nil)
	if res.Status != StatusOK || res.Raw != "AFCC3024-054E-5B1D-9CDE-9FF60BF8E219" || strings.Contains(res.Raw, "SERIAL") {
		t.Fatalf("%+v", res)
	}
	h = newHarness(t, ElevateNone, fixture.Exec{Argv: []string{"ioreg"}, Stdout: "nothing here"})
	if res = h.r.Run(context.Background(), "host.uuid", nil); res.Status != StatusUnavailable || res.Raw != "" {
		t.Fatalf("no match: %+v", res)
	}
}
