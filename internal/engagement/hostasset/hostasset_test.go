package hostasset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/fixture"
)

// Each fixture replays as it was recorded, as the report goldens do.
var fixtureElevation = map[string]string{"ubuntu": "sudo", "fedora": "sudo", "macos": "none"}

func load(t *testing.T, name string) *fixture.Target {
	t.Helper()
	fx, err := fixture.Load(filepath.Join("..", "..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return fx
}

// The host asset is the 0.0.1 host collector: for the same profile,
// elevation and context, its facts, assessments and findings equal the
// golden JSON report's (docs/ROADMAP.md, E1b "Done when").
func TestHostAssetEqualsTheGoldenReport(t *testing.T) {
	for name, elev := range fixtureElevation {
		t.Run(name, func(t *testing.T) {
			c, err := Collect(context.Background(), Options{Target: load(t, name), Elevate: elev, Profile: "baseline", Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if !c.Complete() {
				t.Fatal("collection incomplete")
			}
			var got bytes.Buffer
			if err := report.WriteJSON(&got, c.Envelope()); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join("..", "..", "report", "testdata", "golden", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			want, have := sections(t, raw, false), sections(t, got.Bytes(), elev == "none")
			for _, key := range []string{"facts", "assessments", "findings", "observations"} {
				if !bytes.Equal(want[key], have[key]) {
					t.Errorf("%s differs from the 0.0.1 golden report\n--- want ---\n%.2000s\n--- got ---\n%.2000s", key, want[key], have[key])
				}
			}
		})
	}
}

// sections returns the envelope's top-level keys re-encoded with run-time
// fields removed, so only what the collector read and concluded compares.
//
// Unelevated, the host collector first runs sys.uid to detect a root
// session, as `scheck local` and `scheck ssh` do; the report goldens are
// built from the plan alone. With rootProbe, that one observation is
// removed and the plan's own sys.uid takes its reference back; occurrence
// numbers, which it shifts, are not compared.
func sections(t *testing.T, raw []byte, rootProbe bool) map[string][]byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if rootProbe {
		obs, _ := doc["observations"].(map[string]any)
		if _, ok := obs["sys.uid#2"]; !ok {
			t.Fatal("no root-detection observation to remove")
		}
		delete(obs, "sys.uid#1")
		b, _ := json.Marshal(doc)
		doc = nil
		if err := json.Unmarshal(bytes.ReplaceAll(b, []byte("sys.uid#2"), []byte("sys.uid#1")), &doc); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"facts", "observations"} {
		m, _ := doc[key].(map[string]any)
		for _, v := range m {
			if e, ok := v.(map[string]any); ok {
				delete(e, "duration_ms")
				delete(e, "occurrence")
			}
		}
	}
	out := map[string][]byte{}
	for k, v := range doc {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = b
	}
	return out
}

// The asset's context reaches the grader attributed to the engagement
// file, an accepted risk to its own entry, and an accepted risk leaves the
// finding in the report and out of the count that sets the exit code.
func TestContextAndAcceptedRisksGrade(t *testing.T) {
	base, err := Collect(context.Background(), Options{Target: load(t, "macos")})
	if err != nil {
		t.Fatal(err)
	}
	open := base.Envelope().Findings
	if len(open) == 0 || base.OpenFindings() == 0 {
		t.Fatal("the macos fixture has no open finding to accept; pick a fixture that has one")
	}
	accepted := open[0].ID
	src, entry := "engagement.yaml assets.web", "engagement.yaml intent.accepted_risks[0]"
	c, err := Collect(context.Background(), Options{Target: load(t, "macos"),
		ContextSource: src, Context: &operator.Structured{Exposure: "internet",
			AcceptedRisks: []operator.Risk{{ID: accepted, Reason: "known", Source: entry}}}})
	if err != nil {
		t.Fatal(err)
	}
	env := c.Envelope()
	var got *finding.Finding
	for i, f := range env.Findings {
		if f.ID == accepted {
			got = &env.Findings[i]
		}
	}
	if got == nil || got.Status != "accepted" || got.AcceptedReason != "known" {
		t.Fatalf("finding %s = %+v, want accepted", accepted, got)
	}
	_, steps := c.meta.Grader().Grade(*got)
	if !slices.ContainsFunc(steps, func(s finding.Step) bool {
		return s.To == "accepted" && strings.Contains(s.Reason, "accepted in "+entry)
	}) {
		t.Errorf("the acceptance is not attributed to %s: %+v", entry, steps)
	}
	if c.OpenFindings() != base.OpenFindings()-1 {
		t.Errorf("open findings %d, want %d", c.OpenFindings(), base.OpenFindings()-1)
	}
	if len(env.Run.ContextSources) != 1 || env.Run.ContextSources[0].Name != src || env.Run.ContextSources[0].Kind != "config" {
		t.Errorf("context sources = %+v", env.Run.ContextSources)
	}
}

// losingTarget answers like inner until it has run after commands, then
// as a session that is gone.
type losingTarget struct {
	inner target.Target
	after int
	n     int
}

func (l *losingTarget) Exec(ctx context.Context, argv []string) (target.Result, error) {
	if l.n++; l.n > l.after {
		return target.Result{Code: -1}, fmt.Errorf("ssh: session: EOF (%w)", target.ErrTransport)
	}
	return l.inner.Exec(ctx, argv)
}
func (l *losingTarget) Platform() target.Platform   { return l.inner.Platform() }
func (l *losingTarget) Transport() target.Transport { return target.TransportSSH }

// A session lost mid-run stops the plan: the facts read before it are
// kept, nothing after it runs, and the collection is incomplete with the
// failure named, never a complete run of unavailable checks.
func TestLostSessionCutsTheCollection(t *testing.T) {
	lt := &losingTarget{inner: load(t, "ubuntu"), after: 10}
	c, err := Collect(context.Background(), Options{Target: lt, Elevate: "sudo"})
	if err != nil {
		t.Fatal(err)
	}
	env := c.Envelope()
	if c.Complete() || c.Lost() == "" || env.Run.Status != "incomplete" {
		t.Fatalf("complete %v, lost %q, status %s", c.Complete(), c.Lost(), env.Run.Status)
	}
	// One exec past the loss, the one that found it: an availability probe
	// counts, since under sudo it is what meets the lost session first.
	if lt.n != lt.after+1 {
		t.Errorf("%d execs after the session was lost, want none", lt.n-lt.after-1)
	}
	last := c.sheet.Results[c.sheet.Order[len(c.sheet.Order)-1]]
	if !last.TransportLost || len(env.Facts) != len(c.sheet.Order) {
		t.Errorf("last check %s: %+v", last.CheckID, last)
	}
	if !slices.ContainsFunc(env.Run.Warnings, func(w string) bool { return strings.Contains(w, "connection was lost") }) {
		t.Errorf("warnings = %q", env.Run.Warnings)
	}
}

// The redactor carries the engagement's redact_extra, and a secret on the
// host never reaches the envelope.
func TestRedactExtraAndSeededSecret(t *testing.T) {
	fx := fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux box 6.8 key=AKIAIOSFODNN7EXAMPLE codename=tangerine-42\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/machine-id"}, Stdout: "0123456789abcdef0123456789abcdef\n"},
	)
	c, err := Collect(context.Background(), Options{Target: fx, RedactExtra: []string{`tanger[i]ne-[0-9]+`}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.WriteJSON(&out, c.Envelope()); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "tangerine-42"} {
		if bytes.Contains(out.Bytes(), []byte(secret)) {
			t.Errorf("%s reached the envelope", secret)
		}
	}
	for _, marker := range []string{"[REDACTED:aws-access-key:20 bytes]", "[REDACTED:extra:0:12 bytes]"} {
		if !bytes.Contains(out.Bytes(), []byte(marker)) {
			t.Errorf("marker %s missing", marker)
		}
	}
}

// A run timeout cuts the collection: incomplete, as in 0.0.1.
func TestRunTimeoutCutsTheCollection(t *testing.T) {
	fx := fixture.New(check.Linux, fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux\n", Sleep: time.Second})
	c, err := Collect(context.Background(), Options{Target: fx, RunTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if c.Complete() || c.Envelope().Run.Status != "incomplete" {
		t.Fatalf("complete = %v, status %s", c.Complete(), c.Envelope().Run.Status)
	}
}

// What the operator must fix is a usage error; a host that never answered
// is a transport failure.
func TestErrorsAreClassified(t *testing.T) {
	_, err := Collect(context.Background(), Options{Host: "203.0.113.5", Port: 22})
	if e, ok := errors.AsType[*Error](err); !ok || !e.Usage {
		t.Fatalf("no SSH user: %v, want a usage error", err)
	}
	_, err = Collect(context.Background(), Options{Target: fixture.New(target.Unknown)})
	if e, ok := errors.AsType[*Error](err); !ok || e.Usage {
		t.Fatalf("unknown platform: %v, want a transport failure", err)
	}
	_, err = Collect(context.Background(), Options{Target: fixture.New(check.Linux), Profile: "paranoid"})
	if e, ok := errors.AsType[*Error](err); !ok || !e.Usage {
		t.Fatalf("bad profile: %v, want a usage error", err)
	}
}
