package baseline

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

var update = flag.Bool("update", false, "rewrite the golden command traces")

// traceElevation replays each fixture the way it was recorded, like the
// report goldens do (see TestFixtureReplay).
var traceElevation = map[string]runner.Elevation{
	"ubuntu": runner.ElevateSudo,
	"fedora": runner.ElevateSudo,
	"macos":  runner.ElevateNone,
}

// The command trace is the run's own audit log, pinned per fixture (M4.5,
// docs/SPEC.md §11): one line per attempted check in execution order, with the
// observation reference, the bound parameters, the actual argv, the decision,
// the exit code, the elevation and the SHA-256 of the redacted output. The
// report goldens say what an operator reads; this one says what reached the
// target, and it is the artifact that fails if the tool ever quietly starts
// running something else. Regenerate with `go test ./internal/baseline
// -update` and read the diff as a review item.
//
// A baseline plan takes no parameters, so it produces no `denied:` line; the
// denial format is asserted directly in internal/runner (unknown check,
// path.not_allowed, param), not goldened here.
func TestGoldenCommandTrace(t *testing.T) {
	for name, elev := range traceElevation {
		t.Run(name, func(t *testing.T) {
			got := replayTrace(t, name, elev)
			// Observation references are assigned in execution order, so a
			// replay reproduces them exactly. That is why the suite has no
			// remapping step: there is nothing nondeterministic to remap.
			if again := replayTrace(t, name, elev); again != got {
				t.Error("the trace is not reproducible across replays")
			}
			compareTrace(t, name+"-trace.jsonl", got)
		})
	}
}

func replayTrace(t *testing.T, name string, elev runner.Elevation) string {
	t.Helper()
	fx, err := fixture.Load(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Skip(err)
	}
	var log bytes.Buffer
	red, _ := policy.NewRedactor(nil)
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red,
		Budgets: policy.DefaultBudgets(), Elevate: elev, Audit: policy.NewAudit(&log)}
	Run(context.Background(), r, Plan(fx.Platform(), nil), nil)
	return normalizeTrace(t, log.String())
}

// normalizeTrace zeroes the clock and the stopwatch, and nothing else. Every
// other field is the point of the artifact; round-tripping through
// policy.AuditEntry also asserts each line is one.
func normalizeTrace(t *testing.T, log string) string {
	t.Helper()
	var out strings.Builder
	for line := range strings.SplitSeq(strings.TrimSpace(log), "\n") {
		var e policy.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not an AuditEntry: %v\n%s", err, line)
		}
		e.Time, e.DurationMS = time.Time{}, 0
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.String()
}

func compareTrace(t *testing.T, name, got string) {
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
		t.Fatalf("%v (run `go test ./internal/baseline -update` to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden trace.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}
