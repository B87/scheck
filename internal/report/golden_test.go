package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/runner"
)

var update = flag.Bool("update", false, "rewrite the golden text reports")

// fixtureElevation matches how each fixture was recorded (see
// internal/baseline/fixtures_test.go): the Linux containers ran with the
// sudoers fragment installed, the Mac unprivileged. Replaying macos under
// --sudo would show every elevated check as a missing binary instead of the
// "requires elevated read" skip the report is meant to explain.
var fixtureElevation = map[string]runner.Elevation{
	"ubuntu": runner.ElevateSudo,
	"fedora": runner.ElevateSudo,
	"macos":  runner.ElevateNone,
}

// The text report is a contract (docs/SPEC.md §7.6), so it is pinned per
// fixture at every verbosity. Regenerate with `go test ./internal/report
// -update` and read the diff: a change here is a change to what an operator
// reads.
func TestGoldenTextReports(t *testing.T) {
	for name, elev := range fixtureElevation {
		for _, v := range []int{0, 1, 2} {
			t.Run(name+verbSuffix(v), func(t *testing.T) {
				env := Build(sheetFor(t, name, elev), goldenMeta(elev))
				var buf bytes.Buffer
				if err := WriteText(&buf, normalize(env), Options{Verbose: v}); err != nil {
					t.Fatal(err)
				}
				compareGolden(t, name+verbSuffix(v)+".txt", buf.String())
			})
		}
	}
}

// No rendered line may exceed the wrap width, and none may carry trailing
// padding (docs/SPEC.md §7.6). Checked over every golden at several widths.
func TestTextReportRespectsWidth(t *testing.T) {
	for name, elev := range fixtureElevation {
		env := normalize(Build(sheetFor(t, name, elev), goldenMeta(elev)))
		for _, width := range []int{0, 60, 80, 100, 200} {
			var buf bytes.Buffer
			if err := WriteText(&buf, env, Options{Verbose: 2, Width: width}); err != nil {
				t.Fatal(err)
			}
			want := width
			if want == 0 {
				want = DefaultWidth
			}
			// The table's own columns set a floor below which the layout
			// cannot shrink; prose and evidence must still fit.
			floor := tableFloor(env)
			for i, line := range strings.Split(buf.String(), "\n") {
				if line != strings.TrimRight(line, " \t") {
					t.Fatalf("%s w=%d line %d has trailing padding: %q", name, width, i+1, line)
				}
				if n := len([]rune(line)); n > want && n > floor {
					t.Fatalf("%s w=%d line %d is %d runes (want <= %d):\n%s", name, width, i+1, n, want, line)
				}
			}
		}
	}
}

// tableFloor is the narrowest the fact table can be: its fixed columns plus
// the minimum reading column.
func tableFloor(env Envelope) int {
	domainW, checkW := len("DOMAIN"), len("CHECK")
	for id := range env.Facts {
		checkW = max(checkW, min(len(id), maxCheckWidth))
	}
	for _, e := range domainLabels {
		domainW = max(domainW, min(len(e.Label), maxDomainWidth))
	}
	return domainW + gutter + statusColumn + gutter + checkW + gutter + minReadingCol
}

func verbSuffix(v int) string {
	switch v {
	case 0:
		return "-default"
	case 1:
		return "-v"
	default:
		return "-vv"
	}
}

func goldenMeta(elev runner.Elevation) Meta {
	m := meta()
	m.Elevation = string(elev)
	return m
}

// normalize removes what changes between runs so a golden file diff shows
// only rendering changes.
func normalize(env Envelope) Envelope {
	env.Run.Started = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	env.Run.DurationMS = 1234
	env.Run.Persisted = nil
	for id, f := range env.Facts {
		f.DurationMS = 0
		env.Facts[id] = f
	}
	return env
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
		t.Fatalf("%v (run `go test ./internal/report -update` to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden report.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}
