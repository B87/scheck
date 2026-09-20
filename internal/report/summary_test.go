package report

import (
	"regexp"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// shapeOnly is the reading M1.6 produced and M1.7 replaced: a count of lines
// or keys, or the first raw line of a chatty command. No fact may read that
// way any more (docs/SPEC.md §7.6, roadmap M1.7).
var shapeOnly = regexp.MustCompile(`^\d+ (lines?|keys?|items?|records?)\b`)

// Every check that ran on every recorded fixture says something a person can
// read, in the same words the JSON carries.
func TestEveryFactHasAMeaningfulSummary(t *testing.T) {
	for name, elev := range fixtureElevation {
		t.Run(name, func(t *testing.T) {
			env := Build(sheetFor(t, name, elev), goldenMeta(elev))
			for id, f := range env.Facts {
				if f.Summary == "" {
					t.Errorf("%s: no summary", id)
					continue
				}
				if f.Status != "ok" {
					continue
				}
				if shapeOnly.MatchString(f.Summary) {
					t.Errorf("%s: shape-level reading %q; name the records with Unit or a typed shape", id, f.Summary)
				}
				if strings.Contains(f.Summary, "\n") {
					t.Errorf("%s: a summary is one line: %q", id, f.Summary)
				}
			}
		})
	}
}

// A count from incomplete output is labelled partial rather than presented as
// an exact total (docs/SPEC.md §7.5).
func TestPartialCountsAreLabelled(t *testing.T) {
	c, _ := check.Lookup("net.listeners", check.Linux)
	parsed, err := check.Parse(c, []byte("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n[TRUNCATED:900 bytes]"))
	if err != nil {
		t.Fatal(err)
	}
	got := Summarize(c, Fact{Status: "ok", Parsed: parsed})
	if !strings.Contains(got, "1 listening socket") || !strings.Contains(got, "partial") {
		t.Fatalf("summary %q must count and admit it is incomplete", got)
	}
}

// The summary of a check that did not run is why it did not run, escaped:
// target text can never forge a line of the report (docs/SPEC.md §7.6).
func TestSummaryOfUnavailableFactIsItsReason(t *testing.T) {
	c, _ := check.Lookup("sshd.config", check.Linux)
	got := Summarize(c, Fact{Status: "unavailable", Reason: "requires elevated read"})
	if got != "requires elevated read" {
		t.Errorf("got %q", got)
	}
	if got := Summarize(c, Fact{Status: "denied"}); got != "denied, no reason recorded" {
		t.Errorf("a denial with no reason must still say something: %q", got)
	}
	evil := Summarize(c, Fact{Status: "unavailable", Reason: "exit 1: \x1b[2Jforged"})
	if strings.Contains(evil, "\x1b") {
		t.Errorf("control character survived into a summary: %q", evil)
	}
}

// The text report and the JSON envelope read the same string, because it is
// the same string (docs/SPEC.md §7.4).
func TestTextAndJSONShareTheSummary(t *testing.T) {
	sheet := sheetFor(t, "ubuntu", runner.ElevateSudo)
	env := Build(sheet, goldenMeta(runner.ElevateSudo))
	out := render(t, env, Options{Width: 200})
	for id, f := range env.Facts {
		if f.Status != "ok" || strings.Contains(f.Summary, "(") {
			continue // flags and partial notes are rendered alongside, not inside
		}
		if !strings.Contains(out, f.Summary) {
			t.Errorf("%s: %q is in the JSON but not in the text report", id, f.Summary)
		}
	}
}
