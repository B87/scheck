package report

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

// Every risk area has a fixed list of what this version does not judge,
// its ids unique and named for the area (docs/spec/report.md, "Coverage").
func TestEveryAreaHasAFixedList(t *testing.T) {
	seen := map[string]bool{}
	for _, area := range finding.Areas {
		items := fixedNotJudged[area]
		if len(items) == 0 {
			t.Errorf("area %s has no fixed not-judged list", area)
		}
		for _, f := range items {
			if !strings.HasPrefix(f.ID, string(area)+".") || f.Text == "" {
				t.Errorf("fixed item %q in %s: id must start with the area key and have text", f.ID, area)
			}
			if seen[f.ID] {
				t.Errorf("fixed item %q listed twice", f.ID)
			}
			seen[f.ID] = true
		}
	}
	if len(fixedNotJudged) != len(finding.Areas) {
		t.Errorf("fixed lists for %d areas, want %d", len(fixedNotJudged), len(finding.Areas))
	}
}

// An unbuilt item makes an assessed row partial and changes nothing else:
// it lifts no row that was not checked and leaves the operator's
// not_used declaration as it is.
func TestAFixedListOnlyLowersAssessed(t *testing.T) {
	for mark, want := range map[string]string{"assessed": "partial", "partial": "partial", "not_assessed": "not_assessed", "not_applicable": "not_applicable"} {
		got := withFixedList(Row{Area: "identity", Mark: mark}, finding.AreaIdentity)
		if got.Mark != want || len(got.NotJudged) == 0 {
			t.Errorf("%s became %s with %d fixed items, want %s", mark, got.Mark, len(got.NotJudged), want)
		}
	}
}

// The list changes marks only: the exit and what the run left incomplete
// are the same as with no list at all.
func TestAFixedListLeavesTheExitAlone(t *testing.T) {
	for name, in := range map[string]func(*testing.T) Input{"host": func(t *testing.T) Input { return oneHost(t, "ubuntu") }, "domain": withDomainRoot, "lost": lostSession} {
		with := build(in(t))
		// Not parallel: the list is package state.
		without := func() *Report {
			saved := fixedNotJudged
			defer func() { fixedNotJudged = saved }()
			fixedNotJudged = map[finding.Area][]FixedItem{}
			return build(in(t))
		}()
		if !reflect.DeepEqual(with.Exit, without.Exit) || !reflect.DeepEqual(with.Incomplete, without.Incomplete) {
			t.Errorf("%s: the fixed list changed the exit or the shortfalls: %+v %+v", name, with.Exit, without.Exit)
		}
	}
}

// Every risk-area row carries its list, folded and not-applicable ones too,
// and no other row does.
func TestEveryAreaRowCarriesItsList(t *testing.T) {
	in := withDomainRoot(t)
	in.NotUsed = []string{"cloud"}
	r := build(in)
	validate(t, schema(t), r)
	for _, row := range r.Coverage {
		area := finding.Area(row.Area)
		if !slices.Contains(finding.Areas, area) {
			if row.NotJudged != nil {
				t.Errorf("row %s/%s carries a fixed list", row.Area, row.Tool)
			}
			continue
		}
		if !slices.Equal(row.NotJudged, fixedNotJudged[area]) {
			t.Errorf("row %s carries %v", row.Area, row.NotJudged)
		}
		if row.Mark == "assessed" {
			t.Errorf("row %s is assessed with a fixed list", row.Area)
		}
	}
	if got := row(t, r, "cloud"); got.Mark != "not_applicable" {
		t.Errorf("cloud declared not used is %s", got.Mark)
	}
}

// The text prints the list once per row it prints on its own, joins the
// limits inside built sub-items to it, and never prints it for a row the
// operator declared not used or a folded one.
func TestTheTextPrintsTheListOncePerRow(t *testing.T) {
	in := withDomainRoot(t)
	in.NotUsed = []string{"cloud"}
	var buf bytes.Buffer
	if err := WriteText(&buf, build(in), Options{}); err != nil {
		t.Fatal(err)
	}
	out := strings.Join(strings.Fields(buf.String()), " ")
	for _, area := range []finding.Area{finding.AreaExternal, finding.AreaWeb} {
		if n := strings.Count(out, fixedNotJudged[area][0].Text); n != 1 {
			t.Errorf("%s's list printed %d times", area, n)
		}
	}
	for _, area := range []finding.Area{finding.AreaCloud, finding.AreaIdentity} {
		if strings.Contains(out, fixedNotJudged[area][0].Text) {
			t.Errorf("%s's list printed for a not-used or folded row", area)
		}
	}
	if strings.Contains(out, "this version of scheck has no rule for it (TLS versions") {
		t.Error("a limit still prints as a no_rule reason")
	}
	if !strings.Contains(out, "Also not judged on the assets read: TLS versions and ciphers other than those negotiated, and revocation.") {
		t.Error("the external row's limit is not joined to its list")
	}
}
