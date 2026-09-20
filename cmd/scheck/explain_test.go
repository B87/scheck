package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the complete catalog
	"github.com/b87/scheck/internal/report"
)

// flat collapses the wrapped layout so a test can assert on a sentence
// without pinning where it breaks.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

func explain(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"explain"}, args...))
	err := root.Execute()
	return out.String(), err
}

// explain prints one catalog entry verbatim: the literal argv, the parser,
// the elevation and the typed parameters (docs/SPEC.md §8).
func TestExplainShowsTheWholeEntry(t *testing.T) {
	out, err := explain(t, "sshd.config")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := check.Lookup("sshd.config", check.Linux)
	if !ok {
		t.Fatal("sshd.config missing from the catalog")
	}
	for _, want := range []string{
		"sshd.config",
		"SSH server", // the human domain label
		"sshd",       // the domain slug stays visible next to it
		c.Description,
		argvString(c.Argv),
		"kv",
		"baseline",
		"elevation",
	} {
		if !strings.Contains(flat(out), flat(want)) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
}

// A parameterised check shows its placeholders as placeholders, never bound
// to a value: argv is a template, not a command line to copy blindly.
func TestExplainShowsTypedParameters(t *testing.T) {
	out, err := explain(t, "fs.stat")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := check.Lookup("fs.stat", check.Linux)
	if len(c.Params) == 0 {
		t.Skip("fs.stat has no params in this catalog")
	}
	for _, p := range c.Params {
		if !strings.Contains(out, "{"+p.Name+"}") {
			t.Errorf("placeholder {%s} missing:\n%s", p.Name, out)
		}
	}
	if !strings.Contains(flat(out), "path policy") {
		t.Errorf("a path param must say it goes through the path policy:\n%s", out)
	}
}

// An id defined once per platform prints one section per platform, clearly
// labelled, rather than silently picking one.
func TestExplainHandlesPlatformSpecificDefinitions(t *testing.T) {
	var id string
	for _, c := range check.All() {
		if len(explainEntries(c.ID)) > 1 {
			id = c.ID
			break
		}
	}
	if id == "" {
		t.Skip("no platform-specific ids in the catalog")
	}
	out, err := explain(t, id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "platform-specific definitions") {
		t.Errorf("platform split not announced:\n%s", out)
	}
	for _, c := range explainEntries(id) {
		if !strings.Contains(out, "on "+string(c.Platform)) {
			t.Errorf("missing section for %s:\n%s", c.Platform, out)
		}
		if !strings.Contains(flat(out), flat(argvString(c.Argv))) {
			t.Errorf("missing argv for %s:\n%s", c.Platform, out)
		}
	}
}

// An elevated check says so, and says what happens without --sudo.
func TestExplainDescribesElevation(t *testing.T) {
	var id string
	for _, c := range check.All() {
		if c.Elevated {
			id = c.ID
			break
		}
	}
	out, err := explain(t, id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(flat(out), "sudo -n --") || !strings.Contains(flat(out), "requires elevated read") {
		t.Errorf("elevation not explained for %s:\n%s", id, out)
	}
}

// An unknown id is a usage error (exit 3), not an empty page.
func TestExplainUnknownID(t *testing.T) {
	_, err := explain(t, "no.such_check")
	var ee *exitError
	if !errors.As(err, &ee) || ee.Code != exitUsage {
		t.Fatalf("want a usage error, got %v", err)
	}
	if !strings.Contains(err.Error(), "scheck catalog") {
		t.Errorf("error should point at the catalog: %v", err)
	}
}

// Every catalog entry explains itself without panicking, and no line of any
// explanation overruns the wrap width.
func TestExplainEveryCheckFitsTheWidth(t *testing.T) {
	for _, c := range check.All() {
		var buf bytes.Buffer
		if err := writeExplain(&buf, c.ID, explainEntries(c.ID), report.Options{Width: report.DefaultWidth}); err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(buf.String(), "\n") {
			if n := len([]rune(line)); n > report.DefaultWidth {
				t.Errorf("%s: line of %d runes:\n%s", c.ID, n, line)
			}
			if line != strings.TrimRight(line, " ") {
				t.Errorf("%s: trailing padding: %q", c.ID, line)
			}
		}
	}
}
