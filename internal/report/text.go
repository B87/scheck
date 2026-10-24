package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// WriteFactSheet renders a host's fact sheet (docs/spec/host-collector.md
// §6.6): one row per check with its domain, an execution status that never
// reads as a verdict, and its one-line reading; -v adds each check's
// description and -vv its redacted output. The engagement report prints it
// per host at -v; it is no longer a report of its own (0.0.2 E2).
func WriteFactSheet(w io.Writer, env Envelope, opt Options) error {
	t := &textReport{env: env, opt: opt.normalize()}
	t.st = style{on: t.opt.Color}
	t.platform = check.Platform(env.Host.Platform)
	t.facts()
	_, err := io.WriteString(w, t.b.String())
	return err
}

type textReport struct {
	b        strings.Builder
	env      Envelope
	opt      Options
	st       style
	platform check.Platform
}

// line writes one already-fitting line with no trailing padding.
func (t *textReport) line(s string) {
	t.b.WriteString(strings.TrimRight(s, " "))
	t.b.WriteByte('\n')
}

// row is one check's line in the fact sheet.
type row struct {
	id    string
	chk   check.Check
	known bool
	fact  Fact
}

func (t *textReport) rows() []row {
	out := make([]row, 0, len(t.env.Facts))
	for id, f := range t.env.Facts {
		c, ok := check.Lookup(id, t.platform)
		out = append(out, row{id: id, chk: c, known: ok, fact: f})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := domainOrder(out[i].chk.Domain), domainOrder(out[j].chk.Domain)
		if a != b {
			return a < b
		}
		if out[i].chk.Domain != out[j].chk.Domain {
			return out[i].chk.Domain < out[j].chk.Domain
		}
		return out[i].id < out[j].id
	})
	return out
}

// Column widths. STATUS is as wide as its widest word; DOMAIN and CHECK are
// sized from the data and capped so a long label cannot eat the READING
// column.
const (
	statusColumn   = 7 // len("skipped")
	maxDomainWidth = 24
	maxCheckWidth  = 30
	minReadingCol  = 24
	gutter         = 2
)

// facts prints the fact sheet as one flat table: every row carries its domain,
// so the output sorts, greps and pipes as a table rather than a document. The
// status word says what the command did, never whether the host is configured
// well (docs/spec/host-collector.md §6.6).
func (t *textReport) facts() {
	rows := t.rows()
	if len(rows) == 0 {
		return
	}
	domainW, checkW := len("DOMAIN"), len("CHECK")
	for _, r := range rows {
		domainW = max(domainW, min(len([]rune(t.domainOf(r))), maxDomainWidth))
		checkW = max(checkW, min(len([]rune(r.id)), maxCheckWidth))
	}
	prefix := domainW + gutter + statusColumn + gutter + checkW + gutter
	reading := max(t.opt.Width-prefix, minReadingCol)
	contIndent := strings.Repeat(" ", prefix)

	t.line("")
	t.line(t.st.bold(pad("DOMAIN", domainW) + sp + pad("STATUS", statusColumn) + sp + pad("CHECK", checkW) + sp + "READING"))
	for _, r := range rows {
		head := pad(clip(t.domainOf(r), domainW), domainW) + sp +
			pad(statusWord(r.fact.Status), statusColumn) + sp +
			pad(clip(r.id, checkW), checkW) + sp
		for i, l := range wrap(t.detail(r), reading) {
			if i == 0 {
				t.line(head + l)
				continue
			}
			t.line(contIndent + l)
		}
		if t.opt.Verbose >= 1 && r.chk.Description != "" {
			for _, l := range wrap(r.chk.Description, reading) {
				t.line(contIndent + t.st.dim(l))
			}
		}
		if t.opt.Verbose >= 2 {
			t.output(r)
		}
	}
}

const sp = "  " // one column gutter

// domainOf is the human label for a row's domain; a check the catalog does
// not know (a report rendered on another platform, or a retired id) is still
// listed, under "Other".
func (t *textReport) domainOf(r row) string {
	if !r.known {
		return "Other"
	}
	return DomainLabel(r.chk.Domain)
}

// clip shortens s to n runes, marking that it was cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "\u2026"
}

// detail is the right-hand column: the one-line reading of a successful check,
// or the reason it did not run.
func (t *textReport) detail(r row) string {
	f := r.fact
	// A fact built by Build carries its summary; one handed to the renderer
	// directly is summarised here, so text and JSON never disagree.
	s := f.Summary
	if s == "" {
		s = Summarize(r.chk, f)
	}
	var flags []string
	// A check whose rule fired shows the finding's severity: a status word
	// describes execution and must never read as "posture ok"
	// (docs/spec/host-collector.md §6.6).
	for _, sev := range t.severitiesFor(r.id) {
		flags = append(flags, "finding: "+string(sev))
	}
	if f.Status == "ok" && f.Reason != "" {
		flags = append(flags, sanitize(f.Reason))
	}
	if f.Elevated {
		flags = append(flags, "elevated")
	}
	if f.Redactions > 0 {
		flags = append(flags, fmt.Sprintf("%d redacted", f.Redactions))
	}
	if f.Truncated {
		flags = append(flags, "truncated")
	}
	if len(flags) > 0 {
		s += " [" + strings.Join(flags, ", ") + "]"
	}
	return s
}

// output prints the check's stdout at -vv. It is the redacted, truncated
// capture the runner produced (docs/spec/host-collector.md §4.2); there is no other way to
// see a check's output and nothing here has bypassed the redactor.
func (t *textReport) output(r row) {
	if !r.fact.Attempted && r.fact.Status != "ok" {
		return
	}
	body := strings.TrimRight(expandTabs(sanitize(r.fact.Output)), "\n")
	if r.fact.Stderr != "" {
		body += "\nstderr:\n" + expandTabs(sanitize(r.fact.Stderr))
	}
	// Evidence gets the full width behind a gutter rather than the READING
	// column: command output has its own alignment worth preserving.
	indent := "  | "
	if body == "" {
		t.line(indent + t.st.dim("(no output)"))
		return
	}
	avail := max(t.opt.Width-len([]rune(indent)), 20)
	for _, l := range wrap(body, avail) {
		t.line(indent + t.st.dim(l))
	}
}

// severitiesFor lists the severities of the findings whose evidence includes
// this check, most serious first.
func (t *textReport) severitiesFor(id string) []finding.Severity {
	var out []finding.Severity
	for _, f := range t.env.Findings {
		for _, e := range f.Evidence {
			if e.Check == id {
				out = append(out, f.Severity)
				break
			}
		}
	}
	return out
}

func statusWord(status string) string {
	switch status {
	case "ok":
		return "ran"
	case "unavailable":
		return "skipped"
	case "denied":
		return "denied"
	default:
		return status
	}
}
