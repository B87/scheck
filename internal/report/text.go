package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// WriteText renders the report a person reads (docs/SPEC.md §7.6): a two-line
// header, the facts grouped by domain with an explicit execution status, the
// checks that did not run grouped by reason with a remedy, and a footer that
// says what this build did not assess.
func WriteText(w io.Writer, env Envelope, opt Options) error {
	t := &textReport{env: env, opt: opt.normalize()}
	t.st = style{on: t.opt.Color}
	t.platform = check.Platform(env.Host.Platform)
	t.header()
	t.findings()
	t.coverage()
	t.modelSummary()
	t.facts()
	t.notRun()
	t.footer()
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

// para wraps s to the report width under a fixed indent.
func (t *textReport) para(indent, s string) {
	t.hang(indent, indent, s)
}

// hang wraps s under a first-line prefix, aligning continuations past it.
// The prefix counts against the first line's width, so nothing overruns.
func (t *textReport) hang(first, indent, s string) {
	for _, l := range wrapHanging(first, indent, s, t.opt.Width) {
		t.line(l)
	}
}

// header is the two lines of docs/SPEC.md §7.6: who was audited and how, then
// what the run did. host.id, kernel, profile, mode and timings move to -v.
func (t *textReport) header() {
	h, r := t.env.Host, t.env.Run
	host := h.Hostname
	if host == "" {
		host = "unknown host"
	}
	// The OS string already names the platform ("Ubuntu 24.04", "macOS
	// 26.6"), so the bare platform is printed only when it does not.
	osName := h.OS
	if osName == "" {
		osName = "unidentified " + h.Platform
	}
	transport := h.Transport
	if transport == "" {
		transport = "unknown transport"
	}
	first := fmt.Sprintf("scheck %s — %s — %s — %s, elevation %s",
		r.Version, host, osName, transport, h.Elevation)
	// Styling is applied to whole lines only, after wrapping: an escape
	// sequence must never count against a line's width.
	for _, l := range wrap(inline(first), t.opt.Width) {
		t.line(t.st.bold(l))
	}

	ran, skipped, denied := t.counts()
	parts := []string{fmt.Sprintf("%d ran", ran)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}
	if denied > 0 {
		parts = append(parts, fmt.Sprintf("%d denied by policy", denied))
	}
	result := []string{t.findingsLine()}
	if n := len(t.env.NotAssessed()); n > 0 {
		result = append(result, fmt.Sprintf("%d %s not assessed", n, plural(n, "rule")))
	}
	result = append(result, fmt.Sprintf("%d checks: %s", len(t.env.Facts), strings.Join(parts, ", ")))
	t.para("", strings.Join(result, ", "))

	if t.opt.Verbose >= 1 {
		detail := []string{
			"host.id " + short(h.ID),
			"kernel " + orNone(h.Kernel),
			"profile " + r.Profile,
			"mode " + r.Mode,
			"status " + r.Status,
			fmt.Sprintf("%dms", r.DurationMS),
		}
		if h.Transport == "ssh" {
			detail = append(detail, "remote shell "+orNone(h.RemoteShell), "canary "+h.Canary)
		}
		t.para("", inline(strings.Join(detail, " · ")))
		if r.Persisted != nil {
			t.para("", "persisted "+inline(*r.Persisted))
		}
	}
	for _, msg := range r.Warnings {
		t.hang("warning: ", "         ", sanitize(msg))
	}
}

func (t *textReport) counts() (ran, skipped, denied int) {
	for _, f := range t.env.Facts {
		switch f.Status {
		case "ok":
			ran++
		case "denied":
			denied++
		default:
			skipped++
		}
	}
	return
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
// well (docs/SPEC.md §7.6).
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
	// (docs/SPEC.md §7.6).
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
// capture the runner produced (docs/SPEC.md §4.2); there is no other way to
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

// notRun explains every check that produced no fact. Skipped checks are
// grouped by why, each group with the remedy; policy denials are their own
// section because nothing on the host needs changing for them
// (docs/SPEC.md §7.6).
func (t *textReport) notRun() {
	var skipped, denied []row
	for _, r := range t.rows() {
		switch r.fact.Status {
		case "ok":
		case "denied":
			denied = append(denied, r)
		default:
			skipped = append(skipped, r)
		}
	}
	t.section("Skipped", "these checks produced no usable fact; some executed but failed", skipped)
	t.section("Denied by policy", "scheck refused to run these; the target was never asked", denied)
}

func (t *textReport) section(title, note string, rows []row) {
	if len(rows) == 0 {
		return
	}
	t.line("")
	t.line(t.st.bold(fmt.Sprintf("%s (%d)", title, len(rows))))
	t.para("  ", note)
	for _, g := range groupByReason(rows) {
		t.para("  ", fmt.Sprintf("%d %s", len(g.rows), g.title))
		if g.detailed {
			idw := 0
			for _, r := range g.rows {
				idw = max(idw, min(len([]rune(r.id)), maxCheckWidth))
			}
			for _, r := range g.rows {
				t.hang("    "+pad(clip(r.id, idw), idw)+sp, strings.Repeat(" ", 4+idw+gutter),
					sanitize(reasonDetail(r.fact.Reason)))
			}
		} else {
			ids := make([]string, 0, len(g.rows))
			for _, r := range g.rows {
				ids = append(ids, r.id)
			}
			t.para("    ", strings.Join(ids, ", "))
		}
		if g.remedy != "" {
			t.hang("    remedy: ", "            ", g.remedy)
		}
	}
}

// modelSummary prints the model's closing text after the findings. It is
// model output: escaped like target output, labelled as the model's, never
// a verdict of scheck's.
func (t *textReport) modelSummary() {
	a := t.env.Run.Agent
	if a == nil || strings.TrimSpace(a.Text) == "" {
		return
	}
	t.line("")
	t.line(t.st.bold("Model summary"))
	t.para("  ", "the model's own closing words; findings above carry the code-assigned severity")
	for para := range strings.SplitSeq(strings.TrimSpace(a.Text), "\n") {
		if strings.TrimSpace(para) == "" {
			continue
		}
		t.para("  ", sanitize(para))
	}
}

// footer never claims an absence of problems: it says what assessed the
// host and what did not (docs/SPEC.md §7.6).
func (t *textReport) footer() {
	t.line("")
	r := t.env.Run
	var scope string
	if r.Agent == nil {
		scope = "assessment: posture rules only. "
	} else {
		provider, model := orNone(deref(r.Provider)), orNone(deref(r.Model))
		scope = fmt.Sprintf("assessment: posture rules and the %s pass (%s, %s; %d %s, %d model-initiated %s, %d/%d tokens in/out). ",
			r.Mode, provider, model, r.Agent.Iterations, plural(r.Agent.Iterations, "turn"), r.Agent.Checks, plural(r.Agent.Checks, "check"),
			r.Usage.Input, r.Usage.Output)
	}
	if n := len(t.env.Assessments); n == 0 {
		scope += "No posture rule applied to this host. "
	} else {
		scope += fmt.Sprintf("%d of %d rules had the evidence to decide. ", n-len(t.env.NotAssessed()), n)
	}
	tail := "Every other line reports what a command observed, not whether the host is " +
		"configured safely: a rule reads one fact and says nothing about what no rule covers. "
	if r.Agent == nil {
		tail += "The agentic pass did not run."
	} else if r.Agent.Ended != "model stopped" {
		tail += "The " + r.Mode + " pass did not finish: " + sanitize(r.Agent.Ended) + "."
	} else {
		tail += "Model findings carry code-assigned severity and evidence validated against check output."
	}
	t.para("", scope+tail)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
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

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
