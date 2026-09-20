package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// severityColumn is as wide as the widest severity word.
const severityColumn = 8 // len("critical")

// findings renders the findings first, ahead of the fact sheet: what the run
// concluded, then what it observed (docs/SPEC.md §7.6). Each one is its
// title, the evidence excerpt with the check it came from, and the
// remediation summary; -v adds the impact and the remediation commands.
func (t *textReport) findings() {
	fs := t.env.Findings
	if len(fs) == 0 {
		return
	}
	t.line("")
	t.line(t.st.bold(fmt.Sprintf("Findings (%d)", len(fs))))
	indent := strings.Repeat(" ", 2+severityColumn+gutter)
	for _, f := range fs {
		head := "  " + pad(string(f.Severity), severityColumn) + sp
		title := sanitize(f.Title) + " [" + f.ID + "]"
		if f.Status == finding.StatusAccepted {
			title += " [accepted]"
		}
		if f.Custom {
			title += " [custom]"
		}
		for i, l := range wrapHanging(head, indent, title, t.opt.Width) {
			if i == 0 {
				// Colour the severity word only: it is the one thing in the
				// report whose colour carries meaning (docs/SPEC.md §7.6).
				l = "  " + t.st.severity(f.Severity, pad(string(f.Severity), severityColumn)) + sp +
					strings.TrimPrefix(l, head)
			}
			t.line(l)
		}
		for _, e := range f.Evidence {
			ref := e.Observation
			if ref == "" {
				ref = e.Check
			} // operator context has no target observation
			t.hang(indent+"evidence  ", indent+"          ",
				sanitize(ref)+": "+sanitize(inline(e.Excerpt)))
		}
		if f.Status == finding.StatusAccepted {
			t.hang(indent+"accepted  ", indent+"          ", sanitize(f.AcceptedReason)+" (excluded from the exit code)")
		}
		if f.ContextNote != "" {
			t.hang(indent+"context   ", indent+"          ", sanitize(f.ContextNote))
		}
		t.hang(indent+"fix       ", indent+"          ", sanitize(f.Remediation.Summary))
		if t.opt.Verbose >= 1 {
			// Every severity change is attributed (docs/SPEC.md §6.4).
			if len(f.Adjustments) > 0 {
				parts := make([]string, 0, len(f.Adjustments))
				for _, a := range f.Adjustments {
					parts = append(parts, fmt.Sprintf("%s (%s, from %s)", a.Rule, a.Delta, sanitize(a.Source)))
				}
				t.hang(indent+"severity  ", indent+"          ", fmt.Sprintf("base %s → %s: %s", f.SeverityBase, f.Severity, strings.Join(parts, "; ")))
			}
			t.hang(indent+"impact    ", indent+"          ", sanitize(f.Impact))
			// Commands are text for the human; scheck never runs one
			// (docs/SPEC.md §7.3). They keep their own lines rather than
			// being wrapped into prose, so they can be copied.
			for i, c := range f.Remediation.Commands {
				label := "          "
				if i == 0 {
					label = "commands  "
				}
				t.line(indent + label + t.st.dim(clip(sanitize(c), max(t.opt.Width-len(indent)-10, 20))))
			}
			if f.Remediation.Caveat != "" {
				t.hang(indent+"caveat    ", indent+"          ", f.Remediation.Caveat)
			}
		}
	}
}

// coverage closes the findings section with the rules that could not be
// evaluated. A rule that was not assessed is not a rule that passed, so it is
// named, grouped by the check that let it down, with that check's own remedy
// (docs/SPEC.md §7.5).
func (t *textReport) coverage() {
	na := t.env.NotAssessed()
	if len(na) > 0 {
		t.line("")
		t.line(t.st.bold(fmt.Sprintf("Not assessed (%d)", len(na))))
		t.para("  ", "these posture rules had no usable evidence; they are not passes")
		for _, g := range t.groupAssessments(na) {
			t.hang("  "+g.check+" ", "    ", g.text)
			t.para("    ", strings.Join(g.findings, ", "))
			if g.remedy != "" {
				t.hang("    remedy: ", "            ", g.remedy)
			}
		}
	}
	if t.opt.Verbose < 1 || len(t.env.Assessments) == 0 {
		return
	}
	// -v prints the whole coverage table, including the rules that were
	// disproved and the ones that do not apply to this host.
	t.line("")
	t.line(t.st.bold(fmt.Sprintf("Rule coverage (%d)", len(t.env.Assessments))))
	as := make([]finding.Assessment, len(t.env.Assessments))
	copy(as, t.env.Assessments)
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Finding != as[j].Finding {
			return as[i].Finding < as[j].Finding
		}
		return as[i].Check < as[j].Check
	})
	idw, statusW := 0, 0
	for _, a := range as {
		idw = max(idw, min(len([]rune(a.Finding)), maxCheckWidth+8))
		statusW = max(statusW, len(a.Status))
	}
	for _, a := range as {
		t.hang("  "+pad(clip(a.Finding, idw), idw)+sp+pad(a.Status, statusW)+sp,
			strings.Repeat(" ", 2+idw+gutter+statusW+gutter),
			a.Check+" · "+sanitize(a.Reason))
	}
}

// findingsLine is the header's one-sentence result: what was concluded before
// what was executed (docs/SPEC.md §7.6).
func (t *textReport) findingsLine() string {
	fs := t.env.Findings
	if len(fs) == 0 {
		// Never "no findings": nothing here looked at what no rule covers.
		return "0 findings from posture rules"
	}
	var open []finding.Finding
	accepted := 0
	for _, f := range fs {
		if f.Open() {
			open = append(open, f)
		} else {
			accepted++
		}
	}
	var parts []string
	for _, c := range finding.CountBySeverity(open) {
		parts = append(parts, fmt.Sprintf("%d %s", c.Count, c.Severity))
	}
	noun := "findings"
	if len(fs) == 1 {
		noun = "finding"
	}
	s := fmt.Sprintf("%d %s", len(fs), noun)
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	if accepted > 0 {
		s += fmt.Sprintf(", %d accepted", accepted)
	}
	return s
}
