package report

import (
	"sort"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// assessmentClass turns an evaluator reason code into words an operator can
// act on. The codes are the evaluator's contract (docs/SPEC.md §7.5); the
// words are the report's.
type assessmentClass struct {
	text   string // "<check> reported a value this rule does not recognise"
	remedy string
}

var assessmentClasses = map[string]assessmentClass{
	"check-not-run": {
		text:   "was not part of this run",
		remedy: "the run ended before the check ran; re-run, or raise --timeout if it was cut short.",
	},
	"check-disabled-by-config": {
		text:   "is disabled in the configuration",
		remedy: "remove the check from `disable_checks` to let its rules run; configuration can only narrow what scheck does.",
	},
	"unrecognized-value": {
		text:   "reported a value this rule does not recognise",
		remedy: "re-run with -vv to see the output and report the check id: an unrecognised state is never read as safe.",
	},
	"unrecognized-state": {
		text:   "reported a state this rule does not recognise",
		remedy: "re-run with -vv to see the output and report the check id: an unrecognised state is never read as safe.",
	},
	"key-absent": {
		text:   "did not report the setting this rule reads",
		remedy: "check the tool's version on this host; the rule needs the setting to be present to judge it.",
	},
	"partial-output": {
		text:   "produced truncated or redacted output",
		remedy: "absence cannot be proved from partial evidence, so the rule stopped; narrow the check or raise its output budget.",
	},
	"value-redacted-or-truncated": {
		text:   "produced a value that was redacted or truncated",
		remedy: "absence cannot be proved from partial evidence, so the rule stopped; nothing on the host needs changing.",
	},
	"no-records": {
		text:   "produced no record for this rule to read",
		remedy: "re-run with -vv to see the output; an empty answer is not read as a pass.",
	},
	"unexpected-parsed-shape": {
		text:   "produced a shape this rule cannot read",
		remedy: "this is a scheck bug: the rule and the check's parser disagree. Report the check id.",
	},
}

// assessmentGroup is one (check, reason) bucket of missing coverage.
type assessmentGroup struct {
	check    string
	text     string
	remedy   string
	findings []string
}

// groupAssessments buckets not-assessed rules by check and reason. The remedy
// for a check that did not run is the check's own remedy, so a rule that is
// blind because of sudo says "re-run with --sudo" and not something vaguer.
func (t *textReport) groupAssessments(as []finding.Assessment) []assessmentGroup {
	byKey := map[string]*assessmentGroup{}
	var order []*assessmentGroup
	for _, a := range as {
		key := a.Check + "\x00" + a.Reason
		g := byKey[key]
		if g == nil {
			text, remedy := t.explainAssessment(a)
			g = &assessmentGroup{check: a.Check, text: text, remedy: remedy}
			byKey[key] = g
			order = append(order, g)
		}
		g.findings = append(g.findings, a.Finding)
	}
	out := make([]assessmentGroup, 0, len(order))
	for _, g := range order {
		sort.Strings(g.findings)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].check != out[j].check {
			return out[i].check < out[j].check
		}
		return out[i].text < out[j].text
	})
	return out
}

func (t *textReport) explainAssessment(a finding.Assessment) (text, remedy string) {
	code, detail, _ := strings.Cut(a.Reason, ":")
	switch code {
	case "check-unavailable", "check-denied":
		// The check's own reason is more specific than the code, and the
		// report already knows how to explain it.
		if f, ok := t.env.Facts[a.Check]; ok && f.Reason != "" {
			cls := classify(f.Reason)
			return "did not run: " + sanitize(reasonDetail(f.Reason)), cls.remedy
		}
		if detail != "" {
			return "did not run: " + detail, ""
		}
		return "did not run", ""
	}
	if cls, ok := assessmentClasses[code]; ok {
		return cls.text, cls.remedy
	}
	return sanitize(a.Reason), ""
}
