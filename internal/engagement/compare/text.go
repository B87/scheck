package compare

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	hostreport "github.com/b87/scheck/internal/report"
)

// clean makes text taken from a report one safe line: control characters
// escaped, whitespace folded (docs/spec/host-collector.md §6.6). A report is
// text scheck wrote from a target's and an operator's, and a file given by
// path may be any text, so every string is escaped on the way out.
func clean(s string) string { return strings.Join(strings.Fields(hostreport.Sanitize(s)), " ") }

type tx struct {
	w    *bufio.Writer
	c    *Comparison
	opt  report.Options
	zone *time.Location
}

// WriteText renders the comparison a person reads. Terminal decisions
// (width, colour) arrive in opt; the text carries no colour, since no colour
// here may mean better or worse.
func WriteText(w io.Writer, c *Comparison, opt report.Options) error {
	if opt.Width <= 0 {
		opt.Width = hostreport.DefaultWidth
	}
	opt.Width = max(opt.Width, 60)
	t := &tx{w: bufio.NewWriter(w), c: c, opt: opt, zone: time.UTC}
	if z, err := time.LoadLocation(c.Later.Timezone); err == nil {
		t.zone = z
	}
	t.header()
	t.comparable()
	t.summary()
	t.sections()
	t.assets()
	t.coverage()
	t.people()
	t.closing()
	return t.w.Flush()
}

func (t *tx) line(s string) { _, _ = t.w.WriteString(strings.TrimRight(s, " ") + "\n") }
func (t *tx) blank()        { t.line("") }

func (t *tx) hang(first, indent, s string) {
	width := max(t.opt.Width-len([]rune(indent)), 20)
	for n, l := range hostreport.Wrap(s, width) {
		if n == 0 {
			t.line(first + l)
		} else {
			t.line(indent + l)
		}
	}
}

func (t *tx) heading(s string) {
	t.blank()
	t.line(s)
}

func (t *tx) date(ts time.Time) string { return ts.In(t.zone).Format("2006-01-02") }

func (t *tx) span(s Side) string {
	a, b := t.date(s.CollectedFrom), t.date(s.CollectedTo)
	if a == b {
		return a
	}
	return a + " to " + b
}

func where(s Side) string {
	if s.Directory == nil {
		return "a report file"
	}
	return clean(*s.Directory)
}

func (t *tx) header() {
	c := t.c
	t.line("Comparison of two runs of " + clean(c.Engagement))
	t.line("  Earlier   read " + t.span(c.Earlier) + ", scheck " + clean(c.Earlier.ScheckVersion) + ", " + where(c.Earlier))
	t.line("  Later     read " + t.span(c.Later) + ", scheck " + clean(c.Later.ScheckVersion) + ", " + where(c.Later))
	t.line("  " + apart(c.Comparable.HoursApart) + " between the last reading of the earlier run and the first of the later.")
	t.blank()
	t.hang("", "", "This compares what two runs read. Nothing was contacted and nothing was checked again. It holds the personal data and internal topology of the reports it compares, for the operator only.")
}

func apart(h int) string {
	switch {
	case h < 1:
		return "Less than an hour"
	case h < 48:
		return fmt.Sprintf("%d %s", h, plural(h, "hour"))
	}
	d := h / 24
	return fmt.Sprintf("%d days", d)
}

func plural(n int, w string) string {
	if n == 1 {
		return w
	}
	return w + "s"
}

func (t *tx) comparable() {
	c := t.c.Comparable
	var out []string
	if !c.SameRules {
		out = append(out, fmt.Sprintf("scheck differs between the runs, or one names no release build (%s, %s). A finding that is gone is not confirmed as fixed and one that appears is reported as first seen, because a change of rules can do either. To confirm fixes, run both with the same release.", clean(t.c.Earlier.ScheckVersion), clean(t.c.Later.ScheckVersion)))
	}
	if !c.SameFile {
		out = append(out, "The engagement file changed between the runs. A finding whose rule reads a declaration from it is not confirmed as fixed or new.")
	}
	if c.VantageChanged {
		out = append(out, fmt.Sprintf("The runs read from different network positions (%s, then %s). Domain and web findings are not confirmed as fixed or new.", orNone(t.c.Earlier.Vantage), orNone(t.c.Later.Vantage)))
	}
	if len(c.PrincipalChanges) > 0 {
		out = append(out, "Read with different access: "+clean(strings.Join(c.PrincipalChanges, ", "))+". What an account can see differs, so a finding that is gone from them is not confirmed as fixed.")
	}
	if c.RedactionRulesDiffer {
		out = append(out, "The runs hide names with a different number of redact_extra patterns, so the names of findings only the earlier run holds are withheld.")
	}
	t.heading("What these two runs can be compared on")
	if len(out) == 0 {
		t.hang("  ", "  ", "The same scheck release, the same engagement file and the same access.")
	}
	if !t.c.Earlier.RunRecordChecked || !t.c.Later.RunRecordChecked {
		out = append(out, "A report was read as a file, not checked against its run directory; scheck cannot say it was not edited.")
	}
	if c.HoursApart < 24 {
		out = append(out, "Some provider changes take up to a day to show (Workspace 2-step verification enforcement, for one), so a finding may still be reported that was fixed.")
	}
	for _, s := range out {
		t.hang("  - ", "    ", s)
	}
}

func orNone(s string) string {
	if s == "" {
		return "not declared"
	}
	return clean(s)
}

func (t *tx) summary() {
	n := t.c.Summary
	t.heading("Summary")
	var parts []string
	add := func(k int, s string) {
		if k > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", k, s))
		}
	}
	add(n.Fixed, "fixed")
	add(n.StillOpen, "still open")
	add(n.AcceptedSince, "accepted since")
	add(n.NotConfirmed, "no longer reported but not confirmed fixed")
	add(n.NotRechecked, "not checked again")
	if n.EarlierOpen == 0 {
		t.hang("  ", "  ", "The earlier run had no open findings.")
	} else {
		t.hang("  ", "  ", fmt.Sprintf("The earlier run had %d open %s%s. Since then:", n.EarlierOpen, plural(n.EarlierOpen, "finding"), acceptedWords(n.EarlierAccepted)))
		if len(parts) == 0 {
			t.hang("    ", "    ", "none changed state.")
		}
		for _, p := range parts {
			t.hang("    - ", "      ", p)
		}
	}
	var since []string
	sadd := func(k int, s string) {
		if k > 0 {
			since = append(since, fmt.Sprintf("%d %s", k, s))
		}
	}
	sadd(n.New, "new")
	sadd(n.FirstReported, "reported for the first time")
	sadd(n.Reopened, "open again")
	if len(since) > 0 {
		t.hang("  ", "  ", "Not in that count: "+strings.Join(since, ", ")+". New means the earlier run read it completely and did not find it; reported for the first time means the earlier run had not looked.")
	} else {
		t.hang("  ", "  ", "Nothing is new, reported for the first time or open again.")
	}
	if n.Moved > 0 || n.Renamed > 0 {
		t.hang("  ", "  ", fmt.Sprintf("%d moved to another asset and %d renamed; they are counted once, where they stand now.", n.Moved, n.Renamed))
	}
}

func acceptedWords(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" and %d accepted (the list below covers both)", n)
}

func (t *tx) name(r *Ref) string {
	if r.AssetName != "" {
		return clean(r.AssetName)
	}
	return clean(r.Asset)
}

func subjectName(r *Ref) string {
	switch {
	case r.SubjectWithheld:
		return "name withheld: the redaction rules of the two runs differ"
	case r.Subject == nil:
		return ""
	case r.Subject.Label != "":
		return clean(r.Subject.Label)
	}
	return clean(r.Subject.Key)
}

func subjectText(r *Ref) string {
	if n := subjectName(r); n != "" {
		return " (" + n + ")"
	}
	return ""
}

func capital(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return strings.ToUpper(string(r[:1])) + string(r[1:])
}

func (t *tx) item(i Instance) string {
	r := i.Later
	if r == nil {
		r = i.Earlier
	}
	return clean(i.Title) + " on " + t.name(r) + subjectText(r)
}

// shown says an instance prints item by item: medium or above at default
// verbosity, everything at -v.
func (t *tx) shown(i Instance) bool {
	if t.opt.Verbose >= 1 {
		return true
	}
	r := i.Later
	if r == nil {
		r = i.Earlier
	}
	return finding.Severity(r.Severity).AtLeast(finding.SevMedium)
}

func (t *tx) sections() {
	groups := map[Category][]Instance{}
	for _, i := range t.c.Instances {
		groups[i.Category] = append(groups[i.Category], i)
	}
	t.group(groups[New], "New since the earlier run", func(i Instance) string {
		return fmt.Sprintf("[%s] %s. The earlier run read it completely and did not find it.", clean(i.Later.Severity), t.item(i))
	})
	t.group(groups[FirstReported], "Reported for the first time", func(i Instance) string {
		return fmt.Sprintf("[%s] %s. %s", clean(i.Later.Severity), t.item(i), t.firstReported(i))
	})
	t.group(groups[Reopened], "Open again", func(i Instance) string {
		s := fmt.Sprintf("[%s] %s. ", clean(i.Later.Severity), t.item(i))
		who := ""
		if i.Acceptance != nil && i.Acceptance.AcceptedBy != "" {
			who = " by " + clean(i.Acceptance.AcceptedBy)
		}
		if i.Cause == CauseAcceptanceExpired {
			return s + "It was accepted before; the acceptance" + who + " ran out" + untilText(i.Acceptance) + ", so it is on the list again."
		}
		return s + "It was accepted" + who + " in the earlier run and is no longer under an acceptance."
	})
	t.group(groups[Fixed], "Fixed", func(i Instance) string {
		s := fmt.Sprintf("%s (rated %s before). The check ran in full on %s and did not find it.", t.item(i), clean(i.Earlier.Severity), t.date(t.c.Later.CollectedTo))
		if slicesContains(i.Notes, NoteRevocationUnchecked) {
			s += " Removing a credential from the code does not show it was changed: whether it was revoked or rotated was not checked, and anyone who copied it could still use it."
		}
		if t.opt.Verbose >= 1 && len(i.NotChecked) > 0 {
			s += " Not checked then, and still not: " + clean(strings.Join(i.NotChecked, "; ")) + "."
		}
		return s
	})
	t.group(groups[StillOpen], "Still open", func(i Instance) string {
		s := fmt.Sprintf("[%s] %s", clean(i.Later.Severity), t.item(i))
		var ch []string
		if i.Severity != nil && clean(i.Severity.From) != i.Severity.To {
			ch = append(ch, "rated "+clean(i.Severity.From)+" before")
		}
		switch i.Identity {
		case "moved", "moved_renamed":
			ch = append(ch, "moved from "+t.name(i.Earlier)+" ("+clean(i.Earlier.Asset)+"); the same machine id, so scheck takes it for the same machine")
		}
		switch i.Identity {
		case "renamed", "moved_renamed":
			ch = append(ch, "renamed from "+subjectName(i.Earlier))
		}
		if len(ch) > 0 {
			s += " (" + strings.Join(ch, "; ") + ")"
		}
		s += "."
		if sc := i.Severity; sc != nil {
			if sc.LoweredByDeclaration {
				s += " Lowered because the engagement file changed (" + clean(stepList(sc.Added, sc.Removed)) + "); nothing read from the asset was shown to change."
			} else if t.opt.Verbose >= 1 && (len(sc.Added) > 0 || len(sc.Removed) > 0) {
				s += " Chain: " + clean(stepList(sc.Added, sc.Removed)) + "."
			}
		}
		return s
	})
	t.group(groups[AcceptedSince], "Accepted since the earlier run, not fixed", func(i Instance) string {
		s := fmt.Sprintf("[%s] %s.", clean(i.Later.Severity), t.item(i))
		if a := i.Acceptance; a != nil {
			s += " " + clean(a.AcceptedBy) + " agreed to live with it" + untilText(a) + "; the reason given: " + clean(a.Reason)
			if !strings.HasSuffix(s, ".") {
				s += "."
			}
		}
		return s
	})
	if n := len(groups[StillAccepted]); n > 0 {
		t.heading("Accepted before and still accepted")
		if t.opt.Verbose >= 1 {
			for _, i := range groups[StillAccepted] {
				t.hang("  - ", "    ", t.item(i)+".")
			}
		} else {
			t.hang("  ", "  ", fmt.Sprintf("%d %s; see -v. Accepting a finding is a decision, not a fix.", n, plural(n, "finding")))
		}
	}
	t.gone(groups[NotConfirmed], "No longer reported, not confirmed fixed", true)
	t.gone(groups[NotRechecked], "Not checked again", false)
}

func slicesContains(s []string, v string) bool {
	return slices.Contains(s, v)
}

func untilText(a *AcceptChange) string {
	if a == nil || a.Expires == nil {
		return ""
	}
	return " (until " + clean(*a.Expires) + ")"
}

func stepList(added, removed []Step) string {
	var parts []string
	for _, s := range added {
		parts = append(parts, "added "+s.Rule+" "+s.Delta+" "+s.Source)
	}
	for _, s := range removed {
		parts = append(parts, "removed "+s.Rule+" "+s.Delta+" "+s.Source)
	}
	return strings.Join(parts, ", ")
}

func (t *tx) group(in []Instance, title string, f func(Instance) string) {
	if len(in) == 0 {
		return
	}
	t.heading(title)
	hidden := 0
	for _, i := range in {
		if !t.shown(i) {
			hidden++
			continue
		}
		t.hang("  - ", "    ", f(i))
	}
	if hidden > 0 {
		t.hang("  ", "  ", fmt.Sprintf("Also %d at low severity or informational; see -v.", hidden))
	}
}

var goneOrder = []string{
	CauseSubjectUnmatchable, CauseSubjectReplaced, CauseRulesChanged, CauseDeclarationChanged, CausePrincipalChanged, CauseVantageChanged,
	CauseAssetReplaced, CauseIncomplete, CauseAssetNotInRun, CauseAssetNotListed, CauseAssetNotRead, CauseRuleNotAssessed, CauseRuleUndecided,
}

func (t *tx) gone(in []Instance, title string, confirmed bool) {
	if len(in) == 0 {
		return
	}
	t.heading(title)
	t.hang("  ", "  ", map[bool]string{
		true:  "The later check did not report these, but something that has to hold before scheck calls a finding fixed did not hold. Check them by hand, or compare two runs made with the same scheck release, the same file and the same access.",
		false: "The later run did not look at these, so nothing is said about them either way. Not looking is not a fix.",
	}[confirmed])
	for _, cause := range goneOrder {
		var sel []Instance
		for _, i := range in {
			if i.Cause == cause {
				sel = append(sel, i)
			}
		}
		if len(sel) == 0 {
			continue
		}
		t.hang("  ", "  ", capital(t.goneCause(cause, sel[0]))+":")
		hidden := 0
		for _, i := range sel {
			if !t.shown(i) {
				hidden++
				continue
			}
			t.hang("    - ", "      ", fmt.Sprintf("[%s] %s", clean(i.Earlier.Severity), t.item(i)))
		}
		if hidden > 0 {
			t.hang("    ", "    ", fmt.Sprintf("Also %d at low severity or informational; see -v.", hidden))
		}
	}
}

func (t *tx) goneCause(cause string, i Instance) string {
	reason := func() string {
		if i.Reason == "" {
			return ""
		}
		return ": " + clean(t.reasonPhrase(i.Reason))
	}
	switch cause {
	case CauseRulesChanged:
		return fmt.Sprintf("scheck's rules may have changed between the runs (%s, then %s); to confirm, run both with the same release", clean(t.c.Earlier.ScheckVersion), clean(t.c.Later.ScheckVersion))
	case CauseDeclarationChanged:
		return "you changed the engagement file, and the rule reads declarations from it"
	case CausePrincipalChanged:
		return "the access used to read the asset differs between the runs, and what an account can see differs"
	case CauseVantageChanged:
		return "the runs read from different network positions"
	case CauseAssetReplaced:
		return "a different machine or tenant answered at the same address or name; if it was rebuilt the weakness may be gone, but scheck cannot tell whether the old one still runs elsewhere"
	case CauseIncomplete:
		return "the rule did not read everything it needed this time (a cap, a sample or a page limit), so absence is not shown"
	case CauseSubjectUnmatchable:
		return "the name is hidden by a redaction rule, so it cannot be matched between the runs"
	case CauseSubjectReplaced:
		return "the same name is held by a different account in the later run (another provider id), so it is not the same instance"
	case CauseAssetNotInRun:
		return "the asset is not in the later run; removing it from scope does not fix it, and if it was shut down scheck did not check that"
	case CauseAssetNotListed:
		return "the asset has no entry in the run's asset list (it was found under a root), so whether it was read in full is not recorded"
	case CauseAssetNotRead:
		return "the asset was not read this time" + reason()
	case CauseRuleNotAssessed:
		return "the rule did not run on the asset this time (not among the checks chosen, or not in this version)"
	case CauseRuleUndecided:
		return "the rule could not decide this time" + reason()
	}
	return cause
}

func (t *tx) reasonPhrase(token string) string {
	return (&report.Report{}).ReasonPhrase(report.ReasonDetail{Reason: token})
}

func (t *tx) firstReported(i Instance) string {
	switch i.Cause {
	case CauseAssetNotInRun:
		return "The earlier run did not include this asset."
	case CauseAssetNotListed:
		return "The earlier run records no asset entry for it, so whether it was read in full is not recorded."
	case CauseAssetNotRead:
		return "The earlier run did not read this asset."
	case CauseRuleNotAssessed:
		return "The earlier run did not run this rule on it."
	case CauseRuleUndecided:
		return "The earlier run could not decide this rule."
	case CauseIncomplete:
		return "The earlier run did not read everything this rule needs."
	case CauseRulesChanged:
		return fmt.Sprintf("scheck's rules may have changed (%s, then %s), so it may be new to the rules and not to the asset.", clean(t.c.Earlier.ScheckVersion), clean(t.c.Later.ScheckVersion))
	case CauseDeclarationChanged:
		return "The engagement file changed, and this rule reads declarations from it."
	case CausePrincipalChanged:
		return "It was read with different access this time."
	case CauseVantageChanged:
		return "The runs read from different network positions."
	case CauseAssetReplaced:
		return "A different machine or tenant answered at this address or name."
	case CauseSubjectUnmatchable:
		return "Its name is hidden by a redaction rule, so it cannot be matched to the earlier run."
	case CauseSubjectReplaced:
		return "A different account (another provider id) now holds this name."
	}
	return ""
}

func (t *tx) assets() {
	if len(t.c.Assets) == 0 {
		return
	}
	t.heading("Assets that changed")
	for _, a := range t.c.Assets {
		var s string
		switch a.Change {
		case "added":
			s = clean(a.Name) + " was added to the engagement (" + clean(a.Asset) + ")."
		case "unlisted":
			s = clean(a.Name) + " (" + clean(a.Asset) + ") is no longer listed as an asset, but the later run still read under it."
		case "removed":
			s = clean(a.Name) + " (" + clean(a.Asset) + ") is no longer in the engagement. Removing it from scope does not fix anything on it."
		case "moved":
			s = clean(a.Name) + " moved from " + clean(a.From) + " to " + clean(a.To) + ", the same machine or tenant."
		case "replaced":
			s = clean(a.Name) + " (" + clean(a.Asset) + "): a different machine or tenant answered than in the earlier run."
		case "status":
			s = clean(a.Name) + " was " + stateWord(a.From) + " and is now " + stateWord(a.To) + "."
			if a.Reason != "" {
				s += " " + capital(clean(t.reasonPhrase(a.Reason))) + "."
			}
		case "principal":
			s = clean(a.Name) + " was read as " + clean(a.From) + " and now as " + clean(a.To) + "."
		}
		t.hang("  - ", "    ", s)
	}
}

func (t *tx) coverage() {
	if len(t.c.Coverage) == 0 {
		return
	}
	t.heading("Coverage that changed")
	for _, r := range t.c.Coverage {
		name := report.AreaLabel(r.Area)
		if r.Tool != "" {
			name += " (" + r.Tool + ")"
		}
		t.hang("  - ", "    ", clean(name)+": "+markWord(r.From)+" before, "+markWord(r.To)+" now.")
	}
}

func markWord(m string) string {
	switch m {
	case "assessed":
		return "checked"
	case "partial":
		return "checked in part"
	case "not_assessed":
		return "not checked"
	case "not_applicable":
		return "not applicable"
	case "outside_scheck":
		return "outside scheck"
	}
	return clean(m)
}

func (t *tx) people() {
	if len(t.c.PeopleLeft) == 0 {
		return
	}
	t.heading("People who left")
	for _, p := range t.c.PeopleLeft {
		t.hang("  - ", "    ", fmt.Sprintf("%s, %s: %s before, %s now.", clean(p.Handle), clean(p.Provider), stateWord(p.From), stateWord(p.To)))
	}
}

func stateWord(s string) string {
	return strings.ReplaceAll(clean(s), "_", " ")
}

func (t *tx) closing() {
	e := t.c.Exit
	t.blank()
	switch e.Code {
	case 2:
		t.hang("", "", fmt.Sprintf("Exit 2: the later run did not read everything, so what is gone from it cannot be called fixed where it could not look. %s", clean(strings.Join(e.Reasons, "; "))+"."))
	case 1:
		t.hang("", "", fmt.Sprintf("Exit 1: attention needed. %s. Exit 1 here counts what got worse. Findings that are still open in the later run (%d at or above the threshold) are not what it counts.", clean(strings.Join(e.Reasons, "; ")), e.OpenAtOrAboveThreshold))
	default:
		t.hang("", "", fmt.Sprintf("Exit 0: nothing at or above the threshold is new, reported for the first time, open again or raised since the earlier run. %d %s at or above the threshold %s still open in the later run; exit 0 does not mean they were fixed, and it is not a clean result.", e.OpenAtOrAboveThreshold, plural(e.OpenAtOrAboveThreshold, "finding"), map[bool]string{true: "is", false: "are"}[e.OpenAtOrAboveThreshold == 1]))
	}
}
