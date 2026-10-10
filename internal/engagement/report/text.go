package report

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
	hostreport "github.com/b87/scheck/internal/report"
)

// Options are the host report's: verbosity, width and colour, which the
// caller decides (AGENTS.md, "Conventions": terminal decisions stay in
// cmd/scheck).
type Options = hostreport.Options

// WriteText renders the report a person reads (docs/spec/report.md,
// "The report"): plain words for marks and reasons, never their tokens,
// and every string that came from a target or the operator escaped.
func WriteText(w io.Writer, r *Report, opt Options) error {
	if opt.Width <= 0 {
		opt.Width = hostreport.DefaultWidth
	}
	opt.Width = max(opt.Width, 60)
	bw := bufio.NewWriter(w)
	t := &text{w: bw, r: r, opt: opt, names: map[string]string{}}
	for _, a := range r.Assets {
		t.names[a.ID] = a.Name
	}
	// A finding may belong to a name found under a root, not declared: it
	// is named as itself.
	for _, f := range r.Findings {
		if _, ok := t.names[f.Key.Asset]; !ok && f.AssetName != "" {
			t.names[f.Key.Asset] = f.AssetName
		}
	}
	t.zone = time.UTC
	if z, err := time.LoadLocation(r.Engagement.Timezone); err == nil {
		t.zone = z
	}
	t.header()
	t.status()
	t.summary()
	t.coverage()
	t.findings()
	t.pastes()
	t.notChecked()
	t.excluded()
	t.egress()
	t.notes()
	t.factSheets()
	t.close()
	return bw.Flush()
}

type text struct {
	w     *bufio.Writer
	r     *Report
	opt   Options
	names map[string]string
	zone  *time.Location
}

// clean makes target- or operator-derived text one safe line: control
// characters escaped, whitespace folded (docs/spec/host-collector.md §6.6).
func clean(s string) string { return strings.Join(strings.Fields(hostreport.Sanitize(s)), " ") }

func (t *text) line(s string) { _, _ = t.w.WriteString(strings.TrimRight(s, " ") + "\n") }
func (t *text) blank()        { t.line("") }

// hang wraps s after the prefix first, continuing under indent.
func (t *text) hang(first, indent, s string) {
	for _, l := range wrapHang(first, indent, s, t.opt.Width) {
		t.line(l)
	}
}

// field prints a labelled value, the label padded to a fixed column.
func (t *text) field(indent, label string, col int, s string) {
	first := indent + pad(label, col)
	t.hang(first, strings.Repeat(" ", len([]rune(first))), s)
}

func (t *text) bold(s string) string {
	if !t.opt.Color || s == "" {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func (t *text) sev(s string) string {
	if !t.opt.Color {
		return s
	}
	code := map[string]string{"critical": "1;31", "high": "31", "medium": "33", "low": "36"}[s]
	if code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (t *text) name(id string) string {
	if n := t.names[id]; n != "" {
		return clean(n)
	}
	return clean(id)
}

func (t *text) clock(ts time.Time) string {
	format := "15:04"
	if t.r.Engagement.Collected.From.In(t.zone).Format("2006-01-02") != t.r.Engagement.Collected.To.In(t.zone).Format("2006-01-02") {
		format = "2006-01-02 15:04"
	}
	return ts.In(t.zone).Format(format)
}

// --- header ----------------------------------------------------------------

func (t *text) header() {
	e := t.r.Engagement
	t.line(t.bold("scheck engagement report: " + clean(e.Name)))
	read := fmt.Sprintf("Read %s to %s (%s). scheck %s.", e.Collected.From.In(t.zone).Format("2006-01-02 15:04"),
		t.clock(e.Collected.To), t.zone, clean(t.r.ScheckVersion))
	if e.Operator != nil {
		read = "For " + clean(*e.Operator) + ". " + read
	}
	t.hang("", "", read)
	trigger := "not declared"
	if e.BuiltFrom == "host" {
		trigger = "not declared (one-host check)"
	}
	if e.Trigger != nil {
		trigger = map[string]string{"questionnaire": "customer questionnaire", "audit": "audit", "funding": "funding round",
			"incident": "incident", "routine": "routine"}[*e.Trigger]
	}
	t.field("", "Trigger", 15, trigger)
	if t.r.Run.Vantage == "" && slices.ContainsFunc(t.r.Assessments, func(a Assessment) bool { return a.ID == finding.IDWebRestrictedReachable }) {
		t.field("", "Vantage", 15, "not given: restricted pages were not checked for outside reachability (--vantage internet). internet means outside every permitted source, including office allowlists and VPN.")
	}
	if t.r.Run.Vantage != "" {
		t.field("", "Vantage", 15, clean(t.r.Run.Vantage)+" (your declaration; not verified). internet means outside every permitted source, including office allowlists and VPN.")
	}
	if t.r.Run.Resumed {
		kept := "was kept"
		if slices.ContainsFunc(t.r.Assets, func(a Asset) bool { return a.Collector != nil && *a.Collector == "github" }) {
			kept += " where reuse was allowed"
		}
		t.field("", "Resumed", 15, "this run was stopped and resumed: what an earlier session read completely "+kept+", and "+
			"everything else was read again. Kept evidence was not read again and retains its original observation date.")
	}
	for _, a := range t.r.Assets {
		if a.Collector != nil && *a.Collector == "github" && a.Principal != nil {
			t.field("", "GitHub account", 15, clean(a.ID)+": "+clean(a.Principal.Identity)+". Inventory visibility depends on this credential.")
		}
	}
	for _, change := range e.PrincipalChanges {
		t.field("", "Principal", 15, clean(change.Asset)+": GitHub principal changed from "+clean(change.From)+" to "+clean(change.To)+". Earlier authenticated GitHub evidence was not reused.")
	}
	if len(e.EditedByHand) > 0 {
		names := make([]string, len(e.EditedByHand))
		for i, n := range e.EditedByHand {
			names[i] = clean(n)
		}
		them := "them"
		if len(names) == 1 {
			them = "it"
		}
		t.field("", "Edited by hand", 15, strings.Join(names, ", ")+": changed since scheck wrote "+them+", and used as written.")
	}
	if e.Trigger != nil && *e.Trigger == "incident" {
		t.hang("", "", "This is not incident response. scheck does not look for signs of intrusion, and evidence read "+
			"from a possibly compromised system cannot be trusted. This report lists weaknesses in what scheck could read; "+
			"it cannot tell you whether you are safe now or how the incident happened. For that you need an incident "+
			"responder; what this report can do is list weaknesses to close.")
	}
	t.field("", "Method", 15, "rules only: a fixed checklist per asset type, no model, no hypotheses. Reading only: "+
		"nothing was probed, scanned, exploited or changed. Not a penetration test.")
	auth := "none recorded. This run only read, with access you already hold; scheck requires a record only for probes and scans."
	if a := e.Authorization; a != nil {
		auth = "by " + clean(a.By) + " on " + clean(a.Date) + "."
		for _, w := range a.Windows {
			auth += " Window " + w.From.In(t.zone).Format("2006-01-02 15:04") + " to " + w.To.In(t.zone).Format("2006-01-02 15:04") + "."
		}
		if len(a.Source) > 0 {
			auth += " From " + clean(strings.Join(a.Source, ", ")) + "."
		}
		if a.Note != "" {
			auth += " " + clean(a.Note)
		}
		auth += " Levels used: " + orNone(strings.Join(e.Method.LevelsUsed, ", ")) + ". Probe off, scan off."
	}
	t.field("", "Authorization", 15, auth)
	t.hang("", "", "Handle with care: this report names people, accounts, internal hosts and services, and says where "+
		"weaknesses are. Keep it as private as a list of passwords. It is written for you, not for your customers.")
	t.blank()
}

// --- run status -------------------------------------------------------------

func (t *text) status() {
	for _, s := range t.r.Refused {
		t.hang("REFUSED: ", "  ", t.refusal(s))
	}
	for _, s := range t.r.Incomplete {
		t.hang("INCOMPLETE: ", "  ", t.shortfall(s))
	}
	open := t.openCount()
	switch {
	case len(t.r.Refused)+len(t.r.Incomplete) > 0:
		if open > 0 {
			t.hang("", "", "Findings are also open on "+strings.Join(t.openOn(), ", ")+"; see Findings below.")
		}
	default:
		// Only what was collected was read: an asset no collector reads
		// is named apart, never listed as read.
		var read, unread []string
		for _, a := range t.r.Assets {
			if a.Status == statusCollected || a.Status == statusIncomplete {
				read = append(read, clean(a.Name))
			} else {
				unread = append(unread, clean(a.Name))
			}
		}
		// It leads with what was read and how much of it was judged, never
		// with a sentence that reassures before anything is read.
		s := "Read: none"
		if len(read) > 0 {
			s = "Read: " + strings.Join(read, ", ")
		}
		if part := t.partly(); len(part) > 0 {
			s += " (checked only in part: " + strings.Join(part, "; ") + ")"
		}
		if len(unread) > 0 {
			s += fmt.Sprintf(". Not read: %s (this version of scheck does not read %s)", strings.Join(unread, ", "),
				map[bool]string{true: "it", false: "them"}[len(unread) == 1])
		}
		t.hang("", "", s+". See Coverage for what was not checked.")
	}
	t.blank()
}

// refusal words a refused asset by its kind (docs/spec/report.md,
// "Incompleteness and refusals"); the raw error follows at -v. A canary
// echo is never printed.
func (t *text) refusal(s Shortfall) string {
	n := t.name(s.Asset)
	var out string
	switch s.Kind {
	case "host_key_changed":
		out = n + " was not contacted: its host key changed. A changed key can mean a reinstalled server or an " +
			"interception; confirm the fingerprint with whoever runs the host before you accept it."
	case "host_key_unknown":
		out = n + " was not contacted: its host key is not in your known_hosts file. Confirm the fingerprint with " +
			"whoever runs the host, then add it."
	case "jump_host_key_changed":
		out = n + " was not contacted: the host key of its jump host " + t.via(s.Asset) + " changed. A changed key can " +
			"mean a reinstalled server or an interception; confirm the fingerprint with whoever runs the jump host " +
			"before you accept it."
	case "jump_host_key_unknown":
		out = n + " was not contacted: the host key of its jump host " + t.via(s.Asset) + " is not in your known_hosts " +
			"file. Confirm the fingerprint with whoever runs the jump host, then add it."
	case "excluded":
		out = n + " was not contacted: its name resolves to an address your engagement file excludes. Remove the " +
			"exclude if the host is in scope, or the host if it is not."
	case "jump_excluded":
		out = n + " was not contacted: its jump host " + t.via(s.Asset) + " resolves to an address your engagement " +
			"file excludes, and scheck never connects to an excluded address."
	case "canary":
		out = n + ": scheck stopped before running any check, because the host's login shell changed what it sent " +
			"back (often a login banner or a profile script that prints text). This does not by itself mean the host " +
			"is compromised: ask whoever runs it to look at its login scripts."
		if s.Echo != "" {
			out += " The raw reply is in report.json."
		}
		if t.opt.Verbose == 0 {
			return out
		}
	case "access":
		out = n + ": scheck could not use the access it was given (" + strings.TrimSuffix(clean(s.Detail), ".") + "). Nothing was read from it."
		return out
	default:
		return n + ": " + strings.TrimSuffix(clean(s.Detail), ".") + "."
	}
	if t.opt.Verbose > 0 && s.Detail != "" {
		out += " (" + strings.TrimSuffix(clean(s.Detail), ".") + ")"
	}
	return out
}

func (t *text) shortfall(s Shortfall) string {
	n := t.name(s.Asset)
	for _, a := range t.r.Assets {
		if a.ID == s.Asset && a.Collector != nil && *a.Collector == "github" {
			return n + ": GitHub inventory was not completed (" + strings.TrimSuffix(clean(s.Detail), ".") + "). The inventory notes show what was read and what remains unknown."
		}
	}
	if e := s.Effect; e != nil {
		attempted := e.ChecksRun + e.ChecksUnknown
		total := attempted + e.ChecksNotRun
		cause := "the connection was lost"
		if s.Reason != "failed" {
			cause = orNone(strings.TrimSuffix(clean(s.Detail), "."))
		}
		return fmt.Sprintf("%s: %s after %d of %d checks; %d were not run. What was read before is kept and assessed. "+
			"scheck only reads; an interrupted run leaves nothing half-changed.", n, cause, attempted, total, e.ChecksNotRun)
	}
	switch s.Reason {
	case "collector_not_built":
		return n + " (" + kindLabel(s.Asset) + "): this version of scheck does not read it. Nothing was read from it."
	case "limit_reached":
		if strings.Contains(s.Detail, "while it was read") {
			return n + ": limits.timeout ended the engagement while it was read."
		}
		return n + ": limits.timeout ended the engagement before it was read."
	case "failed":
		return n + ": could not connect from this machine (" + strings.TrimSuffix(clean(s.Detail), ".") +
			"). This does not tell you whether it is up for anyone else. Nothing was read."
	}
	return n + ": " + strings.TrimSuffix(clean(s.Detail), ".") + ". Nothing was read."
}

// openCount is the number of open findings at or above their asset's
// threshold: what exit 1 counts.
func (t *text) openCount() int {
	n := 0
	for _, f := range t.r.Findings {
		th, ok := t.r.Exit.Thresholds[f.Key.Asset]
		if ok && f.Status == finding.StatusOpen && finding.Severity(f.Severity).AtLeast(finding.Severity(th.Severity)) {
			n++
		}
	}
	return n
}

// --- summary ----------------------------------------------------------------

var areaLabel = map[string]string{
	"identity": "Identity and access", "secrets": "Secrets", "cloud": "Cloud configuration",
	"data": "Data stores and backups", "cicd": "CI/CD and supply chain", "external": "External surface",
	"web": "Web application", "hosts": "Hosts", "email": "Email and domain", "logging": "Logging and incident readiness",
	"endpoints": "Malware and stolen sessions", "application_logic": "Application logic", "processes": "Processes",
	"lookalike_domains": "Lookalike and typo domains",
}

func lower(label string) string {
	if strings.HasPrefix(label, "CI/CD") {
		return label
	}
	return strings.ToLower(label[:1]) + label[1:]
}

// folds says whether a row joins the "Not requested" line: nothing was
// declared for its area, and nothing in the file points at it.
func folds(row Row) bool {
	return row.Mark == "not_assessed" && len(row.Reasons) == 1 && row.Reasons[0].Reason == "not_declared" &&
		len(row.DeclaredNotVerified) == 0
}

func (t *text) areas() (checked, part, notChecked, folded, na []string) {
	for _, row := range t.r.Coverage {
		label, ok := areaLabel[row.Area]
		if !ok || !slices.Contains(finding.Areas, finding.Area(row.Area)) {
			continue
		}
		switch {
		case row.Mark == "assessed":
			checked = append(checked, label)
		case row.Mark == "partial":
			part = append(part, label)
		case row.Mark == "not_applicable":
			na = append(na, label)
		case folds(row):
			folded = append(folded, label)
		default:
			notChecked = append(notChecked, label)
		}
	}
	return
}

func (t *text) summary() {
	t.line(t.bold("SUMMARY"))
	ciSelected, ciDecided := 0, 0
	for _, a := range t.r.Assessments {
		if slices.Contains(finding.GitHubCIIDs(), a.ID) {
			ciSelected++
			if a.Status != finding.NotAssessed {
				ciDecided++
			}
		}
	}
	if ciSelected > 0 {
		if ciDecided == 0 {
			t.hang("", "", "No CI configuration rule could decide from the available evidence; see the missing reads and next steps below.")
		} else {
			t.field("", "CI configuration", 17, fmt.Sprintf("%d of %d rule assessments decided; runtime execution was not verified.", ciDecided, ciSelected))
		}
	}
	checked, part, notChecked, folded, na := t.areas()
	if len(checked) > 0 {
		t.field("", "Checked", 17, strings.Join(checked, ", ")+".")
	}
	if len(part) > 0 {
		t.field("", "Checked in part", 17, strings.Join(t.partLabels(part), ", ")+".")
	}
	if len(notChecked) > 0 {
		t.field("", "Not checked", 17, strings.Join(notChecked, ", ")+": see Coverage.")
	}
	if len(folded) > 0 {
		t.field("", "Not requested", 17, t.foldText(folded))
	}
	if len(na) > 0 {
		t.field("", "Not applicable", 17, strings.Join(na, ", ")+": you declared they do not apply.")
	}
	t.field("", "Outside scheck", 17, "Malware on any machine, application logic, processes, lookalike domains.")
	t.blank()

	t.line(t.bold("Fix these first: a ranking of what was checked, not of all your risks"))
	for _, it := range t.r.Summary.Items {
		var names []string
		for _, a := range it.Assets {
			names = append(names, t.name(a))
		}
		first := fmt.Sprintf("  %d  %s  ", it.Rank, t.sev(pad(it.Severity, 8)))
		t.hang(first, "             ", clean(it.Title)+"  ("+strings.Join(names, ", ")+")")
		if why := t.raisedBy(it.Keys[0]); why != "" {
			t.hang("             ", "             ", why)
		}
	}
	b := t.r.Summary.Below
	below := fmt.Sprintf("Below: %d low, %d informational, %d accepted.", b.Low, b.Info, b.Accepted)
	switch {
	case len(t.r.Summary.Items) == 0 && ciSelected > 0 && t.r.Summary.Rules.Decided == 0:
		t.hang("  ", "  ", "No security verdict was possible from the collected CI evidence. "+below)
	case len(t.r.Summary.Items) == 0:
		t.hang("  ", "  ", "Nothing open ranks at medium or above among what was checked"+t.unanswered()+". "+below)
	case t.r.Summary.More > 0:
		t.hang("", "", fmt.Sprintf("%d more open at medium or above; see Findings. ", t.r.Summary.More)+below)
	default:
		t.hang("", "", "Nothing else open ranks at medium or above among what was checked. "+below)
	}
	t.blank()

	var s strings.Builder
	s.WriteString("A short list is not a clean bill of health. scheck reports only what its rules could decide.")
	if len(checked) > 0 {
		s.WriteString(" Checked: " + lowerAll(checked) + ".")
	}
	if len(part) > 0 {
		s.WriteString(" Checked in part: " + lowerAll(part) + ".")
	}
	for _, h := range t.hostAreas() {
		s.WriteString(" " + h.sentence())
	}
	switch {
	case len(notChecked)+len(folded) == 0:
	case t.r.Engagement.BuiltFrom == "host" && len(notChecked) == 0:
		s.WriteString(" Nothing but this host was looked at.")
	default:
		s.WriteString(" Not checked: " + lowerAll(append(append([]string{}, notChecked...), folded...)) + ".")
	}
	if len(na) > 0 {
		s.WriteString(" Not applicable, as you declared: " + lowerAll(na) + ".")
	}
	s.WriteString(" Anything not checked is unknown, not fine.")
	t.hang("", "", s.String())
	t.blank()
}

func (t *text) foldText(folded []string) string {
	if t.r.Engagement.BuiltFrom == "host" {
		return "A one-host check reads this host only. Your accounts, code, cloud, domains and email were not looked at."
	}
	return "Not part of this run: " + lowerAll(folded) + ". To include one, list it under roots in the engagement file."
}

// hostArea counts one host's domains: judged by a rule that decided, read
// with no rule to judge them, or without usable evidence.
type hostArea struct {
	name                              string
	judged, total, noRule, noEvidence int
}

func (h hostArea) sentence() string {
	s := fmt.Sprintf("On %s, %d of %d host areas were judged, each only on the settings named under Coverage", h.name, h.judged, h.total)
	var rest []string
	if h.noRule > 0 {
		rest = append(rest, fmt.Sprintf("%d %s no rule in this version", h.noRule, map[bool]string{true: "has", false: "have"}[h.noRule == 1]))
	}
	if h.noEvidence > 0 {
		rest = append(rest, fmt.Sprintf("%d had no usable evidence", h.noEvidence))
	}
	if len(rest) > 0 {
		s += "; " + strings.Join(rest, " and ")
	}
	return s + "."
}

func (t *text) hostAreas() []hostArea {
	var out []hostArea
	for _, a := range t.r.Assets {
		if a.Envelope == nil {
			continue
		}
		h := hostArea{name: clean(a.Name)}
		for _, row := range t.r.Coverage {
			for _, si := range row.SubItems {
				if si.Asset != a.ID || si.Mark == "not_applicable" {
					continue
				}
				h.total++
				switch {
				case si.Mark == "assessed" || si.Mark == "partial":
					h.judged++
				case len(si.Reasons) == 1 && si.Reasons[0].Reason == "no_rule":
					h.noRule++
				default:
					h.noEvidence++
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// partLabels names the areas checked in part, a host's with how many of its
// areas were judged.
func (t *text) partLabels(part []string) []string {
	out := make([]string, len(part))
	for i, p := range part {
		out[i] = p
		if p != areaLabel["hosts"] {
			continue
		}
		var hs []string
		for _, h := range t.hostAreas() {
			hs = append(hs, fmt.Sprintf("%s, %d of %d areas judged", h.name, h.judged, h.total))
		}
		if len(hs) > 0 {
			out[i] += " (" + strings.Join(hs, "; ") + ")"
		}
	}
	return out
}

// partly says what was checked only in part, for the run status line.
func (t *text) partly() []string {
	var out []string
	for _, row := range t.r.Coverage {
		if row.Mark != "partial" || !slices.Contains(finding.Areas, finding.Area(row.Area)) {
			continue
		}
		if row.Area != "hosts" {
			out = append(out, lower(areaLabel[row.Area]))
			continue
		}
		for _, h := range t.hostAreas() {
			out = append(out, fmt.Sprintf("%s, %d of %d host areas judged", h.name, h.judged, h.total))
		}
	}
	return out
}

// unanswered names, per host, the checks that gave no answer, so "nothing
// open" is never read as a clean host.
func (t *text) unanswered() string {
	var parts []string
	for _, a := range t.r.Assets {
		if c := a.Checks; c != nil && c.Unknown+c.NotRun > 0 {
			parts = append(parts, fmt.Sprintf("on %s, %d of %d checks gave no answer", clean(a.Name), c.Unknown+c.NotRun, c.Planned))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// openOn names the assets with an open finding at or above threshold.
func (t *text) openOn() []string {
	var out []string
	for _, f := range t.r.Findings {
		th, ok := t.r.Exit.Thresholds[f.Key.Asset]
		if ok && f.Status == finding.StatusOpen && finding.Severity(f.Severity).AtLeast(finding.Severity(th.Severity)) {
			out = appendUnique(out, t.name(f.Key.Asset))
		}
	}
	return out
}

// kindLabel names what kind of thing an asset id is, in words.
func kindLabel(id string) string {
	switch {
	case strings.HasPrefix(id, "saas:github:"):
		return "GitHub organization"
	case strings.HasPrefix(id, "saas:google-workspace:"):
		return "Google Workspace tenant"
	case strings.HasPrefix(id, "saas:"):
		return "SaaS tenant"
	case strings.HasPrefix(id, "repo:"):
		return "repository"
	case strings.HasPrefix(id, "domain:"):
		return "domain"
	case strings.HasPrefix(id, "url:"):
		return "web address"
	case strings.HasPrefix(id, "network:"):
		return "network"
	case strings.HasPrefix(id, "cloud:"):
		return "cloud account"
	case strings.HasPrefix(id, "host:"):
		return "host"
	}
	return "asset"
}

func lowerAll(labels []string) string {
	out := make([]string, len(labels))
	for i, l := range labels {
		out[i] = lower(l)
	}
	return strings.Join(out, ", ")
}

// raisedBy is the one phrase "Fix these first" prints when context moved a
// finding's severity.
func (t *text) raisedBy(k Key) string {
	f := t.finding(k)
	if f == nil || len(f.Adjustments) == 0 || f.Severity == f.SeverityBase {
		return ""
	}
	dir := "raised"
	if finding.Severity(f.Severity).Rank() < finding.Severity(f.SeverityBase).Rank() {
		dir = "lowered"
	}
	why := ""
	if len(f.WhyHere) > 0 {
		why = f.WhyHere[0]
		if i := strings.LastIndex(why, " ("); i > 0 {
			why = why[:i]
		}
		why = ": " + lower(strings.TrimSuffix(clean(why), "."))
	}
	return "base " + f.SeverityBase + ", " + dir + why
}

func (t *text) finding(k Key) *Finding {
	for i := range t.r.Findings {
		f := &t.r.Findings[i]
		if f.Key.ID == k.ID && f.Key.Asset == k.Asset && deref(f.Key.Subject) == deref(k.Subject) {
			return f
		}
	}
	return nil
}

// --- coverage ---------------------------------------------------------------

var markWord = map[string]string{
	"assessed": "checked", "partial": "checked in part", "not_assessed": "not checked",
	"not_applicable": "not applicable", "outside_scheck": "outside scheck",
}

// reasonText is a reason's fixed phrase (docs/spec/report.md,
// "Reason wording"): what is unknown and what would change it, never a
// verdict on the target.
func (t *text) reasonText(rd ReasonDetail) string {
	code, arg, _ := strings.Cut(rd.Reason, ":")
	switch code {
	case "no_credentials":
		return "no access was given for it"
	case "insufficient_permission":
		if arg == "sudo" {
			return "the access scheck was given cannot read this; it needs sudo"
		}
		return "the access scheck was given cannot read this; it needs " + clean(arg) + ", read-only where the provider offers it"
	case "not_on_plan":
		if p, ok := strings.CutPrefix(arg, "profile="); ok {
			return "not in the checks you chose (profile " + clean(p) + ")"
		}
		return "your plan with the provider does not include " + clean(arg)
	case "collector_not_built":
		return "this version of scheck does not read it"
	case "refused":
		return "refused before any check ran"
	case "not_declared":
		if t.r.Engagement.Source.Path != nil {
			return "not part of this engagement; to include it, list it under roots in " + clean(*t.r.Engagement.Source.Path)
		}
		return "not part of this engagement"
	case "excluded_by_operator":
		return "left out by the engagement file"
	case "limit_reached":
		return "not run: stopped by a time limit"
	case "failed":
		return "not run: scheck's connection to the host dropped before this check"
	case "sampled":
		return "only part was read; the rest is unknown"
	case "unavailable":
		if detail, ok := map[string]string{
			"not_read":                 "the required read was not collected",
			"vantage_unknown":          "restricted pages were not checked for outside reachability: no --vantage given",
			"vantage_inside":           "restricted pages were not checked for outside reachability: you declared this run came from inside your network",
			"audience_internet":        "the declared audience is internet, so no restriction contradiction was judged",
			"login_flow":               "the login flow was not read, so session cookies were not fully checked",
			"web_evidence":             "some web-response checks could not reach a decision",
			"github_evidence":          "required GitHub authority, visibility, context or recognized evidence was missing",
			"tls_interception":         "your network inspects TLS, so certificates were not judged",
			"certificate_unclassified": "certificate verification failed without a recognized cause",
			"certificate":              "the HTTPS certificate could not be verified",
			"tls_handshake":            "the TLS handshake did not give sufficient evidence",
			"takeover":                 "the takeover candidate subsumes this certificate check",
			"response_shape":           "the response format or incomplete body prevented this check",
			"security_txt":             "the contact file had no recognized current expiry or valid retrieval scope",
			"http_status":              "the HTTP status did not give usable evidence",
			"blocked":                  "a protection service blocked this read",
			"redirect_not_entry_point": "the redirect could not be followed within the declared entry points",
			"dkim_selector":            "DKIM was not checked: no selector given",
			"mail_senders":             "SPF was not compared with declared senders: none were listed",
			"mail_use":                 "mail use could not be established from the declaration or DNS evidence",
			"mail_evidence":            "email evidence was not judged",
			"dmarc_parent":             "inherited DMARC is unknown: the organizational-domain policy was not read",
			"dmarc_descendants":        "descendant policies were not assessed for a non-organizational domain",
			"dmarc_existence":          "inherited np policy is uncertain: whether the domain exists was not established",
			"dmarc_policy":             "a DMARC policy value was not recognized",
			"spf_incomplete":           "the relevant SPF include tree was not read completely",
			"spf_path":                 "earlier SPF denials leave later authorization uncertain",
			"spf_macro":                "SPF uses macros that require a message sender to evaluate",
			"dkim_key":                 "the DKIM key could not be parsed or was absent or revoked",
			"dkim_multiple_keys":       "multiple DKIM keys leave the selector ambiguous",
		}[arg]; ok {
			return detail
		}
		if arg == "command_missing" {
			return "the tool that would tell is not installed on the host, so scheck could not tell (this is not a finding)"
		}
		return "the command that reads it did not give a usable answer (" + clean(arg) + ")"
	case "no_rule":
		return "this version of scheck has no rule for it"
	}
	return clean(rd.Reason)
}

func (t *text) reasonsText(rs []ReasonDetail) string {
	var out []string
	for _, rd := range rs {
		s := t.reasonText(rd)
		if rd.Detail != "" && (t.opt.Verbose > 0 || rd.Reason == "no_rule" || rd.Reason == "unavailable:dkim_selector" || rd.Reason == "unavailable:mail_senders") {
			s += " (" + clean(rd.Detail) + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

func (t *text) coverage() {
	t.line(t.bold("COVERAGE"))
	var folded []string
	var other, outside []Row
	for _, row := range t.r.Coverage {
		switch {
		case row.Area == "other_saas":
			other = append(other, row)
			continue
		case row.Mark == "outside_scheck":
			outside = append(outside, row)
			continue
		case folds(row):
			folded = append(folded, areaLabel[row.Area])
			continue
		}
		t.row(row)
	}
	if len(folded) > 0 {
		t.field("", "Not requested", 25, t.foldText(folded))
	}
	for _, row := range other {
		t.field("", "Other declared SaaS", 25, clean(row.Tool)+": "+t.reasonsText(row.Reasons))
	}
	for i, row := range outside {
		label := ""
		if i == 0 {
			label = "Outside scheck"
		}
		t.field("", label, 25, areaLabel[row.Area]+": "+row.Detail+".")
	}
	t.blank()
}

func (t *text) row(row Row) {
	head := markWord[row.Mark]
	if p := row.Population; row.Area == "hosts" && p != nil && p.Read < p.InScope {
		head += fmt.Sprintf(": %d of %d hosts read", p.Read, p.InScope)
	}
	t.field("", areaLabel[row.Area], 25, head)
	if row.Area == "hosts" {
		t.hosts(row)
	} else {
		if p := row.Population; p != nil && row.Mark != "assessed" {
			t.hang("  ", "  ", fmt.Sprintf("%d of %s read.", p.Read, count(p.InScope, singular(p.Kind), p.Kind)))
		}
		if len(row.Reasons) > 0 {
			s := upper(t.reasonsText(row.Reasons))
			if len(row.AssetsCovered) == 0 && row.Population != nil && row.Population.Read == 0 {
				var unread []string
				for _, a := range t.r.Assets {
					if feedsRow(row.Area, a) {
						unread = append(unread, clean(a.Name)+" ("+kindLabel(a.ID)+")")
					}
				}
				if len(unread) > 0 {
					s += ": " + strings.Join(unread, ", ")
				}
			}
			t.hang("  ", "  ", s+".")
		}
	}
	for _, item := range row.SubItems {
		if item.Name == "Services your names point at" {
			t.hang("  Services your names point at: ", "    ", clean(item.Asset))
			for _, name := range item.ReadNotJudged {
				t.hang("    ", "    ", clean(name)+"; not checked for takeover: no fingerprint for this provider.")
			}
		}
	}
	for _, n := range row.DeclaredNotVerified {
		t.hang("  Declared, not verified: ", "    ", clean(n.Detail)+" ("+clean(entryKey(n.Source))+").")
	}
}

func (t *text) hosts(row Row) {
	var hostAssets []Asset
	for _, a := range t.r.Assets {
		if a.Kind == "host" {
			hostAssets = append(hostAssets, a)
		}
	}
	collapse := len(hostAssets) > 3
	for _, a := range hostAssets {
		if a.Envelope == nil {
			why := t.reasonText(ReasonDetail{Reason: a.Reason})
			switch a.Status {
			case statusRefused:
				why = t.refusedWhy(a.ID)
			case statusFailed:
				why = "could not connect from this machine"
				if a.Via != "" {
					why += " through " + clean(a.Via)
				}
			}
			t.hang("  "+clean(a.Name)+"  ", "    ", clean(a.ID)+": not checked: "+why+".")
			continue
		}
		env := a.Envelope
		as := "read as " + clean(a.Principal.Identity)
		switch env.Host.Elevation {
		case "sudo":
			as += " with sudo -n"
		case "root":
			as += ", as root"
		default:
			as += ", no elevation"
		}
		if a.Via != "" {
			as += ", through " + clean(a.Via)
		}
		span := ""
		if a.Collected != nil {
			span = ", " + t.clock(a.Collected.From) + "-" + t.clock(a.Collected.To)
		}
		t.hang("  "+clean(a.Name)+"  ", "    ", clean(a.ID)+", "+orNone(clean(env.Host.OS))+", "+as+span)
		if c := a.Checks; c != nil {
			sel, dec, without := 0, 0, 0
			for _, ea := range t.r.Assessments {
				if ea.Asset != a.ID {
					continue
				}
				sel++
				if ea.Status == finding.NotAssessed {
					without++
				} else {
					dec++
				}
			}
			t.hang("  ", "    ", fmt.Sprintf("checks %d: %d ran, %d unknown, %d not run. rules %d: %d decided, %d had no usable evidence.",
				c.Planned, c.Ran, c.Unknown, c.NotRun, sel, dec, without))
		}
		for _, si := range row.SubItems {
			if si.Asset != a.ID || (collapse && si.Mark == "assessed") {
				continue
			}
			t.field("    ", si.Name, 25, t.subItemText(a, si))
		}
		for _, n := range row.Narrowing {
			if !strings.Contains(n.Entry, "assets."+a.Name+".") {
				continue
			}
			s := clean(entryKey(n.Entry))
			switch {
			case len(n.Removed) > 0:
				s += ": removed " + clean(strings.Join(n.Removed, ", "))
			case n.DeniedReads != nil:
				s += fmt.Sprintf(": %s denied", count(*n.DeniedReads, "read", "reads"))
			default:
				s += ": removed nothing"
			}
			t.hang("  Narrowed in the engagement file: ", "    ", s+".")
		}
	}
}

// subItemText is one host area's line: what a "checked" rests on and what
// it found, never a bare mark that reads as a pass (docs/spec/report.md,
// "The Hosts row").
func (t *text) subItemText(a Asset, si SubItem) string {
	if len(si.Reasons) == 1 && si.Reasons[0].Reason == "no_rule" && si.Mark == "not_assessed" {
		return "not judged: " + t.reasonsText(si.Reasons)
	}
	s := markWord[si.Mark]
	if len(si.Judged) > 0 {
		s += " (" + strings.Join(si.Judged, ", ") + ")"
		if n := t.openIn(a, si); n > 0 {
			s += ": " + count(n, "open finding", "open findings") + " (see Findings)"
		} else {
			s += ": nothing found by these rules"
		}
	}
	if len(si.Reasons) > 0 {
		sep := ": "
		if len(si.Judged) > 0 {
			sep = "; "
		}
		s += sep + t.reasonsText(si.Reasons)
	}
	if len(si.ReadNotJudged) > 0 {
		s += "; also read, not judged: " + clean(strings.Join(si.ReadNotJudged, "; "))
	}
	return s
}

// openIn counts the open findings whose evidence lies in a host area.
func (t *text) openIn(a Asset, si SubItem) int {
	n := 0
	for _, f := range t.r.Findings {
		if f.Key.Asset != a.ID || f.Status != finding.StatusOpen || !slices.Contains(si.Rules, f.ID) {
			continue
		}
		n++
	}
	return n
}

// via is the jump host an asset was reached through, "" if none.
func (t *text) via(id string) string {
	for _, a := range t.r.Assets {
		if a.ID == id {
			return clean(a.Via)
		}
	}
	return ""
}

// refusedWhy is a refused host's cause, in words, for its Hosts line and
// the close.
func (t *text) refusedWhy(id string) string {
	for _, s := range t.r.Refused {
		if s.Asset != id {
			continue
		}
		switch s.Kind {
		case "host_key_changed":
			return "its host key changed, so it was not contacted"
		case "host_key_unknown":
			return "its host key is not in your known_hosts file, so it was not contacted"
		case "jump_host_key_changed":
			return "the host key of its jump host changed, so it was not contacted"
		case "jump_host_key_unknown":
			return "the host key of its jump host is not in your known_hosts file, so it was not contacted"
		case "excluded":
			return "its address is excluded by your engagement file, so it was not contacted"
		case "jump_excluded":
			return "its jump host's address is excluded by your engagement file, so it was not contacted"
		case "canary":
			return "its login shell changed what it sent back, so no check ran"
		case "access":
			return "scheck could not use the access it was given"
		}
	}
	return "refused before any check ran"
}

// feedsRow mirrors the builder's feeds for a row's text: which assets the
// area would read once its collector exists.
func feedsRow(area string, a Asset) bool {
	return feeds(finding.Area(area), AssetInput{ID: a.ID, Kind: a.Kind})
}

// --- findings ---------------------------------------------------------------

func (t *text) findings() {
	var open, info, accepted []Finding
	for _, f := range t.r.Findings {
		switch {
		case f.Status == finding.StatusAccepted:
			accepted = append(accepted, f)
		case f.Severity == string(finding.SevInfo):
			info = append(info, f)
		default:
			open = append(open, f)
		}
	}
	var tally []string
	for _, s := range []string{"critical", "high", "medium", "low"} {
		n := 0
		for _, f := range open {
			if f.Severity == s {
				n++
			}
		}
		if n > 0 {
			tally = append(tally, fmt.Sprintf("%d %s", n, s))
		}
	}
	head := fmt.Sprintf("FINDINGS: %d open", len(open))
	if len(tally) > 0 {
		head += " (" + strings.Join(tally, ", ") + ")"
	}
	t.line(t.bold(fmt.Sprintf("%s, %d informational, %d accepted", head, len(info), len(accepted))))
	t.hang("", "", "Ranked by severity in your context, among what scheck checked. Areas not checked may hold worse problems than anything here.")
	if len(open) > 0 {
		t.hang("", "", "To accept a risk instead of fixing it, see IF YOU DECIDE NOT TO FIX A FINDING after the findings.")
	}
	for i, f := range open {
		t.blank()
		t.findingBlock(i+1, f)
	}
	if len(info) > 0 {
		t.blank()
		t.line("Informational")
		for _, f := range info {
			t.hang("   ", "     ", clean(f.Title)+"  ("+t.name(f.Key.Asset)+")  ["+f.ID+"]"+t.lowered(f))
		}
	}
	if len(accepted) > 0 {
		t.blank()
		t.line("Accepted (not counted as open)")
		for _, f := range accepted {
			t.hang("   "+t.sev(pad(f.Severity, 8)), "     ", t.acceptedLine(f))
		}
	}
	t.blank()
}

func (t *text) lowered(f Finding) string {
	if f.Severity == f.SeverityBase || len(f.WhyHere) == 0 {
		return ""
	}
	return ": base " + f.SeverityBase + ", lowered: " + lower(strings.TrimSuffix(clean(f.WhyHere[0]), "."))
}

func (t *text) acceptedLine(f Finding) string {
	s := clean(f.Title) + "  (" + t.name(f.Key.Asset) + ")"
	a := f.Acceptance
	if a == nil {
		return s
	}
	by := clean(a.AcceptedBy)
	if by == "" {
		by = "the engagement file"
	}
	if a.Expires == nil {
		s += ": accepted by " + by + ", no expiry"
	} else {
		s += ": accepted by " + by + " until " + *a.Expires
		if days := t.daysUntil(*a.Expires); days >= 0 && days <= 30 {
			s += fmt.Sprintf(" (expires in %s)", count(days, "day", "days"))
		}
	}
	s += `: "` + clean(a.Reason) + `"`
	if a.Entry != "" {
		s += " (" + clean(entryKey(a.Entry)) + ")"
	}
	if a.CoversEveryInstance {
		s += ". Covers every instance of this id on this asset"
	}
	return s + "."
}

func (t *text) daysUntil(date string) int { return calendarDays(t.r.Run.Started, date, t.zone) }

// entryKey drops the file from "<file> intent.accepted_risks[0]".
func entryKey(entry string) string {
	if i := strings.LastIndex(entry, " "); i >= 0 {
		return entry[i+1:]
	}
	return entry
}

const col = 14

func (t *text) findingBlock(n int, f Finding) {
	first := fmt.Sprintf("%d  %s  ", n, t.sev(f.Severity))
	t.hang(first, "   ", clean(f.Title)+"  ("+t.name(f.Key.Asset)+")  ["+f.ID+"]")
	in := "   "
	if s := f.Subject; s != nil {
		t.field(in, "Subject", col, clean(s.Label)+" ("+clean(s.Kind)+" "+clean(s.Key)+")")
	}
	for _, e := range f.Evidence {
		if e.Kind == "declared" {
			t.field(in, "You declared", col, clean(e.Source)+": "+clean(e.Excerpt))
		}
	}
	for _, e := range f.Evidence {
		if e.Kind != "observed" {
			continue
		}
		where := clean(e.Observation)
		if e.CollectedAt != nil {
			where += " (" + t.clock(*e.CollectedAt) + ", as " + clean(e.Principal) + ")"
		}
		t.field(in, "Observed", col, where+": "+clean(e.Excerpt))
	}
	if f.Rule.Kind == "multi_fact" {
		t.field(in, "Concluded from", col, clean(strings.Join(f.Rule.Reads, ", ")))
	}
	var sev strings.Builder
	sev.WriteString(f.Severity)
	if len(f.Adjustments) > 0 {
		sev.WriteString(": base " + f.SeverityBase)
	}
	for _, a := range f.Adjustments {
		sev.WriteString(", " + a.Delta + " " + strings.NewReplacer(":", " ", "_", " ").Replace(a.Rule))
		switch {
		case a.Source.Key != "":
			sev.WriteString(" (" + clean(a.Source.Key) + ")")
		case a.Source.Observation != "":
			sev.WriteString(" (" + clean(a.Source.Observation) + ": " + clean(a.Source.Excerpt) + ")")
		}
	}
	t.field(in, "Severity", col, sev.String())
	for _, a := range t.r.Acceptances {
		if a.Outcome == "expired" && slices.ContainsFunc(a.Findings, func(k Key) bool { return k == f.Key }) {
			t.field(in, "Acceptance", col, "the acceptance by "+orNone(clean(a.AcceptedBy))+" expired on "+deref(a.Expires)+
				" ("+clean(entryKey(a.Entry))+"); the finding is open again.")
		}
	}
	if len(f.WhyHere) > 0 {
		var why []string
		for _, w := range f.WhyHere {
			why = append(why, clean(w))
		}
		t.field(in, "Why here", col, strings.Join(why, " "))
	} else {
		t.field(in, "Why here", col, "scheck was not told how this machine is used (for example, whether it faces the "+
			"internet), so this is the standard rating.")
	}
	if len(f.NotChecked) > 0 {
		t.field(in, "Not checked", col, clean(strings.Join(f.NotChecked, "; ")))
	}
	t.field(in, "Fix", col, clean(f.Remediation.Summary))
	pre := in + strings.Repeat(" ", col)
	for i, s := range f.Remediation.Steps {
		t.hang(pre+fmt.Sprintf("%d. ", i+1), pre+"   ", clean(s))
	}
	if f.Remediation.Caveat != "" {
		t.hang(pre+"Caveat: ", pre+"  ", clean(f.Remediation.Caveat))
	}
	if len(f.Remediation.Commands) > 0 {
		t.line(pre + "Commands (review before running):")
		for _, c := range f.Remediation.Commands {
			t.line(pre + "  " + hostreport.Sanitize(c))
		}
	}
	if f.Remediation.Where != "" {
		t.hang(pre+"Where: ", pre+"  ", clean(f.Remediation.Where))
	}
}

// pastes prints, once, the entry that accepts each open finding instead of
// fixing it, headed so nobody reads it as the default (docs/spec/report.md,
// "The paste").
func (t *text) pastes() {
	var ps []*AcceptTemplate
	var titles, sevs []string
	for _, f := range t.r.Findings {
		if f.AcceptTemplate != nil {
			ps = append(ps, f.AcceptTemplate)
			titles = append(titles, clean(f.Title)+" ("+t.name(f.Key.Asset)+")")
			sevs = append(sevs, f.Severity)
		}
	}
	if len(ps) == 0 {
		return
	}
	t.line(t.bold("IF YOU DECIDE NOT TO FIX A FINDING"))
	if ps[0].NeedsPeople {
		t.hang("", "", "Only for a risk you decide not to fix, and decided by whoever owns it: write the engagement to a "+
			"file (--write-engagement FILE), add yourself under people, paste the entry under intent.accepted_risks in "+
			"that file and write the reason, then run `scheck run FILE` from then on.")
	} else {
		file := "the engagement file"
		if path := t.r.Engagement.Source.Path; path != nil && *path != "" {
			file = clean(*path)
		}
		t.hang("", "", "Only for a risk you decide not to fix, and decided by whoever owns it: paste the entry under "+
			"intent.accepted_risks in "+file+" and write the reason.")
	}
	for i, p := range ps {
		t.blank()
		t.line("  # " + titles[i])
		if s := sevs[i]; s == string(finding.SevCritical) || s == string(finding.SevHigh) {
			t.line("  # " + s + ": accept only with whoever owns the business, never to quiet the report")
		}
		t.paste(p)
	}
	t.blank()
}

// paste renders one acceptance entry as YAML.
func (t *text) paste(p *AcceptTemplate) {
	in := "  "
	kv := func(k, v, comment string) {
		s := pad(k+": "+v, 29)
		if comment != "" {
			s += "# " + comment
		}
		t.line(in + "    " + s)
	}
	t.line(in + "  - id: " + p.ID)
	kv("asset", clean(p.Asset), "")
	switch {
	case p.Subject != "":
		subject := clean(p.Subject)
		// A wildcard starts YAML's alias syntax: quote it so the pasted
		// acceptance names the DNS subject (web-collector.md, "Wildcards").
		if strings.HasPrefix(subject, "*") {
			subject = strconv.Quote(subject)
		}
		kv("subject", subject, "required: this entry accepts this one only")
	case p.SubjectNote != "":
		t.line(in + "    # " + clean(p.SubjectNote))
	}
	kv("reason", `""`, "why this is acceptable here; required")
	who := "your handle under people"
	if len(p.AcceptedByCandidates) > 0 {
		var c []string
		for _, cand := range p.AcceptedByCandidates {
			c = append(c, clean(cand.Handle)+" ("+clean(cand.Why)+")")
		}
		who = "a handle under people: " + strings.Join(c, ", ")
	}
	kv("accepted_by", `""`, who)
	kv("expires", p.Expires, "after this date the finding counts again")
	t.line(in + "    " + pad("", 29) + "# until someone re-reviews it")
}

// --- not checked, excluded, notes, close ------------------------------------

func (t *text) notChecked() {
	var lines []string
	host := t.r.Engagement.BuiltFrom == "host"
	rerun := false
	for _, s := range t.r.Incomplete {
		if s.Effect != nil || s.Reason == "failed" || s.Reason == "limit_reached" {
			lines = append(lines, "Run again: "+t.shortfall(s))
			rerun = true
		}
	}
	for _, a := range t.r.Assets {
		if a.Envelope == nil {
			continue
		}
		var sudo, missing, unusable []string
		for _, id := range sortedKeys(a.Envelope.Facts) {
			switch rc := a.Envelope.Facts[id].ReasonCode; rc {
			case "":
			case "requires_elevation", "sudo_refused":
				sudo = append(sudo, id)
			case "command_missing":
				missing = append(missing, id)
			case "path_denied", "run_timeout", "canceled":
			default:
				unusable = append(unusable, id)
			}
		}
		n := clean(a.Name)
		if len(sudo) > 0 {
			how := "set elevate: sudo on " + n + " in the engagement file"
			if host {
				how = "run again with --sudo"
			}
			lines = append(lines, fmt.Sprintf("On %s, %s root: %s. To read them, %s.", n, count(len(sudo), "check needs", "checks need"),
				strings.Join(sudo, ", "), how))
		}
		if len(unusable) > 0 {
			lines = append(lines, fmt.Sprintf("On %s, %s not give a usable answer: %s. `scheck explain <check-id>` prints each command; run it by hand to see why.",
				n, count(len(unusable), "check did", "checks did"), strings.Join(unusable, ", ")))
		}
		switch {
		case len(missing) > 0 && t.opt.Verbose > 0:
			lines = append(lines, fmt.Sprintf("On %s, %s a tool this host does not have, so they could not tell (not a finding): %s. "+
				"Nothing to do unless you expected it installed.", n, count(len(missing), "check needs", "checks need"), strings.Join(missing, ", ")))
		case len(missing) > 0:
			lines = append(lines, fmt.Sprintf("On %s, %s a tool this host does not have, so they could not tell (not a finding; "+
				"listed with -v).", n, count(len(missing), "check needs", "checks need")))
		}
		if len(sudo) > 0 && host {
			rerun = true
		}
		var noRule []string
		for _, row := range t.r.Coverage {
			for _, si := range row.SubItems {
				if si.Asset == a.ID && len(si.Reasons) == 1 && si.Reasons[0].Reason == "no_rule" {
					noRule = append(noRule, lower(si.Name))
				}
			}
		}
		if len(noRule) > 0 {
			lines = append(lines, "On "+n+", this version of scheck has no rule for "+strings.Join(noRule, ", ")+
				". What was read is in the JSON report (--format json) for a person to look at.")
		}
	}
	var unread []string
	for _, a := range t.r.Assets {
		if a.Reason == "collector_not_built" {
			unread = append(unread, clean(a.Name)+" ("+kindLabel(a.ID)+")")
		}
	}
	for _, row := range t.r.Coverage {
		if row.Area == "other_saas" {
			unread = append(unread, clean(row.Tool))
		}
	}
	if len(unread) > 0 {
		them := "them"
		if len(unread) == 1 {
			them = "it"
		}
		lines = append(lines, strings.Join(unread, ", ")+": this version of scheck does not read "+them+"; assess "+them+" by other means until it does.")
	}
	if (rerun || len(t.r.Refused) > 0) && t.r.Run.Command != "" {
		lines = append(lines, "To run again: "+clean(t.r.Run.Command))
	}
	if len(lines) == 0 {
		return
	}
	t.line(t.bold("NOT CHECKED, AND WHAT WOULD CLOSE THE GAP"))
	for _, l := range lines {
		t.hang("  ", "    ", l)
	}
	t.blank()
}

func (t *text) excluded() {
	t.line(t.bold("EXCLUDED, NARROWED AND NOT RUN"))
	for _, e := range t.r.Excluded {
		t.field("  ", "Excluded in the file", 22, clean(e.Entry)+": "+clean(e.Detail))
	}
	for _, row := range t.r.Coverage {
		for _, n := range row.Narrowing {
			s := clean(entryKey(n.Entry))
			if len(n.Removed) > 0 {
				s += ": removed " + clean(strings.Join(n.Removed, ", "))
			} else if n.DeniedReads != nil {
				s += fmt.Sprintf(": %s denied", count(*n.DeniedReads, "read", "reads"))
			}
			t.field("  ", "Narrowed in the file", 22, s)
		}
	}
	builtin := 0
	for _, n := range t.r.Redaction.Builtin {
		builtin += n
	}
	red := fmt.Sprintf("built-in rules: %s.", count(builtin, "value", "values"))
	if op := t.r.Redaction.Operator; op.Rules > 0 {
		red += fmt.Sprintf(" Your redact_extra rules: %s (patterns not shown).", count(op.Matches, "match", "matches"))
	}
	t.field("  ", "Redacted", 22, red)
	t.field("  ", "Probes and scans", 22, "none exist in this version; nothing beyond reading was attempted.")
	for _, a := range t.r.Acceptances {
		if a.Outcome == "not_applied" {
			t.field("  ", "Not applied", 22, t.acceptanceName(a)+": "+clean(a.Why)+".")
		}
	}
	t.blank()
}

func (t *text) notes() {
	var lines []string
	for _, n := range t.r.Notes {
		if n.Kind == "acceptance_not_applied" {
			continue
		}
		who := clean(entryKey(n.Source))
		for _, a := range t.r.Acceptances {
			if a.Entry == n.Source {
				who = t.acceptanceName(a)
			}
		}
		lines = append(lines, who+": "+strings.TrimSuffix(clean(n.Detail), ".")+".")
	}
	if len(lines) == 0 {
		return
	}
	t.line(t.bold("NOTES FOR THE READOUT"))
	for _, l := range lines {
		t.hang("  ", "    ", l)
	}
	t.blank()
}

// acceptanceName names an accepted_risks entry by the finding it accepts and
// who accepted it, with its position in the file last.
func (t *text) acceptanceName(a Acceptance) string {
	title := a.ID
	if def, ok := finding.Lookup(a.ID); ok {
		title = def.Title
	}
	return "The acceptance of \"" + clean(title) + "\" on " + clean(a.Asset) + " by " + orNone(clean(a.AcceptedBy)) +
		" (" + clean(entryKey(a.Entry)) + ")"
}

// factSheets prints each collected host's facts at -v, one row per check
// with an execution status, and at -vv the redacted captures too
// (docs/spec/report.md, "Text and JSON"). The default report leaves
// them to the JSON: a reader does not act on them.
func (t *text) factSheets() {
	if t.opt.Verbose < 1 {
		return
	}
	for _, a := range t.r.Assets {
		if a.Envelope == nil {
			continue
		}
		t.line(t.bold("FACTS READ ON " + strings.ToUpper(clean(a.Name))))
		_ = t.w.Flush()
		_ = hostreport.WriteFactSheet(t.w, *a.Envelope, t.opt)
		t.blank()
	}
}

func (t *text) close() {
	t.line(t.bold("FOR AUTOMATION"))
	e := t.r.Exit
	open := t.openCount()
	precedence := func(code int) string {
		if open == 0 {
			return ""
		}
		return fmt.Sprintf(" Exit %d takes precedence over exit 1, so a pipeline that gates on exit 1 will not see the %s.",
			code, count(open, "open finding", "open findings"))
	}
	notClean := " Exit 0 is not a clean result either: it means only that no rule that could decide found an open problem at or above threshold."
	switch e.Code {
	case 0:
		rc := t.r.Summary.Rules
		_, _, notChecked, folded, _ := t.areas()
		t.hang("", "", fmt.Sprintf("Exit 0: no open finding at or above threshold among the %d rules that could decide. "+
			"That is not a clean result: %s no usable evidence, and %s not checked.", rc.Decided,
			count(rc.WithoutEvidence, "rule had", "rules had"), count(len(notChecked)+len(folded), "area was", "areas were")))
	case 1:
		t.hang("", "", fmt.Sprintf("Exit 1: %s (%s). Exit 0 would not have meant a clean result either.",
			openPhrase(open), t.thresholds()))
	case 2:
		var why []string
		for _, s := range t.r.Incomplete {
			w := map[string]string{"failed": "could not be reached", "limit_reached": "hit a time limit",
				"collector_not_built": "is not read by this version"}[s.Reason]
			if s.Effect != nil && s.Reason == "failed" {
				w = "lost its connection part-way"
			}
			why = append(why, t.name(s.Asset)+" "+w)
		}
		t.hang("", "", "Exit 2: incomplete: "+strings.Join(why, "; ")+"."+precedence(2)+notClean)
	case 3:
		var who []string
		for _, s := range t.r.Refused {
			who = append(who, t.name(s.Asset)+" was not assessed: "+t.refusedWhy(s.Asset))
		}
		s := "Exit 3: " + strings.Join(who, "; ") + "."
		if len(t.r.Assets) > len(t.r.Refused) {
			s += " The other assets were read and are reported above."
		}
		t.hang("", "", s+precedence(3))
	}
	if d := t.r.Run.Directory; d != nil {
		t.hang("Files  ", "       ", clean(*d)+"/: report.txt, report.json, audit.jsonl (every command and request, in order), evidence/")
	} else {
		t.hang("", "", "--no-persist: no run directory or audit log was written; the command trace is in the JSON report (--format json).")
	}
}

func (t *text) thresholds() string {
	var parts []string
	def := false
	for _, a := range t.r.Assets {
		th, ok := t.r.Exit.Thresholds[a.ID]
		if !ok {
			continue
		}
		if p, isProfile := strings.CutPrefix(th.Basis, "profile:"); isProfile {
			parts = append(parts, t.name(a.ID)+": "+th.Severity+", profile "+p)
		} else {
			def = true
		}
	}
	if def {
		if len(parts) > 0 {
			parts = append(parts, "every other asset: medium")
		} else {
			parts = append(parts, "every asset: medium")
		}
	}
	return strings.Join(parts, "; ")
}

// --- layout -----------------------------------------------------------------

func upper(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

// singular names one of a population's plural kind.
func singular(kind string) string {
	if one, ok := map[string]string{"repositories": "repository", "assets": "asset", "hosts": "host",
		"rules": "rule", "tenants": "tenant", "users": "user", "entry points": "entry point"}[kind]; ok {
		return one
	}
	return kind
}

func openPhrase(n int) string {
	if n == 1 {
		return "1 open finding at or above its asset's threshold"
	}
	return fmt.Sprintf("%d open findings at or above their asset's threshold", n)
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func pad(s string, n int) string {
	if d := n - visible(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s + " "
}

// visible is s's width without colour sequences.
func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			n++
		}
	}
	return n
}

// wrapHang lays s out after first, continuing under indent, within width.
// A word longer than a line is cut, never allowed to overrun.
func wrapHang(first, indent, s string, width int) []string {
	limit := max(width-visible(indent), 20)
	var words []string
	for w := range strings.FieldsSeq(s) {
		r := []rune(w)
		for len(r) > limit {
			words = append(words, string(r[:limit]))
			r = r[limit:]
		}
		words = append(words, string(r))
	}
	if len(words) == 0 {
		return []string{first}
	}
	var out []string
	cur, empty := first, true
	for _, w := range words {
		if !empty && visible(cur)+1+visible(w) > width {
			out = append(out, cur)
			cur, empty = indent, true
		}
		if !empty {
			cur += " "
		}
		cur += w
		empty = false
	}
	return append(out, cur)
}
