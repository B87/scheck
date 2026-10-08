package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
)

// Asset statuses, as Recon records them.
const (
	statusCollected    = "collected"
	statusIncomplete   = "incomplete"
	statusFailed       = "failed"
	statusRefused      = "refused"
	statusNotCollected = "not_collected"
)

// builder holds what Build has derived so far.
type builder struct {
	in    Input
	zone  *time.Location
	hosts map[string]*hostView // by asset id
	// applying maps "<asset id>\x00<finding id>" to the acceptance the host
	// grader applied: the last entry without a subject.
	applying map[string]AcceptanceInput
	r        *Report
}

// Build assembles the report from a run's collections. It never fails: an
// asset that was not read is a coverage gap and an exit code, not an error.
func Build(in Input) *Report {
	b := &builder{in: in, zone: in.Zone, hosts: map[string]*hostView{}, applying: map[string]AcceptanceInput{}}
	if b.zone == nil {
		b.zone = time.UTC
	}
	if in.Finished.IsZero() {
		b.in.Finished = in.Started
	}
	for _, acc := range in.Acceptances {
		if acc.Subject == "" && !strings.HasPrefix(acc.ID, "custom:") {
			b.applying[acc.AssetID+"\x00"+acc.ID] = acc
		}
	}
	r := &Report{
		SchemaVersion: SchemaVersion, ScheckVersion: in.Version, RulesVersion: in.Version,
		Run:        Run{Started: in.Started.UTC(), Resumed: in.Resumed, Command: in.Rerun},
		Engagement: b.engagement(),
		Notice:     Notice{PersonalData: true, InternalTopology: true, Audience: "operator"},
		Refused:    []Shortfall{}, Incomplete: []Shortfall{},
		Findings: []Finding{}, Assessments: []Assessment{}, Acceptances: []Acceptance{},
		Excluded: []Excluded{}, Assets: []Asset{}, Notes: []Note{},
		Redaction: Redaction{Builtin: map[string]int{}, Operator: OperatorRedaction{Rules: in.RedactExtra}},
	}
	if in.Directory != "" {
		dir := in.Directory
		r.Run.Directory = &dir
	}
	b.r = r
	for _, a := range in.Assets {
		if a.Host != nil {
			b.hosts[a.ID] = newHostView(a)
		}
	}
	for _, a := range in.Assets {
		r.Assets = append(r.Assets, b.asset(a))
		b.shortfall(a)
		if v := b.hosts[a.ID]; v != nil {
			r.Findings = append(r.Findings, b.hostFindings(v)...)
			r.Assessments = append(r.Assessments, v.assessments()...)
			r.Redaction.Operator.Matches += v.redactions(r.Redaction.Builtin)
		}
	}
	b.rankFindings()
	b.acceptances()
	r.Coverage = b.coverage()
	for _, e := range in.Excludes {
		x := Excluded{Entry: e, Detail: "not matched: nothing in this version discovers what it covers"}
		if n, ok := in.ExcludeMatches[e]; ok {
			matched := n > 0
			x.Matched, x.Detail = &matched, fmt.Sprintf("dropped %d discovered %s", n, plural(n, "name"))
		}
		r.Excluded = append(r.Excluded, x)
	}
	r.Egress = b.egress()
	r.Summary = b.summary()
	r.Exit = b.exit()
	return r
}

func (b *builder) engagement() Engagement {
	in := b.in
	e := Engagement{
		Name: in.Name, Timezone: b.zone.String(), BuiltFrom: "file",
		Source:        Source{SHA256: in.SHA256},
		Collected:     Span{From: in.Started.UTC(), To: in.Finished.UTC()},
		Method:        Method{Assessment: "rules", Plan: "checklist", LevelsUsed: []string{}},
		Authorization: in.Authorization, EditedByHand: append([]string{}, in.EditedByHand...),
	}
	if in.Operator != "" {
		op := in.Operator
		e.Operator = &op
	}
	if in.Trigger != "" {
		t := in.Trigger
		e.Trigger = &t
	}
	if in.FromHost {
		e.BuiltFrom = "host"
	} else {
		p := in.Path
		e.Source.Path = &p
	}
	for _, a := range in.Assets {
		if a.Host != nil {
			e.Method.LevelsUsed = []string{"observe"}
			break
		}
	}
	return e
}

func (b *builder) asset(a AssetInput) Asset {
	out := Asset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root, Status: a.Status, Reason: a.Reason,
		Detail: a.Detail, Via: a.Via, Trace: []Trace{}}
	if a.Kind == "host" {
		host := "host"
		out.Collector = &host
	}
	// Every collection attempt's commands, a refused or failed one's
	// included: the trace says what touched every asset.
	for _, e := range a.Trace {
		out.Trace = append(out.Trace, Trace{Observation: e.Observation, Check: e.CheckID, Params: e.Params,
			At: e.Time.UTC(), Decision: e.Decision, OutputSHA256: e.OutputHash})
	}
	v := b.hosts[a.ID]
	if v == nil {
		return out
	}
	env := v.env
	bound := env.Host.ID
	out.BoundID = &bound
	out.Principal = &Principal{Identity: v.h.User, Elevation: env.Host.Elevation, ScopesSource: "provider"}
	span := Span{From: env.Run.Started.UTC(), To: env.Run.Started.Add(time.Duration(env.Run.DurationMS) * time.Millisecond).UTC()}
	if n := len(out.Trace); n > 0 {
		span = Span{From: out.Trace[0].At, To: out.Trace[n-1].At}
	}
	out.Collected = &span
	if v.h.Evidence != "" {
		p := v.h.Evidence
		out.Evidence = &p
	}
	envCopy := env
	out.Envelope = &envCopy
	out.Kept = a.Kept
	c := v.checks()
	out.Checks = &c
	return out
}

// shortfall records a refused asset (exit 3) and an incomplete one (exit
// 2): a declared root with no successful read, or a collection cut short
// (docs/spec/engagement.md, "Exit codes").
func (b *builder) shortfall(a AssetInput) {
	s := Shortfall{Asset: a.ID, AssetName: a.Name, Reason: a.Reason, Detail: a.Detail, Echo: a.Echo, Kind: a.Refusal}
	switch a.Status {
	case statusRefused:
		s.Reason = "refused"
		b.r.Refused = append(b.r.Refused, s)
	case statusFailed:
		s.Reason = "failed"
		b.r.Incomplete = append(b.r.Incomplete, s)
	case statusNotCollected:
		if a.Root || a.Reason == "limit_reached" {
			b.r.Incomplete = append(b.r.Incomplete, s)
		}
	case statusIncomplete:
		if v := b.hosts[a.ID]; v != nil {
			c := v.checks()
			s.Effect = &Effect{ChecksRun: c.Ran, ChecksUnknown: c.Unknown, ChecksNotRun: c.NotRun, Kept: true}
		}
		b.r.Incomplete = append(b.r.Incomplete, s)
	}
}

// acceptances settles every intent.accepted_risks entry and writes the
// readout's notes about them (docs/spec/engagement.md, "Acceptances").
func (b *builder) acceptances() {
	for _, acc := range b.in.Acceptances {
		out := Acceptance{Entry: acc.Entry, ID: acc.ID, Asset: acc.Asset, AcceptedBy: acc.AcceptedBy, Findings: []Key{}}
		if acc.Subject != "" {
			s := acc.Subject
			out.Subject = &s
		}
		if acc.Expires != "" {
			e := acc.Expires
			out.Expires = &e
		}
		out.Outcome, out.Why = b.outcome(acc, &out)
		b.r.Acceptances = append(b.r.Acceptances, out)
		kind := map[string]string{"not_applied": "acceptance_not_applied", "not_matched": "acceptance_not_matched",
			"rule_not_decided": "acceptance_rule_not_decided", "subject_not_found": "acceptance_subject_not_found"}[out.Outcome]
		if kind != "" {
			b.note(kind, acc.Entry, out.Why)
		}
		switch days := b.daysLeft(acc.Expires, acc.AssetID); {
		case acc.Expires == "" && out.Outcome != "not_matched":
			b.note("acceptance_without_expiry", acc.Entry, "it has no expiry date, so nobody is asked to look at it again")
		case out.Outcome != "expired" && days >= 0 && days <= 30:
			b.note("acceptance_expiring", acc.Entry, fmt.Sprintf("it expires on %s, in %d days", acc.Expires, days))
		}
	}
}

func (b *builder) outcome(acc AcceptanceInput, out *Acceptance) (string, string) {
	v := b.hosts[acc.AssetID]
	if v == nil {
		return "rule_not_decided", "the asset was not read on this run"
	}
	if acc.Subject != "" {
		return "not_applied", "it names one instance, and this version cannot accept one instance of a host finding, " +
			"so it was ignored rather than widened to all of them"
	}
	if strings.HasPrefix(acc.ID, "custom:") {
		return "rule_not_decided", "no rule decides a custom finding"
	}
	var ea *Assessment
	for i := range b.r.Assessments {
		if a := &b.r.Assessments[i]; a.Asset == acc.AssetID && a.ID == acc.ID {
			ea = a
		}
	}
	if ea == nil {
		return "rule_not_decided", "no rule for this id ran on this asset"
	}
	switch {
	case ea.Status == finding.Matched:
		key := Key{ID: acc.ID, Asset: acc.AssetID}
		out.Findings = append(out.Findings, key)
		if applied := b.applying[acc.AssetID+"\x00"+acc.ID]; applied.Entry != acc.Entry {
			return "not_applied", "a later entry for the same id applies: " + applied.Entry
		}
		if b.expired(acc.Expires, acc.AssetID) {
			return "expired", "expired " + acc.Expires + "; the finding is open again"
		}
		return "applied", ""
	case ea.Status == finding.NotMatched && ea.Complete:
		return "not_matched", "its rule found no instance in everything it read: likely fixed. Confirm, then remove the entry"
	case ea.Status == finding.NotMatched:
		return "rule_not_decided", "its rule found no instance in what it read, which is only part of what is there: " +
			"the acceptance still stands, and scheck cannot say whether the problem is gone"
	}
	return "rule_not_decided", "its rule could not decide this time: the acceptance still stands, and scheck does not know " +
		"whether the problem is still there"
}

// expired reads an acceptance's date in engagement.timezone against the
// collection time of the asset it names (docs/spec/engagement.md,
// "Accepted risks"), as its grader did.
func (b *builder) expired(date, asset string) bool {
	return operator.Risk{Expires: date, Zone: b.zone}.Expired(b.gradedAt(asset))
}

// daysLeft is how many calendar days remain before date ends, in the
// engagement's zone, from the asset's collection date; negative once it
// has passed.
func (b *builder) daysLeft(date, asset string) int {
	return calendarDays(b.gradedAt(asset), date, b.zone)
}

// gradedAt is when the host asset was graded, a resumed run's sessions
// apart; the run's start for anything else.
func (b *builder) gradedAt(asset string) time.Time {
	for _, a := range b.in.Assets {
		if a.ID == asset && a.Host != nil && !a.Host.Graded.IsZero() {
			return a.Host.Graded
		}
	}
	return b.in.Started
}

// calendarDays counts the days from at's date in zone to date, as calendar
// dates: a daylight-saving change never shortens or lengthens one.
func calendarDays(at time.Time, date string, zone *time.Location) int {
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return -1
	}
	y, m, day := at.In(zone).Date()
	return int(d.Sub(time.Date(y, m, day, 0, 0, 0, 0, time.UTC)).Hours() / 24)
}

func (b *builder) note(kind, source, detail string) {
	b.r.Notes = append(b.r.Notes, Note{Kind: kind, Source: source, Detail: detail})
}

// findingAcceptance is the entry an accepted finding is under.
func (b *builder) findingAcceptance(asset, id, reason string) *FindingAccept {
	acc, ok := b.applying[asset+"\x00"+id]
	if !ok {
		return &FindingAccept{Reason: reason, Expires: nil, CoversEveryInstance: true}
	}
	fa := &FindingAccept{Entry: acc.Entry, Reason: acc.Reason, AcceptedBy: acc.AcceptedBy, CoversEveryInstance: true}
	if acc.Expires != "" {
		e := acc.Expires
		fa.Expires = &e
	}
	return fa
}

// template is the ready-to-paste acceptance for an open finding: reason and
// accepted_by left for the risk's owner, expires a quarter out for critical
// and high and half a year otherwise (docs/spec/engagement.md, "The paste").
func (b *builder) template(a AssetInput, id string, sev finding.Severity) *AcceptTemplate {
	days := 180
	if sev.AtLeast(finding.SevHigh) {
		days = 90
	}
	y, m, d := b.in.Started.In(b.zone).Date()
	ref := a.Name
	if ref == "" {
		ref = a.ID
	}
	cands := b.in.Candidates
	if cands == nil {
		cands = []Candidate{}
	}
	return &AcceptTemplate{ID: id, Asset: ref, AcceptedByCandidates: cands,
		Expires:     time.Date(y, m, d, 0, 0, 0, 0, b.zone).AddDate(0, 0, days).Format("2006-01-02"),
		NeedsPeople: !b.in.People}
}

// rankFindings puts findings[] in the order the report ranks them: open
// findings by severity after context, risk area, an asset named in
// data.matters_most, then asset and id; then informational ones; then the
// accepted (docs/spec/engagement.md, "Ranking"). A consumer reading the
// JSON in order reads the most serious first.
func (b *builder) rankFindings() {
	group := func(f Finding) int {
		switch {
		case f.Status == finding.StatusAccepted:
			return 2
		case f.Severity == string(finding.SevInfo):
			return 1
		}
		return 0
	}
	slices.SortStableFunc(b.r.Findings, func(x, y Finding) int {
		return cmp.Or(
			cmp.Compare(group(x), group(y)),
			cmp.Compare(finding.Severity(y.Severity).Rank(), finding.Severity(x.Severity).Rank()),
			cmp.Compare(slices.Index(finding.Areas, finding.Area(x.Area)), slices.Index(finding.Areas, finding.Area(y.Area))),
			boolFirst(slices.Contains(b.in.DataMattersMost, x.Key.Asset), slices.Contains(b.in.DataMattersMost, y.Key.Asset)),
			cmp.Compare(x.Key.Asset, y.Key.Asset),
			cmp.Compare(x.ID, y.ID),
		)
	})
}

// summary ranks the open findings at medium or above into at most five
// items, one per finding id (docs/spec/engagement.md, "Ranking").
func (b *builder) summary() Summary {
	s := Summary{Items: []Item{}, Areas: AreaCounts{Total: len(finding.Areas)}}
	type group struct {
		item  Item
		rank  int
		area  int
		dmm   string // the first asset data.matters_most names
		count int
	}
	groups := map[string]*group{}
	var order []*group
	for _, f := range b.r.Findings {
		switch {
		case f.Status == finding.StatusAccepted:
			s.Below.Accepted++
			continue
		case f.Severity == string(finding.SevInfo):
			s.Below.Info++
			continue
		case f.Severity == string(finding.SevLow):
			s.Below.Low++
			continue
		}
		g := groups[f.ID]
		if g == nil {
			g = &group{item: Item{Kind: "finding_id", IDs: []string{f.ID}, Title: f.Title, Keys: []Key{}, Assets: []string{}}, rank: -1,
				area: slices.Index(finding.Areas, finding.Area(f.Area))}
			groups[f.ID] = g
			order = append(order, g)
		}
		if r := finding.Severity(f.Severity).Rank(); r > g.rank {
			g.rank, g.item.Severity = r, f.Severity
		}
		g.item.Keys = append(g.item.Keys, f.Key)
		g.item.Assets = appendUnique(g.item.Assets, f.Key.Asset)
		g.count++
		if g.dmm == "" && slices.Contains(b.in.DataMattersMost, f.Key.Asset) {
			g.dmm = f.Key.Asset
		}
	}
	slices.SortStableFunc(order, func(x, y *group) int {
		return cmp.Or(
			cmp.Compare(y.rank, x.rank),
			cmp.Compare(x.area, y.area),
			boolFirst(x.dmm != "", y.dmm != ""),
			cmp.Compare(y.count, x.count),
			cmp.Compare(x.item.Assets[0], y.item.Assets[0]),
			cmp.Compare(x.item.IDs[0], y.item.IDs[0]),
		)
	})
	for i, g := range order {
		if i == 5 {
			s.More = len(order) - 5
			break
		}
		g.item.Rank = i + 1
		g.item.RankBasis = []string{"severity:" + g.item.Severity, "area:" + string(finding.Areas[max(g.area, 0)])}
		if g.dmm != "" {
			g.item.RankBasis = append(g.item.RankBasis, "data_matters_most:"+g.dmm)
		}
		s.Items = append(s.Items, g.item)
	}
	for _, row := range b.r.Coverage {
		if !slices.Contains(finding.Areas, finding.Area(row.Area)) {
			continue
		}
		switch row.Mark {
		case "assessed":
			s.Areas.Assessed++
		case "partial":
			s.Areas.Partial++
		case "not_applicable":
			s.Areas.NotApplicable++
		default:
			s.Areas.NotAssessed++
		}
	}
	for _, a := range b.r.Assessments {
		s.Rules.Selected++
		if a.Status == finding.NotAssessed {
			s.Rules.WithoutEvidence++
		} else {
			s.Rules.Decided++
		}
	}
	return s
}

func boolFirst(x, y bool) int {
	switch {
	case x == y:
		return 0
	case x:
		return -1
	}
	return 1
}

// exit is the exit code: 3 when a host refused us, 2 when the run is
// incomplete, 1 when an open finding is at or above its asset's threshold,
// in that precedence (docs/spec/engagement.md, "Exit codes").
func (b *builder) exit() Exit {
	e := Exit{Reasons: []ExitReason{}, Thresholds: map[string]Threshold{}}
	for _, a := range b.in.Assets {
		t := Threshold{Severity: string(finding.SevMedium), Basis: "default"}
		profile := a.Profile
		if v := b.hosts[a.ID]; v != nil {
			profile = v.env.Run.Profile
		}
		if p, ok := check.ParseProfile(profile); ok && a.Kind == "host" {
			t = Threshold{Severity: string(finding.Threshold(p)), Basis: "profile:" + p.String()}
		}
		e.Thresholds[a.ID] = t
	}
	for _, s := range b.r.Refused {
		e.Reasons = append(e.Reasons, ExitReason{Code: 3, Why: s.AssetName + " was not assessed: " + s.Detail, Asset: s.Asset})
	}
	for _, s := range b.r.Incomplete {
		why := s.AssetName + ": " + s.Reason
		if s.Detail != "" {
			why += ": " + s.Detail
		}
		e.Reasons = append(e.Reasons, ExitReason{Code: 2, Why: why, Asset: s.Asset})
	}
	if n := b.openAtOrAbove(e.Thresholds); n > 0 {
		why := fmt.Sprintf("%d open findings at or above their asset's threshold", n)
		if n == 1 {
			why = "1 open finding at or above its asset's threshold"
		}
		e.Reasons = append(e.Reasons, ExitReason{Code: 1, Why: why})
	}
	switch {
	case len(b.r.Refused) > 0:
		e.Code = 3
	case len(b.r.Incomplete) > 0:
		e.Code = 2
	case len(e.Reasons) > 0:
		e.Code = 1
	}
	return e
}

// openAtOrAbove counts open findings at or above their asset's threshold:
// what makes a run exit 1.
func (b *builder) openAtOrAbove(t map[string]Threshold) int {
	n := 0
	for _, f := range b.r.Findings {
		if f.Status == finding.StatusOpen && finding.Severity(f.Severity).AtLeast(finding.Severity(t[f.Key.Asset].Severity)) {
			n++
		}
	}
	return n
}
