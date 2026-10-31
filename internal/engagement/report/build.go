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
	// acceptedAt is, by entry, the collection time an acceptance whose
	// finding was matched had its expiry judged at.
	acceptedAt map[string]time.Time
	// entryAt memoizes acceptanceAt by entry.
	entryAt map[string]time.Time
	r       *Report
}

// Build assembles the report from a run's collections. It never fails: an
// asset that was not read is a coverage gap and an exit code, not an error.
func Build(in Input) *Report {
	b := &builder{in: in, zone: in.Zone, hosts: map[string]*hostView{}, applying: map[string]AcceptanceInput{}, acceptedAt: map[string]time.Time{}, entryAt: map[string]time.Time{}}
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
		Run:        Run{Vantage: in.Vantage, Started: in.Started.UTC(), Resumed: in.Resumed, Command: in.Rerun, SessionStarted: cmp.Or(in.Session, in.Started).UTC()},
		Engagement: b.engagement(),
		Notice:     Notice{PersonalData: true, InternalTopology: true, Audience: "operator"},
		Refused:    []Shortfall{}, Incomplete: []Shortfall{},
		Findings: []Finding{}, Assessments: []Assessment{}, Acceptances: []Acceptance{}, PeopleLeft: []PersonLeft{},
		Excluded: []Excluded{}, Assets: []Asset{}, Notes: []Note{},
		Redaction: Redaction{Builtin: map[string]int{}, Operator: OperatorRedaction{Rules: in.RedactExtra}},
	}
	if in.Directory != "" {
		dir := in.Directory
		r.Run.Directory = &dir
	}
	if in.RulesVersion != "" {
		r.RulesVersion = in.RulesVersion
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
		r.Incomplete = append(r.Incomplete, a.WebShortfalls...)
		if v := b.hosts[a.ID]; v != nil {
			r.Findings = append(r.Findings, b.hostFindings(v)...)
			r.Assessments = append(r.Assessments, v.assessments()...)
			r.Redaction.Operator.Matches += v.redactions(r.Redaction.Builtin)
		}
		if a.Collector != "" {
			r.Notes = append(r.Notes, a.InventoryNotes...)
			r.Notes = append(r.Notes, a.MailNotes...)
			r.Notes = append(r.Notes, a.WebNotes...)
			for _, h := range a.Redactions {
				if strings.HasPrefix(h.Rule, "extra:") {
					r.Redaction.Operator.Matches++
				} else {
					r.Redaction.Builtin[h.Rule]++
				}
			}
		}
		// A network collector's verdicts, and the multi-fact rules' on a host.
		r.Findings = append(r.Findings, b.judgedFindings(a)...)
		r.Assessments = append(r.Assessments, judgedAssessments(a)...)
	}
	for _, n := range in.ContextNotes {
		r.Notes = append(r.Notes, n.Note)
	}
	r.Findings = uniqueFindings(r.Findings)
	r.Assessments = uniqueAssessments(r.Assessments)
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
	r.PeopleLeft = b.peopleLeft()
	r.Summary = b.summary()
	r.Summary.MattersMost = b.mattersMost()
	r.Exit = b.exit()
	return r
}

func (b *builder) engagement() Engagement {
	in := b.in
	e := Engagement{
		Name: in.Name, Timezone: b.zone.String(), BuiltFrom: "file",
		Source:           Source{SHA256: in.SHA256},
		Collected:        Span{From: in.Started.UTC(), To: in.Finished.UTC()},
		Method:           Method{Assessment: "rules", Plan: "checklist", LevelsUsed: append([]string{}, in.LevelsUsed...), Probes: in.Probes},
		PrincipalChanges: append([]PrincipalChange{}, in.PrincipalChanges...),
		Authorization:    in.Authorization, EditedByHand: append([]string{}, in.EditedByHand...),
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
		switch {
		case a.Host != nil && !slices.Contains(e.Method.LevelsUsed, "observe"):
			e.Method.LevelsUsed = append(e.Method.LevelsUsed, "observe")
		}
	}
	return e
}

func (b *builder) asset(a AssetInput) Asset {
	out := Asset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root, Status: a.Status, Reason: a.Reason,
		Detail: a.Detail, Via: a.Via, Trace: []Trace{}}
	if !a.OldestCollectedAt.IsZero() {
		at := a.OldestCollectedAt.UTC()
		out.OldestCollectedAt = &at
	}
	if a.Kind == "host" {
		host := "host"
		out.Collector = &host
	}
	if a.Collector != "" {
		c := a.Collector
		out.Collector = &c
	}
	// Every collection attempt's commands, a refused or failed one's
	// included: the trace says what touched every asset.
	for _, e := range a.Trace {
		out.Trace = append(out.Trace, Trace{Observation: e.Observation, Check: e.CheckID, Params: e.Params,
			At: e.Time.UTC(), Decision: e.Decision, OutputSHA256: e.OutputHash})
	}
	out.Trace = append(out.Trace, a.NetworkTrace...)
	out.Principal = a.NetworkPrincipal
	v := b.hosts[a.ID]
	if v == nil {
		return out
	}
	env := v.env
	bound := env.Host.ID
	out.BoundID = &bound
	out.BoundIDSource = env.Host.IDSource
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
// (docs/spec/scope.md, "Exit codes").
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
// readout's notes about them (docs/spec/report.md, "Acceptances").
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
		// An acceptance whose finding was not matched has no time its
		// expiry is judged at; its date is printed and nothing else.
		at, judged := b.acceptedAt[acc.Entry]
		switch days := calendarDays(at, acc.Expires, b.zone); {
		case acc.Expires == "" && out.Outcome != "not_matched":
			b.note("acceptance_without_expiry", acc.Entry, "it has no expiry date, so nobody is asked to look at it again")
		case judged && out.Outcome != "expired" && days >= 0 && days <= 30:
			b.note("acceptance_expiring", acc.Entry, fmt.Sprintf("it expires on %s, %s after collection on %s", acc.Expires, count(days, "day", "days"), b.day(at)))
		}
	}
}

func (b *builder) outcome(acc AcceptanceInput, out *Acceptance) (string, string) {
	// A host's posture findings are the host grader's to accept, by whole
	// id; a multi-fact rule's are judged like a network collector's.
	def, _ := finding.Lookup(acc.ID)
	if judged, read := b.judgedFor(acc.AssetID); read && (b.hosts[acc.AssetID] == nil || def.MultiFact) {
		return b.judgedOutcome(acc, out, judged)
	}
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
		at := b.readAt(acc.AssetID, nil)
		b.acceptedAt[acc.Entry] = at
		if b.expired(acc.Expires, at) {
			return "expired", "expired " + acc.Expires + ", before collection on " + b.day(at) + "; the finding is open again"
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

// expired reads an acceptance's date in engagement.timezone against at,
// the collection time of what the matched finding rests on
// (docs/spec/engagement.md, "Accepted risks", "Severity in context").
func (b *builder) expired(date string, at time.Time) bool {
	return operator.Risk{Expires: date, Zone: b.zone}.Expired(at)
}

// readAt is the collection time a finding's acceptance is judged at: the
// latest of the reads it cites; for a host, the start of the session that
// collected it. Zero when it cites no read with a recorded time: then no
// clock decides the acceptance, and the finding stays open.
func (b *builder) readAt(asset string, reads []string) time.Time {
	if at := b.gradedAt(asset); !at.IsZero() {
		return at
	}
	var at time.Time
	for _, r := range reads {
		if meta, ok := b.in.Observations[r]; ok && meta.CollectedAt.After(at) {
			at = meta.CollectedAt
		}
	}
	return at
}

// current says an acceptance holds at at: a collection time is recorded
// and its date had not ended then.
func (b *builder) current(date string, at time.Time) bool {
	return !at.IsZero() && !b.expired(date, at)
}

// gradedAt is when the host asset was graded, a resumed run's sessions
// apart; zero for anything else.
func (b *builder) gradedAt(asset string) time.Time {
	for _, a := range b.in.Assets {
		if a.ID == asset && a.Host != nil {
			return cmp.Or(a.Host.Graded, b.in.Started)
		}
	}
	return time.Time{}
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

// day is a collection time's date in engagement.timezone.
func (b *builder) day(at time.Time) string { return at.In(b.zone).Format(time.DateOnly) }

func (b *builder) note(kind, source, detail string) {
	b.r.Notes = append(b.r.Notes, Note{Kind: kind, Source: source, Detail: detail})
}

// findingAcceptance is the entry an accepted finding is under.
func (b *builder) findingAcceptance(asset, id, reason string) *FindingAccept {
	acc, ok := b.applying[asset+"\x00"+id]
	if !ok {
		return &FindingAccept{Reason: reason, Expires: nil, CoversEveryInstance: true}
	}
	at := b.readAt(asset, nil)
	fa := &FindingAccept{Entry: acc.Entry, Reason: acc.Reason, AcceptedBy: acc.AcceptedBy, CoversEveryInstance: true, JudgedAt: &at}
	if acc.Expires != "" {
		e := acc.Expires
		fa.Expires = &e
	}
	return fa
}

// template is the ready-to-paste acceptance for an open finding: reason and
// accepted_by left for the risk's owner, date the collection day, expires a
// quarter out for critical and high and half a year otherwise, inside the
// one-year cap (docs/spec/report.md, "The paste").
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
	written := time.Date(y, m, d, 0, 0, 0, 0, b.zone)
	return &AcceptTemplate{ID: id, Asset: ref, AcceptedByCandidates: cands,
		Date:        written.Format("2006-01-02"),
		Expires:     written.AddDate(0, 0, days).Format("2006-01-02"),
		NeedsPeople: !b.in.People}
}

// rankFindings puts findings[] in the order the report ranks them: open
// findings by severity after context, risk area, an asset named in
// data.matters_most, then asset and id; then informational ones; then the
// accepted (docs/spec/report.md, "Ranking"). A consumer reading the
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
// items: one per finding id, or one per person who left whose open
// findings one offboarding closes (docs/spec/report.md, "Ranking").
func (b *builder) summary() Summary {
	s := Summary{Items: []Item{}, Areas: AreaCounts{Total: len(finding.Areas)}}
	var open []Finding
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
		// An empty password SSH accepts is ranked; the host-local finding on
		// the same host is its first fix, listed under Findings only, when
		// the remote one names every account it does.
		if f.ID == finding.IDEmptyPassword && slices.ContainsFunc(b.r.Findings, func(o Finding) bool {
			return o.ID == finding.IDEmptyPasswordRemote && o.Key.Asset == f.Key.Asset && o.Status == finding.StatusOpen &&
				o.Affected != nil && coversAccounts(o.Affected.Listed, f)
		}) {
			continue
		}
		open = append(open, f)
	}
	people, taken := b.personGroups(open)
	groups := map[string]*rankGroup{}
	order := people
	for i, f := range open {
		g := groups[f.ID]
		if g == nil {
			g = &rankGroup{item: Item{Kind: "finding_id", IDs: []string{f.ID}, Title: f.Title, Keys: []Key{}, Assets: []string{}}, rank: -1,
				area: slices.Index(finding.Areas, finding.Area(f.Area))}
			groups[f.ID] = g
		}
		if taken[i] {
			g.item.OtherPeople = true
			continue
		}
		if len(g.item.Keys) == 0 {
			order = append(order, g)
		}
		g.add(f, b.in.DataMattersMost)
	}
	for _, g := range order {
		if g.item.Kind == "finding_id" && slices.Contains(leaverIDs, g.item.IDs[0]) {
			// One person's access across many repositories is one thing
			// to fix: count people, not instances.
			g.count = len(g.people)
		}
	}
	slices.SortStableFunc(order, func(x, y *rankGroup) int {
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
		if g.item.Person != nil {
			g.item.RankBasis = append(g.item.RankBasis, "person:"+*g.item.Person)
		}
		if g.dmm != "" {
			g.item.RankBasis = append(g.item.RankBasis, "data_matters_most:"+g.dmm)
		}
		if g.item.Person != nil {
			for _, a := range g.top.Adjustments {
				g.item.RankBasis = appendUnique(g.item.RankBasis, a.Rule)
			}
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
// in that precedence (docs/spec/scope.md, "Exit codes").
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
	// Discovered names have their own finding assets without a declared
	// AssetInput. Their default threshold is still medium (docs/spec/scope.md,
	// "Outcomes"); a missing map entry must not discard their findings.
	for _, f := range b.r.Findings {
		if _, ok := e.Thresholds[f.Key.Asset]; !ok {
			e.Thresholds[f.Key.Asset] = Threshold{Severity: string(finding.SevMedium), Basis: "default"}
		}
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

// coversAccounts says listed names every account the host-local
// empty-password finding cites in its password-state evidence, which
// reads "name=<account> status=NP" per account.
func coversAccounts(listed []string, f Finding) bool {
	n := 0
	for _, e := range f.Evidence {
		if e.Check != "accounts.passwd_status" {
			continue
		}
		for part := range strings.SplitSeq(e.Excerpt, "; ") {
			for field := range strings.FieldsSeq(part) {
				name, ok := strings.CutPrefix(field, "name=")
				if !ok {
					continue
				}
				if !slices.Contains(listed, name) {
					return false
				}
				n++
			}
		}
	}
	return n > 0
}
