package compare

import (
	"fmt"
	"slices"

	"github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
)

func (p *pair) comparable() Comparability {
	c := Comparability{
		SameRules: p.sameRules, SameFile: p.sameFile, VantageChanged: !p.vantageSame,
		RedactionRulesDiffer: p.redactionDiffers, PrincipalChanges: []string{},
	}
	if h := p.l.Engagement.Collected.From.Sub(p.e.Engagement.Collected.To).Hours(); h > 0 {
		c.HoursApart = int(h)
	}
	for _, id := range sortedKeys(p.link) {
		l := p.link[id]
		if principalChanged(p.eAssets[id], p.lAssets[l.later]) {
			c.PrincipalChanges = append(c.PrincipalChanges, l.later)
		}
	}
	return c
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func ref(f *report.Finding, withhold bool) *Ref {
	r := &Ref{Asset: f.Key.Asset, AssetName: f.AssetName, BoundID: f.BoundID, Severity: f.Severity, Status: f.Status}
	if withhold && f.Subject != nil {
		r.SubjectWithheld = true
		return r
	}
	r.Subject = f.Subject
	return r
}

func (p *pair) instances(c *Comparison) {
	pairs, gone, appeared := p.join()
	expired := map[string]bool{}
	for _, a := range p.l.Acceptances {
		if a.Outcome == "expired" {
			for _, k := range a.Findings {
				expired[fkey(k.ID, k.Asset, k.Subject)] = true
			}
		}
	}
	for _, j := range pairs {
		c.Instances = append(c.Instances, p.both(j, expired))
	}
	for _, ef := range gone {
		cat, cause, reason := p.goneVerdict(ef)
		i := Instance{Category: cat, Cause: cause, Reason: reason, ID: ef.ID, Title: ef.Title, Area: ef.Area,
			Earlier: p.goneRef(ef)}
		if cat == Fixed && !p.redactionDiffers {
			// The earlier finding's own not-checked lines can name accounts
			// or logins; with different redaction rules they stay home.
			i.NotChecked = ef.NotChecked
		}
		if cat == Fixed {
			if ef.Area == string(finding.AreaSecrets) {
				i.Notes = append(i.Notes, NoteRevocationUnchecked)
			}
		}
		c.Instances = append(c.Instances, i)
	}
	for _, lf := range appeared {
		cat, cause, reason := p.appearVerdict(lf)
		c.Instances = append(c.Instances, Instance{Category: cat, Cause: cause, Reason: reason, ID: lf.ID, Title: lf.Title, Area: lf.Area, Later: ref(lf, false)})
	}
}

// both builds the instance of a finding present in both runs.
func (p *pair) both(j joined, expired map[string]bool) Instance {
	ef, lf := j.e, j.l
	renamed := j.identity == "renamed" || j.identity == "moved_renamed"
	i := Instance{ID: lf.ID, Title: lf.Title, Area: lf.Area, Earlier: ref(ef, p.redactionDiffers && (renamed || !sameSubject(ef.Subject, lf.Subject))), Later: ref(lf, false), Identity: j.identity}
	if p.redactionDiffers && !equalPtr(ef.BoundID, lf.BoundID) {
		// A bound id is read from the target; the earlier one stays home.
		i.Earlier.BoundID = nil
	}
	switch {
	case ef.Status == "open" && lf.Status == "open":
		i.Category = StillOpen
	case ef.Status == "open" && lf.Status == "accepted":
		i.Category = AcceptedSince
	case ef.Status == "accepted" && lf.Status == "open":
		i.Category = Reopened
		i.Cause = CauseAcceptanceEnded
		if expired[fkey(lf.ID, lf.Key.Asset, subjectKey(lf.Subject))] || ef.Acceptance != nil && ef.Acceptance.Expires != nil && p.l.Engagement.Collected.From.Format("2006-01-02") > *ef.Acceptance.Expires {
			i.Cause = CauseAcceptanceExpired
		}
	default:
		i.Category = StillAccepted
	}
	if ef.Severity != lf.Severity || !slices.EqualFunc(ef.Adjustments, lf.Adjustments, sameStep) {
		if s := sevChange(ef, lf); s != nil {
			i.Severity = s
		}
	}
	if ef.Status != lf.Status || ef.Acceptance != nil && lf.Acceptance != nil && (ef.Acceptance.AcceptedBy != lf.Acceptance.AcceptedBy || !equalPtr(ef.Acceptance.Expires, lf.Acceptance.Expires)) {
		a := &AcceptChange{FromStatus: ef.Status, ToStatus: lf.Status}
		switch {
		case lf.Acceptance != nil:
			a.AcceptedBy, a.Reason, a.Expires = lf.Acceptance.AcceptedBy, lf.Acceptance.Reason, lf.Acceptance.Expires
		case ef.Acceptance != nil:
			a.AcceptedBy, a.Reason, a.Expires = ef.Acceptance.AcceptedBy, ef.Acceptance.Reason, ef.Acceptance.Expires
		}
		i.Acceptance = a
	}
	return i
}

func equalPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func sameStep(a, b report.Adjustment) bool { return step(a) == step(b) }

func step(a report.Adjustment) Step {
	if a.Source.File != "" {
		return Step{Rule: a.Rule, By: a.By, Delta: a.Delta, Source: a.Source.File + " " + a.Source.Key, Declared: true}
	}
	return Step{Rule: a.Rule, By: a.By, Delta: a.Delta, Source: a.Source.Observation}
}

// sevChange diffs two chains by step. The comparison never recomputes a
// severity; it names the steps that differ.
func sevChange(ef, lf *report.Finding) *SevChange {
	s := &SevChange{From: ef.Severity, To: lf.Severity, Added: []Step{}, Removed: []Step{}, BaseChanged: ef.SeverityBase != lf.SeverityBase}
	for _, a := range lf.Adjustments {
		if !slices.ContainsFunc(ef.Adjustments, func(b report.Adjustment) bool { return sameStep(a, b) }) {
			s.Added = append(s.Added, step(a))
		}
	}
	for _, a := range ef.Adjustments {
		if !slices.ContainsFunc(lf.Adjustments, func(b report.Adjustment) bool { return sameStep(a, b) }) {
			s.Removed = append(s.Removed, step(a))
		}
	}
	lowered := finding.Severity(lf.Severity).Rank() < finding.Severity(ef.Severity).Rank()
	if lowered {
		decl := func(st Step) bool { return st.Declared }
		s.LoweredByDeclaration = slices.ContainsFunc(s.Added, decl) || slices.ContainsFunc(s.Removed, decl)
	}
	if s.From == s.To && len(s.Added) == 0 && len(s.Removed) == 0 && !s.BaseChanged {
		return nil
	}
	return s
}

func (p *pair) assets(c *Comparison) {
	c.Assets = []AssetChange{}
	for _, id := range sortedKeys(p.eAssets) {
		ea := p.eAssets[id]
		l, ok := p.link[id]
		switch {
		case !ok:
			c.Assets = append(c.Assets, AssetChange{Change: "removed", Asset: p.assetText(id), Name: p.nameText(id, ea.Name), From: ea.Status})
		case l.how == "moved":
			c.Assets = append(c.Assets, AssetChange{Change: "moved", Asset: l.later, Name: p.lAssets[l.later].Name, From: id, To: l.later})
		case l.how == "replaced":
			c.Assets = append(c.Assets, AssetChange{Change: "replaced", Asset: id, Name: ea.Name})
		default:
			la := p.lAssets[l.later]
			if la == nil {
				c.Assets = append(c.Assets, AssetChange{Change: "unlisted", Asset: p.assetText(id), Name: p.nameText(id, ea.Name), From: ea.Status})
				continue
			}
			if la.Status != ea.Status {
				c.Assets = append(c.Assets, AssetChange{Change: "status", Asset: id, Name: la.Name, From: ea.Status, To: la.Status, Reason: la.Reason})
			}
			if principalChanged(ea, la) {
				c.Assets = append(c.Assets, AssetChange{Change: "principal", Asset: id, Name: la.Name, From: p.principalFrom(ea), To: principalLabel(la)})
			}
		}
	}
	for _, id := range sortedKeys(p.lAssets) {
		if _, ok := p.back[id]; !ok {
			c.Assets = append(c.Assets, AssetChange{Change: "added", Asset: id, Name: p.lAssets[id].Name, To: p.lAssets[id].Status})
		}
	}
}

func principalLabel(a *report.Asset) string {
	if a.Principal == nil {
		return ""
	}
	s := a.Principal.Identity
	if a.Principal.Elevation != "" && a.Principal.Elevation != "none" {
		s += " (" + a.Principal.Elevation + ")"
	}
	return s
}

func (p *pair) coverage(c *Comparison) {
	c.Coverage = []CoverageChange{}
	key := func(r report.Row) string { return r.Area + "\x00" + r.Tool }
	em := map[string]report.Row{}
	for _, r := range p.e.Coverage {
		em[key(r)] = r
	}
	for _, r := range p.l.Coverage {
		er, ok := em[key(r)]
		if !ok || er.Mark == r.Mark {
			continue
		}
		c.Coverage = append(c.Coverage, CoverageChange{Area: r.Area, Tool: r.Tool, From: er.Mark, To: r.Mark})
	}
}

func (p *pair) people(c *Comparison) {
	c.PeopleLeft = []PersonChange{}
	type k struct{ handle, provider, asset string }
	kk := func(h string, t report.PersonTenant) k {
		a := ""
		if t.Asset != nil {
			a = *t.Asset
		}
		return k{h, t.Provider, a}
	}
	em := map[k]string{}
	for _, pl := range p.e.PeopleLeft {
		for _, t := range pl.Tenants {
			em[kk(pl.Handle, t)] = t.State
		}
	}
	for _, pl := range p.l.PeopleLeft {
		for _, t := range pl.Tenants {
			from, ok := em[kk(pl.Handle, t)]
			if !ok || from == t.State {
				continue
			}
			c.PeopleLeft = append(c.PeopleLeft, PersonChange{Handle: pl.Handle, Provider: t.Provider, Asset: t.Asset, From: from, To: t.State})
		}
	}
}

// exit decides the comparison's exit code, 0, 1 or 2: 2 when the later run
// did not read everything (its own exit code is 2 or 3), since "is it fixed"
// cannot be answered for what it could not read; else 1 when something
// worse appeared at or above its asset's threshold; else 0. Exit 3 is for
// input that cannot be compared and is the caller's.
func (p *pair) exit(c *Comparison) {
	c.Exit = Exit{Reasons: []string{}}
	threshold := func(asset string) finding.Severity {
		if t, ok := p.l.Exit.Thresholds[asset]; ok {
			return finding.Severity(t.Severity)
		}
		return finding.SevMedium
	}
	for _, f := range p.l.Findings {
		if f.Status == "open" && finding.Severity(f.Severity).AtLeast(threshold(f.Key.Asset)) {
			c.Exit.OpenAtOrAboveThreshold++
		}
	}
	worse := 0
	for _, i := range c.Instances {
		if i.Later == nil || i.Later.Status != "open" {
			continue
		}
		at := finding.Severity(i.Later.Severity).AtLeast(threshold(i.Later.Asset))
		switch i.Category {
		case New, FirstReported, Reopened:
			// A name hidden by a redaction rule cannot be matched; an unknown
			// is not a worsening.
			if at && i.Cause != CauseSubjectUnmatchable && i.Cause != CauseSuperseded {
				worse++
			}
		case StillOpen:
			if at && i.Severity != nil && finding.Severity(i.Severity.To).Rank() > finding.Severity(i.Severity.From).Rank() &&
				!finding.Severity(i.Severity.From).AtLeast(threshold(i.Later.Asset)) {
				worse++
			}
		}
	}
	switch {
	case p.l.Exit.Code == 2 || p.l.Exit.Code == 3:
		c.Exit.Code = 2
		c.Exit.Reasons = append(c.Exit.Reasons, fmt.Sprintf("the later run did not read everything (its own exit code was %d)", p.l.Exit.Code))
		if worse > 0 {
			c.Exit.Reasons = append(c.Exit.Reasons, fmt.Sprintf("%d new, first-reported or open-again findings at or above the threshold", worse))
		}
	case worse > 0:
		c.Exit.Code = 1
		c.Exit.Reasons = append(c.Exit.Reasons, fmt.Sprintf("%d new, first-reported, open-again or raised findings at or above the threshold", worse))
	}
}

// withholdAsset says an asset id only the earlier run holds is not printed:
// the runs hide names with different redaction rules, and an id the
// operator did not write (a repository or a name found under a root) is
// built from what a target returned.
func (p *pair) withholdAsset(id string) bool {
	if !p.redactionDiffers {
		return false
	}
	a := p.eAssets[id]
	return a == nil || !a.Root
}

func (p *pair) assetText(id string) string {
	if p.withholdAsset(id) {
		return "[withheld]"
	}
	return id
}

func (p *pair) nameText(id, name string) string {
	if p.withholdAsset(id) {
		return "[withheld]"
	}
	return name
}

// goneRef is the earlier run's view of an instance only it holds.
func (p *pair) goneRef(f *report.Finding) *Ref {
	r := ref(f, p.redactionDiffers)
	if p.withholdAsset(f.Key.Asset) {
		r.Asset, r.AssetName = "[withheld]", "[withheld]"
	}
	if p.redactionDiffers {
		r.BoundID = nil
	}
	return r
}

// principalFrom is the earlier principal as printed: the identity label is
// built from what the provider returned, so with different redaction rules
// it stays home.
func (p *pair) principalFrom(a *report.Asset) string {
	if p.redactionDiffers {
		return "[withheld]"
	}
	return principalLabel(a)
}
