package compare

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/report"
)

// This file holds the one predicate that decides whether a finding that is
// gone from a run is fixed (or one that appears is new): what a run's rule
// recorded about its own decision, and whether the two runs can be set side
// by side. Everything that says "fixed" or "new" goes through it, so a
// change to what that claim needs is a change here.

// absence is why a run cannot show a finding absent.
type absence struct {
	cause  string
	reason string
}

// decidedAbsent asks whether run r (assess and assets are its indexes) decided
// that an instance of rule id on asset is not there: the asset was
// collected, the rule decided on it, it read its whole population, and the
// instance's own subject was not abstained on. The empty cause says yes.
func decidedAbsent(assess map[string]*report.Assessment, assets map[string]*report.Asset, asset, id string, subject *string) absence {
	a := assets[asset]
	as := assess[id+"\x00"+asset]
	if a == nil && as == nil {
		return absence{cause: CauseAssetNotInRun}
	}
	if a == nil {
		// Read under a name no asset row records: whether it was collected
		// in full is not recorded, so neither fixed nor new can rest on it.
		return absence{cause: CauseAssetNotListed}
	}
	if a.Status != "collected" {
		return absence{cause: CauseAssetNotRead, reason: a.Reason}
	}
	if as == nil {
		return absence{cause: CauseRuleNotAssessed}
	}
	if as.Status != "matched" && as.Status != "not_matched" {
		return absence{cause: CauseRuleUndecided, reason: as.Reason}
	}
	for _, o := range as.Outcomes {
		if o.Outcome == "fired" && (o.Subject == nil && subject == nil || o.Subject != nil && subject != nil && o.Subject.Key == *subject) {
			// The rule fired on this instance and another finding stands for
			// it (superseded): the problem is there.
			return absence{cause: CauseSuperseded}
		}
		if o.Outcome != "abstained" {
			continue
		}
		if o.Subject == nil && subject == nil || o.Subject != nil && subject != nil && o.Subject.Key == *subject {
			return absence{cause: CauseRuleUndecided, reason: as.Reason}
		}
	}
	if as.Status == "matched" && subject == nil {
		// A rule that matched the asset itself and left no finding: a
		// disagreement the comparison does not read as absence.
		return absence{cause: CauseRuleUndecided, reason: as.Reason}
	}
	if !as.Complete {
		return absence{cause: CauseIncomplete, reason: as.Reason}
	}
	return absence{}
}

// notRechecked says an absence cause is one where the run did not look: the
// rule did not decide on the asset at all.
func notRechecked(cause string) bool {
	switch cause {
	case CauseAssetNotInRun, CauseAssetNotListed, CauseAssetNotRead, CauseRuleNotAssessed, CauseRuleUndecided:
		return true
	}
	return false
}

// hasDeclared says a rule's reads include a declaration of the engagement
// file.
func hasDeclared(reads []string) bool {
	return slices.ContainsFunc(reads, func(r string) bool { return strings.HasPrefix(r, "declared:") })
}

// basis says whether a finding's two runs were read on the same footing. The
// empty cause says they were. eAsset and lAsset are the asset in each run;
// reads are the declared inputs of the finding's rule.
func (p *pair) basis(eAsset, lAsset string, reads []string) string {
	if !p.sameRules {
		return CauseRulesChanged
	}
	if p.link[eAsset].how == "replaced" {
		return CauseAssetReplaced
	}
	if !p.sameFile && hasDeclared(reads) {
		return CauseDeclarationChanged
	}
	if principalChanged(p.eAssets[eAsset], p.lAssets[lAsset]) {
		return CausePrincipalChanged
	}
	if !p.vantageSame {
		if a := p.lAssets[lAsset]; a != nil && (a.Kind == "domain" || a.Kind == "url") {
			return CauseVantageChanged
		}
		if strings.HasPrefix(lAsset, "domain:") || strings.HasPrefix(lAsset, "url:") {
			return CauseVantageChanged
		}
	}
	return ""
}

func principalChanged(e, l *report.Asset) bool {
	if e == nil || l == nil {
		// One run records no row for the asset: who it was read as is not
		// known, so the footing is not known to be the same.
		return e != nil && e.Principal != nil || l != nil && l.Principal != nil
	}
	ep, lp := e.Principal, l.Principal
	if ep == nil && lp == nil {
		return false
	}
	if ep == nil || lp == nil {
		return true
	}
	if ep.Identity != lp.Identity || ep.Elevation != lp.Elevation {
		return true
	}
	es, ls := slices.Clone(ep.Scopes), slices.Clone(lp.Scopes)
	slices.Sort(es)
	slices.Sort(ls)
	return !slices.Equal(es, ls)
}

// goneVerdict decides what became of an earlier finding the later run does
// not report. It returns the category and cause; Fixed has no cause.
func (p *pair) goneVerdict(ef *report.Finding) (Category, string, string) {
	l, ok := p.link[ef.Key.Asset]
	if !ok {
		return NotRechecked, CauseAssetNotInRun, ""
	}
	lasset := l.later
	abs := decidedAbsent(p.lAssess, p.lAssets, lasset, ef.ID, subjectKey(ef.Subject))
	if notRechecked(abs.cause) {
		return NotRechecked, abs.cause, abs.reason
	}
	if p.eAssets[ef.Key.Asset] == nil {
		// The earlier run records no asset row: whether it read the asset in
		// full is not recorded, so a gone finding cannot be called fixed.
		return NotRechecked, CauseAssetNotListed, ""
	}
	if holdsFired(p.l, p.lAssess, lasset, ef.ID, true, subjectKey(ef.Subject)) {
		// The later run reports this id here under a name a redaction rule
		// hides: the instance may be the same one, so it is not gone.
		return NotConfirmed, CauseSubjectUnmatchable, ""
	}
	if replacedSubject(p.l, lasset, ef.ID, ef.Subject) {
		return NotConfirmed, CauseSubjectReplaced, ""
	}
	if hidden(ef.Subject) {
		return NotConfirmed, CauseSubjectUnmatchable, ""
	}
	if b := p.basis(ef.Key.Asset, lasset, ef.Rule.Reads); b != "" {
		return NotConfirmed, b, ""
	}
	if abs.cause != "" {
		return NotConfirmed, abs.cause, abs.reason
	}
	return Fixed, "", ""
}

// appearVerdict decides what a later finding with no earlier instance is:
// new when the earlier run read the asset completely and the rule decided it
// absent, otherwise reported for the first time, with the cause.
func (p *pair) appearVerdict(lf *report.Finding) (Category, string, string) {
	easset, ok := p.back[lf.Key.Asset]
	if !ok {
		return FirstReported, CauseAssetNotInRun, ""
	}
	if (hidden(lf.Subject) || p.redactionDiffers) && holdsFired(p.e, p.eAssess, easset, lf.ID, true, subjectKey(lf.Subject)) ||
		hidden(lf.Subject) && p.redactionDiffers && holdsFired(p.e, p.eAssess, easset, lf.ID, false, nil) {
		// The earlier run holds this id here under a name a redaction rule
		// hides, and either this name is hidden or the runs hide names with
		// different rules: it cannot be told new from the same instance.
		return FirstReported, CauseSubjectUnmatchable, ""
	}
	if replacedSubject(p.e, easset, lf.ID, lf.Subject) {
		return FirstReported, CauseSubjectReplaced, ""
	}
	abs := decidedAbsent(p.eAssess, p.eAssets, easset, lf.ID, subjectKey(lf.Subject))
	if abs.cause != "" && notRechecked(abs.cause) {
		// The earlier run did not look.
		return FirstReported, abs.cause, abs.reason
	}
	if b := p.basis(easset, lf.Key.Asset, lf.Rule.Reads); b != "" {
		return FirstReported, b, ""
	}
	if abs.cause != "" {
		return FirstReported, abs.cause, abs.reason
	}
	return New, "", ""
}

// holdsFired says a run reports, or its rule fired on, an instance of rule id
// on asset whose name a redaction rule hides (hiddenOnly), or any instance at
// all. A disproved or abstained outcome is not an instance. visible is a
// subject key the run decided by its visible name: such a name is not the
// hidden one.
func holdsFired(r *report.Report, assess map[string]*report.Assessment, asset, id string, hiddenOnly bool, visible *string) bool {
	if visible != nil && !strings.Contains(strings.ToLower(*visible), "[redacted:") {
		if as := assess[id+"\x00"+asset]; as != nil {
			for _, o := range as.Outcomes {
				if o.Subject != nil && o.Subject.Key == *visible {
					return false
				}
			}
		}
		for i := range r.Findings {
			if f := &r.Findings[i]; f.ID == id && f.Key.Asset == asset && f.Subject != nil && f.Subject.Key == *visible {
				return false
			}
		}
	}
	for i := range r.Findings {
		if f := &r.Findings[i]; f.ID == id && f.Key.Asset == asset && (!hiddenOnly || hidden(f.Subject)) {
			return true
		}
	}
	if as := assess[id+"\x00"+asset]; as != nil {
		for _, o := range as.Outcomes {
			if o.Outcome == "fired" && (!hiddenOnly || hidden(o.Subject)) {
				return true
			}
		}
	}
	return false
}

// replacedSubject says a run reports the same {id, asset, key} under a
// different provider id: a different account now holds the name.
func replacedSubject(r *report.Report, asset, id string, s *report.Subject) bool {
	if s == nil || s.ProviderID == "" {
		return false
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.ID == id && f.Key.Asset == asset && f.Subject != nil && f.Subject.Key == s.Key && contradicts(f.Subject, s) {
			return true
		}
	}
	return false
}
