package compare

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/report"
)

// pair holds the two reports, indexed once.
type pair struct {
	e, l             *report.Report
	eIn, lIn         Input
	eAssets, lAssets map[string]*report.Asset
	eAssess, lAssess map[string]*report.Assessment
	// link maps an earlier asset id to the later one that is the same
	// asset: the same id, or a host or tenant whose bound id moved.
	link map[string]assetLink
	// back maps a later asset id to the earlier asset it continues.
	back map[string]string

	sameRules, sameFile, vantageSame, redactionDiffers bool
}

type assetLink struct {
	later string
	// how: same | moved | replaced. replaced is the same id answering with a
	// different bound id: a different machine or tenant.
	how string
}

func newPair(earlier, later Input) *pair {
	p := &pair{e: earlier.Report, l: later.Report, eIn: earlier, lIn: later,
		eAssets: map[string]*report.Asset{}, lAssets: map[string]*report.Asset{},
		eAssess: map[string]*report.Assessment{}, lAssess: map[string]*report.Assessment{},
		link: map[string]assetLink{}, back: map[string]string{}}
	for i := range p.e.Assets {
		p.eAssets[p.e.Assets[i].ID] = &p.e.Assets[i]
	}
	for i := range p.l.Assets {
		p.lAssets[p.l.Assets[i].ID] = &p.l.Assets[i]
	}
	for i := range p.e.Assessments {
		a := &p.e.Assessments[i]
		p.eAssess[a.ID+"\x00"+a.Asset] = a
	}
	for i := range p.l.Assessments {
		a := &p.l.Assessments[i]
		p.lAssess[a.ID+"\x00"+a.Asset] = a
	}
	p.sameRules = p.e.ScheckVersion == p.l.ScheckVersion && releaseBuild(p.e.ScheckVersion) && releaseBuild(p.l.ScheckVersion)
	p.sameFile = p.e.Engagement.Source.SHA256 == p.l.Engagement.Source.SHA256
	p.vantageSame = p.e.Run.Vantage == p.l.Run.Vantage
	p.redactionDiffers = p.e.Redaction.Operator.Rules != p.l.Redaction.Operator.Rules
	p.linkAssets()
	return p
}

// mentions says the later (or earlier) run holds anything about an asset
// that is not in its asset list: a name found under a domain root.
func (p *pair) laterHas(id string) bool {
	if p.lAssets[id] != nil {
		return true
	}
	for k := range p.lAssess {
		if strings.HasSuffix(k, "\x00"+id) {
			return true
		}
	}
	for i := range p.l.Findings {
		if p.l.Findings[i].Key.Asset == id {
			return true
		}
	}
	return false
}

func (p *pair) earlierHas(id string) bool {
	if p.eAssets[id] != nil {
		return true
	}
	for k := range p.eAssess {
		if strings.HasSuffix(k, "\x00"+id) {
			return true
		}
	}
	for i := range p.e.Findings {
		if p.e.Findings[i].Key.Asset == id {
			return true
		}
	}
	return false
}

// linkAssets decides which later asset each earlier one continues. Identity
// is the canonical id, and a bound id (a host's machine id, a tenant's
// customer id) that names exactly one asset in each run and the same kind. A
// bound id on two or more assets of a run is a cloned image, not identity.
// An asset name (an alias the operator chose) is never identity.
func (p *pair) linkAssets() {
	boundE := map[string][]string{}
	boundL := map[string][]string{}
	for id, a := range p.eAssets {
		if a.BoundID != nil && *a.BoundID != "" {
			boundE[*a.BoundID] = append(boundE[*a.BoundID], id)
		}
	}
	for id, a := range p.lAssets {
		if a.BoundID != nil && *a.BoundID != "" {
			boundL[*a.BoundID] = append(boundL[*a.BoundID], id)
		}
	}
	ids := make([]string, 0, len(p.eAssets))
	for id := range p.eAssets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		ea := p.eAssets[id]
		if la := p.lAssets[id]; la != nil {
			how := "same"
			if ea.BoundID != nil && la.BoundID != nil && *ea.BoundID != "" && *la.BoundID != "" && *ea.BoundID != *la.BoundID {
				how = "replaced"
			}
			p.link[id] = assetLink{later: id, how: how}
			p.back[id] = id
			continue
		}
		if p.laterHas(id) {
			// No longer listed, but the later run still reads under it.
			p.link[id] = assetLink{later: id, how: "same"}
			p.back[id] = id
			continue
		}
		if ea.BoundID == nil || *ea.BoundID == "" {
			continue
		}
		b := *ea.BoundID
		if len(boundE[b]) != 1 || len(boundL[b]) != 1 {
			continue
		}
		lid := boundL[b][0]
		if p.eAssets[lid] != nil || p.lAssets[lid].Kind != ea.Kind {
			continue
		}
		p.link[id] = assetLink{later: lid, how: "moved"}
		p.back[lid] = id
	}
	// An asset only findings name (found under a root) continues by id.
	for _, f := range p.e.Findings {
		if _, ok := p.link[f.Key.Asset]; !ok && p.eAssets[f.Key.Asset] == nil && p.laterHas(f.Key.Asset) {
			p.link[f.Key.Asset] = assetLink{later: f.Key.Asset, how: "same"}
			p.back[f.Key.Asset] = f.Key.Asset
		}
	}
	for _, f := range p.l.Findings {
		if _, ok := p.back[f.Key.Asset]; !ok && p.lAssets[f.Key.Asset] == nil && p.eAssets[f.Key.Asset] == nil && p.earlierHas(f.Key.Asset) {
			p.link[f.Key.Asset] = assetLink{later: f.Key.Asset, how: "same"}
			p.back[f.Key.Asset] = f.Key.Asset
		}
	}
}

func subjectKey(s *report.Subject) *string {
	if s == nil {
		return nil
	}
	k := s.Key
	return &k
}

// hidden says a subject key carries a redaction marker, which two different
// hidden names of one length share: never a join key.
func hidden(s *report.Subject) bool {
	// Keys built from redacted values are sometimes lowercased.
	return s != nil && strings.Contains(strings.ToLower(s.Key), "[redacted:")
}

type joined struct {
	e, l     *report.Finding
	identity string // "", moved, renamed, moved_renamed
}

// join pairs each earlier finding with its later instance. The exact key
// {id, asset, subject} joins first, on the asset the earlier one continues
// as. A subject renamed (same id, same asset, an equal non-empty provider
// id) joins second, and only when exactly one candidate stands. Nothing else
// joins: the same weakness on two assets without an identity link is two
// findings.
func (p *pair) join() (pairs []joined, unmatchedE, unmatchedL []*report.Finding) {
	usedL := map[int]bool{}
	byKey := map[string]int{}
	for i := range p.l.Findings {
		f := &p.l.Findings[i]
		byKey[fkey(f.ID, f.Key.Asset, subjectKey(f.Subject))] = i
	}
	var rest []int
	for i := range p.e.Findings {
		ef := &p.e.Findings[i]
		la, linked := p.link[ef.Key.Asset]
		if !linked || la.how == "replaced" {
			// A different machine answering at the same address is not the
			// same instance.
			rest = append(rest, i)
			continue
		}
		id := ""
		if la.how == "moved" {
			id = "moved"
		}
		if li, ok := byKey[fkey(ef.ID, la.later, subjectKey(ef.Subject))]; ok && !usedL[li] && !hidden(ef.Subject) && !contradicts(ef.Subject, p.l.Findings[li].Subject) {
			usedL[li] = true
			pairs = append(pairs, joined{e: ef, l: &p.l.Findings[li], identity: id})
			continue
		}
		rest = append(rest, i)
	}
	for _, i := range rest {
		ef := &p.e.Findings[i]
		la, linked := p.link[ef.Key.Asset]
		if linked && la.how != "replaced" && ef.Subject != nil && providerID(ef.Subject) != "" {
			var cand []int
			for li := range p.l.Findings {
				lf := &p.l.Findings[li]
				if usedL[li] || lf.ID != ef.ID || lf.Key.Asset != la.later || lf.Subject == nil {
					continue
				}
				if providerID(lf.Subject) == providerID(ef.Subject) {
					cand = append(cand, li)
				}
			}
			if len(cand) == 1 {
				id := "renamed"
				if la.how == "moved" {
					id = "moved_renamed"
				}
				usedL[cand[0]] = true
				pairs = append(pairs, joined{e: ef, l: &p.l.Findings[cand[0]], identity: id})
				continue
			}
		}
		unmatchedE = append(unmatchedE, ef)
	}
	for li := range p.l.Findings {
		if !usedL[li] {
			unmatchedL = append(unmatchedL, &p.l.Findings[li])
		}
	}
	return pairs, unmatchedE, unmatchedL
}

func fkey(id, asset string, subject *string) string {
	s := "\x01"
	if subject != nil {
		s = *subject
	}
	return id + "\x00" + asset + "\x00" + s
}

// contradicts says two subjects carry different provider ids: the same key
// on two different accounts, so the key does not join them.
func contradicts(a, b *report.Subject) bool {
	return a != nil && b != nil && providerID(a) != "" && providerID(b) != "" && providerID(a) != providerID(b)
}

// sameSubject says two subjects print identically.
func sameSubject(a, b *report.Subject) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Key == b.Key && a.Label == b.Label && a.ProviderID == b.ProviderID
}

// providerID is a subject's provider id, or empty when it is unknown or a
// redaction rule hid it: two ids hidden to one length are not one account.
func providerID(s *report.Subject) string {
	if s == nil || strings.Contains(strings.ToLower(s.ProviderID), "[redacted:") {
		return ""
	}
	return s.ProviderID
}
