package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// Judgment is a network collector rule's verdict on one subject
// (docs/spec/engagement.md, "Findings"): fired, disproved or abstained,
// with the gate requests it read.
type Judgment struct {
	ID string
	// Asset is the most specific asset holding the subject, "" for the
	// asset the collector read.
	Asset   string
	Subject Subject
	Verdict string
	// Reason is why it abstained, as a coverage reason.
	Reason     string
	Reads      []string
	NotChecked []string
	Excerpt    string
}

// The verdicts of a judgment.
const (
	verdictFired     = "fired"
	verdictDisproved = "disproved"
	verdictAbstained = "abstained"
)

// readBy is the principal a network collector's unauthenticated reads ran
// as: DNS and public web pages are read as nobody in particular.
const readBy = "anonymous"

// judgedFindings turns an asset's fired judgments into findings, one per
// subject, each under the most specific asset holding it. A collector's
// configuration findings carry no context adjustment but the engagement's
// own for the data that matters most (docs/spec/engagement.md, "Severity
// in context").
func (b *builder) judgedFindings(a AssetInput) []Finding {
	var out []Finding
	at := b.in.Started.UTC()
	for _, j := range a.Judged {
		if j.Verdict != verdictFired {
			continue
		}
		def, _ := finding.Lookup(j.ID)
		key, subject := j.Subject.Key, j.Subject
		owner := b.ownerOf(a, j)
		sev := def.BaseSeverity
		f := Finding{
			Key: Key{ID: j.ID, Asset: owner.ID, Subject: &key}, AssetName: owner.Name, Subject: &subject,
			ID: j.ID, Title: def.Title, Area: string(def.Area), Category: def.Category,
			ExposureFinding: def.Exposure == finding.IsExposure,
			SeverityBase:    string(def.BaseSeverity), Adjustments: []Adjustment{}, Status: finding.StatusOpen,
			Rule:   Rule{Kind: "single_fact", Reads: requestRefs(j.Reads)},
			Impact: def.Impact, NotChecked: append([]string{}, j.NotChecked...),
			Remediation: Remediation{Summary: def.Remediation.Summary, Commands: def.Remediation.Commands, Caveat: def.Remediation.Caveat},
		}
		if mattersMost(def.Area) && slices.Contains(b.in.DataMattersMost, owner.ID) {
			sev = raise(sev)
			f.Adjustments = append(f.Adjustments, Adjustment{Rule: "data_matters_most", By: "engagement", Delta: "+1",
				Source: SourceRef{File: b.in.Path, Key: "data.matters_most"}})
			f.WhyHere = []string{"You listed " + owner.Name + " under data.matters_most, so this ranks one step higher."}
		} else {
			// What is configured is not moved by how the asset is used.
			f.WhyHere = []string{"This is the standard rating: it is about how the records are set up, which nothing you declared changes."}
		}
		f.Severity = string(sev)
		for _, r := range j.Reads {
			f.Evidence = append(f.Evidence, Evidence{Kind: "observed", Asset: owner.ID, Request: r, Observation: r,
				CollectedAt: &at, Principal: readBy, Excerpt: j.Excerpt})
		}
		if acc, ok := b.effective(owner.ID, j.ID, key); ok && !b.expired(acc.Expires, owner.ID) {
			f.Status = finding.StatusAccepted
			f.Acceptance = &FindingAccept{Entry: acc.Entry, Reason: acc.Reason, AcceptedBy: acc.AcceptedBy, CoversEveryInstance: acc.Subject == ""}
			if acc.Expires != "" {
				e := acc.Expires
				f.Acceptance.Expires = &e
			}
		} else {
			// A name the file does not declare is written as its id, the
			// one form validation takes for it.
			ref := owner
			if !b.declared(owner.ID) {
				ref.Name = owner.ID
			}
			f.AcceptTemplate = b.template(ref, j.ID, sev)
			f.AcceptTemplate.Subject, f.AcceptTemplate.BySubject = key, true
		}
		out = append(out, f)
	}
	return out
}

// declared reports an asset the engagement file names.
func (b *builder) declared(id string) bool {
	return slices.ContainsFunc(b.in.Assets, func(a AssetInput) bool { return a.ID == id })
}

// openUnder is the name of an asset under domain asset id holding a fired
// instance of finding id (with subject, when one is given), "" when none:
// an acceptance on id covers its own instances only, but must not say the
// problem is gone while one under it is open.
func (b *builder) openUnder(asset, id, subject string) string {
	parent, ok := strings.CutPrefix(asset, "domain:")
	if !ok {
		return ""
	}
	for _, a := range b.in.Assets {
		for _, j := range a.Judged {
			name, isDomain := strings.CutPrefix(j.Asset, "domain:")
			if j.Verdict == verdictFired && j.ID == id && isDomain && j.Asset != asset &&
				strings.HasSuffix(name, "."+parent) && (subject == "" || j.Subject.Key == subject) {
				// One its own entry accepts is not open.
				if acc, ok := b.effective(j.Asset, id, j.Subject.Key); ok && !b.expired(acc.Expires, j.Asset) {
					continue
				}
				return name
			}
		}
	}
	return ""
}

// heldUnder is the name of an asset under domain asset id whose judgments
// of finding id include subject, "" when none.
func (b *builder) heldUnder(asset, id, subject string) string {
	parent, ok := strings.CutPrefix(asset, "domain:")
	if !ok || subject == "" {
		return ""
	}
	for _, a := range b.in.Assets {
		for _, j := range a.Judged {
			name, isDomain := strings.CutPrefix(j.Asset, "domain:")
			if j.ID == id && j.Subject.Key == subject && isDomain && j.Asset != asset && strings.HasSuffix(name, "."+parent) {
				return name
			}
		}
	}
	return ""
}

// mattersMost says data.matters_most moves findings of the area
// (docs/spec/engagement.md, "Severity in context").
func mattersMost(area finding.Area) bool {
	return area == finding.AreaIdentity || area == finding.AreaSecrets || area == finding.AreaData || area == finding.AreaExternal
}

// raise is one step higher, critical staying critical.
func raise(s finding.Severity) finding.Severity {
	order := []finding.Severity{finding.SevInfo, finding.SevLow, finding.SevMedium, finding.SevHigh, finding.SevCritical}
	if i := slices.Index(order, s); i >= 0 && i < len(order)-1 {
		return order[i+1]
	}
	return s
}

// ownerOf is the asset a judgment's subject belongs to: the declared asset
// with that id, else the name's own id, named by the name, else the asset
// the collector read.
func (b *builder) ownerOf(a AssetInput, j Judgment) AssetInput {
	if j.Asset == "" || j.Asset == a.ID {
		return a
	}
	for _, x := range b.in.Assets {
		if x.ID == j.Asset {
			return x
		}
	}
	return AssetInput{ID: j.Asset, Name: strings.TrimPrefix(j.Asset, "domain:"), Kind: "domain"}
}

func requestRefs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = appendUnique(out, "request:"+id)
	}
	return out
}

// effective is the acceptance that applies to one instance: the last entry
// for its asset and id that names its subject or none.
func (b *builder) effective(asset, id, subject string) (AcceptanceInput, bool) {
	var out AcceptanceInput
	found := false
	for _, acc := range b.in.Acceptances {
		if acc.AssetID == asset && acc.ID == id && (acc.Subject == "" || acc.Subject == subject) {
			out, found = acc, true
		}
	}
	return out, found
}

// judgedAssessments is one assessment per finding id per asset holding its
// subjects: matched when an instance fired, not matched when every subject
// was disproved, not assessed when none decided; complete when none
// abstained.
func judgedAssessments(a AssetInput) []Assessment {
	var out []Assessment
	byKey := map[string]*Assessment{}
	var keys []string
	for _, j := range a.Judged {
		asset := j.Asset
		if asset == "" {
			asset = a.ID
		}
		k := asset + "\x00" + j.ID
		ea := byKey[k]
		if ea == nil {
			ea = &Assessment{ID: j.ID, Asset: asset, Status: finding.NotAssessed, Complete: true, Reads: []string{}}
			byKey[k] = ea
			keys = append(keys, k)
		}
		for _, r := range requestRefs(j.Reads) {
			ea.Reads = appendUnique(ea.Reads, r)
		}
		if j.Reason != "" {
			ea.Complete = false
			if ea.Reason == "" {
				ea.Reason = j.Reason
			}
		}
		switch j.Verdict {
		case verdictFired:
			ea.Status = finding.Matched
			ea.Instances++
		case verdictDisproved:
			if ea.Status != finding.Matched {
				ea.Status = finding.NotMatched
			}
		default:
			ea.Complete = false
			if ea.Reason == "" {
				ea.Reason = j.Reason
			}
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out
}

// judgedFor are the judgments on an asset, from whichever collector read it,
// and whether a collector read it at all: a declared domain under a root
// the collector read was read with it.
func (b *builder) judgedFor(asset string) ([]Judgment, bool) {
	var out []Judgment
	read := false
	for _, a := range b.in.Assets {
		if a.Collector == "" {
			continue
		}
		read = read || a.ID == asset
		for _, j := range a.Judged {
			owner := j.Asset
			if owner == "" {
				owner = a.ID
			}
			if owner == asset {
				out, read = append(out, j), true
			}
		}
	}
	for _, a := range b.in.Assets {
		if a.ID == asset && a.Kind == "domain" && a.Status == statusCollected {
			read = true
		}
		// A name under a root the collector read was looked up with it,
		// declared or not.
		if root, ok := strings.CutPrefix(a.ID, "domain:"); ok && a.Collector != "" {
			if name, isDomain := strings.CutPrefix(asset, "domain:"); isDomain && strings.HasSuffix(name, "."+root) {
				read = true
			}
		}
	}
	return out, read
}

// judgedOutcome settles an acceptance on an asset a network collector
// judged: by subject when it names one, else over every instance of its id
// (docs/spec/engagement.md, "Acceptances").
func (b *builder) judgedOutcome(acc AcceptanceInput, out *Acceptance, judged []Judgment) (string, string) {
	if strings.HasPrefix(acc.ID, "custom:") {
		return "rule_not_decided", "no rule decides a custom finding"
	}
	var fired, disproved, abstained, applies int
	for _, j := range judged {
		if j.ID != acc.ID || acc.Subject != "" && j.Subject.Key != acc.Subject {
			continue
		}
		switch j.Verdict {
		case verdictFired:
			fired++
			key := j.Subject.Key
			out.Findings = append(out.Findings, Key{ID: j.ID, Asset: acc.AssetID, Subject: &key})
			if e, _ := b.effective(acc.AssetID, j.ID, key); e.Entry == acc.Entry {
				applies++
			}
		case verdictDisproved:
			disproved++
		default:
			abstained++
		}
	}
	if under := b.openUnder(acc.AssetID, acc.ID, acc.Subject); fired == 0 && under != "" {
		return "rule_not_decided", "an instance is open under it, on " + under + ", which is its own asset: accept it there " +
			"(asset: domain:" + under + ")"
	}
	switch {
	case fired > 0 && applies == 0:
		return "not_applied", "a later entry for the same id applies to every instance it names"
	case fired > 0 && b.expired(acc.Expires, acc.AssetID):
		return "expired", "expired " + acc.Expires + "; the finding is open again"
	case fired > 0:
		return "applied", ""
	case acc.Subject != "" && disproved+abstained == 0:
		if under := b.heldUnder(acc.AssetID, acc.ID, acc.Subject); under != "" {
			return "subject_not_found", "that subject was read on " + under + ", which is its own asset (asset: domain:" + under + ")"
		}
		return "subject_not_found", "nothing with that subject points anywhere on this run: if the record was removed, remove the entry"
	case abstained == 0 && disproved > 0:
		return "not_matched", "its rule found no instance in everything it read: likely fixed. Confirm, then remove the entry"
	}
	return "rule_not_decided", "its rule could not decide this time: the acceptance still stands, and scheck does not know " +
		"whether the problem is still there"
}

// judgedFamilies are the sub-items of an area a network collector judges,
// each a family of finding ids, with what it judges.
var judgedFamilies = map[finding.Area][]struct {
	name, judges string
	ids          []string
}{
	finding.AreaExternal: {
		{"dangling records", "records pointing at names that do not exist",
			[]string{finding.IDDNSDanglingExternal, finding.IDDNSDanglingInternal}},
		{"subdomain takeover", "names pointing at providers with verified fingerprints", []string{finding.IDDNSTakeoverCandidate, finding.IDDNSUnclaimedAtProvider}},
		{"private addresses", "public names publishing private addresses", []string{finding.IDDNSPrivateAddress}},
	},
}

// notJudged lists, per area, what the domain collector reads or would read
// that no rule judges in this build.
var notJudged = map[finding.Area][]string{
	finding.AreaExternal: {"TLS and certificates"},
	finding.AreaEmail:    {"SPF, DMARC and DKIM records"},
}

// judgedRow is an area a network collector reads: one sub-item per rule
// family per asset, marked from the judgments (docs/spec/engagement.md,
// "Coverage"), and what was read that no rule judges yet.
func (b *builder) judgedRow(area finding.Area, assets []AssetInput) Row {
	row := Row{Area: string(area), Reasons: []ReasonDetail{}}
	var fed, read int
	some := false
	for _, a := range b.in.Assets {
		if !feeds(area, a) {
			continue
		}
		fed++
		if a.ReadWith != "" && slices.ContainsFunc(assets, func(x AssetInput) bool { return x.ID == a.ReadWith }) {
			// Its names were judged under its root's sub-items.
			read++
			row.AssetsCovered = append(row.AssetsCovered, a.ID)
			continue
		}
		if !slices.ContainsFunc(assets, func(x AssetInput) bool { return x.ID == a.ID }) {
			reason := a.Reason
			if reason == "" {
				reason = "collector_not_built"
			}
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: reason, Detail: a.Name})
			continue
		}
		read++
		row.AssetsCovered = append(row.AssetsCovered, a.ID)
		if a.Status == statusIncomplete {
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "limit_reached", Detail: a.Name})
		}
		for _, fam := range judgedFamilies[area] {
			si := SubItem{Name: fam.name, Asset: a.ID, Reasons: []ReasonDetail{}, Rules: fam.ids}
			var decided, undecided int
			for _, j := range a.Judged {
				if !slices.Contains(fam.ids, j.ID) {
					continue
				}
				if j.Verdict == verdictAbstained || j.Reason != "" {
					undecided++
					si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: j.Reason, Detail: j.Subject.Label})
				}
				if j.Verdict != verdictAbstained {
					decided++
				}
			}
			switch {
			case decided == 0 && undecided == 0:
				// Everything was read and nothing of this kind exists.
				si.Mark = "not_applicable"
			case undecided == 0:
				si.Mark, si.Judged = "assessed", []string{fam.judges}
			case decided > 0:
				si.Mark, si.Judged = "partial", []string{fam.judges}
			default:
				si.Mark = "not_assessed"
			}
			some = some || si.Mark == "assessed" || si.Mark == "partial"
			for _, r := range si.Reasons {
				row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: r.Reason})
			}
			row.SubItems = append(row.SubItems, si)
		}
		if area == finding.AreaExternal && len(a.Unfingerprinted) > 0 {
			detail := fmt.Sprintf("%d not checked for takeover: no fingerprint for this provider", len(a.Unfingerprinted))
			row.SubItems = append(row.SubItems, SubItem{Name: "Services your names point at", Asset: a.ID, Mark: "not_assessed",
				Reasons: []ReasonDetail{{Reason: "no_rule", Detail: detail}}, ReadNotJudged: a.Unfingerprinted})
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: detail})
		}
		if nj := notJudged[area]; len(nj) > 0 {
			row.SubItems = append(row.SubItems, SubItem{Name: strings.Join(nj, ", "), Asset: a.ID, Mark: "not_assessed",
				Reasons: []ReasonDetail{{Reason: "no_rule", Detail: "not judged in this version"}}, ReadNotJudged: nj})
		}
	}
	if nj := notJudged[area]; len(nj) > 0 && read > 0 {
		row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: strings.Join(nj, ", ")})
	}
	assessed := read == fed
	for _, si := range row.SubItems {
		assessed = assessed && (si.Mark == "assessed" || si.Mark == "not_applicable")
	}
	switch {
	case assessed && len(row.SubItems) > 0:
		row.Mark = "assessed"
	case some:
		row.Mark = "partial"
	default:
		row.Mark = "not_assessed"
	}
	row.Population = &Population{Kind: "assets", InScope: fed, Read: read}
	return row
}
