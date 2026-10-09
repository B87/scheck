package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// Judgment is a network collector rule's verdict on one subject
// (docs/spec/report.md, "Findings"): fired, disproved or abstained,
// with the gate requests it read.
type Judgment struct {
	Attributes []string
	Listed     []string
	Details    map[string]any
	ID         string
	Context    string
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
		if j.ID == finding.IDWebRestrictedReachable {
			f.Rule.Kind = "multi_fact"
			f.Rule.Reads = append(f.Rule.Reads, "declared:"+j.Context, "declared:--vantage")
			audience, _ := j.Details["audience"].(string)
			f.Evidence = append(f.Evidence, Evidence{Kind: "declared", Source: b.in.Path + " " + j.Context, Excerpt: key + " is reachable only from " + audience}, Evidence{Kind: "declared", Source: "--vantage", Excerpt: b.in.Vantage + " (your declaration; not verified)"})
		}
		if j.Context != "" {
			f.WhyHere = []string{j.Context}
		} else if mattersMost(def.Area) && slices.Contains(b.in.DataMattersMost, owner.ID) {
			sev = raise(sev)
			f.Adjustments = append(f.Adjustments, Adjustment{Rule: "data_matters_most", By: "engagement", Delta: "+1",
				Source: SourceRef{File: b.in.Path, Key: "data.matters_most"}})
			f.WhyHere = []string{"You listed " + owner.Name + " under data.matters_most, so this ranks one step higher."}
		} else {
			// What is configured is not moved by how the asset is used.
			f.WhyHere = []string{"This is the standard rating: it is about how the records are set up, which nothing you declared changes."}
		}
		for _, attr := range j.Attributes {
			if attr == "contradiction" && j.ID == finding.IDWebRestrictedReachable {
				sev = raise(sev)
				f.Adjustments = append(f.Adjustments, Adjustment{Rule: "contradiction", By: "engagement", Delta: "+1", Source: SourceRef{File: b.in.Path, Key: j.Context}})
				f.WhyHere = []string{"You declared this URL restricted, but it answered from a source you declared outside every permitted network. Authentication was not tested."}
			}
			if attr == "password_form" && j.ID == finding.IDWebPlaintextHTTP {
				sev = raise(sev)
				f.Adjustments = append(f.Adjustments, Adjustment{Rule: "attribute:password_form", By: "collector", Delta: "+1", Source: SourceRef{Observation: firstRead(j.Reads), Excerpt: j.Excerpt}})
			}
			if attr == "slack_webhook" && j.ID == finding.IDWebSecretInResponse {
				sev = finding.SevHigh
				f.Adjustments = append(f.Adjustments, Adjustment{Rule: "attribute:slack_webhook", By: "collector", Delta: "-1", Source: SourceRef{Observation: firstRead(j.Reads), Excerpt: j.Excerpt}})
			}
		}
		for _, e := range b.in.Exposures {
			if j.ID == finding.IDWebVersionDisclosed && e.URL == key {
				sev = finding.SevInfo
				f.Adjustments = append(f.Adjustments, Adjustment{Rule: "exposed_on_purpose", By: "engagement", Delta: "-1", Source: SourceRef{File: b.in.Path, Key: e.Source}})
				f.WhyHere = []string{"You declared this URL exposed on purpose: " + e.Reason}
			}
		}
		if len(j.Listed) > 0 {
			f.Affected = &Affected{Count: len(j.Listed), Listed: j.Listed, Cap: len(j.Listed)}
		}
		keys := []string{}
		for k := range j.Details {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			f.Derived = append(f.Derived, Derived{Name: k, Value: j.Details[k]})
		}
		if strings.HasPrefix(j.ID, "web.") || strings.HasPrefix(j.ID, "tls.") {
			if j.Context == "" && len(f.Adjustments) == 0 {
				f.WhyHere = []string{"This is the standard rating for the response or connection observed."}
			}
			if slices.Contains(j.Attributes, "password_form") {
				f.WhyHere = []string{"The HTTP page contains a password input, so it ranks one step higher."}
			}
		}
		f.Severity = string(sev)
		for _, r := range j.Reads {
			observed := at
			vantage := b.in.Vantage
			if meta, ok := b.in.Observations[r]; ok {
				if !meta.CollectedAt.IsZero() {
					observed = meta.CollectedAt
				}
				vantage = meta.Vantage
			}
			f.Evidence = append(f.Evidence, Evidence{Kind: "observed", Asset: owner.ID, Request: r, Observation: r,
				CollectedAt: &observed, Vantage: vantage, Principal: readBy, Excerpt: j.Excerpt})
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

func firstRead(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
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
		if len(j.Details) > 0 {
			ea.Outcomes = append(ea.Outcomes, AssessmentOutcome{Subject: j.Subject, Outcome: j.Verdict, Detail: j.Details})
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
// (docs/spec/report.md, "Acceptances").
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
		complete, seen := true, false
		for _, j := range judged {
			if j.ID == acc.ID {
				seen = true
				if j.Verdict == verdictAbstained || j.Reason != "" {
					complete = false
				}
			}
		}
		for _, a := range b.in.Assets {
			owns := a.ID == acc.AssetID
			for _, j := range a.Judged {
				if j.ID == acc.ID && j.Asset == acc.AssetID {
					owns = true
				}
			}
			if owns {
				if a.Status != statusCollected || a.PopulationIncomplete {
					complete = false
				}
			}
		}
		if !seen || !complete {
			return "rule_not_decided", "the applicable subject population was not completely assessed; scheck cannot tell whether this subject disappeared"
		}
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
	finding.AreaEmail: {
		{"DMARC policy", "published DMARC enforcement and subdomain policy", []string{finding.IDEmailDMARCNotEnforced, finding.IDEmailDMARCPartial, finding.IDEmailDMARCSubdomainsOpen, finding.IDEmailNoMailSpoofable}},
		{"SPF policy", "SPF presence, syntax, static lookup limits and broad authorization", []string{finding.IDEmailSPFMissing, finding.IDEmailSPFInvalid, finding.IDEmailSPFPermitsAnyone}},
		{"SPF senders", "recognized positive SPF includes compared with declared senders", []string{finding.IDEmailSPFUndeclaredSender}},
		{"DKIM selectors", "declared DKIM keys and their strength", []string{finding.IDEmailDKIMMissing, finding.IDEmailDKIMKeyBreakable, finding.IDEmailDKIMKey1024}},
	},
	finding.AreaSecrets: {{"response secrets", "specific secret detector hits in inspected responses", []string{finding.IDWebSecretInResponse}}},
	finding.AreaWeb: {
		{"HTTPS and plain HTTP", "HSTS and plain HTTP responses from the recorded vantage", []string{finding.IDWebHSTSMissing, finding.IDWebPlaintextHTTP, finding.IDWebPlaintextHTTPClients}},
		{"entry response headers", "browser security instruction presence", []string{finding.IDWebSecurityHeaders}},
		{"session cookies", "observed session-like cookie flags", []string{finding.IDWebSessionCookieFlags}},
		{"software versions", "explicit versions in inspected responses", []string{finding.IDWebVersionDisclosed}},
		{"security contact", "the current security.txt contact file", []string{finding.IDWebSecurityTXT}},
	},
	finding.AreaExternal: {
		{"restricted URL reachability", "restricted endpoints answering from a declared outside vantage", []string{finding.IDWebRestrictedReachable}},
		{"dangling records", "records pointing at names that do not exist",
			[]string{finding.IDDNSDanglingExternal, finding.IDDNSDanglingInternal}},
		{"subdomain takeover", "names pointing at providers with verified fingerprints", []string{finding.IDDNSTakeoverCandidate, finding.IDDNSUnclaimedAtProvider}},
		{"private addresses", "public names publishing private addresses", []string{finding.IDDNSPrivateAddress}},
		{"TLS and certificates", "one TLS negotiation and its certificate verification and expiry", []string{finding.IDTLSCertificateInvalid, finding.IDTLSCertificateExpiring, finding.IDTLSLegacyOnly}},
	},
}

// notJudged lists, per area, what the domain collector reads or would read
// that no rule judges in this build.
var notJudged = map[finding.Area][]string{finding.AreaExternal: {"TLS versions and ciphers other than those negotiated, and revocation"}, finding.AreaSecrets: {"loaded scripts and pages beyond entry points"}}

// judgedRow is an area a network collector reads: one sub-item per rule
// family per asset, marked from the judgments (docs/spec/report.md,
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
				if (area == finding.AreaWeb || area == finding.AreaSecrets) || (area == finding.AreaExternal && fam.name == "TLS and certificates") {
					si.Mark = "not_assessed"
					si.Reasons = append(si.Reasons, ReasonDetail{Reason: "unavailable:web_evidence", Detail: "no judgments from web responses were recorded"})
				}
				if area == finding.AreaEmail && !slices.ContainsFunc(a.Judged, func(j Judgment) bool { return strings.HasPrefix(j.ID, "email.") }) {
					si.Mark = "not_assessed"
					si.Reasons = append(si.Reasons, ReasonDetail{Reason: "unavailable:mail_evidence", Detail: "no email judgments were recorded"})
				}
			case undecided == 0:
				si.Mark, si.Judged = "assessed", []string{fam.judges}
			case decided > 0:
				si.Mark, si.Judged = "partial", []string{fam.judges}
			default:
				si.Mark = "not_assessed"
			}
			some = some || si.Mark == "assessed" || si.Mark == "partial"
			for _, r := range si.Reasons {
				detail := ReasonDetail{Reason: r.Reason}
				if area == finding.AreaEmail || area == finding.AreaWeb || area == finding.AreaSecrets {
					detail = r
				}
				row.Reasons = appendReason(row.Reasons, detail)
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

// Shared origins can be read under several roots. Their report identity
// remains {id,asset,subject}, not which collector supplied the evidence
// (docs/spec/report.md, "Findings").
func uniqueFindings(in []Finding) []Finding {
	out := make([]Finding, 0, len(in))
	index := map[string]int{}
	for _, f := range in {
		subject := ""
		if f.Key.Subject != nil {
			subject = *f.Key.Subject
		}
		key := f.ID + "\x00" + f.Key.Asset + "\x00" + subject
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, f)
			continue
		}
		old := out[i]
		if finding.Severity(f.Severity).Rank() > finding.Severity(old.Severity).Rank() {
			out[i] = f
			f = old
		}
		for _, r := range f.Rule.Reads {
			out[i].Rule.Reads = appendUnique(out[i].Rule.Reads, r)
		}
		for _, e := range f.Evidence {
			if !slices.ContainsFunc(out[i].Evidence, func(x Evidence) bool {
				return x.Request == e.Request && x.Observation == e.Observation && x.Excerpt == e.Excerpt
			}) {
				out[i].Evidence = append(out[i].Evidence, e)
			}
		}
	}
	return out
}
func uniqueAssessments(in []Assessment) []Assessment {
	out := make([]Assessment, 0, len(in))
	index := map[string]int{}
	rank := map[string]int{finding.NotAssessed: 0, finding.NotApplicable: 0, finding.NotMatched: 1, finding.Matched: 2}
	for _, a := range in {
		key := a.ID + "\x00" + a.Asset
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, a)
			continue
		}
		old := &out[i]
		old.Complete = old.Complete && a.Complete
		if old.Reason == "" {
			old.Reason = a.Reason
		}
		if rank[a.Status] > rank[old.Status] {
			old.Status = a.Status
		}
		if a.Instances > old.Instances {
			old.Instances = a.Instances
		}
		for _, r := range a.Reads {
			old.Reads = appendUnique(old.Reads, r)
		}
		for _, observation := range a.Observations {
			old.Observations = appendUnique(old.Observations, observation)
		}
		for _, outcome := range a.Outcomes {
			at := slices.IndexFunc(old.Outcomes, func(x AssessmentOutcome) bool {
				return x.Subject.Kind == outcome.Subject.Kind && x.Subject.Key == outcome.Subject.Key
			})
			if at < 0 {
				old.Outcomes = append(old.Outcomes, outcome)
			} else if verdictPriority(outcome.Outcome) > verdictPriority(old.Outcomes[at].Outcome) {
				old.Outcomes[at] = outcome
			}
		}
	}
	return out
}

func verdictPriority(verdict string) int {
	switch verdict {
	case verdictFired:
		return 2
	case verdictAbstained:
		return 1
	default:
		return 0
	}
}
