package report

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

// Judgment is a network collector rule's verdict on one subject
// (docs/spec/report.md, "Findings"): fired, disproved or abstained,
// with the gate requests it read.
type Judgment = finding.Judgment

// The verdicts of a judgment.
const (
	verdictFired     = "fired"
	verdictDisproved = "disproved"
	verdictAbstained = "abstained"
)

// readBy is the principal a network collector's unauthenticated reads ran
// as: DNS and public web pages are read as nobody in particular.
const readBy = "anonymous"

// reported says a judgment is a finding the report shows: fired, and not
// superseded by another finding. The findings, an acceptance's time and its
// outcome all read this one set.
func reported(j Judgment) bool {
	return j.Verdict == verdictFired && j.Details["superseded_by"] == nil
}

// judgedFindings turns an asset's fired judgments into findings, one per
// subject, each under the most specific asset holding it, at the severity
// Analyze graded (docs/spec/engagement.md, "Severity in context").
func (b *builder) judgedFindings(a AssetInput) []Finding {
	var out []Finding
	at := b.in.Started.UTC()
	for _, j := range a.Judged {
		if !reported(j) {
			continue
		}
		if j.Chain == nil {
			// Never drop a fired verdict: one Analyze did not grade is
			// reported at its base.
			j.Chain = &finding.Chain{Base: def0(j.ID), Severity: def0(j.ID)}
		}
		def, _ := finding.Lookup(j.ID)
		key, subject := j.Subject.Key, j.Subject
		owner := b.ownerOf(a, j)
		var sev finding.Severity
		var subjectPtr *Subject
		var keyPtr *string
		if def.Subject != "" {
			subjectPtr = &subject
			keyPtr = &key
		}
		f := Finding{
			Key: Key{ID: j.ID, Asset: owner.ID, Subject: keyPtr}, AssetName: owner.Name, Subject: subjectPtr,
			ID: j.ID, Title: def.Title, Area: string(def.Area), Category: def.Category,
			ExposureFinding: def.Exposure == finding.IsExposure,
			SeverityBase:    string(def.BaseSeverity), Adjustments: []Adjustment{}, Status: finding.StatusOpen,
			Rule:   Rule{Kind: "single_fact", Reads: requestRefs(j.Reads)},
			Impact: def.Impact, NotChecked: append([]string{}, j.NotChecked...),
			Remediation: Remediation{Summary: def.Remediation.Summary, Commands: def.Remediation.Commands, Caveat: def.Remediation.Caveat},
		}
		if j.ID == finding.IDIdentityFormerPersonHasAccess && a.Collector == "workspace" {
			f.Remediation.Summary = finding.RemediationFormerPersonWorkspace
		}
		if def.MultiFact {
			f.Rule.Kind = "multi_fact"
		}
		if slices.Contains([]string{finding.IDGitHubMutableActionWrite, finding.IDGitHubPRTargetUnsafe, finding.IDGitHubDefaultBranchUnprotected, finding.IDGitHubSecretScanningOpen, finding.IDGitHubHistoryCredential}, j.ID) {
			f.Rule.Kind = "multi_fact"
		}
		if j.ID == finding.IDWebRestrictedReachable {
			f.Rule.Kind = "multi_fact"
			declared := firstRead(j.Sources)
			f.Rule.Reads = append(f.Rule.Reads, "declared:"+declared, "declared:--vantage")
			audience, _ := j.Details["audience"].(string)
			f.Evidence = append(f.Evidence, Evidence{Kind: "declared", Source: b.in.Path + " " + declared, Excerpt: key + " is reachable only from " + audience}, Evidence{Kind: "declared", Source: "--vantage", Excerpt: b.in.Vantage + " (your declaration; not verified)"})
		} else if len(j.Sources) > 0 {
			f.Rule.Kind = "multi_fact"
			for _, source := range j.Sources {
				if source != "" {
					f.Rule.Reads = appendUnique(f.Rule.Reads, "declared:"+source)
					f.Evidence = append(f.Evidence, Evidence{Kind: "declared", Source: b.in.Path + " " + source, Excerpt: "Operator declaration at " + source})
				}
			}
		}
		sev = b.renderChain(&f, j)
		if len(j.Listed) > 0 {
			f.Affected = &Affected{Count: len(j.Listed), Listed: j.Listed, Cap: len(j.Listed)}
			for _, n := range j.OfNote {
				f.Affected.OfNote = append(f.Affected.OfNote, OfNote{Key: n.Key, Why: n.Why})
			}
		}
		keys := []string{}
		for k := range j.Details {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			f.Derived = append(f.Derived, Derived{Name: k, Value: j.Details[k]})
		}
		f.Severity = string(sev)
		for _, r := range j.Reads {
			observed := at
			principal := observedPrincipal(a)
			excerpt := j.Excerpt
			if j.ID == finding.IDGitHubHistoryCredential || j.ID == finding.IDGitHubRemoteCredential {
				if r != firstRead(j.Reads) {
					excerpt = "Advertised reference metadata was compared with the local mirror; credential matches came from local blob reads"
				}
				if source, ok := j.Details["repository_read"].(string); ok && r == source {
					excerpt = "Observed repository visibility: public"
				}
			}
			vantage := b.in.Vantage
			if meta, ok := b.in.Observations[r]; ok {
				if !meta.CollectedAt.IsZero() {
					observed = meta.CollectedAt
				}
				vantage = meta.Vantage
				if meta.Principal != "" {
					principal = meta.Principal
				}
			}
			f.Evidence = append(f.Evidence, Evidence{Kind: "observed", Asset: owner.ID, Request: r, Observation: r,
				CollectedAt: &observed, Vantage: vantage, Principal: principal, Excerpt: excerpt})
		}
		// A host fact an engagement rule rests on, as the host's own
		// findings cite theirs.
		if v := b.hosts[owner.ID]; v != nil {
			for _, fr := range j.Facts {
				observed := v.collectedAt(fr.Observation)
				f.Rule.Reads = appendUnique(f.Rule.Reads, "check:"+fr.Check)
				f.Evidence = append(f.Evidence, Evidence{Kind: "observed", Asset: owner.ID, Check: fr.Check, Observation: fr.Observation,
					CollectedAt: &observed, Principal: v.principal(fr.Observation), Excerpt: fr.Excerpt})
			}
		}
		if acc, ok := b.effective(owner.ID, j.ID, key); ok && b.current(acc.Expires, b.acceptanceAt(acc)) {
			at := b.acceptanceAt(acc)
			f.Status = finding.StatusAccepted
			f.Acceptance = &FindingAccept{Entry: acc.Entry, Reason: acc.Reason, AcceptedBy: acc.AcceptedBy, CoversEveryInstance: acc.Subject == "", JudgedAt: &at}
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
			if def.Subject != "" {
				f.AcceptTemplate.Subject, f.AcceptTemplate.BySubject = key, true
			}
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
			if reported(j) && j.ID == id && isDomain && j.Asset != asset &&
				strings.HasSuffix(name, "."+parent) && (subject == "" || j.Subject.Key == subject) {
				// One its own entry accepts is not open.
				if acc, ok := b.effective(j.Asset, id, j.Subject.Key); ok && b.current(acc.Expires, b.acceptanceAt(acc)) {
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
	if after, ok := strings.CutPrefix(j.Asset, "repo:github:"); ok {
		return AssetInput{ID: j.Asset, Name: after, Kind: "repo"}
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

// acceptanceAt is the one collection time an acceptance's expiry is read
// at, for its outcome and every instance it covers alike: the latest of
// the reads its matched instances cite; zero, so undecided and every
// instance open, when any of them cites no read with a recorded time
// (docs/spec/engagement.md, "Severity in context").
func (b *builder) acceptanceAt(acc AcceptanceInput) time.Time {
	if at, ok := b.entryAt[acc.Entry]; ok {
		return at
	}
	var at time.Time
	judged, _ := b.judgedFor(acc.AssetID)
	for _, j := range judged {
		if !reported(j) || j.ID != acc.ID || acc.Subject != "" && j.Subject.Key != acc.Subject {
			continue
		}
		if e, _ := b.effective(acc.AssetID, j.ID, j.Subject.Key); e.Entry != acc.Entry {
			continue
		}
		t := b.readAt(acc.AssetID, j.Reads)
		if t.IsZero() {
			at = time.Time{}
			break
		}
		if t.After(at) {
			at = t
		}
	}
	b.entryAt[acc.Entry] = at
	return at
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
			var subject *Subject
			if j.Subject.Kind != "" {
				v := j.Subject
				subject = &v
			}
			ea.Outcomes = append(ea.Outcomes, AssessmentOutcome{Subject: subject, Outcome: j.Verdict, Detail: j.Details})
		}
		for _, r := range requestRefs(j.Reads) {
			ea.Reads = appendUnique(ea.Reads, r)
		}
		for _, fr := range j.Facts {
			ea.Reads = appendUnique(ea.Reads, "check:"+fr.Check)
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
		if a.Collector == "" && a.Host == nil {
			continue
		}
		read = read || a.ID == asset && (a.Collector != "" || b.hosts[a.ID] != nil)
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
	// supersededBy names the finding that reports an instance in its place:
	// that instance is no finding, so it neither counts, lists nor sets a
	// time (reported).
	supersededBy := ""
	at := b.acceptanceAt(acc)
	for _, j := range judged {
		if j.ID != acc.ID || acc.Subject != "" && j.Subject.Key != acc.Subject {
			continue
		}
		if j.Verdict == verdictFired && !reported(j) {
			supersededBy = fmt.Sprint(j.Details["superseded_by"])
			continue
		}
		switch j.Verdict {
		case verdictFired:
			fired++
			key := j.Subject.Key
			var subject *string
			if finding.SubjectOf(j.ID) != "" {
				subject = &key
			}
			out.Findings = append(out.Findings, Key{ID: j.ID, Asset: acc.AssetID, Subject: subject})
			if e, _ := b.effective(acc.AssetID, j.ID, key); e.Entry == acc.Entry {
				applies++
			}
		case verdictDisproved:
			disproved++
		default:
			abstained++
		}
	}
	if fired == 0 && supersededBy != "" {
		// The problem is there, reported as a worse finding: never "fixed"
		// nor "remove the entry".
		return "rule_not_decided", "what it names is reported as " + supersededBy + " on this run, a worse finding: accept that one if the risk is still accepted"
	}
	if under := b.openUnder(acc.AssetID, acc.ID, acc.Subject); fired == 0 && under != "" {
		return "rule_not_decided", "an instance is open under it, on " + under + ", which is its own asset: accept it there " +
			"(asset: domain:" + under + ")"
	}
	switch {
	case fired > 0 && applies == 0:
		return "not_applied", "a later entry for the same id applies to every instance it names"
	case fired > 0 && at.IsZero():
		return "rule_not_decided", "no collection time was recorded for what the finding rests on, so its expiry cannot be read: " +
			"the finding stays open"
	case fired > 0 && b.expired(acc.Expires, at):
		b.acceptedAt[acc.Entry] = at
		return "expired", "expired " + acc.Expires + ", before collection on " + b.day(at) + "; the finding is open again"
	case fired > 0:
		b.acceptedAt[acc.Entry] = at
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
		if finding.SubjectOf(acc.ID) == "service" {
			return "subject_not_found", "nothing listens on that port on this run: if the service was moved or closed, remove the entry"
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
	finding.AreaSecrets: {
		{"response secrets", "specific secret detector hits in inspected responses", []string{finding.IDWebSecretInResponse}},
		{"exposed files", "version-control metadata and configuration files served by sites probed", []string{finding.IDWebVCSMetadataExposed, finding.IDWebConfigFileExposed}},
	},
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
		{"debug and status pages", "framework debug and status pages served by sites probed", []string{finding.IDWebDebugInterfaceExposed}},
	},
}

// probeFamilies are the sub-items that exist only for an asset whose sites were
// probed or planned for it: a run with probes off carries none.
var probeFamilies = map[string]bool{"exposed files": true, "debug and status pages": true}

// declaredOnly names what only a declared asset of the area's own kind
// brings, for a row a collector's plan read without one.
var declaredOnly = map[finding.Area]string{finding.AreaEmail: "Domain email settings (SPF, DKIM and DMARC)"}

// webLimits lists, per area, what the domain collector reads or would read
// that no rule judges in this build: limits inside its built sub-items.
var webLimits = map[finding.Area][]string{finding.AreaExternal: {"TLS versions and ciphers other than those negotiated, and revocation"}, finding.AreaSecrets: {"loaded scripts and pages beyond entry points"}}

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
		if plan := planOf(a, area); plan != nil && a.Host != nil {
			// A host the multi-fact rules judged, by their plan.
			if b.hosts[a.ID] != nil {
				read++
				row.AssetsCovered = append(row.AssetsCovered, a.ID)
			}
			some = b.planCoverage(&row, a, *plan) || some
			continue
		}
		if a.Collector == "workspace" {
			plan := planOf(a, area)
			// An asset whose plan reads nothing in this area was not read for it.
			if a.InventoryRead && (plan == nil || plan.OnPlan()) {
				read++
				row.AssetsCovered = append(row.AssetsCovered, a.ID)
			}
			if plan != nil && len(a.Judged) > 0 {
				some = b.planCoverage(&row, a, *plan) || some
			} else {
				why := unreadInventory(a, ReasonDetail{Reason: "no_rule", Detail: "Inventory only; no Workspace rule judgments were recorded"})
				row.SubItems = append(row.SubItems, SubItem{Name: "Workspace account controls", Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{why}})
				if a.InventoryRead {
					row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: a.Name + ": Workspace inventory only"})
				} else if a.Reason != "" {
					row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: inventoryCoverageReason(a), Detail: a.Name})
				}
			}
			if a.NetworkPrincipal != nil {
				row.Principals = append(row.Principals, *a.NetworkPrincipal)
			}
			continue
		}
		if a.Collector == "github" {
			if a.InventoryRead {
				read++
				row.AssetsCovered = append(row.AssetsCovered, a.ID)
			}
			some = b.githubCoverage(&row, area, a) || some
			continue
		}
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
			if probeFamilies[fam.name] && !slices.ContainsFunc(a.Judged, func(j Judgment) bool { return slices.Contains(fam.ids, j.ID) }) {
				continue
			}
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
		if nj := webLimits[area]; len(nj) > 0 {
			row.SubItems = append(row.SubItems, SubItem{Name: strings.Join(nj, ", "), Asset: a.ID, Mark: "not_assessed",
				Reasons: []ReasonDetail{{Reason: "no_rule", Detail: "not judged in this version"}}, ReadNotJudged: nj})
		}
	}
	// A row read only through a collector's plan still says what declaring
	// its own kind of asset would add (domains for email).
	if only, ok := declaredOnly[area]; ok && !slices.ContainsFunc(b.in.Assets, func(a AssetInput) bool { return declaredFeeds(area, a) }) {
		row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "not_declared", Detail: only})
	}
	if nj := webLimits[area]; len(nj) > 0 && slices.ContainsFunc(assets, func(a AssetInput) bool { return a.Collector == "web" }) {
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
				if x.Subject == nil || outcome.Subject == nil {
					return x.Subject == nil && outcome.Subject == nil
				}
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

func observedPrincipal(a AssetInput) string {
	if a.NetworkPrincipal != nil {
		return a.NetworkPrincipal.Identity
	}
	return readBy
}

// renderChain writes the chain Analyze gave a judgment as the finding's
// adjustments and why-here, and returns its severity. A step that did not
// move it is not an adjustment; a cap is still said.
func (b *builder) renderChain(f *Finding, j Judgment) finding.Severity {
	var why []string
	add := func(s string) {
		if s != "" && !slices.Contains(why, s) {
			why = append(why, s)
		}
	}
	// The reasons of steps that moved it first (the ranking prints the
	// first), then the collector's, then a cap that still holds: one a
	// later step went past no longer explains the severity.
	moved := false
	for _, m := range j.Chain.Moves {
		if m.Stopped == "" && m.From != m.To {
			moved = true
			add(m.Why)
		}
	}
	add(j.Why)
	if len(why) == 0 && moved {
		// Decided before any cap: a cap is never the reason it moved.
		add("Context moved this rating; see the adjustments.")
	}
	for _, m := range j.Chain.Moves {
		if m.Stopped != "" && j.Chain.Severity.Rank() <= m.To.Rank() {
			add(m.Why)
		}
	}
	for _, m := range j.Chain.Moves {
		if m.Stopped != "" {
			continue
		}
		src := SourceRef{Observation: m.Ref.Observation, Excerpt: m.Ref.Excerpt}
		if m.Ref.Key != "" {
			src = SourceRef{File: b.in.Path, Key: m.Ref.Key}
		}
		f.Adjustments = append(f.Adjustments, Adjustment{Rule: m.Rule, By: m.By, Delta: deltaString(m.To.Rank() - m.From.Rank()), Source: src})
	}
	if len(why) == 0 {
		switch def, _ := finding.Lookup(j.ID); {
		case j.ID == finding.IDEmptyPasswordRemote:
			// docs/spec/engagement.md, R2: no host context step moves it.
			why = []string{"This is the standard rating, whatever the host is used for: anyone who can reach sshd can sign in as these accounts."}
		case def.MultiFact:
			why = []string{"This is the standard rating for what this host's settings show."}
		case strings.HasPrefix(j.ID, "web.") || strings.HasPrefix(j.ID, "tls."):
			why = []string{"This is the standard rating for the response or connection observed."}
		case strings.HasPrefix(j.ID, "github.") || strings.HasPrefix(j.ID, "workspace.") || strings.HasPrefix(j.ID, "identity."):
			why = []string{"This is the standard rating for the observed access or settings."}
		default:
			// What is configured is not moved by how the asset is used.
			why = []string{"This is the standard rating: it is about how the records are set up, which nothing you declared changes."}
		}
	}
	f.WhyHere = why
	return j.Chain.Severity
}

func deltaString(d int) string {
	if d > 0 {
		return fmt.Sprintf("+%d", d)
	}
	return fmt.Sprint(d)
}

// def0 is a finding id's base severity, "" for an unknown id.
func def0(id string) finding.Severity {
	def, _ := finding.Lookup(id)
	return def.BaseSeverity
}
