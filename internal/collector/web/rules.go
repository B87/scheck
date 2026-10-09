package web

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// A rule's verdict on one subject (docs/spec/web-collector.md, "Rules").
const (
	Fired     = "fired"
	Disproved = "disproved"
	Abstained = "abstained"
)

// Subject kinds (docs/spec/web-collector.md, "Subjects").
const (
	SubjectDNSName   = "dns_name"
	SubjectDNSRecord = "dns_record"
)

// Subject is the instance a judgment is about.
type Subject struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Judgment is one rule's verdict on one subject, and what it read.
type Judgment struct {
	ID string `json:"id"`
	// Asset is the most specific asset holding the subject: the name's own
	// id under the root (docs/spec/web-collector.md, "Subjects").
	Asset   string  `json:"asset"`
	Subject Subject `json:"subject"`
	Verdict string  `json:"verdict"`
	// Reason says why a rule abstained, as a coverage reason.
	Reason string `json:"reason,omitempty"`
	// Reads are the gate request ids of the reads it rests on, the Scope
	// stage's lookups among them.
	Reads []string `json:"reads"`
	// Excerpt is what was observed, as read and redacted.
	Excerpt    string   `json:"excerpt,omitempty"`
	NotChecked []string `json:"not_checked,omitempty"`
	Members    []string `json:"members,omitempty"`
}

// Name is a name the Scope stage looked up, as the rules read it, with its
// lookup's request id.
type Name struct {
	Name, Status, Detail, Outcome, Request string
	Chain, Addresses                       []string
	FinalInRoot                            bool
}

// The Scope stage's name statuses the rules read (scope.json; the
// engagement's test binds them to its own).
const (
	StatusResolves     = "resolves"
	StatusDangling     = "dangling"
	StatusGone         = "no_longer_exists"
	StatusNoAddress    = "no_address"
	StatusInsufficient = "insufficient_evidence"
	StatusWildcard     = "matches_wildcard"
	StatusExcluded     = "excluded"
	StatusNotChecked   = "not_checked"
)

// Gap is part of a root's names Scope could not list, which no rule over
// the root may count as read: certificate transparency unavailable, or
// names redaction dropped.
type Gap struct {
	Reason, Detail string
}

// Input is what the rules judge under one domain root: the names Scope
// looked up and what it could not list, whether the resolver answers names
// that do not exist, and what Recon read.
type Input struct {
	Asset, Root string
	Names       []Name
	Wildcard    *Name
	Gaps        []Gap
	// Doubt is why no verdict over the resolver's answers stands, as a
	// coverage reason: it answers names that do not exist, or whether it
	// does is unknown (docs/spec/web-collector.md, "Takeover
	// fingerprints", "Wildcards"). "" when it does not.
	Doubt    string
	Evidence Evidence
}

// Judge applies the collector's rules. Each rule declares what it reads and
// abstains when it is unknown: a lookup that failed, a name Scope did not
// look up, a read that said nothing, a resolver that invents answers. A
// name an exclude covers is judged by none. One subject gets one verdict.
func Judge(in Input) []Judgment {
	j := judging{in: in, byKey: map[string]int{}}
	for _, g := range in.Gaps {
		// Names Scope could not list may hold what a rule looks for.
		for _, id := range []string{finding.IDDNSDanglingExternal, finding.IDDNSPrivateAddress, finding.IDDNSTakeoverCandidate, finding.IDDNSUnclaimedAtProvider} {
			j.add(Judgment{ID: id, Asset: in.Asset, Verdict: Abstained, Reason: g.Reason,
				Subject: Subject{Kind: SubjectDNSName, Key: "*." + in.Root, Label: "names under " + in.Root + " not listed: " + g.Detail}})
		}
	}
	j.wildcard()
	for _, n := range in.Names {
		j.name(n)
	}
	for _, m := range in.Evidence.Mail {
		j.records(m.Domain, "MX", m.MX, m.MXTargets, true)
		j.records(m.Domain, "TXT", m.TXT, m.SPF, m.SPFComplete)
	}
	j.records(in.Root, "NS", in.Evidence.NS, in.Evidence.NSTargets, true)
	return j.out
}

type judging struct {
	in    Input
	out   []Judgment
	byKey map[string]int
}

// add files a judgment, merging one on the same id and subject: a fired
// verdict stands over an abstention, an abstention over a disproof.
func (j *judging) add(x Judgment) {
	if j.in.Doubt != "" {
		x.Verdict, x.Reason = Abstained, j.in.Doubt
	}
	key := x.ID + "\x00" + x.Subject.Key
	i, ok := j.byKey[key]
	if !ok {
		j.byKey[key] = len(j.out)
		j.out = append(j.out, x)
		return
	}
	// Every read stays; the stronger verdict stands.
	reads := j.out[i].Reads
	for _, r := range x.Reads {
		if !slices.Contains(reads, r) {
			reads = append(reads, r)
		}
	}
	reason := j.out[i].Reason
	if reason == "" {
		reason = x.Reason
	}
	rank := map[string]int{Disproved: 0, Abstained: 1, Fired: 2}
	if rank[x.Verdict] > rank[j.out[i].Verdict] {
		j.out[i] = x
	}
	j.out[i].Reads = reads
	j.out[i].Reason = reason
}

// assetOf is the asset a name's subject belongs to: the name's own id
// under the root, the root for the root itself or for a name the
// engagement file cannot name as an asset (one redaction marked, one
// holding an underscore).
func (j *judging) assetOf(name string) string {
	if name == "" || name == j.in.Root || !hostLike.MatchString(name) {
		return j.in.Asset
	}
	return "domain:" + name
}

var hostLike = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]*[a-z][a-z0-9-]*$`)

// unknown is the coverage reason of a name Scope did not look up or whose
// lookup said nothing.
func unknown(n Name) string {
	switch {
	case n.Status == StatusNotChecked && strings.Contains(n.Detail, ":"):
		return gate.ReasonOf(n.Detail)
	case n.Status == StatusNotChecked:
		return "sampled"
	}
	return outcomeReason(n.Outcome)
}

// name applies the name rules. dns.dangling_* through a CNAME fires when
// the chain ends at a name that does not exist or has no address, is
// disproved when it resolves, and abstains when the lookup said nothing
// (with or without a chain: a failed first lookup does not say whether
// there is a CNAME); a name with no CNAME is no record pointing anywhere.
// dns.private_address fires when every address a name publishes is
// private (RFC 1918, unique local, CGNAT or loopback), is disproved by any
// public one, and abstains when the lookup said nothing. A name matching
// the root's wildcard answer is the wildcard's, judged on none of them.
func (j *judging) name(n Name) {
	subject := Subject{Kind: SubjectDNSName, Key: n.Name, Label: n.Name}
	base := Judgment{Asset: j.assetOf(n.Name), Subject: subject, Reads: []string{}}
	if n.Request != "" {
		base.Reads = []string{n.Request}
	}
	abstain := func(id string) {
		x := base
		x.ID, x.Verdict, x.Reason = id, Abstained, unknown(n)
		j.add(x)
	}
	switch n.Status {
	case StatusExcluded, StatusWildcard:
		return
	case StatusNotChecked, StatusInsufficient:
		if provider(n) == nil {
			abstain(finding.IDDNSTakeoverCandidate)
			abstain(finding.IDDNSUnclaimedAtProvider)
		} else {
			j.takeover(n, base)
		}
		abstain(danglingID(n.FinalInRoot))
		abstain(finding.IDDNSPrivateAddress)
		return
	}
	taken := j.takeover(n, base)
	if len(n.Chain) > 0 && !taken {
		x := base
		x.ID = danglingID(n.FinalInRoot)
		x.Excerpt = n.Name + " → " + strings.Join(n.Chain, " → ") + ": " + n.Outcome
		switch n.Status {
		case StatusDangling:
			x.Verdict = Fired
			if !n.FinalInRoot && provider(n) == nil {
				x.NotChecked = []string{"Whether another account could claim this target was not assessed: no verified fingerprint for this provider"}
			}
			if p := provider(n); p != nil && !p.Ownership && n.Outcome == string(gate.OutcomeNoData) {
				x.Excerpt += "; the provider still knows this name but serves no address for it"
			}
		case StatusResolves:
			x.Verdict = Disproved
		}
		if x.Verdict != "" {
			j.add(x)
		}
	}
	if n.Status != StatusResolves {
		return
	}
	if len(n.Addresses) == 0 {
		return
	}
	x := base
	x.ID, x.Verdict, x.Excerpt = finding.IDDNSPrivateAddress, Fired, n.Name+": "+strings.Join(n.Addresses, ", ")
	for _, s := range n.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			x.Verdict, x.Reason, x.Excerpt = Abstained, "unavailable:dns_error", ""
			break
		}
		if !private(a.Unmap()) {
			x.Verdict = Disproved
		}
	}
	j.add(x)
}

// danglingID is the dangling finding for a target inside or outside every
// root.
func danglingID(inRoot bool) string {
	if inRoot {
		return finding.IDDNSDanglingInternal
	}
	return finding.IDDNSDanglingExternal
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func private(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || cgnat.Contains(a)
}

// records applies dns.dangling_* to the names owner's MX, NS or SPF
// include: records point at (docs/spec/web-collector.md, "DNS and
// takeover"): it fires when the target does not exist (an MX or NS target
// with no address too), is disproved when it resolves, and abstains on a
// read that said nothing. A read of the records themselves that said
// nothing, or an SPF tree not read to its end, leaves what they point at
// unknown. An excluded target is judged by none; a redirect= target that
// is gone, or an include that exists with no SPF record, is SPF's own
// error, not a dangling record.
func (j *judging) records(owner, typ string, read RecordRead, targets []TargetRead, complete bool) {
	label := map[string]string{"MX": "MX of ", "NS": "NS of ", "TXT": "SPF includes of "}[typ]
	if read.Insufficient() || !complete {
		reason := readReason(read)
		if !read.Insufficient() {
			reason = "unavailable:spf_incomplete"
		}
		j.add(Judgment{ID: finding.IDDNSDanglingExternal, Asset: j.assetOf(owner), Verdict: Abstained, Reason: reason,
			Reads: nonEmpty(read.RequestID), Subject: Subject{Kind: SubjectDNSRecord, Key: owner + "/" + typ, Label: label + owner}})
	}
	for _, t := range targets {
		if t.Decision == "refused:excluded" || t.Via == "redirect" {
			continue
		}
		src := t.Owner
		if src == "" {
			src = owner
		}
		kind := map[string]string{"MX": "MX", "NS": "NS", "TXT": "SPF include"}[typ]
		x := Judgment{ID: danglingID(t.FinalInRoot), Asset: j.assetOf(owner), Reads: nonEmpty(t.RequestID),
			Subject: Subject{Kind: SubjectDNSRecord, Key: src + "/" + typ + "/" + t.Name, Label: kind + " of " + src + " → " + t.Name}}
		x.Excerpt = x.Subject.Label + ": " + t.Outcome
		switch {
		case t.Insufficient():
			x.Verdict, x.Reason, x.Excerpt = Abstained, readReason(t.RecordRead), ""
		case t.Outcome == string(gate.OutcomeNXDomain), typ != "TXT" && t.Outcome == string(gate.OutcomeNoData):
			x.Verdict = Fired
		default:
			x.Verdict = Disproved
		}
		j.add(x)
	}
}

func nonEmpty(id string) []string {
	if id == "" {
		return []string{}
	}
	return []string{id}
}

// readReason is the coverage reason of a read that said nothing: the
// gate's own for a refusal (docs/spec/scope.md, "Outcomes").
func readReason(r RecordRead) string {
	if r.Decision != gate.DecisionSent {
		return gate.ReasonOf(r.Decision)
	}
	return outcomeReason(r.Outcome)
}

// outcomeReason is the coverage reason of a lookup that said nothing.
func outcomeReason(o string) string {
	switch o {
	case string(gate.OutcomeDeadline), string(gate.OutcomeCanceled):
		return "limit_reached"
	case "":
		return "unavailable:dns_error"
	}
	return "unavailable:dns_" + o
}

// wildcard judges the concrete control answer once, filing its verdicts on
// *.root. Matching CT names remain grouped evidence, never separate findings
// or HTTP reads (docs/spec/web-collector.md, "Wildcards").
func (j *judging) wildcard() {
	if j.in.Wildcard == nil {
		return
	}
	n := *j.in.Wildcard
	if n.Status == StatusExcluded || n.Status == StatusGone || n.Status == StatusNoAddress {
		return
	}
	sub := judging{in: j.in, byKey: map[string]int{}}
	sub.name(n)
	var members []string
	for _, m := range j.in.Names {
		if m.Status == StatusWildcard {
			members = append(members, m.Name)
		}
	}
	slices.Sort(members)
	for _, x := range sub.out {
		x.Asset = j.in.Asset
		x.Subject = Subject{Kind: SubjectDNSName, Key: "*." + j.in.Root, Label: "*." + j.in.Root}
		x.Members = members
		if len(members) > 0 {
			x.Excerpt += "; names with matching DNS answers (their pages were not read): " + strings.Join(members, ", ")
		}
		j.add(x)
	}
}
