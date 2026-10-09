// Package web is the collector for domain roots, mail domains and sites
// (docs/spec/web-collector.md): a declared list of reads, which the scope
// gate sends, and the evidence they return. It builds no URL, names no
// request target the engagement did not give it, and holds no credential.
package web

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/policy"
)

// Gate is what the collector asks of the scope gate.
type Gate interface {
	Send(context.Context, gate.Request) gate.Result
	ReadRecords(context.Context, gate.Records) gate.RecordSet
	FollowTarget(context.Context, gate.Follow) gate.RecordSet
}

// OpFront is the collector's one web op (docs/spec/web-collector.md,
// "Reads").
const OpFront = "web.front"

const OpEntry = "web.entry"

// frontMax caps a front page: enough for a provider's "not configured"
// page and the generator meta tag.
const frontMax = 64 << 10

// Ops are the collector's declared requests: the front page of a read name
// over https and http. The https read's handshake is the name's one TLS
// handshake, and its certificate is read from it.
var Ops = []gate.Op{
	{ID: OpFront, Provider: "web", Method: gate.GET, URL: "{scheme}://{host}/",
		Params: []gate.Param{{Name: "scheme", Type: gate.Scheme}, {Name: "host", Type: gate.Host}},
		Level:  gate.Observe, Accept: []string{"text/html", "text/plain", "*/*"}, MaxBytes: frontMax},
	{ID: OpEntry, Provider: "web", Method: gate.GET, URL: "{scheme}://{host}{path}",
		Params: []gate.Param{{Name: "scheme", Type: gate.Scheme}, {Name: "host", Type: gate.Host}, {Name: "path", Type: gate.URLPath}},
		Level:  gate.Observe, Accept: []string{"text/html", "text/plain", "*/*"}, MaxBytes: frontMax},
}

// Domain is one domain root to read.
type Domain struct {
	// Asset is the root's canonical id; Name its name.
	Asset, Name string
	// Mail are the mail domains under the root, the root first.
	Mail []MailDomain
	// Names are the names Scope chose to read under the root.
	Names   []string
	Sites   []SitePlan
	URLOnly bool
	Stage   string
}

// MailDomain is a mail domain and the DKIM selectors declared for it.
type MailDomain struct {
	Name      string
	Selectors []string
}

// Evidence is what the collector read under one domain root, redacted as
// the gate returned it.
type Evidence struct {
	Mail      []MailEvidence `json:"mail,omitempty"`
	NS        RecordRead     `json:"ns"`
	NSTargets []TargetRead   `json:"ns_targets,omitempty"`
	Sites     []Site         `json:"sites,omitempty"`
}

// MailEvidence is what was read for one mail domain, kept to the fields its
// rules read (docs/spec/web-collector.md, "Reads"): at the domain only its
// v=spf1 records, at _dmarc each v=DMARC1 record's policy tags and whether
// it names a report address, at a selector each record's DKIM tags.
type MailEvidence struct {
	Domain string `json:"domain"`
	// TXT is the domain's TXT read, its records only the v=spf1 ones.
	TXT RecordRead `json:"txt"`
	// DMARC is the _dmarc read, its records in DMARCRecords.
	DMARC        RecordRead `json:"dmarc"`
	DMARCRecords []DMARC    `json:"dmarc_records,omitempty"`
	// DMARCMarked counts potentially relevant records a marker made
	// uncertain, including recognized records with a hidden policy tag.
	DMARCMarked int          `json:"dmarc_marked,omitempty"`
	MX          RecordRead   `json:"mx"`
	MXTargets   []TargetRead `json:"mx_targets,omitempty"`
	// SPF is the include tree, in the order read, each read's records only
	// its v=spf1 ones. SPFComplete says nothing in it is unknown: the
	// domain's TXT was read, and either it holds no single SPF record to
	// walk, or every include and redirect within SPF's limit was read.
	SPF         []TargetRead   `json:"spf,omitempty"`
	SPFComplete bool           `json:"spf_complete"`
	DKIM        []SelectorRead `json:"dkim,omitempty"`
}

// DMARC is one record beginning v=DMARC1, as RFC 7489 §6.3 requires of
// a DMARC record (any other record at _dmarc is not one): its policy tags,
// and whether it names an aggregate report address (rua), never the
// address. Malformed says a tag repeats, which makes the record invalid.
type DMARC struct {
	Tags      map[string]string `json:"tags,omitempty"`
	RUA       bool              `json:"rua"`
	Malformed bool              `json:"malformed,omitempty"`
}

// DKIMKey is one record at a selector that is a DKIM key: one with a p=
// tag, and v=DKIM1 first when it has a version (RFC 6376 §3.6.1). Malformed
// says a tag repeats.
type DKIMKey struct {
	Tags      map[string]string `json:"tags,omitempty"`
	Malformed bool              `json:"malformed,omitempty"`
}

// SelectorRead is a declared DKIM selector's read, its records as their
// DKIM tags.
type SelectorRead struct {
	Selector string     `json:"selector"`
	Read     RecordRead `json:"read"`
	Keys     []DKIMKey  `json:"keys,omitempty"`
	// Other counts the records there that are not DKIM keys; Marked those
	// a redaction marked, including recognized keys with hidden tags.
	Other  int `json:"other,omitempty"`
	Marked int `json:"marked,omitempty"`
}

// RecordRead is one DNS read as the gate answered it.
type RecordRead struct {
	Vantage     string        `json:"vantage"`
	CollectedAt time.Time     `json:"collected_at"`
	SPFMarked   bool          `json:"spf_marked,omitempty"`
	RequestID   string        `json:"request_id"`
	Decision    string        `json:"decision"`
	Detail      string        `json:"detail,omitempty"`
	Outcome     string        `json:"outcome,omitempty"`
	Chain       []string      `json:"chain,omitempty"`
	TXT         []string      `json:"txt,omitempty"`
	MX          []gate.MX     `json:"mx,omitempty"`
	NS          []string      `json:"ns,omitempty"`
	Targets     []gate.Target `json:"targets,omitempty"`
	Addrs       []netip.Addr  `json:"addrs,omitempty"`
	FinalInRoot bool          `json:"final_in_root,omitempty"`
}

// Insufficient reports a read that says nothing about its name: not sent,
// or a failure (docs/spec/scope.md, "The resolver").
func (r RecordRead) Insufficient() bool {
	return (r.Decision != gate.DecisionSent && r.Decision != gate.DecisionReused) || (r.Outcome != string(gate.OutcomeRecords) &&
		r.Outcome != string(gate.OutcomeNXDomain) && r.Outcome != string(gate.OutcomeNoData) &&
		r.Outcome != string(gate.OutcomeAddresses))
}

// TargetRead is the lookup of a name an answer pointed at: Owner is the
// name whose record pointed at it.
type TargetRead struct {
	Owner string `json:"owner"`
	From  string `json:"from"`
	Index int    `json:"index"`
	Via   string `json:"via"`
	Name  string `json:"name"`
	RecordRead
}

// Site is what was read of one name: its front page over https, whose
// TLS is the name's certificate, and over http.
type Site struct {
	Name     string `json:"name"`
	HTTPS    Page   `json:"https"`
	HTTP     Page   `json:"http"`
	Declared bool   `json:"declared,omitempty"`
	Pages    []Page `json:"pages,omitempty"`
}

// Page is one web request's result.
type Page struct {
	Vantage       string              `json:"vantage"`
	CollectedAt   time.Time           `json:"collected_at"`
	RobotsCount   *int                `json:"robots_disallow_count,omitempty"`
	BlockedVendor string              `json:"blocked_vendor,omitempty"`
	RedirectOf    string              `json:"redirect_of,omitempty"`
	URL           string              `json:"url,omitempty"`
	FirstParty    bool                `json:"first_party,omitempty"`
	Redactions    []policy.Hit        `json:"redactions,omitempty"`
	RequestID     string              `json:"request_id"`
	Decision      string              `json:"decision"`
	Reason        string              `json:"reason,omitempty"`
	Detail        string              `json:"detail,omitempty"`
	Status        int                 `json:"status,omitempty"`
	Header        map[string][]string `json:"header,omitempty"`
	Body          string              `json:"body,omitempty"`
	Truncated     bool                `json:"truncated,omitempty"`
	TLS           *gate.TLSInfo       `json:"tls,omitempty"`
}

// Collect reads one domain root through the gate.
func Collect(ctx context.Context, g Gate, d Domain) Evidence {
	c := collector{g: g, d: d}
	var ev Evidence
	if d.URLOnly {
		return Enrich(ctx, g, d, ev)
	}
	for _, m := range d.Mail {
		ev.Mail = append(ev.Mail, c.mail(ctx, m))
	}
	ev.NS = c.read(ctx, d.Name, "NS")
	ev.NSTargets = c.followAll(ctx, d.Name, ev.NS)
	ev.Sites = c.sites(ctx)
	return ev
}

type collector struct {
	g Gate
	d Domain
}

func (c collector) read(ctx context.Context, name, typ string) RecordRead {
	return recordRead(c.g.ReadRecords(ctx, gate.Records{Asset: c.d.Asset, Name: name, Type: typ, Stage: c.d.Stage}))
}

func (c collector) follow(ctx context.Context, owner string, from RecordRead, i int) TargetRead {
	t := from.Targets[i]
	r := c.g.FollowTarget(ctx, gate.Follow{Asset: c.d.Asset, Stage: c.d.Stage, From: from.RequestID, Index: i})
	return TargetRead{Owner: owner, From: from.RequestID, Index: i, Via: t.Via, Name: t.Name, RecordRead: recordRead(r)}
}

// followAll looks up every target owner's MX or NS answer pointed at.
func (c collector) followAll(ctx context.Context, owner string, from RecordRead) []TargetRead {
	var out []TargetRead
	for i := range from.Targets {
		out = append(out, c.follow(ctx, owner, from, i))
	}
	return out
}

func (c collector) mail(ctx context.Context, m MailDomain) MailEvidence {
	ev := MailEvidence{Domain: m.Name}
	ev.TXT = c.read(ctx, m.Name, "TXT")
	ev.SPF, ev.SPFComplete = c.spf(ctx, m.Name, ev.TXT)
	ev.TXT.SPFMarked = markedOther(ev.TXT.TXT)
	ev.TXT.TXT = spfOnly(ev.TXT.TXT)
	ev.DMARC = c.read(ctx, "_dmarc."+m.Name, "TXT")
	for _, r := range ev.DMARC.TXT {
		keys, tags, ok := tagList(r, true)
		if len(keys) == 0 || keys[0] != "v" || tags["v"] != "DMARC1" {
			if couldBe(r, "v=dmarc1") {
				ev.DMARCMarked++
			}
			continue
		}
		// Preserve uncertainty before tag reduction can discard a marker
		// in a tag name or fragment (docs/spec/web-collector.md, "Reads").
		if marked(r) {
			ev.DMARCMarked++
			continue
		}
		d := DMARC{Malformed: !ok}
		if ok {
			d.Tags = keep(tags, "v", "p", "sp", "np", "pct", "t", "adkim", "aspf")
			d.RUA = tags["rua"] != ""
		}
		ev.DMARCRecords = append(ev.DMARCRecords, d)
	}
	ev.DMARC.TXT = nil
	ev.MX = c.read(ctx, m.Name, "MX")
	ev.MXTargets = c.followAll(ctx, m.Name, ev.MX)
	for _, sel := range m.Selectors {
		r := SelectorRead{Selector: sel, Read: c.read(ctx, sel+"._domainkey."+m.Name, "TXT")}
		for _, rec := range r.Read.TXT {
			// DKIM tag names are case-sensitive (RFC 6376 §3.2).
			keys, tags, ok := tagList(rec, false)
			_, hasKey := tags["p"]
			_, hasV := tags["v"]
			switch {
			// Any record may hold p=, so any marked one may have been a key.
			case (!hasKey || hasV && (keys[0] != "v" || tags["v"] != "DKIM1")) && marked(rec):
				r.Marked++
				continue
			case !hasKey || hasV && (keys[0] != "v" || tags["v"] != "DKIM1"):
				r.Other++
				continue
			}
			// A part that is not a tag breaks the key's format: a verifier
			// ignores it (RFC 6376 §6.1.2).
			if marked(rec) {
				r.Marked++
				continue
			}
			k := DKIMKey{Malformed: !ok || slices.Contains(keys, "")}
			if ok {
				k.Tags = keep(tags, "v", "k", "p", "t")
			}
			r.Keys = append(r.Keys, k)
		}
		r.Read.TXT = nil
		ev.DKIM = append(ev.DKIM, r)
	}
	return ev
}

// tagList reads a tag=value; list (RFC 7489 §6.4, RFC 6376 §3.2): the tag
// names in order, lowercased when fold is set (DMARC's are
// case-insensitive, DKIM's are not), and their values; ok is false when a
// tag repeats, which makes the list invalid. A part with no = is no tag.
func tagList(record string, fold bool) ([]string, map[string]string, bool) {
	var keys []string
	tags := map[string]string{}
	ok := true
	for i, part := range strings.Split(record, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if k = strings.TrimSpace(k); fold {
			k = strings.ToLower(k)
		}
		if !found || k == "" {
			// A part that is not a tag still has its place, so a record
			// beginning with one does not begin with its version; an
			// empty part after a tag (a trailing ;) is nothing.
			if i == 0 || strings.TrimSpace(part) != "" {
				keys = append(keys, "")
			}
			continue
		}
		if _, dup := tags[k]; dup {
			ok = false
			continue
		}
		keys, tags[k] = append(keys, k), strings.TrimSpace(v)
	}
	return keys, tags, ok
}

// couldBe reports a marked record whose remaining prefix could begin the
// required version. DMARC permits the whitespace tagList trims around its
// first tag; SPF requires its version at byte zero (RFC 7208 §4.5).
func couldBe(record, version string) bool {
	i := strings.Index(record, "[REDACTED:")
	if cut := strings.Index(record, "[TRUNCATED:"); cut >= 0 && (i < 0 || cut < i) {
		i = cut
	}
	if i < 0 {
		return false
	}
	before := record[:i]
	if version == "v=dmarc1" {
		before = strings.TrimSpace(before)
		if k, v, ok := strings.Cut(before, "="); ok {
			before = strings.TrimSpace(k) + "=" + strings.TrimSpace(v)
		}
	}
	return strings.HasPrefix(version, strings.ToLower(before))
}

// keep is tags with only the names given.
func keep(tags map[string]string, names ...string) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if v, ok := tags[n]; ok {
			out[n] = v
		}
	}
	return out
}

func spfOnly(records []string) []string {
	var out []string
	for _, r := range records {
		if isSPF(r) {
			out = append(out, r)
		}
	}
	return out
}

// spf reads the include tree of a domain's one SPF record, depth first in
// the order its terms are written, counting DNS-querying terms across the
// tree and stopping at SPF's limit (docs/spec/web-collector.md, "Reads").
// It is complete only when nothing in it is unknown: a read that failed,
// or an include or redirect the gate could not follow (a macro), leaves it
// incomplete.
func (c collector) spf(ctx context.Context, domain string, txt RecordRead) ([]TargetRead, bool) {
	if txt.Insufficient() {
		return nil, false
	}
	// A record a redaction marked that is not seen as SPF may have been an
	// SPF record the gate saw: how many there are, so the tree, is unknown.
	if markedOther(txt.TXT) {
		return nil, false
	}
	records := spfOnly(txt.TXT)
	if len(records) != 1 {
		return nil, true
	}
	var tree []TargetRead
	count := Lookups(records[0])
	complete := followable(records[0], txt.Targets)
	var walk func(owner string, from RecordRead) bool
	walk = func(owner string, from RecordRead) bool {
		recs := spfOnly(from.TXT)
		if len(recs) != 1 {
			return true
		}
		indexes, known := spfTargets(recs[0], from.Targets)
		complete = complete && known
		for _, i := range indexes {
			if count > MaxLookups {
				return false
			}
			r := c.follow(ctx, owner, from, i)
			r.SPFMarked = markedOther(r.TXT)
			r.TXT = spfOnly(r.TXT)
			tree = append(tree, r)
			if r.Insufficient() {
				return false
			}
			if recs := spfOnly(r.TXT); len(recs) == 1 {
				count += Lookups(recs[0])
				complete = complete && followable(recs[0], r.Targets)
			}
			complete = complete && !r.SPFMarked
			r.TXT = spfOnly(r.TXT)
			tree[len(tree)-1] = r
			if !walk(r.Name, r.RecordRead) {
				return false
			}
		}
		return true
	}
	complete = walk(domain, txt) && complete && count <= MaxLookups
	return tree, complete
}

// markedOther reports a record a redaction marked that is not seen as SPF
// but may have been one.
func markedOther(records []string) bool {
	return slices.ContainsFunc(records, func(r string) bool { return !isSPF(r) && couldBe(r, "v=spf1") })
}

// followable reports whether the gate gave a target for each include and
// redirect term of an SPF record: a macro or a malformed target is none.
func followable(record string, targets []gate.Target) bool {
	_, ok := spfTargets(record, targets)
	return ok
}

func spfTargets(record string, targets []gate.Target) ([]int, bool) {
	p := parseSPF(record)
	if p.invalid {
		return nil, false
	}
	var indexes []int
	complete := !p.unknown
	for _, term := range p.terms {
		if term.name != "include" && term.name != "redirect" {
			continue
		}
		found := false
		for i, t := range targets {
			if !slices.Contains(indexes, i) && t.Via == term.name && strings.EqualFold(strings.TrimSuffix(t.Name, "."), strings.TrimSuffix(term.arg, ".")) {
				indexes = append(indexes, i)
				found = true
				break
			}
		}
		complete = complete && found
	}
	return indexes, complete
}

// MaxLookups is SPF's limit of DNS-querying terms per evaluation (RFC 7208
// §4.6.4).
const MaxLookups = 10

func isSPF(record string) bool {
	// RFC 7208 §4.5: the version begins the record and is followed by
	// ASCII space or the end. Fields would accept a different DNS record.
	const version = "v=spf1"
	return len(record) >= len(version) && strings.EqualFold(record[:len(version)], version) &&
		(len(record) == len(version) || record[len(version)] == ' ')
}

// Lookups counts an SPF record's DNS-querying terms: include, a, mx, ptr,
// exists and redirect (RFC 7208 §4.6.4).
func Lookups(record string) int {
	n := 0
	for _, term := range parseSPF(record).terms {
		switch term.name {
		case "include", "a", "mx", "ptr", "exists", "redirect":
			n++
		}
	}
	return n
}

func (c collector) site(ctx context.Context, name string) Site {
	s := Site{Name: name}
	for _, read := range []struct {
		scheme string
		page   *Page
	}{{"https", &s.HTTPS}, {"http", &s.HTTP}} {
		*read.page = page(c.g.Send(ctx, gate.Request{Op: OpFront, Asset: c.d.Asset, Stage: c.d.Stage,
			Params: map[string]string{"scheme": read.scheme, "host": name}}))
	}
	return s
}

// Cut reports a read the run's deadline refused or ended: what the
// evidence lacks is for want of time.
func (e Evidence) Cut() bool {
	cut := func(d, reason string) bool {
		return d == "refused:deadline" || d == "unavailable:deadline" || reason == "limit_reached"
	}
	for _, r := range e.reads() {
		// A lookup the deadline ended in flight was sent.
		if cut(r.Decision, "") || r.Outcome == string(gate.OutcomeDeadline) {
			return true
		}
	}
	for _, s := range e.Sites {
		for _, p := range allPages(s) {
			if cut(p.Decision, p.Reason) {
				return true
			}
		}
	}
	return false
}

// reads lists every DNS read in the evidence.
func (e Evidence) reads() []RecordRead {
	reads := []RecordRead{e.NS}
	for _, t := range e.NSTargets {
		reads = append(reads, t.RecordRead)
	}
	for _, m := range e.Mail {
		reads = append(reads, m.TXT, m.DMARC, m.MX)
		for _, t := range slices.Concat(m.MXTargets, m.SPF) {
			reads = append(reads, t.RecordRead)
		}
		for _, d := range m.DKIM {
			reads = append(reads, d.Read)
		}
	}
	return reads
}

func recordRead(r gate.RecordSet) RecordRead {
	return RecordRead{Vantage: r.Vantage, CollectedAt: r.CollectedAt, RequestID: r.RequestID, Decision: r.Decision, Detail: r.Detail, Outcome: string(r.Outcome), Chain: r.Chain,
		TXT: r.TXT, MX: r.MX, NS: r.NS, Targets: r.Targets, Addrs: r.Addrs, FinalInRoot: r.FinalInRoot}
}

func page(r gate.Result) Page {
	p := Page{RequestID: r.RequestID, Decision: r.Decision, Reason: r.Reason, Detail: r.Detail}
	if resp := r.Response; resp != nil {
		p.Status, p.Header, p.Truncated, p.TLS = resp.Status, resp.Header, resp.Truncated, resp.TLS
		p.Body = string(resp.Body)
		p.Redactions, p.FirstParty = resp.Redactions, resp.FirstParty
		p.CollectedAt = resp.CollectedAt
		p.Vantage = resp.Vantage
	}
	return p
}
