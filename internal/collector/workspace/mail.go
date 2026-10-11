package workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// IDExternalForwarding is the forwarding rule
// (docs/spec/workspace-collector.md, "Forwarding interpretation").
const IDExternalForwarding = "workspace.external_forwarding"

const (
	reasonSubdomain = "unavailable:forwarding_subdomain"
	mailLimit       = "Checked: automatic forwarding and forwarding filters of each active mailbox, by destination domain. Not checked: whether any message was forwarded, what each filter matches, the Admin console's forwarding setting, routing and compliance rules, mail delegates, POP/IMAP and other mail apps, send-as addresses, where mail forwarded to a group or another address in your domains goes next, and suspended or archived mailboxes"
)

func init() {
	finding.Register(finding.Def{ID: IDExternalForwarding, Title: "A mailbox forwards mail outside your organization", Category: finding.CategoryEmail,
		Area: finding.AreaEmail, Exposure: finding.NotExposure, Subject: "mail_forward", Judges: "Mail forwarding destinations", BaseSeverity: finding.SevMedium,
		Impact:      "Mail this setting matches is copied to an address your organization does not control: invoices, contracts, password-reset links and anything people send to this person. Whoever controls that address can read it without signing in to your Workspace, until the forwarding is removed. Attackers who take over a mailbox often add forwarding so they keep reading it after the password is changed.",
		Remediation: finding.Remediation{Summary: "Ask the person, in person or by phone rather than by email, whether they set this up and still need it. If they did and still need it, note why and accept it for this address; forwarding to any other address stays open. If not, remove it in the person's Gmail: Settings → See all settings → Forwarding and POP/IMAP (forwarding) and Filters and Blocked Addresses (filters). If nobody set it up, treat the account as possibly taken over and contain it before removing anything, so a live session cannot add it back: sign the account out everywhere, reset its password, revoke its app access and check its 2-step verification; then remove the forwarding, and use Email Log Search in the Admin console to see what was forwarded. To stop forwarding outside the organization for everyone, an administrator can allow automatic forwarding to internal addresses only, or turn it off: Admin console → Apps → Google Workspace → Gmail → End User Access → Automatic forwarding. Afterwards, check that existing forwarding stopped; scheck did not test this."}})
}

// FilterForward is one filter that forwards, as Google reports it. Hides
// says it also moves the message to Trash or out of the inbox.
type FilterForward struct {
	ID      string `json:"id,omitempty"`
	Address string `json:"address"`
	Hides   bool   `json:"hides_mail,omitempty"`
}

// MailboxForwarding is one admitted mailbox's two settings reads. A field
// Google left out, or sent in a shape scheck does not recognize, is unknown.
type MailboxForwarding struct {
	ID          string `json:"id"`
	AutoRead    Read   `json:"auto_read"`
	FiltersRead Read   `json:"filters_read"`
	// AutoUsable says the automatic forwarding setting was read;
	// AutoMalformed that a field in it was of a shape scheck does not know.
	AutoUsable    bool   `json:"auto_usable"`
	AutoMalformed bool   `json:"auto_malformed,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
	Address       string `json:"address,omitempty"`
	Disposition   string `json:"disposition,omitempty"`
	// FiltersUsable says the filters were read; FiltersComplete that every
	// one was kept and recognized. Filters lists only those that forward.
	FiltersUsable    bool            `json:"filters_usable"`
	FiltersComplete  bool            `json:"filters_complete"`
	FiltersSeen      int             `json:"filters_seen"`
	FiltersMalformed int             `json:"filters_malformed,omitempty"`
	Filters          []FilterForward `json:"filters"`
}

// MailEvidence is the optional forwarding surface. Complete needs the whole
// users population and every mailbox scheck may read attempted.
type MailEvidence struct {
	Selected bool                `json:"selected"`
	Accounts []MailboxForwarding `json:"accounts,omitempty"`
	Complete bool                `json:"complete"`
}

// refusal is the read that decides the surface's own outcome: the read
// that stopped collection, which the gate says every later one would
// repeat, or, when no settings read was usable at all, the first one
// attempted. It is nil when settings were read and nothing stopped them.
func (m MailEvidence) refusal() *Read {
	var first *Read
	usable := false
	for _, a := range m.Accounts {
		for _, r := range []Read{a.AutoRead, a.FiltersRead} {
			if r.Repeats {
				read := r
				return &read
			}
			usable = usable || readUsable(r)
			if r.Op != "" && !readUsable(r) && first == nil {
				read := r
				first = &read
			}
		}
	}
	if usable {
		return nil
	}
	return first
}

// refusalWording words the surface's own outcome once, for the coverage gap
// and the readout note alike; attempted is how many mailboxes were tried.
func refusalWording(r Read, attempted int) (gap finding.CoverageReason, note string) {
	gap.Reason = r.Reason
	switch {
	case r.Reason == "unavailable:needs_service_account":
		gap.Detail = "Mail forwarding needs a service account with domain-wide delegation; the credential used holds one person's sign-in"
		note = "Mail forwarding was not read: it needs a Google service account with domain-wide delegation, and the credential file this run used (the one GOOGLE_APPLICATION_CREDENTIALS names, or your own gcloud sign-in) holds one person's sign-in, which scheck does not use to read mail settings. To turn the check on, ask whoever manages your Google setup (often your IT provider) to create a service account with domain-wide delegation for gmail.readonly, or leave the check off. Nothing else in this run was affected."
	case strings.HasPrefix(r.Reason, "insufficient_permission") && r.Repeats:
		gap.Detail = "Google has not granted scheck's service account the mail-settings permission (gmail.readonly)"
		note = "The mail forwarding check did not run: Google has not granted scheck's service account the mail-settings permission (gmail.readonly). Nothing is wrong with your mail settings, and nothing else in this run was affected. A super administrator can grant it under Security → Access and data control → API controls → Manage Domain Wide Delegation, by adding https://www.googleapis.com/auth/gmail.readonly to the entry for this service account's client ID. That permission can read every message in every mailbox, so you may prefer a service account used only for this check."
	case strings.HasPrefix(r.Reason, "insufficient_permission"):
		gap.Detail = "Google refused scheck's service account every mailbox it tried"
		note = "Google refused scheck's service account every mailbox it tried, one by one, so no forwarding settings were read. An administrator policy may block the service account for those organizational units: check its app under Security → Access and data control → API controls, and that its entry under Manage Domain Wide Delegation lists gmail.readonly."
	case r.Reason == "unavailable:api_disabled":
		gap.Detail = "The Gmail API is not enabled in the Google Cloud project of scheck's service account"
		note = "The mail forwarding check did not run: the Gmail API is not enabled in the Google Cloud project of scheck's service account, so Google refused every mailbox's settings. Nothing is wrong with your mail settings, and nothing else in this run was affected. Whoever manages that project can enable it under APIs & Services → Library → Gmail API, then run again."
	case r.Reason == "unavailable:credential_exchange" && r.Repeats:
		gap.Detail = "Google did not sign scheck in as one mailbox after another, so scheck stopped asking"
		note = fmt.Sprintf("Google did not sign scheck in as one mailbox after another, so scheck stopped after %s. Google may have been failing for a while: run again later. If it repeats, check that the service account's key is current and that its client ID under Security → Access and data control → API controls → Manage Domain Wide Delegation lists gmail.readonly.", mailboxes(attempted, ""))
	default:
		gap.Detail = "Mail forwarding was not read: " + strings.TrimSuffix(cmpOr(r.Detail, "the read did not give a usable answer"), ".")
	}
	return gap, note
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// mailboxState is whether scheck reads an account's mail settings: only a
// known-active account that has a mailbox (docs/spec/workspace-collector.md,
// "Forwarding interpretation").
type mailboxState int

const (
	mailboxRead mailboxState = iota
	mailboxSuspended
	mailboxArchived
	mailboxNone    // isMailboxSetup:false
	mailboxUnknown // activity unknown or conflicting
)

func mailboxStateOf(v accountView) mailboxState {
	u := v.user
	switch {
	case v.access.Conflict || !active(u) && !inactive(u):
		return mailboxUnknown
	case yes(u.Suspended):
		return mailboxSuspended
	case yes(u.Archived):
		return mailboxArchived
	case no(u.Mailbox):
		return mailboxNone
	}
	return mailboxRead
}

// collectMail reads each readable mailbox's automatic forwarding and its
// filters, in the optional-surface read order, after every other read.
func (e *Evidence) collectMail(ctx context.Context, sender Sender, target Target, view Context, views []accountView) {
	e.Mail.Selected = slices.Contains(e.Binding.Surfaces, gate.WorkspaceGmailForwarding)
	if !e.Mail.Selected {
		return
	}
	eligible := slices.DeleteFunc(slices.Clone(views), func(v accountView) bool { return mailboxStateOf(v) != mailboxRead })
	req := func(op, user string) gate.Request {
		return gate.Request{Op: op, Asset: target.Asset, Stage: target.Stage, Exists: true, Params: map[string]string{"domain": e.Binding.Domain, "user": user}}
	}
	all := readAccounts(eligible, view, func(v accountView) bool {
		u := v.user
		m := MailboxForwarding{ID: u.ID, Filters: []FilterForward{}}
		auto := sender.Send(ctx, req(OpMailAutoForwarding, u.ID))
		m.autoOf(auto)
		if auto.Repeats {
			e.Mail.Accounts = append(e.Mail.Accounts, m)
			return true
		}
		filters := sender.Send(ctx, req(OpMailFilters, u.ID))
		m.filtersOf(filters)
		e.Mail.Accounts = append(e.Mail.Accounts, m)
		return filters.Repeats
	})
	e.Mail.Complete = all && e.Users.Complete
}

func (m *MailboxForwarding) autoOf(r gate.Result) {
	m.AutoRead = readOf(OpMailAutoForwarding, r)
	var body map[string]json.RawMessage
	if !usable(r) || json.Unmarshal(r.Response.Body, &body) != nil || body == nil {
		if usable(r) {
			m.AutoRead.Reason = "insufficient_evidence"
		}
		return
	}
	m.AutoUsable = true
	if v, present := body["enabled"]; present {
		var b bool
		if json.Unmarshal(v, &b) != nil || string(v) == "null" {
			m.AutoMalformed = true
		} else {
			m.Enabled = &b
		}
	}
	if v, present := body["emailAddress"]; present && json.Unmarshal(v, &m.Address) != nil {
		m.AutoMalformed, m.Address = true, ""
	}
	if v, present := body["disposition"]; present && json.Unmarshal(v, &m.Disposition) != nil {
		m.Disposition = ""
	}
}

func (m *MailboxForwarding) filtersOf(r gate.Result) {
	m.FiltersRead = readOf(OpMailFilters, r)
	// The gate hands a list's kept items as one array.
	var items []json.RawMessage
	if !usable(r) || json.Unmarshal(r.Response.Body, &items) != nil || items == nil {
		if usable(r) {
			m.FiltersRead.Reason = "insufficient_evidence"
		}
		return
	}
	m.FiltersUsable = true
	m.FiltersSeen = len(items)
	for _, raw := range items {
		f, forwards, ok := filterOf(raw)
		switch {
		case !ok:
			m.FiltersMalformed++
		case forwards:
			m.Filters = append(m.Filters, f)
		}
	}
	pop := r.Response.Population
	m.FiltersComplete = m.FiltersMalformed == 0 && pop != nil && len(pop.Incomplete) == 0 && !pop.More
}

// filterOf recognizes one projected filter. No action or no forward is a
// filter that does not forward; a forward or an action of another shape, or
// an empty forward, is malformed.
func filterOf(raw json.RawMessage) (FilterForward, bool, bool) {
	var item map[string]json.RawMessage
	if json.Unmarshal(raw, &item) != nil || item == nil {
		return FilterForward{}, false, false
	}
	var f FilterForward
	if v, present := item["id"]; present && json.Unmarshal(v, &f.ID) != nil {
		f.ID = ""
	}
	actionRaw, present := item["action"]
	if !present {
		return f, false, true
	}
	var action map[string]json.RawMessage
	if json.Unmarshal(actionRaw, &action) != nil || action == nil {
		return FilterForward{}, false, false
	}
	forward, present := action["forward"]
	if !present {
		return f, false, true
	}
	if json.Unmarshal(forward, &f.Address) != nil || f.Address == "" {
		return FilterForward{}, false, false
	}
	var add, remove []string
	_ = json.Unmarshal(action["addLabelIds"], &add)
	_ = json.Unmarshal(action["removeLabelIds"], &remove)
	f.Hides = slices.Contains(add, "TRASH") || slices.Contains(remove, "INBOX")
	return f, true, true
}

// destClass is what a destination's domain is to this tenant.
type destClass int

const (
	destInternal  destClass = iota
	destExternal            // outside a complete set of verified domains
	destSubdomain           // under a verified domain, not itself verified
	destUnknown             // the domain set was incomplete
)

var mailLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// mailDomain is the lowercased domain of an address with one @, a nonempty
// local part and a valid DNS name; ok is false for anything else, a
// redacted address included.
func mailDomain(address string) (string, bool) {
	if strings.Contains(address, "[REDACTED:") || strings.Count(address, "@") != 1 {
		return "", false
	}
	local, domain, _ := strings.Cut(address, "@")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	labels := strings.Split(domain, ".")
	if local == "" || strings.ContainsFunc(local, func(r rune) bool { return r <= ' ' || r == 0x7f }) || len(labels) < 2 || len(domain) > 253 {
		return "", false
	}
	for _, l := range labels {
		if !mailLabel.MatchString(l) {
			return "", false
		}
	}
	return domain, true
}

// tenantDomains is the exact set of verified domains and verified domain
// aliases; complete only when both lists were read whole.
func tenantDomains(e Evidence) (map[string]bool, bool) {
	out := map[string]bool{}
	for _, d := range e.Domains.Items {
		if yes(d.Verified) {
			out[strings.TrimSuffix(strings.ToLower(d.Name), ".")] = true
		}
	}
	for _, a := range e.Aliases.Items {
		if yes(a.Verified) {
			out[strings.TrimSuffix(strings.ToLower(a.Name), ".")] = true
		}
	}
	return out, e.Domains.Complete && e.Aliases.Complete
}

// classify places a destination domain by exact comparison: a suffix, a
// subdomain or an engagement root never makes it internal.
func classify(domain string, internal map[string]bool, complete bool) destClass {
	switch {
	case internal[domain]:
		return destInternal
	case !complete:
		return destUnknown
	}
	for d := range internal {
		if strings.HasSuffix(domain, "."+d) {
			return destSubdomain
		}
	}
	return destExternal
}

// mailDest is one destination of one mailbox, by lowercased address, with
// how it is reached.
type mailDest struct {
	address, domain string
	class           destClass
	auto            bool
	// trash says automatic forwarding moves the original to Trash.
	trash   bool
	filters []FilterForward
}

// hides says the forwarding also moves the original out of sight: to Trash
// after automatic forwarding, or by a forwarding filter.
func (d mailDest) hides() bool {
	return d.trash || slices.ContainsFunc(d.filters, func(f FilterForward) bool { return f.Hides })
}

// mailbox is one account's forwarding, decided once for the rule and the
// readout.
type mailbox struct {
	view     accountView
	state    mailboxState
	m        *MailboxForwarding // nil when not attempted
	dests    []mailDest
	gap      bool   // a read failed, was cut or held something unrecognized
	savedOff string // a saved but turned-off address outside, or not placed
	reason   string // why the mailbox's forwarding is unknown
	notRead  string // a plain reason, for the readout
}

// fullyRead says both settings were read whole and recognized.
func (b mailbox) fullyRead() bool { return b.m != nil && !b.gap }

// mailState is the forwarding surface decided once.
type mailState struct {
	selected, complete, domainsComplete bool
	boxes                               []mailbox // readable and unknown-status mailboxes
	counts                              map[mailboxState]int
	read, attempted                     int
	usable                              bool  // some settings read was usable
	tokens                              int   // mailboxes a token was used for
	failure                             *Read // the first unusable read
	refused                             *Read // MailEvidence.refusal
	attemptedAll                        int   // mailboxes tried
}

func mailView(e Evidence, views []accountView) mailState {
	s := mailState{selected: e.Mail.Selected, complete: e.Mail.Complete, counts: map[mailboxState]int{}}
	if !s.selected {
		return s
	}
	internal, complete := tenantDomains(e)
	s.domainsComplete = complete
	s.refused, s.attemptedAll = e.Mail.refusal(), len(e.Mail.Accounts)
	byID := map[string]*MailboxForwarding{}
	for i := range e.Mail.Accounts {
		m := &e.Mail.Accounts[i]
		byID[m.ID] = m
		if m.AutoRead.ActedAs || m.FiltersRead.ActedAs {
			s.tokens++
		}
		for _, r := range []Read{m.AutoRead, m.FiltersRead} {
			s.usable = s.usable || readUsable(r)
			if r.Op != "" && !readUsable(r) && s.failure == nil {
				read := r
				s.failure = &read
			}
		}
	}
	for _, v := range views {
		state := mailboxStateOf(v)
		s.counts[state]++
		if state != mailboxRead && state != mailboxUnknown {
			continue
		}
		b := mailbox{view: v, state: state, m: byID[v.user.ID]}
		switch {
		case state == mailboxUnknown:
			b.reason, b.notRead = "unavailable:workspace_evidence", "status unknown"
		case b.m == nil:
			b.reason, b.notRead = surfaceReason(s.refused), "not attempted"
		default:
			s.attempted++
			b.decide(internal, complete)
			if b.fullyRead() {
				s.read++
			}
		}
		s.boxes = append(s.boxes, b)
	}
	return s
}

// mailboxes counts mailboxes, as "1 active mailbox" or "2 active mailboxes".
func mailboxes(n int, kind string) string {
	if n == 1 {
		return "1 " + kind + "mailbox"
	}
	return fmt.Sprintf("%d %smailboxes", n, kind)
}

// cmpPtr is the first non-nil read.
func cmpPtr(a, b *Read) *Read {
	if a != nil {
		return a
	}
	return b
}

func sent(r Read) bool { return r.Decision == "sent" || r.Decision == "reused" }

// decide sorts one read mailbox's destinations and gaps.
func (b *mailbox) decide(internal map[string]bool, complete bool) {
	m := b.m
	// One destination per lowercased address, auto and filters merged.
	type pending struct {
		address string
		auto    bool
		filter  *FilterForward
	}
	var found []pending
	switch {
	case !m.AutoUsable:
		b.gap, b.reason, b.notRead = true, surfaceReason(&m.AutoRead), unreadWhy(m.AutoRead)
	case m.AutoMalformed || m.Enabled == nil:
		b.gap = true
	case *m.Enabled:
		if _, ok := mailDomain(m.Address); ok {
			found = append(found, pending{address: m.Address, auto: true})
		} else {
			b.gap = true
		}
	default:
		if domain, ok := mailDomain(m.Address); ok {
			if class := classify(domain, internal, complete); class == destExternal || class == destUnknown {
				b.savedOff = strings.ToLower(m.Address)
			}
		}
	}
	switch {
	case !m.FiltersUsable:
		if !b.gap {
			b.reason, b.notRead = surfaceReason(&m.FiltersRead), unreadWhy(m.FiltersRead)
		}
		b.gap = true
	case !m.FiltersComplete:
		b.gap = true
	}
	for i := range m.Filters {
		f := m.Filters[i]
		if _, ok := mailDomain(f.Address); !ok {
			b.gap = true
			continue
		}
		found = append(found, pending{address: f.Address, filter: &f})
	}
	index := map[string]int{}
	for _, p := range found {
		key := strings.ToLower(p.address)
		i, seen := index[key]
		if !seen {
			domain, _ := mailDomain(p.address)
			i = len(b.dests)
			index[key] = i
			b.dests = append(b.dests, mailDest{address: key, domain: domain, class: classify(domain, internal, complete)})
		}
		b.dests[i].auto = b.dests[i].auto || p.auto
		b.dests[i].trash = b.dests[i].trash || p.auto && m.Disposition == "trash"
		if p.filter != nil {
			b.dests[i].filters = append(b.dests[i].filters, *p.filter)
		}
	}
	if b.gap && b.reason == "" {
		b.reason, b.notRead = "unavailable:workspace_evidence", "settings scheck does not recognize"
	}
	slices.SortFunc(b.dests, func(x, y mailDest) int { return strings.Compare(x.address, y.address) })
}

// surfaceReason is why an optional surface's evidence is missing, as the
// gate classified it: a refused optional permission names its scope there.
func surfaceReason(r *Read) string {
	if r == nil || r.Reason == "" || r.Reason == "insufficient_evidence" {
		return "unavailable:workspace_evidence"
	}
	return r.Reason
}

// unreadWhy is an unread account's reason in plain words, for the readout.
func unreadWhy(r Read) string {
	switch {
	case strings.HasPrefix(r.Reason, "insufficient_permission"):
		return "permission denied"
	case r.Reason == "limit_reached":
		return "limit"
	case r.Reason == "unavailable:mailbox_credential":
		return "Google did not sign scheck in as this mailbox"
	case r.Reason == "unavailable:mailbox_unavailable":
		return "Google did not serve this mailbox"
	case r.Reason == "unavailable:api_disabled":
		return "the Gmail API is not enabled"
	case r.Reason == "unavailable:server_error" || strings.HasPrefix(r.Reason, "unavailable:connection") || r.Reason == "unavailable:timeout":
		return "Google did not answer"
	case len(r.Redactions) > 0:
		return "redacted"
	}
	return "unreadable"
}

func forwardSubject(v accountView, to string) finding.Subject {
	s := subject(v.user, v.person)
	s.Kind, s.Key, s.Label = "mail_forward", strings.ToLower(v.user.Primary)+" -> "+to, v.user.Primary+" -> "+to
	if to == "none" {
		// The key stays comparable across runs; the label reads as the mailbox.
		s.Label = v.user.Primary + " (mailbox)"
	}
	return s
}

func mailJudgments(e Evidence, asset string, views []accountView, c Context) []finding.Judgment {
	s := mailView(e, views)
	if !s.selected {
		return nil
	}
	out := []finding.Judgment{}
	base := reads(e.Users.Reads)
	eligible := s.counts[mailboxRead] + s.counts[mailboxUnknown]
	// A surface refused before any settings were read speaks once, for the
	// asset; otherwise each mailbox has its outcome.
	if s.usable {
		for _, b := range s.boxes {
			out = append(out, b.judgments(asset, base, s.domainsComplete, e.Users.Complete, c)...)
		}
	}
	rs := slices.Clone(base)
	for _, m := range e.Mail.Accounts {
		rs = append(rs, reads([]Read{m.AutoRead, m.FiltersRead})...)
	}
	j := newJudgment(IDExternalForwarding, asset, finding.Subject{}, sortedUnique(rs))
	switch {
	case len(views) == 0:
		j.NotChecked = []string{"No current account evidence was available for this rule."}
	case eligible == 0:
		j.Excerpt = "No active account with a mailbox was found."
		j.NotChecked = []string{"No active account with a mailbox was found, so no forwarding settings were read."}
	case s.read == 0:
		why := cmpPtr(s.refused, s.failure)
		j.Reason = surfaceReason(why)
		j.Excerpt = "No mailbox's forwarding settings could be read whole."
		j.NotChecked = []string{"No mailbox's forwarding settings could be read whole" + failureDetail(why)}
	case s.read < eligible || !e.Users.Complete:
		j.Reason = surfaceReason(cmpPtr(s.refused, s.failure))
		j.Excerpt = fmt.Sprintf("Forwarding settings were read for %d of %s.", s.read, mailboxes(eligible, "active "))
		if s.read == eligible {
			j.Excerpt = "Forwarding settings were read for every active mailbox listed, but the account list was incomplete."
		}
		j.NotChecked = []string{"Mailboxes whose settings were not read whole may forward mail outside your organization."}
	default:
		return out
	}
	j.Details = map[string]any{"mailboxes_read": s.read, "mailboxes": eligible, "population_complete": e.Users.Complete && s.complete}
	return append(out, j)
}

// judgments are one mailbox's outcomes: a finding per outside destination,
// an abstention per destination scheck cannot place, and otherwise one
// outcome for the mailbox as a whole.
func (b mailbox) judgments(asset string, base []string, domainsComplete, usersComplete bool, c Context) []finding.Judgment {
	v := b.view
	who := v.user.Primary
	if b.state == mailboxUnknown {
		j := newJudgment(IDExternalForwarding, asset, forwardSubject(v, "none"), base)
		j.Excerpt = "Google did not say clearly whether " + who + " is active, so its mail settings were not read."
		j.NotChecked = []string{j.Excerpt}
		j.Details = b.details(domainsComplete)
		return []finding.Judgment{j}
	}
	if b.m == nil {
		j := newJudgment(IDExternalForwarding, asset, forwardSubject(v, "none"), base)
		j.Reason = b.reason
		j.Excerpt = "Forwarding settings for " + who + " were not read: " + b.notRead + "."
		j.NotChecked = []string{j.Excerpt}
		j.Details = b.details(domainsComplete)
		return []finding.Judgment{j}
	}
	out := []finding.Judgment{}
	decided := false
	for _, d := range b.dests {
		rs := slices.Clone(base)
		if d.auto {
			rs = append(rs, b.m.AutoRead.RequestID)
		}
		if len(d.filters) > 0 {
			rs = append(rs, b.m.FiltersRead.RequestID)
		}
		j := newJudgment(IDExternalForwarding, asset, forwardSubject(v, d.address), sortedUnique(rs))
		switch d.class {
		case destInternal:
			continue
		case destSubdomain:
			j.Details = b.details(domainsComplete)
			j.Details["destination_domain"] = d.domain
			j.Reason = reasonSubdomain
			parent := strings.SplitN(d.domain, ".", 2)[1]
			j.Excerpt = who + " forwards to an address at " + d.domain + ", a subdomain of " + parent + " that is not a domain of this Workspace; scheck cannot tell where that name's mail goes. Ask whoever runs mail for " + d.domain + " where it goes."
			j.NotChecked = []string{j.Excerpt}
		case destUnknown:
			j.Details = b.details(domainsComplete)
			j.Details["destination_domain"] = d.domain
			j.Reason = "unavailable:workspace_inventory"
			j.Excerpt = "This Workspace's list of domains was incomplete, so " + d.domain + " could not be judged."
			j.NotChecked = []string{j.Excerpt}
		case destExternal:
			decided = true
			b.fire(&j, d, domainsComplete, usersComplete, c)
		}
		out = append(out, j)
	}
	if decided || len(out) > 0 {
		return out
	}
	j := newJudgment(IDExternalForwarding, asset, forwardSubject(v, "none"), sortedUnique(append(slices.Clone(base), b.m.AutoRead.RequestID, b.m.FiltersRead.RequestID)))
	if b.gap {
		j.Reason = b.reason
		j.Excerpt = "Forwarding settings for " + who + " were not read whole: " + b.notRead + "."
		j.NotChecked = []string{j.Excerpt}
		j.Details = b.details(domainsComplete)
		return []finding.Judgment{j}
	}
	// An internal destination is placed only against every verified domain.
	if len(b.dests) > 0 && !domainsComplete {
		j.Reason = "unavailable:workspace_inventory"
		j.Excerpt = "This Workspace's list of domains was incomplete, so where " + who + " forwards mail could not be judged."
		j.NotChecked = []string{j.Excerpt}
		j.Details = b.details(domainsComplete)
		return []finding.Judgment{j}
	}
	auto := "off"
	for _, d := range b.dests {
		if d.auto {
			auto = "on to " + d.domain
		}
	}
	decide(&j, true, false, fmt.Sprintf("Google reports automatic forwarding %s and no filter forwarding outside this Workspace's domains for %s (%s read).", auto, who, plural(b.m.FiltersSeen, "filter")))
	j.Details = b.details(domainsComplete)
	if b.savedOff != "" {
		j.Details["saved_external"] = b.savedOff
	}
	return []finding.Judgment{j}
}

// details are what a mailbox outcome records in the JSON report, whatever
// its verdict: the automatic forwarding state, the filters read, whether
// the domain list was whole.
func (b mailbox) details(domainsComplete bool) map[string]any {
	auto := "unknown"
	if m := b.m; m != nil && m.AutoUsable && !m.AutoMalformed && m.Enabled != nil {
		auto = map[bool]string{true: "on", false: "off"}[*m.Enabled]
	}
	out := map[string]any{"auto_forward": auto, "domains_complete": domainsComplete}
	if b.m != nil && b.m.FiltersUsable {
		out["filters_read"] = b.m.FiltersSeen
	}
	return out
}

var dispositions = map[string]string{"trash": "moves the original to Trash", "archive": "archives it", "markRead": "marks it read"}

// fire words one outside destination of one mailbox.
func (b mailbox) fire(j *finding.Judgment, d mailDest, domainsComplete, usersComplete bool, c Context) {
	who := b.view.user.Primary
	parts := []string{}
	mechanisms := []string{}
	if d.auto {
		mechanisms = append(mechanisms, "auto")
		text := who + " forwards all incoming mail except spam to " + d.address + " (automatic forwarding is on"
		if what := dispositions[b.m.Disposition]; what != "" {
			text += "; after forwarding, Gmail " + what
		}
		if d.trash {
			text += ", a pattern used to hide forwarded mail from the person"
		}
		parts = append(parts, text+").")
	}
	if n := len(d.filters); n > 0 {
		mechanisms = append(mechanisms, "filter")
		noun, match := "filter that forwards", "it matches"
		if n > 1 {
			noun, match = "filters that forward", "they match"
		}
		text := fmt.Sprintf("%s has %d %s matching mail to %s; scheck did not read what %s", who, n, noun, d.address, match)
		if hiding := slices.ContainsFunc(d.filters, func(f FilterForward) bool { return f.Hides }); hiding && n == 1 {
			text += "; it also moves the message to Trash or out of the inbox, a pattern used to hide forwarded mail from the person, though some tools are set up this way"
		} else if hiding {
			text += "; one also moves the message to Trash or out of the inbox, a pattern used to hide forwarded mail from the person, though some tools are set up this way"
		}
		parts = append(parts, text+".")
	}
	if slices.Contains(c.DeclaredDomains, d.domain) {
		parts = append(parts, d.domain+" is declared in this engagement but is not a domain of this Workspace.")
	} else {
		parts = append(parts, d.domain+" is not a domain of this Workspace.")
	}
	if p := b.view.person; p != nil && leftPassed(p.Left, c) {
		parts = append(parts, who+" belongs to "+p.Handle+", declared as having left on "+p.Left+".")
	}
	parts = append(parts, "scheck read the setting, not whether any message was forwarded.")
	decide(j, true, true, strings.Join(parts, " "))
	auto := "off"
	if d.auto {
		auto = "on"
	}
	j.Details = map[string]any{"mechanisms": strings.Join(mechanisms, ","), "filters_forwarding": len(d.filters),
		"auto_forward": auto, "destination_domain": d.domain, "domains_complete": domainsComplete, "population_complete": usersComplete, "hides_mail": d.hides()}
	if b.m.FiltersUsable {
		j.Details["filters_read"] = b.m.FiltersSeen
	}
	if d.auto && b.m.Disposition != "" {
		j.Details["disposition"] = b.m.Disposition
	}
	ids := []string{}
	for _, f := range d.filters {
		if f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) > 0 {
		j.Details["filter_ids"] = strings.Join(ids, ",")
	}
	if b.view.admin && !yes(b.view.user.IsAdmin) {
		j.Details["delegated_admin"] = true
	}
	// A known-active super administrator's mailbox receives what is sent to
	// administrators (docs/spec/workspace-collector.md, "Forwarding
	// interpretation").
	if yes(b.view.user.IsAdmin) && !b.view.access.Conflict {
		j.Attributes = []string{"admin"}
		j.Details["admin_mailbox_read"] = firstRead(j.Reads, b.m)
		j.Context = who + " is a super administrator: mail sent to administrators, such as security alerts and password-reset links from other services, goes to this mailbox."
	}
	j.NotChecked = []string{"Whether any message was forwarded, and what each filter matches, were not checked."}
}

func firstRead(rs []string, m *MailboxForwarding) string {
	for _, id := range []string{m.AutoRead.RequestID, m.FiltersRead.RequestID} {
		if slices.Contains(rs, id) {
			return id
		}
	}
	return ""
}

// mailNotes is the readout for the forwarding surface, from the same view as
// the rule.
func mailNotes(e Evidence, asset string, views []accountView) []Note {
	out := []Note{}
	note := func(kind, text string) { out = append(out, Note{Kind: kind, Source: asset, Detail: text}) }
	if e.Binding.CustomerID == "" {
		return out
	}
	s := mailView(e, views)
	if !s.selected {
		note("workspace_inventory", "Mail forwarding was not checked. It finds mailboxes that send copies of mail to outside addresses, a common way an attacker keeps reading someone's mail after the password is changed. It needs a Google service account with domain-wide delegation for gmail.readonly, which can read every message; most small companies do not have one, and whoever manages your Google setup (often your IT provider) would create it. scheck signs in as each active mailbox and reads only its forwarding settings and filters, never a message. Get approval from whoever must approve access to staff mailboxes (often the owner) before turning it on, then run with that service account's key file and SCHECK_WORKSPACE_PROFILE="+e.Binding.offer(gate.WorkspaceGmailForwarding, "directory_mail")+".")
		return out
	}
	if s.refused != nil {
		if _, text := refusalWording(*s.refused, s.attemptedAll); text != "" {
			note("workspace_inventory", text)
		}
	}
	if s.tokens > 0 {
		note("workspace_credential_warning", fmt.Sprintf("No message was opened or read. To read forwarding settings, scheck asked Google to sign it in as each of %s with Google's gmail.readonly permission and sent only the declared reads of forwarding settings and filters. That permission could read every message in those mailboxes, and Google's logs may show scheck's service account acting as each of those people. The permission stays on the service account until an administrator removes it: if you will not run this check again, a super administrator can remove https://www.googleapis.com/auth/gmail.readonly from the service account's entry under Security → Access and data control → API controls → Manage Domain Wide Delegation, and delete the key file if it was created for this check.", mailboxes(s.tokens, "")))
	}
	eligible := s.counts[mailboxRead] + s.counts[mailboxUnknown]
	qualifier := ""
	if !e.Users.Complete {
		qualifier = "at least "
	}
	unread, saved, subdomains := []string{}, []string{}, []string{}
	for _, b := range s.boxes {
		if b.m == nil || b.gap {
			entry := b.view.user.Primary + " (" + b.notRead + ")"
			if yes(b.view.user.IsAdmin) {
				entry = b.view.user.Primary + " (super administrator, " + b.notRead + ")"
			}
			unread = append(unread, entry)
		}
		if b.savedOff != "" {
			saved = append(saved, b.view.user.Primary+" has forwarding to "+b.savedOff+" saved but turned off; one switch turns it back on.")
		}
		for _, d := range b.dests {
			if d.class == destSubdomain {
				subdomains = append(subdomains, b.view.user.Primary+" → "+d.address)
			}
		}
	}
	text := fmt.Sprintf("Mail forwarding settings were read whole for %d of %s%s", s.read, qualifier, mailboxes(eligible, "active "))
	if len(unread) > 0 {
		text += "; not read whole: " + capped(unread) + ". Check those mailboxes' forwarding and filters by hand in each person's Gmail settings"
	}
	text += "."
	notAttempted := []string{}
	for _, c := range []struct {
		state mailboxState
		what  string
	}{{mailboxSuspended, "suspended"}, {mailboxArchived, "archived"}, {mailboxNone, "without a mailbox"}} {
		if n := s.counts[c.state]; n > 0 {
			notAttempted = append(notAttempted, fmt.Sprintf("%d %s", n, c.what))
		}
	}
	if len(notAttempted) > 0 {
		text += " Not attempted, because not active or without a mailbox: " + strings.Join(notAttempted, ", ") + "."
	}
	if !e.Users.Complete {
		text += " The account list itself was incomplete."
	}
	note("workspace_inventory", text+" "+mailLimit+". To see what was actually forwarded, use Email Log Search in the Admin console.")
	for _, text := range saved {
		note("workspace_inventory", text+" Remove it if it is not needed.")
	}
	if len(subdomains) > 0 {
		note("workspace_inventory", "Forwarding to subdomains of your domains that are not themselves domains of this Workspace was not judged: "+capped(subdomains)+". scheck cannot tell where those names' mail goes; ask whoever runs mail for those names where it goes.")
	}
	return out
}
