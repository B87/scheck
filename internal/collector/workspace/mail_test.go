package workspace

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

// readMailbox is a mailbox whose two settings reads succeeded: automatic
// forwarding explicitly off and no filter.
func readMailbox(id string) MailboxForwarding {
	return MailboxForwarding{ID: id, AutoRead: Read{Op: OpMailAutoForwarding, RequestID: "a-" + id, Decision: "sent", Status: 200, ActedAs: true},
		FiltersRead: Read{Op: OpMailFilters, RequestID: "f-" + id, Decision: "sent", Status: 200, Population: &gate.Population{Page: 1}},
		AutoUsable:  true, Enabled: new(false), FiltersUsable: true, FiltersComplete: true, Filters: []FilterForward{}}
}

// mailFixture is a complete population of active non-administrators, every
// mailbox read clean, in a tenant with one verified domain and one verified
// alias.
func mailFixture(users ...User) (Evidence, Context) {
	e, c := stepFixture(users...)
	e.Binding = Binding{CustomerID: "C123", Domain: "example.com", Profile: "directory_mail", Surfaces: []gate.WorkspaceSurface{gate.WorkspaceGmailForwarding}}
	e.OAuth = OAuthEvidence{}
	e.Domains = Population[Domain]{Complete: true, Items: []Domain{{Name: "example.com", Verified: new(true)}, {Name: "unverified.example", Verified: new(false)}}}
	e.Aliases = Population[Alias]{Complete: true, Items: []Alias{{Name: "example.org", Parent: "example.com", Verified: new(true)}}}
	e.Mail = MailEvidence{Selected: true, Complete: true}
	for _, u := range users {
		e.Mail.Accounts = append(e.Mail.Accounts, readMailbox(u.ID))
	}
	return e, c
}

func mailUser(id string) User { return stepUser(id, "/Sales", new(true), new(true)) }

func forwarding(e Evidence, c Context) []finding.Judgment {
	out := []finding.Judgment{}
	for _, j := range Judge(e, "asset", c) {
		if j.ID == IDExternalForwarding {
			out = append(out, j)
		}
	}
	return out
}

func outcome(t *testing.T, e Evidence, c Context, key string) finding.Judgment {
	t.Helper()
	for _, j := range forwarding(e, c) {
		if j.Subject.Key == key {
			return j
		}
	}
	t.Fatalf("no outcome for %q in %+v", key, forwarding(e, c))
	return finding.Judgment{}
}

func TestForwardingFiresPerDestinationAndMergesMechanisms(t *testing.T) {
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	m := &e.Mail.Accounts[0]
	m.Enabled, m.Address, m.Disposition = new(true), "Amy.Personal@Gmail.com", "trash"
	m.Filters = []FilterForward{{ID: "f1", Address: "amy.personal@gmail.com", Hides: true}, {ID: "f2", Address: "books@accounting.example.net"}, {ID: "f3", Address: "team@example.org"}}
	m.FiltersSeen = 4
	out := forwarding(e, c)
	keys := []string{}
	for _, j := range out {
		keys = append(keys, j.Subject.Key+"="+j.Verdict)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"amy@example.com -> amy.personal@gmail.com=fired", "amy@example.com -> books@accounting.example.net=fired", "bob@example.com -> none=disproved"}) {
		t.Fatal(keys)
	}
	j := outcome(t, e, c, "amy@example.com -> amy.personal@gmail.com")
	for _, want := range []string{"forwards all incoming mail except spam to amy.personal@gmail.com (automatic forwarding is on; after forwarding, Gmail moves the original to Trash, a pattern used to hide forwarded mail", "has 1 filter that forwards matching mail to amy.personal@gmail.com", "a pattern used to hide forwarded mail", "gmail.com is not a domain of this Workspace.", "not whether any message was forwarded"} {
		if !strings.Contains(j.Excerpt, want) {
			t.Fatalf("excerpt lacks %q: %s", want, j.Excerpt)
		}
	}
	if j.Subject.Kind != "mail_forward" || j.Subject.ProviderID != "amy" || j.Details["mechanisms"] != "auto,filter" || j.Details["hides_mail"] != true || j.Details["filter_ids"] != "f1" || j.Details["disposition"] != "trash" || len(j.Attributes) != 0 {
		t.Fatalf("%+v", j)
	}
	if !slices.Contains(j.Reads, "a-amy") || !slices.Contains(j.Reads, "f-amy") {
		t.Fatal(j.Reads)
	}
	if b := outcome(t, e, c, "bob@example.com -> none"); !strings.Contains(b.Excerpt, "automatic forwarding off and no filter forwarding outside") {
		t.Fatal(b.Excerpt)
	}
}

func TestForwardingDomainsAreExact(t *testing.T) {
	for _, tc := range []struct{ address, verdict, reason string }{
		{"a@example.com", Disproved, ""},
		{"a@EXAMPLE.org", Disproved, ""},
		{"a@mail.example.com", Abstained, reasonSubdomain},
		{"a@example.com.evil.net", Fired, ""},
		{"a@notexample.com", Fired, ""},
		{"a@unverified.example", Fired, ""},
	} {
		t.Run(tc.address, func(t *testing.T) {
			e, c := mailFixture(mailUser("amy"))
			e.Mail.Accounts[0].Enabled, e.Mail.Accounts[0].Address = new(true), tc.address
			key := "amy@example.com -> " + strings.ToLower(tc.address)
			if tc.verdict == Disproved {
				key = "amy@example.com -> none"
			}
			j := outcome(t, e, c, key)
			if j.Verdict != tc.verdict || j.Reason != tc.reason {
				t.Fatalf("%+v", j)
			}
		})
	}
	// An engagement root never makes a destination internal; it is named.
	e, c := mailFixture(mailUser("amy"))
	c.DeclaredDomains = []string{"acquired.example"}
	e.Mail.Accounts[0].Filters = []FilterForward{{Address: "amy@acquired.example"}}
	if j := outcome(t, e, c, "amy@example.com -> amy@acquired.example"); j.Verdict != Fired || !strings.Contains(j.Excerpt, "acquired.example is declared in this engagement but is not a domain of this Workspace") {
		t.Fatalf("%+v", j)
	}
	// An incomplete domain list places only a known domain.
	e, c = mailFixture(mailUser("amy"), mailUser("bob"))
	e.Domains.Complete = false
	e.Mail.Accounts[0].Filters = []FilterForward{{Address: "x@gmail.com"}}
	e.Mail.Accounts[1].Filters = []FilterForward{{Address: "x@example.com"}}
	if j := outcome(t, e, c, "amy@example.com -> x@gmail.com"); j.Verdict != Abstained || j.Reason != "unavailable:workspace_inventory" || !strings.Contains(j.Excerpt, "list of domains was incomplete") {
		t.Fatalf("%+v", j)
	}
	if j := outcome(t, e, c, "bob@example.com -> none"); j.Verdict != Abstained {
		t.Fatal("a mailbox was disproved over an incomplete domain list", j)
	}
}

// A filters HTTP 204 is the empty list. Forwarding explicitly off is then
// disproved. A 204 that is not that list, and a refused 204, are not.
func TestFilter204WithForwardingOffIsDisproved(t *testing.T) {
	e, c := mailFixture(mailUser("amy"))
	m := &e.Mail.Accounts[0]
	m.filtersOf(gate.Result{RequestID: "f-amy", Decision: "sent", ActedAsMailbox: true, Response: &gate.Response{Status: 204, Body: []byte("[]"), Population: &gate.Population{Page: 1}}})
	if !m.FiltersUsable || !m.FiltersComplete || m.FiltersSeen != 0 || m.FiltersRead.Status != 204 {
		t.Fatal(m.FiltersUsable, m.FiltersComplete, m.FiltersSeen, m.FiltersRead)
	}
	if j := outcome(t, e, c, "amy@example.com -> none"); j.Verdict != Disproved {
		t.Fatal(j)
	}
	bad := MailboxForwarding{}
	bad.filtersOf(gate.Result{RequestID: "f-bad", Decision: "sent", Response: &gate.Response{Status: 204, Body: []byte(`{"enabled":false}`), Population: &gate.Population{Page: 1}}})
	if bad.FiltersUsable || bad.FiltersRead.Reason != "insufficient_evidence" {
		t.Fatal(bad.FiltersUsable, bad.FiltersRead.Reason)
	}
	refused := MailboxForwarding{}
	refused.filtersOf(gate.Result{Decision: "unavailable:malformed_response", Reason: "unavailable:malformed_response", Response: &gate.Response{Status: 204}})
	if refused.FiltersUsable || refused.FiltersRead.Reason != "unavailable:malformed_response" {
		t.Fatal(refused.FiltersUsable, refused.FiltersRead.Reason)
	}
	// The 204 still counts as a read when the automatic-forwarding read does not.
	e, c = mailFixture(mailUser("amy"))
	m = &e.Mail.Accounts[0]
	m.AutoRead.Redactions = []policy.Hit{{Rule: "email", Bytes: 3}}
	m.filtersOf(gate.Result{RequestID: "f-amy", Decision: "sent", ActedAsMailbox: true, Response: &gate.Response{Status: 204, Body: []byte("[]"), Population: &gate.Population{Page: 1}}})
	if j := outcome(t, e, c, "amy@example.com -> none"); j.Verdict != Disproved {
		t.Fatal(j)
	}
}

func TestForwardingDisabledUnknownAndMalformed(t *testing.T) {
	// Saved but turned off never fires; the readout names it.
	e, c := mailFixture(mailUser("amy"))
	e.Mail.Accounts[0].Address = "old@gmail.com"
	if j := outcome(t, e, c, "amy@example.com -> none"); j.Verdict != Disproved {
		t.Fatalf("%+v", j)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "amy@example.com has forwarding to old@gmail.com saved but turned off")
	}) {
		t.Fatal("saved address note missing")
	}
	for name, change := range map[string]func(*MailboxForwarding){
		"enabled absent":    func(m *MailboxForwarding) { m.Enabled = nil },
		"enabled malformed": func(m *MailboxForwarding) { m.Enabled, m.AutoMalformed = nil, true },
		"redacted address":  func(m *MailboxForwarding) { m.Enabled, m.Address = new(true), "[REDACTED:secret:12 bytes]" },
		"address no domain": func(m *MailboxForwarding) { m.Enabled, m.Address = new(true), "someone" },
		"filters malformed": func(m *MailboxForwarding) { m.FiltersMalformed, m.FiltersComplete = 1, false },
		"filters over cap": func(m *MailboxForwarding) {
			m.FiltersUsable, m.FiltersComplete, m.FiltersRead.Reason = false, false, "limit_reached"
		},
		"filters unread": func(m *MailboxForwarding) {
			m.FiltersUsable, m.FiltersComplete, m.FiltersRead.Status = false, false, 403
		},
		"auto unread": func(m *MailboxForwarding) {
			m.AutoUsable, m.Enabled, m.AutoRead.Reason = false, nil, "unavailable:mailbox_credential"
		},
		"filter dest broken": func(m *MailboxForwarding) { m.Filters = []FilterForward{{Address: "a@@b"}} },
	} {
		t.Run(name, func(t *testing.T) {
			e, c := mailFixture(mailUser("amy"))
			change(&e.Mail.Accounts[0])
			if j := outcome(t, e, c, "amy@example.com -> none"); j.Verdict != Abstained || j.Reason == "" {
				t.Fatalf("%+v", j)
			}
		})
	}
	// Fire wins on what was read, even when the other read failed.
	e, c = mailFixture(mailUser("amy"))
	m := &e.Mail.Accounts[0]
	m.AutoUsable, m.Enabled = false, nil
	m.Filters = []FilterForward{{Address: "drop@evil.example"}}
	if j := outcome(t, e, c, "amy@example.com -> drop@evil.example"); j.Verdict != Fired {
		t.Fatalf("%+v", j)
	}
}

func TestForwardingAccountsReadOrSkipped(t *testing.T) {
	gone, archived, nobox, unknown := mailUser("gone"), mailUser("arch"), mailUser("nobox"), mailUser("unk")
	gone.Suspended, archived.Archived, nobox.Mailbox, unknown.Suspended = new(true), new(true), new(false), nil
	e, c := mailFixture(mailUser("amy"), gone, archived, nobox, unknown)
	e.Mail.Accounts = []MailboxForwarding{readMailbox("amy")}
	keys := []string{}
	for _, j := range forwarding(e, c) {
		keys = append(keys, j.Subject.Key+"="+j.Verdict)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"=abstained", "amy@example.com -> none=disproved", "unk@example.com -> none=abstained"}) {
		t.Fatal(keys)
	}
	if j := outcome(t, e, c, ""); !strings.Contains(j.Excerpt, "read for 1 of 2 active mailboxes") {
		t.Fatal(j.Excerpt)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "read whole for 1 of 2 active mailboxes; not read whole: unk@example.com (status unknown).") && strings.Contains(n.Detail, "Not attempted, because not active or without a mailbox: 1 suspended, 1 archived, 1 without a mailbox.")
	}) {
		t.Fatal("limits note does not count skipped mailboxes")
	}
	// No active mailbox at all.
	e, c = mailFixture(gone)
	e.Mail.Accounts = nil
	if j := outcome(t, e, c, ""); j.Verdict != Abstained || !strings.Contains(j.Excerpt, "No active account with a mailbox") {
		t.Fatal(j)
	}
}

func TestForwardingAdminRaiseAndLeaver(t *testing.T) {
	admin := mailUser("root")
	admin.IsAdmin = new(true)
	e, c := mailFixture(admin)
	c.People = []Person{{Handle: "root", Kind: "employee", Left: "2026-10-01", Addresses: []string{"root@example.com"}}}
	e.Mail.Accounts[0].Enabled, e.Mail.Accounts[0].Address = new(true), "x@gmail.com"
	j := outcome(t, e, c, "root@example.com -> x@gmail.com")
	if (len(j.Attributes) != 1 || !j.Has("admin")) || j.Details["admin_mailbox_read"] != "a-root" || !strings.HasPrefix(j.Why, "root@example.com is a super administrator: mail sent to administrators") {
		t.Fatalf("%+v", j)
	}
	if !strings.Contains(j.Excerpt, "root@example.com belongs to root, declared as having left on 2026-10-01.") {
		t.Fatal(j.Excerpt)
	}
	// A conflicting fresh detail leaves the account unread and unraised.
	e.Access.Accounts[0].Conflict = true
	if j := outcome(t, e, c, "root@example.com -> none"); j.Verdict != Abstained || len(j.Attributes) != 0 {
		t.Fatal(j)
	}
}

func TestForwardingAssetOutcomes(t *testing.T) {
	// Nothing read: one asset abstention with the gate's reason, no per-mailbox noise.
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	e.Mail.Accounts = []MailboxForwarding{{ID: "amy", AutoRead: Read{Op: OpMailAutoForwarding, RequestID: "a-amy", Decision: "unavailable:needs_service_account", Reason: "unavailable:needs_service_account"}}}
	e.Mail.Complete = false
	out := forwarding(e, c)
	if len(out) != 1 || out[0].Subject.Key != "" || out[0].Reason != "unavailable:needs_service_account" {
		t.Fatalf("%+v", out)
	}
	plan := e.Coverage(nil)[1]
	if plan.Area != finding.AreaEmail || plan.Groups[0].Gap == nil || plan.Groups[0].Gap.Reason != "unavailable:needs_service_account" {
		t.Fatalf("%+v", plan)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool { return strings.Contains(n.Detail, "holds one person's sign-in") }) {
		t.Fatal("authorized_user note missing")
	}
	// A refused permission names the scope and the delegation entry.
	e.Mail.Accounts[0].AutoRead = Read{Op: OpMailAutoForwarding, RequestID: "a-amy", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:gmail.readonly"}
	if g := e.Coverage(nil)[1].Groups[0].Gap; g == nil || g.Reason != "insufficient_permission:gmail.readonly" {
		t.Fatal(g)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool { return strings.Contains(n.Detail, "Manage Domain Wide Delegation") }) {
		t.Fatal("permission note missing")
	}
	// Not selected: no judgment, not on plan, and the offered profile.
	e, c = mailFixture(mailUser("amy"))
	e.Mail = MailEvidence{}
	e.Binding.Profile, e.Binding.Surfaces = "directory_oauth", []gate.WorkspaceSurface{gate.WorkspaceOAuthGrants}
	e.Binding.Offers = map[gate.WorkspaceSurface]string{gate.WorkspaceGmailForwarding: "directory_oauth_mail"}
	if len(forwarding(e, c)) != 0 {
		t.Fatal("an unselected surface was judged")
	}
	g := e.Coverage(nil)[1].Groups[0]
	if g.NotOnPlan == nil || g.NotOnPlan.Reason != "not_on_plan:profile=directory_oauth" || !strings.Contains(g.NotOnPlan.Detail, "SCHECK_WORKSPACE_PROFILE=directory_oauth_mail") {
		t.Fatal(g)
	}
	// Tokens used are counted in the warning, which says no message was read.
	e, c = mailFixture(mailUser("amy"), mailUser("bob"))
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return n.Kind == "workspace_credential_warning" && strings.HasPrefix(n.Detail, "No message was opened or read.") && strings.Contains(n.Detail, "asked Google to sign it in as each of 2 mailboxes") && strings.Contains(n.Detail, "Manage Domain Wide Delegation")
	}) {
		t.Fatal("credential warning missing")
	}
	// The limits note and the coverage limit are one sentence.
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool { return strings.Contains(n.Detail, mailLimit+".") }) || e.Coverage(nil)[1].Groups[0].Limit != mailLimit {
		t.Fatal("limits differ")
	}
}

// collectMail reads only mailboxes it may, both settings each, in priority
// order, and stops on the gate's Repeats.
func TestCollectMailReadsEligibleMailboxesAndStops(t *testing.T) {
	admin, gone, nobox := mailUser("root"), mailUser("gone"), mailUser("nobox")
	admin.IsAdmin, gone.Suspended, nobox.Mailbox = new(true), new(true), new(false)
	e, c := mailFixture(mailUser("amy"), gone, admin, nobox)
	e.Mail = MailEvidence{}
	views := accountViews(e, c, nil)
	var asked []string
	full := &gate.Population{Page: 1}
	send := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		asked = append(asked, r.Op+":"+r.Params["user"])
		body := `{"enabled":false}`
		if r.Op == OpMailFilters {
			body = `[{"id":"f","action":{"forward":"x@gmail.com","addLabelIds":["TRASH"]}},{"id":"g"},{"id":"h","action":{"forward":7}}]`
		}
		return gate.Result{RequestID: r.Op + r.Params["user"], Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(body), Population: full}}
	})
	e.collectMail(context.Background(), send, Target{Asset: "asset", Stage: "recon"}, c, views)
	if !slices.Equal(asked, []string{OpMailAutoForwarding + ":root", OpMailFilters + ":root", OpMailAutoForwarding + ":amy", OpMailFilters + ":amy"}) || !e.Mail.Complete {
		t.Fatalf("asked %v, %+v", asked, e.Mail)
	}
	m := e.Mail.Accounts[0]
	if m.FiltersSeen != 3 || m.FiltersMalformed != 1 || m.FiltersComplete || len(m.Filters) != 1 || !m.Filters[0].Hides || !m.AutoUsable || m.Enabled == nil || *m.Enabled {
		t.Fatalf("%+v", m)
	}
	asked = nil
	e.Mail = MailEvidence{}
	stop := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		asked = append(asked, r.Params["user"])
		return gate.Result{Decision: "unavailable:needs_service_account", Reason: "unavailable:needs_service_account", Repeats: true}
	})
	e.collectMail(context.Background(), stop, Target{Asset: "asset", Stage: "recon"}, c, views)
	if !slices.Equal(asked, []string{"root"}) || e.Mail.Complete || len(e.Mail.Accounts) != 1 {
		t.Fatalf("asked %v", asked)
	}
	asked = nil
	e.Mail, e.Binding.Surfaces = MailEvidence{}, nil
	e.collectMail(context.Background(), send, Target{Asset: "asset", Stage: "recon"}, c, views)
	if len(asked) != 0 || e.Mail.Selected {
		t.Fatal("an unselected profile read mail settings")
	}
}

// A redaction marker in the destination leaves it unknown, never internal.
func TestForwardingParsesProjectedSettings(t *testing.T) {
	var m MailboxForwarding
	body, _ := json.Marshal(map[string]any{"enabled": true, "emailAddress": "[REDACTED:secret:9 bytes]@x.com"})
	m.autoOf(gate.Result{RequestID: "a", Decision: "sent", Response: &gate.Response{Status: 200, Body: body, Redactions: []policy.Hit{{Rule: "secret", Bytes: 9}}}})
	if _, ok := mailDomain(m.Address); !m.AutoUsable || m.Enabled == nil || ok {
		t.Fatalf("%+v", m)
	}
	m = MailboxForwarding{}
	m.autoOf(gate.Result{RequestID: "a", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`{"enabled":"yes"}`)}})
	if !m.AutoMalformed || m.Enabled != nil {
		t.Fatalf("%+v", m)
	}
	m = MailboxForwarding{}
	m.filtersOf(gate.Result{RequestID: "f", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`[]`), Population: &gate.Population{Page: 1}}})
	if !m.FiltersUsable || !m.FiltersComplete || m.FiltersSeen != 0 {
		t.Fatalf("an empty filter list is not complete: %+v", m)
	}
	m = MailboxForwarding{}
	m.filtersOf(gate.Result{RequestID: "f", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`[{"action":null}]`), Population: &gate.Population{Page: 1}}})
	if m.FiltersMalformed != 1 || m.FiltersComplete {
		t.Fatalf("a null action was taken for no forward: %+v", m)
	}
}

// One read decides the surface's own outcome, for the note, the coverage
// gap and the asset outcome alike: a per-mailbox refusal never reads as the
// scope refused, and a tripped breaker is the surface's, not one mailbox's.
func TestForwardingRefusalIsDecidedOnce(t *testing.T) {
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	e.Mail.Accounts[0] = MailboxForwarding{ID: "amy", AutoRead: Read{Op: OpMailAutoForwarding, RequestID: "a-amy", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:gmail.readonly"},
		FiltersRead: Read{Op: OpMailFilters, RequestID: "f-amy", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:gmail.readonly"}}
	e.Mail.Accounts[1].FiltersUsable, e.Mail.Accounts[1].FiltersComplete = false, false
	e.Mail.Accounts[1].FiltersRead = Read{Op: OpMailFilters, RequestID: "f-bob", Decision: "unavailable:mailbox_unavailable", Status: 400, Reason: "unavailable:mailbox_unavailable"}
	if e.Coverage(nil)[1].Groups[0].Gap != nil {
		t.Fatal("a per-mailbox refusal became the surface's gap while settings were read")
	}
	if slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "has not granted") || strings.Contains(n.Detail, "refused scheck's service account every")
	}) {
		t.Fatal("a note claimed the surface was refused")
	}
	if j := outcome(t, e, c, "amy@example.com -> none"); j.Verdict != Abstained || j.Reason != "insufficient_permission:gmail.readonly" {
		t.Fatal(j)
	}
	// Every mailbox refused one by one: the policy wording, never the scope's.
	e.Mail.Accounts = e.Mail.Accounts[:1]
	if g := e.Coverage(nil)[1].Groups[0].Gap; g == nil || !strings.Contains(g.Detail, "every mailbox it tried") {
		t.Fatal(g)
	}
	// A breaker after one mailbox was read: the surface's gap, its note, and
	// the mailboxes never attempted carry the breaker's reason.
	e, c = mailFixture(mailUser("amy"), mailUser("bob"), mailUser("cat"))
	e.Mail.Accounts[1] = MailboxForwarding{ID: "bob", AutoRead: Read{Op: OpMailAutoForwarding, RequestID: "a-bob", Decision: "unavailable:credential_exchange", Reason: "unavailable:credential_exchange", Repeats: true}}
	e.Mail.Accounts, e.Mail.Complete = e.Mail.Accounts[:2], false
	if g := e.Coverage(nil)[1].Groups[0].Gap; g == nil || g.Reason != "unavailable:credential_exchange" {
		t.Fatal(g)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool { return strings.Contains(n.Detail, "so scheck stopped after 2 mailboxes") }) {
		t.Fatal("breaker note missing")
	}
	if j := outcome(t, e, c, "cat@example.com -> none"); j.Reason != "unavailable:credential_exchange" || j.Subject.Label != "cat@example.com (mailbox)" {
		t.Fatal(j)
	}
	if j := outcome(t, e, c, ""); j.Reason != "unavailable:credential_exchange" {
		t.Fatal(j)
	}
}

// A mail limit cuts collection (exit 2); a refusal is a coverage gap; the
// warning counts every mailbox scheck signed in as, a failed read included.
func TestForwardingOutcomeAndWarningCount(t *testing.T) {
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	e.InventoryComplete, e.Access.Complete = true, true
	if o := e.Outcome(); o.Status != OutcomeComplete {
		t.Fatal(o)
	}
	e.Mail.Accounts[1].FiltersRead = Read{Op: OpMailFilters, RequestID: "f-bob", Decision: "unavailable:population_limit", Reason: "limit_reached", ActedAs: true}
	e.Mail.Accounts[1].FiltersUsable, e.Mail.Accounts[1].FiltersComplete = false, false
	if o := e.Outcome(); o.Status != OutcomeIncomplete || o.Reason != "limit_reached" {
		t.Fatal("a filters cap did not cut collection", o)
	}
	e.Mail.Accounts[1].FiltersRead.Reason = "insufficient_permission:gmail.readonly"
	if o := e.Outcome(); o.Status != OutcomeComplete {
		t.Fatal("a refused mailbox made the run incomplete", o)
	}
	e.Mail.Accounts[1].AutoRead = Read{Op: OpMailAutoForwarding, RequestID: "a-bob", Decision: "unavailable:mailbox_unavailable", Reason: "unavailable:mailbox_unavailable", ActedAs: true}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "asked Google to sign it in as each of 2 mailboxes")
	}) {
		t.Fatal("a mailbox whose reads failed after sign-in was not counted")
	}
}
