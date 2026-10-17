package workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

const (
	IDOAuthBroadScope = "workspace.oauth_broad_scope"
	// OAuthTableVersion versions the broad and narrow scope tables below
	// (docs/spec/workspace-collector.md, "OAuth scope interpretation").
	OAuthTableVersion = "2026-10-11"
	scopePrefix       = "https://www.googleapis.com/auth/"
	securityScope     = scopePrefix + "admin.directory.user.security"
	labelCap          = 120 // bytes of an app's self-chosen name
)

func init() {
	finding.Register(finding.Def{ID: IDOAuthBroadScope, Title: "A third-party app holds broad access to Workspace data", Category: "third-party-apps",
		Area: finding.AreaIdentity, Exposure: finding.NotExposure, Subject: "oauth_app", Judges: "OAuth app scopes", BaseSeverity: finding.SevMedium,
		Impact:      "Whoever controls this app (its maker, or anyone who breaches the maker) can use the access listed as the accounts that granted it, without their password or second factor, until the grant is removed.",
		Remediation: finding.Remediation{Summary: "Confirm someone in the company chose this app and still needs it. If not, remove its access: an administrator can block it under Security → Access and data control → API controls → Manage Third-Party App Access, and each person can remove it at myaccount.google.com/permissions. If it is needed, configure it deliberately on that page: Limited or Specific Google data where it still works, Trusted only if it must reach services you restricted. Trusted widens what the app may reach; it does not limit it, and this finding stays open either way. Prefer a version that asks for less (for example, access to its own files instead of all of Drive). To keep it as it is, accept it by its client id."}})
}

// broadScopes maps each supported broad scope to whether it can change
// data rather than only read it; narrowScopes are the only scopes known to
// grant no data access. Any other scope is unknown, never narrow.
var (
	broadScopes = map[string]bool{
		scopePrefix + "drive.readonly": false, scopePrefix + "gmail.readonly": false,
		scopePrefix + "drive": true, scopePrefix + "gmail.modify": true, scopePrefix + "admin.directory.user": true,
		securityScope: true, scopePrefix + "admin.directory.rolemanagement": true, scopePrefix + "cloud-platform": true,
		"https://mail.google.com/": true, scopePrefix + "gmail.settings.basic": true, scopePrefix + "gmail.settings.sharing": true,
		scopePrefix + "gmail.send": true, scopePrefix + "gmail.compose": true, scopePrefix + "gmail.insert": true,
	}
	narrowScopes = map[string]bool{"openid": true, "email": true, "profile": true, scopePrefix + "userinfo.email": true, scopePrefix + "userinfo.profile": true}
)

// Grant is one OAuth grant as Google reports it for one account.
type Grant struct {
	ClientID string   `json:"client_id"`
	Label    string   `json:"label,omitempty"`
	Scopes   []string `json:"scopes"`
	// ScopesKnown is false for a grant Google reported with no scope.
	ScopesKnown bool  `json:"scopes_known"`
	Anonymous   *bool `json:"anonymous,omitempty"`
	NativeApp   *bool `json:"native_app,omitempty"`
}

// AccountGrants is one admitted account's tokens read. Usable says the
// grants were read, a redaction confined to app names included; Complete
// says every returned grant was kept and recognized.
type AccountGrants struct {
	ID        string  `json:"id"`
	Read      Read    `json:"read"`
	Grants    []Grant `json:"grants"`
	Malformed int     `json:"malformed,omitempty"`
	Usable    bool    `json:"usable"`
	Complete  bool    `json:"complete"`
}

// OAuthEvidence is the optional OAuth grant surface. Complete needs the
// whole users population and every admitted account's grants read.
type OAuthEvidence struct {
	Selected bool            `json:"selected"`
	Accounts []AccountGrants `json:"accounts,omitempty"`
	Complete bool            `json:"complete"`
	// Selection names what chose the accounts read when a cap, the
	// deadline or a rate limit cut the sequence; nil otherwise.
	Selection *finding.Selection `json:"selection,omitempty"`
}

// collectGrants reads every admitted account's grants after the baseline,
// highest-stakes and active accounts first. A result the gate says every
// later account would repeat (the optional token refused, binding gone)
// stops the sequence after it is recorded once.
func (e *Evidence) collectGrants(ctx context.Context, sender Sender, target Target, views []accountView) {
	e.OAuth.Selected = slices.Contains(e.Binding.Surfaces, gate.WorkspaceOAuthGrants)
	if !e.OAuth.Selected {
		return
	}
	complete := e.Users.Complete
	all := readAccounts(views, func(v accountView) bool {
		r := sender.Send(ctx, gate.Request{Op: OpUserTokens, Asset: target.Asset, Stage: target.Stage, Exists: true, Params: map[string]string{"domain": e.Binding.Domain, "user": v.user.ID}})
		account := grantsOf(v.user.ID, r)
		e.OAuth.Accounts = append(e.OAuth.Accounts, account)
		complete = complete && account.Complete
		return r.Repeats
	})
	complete = complete && all
	e.OAuth.Complete = complete && len(e.OAuth.Accounts) == len(e.Users.Items)
}

func grantsOf(id string, r gate.Result) AccountGrants {
	out := AccountGrants{ID: id, Read: readOf(OpUserTokens, r), Grants: []Grant{}}
	if !usable(r) {
		return out
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(r.Response.Body, &items) != nil || items == nil {
		out.Read.Reason = "insufficient_evidence"
		return out
	}
	// An app chooses its own name; a name that trips a redaction rule must
	// not hide its grants. A marker anywhere else leaves the read unusable.
	if len(r.Response.Redactions) > 0 {
		for _, item := range items {
			for field, v := range item {
				if field != "displayText" && strings.Contains(string(v), "[REDACTED:") {
					return out
				}
			}
		}
	}
	out.Usable = true
	for _, item := range items {
		g, ok := grantOf(item, id)
		if !ok {
			out.Malformed++
			continue
		}
		out.Grants = append(out.Grants, g)
	}
	pop := r.Response.Population
	out.Complete = out.Malformed == 0 && pop != nil && len(pop.Incomplete) == 0 && !pop.More
	return out
}

// grantOf recognizes one projected grant. A missing or non-string client
// id, or scopes that are not an array of strings, is malformed; an empty
// scope array is a grant whose access is unknown.
func grantOf(item map[string]json.RawMessage, id string) (Grant, bool) {
	var g Grant
	var user string
	if json.Unmarshal(item["clientId"], &g.ClientID) != nil || g.ClientID == "" || json.Unmarshal(item["userKey"], &user) != nil || user != id {
		return Grant{}, false
	}
	raw, present := item["scopes"]
	if !present || json.Unmarshal(raw, &g.Scopes) != nil || g.Scopes == nil || slices.Contains(g.Scopes, "") {
		return Grant{}, false
	}
	g.ScopesKnown = len(g.Scopes) > 0
	if v, present := item["displayText"]; present && json.Unmarshal(v, &g.Label) != nil {
		return Grant{}, false
	}
	for field, dest := range map[string]**bool{"anonymous": &g.Anonymous, "nativeApp": &g.NativeApp} {
		if v, present := item[field]; present {
			var b bool
			if json.Unmarshal(v, &b) != nil {
				return Grant{}, false
			}
			*dest = &b
		}
	}
	slices.Sort(g.Scopes)
	g.Scopes = slices.Compact(g.Scopes)
	return g, true
}

// oauthGrant is one grant with its grantor's view.
type oauthGrant struct {
	view   accountView
	grant  Grant
	readID string
}

// A grantor is known active, known inactive (suspended or archived) or
// unknown, a conflicting fresh detail included.
func (g oauthGrant) activeKnown() bool   { return active(g.view.user) && !g.view.access.Conflict }
func (g oauthGrant) inactiveKnown() bool { return inactive(g.view.user) && !g.view.access.Conflict }
func (g oauthGrant) broad() []string {
	return slices.DeleteFunc(slices.Clone(g.grant.Scopes), func(s string) bool { _, ok := broadScopes[s]; return !ok })
}
func (g oauthGrant) unknown() []string {
	return slices.DeleteFunc(slices.Clone(g.grant.Scopes), func(s string) bool { _, broad := broadScopes[s]; return broad || narrowScopes[s] })
}
func (g oauthGrant) beyondSignIn() bool {
	return !g.grant.ScopesKnown || slices.ContainsFunc(g.grant.Scopes, func(s string) bool { return !narrowScopes[s] })
}

// adminGrantor is a super administrator, or an account attributed to a
// declared break-glass person; delegated administrators are not.
func (g oauthGrant) adminGrantor() (bool, string) {
	if yes(g.view.user.IsAdmin) && !g.view.access.Conflict {
		return true, "is a super administrator"
	}
	if g.view.person != nil && g.view.person.Kind == "break_glass" {
		return true, "is declared as a break-glass account"
	}
	return false, ""
}

// appOutcome is what an app's grants show, before population completeness
// decides between a disproval and an abstention.
type appOutcome int

const (
	appBroad           appOutcome = iota // an active grantor's own grant is broad
	appActivityUnknown                   // broad only through accounts of unknown status
	appUnclassified                      // scopes outside the table, or none, and no broad one
	appInactiveOnly                      // beyond sign-in only through suspended or archived accounts
	appSignInOnly                        // only recognized sign-in scopes
)

// oauthApp is one client id's grants across the tenant, classified once
// for the rule and the readout.
type oauthApp struct {
	client                                                 string
	labels                                                 []string
	grants                                                 []oauthGrant
	outcome                                                appOutcome
	affected, admins, delegates, inactive, unknownActivity []oauthGrant
	readScopes, changeScopes, unknownScopes, narrow        []string
	native, anonymous                                      bool
}

func (app *oauthApp) classify() {
	inactiveBeyond, unclassified := false, false
	for _, g := range app.grants {
		app.native = app.native || yes(g.grant.NativeApp)
		app.anonymous = app.anonymous || yes(g.grant.Anonymous)
		if g.inactiveKnown() {
			app.inactive = append(app.inactive, g)
			inactiveBeyond = inactiveBeyond || g.beyondSignIn()
			continue
		}
		app.unknownScopes = append(app.unknownScopes, g.unknown()...)
		unclassified = unclassified || len(g.unknown()) > 0 || !g.grant.ScopesKnown
		app.narrow = append(app.narrow, slices.DeleteFunc(slices.Clone(g.grant.Scopes), func(s string) bool { return !narrowScopes[s] })...)
		if len(g.broad()) == 0 {
			continue
		}
		if !g.activeKnown() {
			app.unknownActivity = append(app.unknownActivity, g)
			continue
		}
		app.affected = append(app.affected, g)
		for _, s := range g.broad() {
			if broadScopes[s] {
				app.changeScopes = append(app.changeScopes, s)
			} else {
				app.readScopes = append(app.readScopes, s)
			}
		}
		if ok, _ := g.adminGrantor(); ok {
			app.admins = append(app.admins, g)
		} else if g.view.admin {
			app.delegates = append(app.delegates, g)
		}
	}
	byAddress := func(a, b oauthGrant) int {
		return strings.Compare(strings.ToLower(a.view.user.Primary), strings.ToLower(b.view.user.Primary))
	}
	slices.SortStableFunc(app.affected, func(a, b oauthGrant) int {
		x, _ := a.adminGrantor()
		y, _ := b.adminGrantor()
		if x != y {
			if x {
				return -1
			}
			return 1
		}
		return byAddress(a, b)
	})
	slices.SortFunc(app.admins, byAddress)
	for _, set := range []*[]string{&app.readScopes, &app.changeScopes, &app.unknownScopes, &app.narrow} {
		*set = sortedUnique(*set)
	}
	switch {
	case len(app.affected) > 0:
		app.outcome = appBroad
	case len(app.unknownActivity) > 0:
		app.outcome = appActivityUnknown
	case unclassified:
		app.outcome = appUnclassified
	case inactiveBeyond:
		app.outcome = appInactiveOnly
	default:
		app.outcome = appSignInOnly
	}
}

// name is how a text names the app: always by client id, with the name
// Google reported as a quoted, capped, untrusted label.
func (app oauthApp) name() string {
	if label := appLabel(app.labels); label != "" {
		return `App "` + label + `" (client id ` + app.client + `)`
	}
	return "App with client id " + app.client
}

// accountGap is an admitted account whose grants are not fully known, and
// why, for the readout.
type accountGap struct {
	view accountView
	why  string
}

// oauthState is the OAuth surface decided once: apps by client id, the
// assessment client's grant set aside only by elimination, and what was
// not read.
type oauthState struct {
	selected, complete bool
	apps               []oauthApp
	setAside           *oauthGrant
	accounts, read     int
	tokenIssued        bool
	unread, partial    []accountGap
	failure            *Read
}

func oauthView(e Evidence, views []accountView) oauthState {
	s := oauthState{selected: e.OAuth.Selected, complete: e.OAuth.Complete, accounts: len(views)}
	if !s.selected {
		return s
	}
	byID := map[string]AccountGrants{}
	for _, a := range e.OAuth.Accounts {
		byID[a.ID] = a
		s.tokenIssued = s.tokenIssued || sent(a.Read)
		if !a.Usable && s.failure == nil {
			read := a.Read
			s.failure = &read
		}
	}
	apps := map[string]*oauthApp{}
	for _, v := range views {
		a, ok := byID[v.user.ID]
		switch {
		case !ok:
			s.unread = append(s.unread, accountGap{v, "not attempted"})
			continue
		case !a.Usable:
			s.unread = append(s.unread, accountGap{v, unreadWhy(a.Read)})
			continue
		}
		s.read++
		switch {
		case a.Malformed > 0:
			s.partial = append(s.partial, accountGap{v, "Google returned an app grant scheck could not recognize for " + v.user.Primary + " (account id " + v.user.ID + "); that account's grants are incomplete."})
		case !a.Complete:
			s.partial = append(s.partial, accountGap{v, "Google returned an app grant for another account in the reply for " + v.user.Primary + " (account id " + v.user.ID + "); it was dropped, and that account's grants are incomplete."})
		}
		for _, g := range a.Grants {
			app := apps[g.ClientID]
			if app == nil {
				app = &oauthApp{client: g.ClientID}
				apps[g.ClientID] = app
			}
			if g.Label != "" && !slices.Contains(app.labels, g.Label) {
				app.labels = append(app.labels, g.Label)
			}
			app.grants = append(app.grants, oauthGrant{view: v, grant: g, readID: a.Read.RequestID})
		}
	}
	slices.SortStableFunc(s.unread, func(a, b accountGap) int {
		if x := adminRank(a.view) - adminRank(b.view); x != 0 {
			return x
		}
		return strings.Compare(strings.ToLower(a.view.user.Primary), strings.ToLower(b.view.user.Primary))
	})
	// The assessment client's grant is scheck's own only when it is the one
	// candidate in a complete population (docs/spec/workspace-collector.md,
	// "OAuth scope interpretation").
	if app := apps[e.Binding.AssessmentClient]; app != nil && s.complete {
		candidates := []int{}
		for i, g := range app.grants {
			if slices.Contains(g.grant.Scopes, securityScope) {
				candidates = append(candidates, i)
			}
		}
		if len(candidates) == 1 {
			g := app.grants[candidates[0]]
			s.setAside = &g
			app.grants = slices.Delete(app.grants, candidates[0], candidates[0]+1)
			if len(app.grants) == 0 {
				delete(apps, app.client)
			}
		}
	}
	for _, app := range apps {
		app.classify()
		s.apps = append(s.apps, *app)
	}
	slices.SortFunc(s.apps, func(a, b oauthApp) int { return strings.Compare(a.client, b.client) })
	return s
}

func adminRank(v accountView) int {
	if yes(v.user.IsAdmin) {
		return 0
	}
	if v.admin {
		return 1
	}
	return 2
}

func oauthJudgments(e Evidence, asset string, views []accountView) []finding.Judgment {
	s := oauthView(e, views)
	if !s.selected {
		return nil
	}
	out := []finding.Judgment{}
	for _, app := range s.apps {
		out = append(out, appJudgment(app, s, e, asset))
	}
	rs := reads(e.Users.Reads)
	for _, a := range e.OAuth.Accounts {
		rs = append(rs, a.Read.RequestID)
	}
	j := newJudgment(IDOAuthBroadScope, asset, finding.Subject{}, sortedUnique(rs))
	gaps := s.accounts - s.read + len(s.partial)
	switch {
	case s.accounts == 0:
		j.NotChecked = []string{"No current account evidence was available for this rule."}
	case s.read == 0:
		j.Reason = surfaceReason(s.failure)
		j.Excerpt = "No account's app grants could be read."
		j.NotChecked = []string{"No account's app grants could be read" + failureDetail(s.failure)}
	case !s.complete && gaps == 0:
		j.Reason = surfaceReason(s.failure)
		j.Excerpt = "App grants were read for every account listed, but the account list was incomplete."
		j.NotChecked = []string{"Accounts missing from the account list (excluded or not returned) were not read, so an app with broad access may not have been seen."}
	case !s.complete:
		j.Reason = surfaceReason(s.failure)
		j.Excerpt = fmt.Sprintf("App grants were read for %d of %d accounts.", s.read, s.accounts)
		j.NotChecked = []string{fmt.Sprintf("The grants of %s were not read or not fully recognized, so an app with broad access may not have been seen.", plural(gaps, "account"))}
		if !e.Users.Complete {
			j.NotChecked = append(j.NotChecked, "The account list was incomplete.")
		}
	case len(s.apps) == 0:
		text := fmt.Sprintf("Google reports no third-party app grants for any of the %s read", plural(s.read, "account"))
		if s.setAside != nil {
			text += " other than the grant set aside as scheck's own credential"
		}
		decide(&j, true, false, text+".")
	default:
		return out
	}
	j.Details = map[string]any{"accounts_read": s.read, "accounts": s.accounts, "population_complete": s.complete, "table_version": OAuthTableVersion}
	return append(out, j)
}

func failureDetail(r *Read) string {
	if r == nil || r.Detail == "" {
		return "."
	}
	return ": " + strings.TrimSuffix(r.Detail, ".") + "."
}

func appJudgment(app oauthApp, s oauthState, e Evidence, asset string) finding.Judgment {
	label := app.client
	if l := appLabel(app.labels); l != "" {
		label = `"` + l + `"`
	}
	rs := reads(e.Users.Reads)
	for _, g := range app.grants {
		rs = append(rs, g.readID)
	}
	j := newJudgment(IDOAuthBroadScope, asset, finding.Subject{Kind: "oauth_app", Key: app.client, Label: label}, sortedUnique(rs))
	primaries := func(gs []oauthGrant) string {
		out := []string{}
		for _, g := range gs {
			out = append(out, g.view.user.Primary)
		}
		return strings.Join(sortedUnique(out), ", ")
	}
	assessment := app.client != "" && app.client == e.Binding.AssessmentClient
	setAside := s.setAside != nil && s.setAside.grant.ClientID == app.client
	// Report details are scalars: scopes space-separated as OAuth writes
	// them, accounts comma-separated; an empty list is left out.
	j.Details = map[string]any{"native_app": app.native, "anonymous": app.anonymous, "assessment_client": assessment,
		"population_complete": s.complete, "table_version": OAuthTableVersion}
	for key, list := range map[string]string{
		"scopes_read": strings.Join(app.readScopes, " "), "scopes_change": strings.Join(app.changeScopes, " "),
		"scopes_unknown": strings.Join(app.unknownScopes, " "), "scopes_narrow": strings.Join(app.narrow, " "),
		"admin_grantors": primaries(app.admins), "delegated_admin_grantors": primaries(app.delegates),
		"inactive_grantors": primaries(app.inactive), "unknown_status_grantors": primaries(app.unknownActivity),
	} {
		if list != "" {
			j.Details[key] = list
		}
	}
	if len(app.labels) > 1 {
		j.Details["labels"] = len(app.labels)
	}
	name := app.name()
	switch app.outcome {
	case appBroad:
		qualifier := ""
		if !s.complete {
			qualifier = "at least "
		}
		j.Listed = []string{}
		listed := []string{}
		for _, g := range app.affected {
			j.Listed = append(j.Listed, g.view.user.Primary)
			entry := g.view.user.Primary
			if ok, what := g.adminGrantor(); ok {
				why := "declared break-glass account"
				if strings.Contains(what, "super") {
					why = "super administrator"
				}
				entry += " (" + why + ")"
				j.OfNote = append(j.OfNote, finding.OfNote{Key: g.view.user.Primary, Why: why})
			}
			listed = append(listed, entry)
		}
		text := ""
		if assessment && !setAside {
			text = "scheck authenticated with this client id; one of these grants may be the credential this run used. "
		}
		text += fmt.Sprintf("%s holds access that %s through grants from %s%s: %s.", name, capabilities(app.readScopes, app.changeScopes), qualifier, plural(len(app.affected), "active account"), capped(listed))
		if n := len(app.unknownActivity); n > 0 {
			text += " " + plural(n, "more account") + " whose sign-in status is unknown also granted it broad access."
		}
		if len(app.unknownScopes) > 0 {
			text += " Unclassified scopes also held: " + strings.Join(shortScopes(app.unknownScopes), ", ") + "."
		}
		if slices.ContainsFunc(app.changeScopes, func(sc string) bool { return strings.HasPrefix(sc, scopePrefix+"admin.directory.") }) {
			text += " Its admin.directory access depends on the granting account's administrative rights."
		}
		if app.native {
			text += " Google reports this is an installed app; these include Google's and Apple's own (for example Drive for desktop or Mail), where the risk is the device that holds the grant."
		}
		if app.anonymous {
			text += " Google reports this app is not registered with Google."
		}
		if len(app.labels) > 1 {
			text += " It is shown under several names."
		}
		if len(app.labels) > 0 {
			text += " The name is chosen by whoever registered the app; it does not show who made it."
		}
		decide(&j, true, true, text)
		if len(app.admins) > 0 {
			admin := app.admins[0]
			_, what := admin.adminGrantor()
			who, scopes := admin.view.user.Primary, shortScopes(admin.broad())
			others := ""
			if len(app.admins) > 1 {
				others = ", as did " + plural(len(app.admins)-1, "other administrator account")
			}
			reach := "though not that account's other administrator rights"
			if slices.ContainsFunc(admin.broad(), func(sc string) bool { return strings.HasPrefix(sc, scopePrefix+"admin.directory.") }) {
				reach = "including the administrator actions those scopes allow"
			}
			noun := "the scope "
			if len(scopes) > 1 {
				noun = "the scopes "
			}
			j.Details["admin_grant_read"] = admin.readID
			j.Why = fmt.Sprintf("%s %s and granted this app %s%s%s: whoever controls the app can use those scopes as %s, %s.", who, what, noun, strings.Join(scopes, ", "), others, who, reach)
			j.Attributes = []finding.Attribute{{Name: "admin_grantor", Ref: finding.Ref{Observation: admin.readID, Excerpt: j.Why}}}
		}
		j.NotChecked = []string{"When each app was authorized or last used, and what it did with its access, were not checked."}
	case appActivityUnknown:
		j.Excerpt = name + " holds broad access only through accounts whose sign-in status is unknown."
		j.NotChecked = []string{"Whether " + primaries(app.unknownActivity) + " can still sign in was unknown or conflicting."}
	case appUnclassified:
		j.Reason = reasonUnclassified
		j.Excerpt = name + " holds no scope scheck classifies as broad; it holds scopes scheck does not classify: " + strings.Join(shortScopes(app.unknownScopes), ", ") + "."
		if len(app.unknownScopes) == 0 {
			j.Excerpt = name + " has a grant Google reported without any scope."
		}
		j.NotChecked = []string{"Scopes outside table " + OAuthTableVersion + " were not classified."}
	case appInactiveOnly:
		if s.complete {
			decide(&j, true, false, name+" holds access beyond sign-in only through suspended or archived accounts; see the cleanup note.")
			break
		}
		j.Excerpt = name + " holds access beyond sign-in only through suspended or archived accounts in the grants read."
		j.NotChecked = []string{"Not every account's grants were read, so a broader grant to this app may not have been seen."}
	case appSignInOnly:
		if s.complete {
			decide(&j, true, false, name+" holds only sign-in scopes across every account read.")
			break
		}
		j.Excerpt = name + " holds only sign-in scopes in the grants read."
		j.NotChecked = []string{"Not every account's grants were read, so a broader grant to this app may not have been seen."}
	}
	switch {
	case setAside:
		j.NotChecked = append(j.NotChecked, "scheck authenticated with this client id. The one grant holding admin.directory.user.security, from "+s.setAside.view.user.Primary+", was set aside as the credential this run used; the grants above were judged.")
	case assessment:
		j.NotChecked = append(j.NotChecked, "scheck cannot tell whose sign-in its credential file holds, so none of these grants was set aside as its own.")
	}
	return j
}

func capabilities(read, change []string) string {
	parts := []string{}
	if len(read) > 0 {
		parts = append(parts, "can read "+strings.Join(shortScopes(read), ", "))
	}
	if len(change) > 0 {
		parts = append(parts, "can change "+strings.Join(shortScopes(change), ", "))
	}
	return strings.Join(parts, " and ")
}

func shortScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimPrefix(s, scopePrefix))
	}
	return out
}

// appLabel is the first name Google reported, cut with policy's marker. It
// is never matched, keyed or trusted.
func appLabel(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	return policy.CutLabel(labels[0], labelCap)
}

// oauthNotes is the readout for the OAuth surface, from the same view as
// the rule.
func oauthNotes(e Evidence, asset string, views []accountView) []Note {
	out := []Note{}
	note := func(kind, text string) { out = append(out, Note{Kind: kind, Source: asset, Detail: text}) }
	if e.Binding.CustomerID == "" {
		return out
	}
	s := oauthView(e, views)
	if !s.selected {
		note("workspace_inventory", "Third-party app access was not checked: the selected Workspace profile does not read it. The check lists apps people allowed into their mail, Drive or calendar, a common way an attacker keeps access after a phishing email. It needs the Workspace permission admin.directory.user.security, which Google offers only together with the ability to revoke app access, sign people out and turn off 2-step verification; the checks above do not need it. If your organization wants this check, an administrator can approve a dedicated credential for it, so the everyday one keeps read-only permissions; then run again with SCHECK_WORKSPACE_PROFILE="+e.Binding.offer(gate.WorkspaceOAuthGrants, "directory_oauth")+".")
		return out
	}
	if s.failure != nil && s.read == 0 && strings.HasPrefix(s.failure.Reason, "insufficient_permission") {
		if s.failure.Decision == "sent" {
			note("workspace_inventory", "Google refused every account's app grants read. The account scheck acts as needs an administrator role that can manage user security settings (a super administrator, or a custom role with that privilege).")
		} else {
			note("workspace_inventory", "Google did not let this credential read app grants. For a service account, an administrator adds admin.directory.user.security to its domain-wide delegation entry; for a signed-in credential, sign in again granting it. That permission also lets the credential revoke app access, sign people out and turn off 2-step verification, so prefer a dedicated credential for this check. Nothing else in this run was affected.")
		}
	}
	if s.tokenIssued {
		note("workspace_credential_warning", "The separate token scheck used for the app check holds admin.directory.user.security, which also lets it revoke app access and app passwords, read or create backup codes, sign people out and turn off 2-step verification. scheck sent only the declared reads; effective access was not tested. If you will not run the app check again, remove that permission from the credential's domain-wide delegation entry or consent.")
	}
	if s.read == 0 {
		return out
	}
	note("workspace_inventory", oauthLimit+".")
	if g := s.setAside; g != nil {
		note("workspace_credential", "The grant from "+g.view.user.Primary+" to client id "+g.grant.ClientID+" ("+strings.Join(shortScopes(g.grant.Scopes), ", ")+") was set aside as the credential this run used: it is the only grant to scheck's client holding admin.directory.user.security in a complete read. It was not judged.")
	}
	if !s.complete {
		names, superDenied := []string{}, false
		for _, gap := range s.unread {
			entry := gap.view.user.Primary
			if yes(gap.view.user.IsAdmin) {
				entry += " (super administrator, " + gap.why + ")"
				superDenied = superDenied || gap.why == "permission denied"
			} else {
				entry += " (" + gap.why + ")"
			}
			names = append(names, entry)
		}
		text := fmt.Sprintf("App grants were read for %d of %d accounts; app and grantor counts are lower bounds.", s.read, s.accounts)
		if len(names) > 0 {
			text += " Not read: " + capped(names) + "."
		}
		if superDenied {
			text += " A delegated administrator may not be allowed to read super administrators' grants."
		}
		if !e.Users.Complete {
			text += " The account list itself was incomplete."
		}
		note("workspace_inventory", text)
	}
	for _, gap := range s.partial {
		note("workspace_inventory", gap.why)
	}
	inactive, unclassified := []string{}, []string{}
	for _, app := range s.apps {
		for _, g := range app.inactive {
			inactive = append(inactive, g.view.user.Primary)
		}
		if app.outcome == appUnclassified {
			if label := appLabel(app.labels); label != "" {
				unclassified = append(unclassified, `"`+label+`" (`+app.client+`)`)
			} else {
				unclassified = append(unclassified, app.client)
			}
		}
	}
	if inactive = sortedUnique(inactive); len(inactive) > 0 {
		note("workspace_inventory", "These suspended or archived accounts still have app grants: "+capped(inactive)+". scheck did not test whether they work; they may work again if the account is restored. Remove them during offboarding.")
	}
	if len(unclassified) > 0 {
		text := " hold scopes scheck does not classify and none it classifies as broad, so they were not judged: " + capped(unclassified) + ". Their names are chosen by whoever registered them. Check under Security → Access and data control → API controls → Manage Third-Party App Access in the Admin console that someone chose each one."
		if len(unclassified) == 1 {
			text = " holds scopes scheck does not classify and none it classifies as broad, so it was not judged: " + capped(unclassified) + ". Its name is chosen by whoever registered it. Check under Security → Access and data control → API controls → Manage Third-Party App Access in the Admin console that someone chose it."
		}
		note("workspace_inventory", plural(len(unclassified), "app")+text)
	}
	return out
}
