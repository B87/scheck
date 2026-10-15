package workspace

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

const (
	appDrive = "123456789012-k3v9qz7x2m4n8p1r5t6w0y3b7d9f2h4j.apps.googleusercontent.com"
	appOther = "210987654321-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com"
)

// oauthFixture is a complete population of active non-administrators whose
// grants were all read, none yet.
func oauthFixture(users ...User) (Evidence, Context) {
	e, c := stepFixture(users...)
	e.Binding = Binding{CustomerID: "C123", Domain: "example.com", Profile: "directory_oauth", Surfaces: []gate.WorkspaceSurface{gate.WorkspaceOAuthGrants}}
	e.OAuth = OAuthEvidence{Selected: true, Complete: true}
	for _, u := range users {
		e.OAuth.Accounts = append(e.OAuth.Accounts, AccountGrants{ID: u.ID, Read: Read{Op: OpUserTokens, RequestID: "t-" + u.ID, Decision: "sent", Status: 200}, Grants: []Grant{}, Usable: true, Complete: true})
	}
	return e, c
}

func oauthUser(id string) User { return stepUser(id, "/Sales", new(true), new(true)) }

func grant(e *Evidence, i int, client string, scopes ...string) {
	full := []string{}
	for _, s := range scopes {
		if !strings.Contains(s, ":") && !narrowScopes[s] {
			s = scopePrefix + s
		}
		full = append(full, s)
	}
	e.OAuth.Accounts[i].Grants = append(e.OAuth.Accounts[i].Grants, Grant{ClientID: client, Scopes: full, ScopesKnown: len(full) > 0})
}

func appResult(t *testing.T, e Evidence, c Context, client string) finding.Judgment {
	t.Helper()
	for _, j := range Judge(e, "asset", c) {
		if j.ID == IDOAuthBroadScope && j.Subject.Key == client {
			return j
		}
	}
	t.Fatalf("no outcome for %s", client)
	return finding.Judgment{}
}

func assetOutcome(e Evidence, c Context) (finding.Judgment, bool) {
	for _, j := range Judge(e, "asset", c) {
		if j.ID == IDOAuthBroadScope && j.Subject.Key == "" {
			return j, true
		}
	}
	return finding.Judgment{}, false
}

func TestOAuthFiresOnBroadScopeAndListsOnlyBroadGrantors(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	grant(&e, 0, appDrive, "drive.readonly")
	grant(&e, 1, appDrive, "openid")
	e.OAuth.Accounts[0].Grants[0].Label = "Shiny Docs"
	j := appResult(t, e, c, appDrive)
	if j.Verdict != Fired || !slices.Equal(j.Listed, []string{"amy@example.com"}) || j.Subject.Kind != "oauth_app" {
		t.Fatalf("%+v", j)
	}
	for _, want := range []string{`App "Shiny Docs" (client id ` + appDrive + `)`, "can read drive.readonly", "1 active account: amy@example.com.", "it does not show who made it"} {
		if !strings.Contains(j.Excerpt, want) {
			t.Fatalf("excerpt lacks %q: %s", want, j.Excerpt)
		}
	}
	if len(j.Attributes) != 0 || j.Why != "" {
		t.Fatal("a non-administrator grant raised the app", j)
	}
	if _, ok := assetOutcome(e, c); ok {
		t.Fatal("a complete population with an app needs no asset outcome")
	}
}

func TestOAuthAdminRaiseNeedsTheAdministratorsOwnBroadGrant(t *testing.T) {
	admin := oauthUser("root")
	admin.IsAdmin = new(true)
	e, c := oauthFixture(admin, oauthUser("bob"))
	grant(&e, 0, appDrive, "drive", "gmail.readonly")
	j := appResult(t, e, c, appDrive)
	if (len(j.Attributes) != 1 || !j.Has("admin_grantor")) || !strings.Contains(j.Why, "root@example.com is a super administrator and granted this app the scopes drive, gmail.readonly") || strings.Contains(j.Why, " (") {
		t.Fatalf("%+v", j)
	}
	if !strings.Contains(j.Excerpt, "can read gmail.readonly and can change drive") || !strings.Contains(j.Excerpt, "root@example.com (super administrator)") {
		t.Fatal(j.Excerpt)
	}

	e, c = oauthFixture(admin, oauthUser("bob"))
	grant(&e, 0, appDrive, "openid")
	grant(&e, 1, appDrive, "drive")
	if j := appResult(t, e, c, appDrive); j.Verdict != Fired || len(j.Attributes) != 0 {
		t.Fatalf("a sign-in-only administrator grant raised the app: %+v", j)
	}
}

func TestOAuthBreakGlassRaisesAndDelegatesDoNot(t *testing.T) {
	glass := oauthUser("glass")
	glass.Aliases = []string{"recovery@example.com"}
	e, c := oauthFixture(glass, oauthUser("bob"))
	c.People = []Person{{Handle: "recovery", Kind: "break_glass", Addresses: []string{"recovery@example.com"}}}
	grant(&e, 0, appDrive, "https://mail.google.com/")
	j := appResult(t, e, c, appDrive)
	if j.Verdict != Fired || (len(j.Attributes) != 1 || !j.Has("admin_grantor")) || !strings.Contains(j.Why, "is declared as a break-glass account") || !strings.Contains(j.Excerpt, "can change https://mail.google.com/") {
		t.Fatalf("%+v", j)
	}

	e, c = oauthFixture(oauthUser("del"))
	e.Access.Roles.Items = []Role{{ID: "r", Privileges: []Privilege{{Service: "00haapch16h1ysv", Name: "USERS_RESET_PASSWORD"}}}}
	e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "a", Role: "r", Assignee: "del", Type: "USER", Scope: "CUSTOMER"}}
	grant(&e, 0, appDrive, "drive")
	j = appResult(t, e, c, appDrive)
	if j.Verdict != Fired || len(j.Attributes) != 0 || j.Details["delegated_admin_grantors"] != "del@example.com" {
		t.Fatalf("a delegated administrator raised the app or was not listed: %+v", j)
	}
}

func TestOAuthUnknownScopesAndAtLeast(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"))
	grant(&e, 0, appDrive, "drive", "https://www.google.com/accounts/OAuthLogin")
	e.Users.Complete, e.OAuth.Complete = false, false
	j := appResult(t, e, c, appDrive)
	if j.Verdict != Fired || !strings.Contains(j.Excerpt, "at least 1 active account") || !strings.Contains(j.Excerpt, "Unclassified scopes also held: https://www.google.com/accounts/OAuthLogin") {
		t.Fatalf("%+v", j)
	}
	if a, ok := assetOutcome(e, c); !ok || a.Verdict != Abstained {
		t.Fatal("a partial population needs an asset-level abstention", a)
	}
}

func TestOAuthPerAccountDenialFiresOnTheRest(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	grant(&e, 0, appDrive, "drive")
	e.OAuth.Accounts[1].Read = Read{Op: OpUserTokens, RequestID: "t-bob", Decision: "sent", Status: 403, Reason: "insufficient_permission:admin.directory.user.security"}
	e.OAuth.Accounts[1].Usable, e.OAuth.Accounts[1].Complete, e.OAuth.Complete = false, false, false
	if j := appResult(t, e, c, appDrive); j.Verdict != Fired || !strings.Contains(j.Excerpt, "at least") {
		t.Fatalf("%+v", j)
	}
	a, ok := assetOutcome(e, c)
	if !ok || a.Verdict != Abstained || a.Reason != "insufficient_permission:admin.directory.user.security" || !strings.Contains(a.Excerpt, "1 of 2 accounts") {
		t.Fatalf("%+v", a)
	}
	notes := Readout(e, "asset", c)
	if !slices.ContainsFunc(notes, func(n Note) bool { return strings.Contains(n.Detail, "Not read: bob@example.com (permission denied).") }) {
		t.Fatal("partial note missing", notes)
	}
}

func TestOAuthDisprovals(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	grant(&e, 0, appDrive, "openid", "email", "userinfo.profile")
	if j := appResult(t, e, c, appDrive); j.Verdict != Disproved || !strings.Contains(j.Excerpt, "only sign-in scopes across every account read") {
		t.Fatalf("%+v", j)
	}

	e, c = oauthFixture(oauthUser("amy"))
	a, ok := assetOutcome(e, c)
	if !ok || a.Verdict != Disproved || !strings.Contains(a.Excerpt, "no third-party app grants for any of the 1 account read") {
		t.Fatalf("%+v", a)
	}

	gone := oauthUser("gone")
	gone.Suspended = new(true)
	e, c = oauthFixture(gone, oauthUser("amy"))
	grant(&e, 0, appDrive, "drive")
	grant(&e, 1, appDrive, "openid")
	if j := appResult(t, e, c, appDrive); j.Verdict != Disproved || !strings.Contains(j.Excerpt, "holds access beyond sign-in only through suspended or archived accounts; see the cleanup note") || j.Details["inactive_grantors"] != "gone@example.com" {
		t.Fatalf("%+v", j)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "suspended or archived accounts still have app grants: gone@example.com")
	}) {
		t.Fatal("cleanup note missing")
	}
}

func TestOAuthAbstentions(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"))
	grant(&e, 0, appDrive, "https://www.google.com/accounts/OAuthLogin")
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained || j.Reason != "unavailable:oauth_unclassified" {
		t.Fatalf("unknown-only: %+v", j)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "1 app holds scopes scheck does not classify and none it classifies as broad")
	}) {
		t.Fatal("unclassified note missing")
	}

	e, c = oauthFixture(oauthUser("amy"))
	grant(&e, 0, appDrive, "openid")
	e.Users.Complete, e.OAuth.Complete = false, false
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained {
		t.Fatalf("narrow on a partial population: %+v", j)
	}

	e, c = oauthFixture(oauthUser("amy"))
	grant(&e, 0, appDrive)
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained || !strings.Contains(j.Excerpt, "without any scope") {
		t.Fatalf("empty scopes: %+v", j)
	}

	odd := oauthUser("odd")
	odd.Suspended = nil
	e, c = oauthFixture(odd)
	grant(&e, 0, appDrive, "drive")
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained || !strings.Contains(j.NotChecked[0], "odd@example.com") {
		t.Fatalf("unknown activity: %+v", j)
	}

	e, c = oauthFixture(oauthUser("amy"))
	e.OAuth.Accounts[0].Read = Read{Op: OpUserTokens, RequestID: "t-amy", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:admin.directory.user.security", Detail: "Google did not authorize this credential for the optional read permission"}
	e.OAuth.Accounts[0].Usable, e.OAuth.Accounts[0].Complete, e.OAuth.Complete = false, false, false
	a, ok := assetOutcome(e, c)
	if !ok || a.Verdict != Abstained || a.Reason != "insufficient_permission:admin.directory.user.security" || !strings.Contains(a.NotChecked[0], "optional read permission") {
		t.Fatalf("exchange denied: %+v", a)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "Google did not let this credential read app grants")
	}) {
		t.Fatal("permission note missing")
	}
}

func TestOAuthAssessmentClientSetAsideOnlyByElimination(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	e.Binding.AssessmentClient = appDrive
	grant(&e, 0, appDrive, "admin.directory.user.readonly", "admin.directory.user.security")
	grant(&e, 1, appDrive, "cloud-platform")
	j := appResult(t, e, c, appDrive)
	if j.Verdict != Fired || !slices.Equal(j.Listed, []string{"bob@example.com"}) || strings.HasPrefix(j.Excerpt, "scheck authenticated") || !slices.ContainsFunc(j.NotChecked, func(s string) bool { return strings.Contains(s, "from amy@example.com, was set aside") }) {
		t.Fatalf("the sole candidate was not set aside: %+v", j)
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return n.Kind == "workspace_credential" && strings.Contains(n.Detail, "from amy@example.com to client id "+appDrive)
	}) {
		t.Fatal("set-aside note missing")
	}

	e, c = oauthFixture(oauthUser("amy"), oauthUser("bob"))
	e.Binding.AssessmentClient = appDrive
	grant(&e, 0, appDrive, "admin.directory.user.security")
	grant(&e, 1, appDrive, "admin.directory.user.security")
	j = appResult(t, e, c, appDrive)
	if j.Verdict != Fired || len(j.Listed) != 2 || !strings.HasPrefix(j.Excerpt, "scheck authenticated with this client id; one of these grants may be the credential this run used.") || !slices.ContainsFunc(j.NotChecked, func(s string) bool { return strings.Contains(s, "none of these grants was set aside") }) {
		t.Fatalf("two candidates: %+v", j)
	}

	// A partial population sets nothing aside, and a label never selects the
	// assessment client.
	e, c = oauthFixture(oauthUser("amy"), oauthUser("bob"))
	e.Binding.AssessmentClient = appDrive
	grant(&e, 0, appDrive, "admin.directory.user.security")
	grant(&e, 1, appOther, "admin.directory.user.security")
	e.OAuth.Accounts[1].Grants[0].Label = "scheck"
	e.Users.Complete, e.OAuth.Complete = false, false
	if j := appResult(t, e, c, appDrive); j.Verdict != Fired {
		t.Fatalf("partial: %+v", j)
	}
	if j := appResult(t, e, c, appOther); j.Verdict != Fired || j.Details["assessment_client"] != false {
		t.Fatalf("a label selected the assessment client: %+v", j)
	}
}

func TestOAuthNotSelectedHasNoJudgmentAndNamesTheSelection(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"))
	e.Binding.Profile, e.Binding.Surfaces, e.OAuth = "directory", nil, OAuthEvidence{}
	for _, j := range Judge(e, "asset", c) {
		if j.ID == IDOAuthBroadScope {
			t.Fatal("judged an unselected surface", j)
		}
	}
	if !slices.ContainsFunc(Readout(e, "asset", c), func(n Note) bool {
		return strings.Contains(n.Detail, "SCHECK_WORKSPACE_PROFILE=directory_oauth") && strings.Contains(n.Detail, "turn off 2-step verification")
	}) {
		t.Fatal("selection note missing")
	}
	if g := oauthGroup(t, e); g.NotOnPlan == nil || g.NotOnPlan.Reason != "not_on_plan:profile=directory" || !strings.HasPrefix(g.NotOnPlan.Detail, "The default Workspace profile, directory,") {
		t.Fatal(g)
	}
	if g := oauthGroup(t, Evidence{}); g.NotOnPlan != nil {
		t.Fatal("an unbound tenant claimed a plan", g)
	}
	e.Users.Items = nil
	for _, j := range Judge(e, "asset", c) {
		if j.ID == IDOAuthBroadScope {
			t.Fatal("an empty population judged an unselected surface", j)
		}
	}
}

func TestOAuthLabelIsCappedAndNeverKeys(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	grant(&e, 0, appDrive, "drive")
	grant(&e, 1, appDrive, "drive")
	e.OAuth.Accounts[0].Grants[0].Label = strings.Repeat("Ä", 100)
	e.OAuth.Accounts[1].Grants[0].Label = "Google Chrome"
	j := appResult(t, e, c, appDrive)
	if !strings.Contains(j.Subject.Label, strings.Repeat("Ä", 60)+"[TRUNCATED:80 bytes]") || !strings.Contains(j.Excerpt, "shown under several names") || j.Subject.Key != appDrive {
		t.Fatalf("%+v", j)
	}
}

func TestGrantsOfRecognizesOnlyWellFormedGrants(t *testing.T) {
	result := func(body string, redactions []policy.Hit, pop *gate.Population) gate.Result {
		return gate.Result{RequestID: "r", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(body), Redactions: redactions, Population: pop}}
	}
	full := &gate.Population{Items: 1, Kept: 1}
	a := grantsOf("1", result(`[{"clientId":"c","scopes":["openid"],"userKey":"1","displayText":"X","nativeApp":true}]`, nil, full))
	if !a.Complete || len(a.Grants) != 1 || !yes(a.Grants[0].NativeApp) || a.Grants[0].Label != "X" {
		t.Fatalf("%+v", a)
	}
	for name, body := range map[string]string{
		"missing client":    `[{"scopes":["openid"],"userKey":"1"}]`,
		"numeric client":    `[{"clientId":7,"scopes":["openid"],"userKey":"1"}]`,
		"missing scopes":    `[{"clientId":"c","userKey":"1"}]`,
		"string scopes":     `[{"clientId":"c","scopes":"openid","userKey":"1"}]`,
		"non-string scope":  `[{"clientId":"c","scopes":[1],"userKey":"1"}]`,
		"other user":        `[{"clientId":"c","scopes":["openid"],"userKey":"2"}]`,
		"non-bool native":   `[{"clientId":"c","scopes":["openid"],"userKey":"1","nativeApp":"yes"}]`,
		"non-string label":  `[{"clientId":"c","scopes":["openid"],"userKey":"1","displayText":{}}]`,
		"null scope member": `[{"clientId":"c","scopes":[null],"userKey":"1"}]`,
	} {
		if a := grantsOf("1", result(body, nil, full)); a.Complete || a.Malformed != 1 {
			t.Fatalf("%s: %+v", name, a)
		}
	}
	hit := []policy.Hit{{Rule: "x", Bytes: 1}}
	if a := grantsOf("1", result(`[{"clientId":"[REDACTED:x:1 bytes]","scopes":["openid"],"userKey":"1"}]`, hit, full)); a.Usable || a.Complete {
		t.Fatal("a read redacted outside app names is usable", a)
	}
	// An app cannot hide its grants behind a name that trips a redaction rule.
	if a := grantsOf("1", result(`[{"clientId":"c","scopes":["https://www.googleapis.com/auth/drive"],"userKey":"1","displayText":"[REDACTED:x:1 bytes]"}]`, hit, full)); !a.Usable || !a.Complete || a.Grants[0].Label != "[REDACTED:x:1 bytes]" {
		t.Fatal("a redacted app name hid its grants", a)
	}
	if a := grantsOf("1", result(`[]`, nil, &gate.Population{Incomplete: []string{"dropped"}})); a.Complete {
		t.Fatal("a dropped item left the account complete", a)
	}

	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"))
	grant(&e, 1, appDrive, "openid")
	e.OAuth.Accounts[0].Malformed, e.OAuth.Accounts[0].Complete, e.OAuth.Complete = 1, false, false
	e.OAuth.Accounts[1].Complete = false
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained {
		t.Fatal("a malformed grant elsewhere allowed a disproval", j)
	}
	notes := Readout(e, "asset", c)
	if !slices.ContainsFunc(notes, func(n Note) bool { return strings.Contains(n.Detail, "could not recognize for amy@example.com") }) ||
		!slices.ContainsFunc(notes, func(n Note) bool {
			return strings.Contains(n.Detail, "another account in the reply for bob@example.com")
		}) {
		t.Fatal("partial-account notes missing", notes)
	}
	if a, _ := assetOutcome(e, c); !strings.Contains(a.NotChecked[0], "The grants of 2 accounts were not read or not fully recognized") {
		t.Fatal(a)
	}
}

func TestCollectGrantsStopsOnASessionFailureAndReadsAdminsFirst(t *testing.T) {
	admin := oauthUser("zed")
	admin.IsAdmin = new(true)
	e, c := oauthFixture(oauthUser("amy"), admin, oauthUser("bob"))
	e.OAuth = OAuthEvidence{}
	var asked []string
	send := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		asked = append(asked, r.Params["user"])
		if r.Op != OpUserTokens {
			t.Fatal("unexpected op", r.Op)
		}
		return gate.Result{RequestID: "x", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:admin.directory.user.security", Repeats: true}
	})
	// Check hands collectGrants the accounts in Plan's order (CollectUsers).
	attrs := attribute("asset", e.Users.Items, c.People, e.Users.Complete)
	e.collectGrants(context.Background(), send, Target{Asset: "asset", Stage: "check"}, inOrder(accountViews(e, c, attrs), orderUsers(e.Users.Items, e.Access.Accounts, attrs, c)))
	if !slices.Equal(asked, []string{"zed"}) || e.OAuth.Complete || len(e.OAuth.Accounts) != 1 {
		t.Fatalf("asked %v, evidence %+v", asked, e.OAuth)
	}

	asked = nil
	e.OAuth = OAuthEvidence{}
	full := &gate.Population{}
	send = senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		asked = append(asked, r.Params["user"])
		return gate.Result{RequestID: "t-" + r.Params["user"], Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`[]`), Population: full}}
	})
	e.collectGrants(context.Background(), send, Target{Asset: "asset", Stage: "check"}, inOrder(accountViews(e, c, attrs), orderUsers(e.Users.Items, e.Access.Accounts, attrs, c)))
	if !slices.Equal(asked, []string{"zed", "amy", "bob"}) || !e.OAuth.Complete {
		t.Fatalf("asked %v, evidence %+v", asked, e.OAuth)
	}

	asked = nil
	e.Binding.Profile, e.Binding.Surfaces, e.OAuth = "directory_mail", nil, OAuthEvidence{}
	e.collectGrants(context.Background(), send, Target{Asset: "asset", Stage: "recon"}, accountViews(e, c, attribute("asset", e.Users.Items, c.People, e.Users.Complete)))
	if len(asked) != 0 || e.OAuth.Selected {
		t.Fatal("an unselected profile read grants", asked)
	}
}

func TestOAuthReviewRegressions(t *testing.T) {
	// A suspended account's broad grant on a partial population is never
	// described as sign-in only.
	gone := oauthUser("gone")
	gone.Suspended = new(true)
	e, c := oauthFixture(gone, oauthUser("amy"))
	grant(&e, 0, appDrive, "drive")
	grant(&e, 1, appDrive, "openid")
	e.Users.Complete, e.OAuth.Complete = false, false
	if j := appResult(t, e, c, appDrive); j.Verdict != Abstained || !strings.Contains(j.Excerpt, "beyond sign-in only through suspended or archived accounts in the grants read") {
		t.Fatalf("%+v", j)
	}
	// Nor is an unknown scope held only by a suspended account.
	e, c = oauthFixture(gone, oauthUser("amy"))
	grant(&e, 0, appDrive, "https://www.google.com/accounts/OAuthLogin")
	if j := appResult(t, e, c, appDrive); j.Verdict != Disproved || strings.Contains(j.Excerpt, "only sign-in scopes") {
		t.Fatalf("%+v", j)
	}
	// Every account read, but the account list was incomplete.
	e, c = oauthFixture(oauthUser("amy"))
	e.Users.Complete, e.OAuth.Complete = false, false
	if a, ok := assetOutcome(e, c); !ok || a.Excerpt != "App grants were read for every account listed, but the account list was incomplete." || !strings.Contains(a.NotChecked[0], "excluded or not returned") {
		t.Fatalf("%+v", a)
	}
	// Every account refused after the token was issued: the readout says
	// why and still warns about the permission the token holds.
	e, c = oauthFixture(oauthUser("amy"))
	e.OAuth.Accounts[0].Read = Read{Op: OpUserTokens, RequestID: "t-amy", Decision: "sent", Status: 403, Reason: "insufficient_permission:admin.directory.user.security"}
	e.OAuth.Accounts[0].Usable, e.OAuth.Accounts[0].Complete, e.OAuth.Complete = false, false, false
	notes := Readout(e, "asset", c)
	if !slices.ContainsFunc(notes, func(n Note) bool {
		return strings.HasPrefix(n.Detail, "Google refused every account's app grants read.")
	}) ||
		!slices.ContainsFunc(notes, func(n Note) bool {
			return n.Kind == "workspace_credential_warning" && strings.Contains(n.Detail, "admin.directory.user.security")
		}) {
		t.Fatal(notes)
	}
	// Only scheck's own grant: the disproval says it was set aside.
	e, c = oauthFixture(oauthUser("amy"))
	e.Binding.AssessmentClient = appDrive
	grant(&e, 0, appDrive, "admin.directory.user.security")
	if a, ok := assetOutcome(e, c); !ok || a.Verdict != Disproved || !strings.Contains(a.Excerpt, "other than the grant set aside as scheck's own credential") {
		t.Fatalf("%+v", a)
	}
	// An installed app is hedged, and the raise names its source read and
	// says what the scopes do not reach.
	admin := oauthUser("root")
	admin.IsAdmin = new(true)
	e, c = oauthFixture(admin)
	grant(&e, 0, appDrive, "https://mail.google.com/")
	e.OAuth.Accounts[0].Grants[0].NativeApp = new(true)
	j := appResult(t, e, c, appDrive)
	if !strings.Contains(j.Excerpt, "Google's and Apple's own") || j.Details["admin_grant_read"] != "t-root" || !strings.HasSuffix(j.Why, "though not that account's other administrator rights.") || !strings.Contains(j.Why, "granted this app the scope https://mail.google.com/:") {
		t.Fatalf("%+v", j)
	}
}
