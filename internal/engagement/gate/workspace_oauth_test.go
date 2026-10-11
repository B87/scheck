package gate

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const optionalSeed = "opaque-google-optional-0123456789"
const securityScope = "https://www.googleapis.com/auth/admin.directory.user.security"

func wsTokensOp() Op {
	return Op{ID: "workspace.user_tokens", Provider: "google", Method: GET, URL: "https://admin.googleapis.com/admin/directory/v1/users/{user}/tokens",
		Subject: workspacePrefix + "{domain}/users/{user}", Params: []Param{{Name: "domain", Type: DNSName}, {Name: "user", Type: UserKey}}, Auth: WorkspaceADC, Surface: WorkspaceOAuthGrants,
		Level: Observe, Accept: []string{"application/json"}, Keep: []string{"clientId", "scopes", "userKey", "displayText", "anonymous", "nativeApp"}, MaxBytes: 1 << 20,
		List: &List{Items: "items", Kind: KindOther, Envelope: "admin#directory#tokenList", MaxItems: 1000, SelfRef: "userKey"}}
}

// oauthWorld is a tenant with two admitted accounts and an excluded one,
// whose token endpoint answers the baseline refresh with one token and the
// optional refresh as optional says.
type oauthWorld struct {
	w      *world
	api    *server
	mu     sync.Mutex
	forms  []string
	tokens func(user string) string
}

func newOAuthWorld(t *testing.T, profile string, optional func(http.ResponseWriter)) *oauthWorld {
	o := &oauthWorld{w: newWorld(t)}
	o.w.ops = append(wsInventoryOps(), wsTokensOp())
	o.w.scope.orgUnits = map[string][]OrgUnit{wsAsset: {{Path: "/Board", ExcludedBy: "board"}}}
	o.w.env["SCHECK_WORKSPACE_PROFILE"] = profile
	wsAuthorized(t, o.w)
	o.tokens = func(user string) string {
		return `{"kind":"admin#directory#tokenList","items":[{"clientId":"app.apps.googleusercontent.com","scopes":["https://www.googleapis.com/auth/drive"],"userKey":"` + user + `","displayText":"Docs","token":"NEVER_KEPT"}]}`
	}
	cert := o.w.leaf([]string{"oauth2.googleapis.com"}, time.Now().Add(time.Hour), false)
	o.w.serve("oauth2.googleapis.com", "142.250.0.11", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		o.mu.Lock()
		o.forms = append(o.forms, r.PostForm.Get("scope"))
		o.mu.Unlock()
		if r.PostForm.Has("scope") {
			optional(rw)
			return
		}
		jsonReply(200, wsTokenBody())(rw, r)
	})
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	o.api = o.w.google(func(rw http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case strings.HasSuffix(r.URL.Path, "/tokens"):
			if auth != "Bearer "+optionalSeed {
				t.Error("tokens read without the optional token:", auth)
			}
			user := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/users/"), "/tokens")
			jsonReply(200, o.tokens(user))(rw, r)
			return
		case auth == "Bearer "+optionalSeed:
			t.Error("baseline read with the optional token:", r.URL.Path)
		case strings.HasSuffix(r.URL.Path, "/orgunits"):
			jsonReply(200, unitEnvelope)(rw, r)
		case r.URL.Path == "/admin/directory/v1/users":
			jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("1", "alice@example.com", "/")+`,`+userRow("2", "bob@example.com", "/Boardroom")+`,`+userRow("3", "board@example.com", "/Board")+`]}`)(rw, r)
		default:
			bootstrap(rw, r)
		}
	})
	return o
}

func optionalToken(rw http.ResponseWriter) {
	jsonReply(200, fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":3600,"scope":%q}`, optionalSeed, securityScope))(rw, nil)
}

func (o *oauthWorld) admitted() *Gate {
	g := o.w.gate()
	wsBootstrap(g)
	g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	return g
}

func tokensRequest(user string) Request {
	r := wsInventoryRequest("workspace.user_tokens")
	r.Params["user"] = user
	return r
}

func (o *oauthWorld) tokenReads() int {
	n := 0
	for _, r := range o.api.requests() {
		if strings.HasSuffix(r.URL.Path, "/tokens") {
			n++
		}
	}
	return n
}

// The optional surface gets its own token, asked for with exactly its one
// scope after admission, never used for a baseline read and never the
// baseline token; the baseline refresh carries no scope
// (docs/spec/workspace-collector.md, "Credential files and profiles").
func TestWorkspaceOAuthUsesItsOwnScopedTokenOnce(t *testing.T) {
	o := newOAuthWorld(t, "directory_oauth", optionalToken)
	g := o.admitted()
	for _, user := range []string{"1", "2"} {
		res := g.Send(context.Background(), tokensRequest(user))
		if !res.OK() || !strings.Contains(string(res.Response.Body), `"userKey":"`+user+`"`) || strings.Contains(string(res.Response.Body), "NEVER_KEPT") {
			t.Fatal(res, string(res.Response.Body))
		}
	}
	if got := strings.Join(o.forms, "|"); got != "|"+securityScope {
		t.Fatalf("token requests carried scopes %q", got)
	}
	// Excluded and unadmitted accounts are never asked about.
	before := o.tokenReads()
	for _, user := range []string{"3", "board@example.com", "unknown"} {
		// One unadmitted account says nothing about the next one.
		if res := g.Send(context.Background(), tokensRequest(user)); res.OK() || res.Repeats {
			t.Fatal("unadmitted account read, or its refusal claimed to repeat", user, res)
		}
	}
	if o.tokenReads() != before {
		t.Fatal("an unadmitted account was contacted")
	}
	// A baseline read after the optional one still uses the baseline token.
	if res := g.Send(context.Background(), wsInventoryRequest("workspace.units")); !res.OK() {
		t.Fatal(res)
	}
	exchanges := map[string]bool{}
	for _, e := range g.Entries() {
		if e.Op == "workspace.credential_exchange_oauth_grants" {
			exchanges[e.RequestID] = true
		}
	}
	if len(exchanges) != 1 {
		t.Fatalf("%d audited optional exchanges", len(exchanges))
	}
}

func TestWorkspaceOAuthDeniedScopeIsOneRememberedPermissionGap(t *testing.T) {
	for _, tc := range []struct {
		name, reply, reason string
		status              int
	}{
		{"invalid scope", `{"error":"invalid_scope","error_description":"PRIVATE_PROVIDER_TEXT"}`, "insufficient_permission:admin.directory.user.security", 400},
		{"unauthorized client", `{"error":"unauthorized_client"}`, "insufficient_permission:admin.directory.user.security", 401},
		{"rate limited", `{}`, "limit_reached", 429},
		{"broken", `{"error":"server_error"}`, "unavailable:credential_exchange", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOAuthWorld(t, "directory_oauth_mail", func(rw http.ResponseWriter) { jsonReply(tc.status, tc.reply)(rw, nil) })
			g := o.admitted()
			for _, user := range []string{"1", "2"} {
				res := g.Send(context.Background(), tokensRequest(user))
				if res.OK() || res.Reason != tc.reason || !res.Repeats || strings.Contains(res.Detail, "PRIVATE_PROVIDER_TEXT") {
					t.Fatalf("%+v", res)
				}
			}
			if len(o.forms) != 2 || o.tokenReads() != 0 {
				t.Fatalf("forms %q, %d tokens reads", o.forms, o.tokenReads())
			}
			// The baseline is untouched by the optional failure.
			if res := g.Send(context.Background(), wsInventoryRequest("workspace.units")); !res.OK() {
				t.Fatal("an optional failure blocked a baseline read", res)
			}
		})
	}
}

func TestWorkspaceOAuthNeedsItsProfileAndAVerifiedServiceAccount(t *testing.T) {
	o := newOAuthWorld(t, "directory_mail", optionalToken)
	g := o.admitted()
	if res := g.Send(context.Background(), tokensRequest("1")); res.Decision != "unavailable:profile_not_selected" || !res.Repeats || len(o.forms) != 1 || o.tokenReads() != 0 {
		t.Fatal(res, o.forms)
	}

	o = newOAuthWorld(t, "directory_oauth", optionalToken)
	g = o.admitted()
	g.workspaceSource.kind = "service_account"
	if res := g.Send(context.Background(), tokensRequest("1")); res.Decision != "unavailable:principal_unknown" || len(o.forms) != 1 {
		t.Fatal("an unverified delegated account asked for the optional scope", res, o.forms)
	}
}

func TestWorkspaceOAuthTokenLivesNoLongerThanTheSession(t *testing.T) {
	o := newOAuthWorld(t, "directory_oauth", optionalToken)
	g := o.admitted()
	if !g.Send(context.Background(), tokensRequest("1")).OK() {
		t.Fatal("first read")
	}
	s := g.workspace[wsAsset]
	if s.optional[WorkspaceOAuthGrants].expires.After(s.expires) {
		t.Fatal("the optional token outlives the baseline authentication")
	}
	// A rebinding forgets the optional token; the next read asks again,
	// while the still-valid baseline token is kept.
	wsBootstrap(g)
	if s.optional != nil {
		t.Fatal("rebinding kept the optional token")
	}
	g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	if !g.Send(context.Background(), tokensRequest("1")).OK() || len(o.forms) != 3 {
		t.Fatal("no fresh optional exchange after rebinding", o.forms)
	}
	// A 401 on the optional token drops authentication altogether.
	o.tokens = func(string) string { return `{}` }
	o.api.reply = func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(401) }
	g.Send(context.Background(), tokensRequest("2"))
	if s.optional != nil || s.credential != nil || s.bound {
		t.Fatal("a 401 kept authentication")
	}
}

func TestWorkspaceOAuthDropsGrantsOfAnyoneElseAndCapsPopulation(t *testing.T) {
	o := newOAuthWorld(t, "directory_oauth", optionalToken)
	o.tokens = func(string) string {
		return `{"kind":"admin#directory#tokenList","items":[{"clientId":"a","scopes":["openid"],"userKey":"1"},{"clientId":"SECRET_OTHER","scopes":["openid"],"userKey":"2"},{"clientId":"SECRET_NONE","scopes":["openid"]}]}`
	}
	g := o.admitted()
	res := g.Send(context.Background(), tokensRequest("1"))
	if !res.OK() || strings.Contains(string(res.Response.Body), "SECRET_") || res.Response.Population == nil || len(res.Response.Population.Incomplete) == 0 {
		t.Fatal(res)
	}
	o.tokens = func(user string) string {
		items := strings.Repeat(`{"clientId":"a","scopes":["openid"],"userKey":"`+user+`"},`, 1001)
		return `{"kind":"admin#directory#tokenList","items":[` + strings.TrimSuffix(items, ",") + `]}`
	}
	if res := g.Send(context.Background(), tokensRequest("2")); res.OK() || res.Reason != "limit_reached" {
		t.Fatal("more than 1,000 grants were kept", res)
	}
	o.tokens = func(string) string { return `{"kind":"admin#directory#tokens","items":[]}` }
	if res := g.Send(context.Background(), tokensRequest("1")); res.OK() {
		t.Fatal("a foreign envelope was accepted")
	}
}

func TestWorkspaceOAuthRegistryRejectsWidening(t *testing.T) {
	if _, err := NewRegistry(append(wsInventoryOps(), wsTokensOp())...); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Op){
		"baseline surface":  func(o *Op) { o.Surface = WorkspaceBaseline },
		"query":             func(o *Op) { o.URL += "?customer={customer}" },
		"token value kept":  func(o *Op) { o.Keep = append(o.Keep, "token") },
		"no self reference": func(o *Op) { o.List.SelfRef = "" },
		"paged":             func(o *Op) { o.List.Next = &Pages{Param: "page_token", Field: "nextPageToken"} },
		"other envelope":    func(o *Op) { o.List.Envelope = "admin#directory#tokens" },
		"other path":        func(o *Op) { o.URL = "https://admin.googleapis.com/admin/directory/v1/users/{user}/asps" },
		"unknown surface":   func(o *Op) { o.Surface = "gmail_everything" },
	} {
		o := wsTokensOp()
		l := *o.List
		o.List = &l
		mutate(&o)
		if _, err := NewRegistry(append(wsInventoryOps(), o)...); err == nil {
			t.Fatal("widened OAuth op admitted:", name)
		}
	}
	detail := wsInventoryOps()[6]
	detail.Surface = WorkspaceOAuthGrants
	if _, err := NewRegistry(append(wsInventoryOps()[:6], detail)...); err == nil {
		t.Fatal("a baseline read took the optional surface")
	}
	if _, err := NewRegistry(Op{ID: "web.x", Provider: "web", Method: GET, URL: "https://{host}/", Params: []Param{{Name: "host", Type: Host}}, Subject: "domain:{host}", Surface: WorkspaceOAuthGrants, Accept: []string{"text/html"}, MaxBytes: 1 << 10}); err == nil {
		t.Fatal("a non-Workspace op took an optional surface")
	}
}

// A service account asserts exactly the optional scope; an authorized_user
// refresh asks for exactly that scope, while its baseline refresh asks for
// none.
func TestWorkspaceOptionalExchangeFormsCarryOnlyTheirScope(t *testing.T) {
	scopes, _ := profileScopes("directory_oauth")
	source := &googleSource{kind: "authorized_user", clientID: "c", clientSecret: "s", refreshToken: "r", scopes: scopes}
	base, err := source.exchange(time.Now(), WorkspaceBaseline)
	if err != nil || base.form.Has("scope") {
		t.Fatal("the baseline refresh asked for a scope", base.form)
	}
	opt, err := source.exchange(time.Now(), WorkspaceOAuthGrants)
	if err != nil || opt.form.Get("scope") != securityScope || opt.surface != WorkspaceOAuthGrants {
		t.Fatal(opt.form)
	}
	if _, err := source.exchange(time.Now(), "unknown"); err == nil {
		t.Fatal("an uncompiled surface built an exchange")
	}
}

func TestWorkspaceOAuthPerAccountDenialNamesTheScope(t *testing.T) {
	o := newOAuthWorld(t, "directory_oauth", optionalToken)
	g := o.admitted()
	o.api.reply = func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tokens") {
			rw.WriteHeader(403)
		}
	}
	res := g.Send(context.Background(), tokensRequest("1"))
	if res.Reason != "insufficient_permission:admin.directory.user.security" || res.Repeats {
		t.Fatal(res)
	}
	s := g.workspace[wsAsset]
	if !s.bound || s.optional[WorkspaceOAuthGrants].credential == nil {
		t.Fatal("a per-account denial dropped the session")
	}
}

// A Google 403 that is a rate limit is a limit, never a missing permission,
// and a 404 names no scope.
func TestWorkspaceOAuthRateLimitedForbiddenIsALimit(t *testing.T) {
	o := newOAuthWorld(t, "directory_oauth", optionalToken)
	g := o.admitted()
	o.api.reply = func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tokens/") || strings.HasSuffix(r.URL.Path, "/1/tokens") {
			jsonReply(403, `{"error":{"errors":[{"reason":"userRateLimitExceeded","message":"PRIVATE_QUOTA_TEXT"}]}}`)(rw, r)
			return
		}
		rw.WriteHeader(404)
	}
	if res := g.Send(context.Background(), tokensRequest("1")); res.Reason != "limit_reached" || !res.Repeats || res.Response != nil && strings.Contains(string(res.Response.Body), "PRIVATE_QUOTA_TEXT") {
		t.Fatal(res)
	}
	// Google's limit held through the retries: the provider is stopped, and
	// every later read says so without sending.
	if res := g.Send(context.Background(), tokensRequest("2")); res.Decision != "refused:rate_limit" || !res.Repeats {
		t.Fatal(res)
	}
	o = newOAuthWorld(t, "directory_oauth", optionalToken)
	g = o.admitted()
	o.api.reply = func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(404) }
	if res := g.Send(context.Background(), tokensRequest("2")); res.Reason != "insufficient_permission" {
		t.Fatal("a 404 named the optional scope", res)
	}
}
