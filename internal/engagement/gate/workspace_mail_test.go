package gate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const gmailScope = "https://www.googleapis.com/auth/gmail.readonly"
const mailSeed = "ghp_0123456789abcdefABCDEF0123456789abcd"

func wsMailOps() []Op {
	op := func(id, path string, keep []string) Op {
		return Op{ID: id, Provider: "google", Method: GET, URL: "https://gmail.googleapis.com/gmail/v1/users/me/settings/" + path,
			Subject: workspacePrefix + "{domain}/users/{user}", Params: []Param{{Name: "domain", Type: DNSName}, {Name: "user", Type: UserKey}}, Auth: WorkspaceADC, Surface: WorkspaceGmailForwarding,
			Level: Observe, Accept: []string{"application/json"}, Keep: keep, MaxBytes: 1 << 20}
	}
	auto := op("workspace.mail_auto_forwarding", "autoForwarding", []string{"enabled", "emailAddress", "disposition"})
	filters := op("workspace.mail_filters", "filters", []string{"id", "action.forward", "action.addLabelIds", "action.removeLabelIds"})
	filters.List = &List{Items: "filter", Kind: KindOther, MaxItems: 1000}
	return []Op{auto, filters}
}

// mailWorld is a tenant read through a service account acting as
// admin@example.com: five active mailboxes, an excluded one, a suspended one
// and one without a mailbox. The token endpoint answers each assertion as
// exchange says, and Gmail answers as gmail says.
type mailWorld struct {
	w        *world
	gmail    *server
	mu       sync.Mutex
	claims   []map[string]any
	exchange func(sub, scope string) (int, string)
	reply    func(user, path string) (int, string)
}

func mailUserRow(id, email, unit, extra string) string {
	return fmt.Sprintf(`{"id":%q,"primaryEmail":%q,"customerId":"C-opaque-123","orgUnitPath":%q,"isAdmin":false,"suspended":false,"archived":false%s}`, id, email, unit, extra)
}

func newMailWorld(t *testing.T, profile string) *mailWorld {
	m := &mailWorld{w: newWorld(t)}
	m.w.ops = append(append(wsInventoryOps(), wsTokensOp()), wsMailOps()...)
	m.w.scope.orgUnits = map[string][]OrgUnit{wsAsset: {{Path: "/Board", ExcludedBy: "board"}}}
	m.w.env["SCHECK_WORKSPACE_PROFILE"] = profile
	m.w.env["SCHECK_WORKSPACE_SUBJECT"] = "admin@example.com"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "assessment@project.iam.gserviceaccount.com", "private_key_id": "kid1", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	wsFile(t, m.w, string(raw))
	m.exchange = func(sub, scope string) (int, string) {
		if scope == gmailScope {
			return 200, fmt.Sprintf(`{"access_token":"mail-%s-0123456789","token_type":"Bearer","expires_in":3600}`, strings.Split(sub, "@")[0])
		}
		return 200, wsTokenBody()
	}
	m.reply = func(_, path string) (int, string) {
		if strings.HasSuffix(path, "/filters") {
			return 200, `{"filter":[{"id":"f1","criteria":{"query":"` + mailSeed + `","from":"boss@example.com"},"action":{"forward":"copy@gmail.com","addLabelIds":["TRASH"],"removeLabelIds":["INBOX"]}}]}`
		}
		return 200, `{"enabled":true,"emailAddress":"copy@gmail.com","disposition":"trash"}`
	}
	cert := m.w.leaf([]string{"oauth2.googleapis.com"}, time.Now().Add(time.Hour), false)
	m.w.serve("oauth2.googleapis.com", "142.250.0.11", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		claims := map[string]any{}
		if len(parts) == 3 {
			body, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(body, &claims)
		}
		m.mu.Lock()
		m.claims = append(m.claims, claims)
		m.mu.Unlock()
		sub, _ := claims["sub"].(string)
		scope, _ := claims["scope"].(string)
		status, body := m.exchange(sub, scope)
		if status < 0 {
			// The connection drops after the assertion was sent.
			if conn, _, err := rw.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		jsonReply(status, body)(rw, r)
	})
	users := []string{mailUserRow("1", "alice@example.com", "/", ""), mailUserRow("2", "bob@example.com", "/", ""), mailUserRow("6", "carol@example.com", "/", ""),
		mailUserRow("7", "dan@example.com", "/", ""), mailUserRow("8", "erin@example.com", "/", ""), mailUserRow("9", "admin@example.com", "/", ""),
		mailUserRow("3", "board@example.com", "/Board", ""), mailUserRow("4", "gone@example.com", "/", `,"suspended":true`), mailUserRow("5", "nobox@example.com", "/", `,"isMailboxSetup":false`)}
	for i, u := range users {
		users[i] = strings.Replace(u, `"suspended":false,"archived":false,"suspended":true`, `"suspended":true,"archived":false`, 1)
	}
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	m.w.google(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/orgunits"):
			jsonReply(200, unitEnvelope)(rw, r)
		case r.URL.Path == "/admin/directory/v1/users":
			jsonReply(200, `{"kind":"admin#directory#users","users":[`+strings.Join(users, ",")+`]}`)(rw, r)
		case r.URL.Path == "/admin/directory/v1/users/9":
			jsonReply(200, users[5])(rw, r)
		default:
			bootstrap(rw, r)
		}
	})
	gcert := m.w.leaf([]string{"gmail.googleapis.com"}, time.Now().Add(time.Hour), false)
	m.gmail = m.w.serve("gmail.googleapis.com", "142.250.0.12", 443, &gcert, func(rw http.ResponseWriter, r *http.Request) {
		user := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer mail-"), "-0123456789")
		status, body := m.reply(user, r.URL.Path)
		jsonReply(status, body)(rw, r)
	})
	return m
}

func (m *mailWorld) admitted() *Gate {
	g := m.w.gate()
	wsBootstrap(g)
	g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	g.Send(context.Background(), wsInventoryRequest("workspace.delegated_user"))
	return g
}

func mailRequest(op, user string) Request {
	r := wsInventoryRequest(op)
	r.Params["user"] = user
	return r
}

// mailExchanges are the subjects the per-mailbox exchanges acted as.
func (m *mailWorld) mailExchanges() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, c := range m.claims {
		if c["scope"] == gmailScope {
			out = append(out, c["sub"].(string))
		}
	}
	return out
}

func (m *mailWorld) gmailPaths() []string {
	out := []string{}
	for _, r := range m.gmail.requests() {
		out = append(out, r.Header.Get("Authorization")+" "+r.URL.Path)
	}
	return out
}

// Each admitted mailbox gets its own token, asked for with exactly
// gmail.readonly and acting as the gate's own record of that account; the
// read names users/me, keeps only the pinned fields, and the audit names
// the account id, never its address (docs/spec/workspace-collector.md,
// "Boundary").
func TestWorkspaceMailSignsInAsEachAdmittedMailbox(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	g := m.admitted()
	if g.workspace[wsAsset].principal != "9" {
		t.Fatal("delegated account not verified")
	}
	for _, user := range []string{"1", "2", "1"} {
		for _, op := range []string{"workspace.mail_auto_forwarding", "workspace.mail_filters"} {
			res := g.Send(context.Background(), mailRequest(op, user))
			if !res.OK() || strings.Contains(string(res.Response.Body), mailSeed) || strings.Contains(string(res.Response.Body), "boss@") || len(res.Response.Redactions) != 0 {
				t.Fatalf("%s %s: %+v %s", op, user, res, res.Response.Body)
			}
			if op == "workspace.mail_filters" && string(res.Response.Body) != `[{"action":{"addLabelIds":["TRASH"],"forward":"copy@gmail.com","removeLabelIds":["INBOX"]},"id":"f1"}]` {
				t.Fatal(string(res.Response.Body))
			}
		}
	}
	if got := m.mailExchanges(); !slices.Equal(got, []string{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("mailbox exchanges acted as %v", got)
	}
	for _, c := range m.claims {
		if c["scope"] == gmailScope && (c["iss"] != "assessment@project.iam.gserviceaccount.com" || c["aud"] != workspaceTokenURL) {
			t.Fatal(c)
		}
	}
	if paths := m.gmailPaths(); len(paths) != 6 || paths[0] != "Bearer mail-alice-0123456789 /gmail/v1/users/me/settings/autoForwarding" || paths[3] != "Bearer mail-bob-0123456789 /gmail/v1/users/me/settings/filters" {
		t.Fatal(paths)
	}
	exchanges := map[string]string{}
	for _, e := range g.Entries() {
		if e.Op == "workspace.credential_exchange_gmail_forwarding" {
			exchanges[e.RequestID] = e.Params["user"]
		}
		if strings.HasPrefix(e.Op, "workspace.mail_") && (e.Params["user"] == "" || !strings.Contains(e.URL, "/users/me/")) {
			t.Fatal("a mail read's audit line does not name the mailbox it used", e)
		}
	}
	if len(exchanges) != 2 || !slices.Contains(slices.Collect(func(yield func(string) bool) {
		for _, v := range exchanges {
			yield(v)
		}
	}), "1") {
		t.Fatal(exchanges)
	}
	for _, s := range []string{mailSeed, "boss@example.com", "alice@example.com", "mail-alice-0123456789"} {
		if strings.Contains(m.w.audit.String(), s) {
			t.Fatalf("audit holds %q", s)
		}
	}
	// Excluded, unadmitted, suspended and mailbox-less accounts are never
	// signed in as or read.
	before, gmail := len(m.mailExchanges()), len(m.gmailPaths())
	for user, want := range map[string]string{"3": "refused:", "board@example.com": "refused:", "unknown": "refused:", "4": "unavailable:mailbox_inactive", "5": "unavailable:mailbox_inactive", "alice@example.com": "refused:tenant_binding"} {
		res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", user))
		if res.OK() || res.Repeats || !strings.HasPrefix(res.Decision, want) {
			t.Fatal(user, res)
		}
	}
	if len(m.mailExchanges()) != before || len(m.gmailPaths()) != gmail {
		t.Fatal("an account scheck may not read was signed in as or contacted")
	}
}

func TestWorkspaceMailExchangeFailures(t *testing.T) {
	for _, tc := range []struct {
		name, reply, reason string
		status              int
		wide                bool
	}{
		{"scope not delegated", `{"error":"unauthorized_client","error_description":"PRIVATE_PROVIDER_TEXT"}`, "insufficient_permission:gmail.readonly", 401, true},
		{"invalid scope", `{"error":"invalid_scope"}`, "insufficient_permission:gmail.readonly", 400, true},
		{"rate limited", `{}`, "limit_reached", 429, true},
		{"one mailbox refused", `{"error":"invalid_grant","error_description":"PRIVATE_PROVIDER_TEXT"}`, "unavailable:mailbox_credential", 400, false},
		{"policy for one mailbox", `{"error":"admin_policy_enforced"}`, "insufficient_permission:gmail.readonly", 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMailWorld(t, "directory_oauth_mail")
			base := m.exchange
			m.exchange = func(sub, scope string) (int, string) {
				if scope == gmailScope && sub == "alice@example.com" {
					return tc.status, tc.reply
				}
				return base(sub, scope)
			}
			g := m.admitted()
			first := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1"))
			if first.OK() || first.Reason != tc.reason || first.Repeats != tc.wide || strings.Contains(first.Detail, "PRIVATE_PROVIDER_TEXT") {
				t.Fatalf("%+v", first)
			}
			// The failure is remembered: the mailbox's filters read sends nothing.
			again := g.Send(context.Background(), mailRequest("workspace.mail_filters", "1"))
			if again.OK() || again.Reason != tc.reason || len(m.mailExchanges()) != 1 {
				t.Fatalf("%+v %v", again, m.mailExchanges())
			}
			second := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "2"))
			if tc.wide == second.OK() || tc.wide && (!second.Repeats || len(m.mailExchanges()) != 1) {
				t.Fatalf("a surface-wide failure was not remembered, or a mailbox's own was: %+v", second)
			}
			if len(m.gmailPaths()) != map[bool]int{true: 0, false: 1}[tc.wide] {
				t.Fatal(m.gmailPaths())
			}
			if res := g.Send(context.Background(), wsInventoryRequest("workspace.units")); !res.OK() {
				t.Fatal("a mail failure blocked a baseline read", res)
			}
		})
	}
}

// A revoked key looks like one mailbox failing after another: a binding's
// first exchanges all failing stop the surface.
func TestWorkspaceMailBreakerAndCap(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	m.exchange = func(_, scope string) (int, string) {
		if scope == gmailScope {
			return 400, `{"error":"invalid_grant"}`
		}
		return 200, wsTokenBody()
	}
	g := m.admitted()
	for i, user := range []string{"1", "2", "6", "7", "8"} {
		res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", user))
		if res.Repeats != (i == 4) {
			t.Fatal(i, res)
		}
	}
	if res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "9")); res.Decision != "unavailable:credential_exchange" || !res.Repeats || len(m.mailExchanges()) != 5 {
		t.Fatal(res, m.mailExchanges())
	}

	m = newMailWorld(t, "directory_mail")
	g = m.admitted()
	g.workspace[wsAsset].exchanges = map[WorkspaceSurface]int{WorkspaceGmailForwarding: mailboxExchangeCap}
	if res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")); res.Reason != "limit_reached" || !res.Repeats || len(m.mailExchanges()) != 0 {
		t.Fatal("the session's exchange cap did not stop the surface", res)
	}
	// A rebinding does not reset the session's cap.
	wsBootstrap(g)
	if g.workspace[wsAsset].exchanges[WorkspaceGmailForwarding] != mailboxExchangeCap {
		t.Fatal("a rebinding reset the exchange count")
	}
}

func TestWorkspaceMailNeedsServiceAccountProfileAndPrincipal(t *testing.T) {
	m := newMailWorld(t, "directory_oauth")
	g := m.admitted()
	if res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")); res.Decision != "unavailable:profile_not_selected" || !res.Repeats {
		t.Fatal(res)
	}
	m = newMailWorld(t, "directory_mail")
	g = m.admitted()
	g.workspaceSource.kind = "authorized_user"
	m.w.env["SCHECK_WORKSPACE_SUBJECT"] = ""
	if res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")); res.Reason != "unavailable:needs_service_account" || !res.Repeats || len(m.mailExchanges()) != 0 {
		t.Fatal(res)
	}
	m = newMailWorld(t, "directory_mail")
	g = m.admitted()
	g.workspace[wsAsset].principal = ""
	if res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")); res.Decision != "unavailable:principal_unknown" || len(m.mailExchanges()) != 0 {
		t.Fatal(res)
	}
}

func TestWorkspaceMailTokensLiveNoLongerThanTheBinding(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	g := m.admitted()
	if !g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")).OK() {
		t.Fatal("first read")
	}
	s := g.workspace[wsAsset]
	if tok := s.optional[WorkspaceGmailForwarding].tokens["1"]; tok == nil || tok.expires.After(s.expires) {
		t.Fatal("a mailbox token outlives the baseline authentication")
	}
	// Mailbox B's read never carries mailbox A's token.
	if !g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "2")).OK() {
		t.Fatal("second mailbox")
	}
	paths := m.gmailPaths()
	if !strings.HasPrefix(paths[1], "Bearer mail-bob-") {
		t.Fatal(paths)
	}
	wsBootstrap(g)
	if s.optional != nil {
		t.Fatal("rebinding kept mailbox tokens")
	}
	g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	g.Send(context.Background(), wsInventoryRequest("workspace.delegated_user"))
	if !g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")).OK() || len(m.mailExchanges()) != 3 {
		t.Fatal("no fresh mailbox exchange after rebinding", m.mailExchanges())
	}
	// A 401 on a mailbox token drops authentication and binding.
	m.reply = func(string, string) (int, string) { return 401, `{}` }
	g.Send(context.Background(), mailRequest("workspace.mail_filters", "1"))
	if s.optional != nil || s.credential != nil || s.bound {
		t.Fatal("a 401 kept authentication")
	}
}

func TestWorkspaceMailReadOutcomes(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	g := m.admitted()
	for _, tc := range []struct {
		name, body, reason string
		status             int
		ok                 bool
	}{
		{"empty filters", `{}`, "", 200, true},
		{"over the cap", `{"filter":[` + strings.TrimSuffix(strings.Repeat(`{"id":"x"},`, 1001), ",") + `]}`, "limit_reached", 200, false},
		{"member not an object", `{"filter":["x"]}`, "", 200, false},
		{"null list", `{"filter":null}`, "", 200, false},
		{"no Gmail service", `{"error":{"code":400}}`, "unavailable:mailbox_unavailable", 400, false},
		{"denied", `{"error":{"code":403}}`, "insufficient_permission:gmail.readonly", 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m.reply = func(string, string) (int, string) { return tc.status, tc.body }
			res := g.Send(context.Background(), mailRequest("workspace.mail_filters", "1"))
			if res.OK() != tc.ok || tc.reason != "" && res.Reason != tc.reason || res.Repeats {
				t.Fatalf("%+v", res)
			}
		})
	}
	// A malformed kept field stays visible as itself or null, never dropped.
	m.reply = func(string, string) (int, string) {
		return 200, `{"filter":[{"id":"x","action":{"forward":7}},{"id":"y","action":"forward"}]}`
	}
	res := g.Send(context.Background(), mailRequest("workspace.mail_filters", "1"))
	if !res.OK() || string(res.Response.Body) != `[{"action":{"forward":7},"id":"x"},{"action":null,"id":"y"}]` {
		t.Fatal(res, string(res.Response.Body))
	}
}

func TestWorkspaceMailRegistryRejectsWidening(t *testing.T) {
	ops := append(wsInventoryOps(), wsMailOps()...)
	if _, err := NewRegistry(ops...); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Op){
		"messages":           func(o *Op) { o.URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages" },
		"forwarding address": func(o *Op) { o.URL = "https://gmail.googleapis.com/gmail/v1/users/me/settings/forwardingAddresses" },
		"delegates":          func(o *Op) { o.URL = "https://gmail.googleapis.com/gmail/v1/users/me/settings/delegates" },
		"another mailbox":    func(o *Op) { o.URL = "https://gmail.googleapis.com/gmail/v1/users/{user}/settings/filters" },
		"query":              func(o *Op) { o.URL += "?q=x" },
		"criteria kept":      func(o *Op) { o.Keep = append(o.Keep, "criteria.query") },
		"message kept":       func(o *Op) { o.Keep = append(o.Keep, "payload") },
		"baseline surface":   func(o *Op) { o.Surface = WorkspaceBaseline },
		"other surface":      func(o *Op) { o.Surface = WorkspaceOAuthGrants },
		"envelope":           func(o *Op) { o.List.Envelope = "gmail#filters" },
		"paged":              func(o *Op) { o.List.Next = &Pages{Param: "page_token", Field: "nextPageToken"} },
		"bigger":             func(o *Op) { o.List.MaxItems = 5000 },
		"no credential":      func(o *Op) { o.Auth = NoAuth; o.Surface = WorkspaceBaseline },
		"no user":            func(o *Op) { o.Params = o.Params[:1]; o.Subject = workspacePrefix + "{domain}" },
	} {
		o := wsMailOps()[1]
		l := *o.List
		o.List = &l
		mutate(&o)
		if _, err := NewRegistry(append(wsInventoryOps(), o)...); err == nil {
			t.Fatal("widened mail op admitted:", name)
		}
	}
	tokens := wsTokensOp()
	tokens.URL = "https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding"
	tokens.List = nil
	if _, err := NewRegistry(append(wsInventoryOps(), tokens)...); err == nil {
		t.Fatal("another surface read a mail setting")
	}
}

// A mailbox exchange is a service account acting as an admitted account,
// with exactly gmail.readonly.
func TestWorkspaceMailboxExchangeClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	source := &googleSource{kind: "service_account", issuer: "a@p.iam.gserviceaccount.com", subject: "admin@example.com", keyID: "k", key: key}
	at := time.Unix(1791630000, 0)
	ex, err := source.mailboxExchange(at, WorkspaceGmailForwarding, "alice@example.com", "1")
	if err != nil || ex.user != "1" {
		t.Fatal(err)
	}
	body, _ := base64.RawURLEncoding.DecodeString(strings.Split(ex.form.Get("assertion"), ".")[1])
	c := map[string]any{}
	_ = json.Unmarshal(body, &c)
	if c["sub"] != "alice@example.com" || c["scope"] != gmailScope || c["iss"] != source.issuer || len(c) != 6 {
		t.Fatal(c)
	}
	for name, call := range map[string]func() error{
		"no subject": func() error { _, err := source.mailboxExchange(at, WorkspaceGmailForwarding, "", "1"); return err },
		"tenant surface": func() error {
			_, err := source.mailboxExchange(at, WorkspaceOAuthGrants, "alice@example.com", "1")
			return err
		},
		"without acting": func() error { _, err := source.exchange(at, WorkspaceGmailForwarding); return err },
		"authorized user": func() error {
			s := *source
			s.kind = "authorized_user"
			_, err := s.mailboxExchange(at, WorkspaceGmailForwarding, "a@example.com", "1")
			return err
		},
	} {
		if call() == nil {
			t.Fatal("built a mailbox exchange:", name)
		}
	}
	// Each surface's profile offer names the profile that adds it.
	if o := workspaceOffers("directory_oauth"); o[WorkspaceGmailForwarding] != "directory_oauth_mail" || len(o) != 1 {
		t.Fatal(o)
	}
	if o := workspaceOffers("directory"); o[WorkspaceGmailForwarding] != "directory_mail" || o[WorkspaceOAuthGrants] != "directory_oauth" {
		t.Fatal(o)
	}
}

// A sign-in refused before it reached Google (a passed deadline) is the
// surface's limit, never one mailbox's failure: it stops the surface with
// limit_reached, counts toward neither the breaker nor the cap.
func TestWorkspaceMailDeadlineIsTheSurfacesLimit(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	g := m.admitted()
	if !g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1")).OK() {
		t.Fatal("first read")
	}
	g.deadline = time.Now().Add(-time.Minute)
	res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "2"))
	if res.OK() || res.Reason != "limit_reached" || !res.Repeats || res.Decision == "unavailable:mailbox_credential" || res.ActedAsMailbox {
		t.Fatalf("%+v", res)
	}
	s := g.workspace[wsAsset]
	if s.exchanges[WorkspaceGmailForwarding] != 1 || s.optional[WorkspaceGmailForwarding].attempts != 1 || len(m.mailExchanges()) != 1 {
		t.Fatal("a sign-in that never reached Google was counted", s.exchanges, s.optional[WorkspaceGmailForwarding].attempts)
	}
	if again := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "6")); again.Reason != "limit_reached" || !again.Repeats {
		t.Fatal(again)
	}
}

// The Gmail API off in the project answers every mailbox alike: the first
// read stops the surface, and no other mailbox is signed in as.
func TestWorkspaceMailAPIDisabledStopsTheSurface(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	m.reply = func(string, string) (int, string) {
		return 403, `{"error":{"code":403,"message":"PRIVATE_PROJECT_TEXT","errors":[{"reason":"accessNotConfigured"}],"details":[{"reason":"SERVICE_DISABLED"}]}}`
	}
	g := m.admitted()
	res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1"))
	if res.Reason != "unavailable:api_disabled" || !res.Repeats || !res.ActedAsMailbox || res.Response != nil && strings.Contains(string(res.Response.Body), "PRIVATE_PROJECT_TEXT") {
		t.Fatalf("%+v", res)
	}
	if again := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "2")); again.Reason != "unavailable:api_disabled" || !again.Repeats || len(m.mailExchanges()) != 1 || len(m.gmailPaths()) != 1 {
		t.Fatal(again, m.mailExchanges())
	}
}

// A mailbox scheck signed in as says so on every read, whatever the read
// then did.
func TestWorkspaceMailReadsSayTheyActedAsTheMailbox(t *testing.T) {
	m := newMailWorld(t, "directory_mail")
	m.reply = func(string, string) (int, string) { return 400, `{"error":{"code":400}}` }
	g := m.admitted()
	for _, op := range []string{"workspace.mail_auto_forwarding", "workspace.mail_filters"} {
		if res := g.Send(context.Background(), mailRequest(op, "1")); res.OK() || !res.ActedAsMailbox || res.Reason != "unavailable:mailbox_unavailable" {
			t.Fatal(res)
		}
	}
	if res := g.Send(context.Background(), wsInventoryRequest("workspace.units")); res.ActedAsMailbox {
		t.Fatal("a Directory read claimed a mailbox sign-in")
	}
}

func TestWorkspaceMailBreakerTripsOnTwentyInARow(t *testing.T) {
	opt := &workspaceOptional{tokens: map[string]*workspaceToken{}}
	mailboxOutcome(opt, &workspaceToken{}, failMailbox)
	for i := range breakerInARow {
		if opt.failure != nil {
			t.Fatal("tripped after", i)
		}
		opt.attempts++
		mailboxOutcome(opt, &workspaceToken{failure: &halt{decision: "unavailable:credential_exchange", sticky: true}}, failMailbox)
	}
	if opt.failure == nil || opt.failure.decision != "unavailable:credential_exchange" || !opt.failure.sticky {
		t.Fatal("twenty failures in a row after a success did not stop the surface")
	}
}

func TestWorkspaceGmailHostTakesOnlyPinnedWorkspaceReads(t *testing.T) {
	_, err := NewRegistry(Op{ID: "other.mail", Provider: "google", Method: GET, URL: "https://gmail.googleapis.com/gmail/v1/users/me/settings/autoForwarding",
		Subject: workspacePrefix + "{domain}", Params: []Param{{Name: "domain", Type: DNSName}}, Level: Observe, Accept: []string{"application/json"}, Keep: []string{"enabled"}, MaxBytes: 1 << 20})
	if err == nil || !strings.Contains(err.Error(), "only a pinned Workspace read reaches the Gmail host") {
		t.Fatal(err)
	}
}

// Google failing to answer one mailbox's sign-in (a dropped connection, a
// server error) fails that mailbox alone, keeps its own reason, counts
// toward the breaker and the cap, and still counts as asking Google to act
// as it.
func TestWorkspaceMailUnansweredSignInIsThatMailboxs(t *testing.T) {
	for name, status := range map[string]int{"dropped": -1, "server error": 503} {
		t.Run(name, func(t *testing.T) {
			m := newMailWorld(t, "directory_mail")
			base := m.exchange
			m.exchange = func(sub, scope string) (int, string) {
				if scope == gmailScope && sub == "alice@example.com" {
					return status, `{"error":"backendError"}`
				}
				return base(sub, scope)
			}
			g := m.admitted()
			res := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "1"))
			if res.OK() || res.Repeats || !res.ActedAsMailbox || res.Reason == "unavailable:mailbox_credential" || strings.Contains(res.Detail, "refused") {
				t.Fatalf("%+v", res)
			}
			s := g.workspace[wsAsset]
			if s.exchanges[WorkspaceGmailForwarding] != 1 || s.optional[WorkspaceGmailForwarding].failedInARow != 1 {
				t.Fatal("an unanswered sign-in was not counted", s.exchanges)
			}
			if next := g.Send(context.Background(), mailRequest("workspace.mail_auto_forwarding", "2")); !next.OK() {
				t.Fatal("one mailbox's unanswered sign-in stopped the surface", next)
			}
		})
	}
}
