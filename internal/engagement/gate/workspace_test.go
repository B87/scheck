package gate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/policy"
)

const wsAsset = "saas:google-workspace:example.com"
const refreshSeed = "seed-refresh-value-0123456789"
const secretSeed = "seed-client-secret-0123456789"
const accessSeed = "opaque-google-bearer-0123456789"

func wsFoundationOps() []Op {
	var ops []Op
	for _, r := range []struct {
		id, path string
		keep     []string
	}{
		{"workspace.bootstrap_customer", "/customers/my_customer", []string{"id"}},
		{"workspace.bootstrap_domains", "/customer/{customer}/domains", []string{"domains.domainName", "domains.verified"}},
		{"workspace.bootstrap_aliases", "/customer/{customer}/domainaliases", []string{"domainAliases.domainAliasName", "domainAliases.parentDomainName", "domainAliases.verified"}},
		{"workspace.customer", "/customers/{customer}", []string{"id"}},
	} {
		params := []Param{{Name: "domain", Type: DNSName}}
		if r.id != "workspace.bootstrap_customer" {
			params = append(params, Param{Name: "customer", Type: CustomerID})
		}
		ops = append(ops, Op{ID: r.id, Provider: "google", Method: GET, URL: "https://admin.googleapis.com/admin/directory/v1" + r.path, Subject: workspacePrefix + "{domain}", Params: params, Auth: WorkspaceADC, Level: Observe, Accept: []string{"application/json"}, Keep: r.keep, MaxBytes: 1 << 20})
	}
	return ops
}
func wsFile(t *testing.T, w *world, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	w.env["GOOGLE_APPLICATION_CREDENTIALS"] = path
}
func wsAuthorized(t *testing.T, w *world) {
	wsFile(t, w, fmt.Sprintf(`{"type":"authorized_user","client_id":"client.apps.googleusercontent.com","client_secret":%q,"refresh_token":%q}`, secretSeed, refreshSeed))
}
func wsTokenServer(w *world, body string, status int) *server {
	cert := w.leaf([]string{"oauth2.googleapis.com"}, time.Now().Add(time.Hour), false)
	return w.serve("oauth2.googleapis.com", "142.250.0.11", 443, &cert, jsonReply(status, body))
}
func wsTokenBody() string {
	return fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, accessSeed)
}
func wsBootstrap(g *Gate) []Result {
	var results []Result
	for _, op := range []string{"workspace.bootstrap_customer", "workspace.bootstrap_domains", "workspace.bootstrap_aliases"} {
		r := g.Send(context.Background(), Request{Op: op, Asset: wsAsset, Params: map[string]string{"domain": "example.com"}, Stage: "recon"})
		results = append(results, r)
		if !r.OK() {
			break
		}
	}
	return results
}
func wsReply(domains, aliases string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessSeed {
			rw.WriteHeader(401)
			return
		}
		body := `{"id":"C-opaque-123","customerDomain":"foreign.invalid","postalAddress":{"secret":"PRIVATE_CONTACT"}}`
		if strings.HasSuffix(r.URL.Path, "/domains") {
			body = domains
		}
		if strings.HasSuffix(r.URL.Path, "/domainaliases") {
			body = aliases
		}
		jsonReply(200, body)(rw, r)
	}
}
func TestWorkspaceBindingAndPrivateEvidence(t *testing.T) {
	for _, tc := range []struct{ name, domains, aliases string }{
		{"primary", `{"domains":[{"domainName":"example.com","verified":true},{"domainName":"foreign.invalid","verified":true}]}`, `{}`},
		{"secondary", `{"domains":[{"domainName":"primary.invalid","verified":true},{"domainName":"example.com","verified":true}]}`, `{"domainAliases":[]}`},
		{"alias", `{"domains":[{"domainName":"primary.invalid","verified":true}]}`, `{"domainAliases":[{"domainAliasName":"example.com","parentDomainName":"primary.invalid","verified":true}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsFoundationOps()
			wsAuthorized(t, w)
			token := wsTokenServer(w, wsTokenBody(), 200)
			api := w.google(wsReply(tc.domains, tc.aliases))
			g := w.gate()
			reads := wsBootstrap(g)
			if len(reads) != 3 || !reads[2].OK() {
				t.Fatalf("%+v", reads)
			}
			if reads[0].Response.Body != nil || reads[1].Response.Body != nil {
				t.Fatal("unbound bootstrap body exposed")
			}
			if !strings.Contains(string(reads[2].Response.Body), `"id":"C-opaque-123"`) {
				t.Fatal("binding missing")
			}
			if len(g.Successes()) != 0 || len(g.Reused()) != 0 {
				t.Fatal("unknown principal reused evidence")
			}
			for _, s := range []string{refreshSeed, secretSeed, accessSeed, "foreign.invalid", "primary.invalid", "PRIVATE_CONTACT"} {
				if strings.Contains(w.audit.String(), s) {
					t.Fatalf("audit leaked %q", s)
				}
				for _, r := range reads {
					b, _ := json.Marshal(r)
					if strings.Contains(string(b), s) {
						t.Fatalf("result leaked %q", s)
					}
				}
			}
			if len(token.requests()) != 1 || len(api.requests()) != 3 {
				t.Fatal("wrong request count")
			}
			if token.requests()[0].Method != "POST" || token.requests()[0].URL.Path != "/token" {
				t.Fatal("exchange escaped endpoint")
			}
			for _, r := range api.requests() {
				if r.Method != "GET" {
					t.Fatal("target write")
				}
			}
			for _, e := range w.audit.entries(t) {
				if e.Op == workspaceTokenID && (e.OutputHash != "" || e.Stored != 0) {
					t.Fatal("token body persisted or hashed")
				}
			}
			res := g.Send(context.Background(), Request{Op: "workspace.customer", Asset: wsAsset, Params: map[string]string{"domain": "example.com"}})
			if !res.OK() || res.Identity != "" {
				t.Fatalf("bound read %+v", res)
			}
		})
	}
}
func TestWorkspaceBindingRefusesUnknownAndForeignTenant(t *testing.T) {
	for _, tc := range []struct{ name, domains, aliases string }{
		{"foreign", `{"domains":[{"domainName":"foreign.invalid","verified":true}]}`, `{}`},
		{"suffix", `{"domains":[{"domainName":"x.example.com","verified":true}]}`, `{}`},
		{"unverified", `{"domains":[{"domainName":"example.com","verified":false}]}`, `{}`},
		{"unknown boolean", `{"domains":[{"domainName":"example.com"}]}`, `{}`},
		{"contradictory", `{"domains":[{"domainName":"example.com","verified":true},{"domainName":"example.com","verified":false}]}`, `{}`},
		{"bad alias parent", `{"domains":[{"domainName":"primary.invalid","verified":true}]}`, `{"domainAliases":[{"domainAliasName":"example.com","parentDomainName":"absent.invalid","verified":true}]}`},
		{"null aliases", `{"domains":[{"domainName":"example.com","verified":true}]}`, `{"domainAliases":null}`},
		{"malformed", `{"domains":"bad"}`, `{}`},
		{"duplicate keys", `{"domains":[],"domains":[{"domainName":"example.com","verified":true}]}`, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsFoundationOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			api := w.google(wsReply(tc.domains, tc.aliases))
			g := w.gate()
			reads := wsBootstrap(g)
			if reads[len(reads)-1].OK() {
				t.Fatal("invalid binding accepted")
			}
			for _, r := range reads {
				if r.Response != nil && len(r.Response.Body) != 0 {
					t.Fatal("failed bootstrap disclosed body")
				}
			}
			before := len(api.requests())
			for _, customer := range []string{"C-opaque-123", "foreign", "my_customer", "C/evil", "C%2fevil"} {
				r := g.Send(context.Background(), Request{Op: "workspace.customer", Asset: wsAsset, Params: map[string]string{"domain": "example.com", "customer": customer}})
				if r.OK() {
					t.Fatal("unbound/foreign selector accepted")
				}
			}
			if len(api.requests()) != before {
				t.Fatal("unbound followup sent")
			}
			if strings.Contains(w.audit.String(), "foreign.invalid") {
				t.Fatal("foreign inventory leaked")
			}
		})
	}
}
func TestWorkspaceTokenResponsesRemainPrivate(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"access_token":"t","token_type":"MAC","expires_in":3600}`, `{"access_token":"x\r\ny","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"t","token_type":"Bearer","expires_in":"3600"}`, `{"access_token":"t","token_type":"Bearer","expires_in":1.5}`, `{"access_token":"t","token_type":"Bearer","expires_in":-1}`,
		`{"access_token":"t","token_type":"Bearer","expires_in":3600,"expires_in":7200}`, wsTokenBody() + `{}`, strings.Repeat("x", googleTokenLimit+1),
	} {
		t.Run(fmt.Sprint(len(body), body[:min(len(body), 30)]), func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsFoundationOps()
			wsAuthorized(t, w)
			wsTokenServer(w, body, 200)
			api := w.google(jsonReply(200, `{"id":"C123"}`))
			reads := wsBootstrap(w.gate())
			if reads[0].OK() || len(api.requests()) != 0 {
				t.Fatal("bad token admitted bootstrap")
			}
			if strings.Contains(w.audit.String(), body) {
				t.Fatal("token response leaked")
			}
		})
	}
	for _, status := range []int{302, 400, 401, 403, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsFoundationOps()
			wsAuthorized(t, w)
			token := wsTokenServer(w, fmt.Sprintf(`{"error_description":%q,"id_token":"PRIVATE_ID_TOKEN","refresh_token":"REPLACEMENT_TOKEN"}`, secretSeed), status)
			api := w.google(jsonReply(200, `{"id":"C123"}`))
			g := w.gate()
			reads := wsBootstrap(g)
			if reads[0].OK() || len(api.requests()) != 0 || len(token.requests()) != 1 {
				t.Fatal("failed exchange retried/followed")
			}
			if strings.Contains(w.audit.String(), secretSeed) {
				t.Fatal("provider diagnostic leaked")
			}
		})
	}
}
func TestWorkspaceCredentialFilesFailBeforeNetwork(t *testing.T) {
	valid := fmt.Sprintf(`{"type":"authorized_user","client_id":"id","client_secret":%q,"refresh_token":%q}`, secretSeed, refreshSeed)
	for _, body := range []string{`[]`, `null`, `{`, valid + valid, `{"type":"external_account"}`, `{"type":"authorized_user","type":"service_account"}`, strings.Repeat(" ", googleCredentialLimit+1), strings.TrimSuffix(valid, "}") + `,"token_uri":"https://foreign.invalid/token"}`, strings.TrimSuffix(valid, "}") + `,"credential_source":{}}`, strings.TrimSuffix(valid, "}") + `,"universe_domain":"example.com"}`, strings.TrimSuffix(valid, "}") + `,"client_id":23}`} {
		w := newWorld(t)
		w.ops = wsFoundationOps()
		wsFile(t, w, body)
		g := w.gate()
		reads := wsBootstrap(g)
		if reads[0].OK() || w.dials.Load() != 0 || len(w.queries) != 0 {
			t.Fatal("invalid credential contacted network")
		}
		if strings.Contains(w.audit.String(), secretSeed) {
			t.Fatal("ADC diagnostic leaked value")
		}
	}
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	w.env["SCHECK_WORKSPACE_SUBJECT"] = "admin@example.com"
	if wsBootstrap(w.gate())[0].OK() || w.dials.Load() != 0 {
		t.Fatal("authorized-user impersonation allowed")
	}
}
func TestWorkspaceAssertionClaimsAndSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	doc := map[string]string{"type": "service_account", "private_key": pemKey, "private_key_id": "kid123", "client_email": "assessment@test.iam.gserviceaccount.com", "client_id": "unverified-metadata"}
	raw, _ := json.Marshal(doc)
	scopes, _ := profileScopes("directory_oauth_mail")
	source, err := parseGoogleSource(raw, "admin@example.com", "directory_oauth_mail", scopes)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1791630000, 0)
	ex, err := source.exchange(at, WorkspaceBaseline)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(ex.form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Fatal("bad assertion")
	}
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		t.Fatal("signature invalid")
	}
	var h map[string]any
	var c map[string]any
	_ = json.Unmarshal(header, &h)
	_ = json.Unmarshal(claims, &c)
	if len(h) != 3 || h["alg"] != "RS256" || h["kid"] != "kid123" || h["typ"] != "JWT" || len(c) != 6 || c["iss"] != source.issuer || c["sub"] != "admin@example.com" || c["aud"] != workspaceTokenURL || c["iat"] != float64(at.Unix()) || c["exp"] != float64(at.Unix()+300) || c["scope"] != strings.Join(scopes, " ") {
		t.Fatalf("claims/header differ: %s %s", header, claims)
	}
	// The optional surface asserts exactly its one scope, same issuer and subject.
	opt, err := source.exchange(at, WorkspaceOAuthGrants)
	if err != nil {
		t.Fatal(err)
	}
	optClaims, _ := base64.RawURLEncoding.DecodeString(strings.Split(opt.form.Get("assertion"), ".")[1])
	c = map[string]any{}
	_ = json.Unmarshal(optClaims, &c)
	if c["scope"] != "https://www.googleapis.com/auth/admin.directory.user.security" || c["sub"] != "admin@example.com" || c["iss"] != source.issuer || opt.form.Has("scope") {
		t.Fatalf("optional claims differ: %s", optClaims)
	}
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsFile(t, w, string(raw))
	w.env["SCHECK_WORKSPACE_SUBJECT"] = "admin@example.com"
	token := wsTokenServer(w, wsTokenBody(), 200)
	api := w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	g := w.gate()
	if r := wsBootstrap(g); len(r) != 3 || !r[2].OK() {
		t.Fatal(r)
	}
	if len(token.requests()) != 1 || len(api.requests()) != 3 {
		t.Fatal("service-account exchange failed")
	}
	if strings.Contains(w.audit.String(), pemKey) || strings.Contains(w.audit.String(), "unverified-metadata") {
		t.Fatal("key/local identity leaked")
	}
	if len(g.Successes()) != 0 {
		t.Fatal("unverified delegated identity reused")
	}
	for _, bad := range []string{"", "Admin <admin@example.com>", "a\n@example.com"} {
		if _, err := parseGoogleSource(raw, bad, "directory", scopes); err == nil {
			t.Fatal("invalid subject accepted")
		}
	}
	doc["private_key"] = pemKey + pemKey
	bad, _ := json.Marshal(doc)
	if _, err := parseGoogleSource(bad, "admin@example.com", "directory", scopes); err == nil {
		t.Fatal("multiple keys accepted")
	}
}
func TestWorkspaceAdmissionAndAuditFailClosed(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	api := w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	g := w.gate()
	for _, r := range []Request{
		{Op: workspaceTokenID, Asset: wsAsset},
		{Op: "workspace.customer", Asset: wsAsset, Params: map[string]string{"domain": "example.com", "customer": "foreign"}},
		{Op: "workspace.bootstrap_customer", Asset: "saas:google-workspace:foreign.invalid", Params: map[string]string{"domain": "foreign.invalid"}},
	} {
		if g.Send(context.Background(), r).OK() {
			t.Fatal("unadmitted request accepted")
		}
	}
	if w.dials.Load() != 0 {
		t.Fatal("unadmitted request sent")
	}
	w.scope.orgUnits = map[string][]OrgUnit{wsAsset: {{Path: "/Board", ExcludedBy: "exclude[0]"}}}
	if reads := wsBootstrap(g); len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	if len(api.requests()) != 3 {
		t.Fatal("delegated user exclusion bypass")
	}
	g2 := w.gate()
	g2.audit = policy.NewAudit(failWriter{})
	if reads := wsBootstrap(g2); reads[0].OK() {
		t.Fatal("failed audit accepted")
	}
	if len(api.requests()) != 3 {
		t.Fatal("audit failure sent bootstrap")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("audit unavailable") }
func TestWorkspaceScopeKnowledgeAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		scope string
		known bool
	}{{"", false}, {`,"scope":""`, true}, {`,"scope":27`, false}, {`,"scope":"https://www.googleapis.com/auth/admin.directory.user.readonly"`, true}, {`,"scope":"x\ny"`, false}} {
		body := strings.TrimSuffix(wsTokenBody(), "}") + tc.scope + "}"
		ex := &googleExchange{}
		start := time.Unix(100, 0)
		if !readGoogleToken([]byte(body), ex, start) || ex.scopesKnown != tc.known || ex.expires != start.Add(3540*time.Second) {
			t.Fatalf("scope/expiry %+v", ex)
		}
	}
	ex := &googleExchange{}
	start := time.Unix(100, 0)
	if !readGoogleToken([]byte(`{"access_token":"t","token_type":"bearer","expires_in":9223372036854775807}`), ex, start) || ex.expires != start.Add(3540*time.Second) {
		t.Fatal("long expiry overflow")
	}
}

func TestWorkspaceMalformedMemberCannotDisappearDuringProjection(t *testing.T) {
	for _, member := range []string{`"invalid"`, `null`, `17`, `[]`, `{"domainName":"broken"}`} {
		w := newWorld(t)
		w.ops = wsFoundationOps()
		wsAuthorized(t, w)
		wsTokenServer(w, wsTokenBody(), 200)
		w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true},`+member+`]}`, `{}`))
		r := wsBootstrap(w.gate())
		if r[len(r)-1].OK() {
			t.Fatal("malformed member hidden by projection")
		}
	}
}
func TestWorkspaceResumeAlwaysBootstrapsAndProfilesDoNotReuse(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	token := wsTokenServer(w, wsTokenBody(), 200)
	api := w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	g := w.gate()
	if reads := wsBootstrap(g); len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	w.prior = g.Successes()
	g2 := w.gate()
	if reads := wsBootstrap(g2); len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	if len(token.requests()) != 2 || len(api.requests()) != 6 || len(g2.Reused()) != 0 {
		t.Fatal("bootstrap reused")
	}
	w.env["SCHECK_WORKSPACE_PROFILE"] = "directory_mail"
	if reads := wsBootstrap(g2); reads[0].OK() || len(token.requests()) != 2 || len(api.requests()) != 6 {
		t.Fatal("profile change retained authorization")
	}
	// Expired token cannot continue a previously bound read.
	delete(w.env, "SCHECK_WORKSPACE_PROFILE")
	g2.workspace[wsAsset].expires = time.Time{}
	r := g2.Send(context.Background(), Request{Op: "workspace.customer", Asset: wsAsset, Params: map[string]string{"domain": "example.com"}})
	if r.Decision != "unavailable:bootstrap_required" || len(api.requests()) != 6 {
		t.Fatal(r)
	}
}
func TestWorkspaceRetainedScopeEchoHasRedactionMarker(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	body := strings.TrimSuffix(wsTokenBody(), "}") + fmt.Sprintf(`,"scope":%q,"id_token":"PRIVATE_ID_TOKEN","refresh_token":"PRIVATE_REPLACEMENT"}`, accessSeed)
	wsTokenServer(w, body, 200)
	w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	g := w.gate()
	reads := wsBootstrap(g)
	if len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	public, _ := json.Marshal(reads)
	for _, secret := range []string{accessSeed, secretSeed, refreshSeed, "PRIVATE_ID_TOKEN", "PRIVATE_REPLACEMENT"} {
		if strings.Contains(string(public)+w.audit.String(), secret) {
			t.Fatal("secret leaked")
		}
	}
	if !strings.Contains(string(reads[2].Response.Body), "[REDACTED:credential:") || len(reads[2].Response.Redactions) == 0 {
		t.Fatal("retained secret has no marker")
	}
	// Anything a future engagement persists is this public projection alone.
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, public, 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(saved), accessSeed) {
		t.Fatal("persisted secret")
	}
}
func TestWorkspaceFoundationRegistryRejectsWidening(t *testing.T) {
	for _, mutate := range []func(*Op){
		func(o *Op) { o.URL = "https://admin.googleapis.com/admin/directory/v1/users" },
		func(o *Op) { o.Method = POST },
		func(o *Op) { o.Auth = NoAuth }, func(o *Op) { o.Provider = "github" }, func(o *Op) { o.ID = "workspace.bootstrap_unknown" },
		func(o *Op) { o.Subject = "saas:google-workspace:other.com" }, func(o *Op) { o.Params[1].Type = Login },
	} {
		o := wsFoundationOps()[1]
		mutate(&o)
		if _, err := NewRegistry(o); err == nil {
			t.Fatal("widened op admitted")
		}
	}
	o := workspaceTokenOps()[0]
	o.URL = "https://oauth2.googleapis.com/other"
	if _, err := NewRegistry(o); err == nil {
		t.Fatal("arbitrary POST path")
	}
}

func TestWorkspaceEgressNamesTokenAndDirectoryHosts(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	g := w.gate()
	if reads := wsBootstrap(g); len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	uses, _ := g.Egress()
	seen := map[string]int{}
	for _, use := range uses {
		if use.Source == "google" {
			seen[use.Host] = use.Requests
		}
	}
	if seen["oauth2.googleapis.com"] != 1 || seen["admin.googleapis.com"] != 3 {
		t.Fatal("Google hosts were collapsed", uses)
	}
}
func TestWorkspaceCredentialsRejectSymlinkAndInvalidKey(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	link := filepath.Join(t.TempDir(), "adc-link.json")
	if err := os.Symlink(w.env["GOOGLE_APPLICATION_CREDENTIALS"], link); err != nil {
		t.Fatal(err)
	}
	w.env["GOOGLE_APPLICATION_CREDENTIALS"] = link
	if r := wsBootstrap(w.gate()); r[0].OK() || w.dials.Load() != 0 {
		t.Fatal("symlink credential used")
	}
	for _, value := range []string{"not a key", "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"} {
		raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "a@example.com", "private_key_id": "key123", "private_key": value})
		if _, err := parseGoogleSource(raw, "admin@example.com", "directory", nil); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}

func TestWorkspaceOptionalProfilesNeverExpandBootstrapScopes(t *testing.T) {
	baseline, ok := profileScopes("directory")
	if !ok {
		t.Fatal("missing baseline")
	}
	for _, profile := range []string{"directory_oauth", "directory_mail", "directory_oauth_mail"} {
		scopes, ok := profileScopes(profile)
		if !ok || strings.Join(scopes, " ") != strings.Join(baseline, " ") {
			t.Fatal("optional permission blocks baseline bootstrap")
		}
		for _, scope := range scopes {
			if scope == googleScopePrefix+"admin.directory.user.security" || scope == googleScopePrefix+"gmail.readonly" {
				t.Fatal("optional grant requested at bootstrap")
			}
		}
	}
}

func TestWorkspaceNullCredentialFieldsAndScopeStayUnknown(t *testing.T) {
	for _, field := range []string{"account", "client_id", "quota_project_id", "token_uri", "universe_domain"} {
		obj := map[string]any{"type": "authorized_user", "client_id": "id", "client_secret": "secret", "refresh_token": "refresh", field: nil}
		raw, _ := json.Marshal(obj)
		if _, err := parseGoogleSource(raw, "", "directory", nil); err == nil {
			t.Fatal("null credential field accepted", field)
		}
	}
	ex := &googleExchange{}
	body := strings.TrimSuffix(wsTokenBody(), "}") + `,"scope":null}`
	if !readGoogleToken([]byte(body), ex, time.Now()) || ex.scopesKnown {
		t.Fatal("null scope was treated as known")
	}
}

func TestWorkspaceBootstrapGETRetriesKeepPrivateErrors(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	var calls int
	reply := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	api := w.google(func(rw http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			jsonReply(503, `{"error_description":"PRIVATE_PROVIDER_ERROR"}`)(rw, r)
			return
		}
		reply(rw, r)
	})
	g := w.gate()
	reads := wsBootstrap(g)
	if len(reads) != 3 || !reads[2].OK() || len(api.requests()) != 5 {
		t.Fatal("GET retry failed", reads)
	}
	if strings.Contains(w.audit.String(), "PRIVATE_PROVIDER_ERROR") {
		t.Fatal("retry error leaked")
	}
}

func TestWorkspaceUnboundCustomerNeverLeaksThroughTransportErrors(t *testing.T) {
	const privateCustomer = "UNBOUND_CUSTOMER_PRIVATE"
	w := newWorld(t)
	w.ops = wsFoundationOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/my_customer") {
			jsonReply(200, `{"id":"`+privateCustomer+`"}`)(rw, r)
			return
		}
		conn, _, err := rw.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	})
	g := w.gate()
	reads := wsBootstrap(g)
	if len(reads) != 2 || reads[1].OK() {
		t.Fatal("transport failure not recorded")
	}
	public, _ := json.Marshal(reads)
	if strings.Contains(w.audit.String()+string(public), privateCustomer) {
		t.Fatal("unbound customer leaked in transport URL")
	}
}
func TestWorkspaceMissingAliasesAndRedactedBindingCannotBind(t *testing.T) {
	for _, status := range []int{403, 404} {
		w := newWorld(t)
		w.ops = wsFoundationOps()
		wsAuthorized(t, w)
		wsTokenServer(w, wsTokenBody(), 200)
		reply := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
		w.google(func(rw http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/domainaliases") {
				jsonReply(status, `{"error_description":"PRIVATE"}`)(rw, r)
				return
			}
			reply(rw, r)
		})
		reads := wsBootstrap(w.gate())
		if len(reads) != 3 || reads[2].OK() || reads[2].Reason != "insufficient_permission" {
			t.Fatal("missing aliases inferred binding", reads)
		}
	}
	w := newWorld(t)
	w.ops = wsFoundationOps()
	w.extra = append(w.extra, `example\.com`)
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	w.google(wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`))
	reads := wsBootstrap(w.gate())
	if reads[len(reads)-1].OK() {
		t.Fatal("redacted name bound")
	}
}

func TestWorkspaceBoundReadsUseDeclaredProjectionAndInvalidateOn401(t *testing.T) {
	w := newWorld(t)
	w.ops = wsFoundationOps()
	// An ordinary compiled op owns its projection; the gate does not recognize
	// its response as Directory bootstrap data.
	w.ops[3].ID = "workspace.projected_customer"
	w.ops[3].Keep = []string{"description"}
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	unauthorized := false
	api := w.google(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/directory/v1/customers/C-opaque-123" {
			if unauthorized {
				jsonReply(401, `{}`)(rw, r)
				return
			}
			jsonReply(200, `{"description":"`+accessSeed+`","id":"foreign-private-id"}`)(rw, r)
			return
		}
		bootstrap(rw, r)
	})
	g := w.gate()
	r := Request{Op: w.ops[3].ID, Asset: wsAsset, Params: map[string]string{"domain": "example.com"}}
	if res := g.Send(context.Background(), r); res.Decision != "refused:tenant_binding" || len(api.requests()) != 0 {
		t.Fatal(res)
	}
	if reads := wsBootstrap(g); len(reads) != 3 || !reads[2].OK() {
		t.Fatal(reads)
	}
	before := len(api.requests())
	for _, customer := range []string{"C-opaque-123", "foreign", "my_customer"} {
		res := g.Send(context.Background(), Request{Op: r.Op, Asset: wsAsset, Params: map[string]string{"domain": "example.com", "customer": customer}})
		if res.Decision != "refused:tenant_binding" || len(api.requests()) != before {
			t.Fatal(res)
		}
	}
	res := g.Send(context.Background(), r)
	if !res.OK() || !strings.Contains(string(res.Response.Body), "[REDACTED:") || strings.Contains(string(res.Response.Body), accessSeed) || strings.Contains(string(res.Response.Body), "foreign-private-id") {
		t.Fatal(res)
	}
	unauthorized = true
	res = g.Send(context.Background(), r)
	if res.OK() || res.Response == nil || res.Response.Status != 401 {
		t.Fatal(res)
	}
	before = len(api.requests())
	res = g.Send(context.Background(), r)
	if res.Decision != "refused:tenant_binding" || len(api.requests()) != before {
		t.Fatal(res)
	}
	if strings.Contains(w.audit.String(), accessSeed) || strings.Contains(w.audit.String(), "foreign-private-id") {
		t.Fatal("ordinary response leaked")
	}
}

func TestWorkspaceOrdinaryRegistryRequiresBoundCustomerPath(t *testing.T) {
	for _, mutate := range []func(*Op){
		func(o *Op) { o.URL = "https://other.googleapis.com/admin/directory/v1/customers/{customer}" },
		func(o *Op) { o.URL = "https://admin.googleapis.com/admin/directory/v1/customers/my_customer" },
		func(o *Op) { o.URL = "https://admin.googleapis.com/admin/directory/v1/customers/foreign" },
		func(o *Op) { o.URL += "?domain={domain}" },
		func(o *Op) { o.URL += "/../foreign" },
		func(o *Op) { o.URL += "/%2e%2e/foreign" },
		func(o *Op) { o.Params[1].Optional = true },
		func(o *Op) { o.Params[1].Type = Login },
	} {
		o := wsFoundationOps()[3]
		mutate(&o)
		if _, err := NewRegistry(o); err == nil {
			t.Fatalf("unsafe selector registered: %+v", o)
		}
	}
}
