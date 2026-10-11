package gate

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const workspaceTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // public compiled OAuth endpoint, not a credential
const workspaceTokenID = "workspace.credential_exchange"
const googleCredentialLimit = 256 << 10
const googleTokenLimit = 64 << 10
const googleScopePrefix = "https://www.googleapis.com/auth/"

// googleSource is restricted ADC, not Google's full discovery chain.
// docs/spec/workspace-collector.md, "Credential files and profiles".
type googleSource struct {
	kind, env, issuer, subject, keyID, clientID, clientSecret, refreshToken, privatePEM, profile string
	key                                                                                          *rsa.PrivateKey
	scopes                                                                                       []string
}

type googleExchange struct {
	// surface is the optional read surface this exchange asks for, or the
	// baseline; it selects the audited exchange op.
	surface     WorkspaceSurface
	form        url.Values
	credential  *Credential
	token       string
	expires     time.Time
	scopes      []string
	scopesKnown bool
}

func profileScopes(profile string) ([]string, bool) {
	scopes := []string{"admin.directory.customer.readonly", "admin.directory.domain.readonly", "admin.directory.orgunit.readonly", "admin.directory.user.readonly", "admin.directory.rolemanagement.readonly"}
	switch profile {
	case "directory", "directory_oauth", "directory_mail", "directory_oauth_mail":
	default:
		return nil, false
	}
	for i := range scopes {
		scopes[i] = googleScopePrefix + scopes[i]
	}
	slices.Sort(scopes)
	return scopes, true
}

func (g *Gate) loadGoogleSource() (*googleSource, string) {
	profile := g.getenv("SCHECK_WORKSPACE_PROFILE")
	if profile == "" {
		profile = "directory"
	}
	scopes, valid := profileScopes(profile)
	if !valid {
		return nil, "SCHECK_WORKSPACE_PROFILE is not a supported compiled read profile"
	}
	path, env := g.getenv("GOOGLE_APPLICATION_CREDENTIALS"), "GOOGLE_APPLICATION_CREDENTIALS"
	if path == "" {
		env = "local Google credential file"
		if runtime.GOOS == "windows" {
			if g.getenv("APPDATA") == "" {
				return nil, "the conventional Google credential directory is unavailable"
			}
			path = filepath.Join(g.getenv("APPDATA"), "gcloud", "application_default_credentials.json")
		} else {
			home := g.getenv("HOME")
			if home == "" {
				var err error
				home, err = os.UserHomeDir()
				if err != nil {
					return nil, "the conventional Google credential directory is unavailable"
				}
			}
			path = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "scheck could not open the selected Google credential file. Check that it exists and is readable, then retry. No other credentials were tried"
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, "the selected Google credential file is not a regular file"
	}
	raw, err := io.ReadAll(io.LimitReader(f, googleCredentialLimit+1))
	if err != nil || len(raw) > googleCredentialLimit {
		return nil, "the selected Google credential file could not be read within its size limit"
	}
	source, err := parseGoogleSource(raw, g.getenv("SCHECK_WORKSPACE_SUBJECT"), profile, scopes)
	if err != nil {
		return nil, err.Error()
	}
	source.env = env
	return source, ""
}

// strictGoogleObject rejects ambiguity before interpreting sensitive fields.
// Errors deliberately omit decoder snippets and field values.
func strictGoogleObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid JSON encoding")
	}
	// The standard validator also bounds nesting before duplicate-key traversal.
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON document")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueJSONValue(d); err != nil {
		return nil, errors.New("invalid or ambiguous JSON document")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, errors.New("JSON document must be an object")
	}
	return obj, nil
}
func uniqueJSONValue(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := tok.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			k, ok := key.(string)
			if !ok || seen[k] {
				return errors.New("duplicate JSON key")
			}
			seen[k] = true
			if err := uniqueJSONValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSONValue(d); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid delimiter")
	}
	_, err = d.Token()
	return err
}
func googleString(obj map[string]json.RawMessage, field string, required bool) (string, error) {
	raw, present := obj[field]
	if !present && !required {
		return "", nil
	}
	var v string
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &v) != nil || required && v == "" {
		return "", errors.New("the Google credential field " + field + " must be a nonempty string")
	}
	if strings.ContainsAny(v, "\x00\r") && field != "private_key" {
		return "", errors.New("the Google credential field " + field + " contains unsupported characters")
	}
	return v, nil
}
func parseGoogleSource(raw []byte, subject, profile string, scopes []string) (*googleSource, error) {
	obj, err := strictGoogleObject(raw)
	if err != nil {
		return nil, err
	}
	kind, err := googleString(obj, "type", true)
	if err != nil {
		return nil, err
	}
	allowed := []string{"type", "universe_domain", "quota_project_id", "token_uri"}
	switch kind {
	case "authorized_user":
		allowed = append(allowed, "client_id", "client_secret", "refresh_token", "account")
	case "service_account":
		allowed = append(allowed, "project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "auth_provider_x509_cert_url", "client_x509_cert_url")
	default:
		return nil, errors.New("unsupported Google credential type")
	}
	for field := range obj {
		if !slices.Contains(allowed, field) {
			return nil, errors.New("the Google credential contains an unsupported field")
		}
		if _, err := googleString(obj, field, false); err != nil {
			return nil, err
		}
	}
	endpoint, _ := googleString(obj, "token_uri", false)
	if _, set := obj["token_uri"]; set && endpoint != workspaceTokenURL {
		return nil, errors.New("the Google credential token_uri must be the compiled token endpoint")
	}
	universe, _ := googleString(obj, "universe_domain", false)
	if _, set := obj["universe_domain"]; set && universe != "googleapis.com" {
		return nil, errors.New("the Google credential universe_domain is unsupported")
	}
	s := &googleSource{kind: kind, profile: profile, scopes: scopes}
	if kind == "authorized_user" {
		if subject != "" {
			return nil, errors.New("SCHECK_WORKSPACE_SUBJECT cannot impersonate through an authorized_user credential")
		}
		for field, dest := range map[string]*string{"client_id": &s.clientID, "client_secret": &s.clientSecret, "refresh_token": &s.refreshToken} {
			*dest, err = googleString(obj, field, true)
			if err != nil {
				return nil, err
			}
			if !headerSafe(*dest) {
				return nil, errors.New("the Google credential credential field contains unsupported characters")
			}
		}
		return s, nil
	}
	if subject == "" {
		return nil, errors.New("service-account authentication needs the Workspace account to act as. Set SCHECK_WORKSPACE_SUBJECT to that account’s email address, then retry")
	}
	s.subject, err = userKey(subject)
	if err != nil || !strings.Contains(s.subject, "@") {
		return nil, errors.New("SCHECK_WORKSPACE_SUBJECT must be a canonical email address")
	}
	issuer, err := googleString(obj, "client_email", true)
	if err != nil {
		return nil, err
	}
	s.issuer, err = userKey(issuer)
	if err != nil || !strings.Contains(s.issuer, "@") {
		return nil, errors.New("the Google credential client_email must be a canonical email address")
	}
	s.keyID, err = googleString(obj, "private_key_id", true)
	if err != nil {
		return nil, err
	}
	if !headerSafe(s.keyID) {
		return nil, errors.New("the Google credential private_key_id contains unsupported characters")
	}
	s.clientID, _ = googleString(obj, "client_id", false)
	s.privatePEM, err = googleString(obj, "private_key", true)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(s.privatePEM))
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !strings.HasPrefix(s.privatePEM, "-----BEGIN PRIVATE KEY-----") {
		return nil, errors.New("the Google credential private_key must contain one unencrypted PKCS#8 key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the Google credential private_key is invalid")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("the Google credential private_key must be a valid RSA key of at least 2048 bits")
	}
	s.key = key
	return s, nil
}
func headerSafe(s string) bool {
	if len(s) == 0 || len(s) > googleTokenLimit {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

// exchange builds the private token request. The baseline asserts the
// compiled Directory scopes, and an authorized_user baseline refresh sends
// no scope; an optional surface asks for exactly its one scope with either
// credential kind (docs/spec/workspace-collector.md, "Credential files and
// profiles").
func (s *googleSource) exchange(now time.Time, surface WorkspaceSurface) (*googleExchange, error) {
	e := &googleExchange{surface: surface, credential: &Credential{Env: s.env, secrets: []string{s.clientSecret, s.refreshToken, s.privatePEM}}}
	scope := strings.Join(s.scopes, " ")
	if surface != WorkspaceBaseline {
		scope = workspaceSurfaceScope(surface)
		if scope == "" {
			return nil, errors.New("the optional Workspace read surface is not compiled")
		}
	}
	if s.kind == "authorized_user" {
		e.form = url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "client_secret": {s.clientSecret}, "refresh_token": {s.refreshToken}}
		if surface != WorkspaceBaseline {
			e.form.Set("scope", scope)
		}
		return e, nil
	}
	header := marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.keyID})
	claims := marshal(map[string]any{"iss": s.issuer, "sub": s.subject, "aud": workspaceTokenURL, "scope": scope, "iat": now.Unix(), "exp": now.Unix() + 300})
	enc := base64.RawURLEncoding
	unsigned := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, errors.New("the service-account assertion could not be signed")
	}
	assertion := unsigned + "." + enc.EncodeToString(sig)
	e.credential.secrets = append(e.credential.secrets, assertion)
	e.form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	return e, nil
}
func readGoogleToken(raw []byte, e *googleExchange, start time.Time) bool {
	obj, err := strictGoogleObject(raw)
	if err != nil {
		return false
	}
	var token, kind string
	var seconds int64
	if json.Unmarshal(obj["access_token"], &token) != nil || !headerSafe(token) || json.Unmarshal(obj["token_type"], &kind) != nil || !strings.EqualFold(kind, "Bearer") || json.Unmarshal(obj["expires_in"], &seconds) != nil || seconds <= 60 {
		return false
	}
	e.token = token
	e.expires = start.Add(time.Duration(min(seconds, 3600)-60) * time.Second)
	var scope string
	if value, present := obj["scope"]; present && len(bytes.TrimSpace(value)) > 0 && bytes.TrimSpace(value)[0] == '"' && json.Unmarshal(value, &scope) == nil {
		// An empty set is recognized; malformed or control-containing values are unknown.
		valid := !strings.ContainsAny(scope, "\t\r\n")
		for part := range strings.SplitSeq(scope, " ") {
			if part == "" {
				continue
			}
			if !headerSafe(part) || strings.ContainsAny(part, `"\`) {
				valid = false
				break
			}
			e.scopes = append(e.scopes, part)
		}
		e.scopesKnown = valid
		if !valid {
			e.scopes = nil
		}
		slices.Sort(e.scopes)
		e.scopes = slices.Compact(e.scopes)
	}
	return true
}

// Only fixed OAuth codes select diagnostic prose. Descriptions and all unknown
// provider text remain private even when authentication fails.
func googleExchangeFailure(raw []byte) string {
	switch googleErrorCode(raw) {
	case "invalid_client":
		return "Google did not accept the OAuth client credentials. Check the selected credential setup, then retry"
	case "invalid_grant":
		return "Google rejected the refresh token or delegated assertion. Check credential validity and the delegated account setup"
	case "invalid_scope", "unauthorized_client", "access_denied":
		return "Google did not authorize this credential for the compiled reads. Ask your Workspace administrator to review its existing authorization"
	}
	return "Google authentication failed. Check the selected credential setup, then retry"
}

// googleScopeDenied says Google refused the requested authorization, the
// optional-surface permission gap rather than a broken credential.
func googleScopeDenied(raw []byte) bool {
	switch googleErrorCode(raw) {
	case "invalid_scope", "unauthorized_client", "access_denied":
		return true
	}
	return false
}

func googleErrorCode(raw []byte) string {
	obj, err := strictGoogleObject(raw)
	if err != nil {
		return ""
	}
	var code string
	if json.Unmarshal(obj["error"], &code) != nil {
		return ""
	}
	return code
}
