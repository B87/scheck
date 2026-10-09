package gate

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Credential is what the gate attaches to an op after admission. Only the
// variable it came from and the principal are ever printed; the value is
// added to the redactor for every response from its provider
// (docs/spec/scope.md, "Methods and credentials").
type Credential struct {
	// Env names the environment variable the credential came from.
	Env string
	// Principal and Scopes are who the credential is and what it may
	// read, once a principal op has said; a request on a credential whose
	// principal is not known is never reused on resume.
	Principal string
	Scopes    []string
	header    string
	value     string
	secret    string
}

// minTokenLength is shorter than any GitHub token. A shorter value is a
// mistake, and redacting it by value would mangle every response.
const minTokenLength = 20

// credential reads the credential for a binding from the environment, at
// request time, or says why there is none. GitHub takes GITHUB_TOKEN, then
// GH_TOKEN; scheck never runs `gh auth token`, which would start a process
// outside every enforcement point.
func (g *Gate) credential(a Auth) (*Credential, string) {
	switch a {
	case GitHubToken:
		for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
			tok := g.getenv(env)
			if tok == "" {
				continue
			}
			if len(tok) < minTokenLength {
				return nil, env + " is set but too short to be a GitHub token"
			}
			c := &Credential{Env: env, header: "Authorization", value: "Bearer " + tok, secret: tok}
			g.mu.Lock()
			if known, ok := g.principals[tok]; ok {
				c.Principal, c.Scopes = known.Principal, slices.Clone(known.Scopes)
			}
			g.mu.Unlock()
			return c, ""
		}
		return nil, "neither GITHUB_TOKEN nor GH_TOKEN is set; set one to an organization-approved token with the required read permissions (`gh auth token` prints the one gh holds)"
	}
	return nil, "no credential is set for " + string(a)
}

// bindPrincipal consumes only the projected, redacted successful response.
// Exact secret matching is private session state; no credential or hash is persisted
// (docs/spec/github-collector.md, "Principal and resume").
func (g *Gate) bindPrincipal(op *compiled, cred *Credential, res Result) {
	if op.Class != Principal || op.Provider != "github" || op.Method != GET || op.URL != "https://api.github.com/user" || cred == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.principals == nil {
		g.principals = map[string]Credential{}
	}
	delete(g.principals, cred.secret)
	if !res.OK() || res.Response.Status != 200 || res.Response.Truncated || len(res.Response.Redactions) != 0 {
		return
	}
	var doc struct {
		ID    json.RawMessage `json:"id"`
		Login string          `json:"login"`
		Type  string          `json:"type"`
	}
	if json.Unmarshal(res.Response.Body, &doc) != nil {
		return
	}
	id, err := strconv.ParseInt(string(doc.ID), 10, 64)
	if err != nil || id <= 0 || !loginRE.MatchString(doc.Login) || doc.Type != "User" {
		return
	}
	scopes := []string{}
	for part := range strings.SplitSeq(res.Response.Header.Get("X-OAuth-Scopes"), ",") {
		scope := strings.TrimSpace(part)
		if scope == "" {
			continue
		}
		if !scopeName.MatchString(scope) {
			return
		}
		scopes = append(scopes, scope)
	}
	scopes = slices.Compact(slices.Sorted(slices.Values(scopes)))
	g.principals[cred.secret] = Credential{Principal: "github:user:" + strconv.FormatInt(id, 10), Scopes: scopes}
}

var scopeName = regexp.MustCompile(`^[a-z_][a-z_0-9:]*(?:[a-z_0-9])?$`)
