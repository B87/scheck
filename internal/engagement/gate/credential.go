package gate

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
			return &Credential{Env: env, header: "Authorization", value: "Bearer " + tok, secret: tok}, ""
		}
		return nil, "neither GITHUB_TOKEN nor GH_TOKEN is set; set one to a read-only token (`gh auth token` prints the one gh holds)"
	}
	return nil, "no credential is set for " + string(a)
}
