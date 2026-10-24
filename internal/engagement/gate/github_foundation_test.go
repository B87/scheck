package gate

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGitHubPrincipalBinding(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	body := `{"id":123,"login":"ci-bot","type":"User","email":"unneeded@example.org"}`
	gh := w.github(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("X-OAuth-Scopes", "repo, read:org, repo")
		if r.URL.Path == "/user" {
			_, _ = rw.Write([]byte(body))
		} else {
			_, _ = rw.Write([]byte(`{"name":"app"}`))
		}
	})
	g := w.gate()
	principal := Request{Op: "github.user", Asset: "saas:github:example-org"}
	if res := g.Send(context.Background(), principal); !res.OK() {
		t.Fatal(res)
	}
	c, _ := g.credential(GitHubToken)
	if c.Principal != "github:user:123" || strings.Join(c.Scopes, ",") != "read:org,repo" {
		t.Fatalf("identity=%q scopes=%v", c.Principal, c.Scopes)
	}
	if g.identity(g.reg.ops[principal.Op], principal, nil, c) != "" {
		t.Fatal("principal can be reused")
	}
	if res := g.Send(context.Background(), principal); !res.OK() {
		t.Fatal(res)
	}
	if len(gh.requests()) != 2 {
		t.Fatal("principal wasn't freshly sent")
	}
	w.env["GITHUB_TOKEN"] = "changed-token-01234567890123456789"
	c, _ = g.credential(GitHubToken)
	if c.Principal != "" {
		t.Fatal("changed credential inherited principal")
	}
	w.env["GITHUB_TOKEN"] = testToken
	body = `{"id":123,"login":"ci-bot","type":"Organization"}`
	_ = g.Send(context.Background(), principal)
	c, _ = g.credential(GitHubToken)
	if c.Principal != "" {
		t.Fatal("unsupported principal retained prior identity")
	}
	if strings.Contains(w.audit.String(), testToken) {
		t.Fatal("token in audit")
	}
}

func TestGitHubPrincipalRequiresRecognizedIdentity(t *testing.T) {
	for _, body := range []string{`{"id":"123","login":"ci-bot","type":"User"}`, `{"id":0,"login":"ci-bot","type":"User"}`, `{"id":123,"login":"bad/login","type":"User"}`, `{"id":123,"login":"ci-bot"}`, `{"id":123,"login":"ci-bot","type":"Bot"}`, `{`} {
		t.Run(body, func(t *testing.T) {
			w := newWorld(t)
			w.env["GITHUB_TOKEN"] = testToken
			w.github(jsonReply(200, body))
			g := w.gate()
			g.principals = map[string]Credential{testToken: {Principal: "stale"}}
			_ = g.Send(context.Background(), Request{Op: "github.user", Asset: "saas:github:example-org"})
			cred, _ := g.credential(GitHubToken)
			if cred.Principal != "" {
				t.Fatal("malformed identity retained stale principal")
			}
		})
	}
}

func TestGitHubInstallationPrincipalNotSent(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = "ghs_installation-token-01234567890"
	gh := w.github(jsonReply(401, `{}`))
	g := w.gate()
	res := g.Send(context.Background(), Request{Op: "github.user", Asset: "saas:github:example-org"})
	if res.Decision != "unavailable:unsupported_principal" || len(gh.requests()) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestGitHubAPIVersionAndItemSubjects(t *testing.T) {
	op := testOps[0]
	op.APIVersion = "2026-03-10"
	w := newWorld(t)
	w.ops = []Op{op}
	w.env["GITHUB_TOKEN"] = testToken
	gh := w.github(jsonReply(200, `{"name":"app"}`))
	res := w.gate().Send(context.Background(), Request{Op: op.ID, Asset: "saas:github:example-org", Params: map[string]string{"owner": "example-org", "repo": "app"}})
	if !res.OK() {
		t.Fatal(res)
	}
	if got := gh.requests()[0].Header.Get("X-GitHub-Api-Version"); got != op.APIVersion {
		t.Fatalf("version %q", got)
	}
	for _, version := range []string{"other", "2022-11-28"} {
		op.APIVersion = version
		if _, err := NewRegistry(op); err == nil {
			t.Fatal("unreviewed version accepted")
		}
	}
	list := testOps[2]
	for _, subject := range []string{"", "cloud:gcp:{key}", "repo:github:{other}", "repo:github:{key}/other"} {
		copyList := *list.List
		copyList.Subject = subject
		list.List = &copyList
		if _, err := NewRegistry(list); err == nil {
			t.Fatalf("invalid item subject %q", subject)
		}
	}
}
