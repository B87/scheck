package web

import (
	"context"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
)

type deniedRedirectGate struct {
	*fakeGate
	requests []gate.Request
	location string
}

func (g *deniedRedirectGate) Send(_ context.Context, r gate.Request) gate.Result {
	g.requests = append(g.requests, r)
	result := gate.Result{RequestID: g.id(), Decision: gate.DecisionSent, Response: &gate.Response{Status: 200, Body: []byte("<html>entry</html>")}}
	if r.Params["path"] == "/" {
		result.Response.Status = 302
		location := g.location
		if location == "" {
			location = "/login"
		}
		result.Response.Header = map[string][]string{"Location": {location}}
	}
	if r.RedirectOf != "" {
		result.Decision = "unavailable:redirect_not_entry_point"
		result.Response = nil
	}
	return result
}
func TestDeniedRedirectDoesNotSuppressDeclaredEntry(t *testing.T) {
	g := &deniedRedirectGate{fakeGate: &fakeGate{}}
	ev := Enrich(context.Background(), g, Domain{Asset: "url:https://example.com/", Sites: []SitePlan{{Host: "example.com", Declared: true, Entries: []Entry{{"https", "example.com", "/"}, {"https", "example.com", "/login"}}}}}, Evidence{})
	redirected, ordinary := 0, 0
	for _, r := range g.requests {
		if r.Params["path"] != "/login" {
			continue
		}
		if r.RedirectOf == "" {
			ordinary++
		} else {
			redirected++
		}
	}
	if redirected != 1 || ordinary != 1 {
		t.Fatalf("redirected=%d ordinary=%d", redirected, ordinary)
	}
	denied, read := false, false
	for _, p := range ev.Sites[0].Pages {
		if p.URL == "https://example.com/login" {
			denied = denied || p.Decision == "unavailable:redirect_not_entry_point"
			read = read || p.Decision == gate.DecisionSent && p.RedirectOf == ""
		}
	}
	if !denied || !read {
		t.Fatalf("denied=%v read=%v: %+v", denied, read, ev)
	}
}

func TestEscapedRedirectKeepsExactDeclaredEntry(t *testing.T) {
	g := &deniedRedirectGate{fakeGate: &fakeGate{}, location: "/a%20b"}
	ev := Enrich(context.Background(), g, Domain{Asset: "url:https://example.com/", Sites: []SitePlan{{Host: "example.com", Declared: true, Entries: []Entry{{"https", "example.com", "/"}, {"https", "example.com", "/a%20b"}}}}}, Evidence{})
	redirected, ordinary := 0, 0
	for _, r := range g.requests {
		if r.Params["path"] == "/a b" || r.Params["path"] == "/a%2520b" {
			t.Fatal("escaped path changed", r)
		}
		if r.Params["path"] == "/a%20b" {
			if r.RedirectOf == "" {
				ordinary++
			} else {
				redirected++
			}
		}
	}
	if redirected != 1 || ordinary != 1 {
		t.Fatal(redirected, ordinary)
	}
	for _, p := range ev.Sites[0].Pages {
		if p.RedirectOf != "" && p.URL != "https://example.com/a%20b" {
			t.Fatal(p)
		}
	}
}
