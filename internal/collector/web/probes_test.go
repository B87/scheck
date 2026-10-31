package web

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

// The reviewed list is a table: every probe becomes an op the gate
// validates, with a literal path, a signature that compiles and no body
// kept.
func TestProbeListIsValidAndLiteral(t *testing.T) {
	if _, err := gate.NewRegistry(Ops...); err != nil {
		t.Fatal(err)
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	for _, p := range Probes {
		if ids[p.ID] || paths[p.Path] {
			t.Errorf("%s: id or path listed twice", p.ID)
		}
		ids[p.ID], paths[p.Path] = true, true
		if !strings.HasPrefix(p.Path, "/") || strings.ContainsAny(p.Path, "?#{}") {
			t.Errorf("%s: path %q is not a literal path", p.ID, p.Path)
		}
		if _, err := regexp.Compile(p.Signature.Pattern); err != nil || len(p.Signature.Types)+len(p.Signature.NotTypes) == 0 {
			t.Errorf("%s: signature %v, types %v", p.ID, err, p.Signature.Types)
		}
		if p.Tag != "" && !slices.Contains([]string{"laravel", "django", "rails", "spring", "wordpress", "node", "php"}, p.Tag) {
			t.Errorf("%s: unknown tag %q", p.ID, p.Tag)
		}
		if f, ok := finding.Lookup(p.Finding); !ok || f.Subject != "url" {
			t.Errorf("%s: finding %s is not a url-subject finding", p.ID, p.Finding)
		}
	}
	if len(ProbeOps()) != len(Probes) || len(Probes) > 20 {
		t.Errorf("%d ops for %d probes", len(ProbeOps()), len(Probes))
	}
}

// Each signature matches a plausible file and refuses what a catch-all or a
// look-alike serves.
func TestProbeSignatures(t *testing.T) {
	cases := map[string]struct{ yes, no []string }{
		"git_head":         {[]string{"ref: refs/heads/main\n", "0123456789abcdef0123456789abcdef01234567\n"}, []string{"<!doctype html><html>", "ref: refs/heads/main\n<html>", ""}},
		"git_config":       {[]string{"[core]\n\trepositoryformatversion = 0\n"}, []string{"[coreboard]", "<html>[core]"}},
		"env":              {[]string{"APP_KEY=base64:abc\nDB_PASSWORD=x\n", "export STRIPE_KEY=[REDACTED:stripe:30]\n"}, []string{"<html><body>Not found</body></html>", "key=value\n"}},
		"htpasswd":         {[]string{"admin:$apr1$abc$def\n"}, []string{"admin:password\n"}},
		"server_status":    {[]string{"<h1>Apache Server Status for example.com</h1>"}, []string{"<h1>Forbidden</h1>"}},
		"npmrc":            {[]string{"//registry.npmjs.org/:_authToken=[REDACTED]\n"}, []string{"<html>"}},
		"wp_config_bak":    {[]string{"define( 'DB_PASSWORD', 'x' );"}, []string{"<?php // silence"}},
		"wp_debug_log":     {[]string{"[01-Oct-2026 10:00:00 UTC] PHP Warning: x"}, []string{"<html>"}},
		"phpinfo":          {[]string{"<title>phpinfo()</title>PHP Version 8.3.1"}, []string{"<html>not found</html>"}},
		"symfony_profiler": {[]string{"<title>Symfony Profiler</title>"}, []string{"<html>"}},
		"laravel_ignition": {[]string{`{"can_execute_commands":false}`}, []string{`{"ok":true}`}},
		"spring_env":       {[]string{`{"activeProfiles":[],"propertySources":[]}`}, []string{`{"status":"UP"}`}},
		"rails_info":       {[]string{"<td>Rails version</td>"}, []string{"<html>"}},
	}
	for _, p := range Probes {
		c, ok := cases[p.ID]
		if !ok {
			t.Errorf("%s has no signature cases", p.ID)
			continue
		}
		re := regexp.MustCompile(p.Signature.Pattern)
		for _, b := range c.yes {
			if !re.MatchString(b) {
				t.Errorf("%s: %q should match", p.ID, b)
			}
		}
		for _, b := range c.no {
			if re.MatchString(b) {
				t.Errorf("%s: %q should not match", p.ID, b)
			}
		}
	}
}

func TestSelectProbesByFramework(t *testing.T) {
	ids := func(ps []Probe) []string {
		out := []string{}
		for _, p := range ps {
			out = append(out, p.ID)
		}
		return out
	}
	for name, tc := range map[string]struct {
		frameworks []string
		has, not   []string
	}{
		"nothing declared": {nil, []string{"env", "git_head"}, []string{"phpinfo", "spring_env", "wp_debug_log"}},
		"unknown":          {[]string{"unknown"}, []string{"env"}, []string{"laravel_ignition"}},
		"none":             {[]string{"none"}, []string{"env"}, []string{"npmrc"}},
		"laravel":          {[]string{"laravel"}, []string{"env", "laravel_ignition", "phpinfo"}, []string{"spring_env", "wp_debug_log"}},
		"wordpress":        {[]string{"wordpress"}, []string{"wp_debug_log", "wp_config_bak", "phpinfo"}, []string{"laravel_ignition"}},
		"spring":           {[]string{"spring"}, []string{"spring_env"}, []string{"phpinfo"}},
		"django":           {[]string{"django"}, []string{"env"}, []string{"phpinfo", "spring_env", "rails_info"}},
	} {
		apply, skipped := SelectProbes(tc.frameworks)
		for _, id := range tc.has {
			if !slices.Contains(ids(apply), id) {
				t.Errorf("%s: %s not selected", name, id)
			}
		}
		for _, id := range tc.not {
			if slices.Contains(ids(apply), id) || !slices.Contains(ids(skipped), id) {
				t.Errorf("%s: %s should be skipped", name, id)
			}
		}
		if len(apply)+len(skipped) != len(Probes) {
			t.Errorf("%s: the list is split into %d and %d", name, len(apply), len(skipped))
		}
	}
}

// probeGate answers each probe with a scripted result and counts what was
// sent.
type probeGate struct {
	Gate
	sent    []string
	results map[string]gate.Result
}

func (g *probeGate) Send(_ context.Context, r gate.Request) gate.Result {
	g.sent = append(g.sent, r.Op+" "+r.Params["scheme"]+"://"+r.Params["host"])
	if res, ok := g.results[r.Op]; ok {
		return res
	}
	return gate.Result{RequestID: "r-" + r.Op, Decision: gate.DecisionSent, Response: &gate.Response{Status: 404}}
}

// A probe is one request: the collector sends exactly the list it was
// given, once each, and a refusal that holds for the site ends its list.
func TestCollectProbesSendsTheDeclaredCountAndStopsOnASiteRefusal(t *testing.T) {
	apply, _ := SelectProbes(nil)
	g := &probeGate{}
	ev := CollectProbes(context.Background(), g, "domain:example.com",
		[]ProbeTarget{{Name: "shop.example.com", Scheme: "https", Mode: "all", Evidence: "url root", Send: apply}})
	if len(g.sent) != len(apply) || len(ev.Sites[0].Reads) != len(apply) {
		t.Fatalf("sent %d of %d: %v", len(g.sent), len(apply), g.sent)
	}
	g = &probeGate{results: map[string]gate.Result{OpProbe(apply[1]): {RequestID: "w", Decision: "refused:window", Reason: "limit_reached"}}}
	ev = CollectProbes(context.Background(), g, "domain:example.com",
		[]ProbeTarget{{Name: "shop.example.com", Scheme: "https", Mode: "all", Send: apply,
			Skip: []ProbeSkip{{Probe: Probes[len(Probes)-1], Why: NotRunNoTTY}}}})
	if len(g.sent) != 2 {
		t.Errorf("a refusal for the whole site did not stop the list: %v", g.sent)
	}
	reads := ev.Sites[0].Reads
	if reads[0].NotRun != NotRunNoTTY || reads[len(reads)-1].NotRun != NotRunWindow || reads[len(reads)-1].RequestID != "" {
		t.Errorf("%+v", reads)
	}
}

// probeOutcomes judges one read of each finding id three ways.
func probeOutcomes(t *testing.T) []Judgment {
	t.Helper()
	body := func(status int, matched bool, redacted ...string) gate.Result {
		return gate.Result{RequestID: "p", Decision: gate.DecisionSent, Response: &gate.Response{Status: status, Matched: matched,
			Header: http.Header{"Content-Type": {"text/plain"}}, Redactions: func() []policy.Hit {
				var h []policy.Hit
				for _, r := range redacted {
					h = append(h, policy.Hit{Rule: r, Bytes: 9})
				}
				return h
			}()}}
	}
	var out []Judgment
	for _, p := range []string{"git_head", "env", "phpinfo"} {
		for _, res := range []gate.Result{body(200, true), body(404, false), body(403, false)} {
			g := &probeGate{results: map[string]gate.Result{"web.probe." + p: res}}
			var pr Probe
			for _, c := range Probes {
				if c.ID == p {
					pr = c
				}
			}
			ev := CollectProbes(context.Background(), g, "domain:example.com", []ProbeTarget{{Name: "shop.example.com", Scheme: "https", Mode: "all", Evidence: "url root", Send: []Probe{pr}}})
			out = append(out, Judge(Input{Asset: "domain:example.com", Probes: &ev})...)
		}
	}
	return out
}

func TestProbeVerdicts(t *testing.T) {
	read := func(status int, matched bool, decision string, redacted ...string) Judgment {
		in := Input{Asset: "domain:example.com", Probes: &ProbeEvidence{Sites: []ProbeSite{{Name: "shop.example.com", Reads: []ProbeRead{
			{Probe: "env", URL: "https://shop.example.com/.env", Finding: finding.IDWebConfigFileExposed, RequestID: "r1", Decision: decision, Status: status, Matched: matched, Redacted: redacted, ContentType: "text/plain"}}}}}}
		js := Judge(in)
		if len(js) != 1 {
			t.Fatalf("%d judgments", len(js))
		}
		return js[0]
	}
	for _, tc := range []struct {
		name    string
		got     Judgment
		verdict string
		reason  string
	}{
		{"matched", read(200, true, "sent", "kv-secret:12"), Fired, ""},
		{"not found", read(404, false, "sent"), Disproved, ""},
		{"gone", read(410, false, "sent"), Disproved, ""},
		{"a 200 of another shape", read(200, false, "sent"), Disproved, ""},
		{"a 200 with something redacted", read(200, false, "sent", "kv-secret:12"), Abstained, "unavailable:redacted"},
		{"forbidden", read(403, false, "sent"), Abstained, "unavailable:http_status"},
		{"rate limited", read(429, false, "sent"), Abstained, "unavailable:http_status"},
		{"server error", read(503, false, "sent"), Abstained, "unavailable:http_status"},
		{"redirected", read(302, false, "sent"), Abstained, "unavailable:redirected"},
		{"outside the window", read(0, false, "refused:window"), Abstained, "unavailable:probe_window"},
		{"no evidence", read(0, false, "refused:first_party"), Abstained, "unavailable:probe_evidence"},
		{"certificate", read(0, false, "unavailable:tls_invalid"), Abstained, "unavailable:tls_invalid"},
	} {
		if tc.got.Verdict != tc.verdict || tc.got.Reason != tc.reason {
			t.Errorf("%s: %s %q", tc.name, tc.got.Verdict, tc.got.Reason)
		}
		if tc.got.Subject.Kind != "url" || tc.got.Subject.Key != "https://shop.example.com/.env" {
			t.Errorf("%s: subject %+v", tc.name, tc.got.Subject)
		}
	}
	fired := read(200, true, "sent", "kv-secret:12")
	if strings.Contains(fired.Excerpt, "APP_KEY") || fired.Details["redacted"] == nil {
		t.Errorf("%+v", fired)
	}
}

// A probe that was not run is abstained with the reason it was not, never
// disproved.
func TestProbeNotRunIsNeverClean(t *testing.T) {
	for _, why := range []string{NotRunNoTTY, NotRunDeclined, NotRunNoAnswer, NotRunMode} {
		js := Judge(Input{Asset: "domain:example.com", Probes: &ProbeEvidence{Sites: []ProbeSite{{Name: "shop.example.com",
			Reads: []ProbeRead{{Probe: "env", URL: "https://shop.example.com/.env", Finding: finding.IDWebConfigFileExposed, NotRun: why}}}}}})
		if len(js) != 1 || js[0].Verdict != Abstained || js[0].Reason != "unavailable:"+why {
			t.Errorf("%s: %+v", why, js)
		}
	}
}
