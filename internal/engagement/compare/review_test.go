package compare

import (
	"bytes"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/report"
	hostreport "github.com/b87/scheck/internal/report"
)

// A finding on an asset the later run no longer lists must not crash the
// comparison: it is a removed asset.
func TestAssetListedBeforeButNotNowDoesNotCrash(t *testing.T) {
	e, l := pairLab()
	e.asset("domain:old.example.com", "old", "domain", "collected", "")
	e.find("web.a", "domain:old.example.com", "", "medium")
	l.find("web.a", "domain:old.example.com", "", "medium")
	c := compareOK(t, e, l)
	found := false
	for _, a := range c.Assets {
		if a.Change == "unlisted" && a.Asset == "domain:old.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("assets: %+v", c.Assets)
	}
	// Open in both runs: still open, not gone plus first reported.
	if i := category(c, "web.a"); i.Category != StillOpen || c.Exit.Code != 0 {
		t.Errorf("got %+v exit %d", i, c.Exit.Code)
	}
}

// With different redaction rules no earlier-only name may reach the output:
// not a renamed subject, not a fixed instance's not-checked lines.
func TestEarlierNamesStayHomeWhenRedactionRulesDiffer(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	l.Redaction.Operator.Rules = 1
	ef := e.find("identity.a", ws, "alice-secret-project", "high")
	ef.Subject.ProviderID = "123"
	lf := l.find("identity.a", ws, "[REDACTED:extra:20 bytes]", "high")
	lf.Subject.ProviderID = "123"
	gf := e.find("identity.b", ws, "bob-secret", "high")
	gf.NotChecked = []string{"whether bob-secret still has a token"}
	l.notMatched("identity.b", ws)
	c := compareOK(t, e, l)
	var js, tx bytes.Buffer
	if err := WriteJSON(&js, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&tx, c, hostreport.Options{Verbose: 1}); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{js.String(), tx.String()} {
		for _, secret := range []string{"alice-secret-project", "bob-secret"} {
			if strings.Contains(out, secret) {
				t.Errorf("%q reached the output:\n%s", secret, out)
			}
		}
	}
}

// An unchanged finding whose name is hidden is unknown, not a worsening.
func TestUnmatchableSubjectIsNotAWorsening(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("svc.a", web, "[REDACTED:extra:5 bytes]", "high")
	l.find("svc.a", web, "[REDACTED:extra:5 bytes]", "high")
	if c := compareOK(t, e, l); c.Exit.Code != 0 {
		t.Errorf("exit %d: %+v", c.Exit.Code, c.Exit)
	}
}

// Only a release tag names a build that can be installed again.
func TestOnlyReleaseTagsAreTheSameRules(t *testing.T) {
	for v, want := range map[string]bool{
		"0.0.3": true, "v0.0.3": true, "": false, "dev": false, "v0.0.2-14-g53ef2eb": false,
		"v0.0.3-dirty": false, "unknown": false, "0.0.3+local": false,
	} {
		if got := releaseBuild(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}

func TestSeveritiesAreEscapedInText(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("fw.a", web, "", "high")
	l.find("fw.a", web, "", "\x1b[2Jevil")
	var tx bytes.Buffer
	if err := WriteText(&tx, compareOK(t, e, l), hostreport.Options{Verbose: 1}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(tx.String(), 0x1b) {
		t.Errorf("a raw escape reached the text:\n%q", tx.String())
	}
}

func TestAcceptedFindingsGoneAreCountedApart(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("fw.a", web, "", "high")
	af := e.find("fw.b", web, "", "high")
	af.Status, af.Acceptance = "accepted", acceptance("carol", nil)
	l.notMatched("fw.a", web)
	l.notMatched("fw.b", web)
	c := compareOK(t, e, l)
	if c.Summary.EarlierOpen != 1 || c.Summary.EarlierAccepted != 1 || c.Summary.Fixed != 2 {
		t.Errorf("%+v", c.Summary)
	}
}

// A pattern added between the runs hides the name of an instance that is
// still there: it is neither fixed nor new.
func TestInstanceHiddenByALaterPatternIsNotFixed(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	l.Redaction.Operator.Rules = 1 // the later run added the pattern
	e.find("svc.a", web, "6379/tcp", "high")
	l.find("svc.a", web, "[REDACTED:extra:8 bytes]", "high")
	c := compareOK(t, e, l)
	if c.Summary.Fixed != 0 || c.Summary.New != 0 || c.Exit.Code != 0 {
		t.Errorf("%+v %+v", c.Summary, c.Exit)
	}
	// And the other way round.
	e, l = pairLab()
	e.Redaction.Operator.Rules = 1 // the earlier run hid names the later one shows
	e.find("svc.a", web, "[REDACTED:extra:8 bytes]", "high")
	l.find("svc.a", web, "6379/tcp", "high")
	c = compareOK(t, e, l)
	if c.Summary.Fixed != 0 || c.Summary.New != 0 || c.Exit.Code != 0 {
		t.Errorf("reverse: %+v %+v", c.Summary, c.Exit)
	}
}

func TestHiddenInstanceOnAnUnreadEarlierAssetIsNotWorse(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.Assets[0].Status = "incomplete"
	e.find("svc.a", web, "[REDACTED:extra:8 bytes]", "high")
	l.find("svc.a", web, "[REDACTED:extra:8 bytes]", "high")
	if c := compareOK(t, e, l); c.Exit.Code != 0 {
		t.Errorf("%+v", c.Exit)
	}
}

func TestDiscoveredAssetNamesStayHomeWhenRedactionRulesDiffer(t *testing.T) {
	const repo = "repo:github:acme/secret-repo"
	e, l := pairLab()
	l.Redaction.Operator.Rules = 1
	a := e.asset(repo, "secret-repo", "repo", "collected", "")
	a.Root = false
	e.find("ci.a", repo, "", "high")
	var js, tx bytes.Buffer
	c := compareOK(t, e, l)
	if err := WriteJSON(&js, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&tx, c, hostreport.Options{Verbose: 1}); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{js.String(), tx.String()} {
		if strings.Contains(out, "secret-repo") {
			t.Errorf("a discovered name reached the output:\n%s", out)
		}
	}
}

func TestAReplacedMachineIsNotTheSameInstance(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("fw.a", web, "", "high")
	*l.Assets[0].BoundID = "B-other"
	l.find("fw.a", web, "", "high")
	c := compareOK(t, e, l)
	for _, i := range c.Instances {
		if i.Category == StillOpen {
			t.Errorf("joined across a replaced machine: %+v", i)
		}
	}
}

func TestLowercasedRedactionMarkerIsHidden(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	l.Redaction.Operator.Rules = 1
	e.find("identity.ou", ws, "/bigbank", "high")
	l.find("identity.ou", ws, "[redacted:redact_extra:8 bytes]", "high")
	c := compareOK(t, e, l)
	if c.Summary.Fixed != 0 || c.Summary.New != 0 || c.Exit.Code != 0 {
		t.Errorf("%+v %+v", c.Summary, c.Exit)
	}
}

// With the same redaction rules a visible new name cannot be an earlier
// hidden one: it is a new finding and counts.
func TestVisibleNewFindingBesideAHiddenOneStillCounts(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.find("identity.no_2sv", ws, "[REDACTED:redact_extra:14 bytes]", "high")
	l.find("identity.no_2sv", ws, "[REDACTED:redact_extra:14 bytes]", "high")
	l.find("identity.no_2sv", ws, "bob@acme.com", "high")
	if c := compareOK(t, e, l); c.Exit.Code != 1 {
		t.Errorf("exit %d: %+v", c.Exit.Code, c.Instances)
	}
}

func TestEarlierLabelAndPrincipalStayHomeWhenRedactionRulesDiffer(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.principal(ws, "alice-admin (user ID 7)")
	l.principal(ws, "[REDACTED:redact_extra:11 bytes] (user ID 7)")
	l.Redaction.Operator.Rules = 1
	ef := e.find("oauth.broad", ws, "client-1", "high")
	ef.Subject.Label = "BigBank Exporter"
	lf := l.find("oauth.broad", ws, "client-1", "high")
	lf.Subject.Label = "[REDACTED:redact_extra:7 bytes] Exporter"
	c := compareOK(t, e, l)
	var js, tx bytes.Buffer
	if err := WriteJSON(&js, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&tx, c, hostreport.Options{Verbose: 1}); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{js.String(), tx.String()} {
		for _, secret := range []string{"BigBank", "alice-admin"} {
			if strings.Contains(out, secret) {
				t.Errorf("%q reached the output:\n%s", secret, out)
			}
		}
	}
}

func TestAssetWithNoRowCannotConfirmFixedOrNew(t *testing.T) {
	const name = "domain:found.example.com"
	e, l := pairLab()
	e.asset("domain:example.com", "example", "domain", "collected", "")
	l.asset("domain:example.com", "example", "domain", "collected", "")
	e.find("web.a", name, "", "high")
	e.Assets = e.Assets[:len(e.Assets)]
	l.notMatched("web.a", name)
	l.find("web.b", name, "", "high")
	e.notMatched("web.b", name)
	c := compareOK(t, e, l)
	if c.Summary.Fixed != 0 || c.Summary.New != 0 {
		t.Errorf("%+v", c.Summary)
	}
}

func TestAProviderIDThatContradictsTheKeyDoesNotJoin(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.find("identity.a", ws, "alice", "high").Subject.ProviderID = "1"
	e.find("identity.a", ws, "bob", "high").Subject.ProviderID = "2"
	l.find("identity.a", ws, "bob", "high").Subject.ProviderID = "1"
	l.find("identity.a", ws, "carol", "high").Subject.ProviderID = "2"
	c := compareOK(t, e, l)
	for _, i := range c.Instances {
		if i.Category == StillOpen && i.Earlier.Subject.Key != i.Later.Subject.Key && i.Identity == "" {
			t.Errorf("joined: %+v", i)
		}
	}
	if c.Summary.Fixed != 0 {
		t.Errorf("a login that is still there was called fixed: %+v", c.Summary)
	}
}

func TestAVisibleNameTheEarlierRunDisprovedStillCounts(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.Redaction.Operator.Rules = 1
	e.rule("workspace.two_step", ws, "not_matched", true,
		report.AssessmentOutcome{Subject: &report.Subject{Kind: "org_unit", Key: "/[REDACTED:redact_extra:7 bytes]"}, Outcome: "disproved", Detail: map[string]any{}},
		report.AssessmentOutcome{Subject: &report.Subject{Kind: "org_unit", Key: "/Eng"}, Outcome: "disproved", Detail: map[string]any{}})
	l.find("workspace.two_step", ws, "/Eng", "high")
	c := compareOK(t, e, l)
	if i := category(c, "workspace.two_step"); i.Category != New || c.Exit.Code != 1 {
		t.Errorf("%+v exit %d", i, c.Exit.Code)
	}
}

func TestAHiddenNameNobodyHeldBeforeIsNew(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
		r.Redaction.Operator.Rules = 1
	}
	e.notMatched("identity.no_2sv", ws)
	l.find("identity.no_2sv", ws, "[REDACTED:redact_extra:14 bytes]", "high")
	c := compareOK(t, e, l)
	if i := category(c, "identity.no_2sv"); i.Category != New || c.Exit.Code != 1 {
		t.Errorf("%+v exit %d", i, c.Exit.Code)
	}
}

func TestAnAccountThatNowHoldsANameIsNotTheSameInstance(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	e.find("identity.a", ws, "alice@acme.com", "high").Subject.ProviderID = "1"
	l.find("identity.a", ws, "alice@acme.com", "high").Subject.ProviderID = "2"
	c := compareOK(t, e, l)
	var gone, appeared bool
	for _, i := range c.Instances {
		gone = gone || i.Category == NotConfirmed && i.Cause == CauseSubjectReplaced
		appeared = appeared || i.Category == FirstReported && i.Cause == CauseSubjectReplaced
		if i.Category == Fixed || i.Category == New {
			t.Errorf("%+v", i)
		}
	}
	if !gone || !appeared || c.Exit.Code != 1 {
		t.Errorf("%+v", c.Instances)
	}
}

func TestEarlierBoundIDStaysHomeWhenRedactionRulesDiffer(t *testing.T) {
	e, l := pairLab()
	l.Redaction.Operator.Rules = 1
	*l.Assets[0].BoundID = "B-later"
	e.find("fw.a", "host:203.0.113.6:22", "", "high")
	l.find("fw.a", "host:203.0.113.6:22", "", "high")
	var js bytes.Buffer
	if err := WriteJSON(&js, compareOK(t, e, l)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(js.String(), "B-web") {
		t.Errorf("an earlier bound id reached the output:\n%s", js.String())
	}
}

func TestASupersededInstanceIsNotFixed(t *testing.T) {
	const repo = "repo:github:example-org/shop"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(repo, "shop", "repo", "collected", "")
	}
	e.find("github.mutable_action_reference", repo, "release.yml", "medium")
	l.rule("github.mutable_action_reference", repo, "matched", true,
		report.AssessmentOutcome{Subject: &report.Subject{Kind: "workflow", Key: "release.yml"}, Outcome: "fired", Detail: map[string]any{"superseded_by": "github.mutable_action_with_write_token"}})
	l.find("github.mutable_action_with_write_token", repo, "release.yml", "high")
	c := compareOK(t, e, l)
	if i := category(c, "github.mutable_action_reference"); i.Category == Fixed {
		t.Errorf("a superseded instance was called fixed: %+v", i)
	}
}

func TestAnotherVisibleNameBesideAKnownOneCountsWhenRulesDiffer(t *testing.T) {
	const ws = "saas:google-workspace:example.com"
	e, l := pairLab()
	for _, r := range []*lab{e, l} {
		r.asset(ws, "ws", "saas", "collected", "C1")
	}
	l.Redaction.Operator.Rules = 1
	e.find("identity.no_2sv", ws, "alice@acme.com", "high")
	l.find("identity.no_2sv", ws, "alice@acme.com", "high")
	l.find("identity.no_2sv", ws, "mallory@acme.com", "high")
	if c := compareOK(t, e, l); c.Exit.Code != 1 {
		t.Errorf("exit %d: %+v", c.Exit.Code, c.Instances)
	}
}

func TestGoneOnAnAssetTheEarlierRunDidNotListIsNotFixed(t *testing.T) {
	const name = "domain:dev.example.com"
	e, l := pairLab()
	l.asset(name, "dev", "domain", "collected", "")
	e.find("web.a", name, "", "medium")
	l.notMatched("web.a", name)
	c := compareOK(t, e, l)
	if i := category(c, "web.a"); i.Category != NotRechecked || i.Cause != CauseAssetNotListed {
		t.Errorf("%+v", i)
	}
}

func TestAnUnknownAssessmentStatusDecidesNothing(t *testing.T) {
	const web = "host:203.0.113.6:22"
	e, l := pairLab()
	e.find("fw.a", web, "", "medium")
	l.rule("fw.a", web, "bogus", true)
	if i := category(compareOK(t, e, l), "fw.a"); i.Category == Fixed {
		t.Errorf("%+v", i)
	}
}
