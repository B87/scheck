package severity

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/finding"
)

func fired(id string, attrs ...finding.Attribute) finding.Judgment {
	return finding.Judgment{ID: id, Verdict: Fired, Reads: []string{"r1"}, Excerpt: "observed", Attributes: attrs}
}

func moved(c *finding.Chain) []string {
	var out []string
	for _, m := range c.Moves {
		if m.Stopped == "" {
			out = append(out, m.Rule)
		}
	}
	return out
}

// Every finding id a row names is a registered definition, so a renamed
// id cannot leave a row that silently never applies.
func TestEveryRowNamesRegisteredDefinitions(t *testing.T) {
	ids := append([]string{}, productionIDs...)
	ids = append(ids, finding.IDIdentityFormerPersonHasAccess, workspace.IDExternalForwarding, workspace.IDOAuthBroadScope,
		finding.IDGitHubSecretScanningOpen, finding.IDGitHubHistoryCredential)
	for _, id := range ids {
		if _, ok := finding.Lookup(id); !ok {
			t.Errorf("row names unregistered id %s", id)
		}
	}
}

// data.matters_most applies whether or not the collector wrote a sentence:
// a rule that applies is never skipped because of another
// (docs/spec/engagement.md, "Stacking").
func TestDataMattersMostStacksWithContextAndContradiction(t *testing.T) {
	j := fired(finding.IDIdentityUnexpectedAdmin, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "access.admins[0]"}})
	j.Why = "a collector sentence"
	d := Declarations{MattersMost: []Matter{{Asset: "saas:github:acme", Name: "acme", What: "customer orders", Key: "data.matters_most[1]"}}}
	c := Grade(j, "saas:github:acme", d)
	if got := strings.Join(moved(c), ","); got != "data_matters_most,contradiction" || c.Severity != finding.SevCritical {
		t.Fatalf("moves %s, severity %s", got, c.Severity)
	}
	if c.Moves[0].Ref.Key != "data.matters_most[1]" || !strings.Contains(c.Moves[0].Why, "as holding customer orders,") {
		t.Fatal(c.Moves[0])
	}
}

// deploys_to:production and data_matters_most stop at high, with the cap
// worded; contradiction may pass it.
func TestPastHighCapsAreRecordedAndWorded(t *testing.T) {
	j := fired(finding.IDGitHubWritableDeployKey)
	d := Declarations{Production: map[string]Production{"repo:github:acme/shop": {Name: "shop", Key: "assets.shop.deploys_to"}}}
	c := Grade(j, "repo:github:acme/shop", d)
	if c.Severity != finding.SevHigh || strings.Join(moved(c), ",") != "deploys_to:production" || c.Moves[0].Ref.Key != "assets.shop.deploys_to" {
		t.Fatal(c)
	}
	// A leaver starts at high: data_matters_most stops there, worded;
	// admin passes it, then contradiction meets the scale's end.
	j = fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "access.mfa[0]"}}, finding.Attribute{Name: "admin"})
	d = Declarations{MattersMost: []Matter{{Asset: "saas:github:acme", Name: "acme", Key: "data.matters_most[0]"}}}
	c = Grade(j, "saas:github:acme", d)
	if c.Severity != finding.SevCritical || len(c.Moves) != 3 ||
		c.Moves[0].Stopped != finding.StoppedPastHigh || !strings.HasPrefix(c.Moves[0].Why, "capped at high by data_matters_most: critical means") ||
		c.Moves[1].Rule != "contradiction" || c.Moves[1].Stopped != "" || c.Moves[2].Stopped != finding.StoppedScaleEnd || c.Moves[2].Why != "" {
		t.Fatal(c)
	}
	// Forwarding from an admin's mailbox rises to high and no further.
	c = Grade(fired(workspace.IDExternalForwarding, finding.Attribute{Name: "admin"}), "", Declarations{})
	if c.Severity != finding.SevHigh || strings.Join(moved(c), ",") != "attribute:admin" {
		t.Fatal(c)
	}
}

// exposed_on_purpose lowers an exposure finding to info and ends the
// chain; every later row that would apply is recorded as not applied.
func TestExposedOnPurposeIsTerminal(t *testing.T) {
	j := fired(finding.IDWebVersionDisclosed)
	j.Subject = finding.Subject{Kind: "url", Key: "https://example.com/"}
	d := Declarations{Exposed: []Exposed{{URL: "https://example.com/", Reason: "public build page", Key: "intent.exposed_on_purpose[0]"}}}
	c := Grade(j, "url:https://example.com/", d)
	if c.Severity != finding.SevInfo || len(c.Moves) != 1 || c.Moves[0].Rule != "exposed_on_purpose" {
		t.Fatal(c)
	}
	// Another URL is not lowered; a non-exposure finding never is.
	j.Subject.Key = "https://example.com/other"
	if c := Grade(j, "", d); c.Severity != finding.SevLow {
		t.Fatal(c)
	}
	s := fired(finding.IDWebSecretInResponse)
	s.Subject = finding.Subject{Kind: "url", Key: "https://example.com/"}
	if c := Grade(s, "", d); c.Severity != finding.SevCritical || len(c.Moves) != 0 {
		t.Fatal(c)
	}
}

func TestExposedSkipsLaterRowsAndSaysSo(t *testing.T) {
	j := fired(finding.IDWebVersionDisclosed, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "intent.not_exposed[0]"}})
	j.Subject = finding.Subject{Kind: "url", Key: "https://example.com/"}
	d := Declarations{Exposed: []Exposed{{URL: "https://example.com/", Reason: "public", Key: "intent.exposed_on_purpose[0]"}}}
	c := Grade(j, "", d)
	last := c.Moves[len(c.Moves)-1]
	if c.Severity != finding.SevInfo || last.Rule != "contradiction" || last.Stopped != finding.StoppedExposed ||
		last.Why != "not applied: declared exposed on purpose (intent.exposed_on_purpose[0])." {
		t.Fatal(c)
	}
}

// The collector's own steps apply first, by the collector, citing the
// judgment's read when the collector cited nothing else.
func TestCollectorStepsFirst(t *testing.T) {
	c := Grade(fired(finding.IDWebPlaintextHTTP, finding.Attribute{Name: "password_form"}), "", Declarations{})
	if c.Severity != finding.SevMedium || c.Moves[0].By != finding.ByCollector || c.Moves[0].Ref.Observation != "r1" || c.Moves[0].Ref.Excerpt != "observed" {
		t.Fatal(c)
	}
	c = Grade(fired(finding.IDWebSecretInResponse, finding.Attribute{Name: "slack_webhook"}), "", Declarations{})
	if c.Severity != finding.SevHigh || c.Moves[0].Delta != -1 {
		t.Fatal(c)
	}
}

// A chain a collector set is replaced; only fired judgments are graded.
func TestGradeAllReplacesAnyChain(t *testing.T) {
	forged := &finding.Chain{Base: finding.SevCritical, Severity: finding.SevCritical}
	js := []finding.Judgment{fired(finding.IDWebPlaintextHTTP), {ID: finding.IDWebPlaintextHTTP, Verdict: "disproved", Chain: forged}}
	js[0].Chain = forged
	GradeAll(js, "", Declarations{})
	if js[0].Chain == forged || js[0].Chain.Severity != finding.SevLow || js[1].Chain != nil {
		t.Fatal(js)
	}
}

// A finding already at critical meets the scale's end, never a cap: it
// must not say "capped at high".
func TestCriticalMeetsScaleEndNotCap(t *testing.T) {
	j := fired(finding.IDWebSecretInResponse)
	d := Declarations{MattersMost: []Matter{{Asset: "url:https://example.com/", Name: "site", Key: "data.matters_most[0]"}}}
	c := Grade(j, "url:https://example.com/", d)
	if c.Severity != finding.SevCritical || len(c.Moves) != 1 || c.Moves[0].Stopped != finding.StoppedScaleEnd || c.Moves[0].Why != "" {
		t.Fatal(c)
	}
}

// A contradiction rests on a declaration; an attribute that names none
// contradicts nothing and moves nothing.
func TestContradictionNeedsItsDeclaration(t *testing.T) {
	c := Grade(fired(finding.IDIdentityUnexpectedAdmin, finding.Attribute{Name: "contradiction"}), "", Declarations{})
	if len(c.Moves) != 0 || c.Severity != c.Base {
		t.Fatal(c)
	}
}

// Every step that can move a severity says why, in its own words or the
// collector's: a raise with no sentence would print a cap or "the standard
// rating" as its reason.
func TestEveryMovingStepHasASentence(t *testing.T) {
	for _, def := range finding.Defs() {
		for _, a := range def.Attributes {
			if a.Why == "" {
				t.Errorf("%s: attribute %s has no sentence", def.ID, a.Name)
			}
		}
	}
	url := finding.Subject{Kind: "url", Key: "https://example.com/"}
	d := Declarations{
		Exposed:     []Exposed{{URL: url.Key, Reason: "public", Key: "intent.exposed_on_purpose[0]"}},
		MattersMost: []Matter{{Asset: "a", Name: "a", Key: "data.matters_most[0]"}},
		Production:  map[string]Production{"a": {Name: "a", Key: "assets.a.deploys_to"}},
	}
	cases := []finding.Judgment{
		fired(finding.IDWebVersionDisclosed),
		fired(finding.IDIdentityUnexpectedAdmin, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "access.admins"}}),
		fired(finding.IDGitHubWritableDeployKey),
		fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "admin"}),
		fired(workspace.IDExternalForwarding, finding.Attribute{Name: "admin"}),
		fired(workspace.IDOAuthBroadScope, finding.Attribute{Name: "admin_grantor"}),
		fired(finding.IDGitHubSecretScanningOpen, finding.Attribute{Name: "public_repository"}),
	}
	cases[0].Subject = url
	seen := map[string]bool{}
	for _, j := range cases {
		// Graded under an asset data.matters_most names and under one it
		// does not, so a row stopped by an earlier raise also moves once.
		for _, m := range append(Grade(j, "a", d).Moves, Grade(j, "b", d).Moves...) {
			if m.Stopped == "" {
				seen[m.Rule+" "+j.ID] = true
				if m.Why == "" && j.Why == "" {
					t.Errorf("%s on %s moved with no sentence", m.Rule, j.ID)
				}
			}
		}
	}
	// Each row by itself: two rows may share a printed name.
	for i, r := range rules {
		found := false
		for k := range seen {
			name, id, _ := strings.Cut(k, " ")
			found = found || name == r.name && (r.ids == nil || slices.Contains(r.ids, id))
		}
		if !found {
			t.Errorf("row %d (%s) never moved in this test", i, r.name)
		}
	}
}
