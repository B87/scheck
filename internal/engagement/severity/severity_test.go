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
	ids = append(ids, finding.IDDBListensUnfiltered, finding.IDIdentityFormerPersonHasAccess, workspace.IDExternalForwarding, workspace.IDOAuthBroadScope,
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
		Internet:    map[string]string{"b": "assets.b.context.exposure"},
	}
	cases := []finding.Judgment{
		fired(finding.IDWebVersionDisclosed),
		fired(finding.IDIdentityUnexpectedAdmin, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "access.admins"}}),
		fired(finding.IDGitHubWritableDeployKey),
		fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "admin"}),
		fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "write", Ref: finding.Ref{Observation: "r", Excerpt: "push: true"}}),
		fired(workspace.IDExternalForwarding, finding.Attribute{Name: "admin"}),
		fired(workspace.IDOAuthBroadScope, finding.Attribute{Name: "admin_grantor"}),
		fired(finding.IDGitHubSecretScanningOpen, finding.Attribute{Name: "public_repository"}),
		fired(finding.IDDBListensUnfiltered),
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

// A database open on a host rises for the host's declared internet
// exposure and for a contradicted audience, and stops at its ceiling of
// high with the ceiling's words (docs/spec/engagement.md, R1, "Ceilings").
func TestAnOpenDatabaseStopsAtItsCeiling(t *testing.T) {
	const host = "host:db1:22"
	d := Declarations{Internet: map[string]string{host: "assets.db1.context.exposure"}}
	c := Grade(fired(finding.IDDBListensUnfiltered), host, d)
	if got := strings.Join(moved(c), ","); got != "exposure:internet" || c.Severity != finding.SevHigh || c.Moves[0].Ref.Key != "assets.db1.context.exposure" {
		t.Fatalf("moves %s, severity %s", got, c.Severity)
	}
	j := fired(finding.IDDBListensUnfiltered, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "assets.db1.context.expected_services[0]"}})
	c = Grade(j, host, d)
	last := c.Moves[len(c.Moves)-1]
	if c.Severity != finding.SevHigh || last.Rule != "contradiction" || last.Stopped != finding.StoppedCeiling || last.Why != whyCeiling {
		t.Fatalf("%+v", c)
	}
	if c := Grade(fired(finding.IDDBListensUnfiltered), "host:other:22", d); len(moved(c)) != 0 {
		t.Fatalf("another host's exposure moved it: %+v", c)
	}
	// The exposure row moves nothing but the database finding.
	if c := Grade(fired(finding.IDGitHubWritableDeployKey), host, d); slices.Contains(moved(c), "exposure:internet") {
		t.Fatalf("%+v", c)
	}
}

// R4: a left person's push on a repository declared production raises
// their access past high; an admin there is already critical, and the
// second step meets the scale's end. On a repository not declared
// production nothing moves (docs/spec/engagement.md, R4).
func TestProductionWriteRaisesALeftPersonsAccess(t *testing.T) {
	const shop, api = "repo:github:acme/shop", "repo:github:acme/api"
	d := Declarations{Production: map[string]Production{shop: {Name: "shop", Key: "assets.shop.deploys_to"}}}
	write := finding.Attribute{Name: "write", Ref: finding.Ref{Observation: "collab", Excerpt: "role_name: write; push: true"}}
	c := Grade(fired(finding.IDIdentityFormerPersonHasAccess, write), shop, d)
	m := c.Moves[len(c.Moves)-1]
	if c.Severity != finding.SevCritical || m.Rule != "attribute:production_write" || m.Ref.Observation != "collab" ||
		m.Why != "This person left and can still push to acme/shop, which you declared deploys to production, so this ranks one step higher." {
		t.Fatalf("%+v", c)
	}
	c = Grade(fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "repository_admin"}, write), shop, d)
	if got := strings.Join(moved(c), ","); got != "attribute:admin" || c.Severity != finding.SevCritical || c.Moves[1].Stopped != finding.StoppedScaleEnd {
		t.Fatalf("admin then write: %s %+v", got, c)
	}
	if c := Grade(fired(finding.IDIdentityFormerPersonHasAccess, finding.Attribute{Name: "repository_admin"}, write), api, d); len(c.Moves) != 0 || c.Severity != finding.SevHigh {
		t.Fatalf("not production: %+v", c)
	}
	// Workspace's leaver judgment carries no write fact.
	if c := Grade(fired(finding.IDIdentityFormerPersonHasAccess), shop, d); len(c.Moves) != 0 {
		t.Fatalf("%+v", c)
	}
}

// R4 not applied: said, not taken, on the judgment that carries the
// login's facts, naming the first unsettled production repository in
// canonical order and counting the rest; never when push is held on one,
// or when every unsettled repository is not production.
func TestProductionWriteNotEstablished(t *testing.T) {
	const org = "saas:github:acme"
	d := Declarations{Production: map[string]Production{
		"repo:github:acme/shop": {Name: "shop"}, "repo:github:acme/api": {Name: "api"}, "repo:github:acme/web": {Name: "web"}}}
	unsettled := func(asset, cause string) finding.Attribute {
		return finding.Attribute{Name: "write_unsettled", Asset: asset, Ref: finding.Ref{Observation: "r-" + asset, Excerpt: cause}}
	}
	j := fired(finding.IDIdentityFormerPersonHasAccess,
		unsettled("repo:github:acme/web", "web cause"), unsettled("repo:github:acme/api", "api cause"),
		unsettled("repo:github:acme/staging", "staging cause"), unsettled("repo:github:acme/shop", "shop cause"))
	c := Grade(j, org, d)
	if len(c.Moves) != 1 || c.Severity != finding.SevHigh {
		t.Fatalf("%+v", c)
	}
	m := c.Moves[0]
	if m.Rule != "attribute:production_write" || m.Stopped != finding.StoppedNotEstablished || m.From != m.To || m.Ref.Observation != "r-repo:github:acme/api" ||
		m.Why != "not applied: write access to production repositories was not established (api cause; and 2 more production repositories)." {
		t.Fatalf("%+v", m)
	}
	j = fired(finding.IDIdentityFormerPersonHasAccess, unsettled("repo:github:acme/shop", "shop cause"))
	if m := Grade(j, org, d).Moves[0]; m.Why != "not applied: write access to production repositories was not established (shop cause)." {
		t.Fatalf("%+v", m)
	}
	j.Attributes = append(j.Attributes, finding.Attribute{Name: "write_held", Asset: "repo:github:acme/web"})
	if c := Grade(j, org, d); len(c.Moves) != 0 {
		t.Fatalf("push held on a production repository: %+v", c)
	}
	j = fired(finding.IDIdentityFormerPersonHasAccess, unsettled("repo:github:acme/staging", "staging cause"))
	if c := Grade(j, org, d); len(c.Moves) != 0 {
		t.Fatalf("only a repository not declared production: %+v", c)
	}
	if c := Grade(j, org, Declarations{}); len(c.Moves) != 0 {
		t.Fatalf("nothing declared production: %+v", c)
	}
}

// R3 always carries its contradiction: medium, and high on a host
// declared internet-facing (docs/spec/engagement.md, R3).
func TestADeclaredServiceBeyondItsAudience(t *testing.T) {
	const host = "host:app:22"
	j := fired(finding.IDSvcListensBeyond, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "assets.app.context.expected_services[0]"}})
	if c := Grade(j, host, Declarations{}); c.Severity != finding.SevMedium || strings.Join(moved(c), ",") != "contradiction" {
		t.Fatalf("%+v", c)
	}
	d := Declarations{Internet: map[string]string{host: "assets.app.context.exposure"}}
	if c := Grade(j, host, d); c.Severity != finding.SevHigh || strings.Join(moved(c), ",") != "exposure:internet,contradiction" {
		t.Fatalf("%+v", c)
	}
}

// D8: on a host named in data.matters_most only the host access findings
// raise, whatever their area; R3 (external) and the other host findings
// do not. A host posture finding is raised from the severity the host
// collector's table left it at, and stops at high (docs/spec/engagement.md,
// "Severity in context").
func TestDataMattersMostOnAHostRaisesOnlyHostAccess(t *testing.T) {
	const host = "host:db1:22"
	d := Declarations{MattersMost: []Matter{{Asset: host, Name: "db1", What: "orders", Key: "data.matters_most[0]"}}}
	for _, id := range []string{finding.IDPasswordAuthEnabled, finding.IDRootLoginEnabled, finding.IDEmptyPassword} {
		def, _ := finding.Lookup(id)
		if !def.HostAccess {
			t.Fatalf("%s is not flagged", id)
		}
	}
	c := GradeHost(finding.IDPasswordAuthEnabled, finding.SevMedium, host, d)
	if c == nil || c.Severity != finding.SevHigh || strings.Join(moved(c), ",") != "data_matters_most" || c.Moves[0].Ref.Key != "data.matters_most[0]" ||
		c.Base != finding.SevMedium {
		t.Fatalf("%+v", c)
	}
	// Lowered by airgapped (-2) to low, the step still applies from there.
	if c := GradeHost(finding.IDPasswordAuthEnabled, finding.SevLow, host, d); c.Severity != finding.SevMedium {
		t.Fatalf("%+v", c)
	}
	// Left at high by the host table: the step stops there, worded.
	c = GradeHost(finding.IDRootLoginEnabled, finding.SevHigh, host, d)
	if c.Severity != finding.SevHigh || c.Moves[0].Stopped != finding.StoppedPastHigh || !strings.HasPrefix(c.Moves[0].Why, "capped at high by data_matters_most") {
		t.Fatalf("%+v", c)
	}
	for _, id := range []string{finding.IDAppFirewallDisabled, finding.IDUpdatesPending} {
		if c := GradeHost(id, finding.SevMedium, host, d); c != nil {
			t.Fatalf("%s moved: %+v", id, c)
		}
	}
	if c := GradeHost(finding.IDPasswordAuthEnabled, finding.SevMedium, "host:other:22", d); c != nil {
		t.Fatalf("another host: %+v", c)
	}
	// The multi-fact rules: R1 (data) and R2 (hosts) raise by their flag;
	// R3 (external) does not.
	if c := Grade(fired(finding.IDDBListensUnfiltered), host, d); strings.Join(moved(c), ",") != "data_matters_most" {
		t.Fatalf("R1: %+v", c)
	}
	if c := Grade(fired(finding.IDEmptyPasswordRemote), host, d); len(c.Moves) != 1 || c.Moves[0].Rule != "data_matters_most" || c.Severity != finding.SevCritical {
		t.Fatalf("R2: %+v", c)
	}
	r3 := fired(finding.IDSvcListensBeyond, finding.Attribute{Name: "contradiction", Ref: finding.Ref{Key: "assets.db1.context.expected_services[0]"}})
	if c := Grade(r3, host, d); slices.ContainsFunc(c.Moves, func(m finding.Move) bool { return m.Rule == "data_matters_most" }) {
		t.Fatalf("R3: %+v", c)
	}
	// Any other asset kind still matches by area.
	if c := Grade(fired(finding.IDIdentityUnexpectedAdmin), "saas:github:acme",
		Declarations{MattersMost: []Matter{{Asset: "saas:github:acme", Key: "data.matters_most[0]"}}}); strings.Join(moved(c), ",") != "data_matters_most" {
		t.Fatalf("by area: %+v", c)
	}
}
