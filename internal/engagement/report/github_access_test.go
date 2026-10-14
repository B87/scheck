package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
)

const githubAccessOrg = "saas:github:example-org"
const githubAccessRepo = "repo:github:example-org/production"

func githubAccessReport(t *testing.T, verdict string) Input {
	in := githubInventoryReport(t)
	in.Name = "GitHub identity and repository-access review"
	a := &in.Assets[0]
	a.Detail = "GitHub identity and repository-access evidence collected."
	a.NetworkTrace = nil
	for i, id := range []string{"principal", "organization", "membership", "members", "owners", "outside", "invitations", "repositories", "owners-no-mfa", "members-no-mfa", "repository", "collaborators", "keys"} {
		a.NetworkTrace = append(a.NetworkTrace, Trace{Request: id, At: in.Started.Add(time.Duration(i) * time.Second), Decision: "sent"})
	}
	in.Egress.Sources[0].Requests = 13
	a.InventoryNotes[0].Detail = "members: observed 6; owners: observed 5; outside collaborators: observed 1; pending invitations: observed 0; repositories visible to this credential: observed 4. Identity and repository-access rules were evaluated; unobserved permissions remain unknown."
	in.People = true
	in.Candidates = []Candidate{{Handle: "alex", Why: "employee"}}
	account := func(login, id, person string) Subject {
		return Subject{Kind: "account", Key: login, Label: login, ProviderID: id, Person: person}
	}
	// As internal/collector/github emits them under access.mfa: some (the
	// organization contradiction; owners raise only under everyone or admins).
	a.Judged = []Judgment{
		{ID: finding.IDGitHubMFANotRequired, Asset: githubAccessOrg, Reads: []string{"organization"}, Attributes: []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: "access.mfa[0]"}}}, Sources: []string{"access.mfa[0]"}, Excerpt: "two_factor_requirement_enabled=false", Details: map[string]any{"required": false}},
		{ID: finding.IDGitHubOwnerWithoutMFA, Asset: githubAccessOrg, Subject: account("alex", "41", "alex"), Reads: []string{"owners-no-mfa"}, Excerpt: "owner alex appears in the provider's 2fa_disabled owner list"},
		{ID: finding.IDIdentityFormerPersonHasAccess, Asset: githubAccessRepo, Subject: account("former", "42", "pat"), Reads: []string{"collaborators"}, Attributes: []finding.Attribute{{Name: "admin"}}, Sources: []string{"people.pat.left"}, Excerpt: "former permissions.admin=true", Details: map[string]any{"admin": true}},
		{ID: finding.IDIdentityUnexpectedAdmin, Asset: githubAccessOrg, Subject: account("unexpected", "43", "casey"), Reads: []string{"owners"}, Sources: []string{"access.admins", "people.casey"}, Excerpt: "owner unexpected"},
		{ID: finding.IDGitHubTooManyOwners, Asset: githubAccessOrg, Reads: []string{"owners", "members"}, Excerpt: "observed owners=5 members=6", Listed: []string{"alex", "unexpected", "owner3", "owner4", "owner5"}, Details: map[string]any{"owners": 5, "members": 6}},
		{ID: finding.IDGitHubBroadDefaultMemberPermission, Asset: githubAccessOrg, Reads: []string{"organization"}, Excerpt: "default_repository_permission=write", Details: map[string]any{"permission": "write"}},
		{ID: finding.IDGitHubUndeclaredPublicRepository, Asset: githubAccessRepo, Subject: Subject{Kind: "repository", Key: "example-org/production", Label: "example-org/production", ProviderID: "77"}, Reads: []string{"repository"}, Excerpt: "visibility=public", Details: map[string]any{"public": true}},
		{ID: finding.IDGitHubWritableDeployKey, Asset: githubAccessRepo, Subject: Subject{Kind: "deploy_key", Key: "deploy-key:9", Label: "deploy key 9", ProviderID: "9"}, Reads: []string{"keys"}, Sources: []string{"assets.production"}, Excerpt: "deploy key 9 read_only=false"},
		{ID: finding.IDGitHubOutsideAdminOnProduction, Asset: githubAccessRepo, Subject: account("external", "44", "contractor"), Reads: []string{"outside", "collaborators"}, Sources: []string{"assets.production"}, Excerpt: "external permissions.admin=true"},
	}
	for i := range a.Judged {
		a.Judged[i].Verdict = verdict
		if verdict != verdictFired {
			a.Judged[i].Details = nil
			a.Judged[i].Listed = nil
		}
		if verdict == verdictDisproved {
			a.Judged[i].Excerpt = "Recognized provider evidence disproved this condition."
		}
		if verdict == verdictAbstained {
			a.Judged[i].Reason = "unavailable:github_evidence"
			a.Judged[i].Excerpt = "Required evidence was unavailable."
		}
	}
	in.Assets = append(in.Assets, AssetInput{Name: "production", ID: githubAccessRepo, Kind: "repo", Status: "collected", Collector: "github", InventoryRead: true, ReadWith: githubAccessOrg, NetworkPrincipal: a.NetworkPrincipal})
	orgJudged, repoJudged := []Judgment{}, []Judgment{}
	for _, j := range in.Assets[0].Judged {
		if j.Asset == githubAccessRepo {
			repoJudged = append(repoJudged, j)
		} else {
			orgJudged = append(orgJudged, j)
		}
	}
	in.Assets[0].Judged, in.Assets[1].Judged = orgJudged, repoJudged
	in.Observations = map[string]Observation{}
	for _, asset := range in.Assets {
		for _, j := range asset.Judged {
			for _, read := range j.Reads {
				in.Observations[read] = Observation{CollectedAt: in.Started.Add(17 * time.Second)}
			}
		}
	}
	return graded(in, production(githubAccessRepo, "production"))
}
func githubAccessFiredReport(t *testing.T) Input     { return githubAccessReport(t, verdictFired) }
func githubAccessDisprovedReport(t *testing.T) Input { return githubAccessReport(t, verdictDisproved) }
func githubAccessAbstainedReport(t *testing.T) Input { return githubAccessReport(t, verdictAbstained) }
func TestGitHubAccessFindingsHaveCanonicalKeysAndObservedMetadata(t *testing.T) {
	in := githubAccessFiredReport(t)
	r := build(in)
	validate(t, schema(t), r)
	for _, f := range r.Findings {
		def, _ := finding.Lookup(f.ID)
		if def.Subject == "" {
			if f.Subject != nil || f.Key.Subject != nil {
				t.Fatalf("subjectless finding carries instance: %+v", f)
			}
		} else if f.Subject == nil || f.Key.Subject == nil || f.Subject.ProviderID == "" {
			t.Fatalf("missing provider subject: %+v", f)
		}
		for _, e := range f.Evidence {
			if e.Kind == "observed" && (e.Principal != "alice (user ID 41)" || e.CollectedAt == nil || !e.CollectedAt.Equal(in.Started.Add(17*time.Second))) {
				t.Fatalf("lost observation provenance: %+v", e)
			}
		}
		if f.ID == finding.IDGitHubWritableDeployKey || f.ID == finding.IDGitHubUndeclaredPublicRepository {
			if f.Key.Asset != githubAccessRepo || f.AcceptTemplate == nil || f.AcceptTemplate.Asset != "production" || f.AcceptTemplate.Subject == "" {
				t.Fatalf("repository acceptance not specific: %+v", f)
			}
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"subject":null`)) {
		t.Fatal("subjectless finding null contract missing")
	}
}
func TestGitHubAccessContextSeverityRaisesExactlyOnce(t *testing.T) {
	r := build(githubAccessFiredReport(t))
	for _, f := range r.Findings {
		rule, want := "", ""
		switch f.ID {
		case finding.IDIdentityFormerPersonHasAccess:
			rule, want = "attribute:admin", "critical"
		case finding.IDGitHubMFANotRequired:
			rule, want = "contradiction", "critical"
		case finding.IDGitHubWritableDeployKey:
			rule, want = "deploys_to:production", "high"
		}
		if rule != "" && (f.Severity != want || len(f.Adjustments) != 1 || f.Adjustments[0].Rule != rule) {
			t.Fatalf("severity adjustment %+v", f)
		}
	}
}
func TestGitHubAccessCoverageRetainsUnbuiltChecks(t *testing.T) {
	for _, verdict := range []string{verdictFired, verdictDisproved, verdictAbstained} {
		r := build(githubAccessReport(t, verdict))
		for _, area := range []string{"identity", "cicd"} {
			v := row(t, r, area)
			want := "partial"
			if verdict == verdictAbstained {
				want = "not_assessed"
			}
			if v.Mark != want {
				t.Fatalf("%s %s coverage %+v", verdict, area, v)
			}
			unknown := false
			for _, si := range v.SubItems {
				for _, reason := range si.Reasons {
					if reason.Reason == "no_rule" {
						unknown = true
						if si.Mark != "not_assessed" {
							t.Fatal("unbuilt check assessed")
						}
					}
				}
			}
			if !unknown {
				t.Fatal("unbuilt coverage missing")
			}
		}
	}
}
func TestGitHubAccessIncompleteAcceptanceNeverClaimsFixed(t *testing.T) {
	in := githubAccessDisprovedReport(t)
	in.Assets[0].PopulationIncomplete = true
	// A subject that was not observed cannot be declared fixed from a partial
	// subject population, even when every observed subject was disproved.
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDIdentityUnexpectedAdmin, Asset: "engineering", AssetID: githubAccessOrg, Subject: "unseen", Reason: "migration", AcceptedBy: "alex"}}
	r := build(in)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome == "not_matched" || r.Acceptances[0].Outcome == "subject_not_found" {
		t.Fatalf("incomplete acceptance %+v", r.Acceptances)
	}
}
func TestGitHubAccessMixedWebKeepsIndependentCoverage(t *testing.T) {
	in := githubAccessDisprovedReport(t)
	web := withWebRoot(t)
	in.Assets = append(in.Assets, web.Assets...)
	r := build(in)
	if row(t, r, "identity").Mark != "partial" {
		t.Fatal("GitHub identity lost")
	}
	v := row(t, r, "web")
	if v.Mark == "not_assessed" {
		t.Fatalf("web evidence lost: %+v", v)
	}
	var b bytes.Buffer
	if err := WriteText(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "GitHub") {
		t.Fatal("GitHub absent from mixed report")
	}
}

func TestGitHubSubjectlessAcceptanceKeepsNullInstanceKey(t *testing.T) {
	in := githubAccessFiredReport(t)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDGitHubMFANotRequired, Asset: "engineering", AssetID: githubAccessOrg, Reason: "transition", AcceptedBy: "alex"}}
	r := build(in)
	validate(t, schema(t), r)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome != "applied" || len(r.Acceptances[0].Findings) != 1 || r.Acceptances[0].Findings[0].Subject != nil {
		t.Fatalf("subjectless acceptance key: %+v", r.Acceptances)
	}
}

// A network finding's acceptance is read at the collection time of what
// the finding rests on, never the run's first start: evidence a later
// session read, after the acceptance ended, leaves the finding open
// (docs/spec/engagement.md, "Severity in context").
func TestNetworkAcceptanceIsJudgedAtTheReadsTime(t *testing.T) {
	in := githubAccessFiredReport(t)
	day := in.Started.In(in.Zone).Format(time.DateOnly)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDGitHubMFANotRequired, Asset: "engineering", AssetID: githubAccessOrg, Reason: "transition", AcceptedBy: "alex", Expires: day}}
	r := build(in)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome != "applied" {
		t.Fatalf("read on the day it expires: %+v", r.Acceptances)
	}
	for _, f := range r.Findings {
		if f.ID == finding.IDGitHubMFANotRequired && (f.Acceptance == nil || f.Acceptance.JudgedAt == nil || !f.Acceptance.JudgedAt.Equal(in.Started.Add(17*time.Second))) {
			t.Fatalf("judged at: %+v", f.Acceptance)
		}
	}
	// A later session read it two days on: past its end.
	for id, o := range in.Observations {
		o.CollectedAt = in.Started.Add(48 * time.Hour)
		in.Observations[id] = o
	}
	r = build(in)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome != "expired" || !strings.Contains(r.Acceptances[0].Why, "before collection on") {
		t.Fatalf("read after it expired: %+v", r.Acceptances)
	}
	for _, f := range r.Findings {
		if f.ID == finding.IDGitHubMFANotRequired && f.Status != finding.StatusOpen {
			t.Fatalf("the finding an expired acceptance covered is %s", f.Status)
		}
	}
}

// A finding whose reads carry no recorded time leaves its acceptance
// undecided and the finding open: no other clock stands in.
func TestAcceptanceWithNoReadTimeIsUndecided(t *testing.T) {
	in := githubAccessFiredReport(t)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDGitHubMFANotRequired, Asset: "engineering", AssetID: githubAccessOrg, Reason: "transition", AcceptedBy: "alex", Expires: "2099-01-01"}}
	for id := range in.Observations {
		in.Observations[id] = Observation{}
	}
	r := Build(in)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome != "rule_not_decided" {
		t.Fatalf("acceptances %+v", r.Acceptances)
	}
	for _, f := range r.Findings {
		if f.ID == finding.IDGitHubMFANotRequired && f.Status != finding.StatusOpen {
			t.Fatalf("finding %s", f.Status)
		}
	}
}

// One acceptance over instances read at different times is decided at one
// time for its outcome and every instance alike: the latest read, or
// undecided when any instance's read has no recorded time.
func TestAcceptanceOverInstancesReadAtDifferentTimes(t *testing.T) {
	mixed := func(late time.Time) Input {
		in := githubAccessFiredReport(t)
		second := in.Assets[0].Judged[1]
		if second.ID != finding.IDGitHubOwnerWithoutMFA {
			t.Fatalf("fixture order: %s", second.ID)
		}
		second.Subject = Subject{Kind: "account", Key: "second", Label: "second", ProviderID: "45"}
		second.Reads = []string{"late-read"}
		in.Assets[0].Judged = append(in.Assets[0].Judged, second)
		in.Observations["late-read"] = Observation{CollectedAt: late}
		day := in.Started.In(in.Zone).Format(time.DateOnly)
		in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDGitHubOwnerWithoutMFA, Asset: "engineering", AssetID: githubAccessOrg, Reason: "r", AcceptedBy: "alex", Expires: day}}
		return in
	}
	statuses := func(r *Report) []string {
		var out []string
		for _, f := range r.Findings {
			if f.ID == finding.IDGitHubOwnerWithoutMFA {
				out = append(out, f.Status)
			}
		}
		return out
	}
	// Read again three days on: past the end, for the outcome and both.
	in := mixed(time.Time{})
	in.Observations["late-read"] = Observation{CollectedAt: in.Started.Add(72 * time.Hour)}
	r := Build(in)
	if r.Acceptances[0].Outcome != "expired" || !slices.Equal(statuses(r), []string{"open", "open"}) {
		t.Fatalf("expired between reads: %s %v", r.Acceptances[0].Outcome, statuses(r))
	}
	// One read with no recorded time: undecided, and both open.
	in = mixed(time.Time{})
	r = Build(in)
	if r.Acceptances[0].Outcome != "rule_not_decided" || !slices.Equal(statuses(r), []string{"open", "open"}) {
		t.Fatalf("one untimed read: %s %v", r.Acceptances[0].Outcome, statuses(r))
	}
}

// An instance another finding supersedes is no finding: it sets no time
// for the acceptance and is not listed as one of its findings.
func TestSupersededInstanceSetsNoAcceptanceTime(t *testing.T) {
	in := githubAccessFiredReport(t)
	hidden := in.Assets[0].Judged[1]
	hidden.Subject = Subject{Kind: "account", Key: "hidden", Label: "hidden", ProviderID: "46"}
	hidden.Reads = []string{"late-read"}
	hidden.Details = map[string]any{"superseded_by": "another finding"}
	in.Assets[0].Judged = append(in.Assets[0].Judged, hidden)
	in.Observations["late-read"] = Observation{CollectedAt: in.Started.Add(72 * time.Hour)}
	day := in.Started.In(in.Zone).Format(time.DateOnly)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDGitHubOwnerWithoutMFA, Asset: "engineering", AssetID: githubAccessOrg, Reason: "r", AcceptedBy: "alex", Expires: day}}
	r := Build(in)
	if a := r.Acceptances[0]; a.Outcome != "applied" || len(a.Findings) != 1 {
		t.Fatalf("acceptance %+v", a)
	}
	// Unrecorded, it still decides nothing.
	delete(in.Observations, "late-read")
	if a := Build(in).Acceptances[0]; a.Outcome != "applied" {
		t.Fatalf("acceptance %+v", a)
	}
}
