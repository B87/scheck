package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func alertPopulation[T any](items ...T) Population[T] {
	return Population[T]{Items: items, Complete: true, VisibilityComplete: true, Reads: []Read{{Op: OpSecretAlerts, RequestID: "alerts", Decision: gate.DecisionSent, Status: 200}}}
}
func commitLocation() SecretLocation {
	l := SecretLocation{Type: "commit"}
	l.Details.SHA = strings.Repeat("a", 40)
	l.Details.Path = "config/Prod.env"
	l.Details.StartLine = 2
	l.Details.EndLine = 2
	l.Details.StartColumn = 1
	l.Details.EndColumn = 9
	return l
}
func dependencyAlert(severity string) DependencyAlert {
	d := DependencyAlert{Number: map[string]int64{"high": 3, "medium": 4, "low": 5}[severity], State: "open"}
	d.Vulnerability.Severity = severity
	d.Advisory.Severity = severity
	d.Dependency.ManifestPath = "App/package-lock.json"
	return d
}
func alertEvidence() Evidence {
	s := SecretAlert{Number: 7, State: "open", Type: "stripe_secret_key", Validity: new("unknown"), RedactionMarker: "[REDACTED:provider-secret:31 bytes]"}
	return Evidence{OrganizationSecrets: alertPopulation(ActionsSecret{Name: "PROD", Visibility: new("all")}), RepositoriesAlerts: []RepositoryAlerts{{Asset: "repo:github:acme/shop", Visibility: new("private"), RepositoryRead: Read{Op: OpRepository, RequestID: "repo", Decision: gate.DecisionSent, Status: 200}, Dependencies: alertPopulation(dependencyAlert("high"), dependencyAlert("medium"), dependencyAlert("low")), SecretAlerts: alertPopulation(s), Located: []LocatedSecret{{Alert: s, Locations: alertPopulation(commitLocation())}}}}}
}
func TestEveryAlertRuleFiresDisprovesAndAbstains(t *testing.T) {
	for _, v := range []string{Fired, Disproved, Abstained} {
		t.Run(v, func(t *testing.T) {
			e := alertEvidence()
			if v == Disproved {
				e.OrganizationSecrets.Items[0].Visibility = new("selected")
				for i := range e.RepositoriesAlerts[0].Dependencies.Items {
					e.RepositoriesAlerts[0].Dependencies.Items[i].State = "fixed"
				}
				e.RepositoriesAlerts[0].Located[0].Alert.State = "resolved"
				e.RepositoriesAlerts[0].Located[0].Alert.Resolution = new("revoked")
			}
			if v == Abstained {
				e.OrganizationSecrets.Items[0].Visibility = nil
				for i := range e.RepositoriesAlerts[0].Dependencies.Items {
					e.RepositoriesAlerts[0].Dependencies.Items[i].State = "future_state"
				}
				e.RepositoriesAlerts[0].Located[0].Alert.Validity = new("inactive")
			}
			got := JudgeAlerts(e, Context{OrganizationAsset: "saas:github:acme"})
			for _, id := range finding.GitHubAlertIDs() {
				if !hasVerdict(got, id, v) {
					t.Fatalf("%s missing %s %+v", id, v, got)
				}
			}
		})
	}
}
func TestAlertUnknownAndPartialEvidenceNeverDisproves(t *testing.T) {
	e := alertEvidence()
	e.OrganizationSecrets.Complete = false
	e.RepositoriesAlerts[0].Dependencies.Complete = false
	e.RepositoriesAlerts[0].SecretAlerts.Complete = false
	e.RepositoriesAlerts[0].Located[0].Locations.Complete = false
	got := JudgeAlerts(e, Context{})
	for _, id := range finding.GitHubAlertIDs() {
		if !hasVerdict(got, id, Fired) {
			t.Fatal("partial positive lost", id)
		}
	}
	e.OrganizationSecrets.Items[0].Visibility = new("selected")
	for i := range e.RepositoriesAlerts[0].Dependencies.Items {
		e.RepositoriesAlerts[0].Dependencies.Items[i].State = "dismissed"
	}
	e.RepositoriesAlerts[0].Located[0].Alert.State = "resolved"
	e.RepositoriesAlerts[0].Located[0].Alert.Resolution = new("revoked")
	for _, j := range JudgeAlerts(e, Context{}) {
		if j.Verdict == Disproved {
			t.Fatal("partial negative", j)
		}
	}
	e = alertEvidence()
	d := &e.RepositoriesAlerts[0].Dependencies.Items[0]
	d.Dependency.ManifestPath = "../outside"
	d.Vulnerability.Severity = "critical"
	d.Advisory.Severity = "high"
	for _, j := range judgeDependencies(e.RepositoriesAlerts[0]) {
		if j.Subject != nil && j.Subject.ProviderID == "3" && j.Verdict != Abstained {
			t.Fatal("unknown mismatch")
		}
	}
}
func TestProviderValidityResolutionAndMultipleLocations(t *testing.T) {
	for _, validity := range []*string{nil, new("unknown"), new("active"), new("inactive"), new("future")} {
		e := alertEvidence()
		e.RepositoriesAlerts[0].Located[0].Alert.Validity = validity
		want := Fired
		if validity != nil && (*validity == "inactive" || *validity == "future") {
			want = Abstained
		}
		if !hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubSecretScanningOpen, want) {
			t.Fatal("validity", validity)
		}
	}
	for _, resolution := range []string{"revoked", "false_positive", "used_in_tests", "wont_fix", "pattern_edited", "pattern_deleted", "future"} {
		e := alertEvidence()
		s := &e.RepositoriesAlerts[0].Located[0].Alert
		s.State = "resolved"
		s.Resolution = &resolution
		want := Abstained
		if resolution == "revoked" {
			want = Disproved
		}
		if !hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubSecretScanningOpen, want) {
			t.Fatal("resolution", resolution)
		}
	}
	e := alertEvidence()
	e.RepositoriesAlerts[0].Visibility = new("public")
	loc := commitLocation()
	loc.Details.StartLine = 5
	loc.Details.EndLine = 5
	e.RepositoriesAlerts[0].Located[0].Locations.Items = append(e.RepositoriesAlerts[0].Located[0].Locations.Items, loc)
	n := 0
	keys := map[string]bool{}
	for _, j := range JudgeAlerts(e, Context{}) {
		if j.ID == finding.IDGitHubSecretScanningOpen && j.Verdict == Fired {
			n++
			keys[j.Subject.Key] = true
			if len(j.Attributes) != 1 || j.Attributes[0] != "observed_public" {
				t.Fatal("public context")
			}
		}
	}
	if n != 2 || len(keys) != 2 {
		t.Fatal("locations collapsed")
	}
}
func TestAlertMetadataRedactionsDoNotEraseSafeEvidence(t *testing.T) {
	e := alertEvidence()
	e.OrganizationSecrets.Reads[0].Redactions = []policy.Hit{{Rule: "json-secret", Bytes: 20}}
	e.RepositoriesAlerts[0].SecretAlerts.Reads[0].Redactions = e.OrganizationSecrets.Reads[0].Redactions
	if !hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubSecretScanningOpen, Fired) {
		t.Fatal("secret redaction erased metadata")
	}
	e.RepositoriesAlerts[0].Located[0].Locations.Items[0].Details.Path = "[REDACTED:extra:9 bytes]"
	if hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubSecretScanningOpen, Fired) {
		t.Fatal("marked path identified location")
	}
}
func TestCollectAlertsTypedFollowupsAndUnsupportedLocations(t *testing.T) {
	f := &fakeSender{results: map[string][]gate.Result{
		OpOrganizationSecrets:        {result("org", `[{"name":"PROD","visibility":"selected"}]`, true)},
		OpSelectedSecretRepositories: {result("selected", `[]`, true)},
		OpRepositorySecrets:          {result("repo", `[]`, true)},
		OpDependabotAlerts:           {result("deps", `[]`, true)},
		OpSecretAlerts:               {result("alerts", `[{"number":7,"state":"open","secret_type":"stripe","validity":"unknown"}]`, true)},
		OpSecretLocations:            {result("locations", `[{"type":"issue_title"}]`, true)}}}
	e := Evidence{Organization: &OrganizationObject{ID: 2, Login: "acme", Type: "Organization"}, RepositoriesAccess: []RepositoryAccess{ciAccess()}}
	e = CollectAlerts(context.Background(), f, e, Organization{Asset: "saas:github:acme", Name: "acme", Stage: "recon"})
	if len(f.requests) != 6 || len(e.SelectedSecrets) != 1 || len(e.RepositoriesAlerts[0].Located) != 1 || e.RepositoriesAlerts[0].Located[0].Locations.Complete {
		t.Fatalf("%+v", e)
	}
	if f.requests[1].Params["secret_name"] != "PROD" || f.requests[5].Params["alert_number"] != "7" {
		t.Fatal("unbound followup")
	}
	e = Evidence{RepositoriesAccess: []RepositoryAccess{{Asset: "repo:github:acme/shop"}}}
	f.requests = nil
	CollectAlerts(context.Background(), f, e, Organization{})
	if len(f.requests) != 0 {
		t.Fatal("unverified repo sent")
	}
}
func TestMetadataCursorAndFollowupCaps(t *testing.T) {
	f := &fakeSender{results: map[string][]gate.Result{OpDependabotAlerts: {result("p1", `[{"number":1}]`, true), result("p2", `[{"number":2}]`, true)}}}
	f.results[OpDependabotAlerts][0].Response.Population.More = true
	p := metadataPopulation(context.Background(), f, gate.Request{Op: OpDependabotAlerts}, func(d DependencyAlert) string { return numberKey(d.Number) })
	if !p.Complete || len(p.Items) != 2 || f.requests[1].NextOf != "p1" {
		t.Fatal("pagination", p)
	}
	f = &fakeSender{results: map[string][]gate.Result{OpOrganizationSecrets: {result("org", "[]", true)}, OpSelectedSecretRepositories: {}}}
	items := []ActionsSecret{}
	for i := range 101 {
		items = append(items, ActionsSecret{Name: fmt.Sprintf("S_%d", i), Visibility: new("selected")})
		f.results[OpSelectedSecretRepositories] = append(f.results[OpSelectedSecretRepositories], result(fmt.Sprint(i), `[]`, true))
	}
	body, _ := json.Marshal(items)
	f.results[OpOrganizationSecrets][0].Response.Body = body
	e := CollectAlerts(context.Background(), f, Evidence{Organization: &OrganizationObject{Login: "acme"}}, Organization{Asset: "saas:github:acme", Name: "acme"})
	if len(e.SelectedSecrets) != 100 || e.OrganizationSecrets.Complete || e.OrganizationSecrets.Reads[0].Reason != "limit_reached" {
		t.Fatal("followupcap")
	}
}

func TestAlertPopulationGapsAreExplicit(t *testing.T) {
	e := alertEvidence()
	e.OrganizationSecrets.Complete = false
	e.RepositoriesAlerts[0].SecretAlerts.Complete = false
	j := JudgeAlerts(e, Context{})
	for _, id := range []string{finding.IDGitHubOrgSecretAll, finding.IDGitHubSecretScanningOpen} {
		if !hasVerdict(j, id, Fired) || !hasVerdict(j, id, Abstained) {
			t.Fatal("owning population gap lost", id)
		}
	}
	e = alertEvidence()
	e.RepositoriesAlerts[0].Located[0].Locations.Items = nil
	e.RepositoriesAlerts[0].Located[0].Locations.Complete = false
	if !hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubSecretScanningOpen, Abstained) {
		t.Fatal("unsupported locations disappear")
	}
	e = alertEvidence()
	e.OrganizationSecrets.Reads[0].Reason = "limit_reached"
	e.OrganizationSecrets.Complete = false
	if !hasVerdict(JudgeAlerts(e, Context{}), finding.IDGitHubOrgSecretAll, Fired) {
		t.Fatal("follow-up cap erased positive")
	}
}
