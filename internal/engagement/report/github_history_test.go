package report

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func githubHistoryReport(t *testing.T, verdict string) Input {
	in := githubAccessReport(t, verdict)
	in.Name = "GitHub mirror history review"
	for i := range in.Assets {
		in.Assets[i].Judged = nil
		in.Assets[i].InventoryNotes = nil
	}
	repo := &in.Assets[1]
	commit := strings.Repeat("a", 40)
	key := "history:" + commit + ":config%2FProd.env:2:kv-secret"
	history := Judgment{ID: finding.IDGitHubHistoryCredential, Asset: repo.ID, Verdict: verdict, Subject: Subject{Kind: "secret_location", Key: key, Label: "config/Prod.env:2 at " + commit}, Reads: []string{"mirror-history", "heads", "pull"}, Attributes: []string{"observed_public"}, Details: map[string]any{"marker": "[REDACTED:kv-secret:31 bytes]", "commit": commit, "path": "config/Prod.env", "line": 2, "detector": "kv-secret", "repository_read": "repository"}, Excerpt: "config/Prod.env:2 at commit " + commit + ": [REDACTED:kv-secret:31 bytes]. Observed repository visibility: public."}
	remote := Judgment{ID: finding.IDGitHubRemoteCredential, Asset: repo.ID, Verdict: verdict, Subject: Subject{Kind: "secret_location", Key: "remote:origin", Label: "mirror origin configuration"}, Reads: []string{"mirror-history"}, Details: map[string]any{"markers": "[REDACTED:url-credentials:31 bytes]"}, Excerpt: "Recognized credential-bearing mirror origin userinfo: [REDACTED:url-credentials:31 bytes]. No remote URL retained."}
	for _, j := range []*Judgment{&history, &remote} {
		j.NotChecked = []string{"Credential usability and revocation were not tested", "Unadvertised/deleted refs, objects served only by SHA, unreachable objects, reflogs, submodule/LFS payloads and detector misses remain unassessed"}
		if verdict == verdictDisproved {
			j.Excerpt = "No recognized credential pattern found in the supported mirror history read"
			j.Subject = Subject{}
			if j.ID == finding.IDGitHubRemoteCredential {
				j.Subject = Subject{Kind: "secret_location", Key: "remote:origin", Label: "mirror origin configuration"}
				j.Excerpt = "Supported matching mirror origin contains no recognized credential"
			}
			j.Attributes = nil
			j.Details = nil
		}
		if verdict == verdictAbstained {
			j.Reason = "unavailable:github_evidence"
			j.Excerpt = "Mirror refs differ from the observed GitHub refs; no absence claim"
		}
	}
	repo.Judged = []Judgment{history, remote}
	if verdict == verdictFired {
		repo.Redactions = []policy.Hit{{Rule: "kv-secret", Bytes: 31}, {Rule: "url-credentials", Bytes: 31}}
	}
	repo.InventoryNotes = []Note{{Kind: "github_inventory", Source: repo.ID, Detail: "A mirror is the local repository copy supplied for this check; its origin is its saved repository connection. Supported mirror history read at the local observation time; advertised branch and pull refs read separately. Hidden/deleted history and detector misses remain unassessed."}}
	if verdict == verdictAbstained {
		repo.InventoryNotes[0].Detail = "The mirror differs from advertised branch/pull refs. Update your authorized mirror and resume; scheck never fetches or modifies it."
		repo.InventoryNotes = append(repo.InventoryNotes, Note{Kind: "github_history_followup", Source: repo.ID, Detail: "Mirror refs differ from the observed GitHub refs; update your authorized mirror and resume. scheck never fetches or modifies the mirror."})
	}
	in.Observations = map[string]Observation{}
	for _, id := range []string{"mirror-history", "heads", "pull", "repository"} {
		in.Observations[id] = Observation{CollectedAt: in.Started}
		if id == "mirror-history" {
			in.Observations[id] = Observation{CollectedAt: in.Started, Principal: "local mirror reader"}
		}
	}
	return in
}
func githubHistoryFiredReport(t *testing.T) Input { return githubHistoryReport(t, verdictFired) }
func githubHistoryDisprovedReport(t *testing.T) Input {
	return githubHistoryReport(t, verdictDisproved)
}
func githubHistoryAbstainedReport(t *testing.T) Input {
	return githubHistoryReport(t, verdictAbstained)
}
func TestGitHubHistoryReportSubjectsSeverityAndCoverage(t *testing.T) {
	in := githubHistoryFiredReport(t)
	r := Build(in)
	validate(t, schema(t), r)
	if len(r.Findings) != 2 {
		t.Fatal(r.Findings)
	}
	for _, f := range r.Findings {
		want := "medium"
		if f.ID == finding.IDGitHubHistoryCredential {
			want = "critical"
		}
		if f.Severity != want || f.AcceptTemplate == nil || f.AcceptTemplate.Subject == "" {
			t.Fatal(f)
		}
		if f.ID == finding.IDGitHubHistoryCredential {
			found := false
			for _, a := range f.Adjustments {
				if a.Rule == "attribute:public_repository" && a.Source.Observation == "repository" {
					found = true
				}
			}
			if !found {
				t.Fatal(f)
			}
		}
	}
	for _, row := range r.Coverage {
		if row.Area == "secrets" && row.Mark != "partial" {
			t.Fatal(row)
		}
	}
}
func TestHistoryPartialPositiveKeepsFamilyPartial(t *testing.T) {
	in := githubHistoryFiredReport(t)
	repo := &in.Assets[1]
	repo.Judged = append(repo.Judged, Judgment{ID: finding.IDGitHubHistoryCredential, Asset: repo.ID, Verdict: verdictAbstained, Reason: "unavailable:github_evidence", Reads: []string{"mirror-history"}})
	r := Build(in)
	validate(t, schema(t), r)
	found := false
	for _, row := range r.Coverage {
		for _, si := range row.SubItems {
			if si.Name == "supported mirror history credential detection" {
				found = true
				if si.Mark != "partial" {
					t.Fatal(si)
				}
			}
		}
	}
	if !found {
		t.Fatal("no family")
	}
}
