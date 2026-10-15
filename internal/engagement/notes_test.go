package engagement

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/target/fixture"
)

func details(ns []ereport.ContextNote, kind string) []string {
	var out []string
	for _, n := range ns {
		if n.Kind == kind {
			out = append(out, n.Detail)
		}
	}
	return out
}

// C1: a verified tenant domain that is no root is noted, worded by whether
// a root holds it; a root and an unverified domain are not.
func TestWorkspaceDomainNotes(t *testing.T) {
	yes, no := new(true), new(false)
	e := workspace.Evidence{
		Domains: workspace.Population[workspace.Domain]{Complete: true, Items: []workspace.Domain{
			{Name: "example.com", Verified: yes}, {Name: "eu.example.com", Verified: yes}, {Name: "example.co.uk", Verified: yes}, {Name: "draft.io", Verified: no}}},
		Aliases: workspace.Population[workspace.Alias]{Complete: true},
	}
	r := &run{res: &Resolved{Roots: []Ref{{ID: "domain:example.com"}}},
		recon: &ReconDoc{Assets: []ReconAsset{{ID: "saas:google-workspace:example.com", Workspace: &e}}}}
	got := details(r.contextNotes(nil), ereport.NoteContextWorkspaceDomain)
	want := []string{
		"`eu.example.com` is a verified domain of your Workspace tenant under the root `example.com`; scheck reads mail records only at each root and the mail domains you declare, so its SPF and DMARC were not read. Add it under `roots` to have them read.",
		"`example.co.uk` is a verified domain of your Workspace tenant and is under none of your domain roots, so its SPF, DKIM and DMARC were not read. Add it under `roots` to have them read.",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

// C2: a declared repository GitHub shows archived, does not show, or that
// was not read is noted; one that was found, or judged, is not.
func TestDeploysToNotes(t *testing.T) {
	access := func(asset string, status int, archived bool) githubc.RepositoryAccess {
		a := githubc.RepositoryAccess{Asset: asset, RepositoryRead: githubc.Read{RequestID: asset, Decision: "sent", Status: status}}
		if status == 200 {
			a.Repository = &githubc.Repository{FullName: strings.TrimPrefix(asset, "repo:github:"), Archived: &archived}
		}
		if status == 403 {
			a.RepositoryRead.Reason = "insufficient_permission"
		}
		return a
	}
	e := githubc.Evidence{RepositoriesAccess: []githubc.RepositoryAccess{
		access("repo:github:acme/shop", 200, false), access("repo:github:acme/old", 200, true),
		access("repo:github:acme/gone", 404, false), access("repo:github:acme/hidden", 403, false), access("repo:github:acme/judged", 403, false)}}
	var assets []ResolvedAsset
	for _, n := range []string{"shop", "old", "gone", "hidden", "judged"} {
		assets = append(assets, ResolvedAsset{Name: n + "-repo", ID: "repo:github:acme/" + n, DeploysTo: "production"})
	}
	r := &run{res: &Resolved{Assets: assets}, recon: &ReconDoc{Assets: []ReconAsset{{ID: "saas:github:acme", GitHub: &e}}}}
	judged := map[string][]finding.Judgment{"saas:github:acme": {{ID: "x", Asset: "repo:github:acme/judged"}}}
	got := details(r.contextNotes(judged), ereport.NoteContextDeploysTo)
	want := []string{
		"`old-repo` (`github:acme/old`) is declared to deploy production, but GitHub shows it archived. If production now deploys from another repository, declare that one.",
		"`gone-repo` (`github:acme/gone`) is declared to deploy production, but the GitHub credential sees no repository `gone` in `acme`, so nothing on it was judged and no production raise applied. Check the name, whether it was renamed or moved, and whether the credential can see it.",
		"`hidden-repo` (`github:acme/hidden`) is declared to deploy production, but it was not read in this run (the credential was not allowed to read it), so nothing on it was judged.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

// C3: a not_used area the evidence contradicts gets one note, its clauses
// in canonical order; what does not contradict it gives none.
func TestNotUsedNotes(t *testing.T) {
	wf := githubc.WorkflowEvidence{Path: ".github/workflows/deploy.yml", Document: map[string]any{"jobs": map[string]any{
		"deploy": map[string]any{"steps": []any{
			map[string]any{"uses": "google-github-actions/auth@v2"},
			map[string]any{"uses": "appleboy/ssh-action@v1.0.3"},
			map[string]any{"uses": "actions/checkout@v4"},
		}}}}}
	gh := githubc.Evidence{
		RepositoriesCI:     []githubc.RepositoryCI{{Asset: "repo:github:acme/shop", Workflows: []githubc.WorkflowEvidence{wf}}},
		RepositoriesAlerts: []githubc.RepositoryAlerts{{Asset: "repo:github:acme/shop", Secrets: githubc.Population[githubc.ActionsSecret]{Items: []githubc.ActionsSecret{{Name: "AWS_ACCESS_KEY_ID"}, {Name: "DEPLOY_KEY"}, {Name: "SSH_PRIVATE_KEY"}, {Name: "AWS_[REDACTED:x:4 bytes]"}}}}},
	}
	ws := workspace.Evidence{Users: workspace.Population[workspace.User]{Complete: true, Items: []workspace.User{
		{Mailbox: new(true), Suspended: new(false), Archived: new(false)}, {Mailbox: new(true), Suspended: new(false), Archived: new(false)},
		{Mailbox: new(true), Suspended: new(true), Archived: new(false)}, {Mailbox: new(true), Suspended: new(false)}}}}
	r := &run{
		res:    &Resolved{NotUsed: []string{"cloud", "hosts", "email", "web"}},
		recon:  &ReconDoc{Assets: []ReconAsset{{ID: "saas:github:acme", GitHub: &gh}, {ID: "saas:google-workspace:example.com", Workspace: &ws}}},
		scoped: &ScopeDoc{Domains: []ScopeDomain{{Root: "example.com", Names: []ScopeName{{Name: "api.example.com", Chain: []string{"d111.cloudfront.net."}}}}}},
	}
	notes := r.contextNotes(nil)
	got := map[string]string{}
	for _, n := range notes {
		if n.Kind == ereport.NoteContextNotUsed {
			got[n.Area] = n.Detail
		}
	}
	want := map[string]string{
		"cloud": "You said you run no cloud accounts (`not_used`), but `api.example.com` is a CNAME to `d111.cloudfront.net` (AWS); a workflow in `acme/shop` (`.github/workflows/deploy.yml`) uses `google-github-actions/auth`, which signs in to Google Cloud; and `acme/shop` has an Actions secret named `AWS_ACCESS_KEY_ID`. If these are yours, remove `cloud` from `not_used`.",
		"hosts": "You said you run no servers (`not_used`), but a workflow in `acme/shop` (`.github/workflows/deploy.yml`) uses `appleboy/ssh-action`, which connects to a server over SSH; and `acme/shop` has an Actions secret named `SSH_PRIVATE_KEY`. If these are yours, remove `hosts` from `not_used`.",
		"email": "You said you run no email (`not_used`), but 2 accounts in `google-workspace:example.com` have a Gmail mailbox. If these are yours, remove `email` from `not_used`.",
	}
	if len(got) != len(want) {
		t.Fatalf("notes for %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got %s\nwant %s", k, got[k], w)
		}
	}
}

// A database on a host contradicts not_used: data: the note reaches the
// readout and the row, and the row still reports the finding, never "not
// applicable".
func TestADatabaseContradictsNotUsedData(t *testing.T) {
	file := dbHost + "not_used: [data]\n"
	res, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := filepath.Abs(filepath.Join("testdata", "db-open"))
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		fx, err := fixture.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		o.Target = fx
		return hostasset.Collect(ctx, o)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(file), Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range out.Report.Notes {
		found = found || n.Kind == ereport.NoteContextNotUsed && strings.Contains(n.Detail, "`postgres` listens on") && n.Source == "not_used[0]"
	}
	if !found {
		t.Fatalf("no C3 note: %+v", out.Report.Notes)
	}
	for _, row := range out.Report.Coverage {
		if row.Area == "data" && (row.Mark == "not_applicable" || len(row.ContextNotes) != 1) {
			t.Fatalf("data row %+v", row)
		}
	}
}

// What the reviewers found: a domain whose mail records were read is never
// "not read"; the most specific root is named; a partial users read is "at
// least"; only production names a raise; an archived repository is noted
// beside judgments.
func TestContextNotesSayOnlyWhatIsTrue(t *testing.T) {
	yes := new(true)
	ws := workspace.Evidence{
		Domains: workspace.Population[workspace.Domain]{Complete: true, Items: []workspace.Domain{
			{Name: "eu.example.com", Verified: yes}, {Name: "b.a.example.com", Verified: yes}}},
		Users: workspace.Population[workspace.User]{Items: []workspace.User{{Mailbox: yes, Suspended: new(false), Archived: new(false)},
			{Mailbox: yes, Suspended: yes, Archived: new(false)}, {Mailbox: yes, Suspended: new(false), Archived: yes}}},
	}
	webEv := web.Evidence{Mail: []web.MailEvidence{{Domain: "eu.example.com"}}}
	gh := githubc.Evidence{RepositoriesAccess: []githubc.RepositoryAccess{
		{Asset: "repo:github:acme/stage", RepositoryRead: githubc.Read{Decision: "sent", Status: 404}},
		{Asset: "repo:github:acme/old", RepositoryRead: githubc.Read{Decision: "sent", Status: 200}, Repository: &githubc.Repository{Archived: yes}},
	}}
	r := &run{
		res: &Resolved{Roots: []Ref{{ID: "domain:example.com"}, {ID: "domain:a.example.com"}}, NotUsed: []string{"email"},
			Assets: []ResolvedAsset{{Name: "stage", ID: "repo:github:acme/stage", DeploysTo: "staging"}, {Name: "old", ID: "repo:github:acme/old", DeploysTo: "production"}}},
		recon: &ReconDoc{Assets: []ReconAsset{{ID: "domain:example.com", Web: &webEv}, {ID: "saas:google-workspace:example.com", Workspace: &ws}, {ID: "saas:github:acme", GitHub: &gh}}},
	}
	notes := r.contextNotes(map[string][]finding.Judgment{"saas:github:acme": {{ID: "x", Asset: "repo:github:acme/old"}}})
	c1 := details(notes, ereport.NoteContextWorkspaceDomain)
	// eu.example.com is a declared mail domain the web collector read, not
	// a root: no note. b.a.example.com names its most specific root.
	if len(c1) != 1 || !strings.HasPrefix(c1[0], "`b.a.example.com` is a verified domain of your Workspace tenant under the root `a.example.com`;") {
		t.Errorf("C1 %q", c1)
	}
	c2 := details(notes, ereport.NoteContextDeploysTo)
	if len(c2) != 2 || strings.Contains(c2[0], "raise") || !strings.Contains(c2[1], "archived") {
		t.Errorf("C2 %q", c2)
	}
	c3 := details(notes, ereport.NoteContextNotUsed)
	if len(c3) != 1 || !strings.Contains(c3[0], "at least 1 account in `google-workspace:example.com` has a Gmail mailbox") {
		t.Errorf("C3 %q", c3)
	}
}

// The C3 table's version is in rules_version on a report with no domain
// root: a GitHub workflow alone can carry a note.
func TestRulesVersionNamesTheContextTable(t *testing.T) {
	gh := githubc.Evidence{}
	r := &run{res: &Resolved{}, o: RunOptions{Version: "test"},
		recon: &ReconDoc{Assets: []ReconAsset{{Name: "acme", ID: "saas:github:acme", GitHub: &gh}}}}
	in := r.reportInput(nil, nil)
	if !strings.HasSuffix(in.RulesVersion, ":context:"+ContextTableVersion) || !strings.Contains(in.RulesVersion, ":github-access:") {
		t.Fatalf("rules_version %q", in.RulesVersion)
	}
}
