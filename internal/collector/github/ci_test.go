package github

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func ciAccess() RepositoryAccess {
	return RepositoryAccess{Asset: "repo:github:acme/shop", Repository: &Repository{ID: 10, Name: "shop", FullName: "acme/shop", Owner: Account{ID: 2, Login: "acme", Type: "Organization"}, DefaultBranch: new("main")}}
}
func ciFake() *fakeSender {
	sha := strings.Repeat("a", 40)
	blob := strings.Repeat("b", 40)
	return &fakeSender{results: map[string][]gate.Result{
		OpRepositoryWorkflow: {result("defaults", `{"default_workflow_permissions":"read"}`, false)},
		OpBranch:             {result("branch", fmt.Sprintf(`{"name":"main","protected":false,"commit":{"sha":%q}}`, sha), false)},
		OpBranchRules:        {result("rules", `[]`, true)},
		OpWorkflowDirectory:  {result("directory", fmt.Sprintf(`[{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":100}]`, blob), true)},
		OpWorkflowFile:       {result("file", fmt.Sprintf(`{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":100,"decoded_bytes":100,"workflow":{"on":"push","jobs":{"build":{"runs-on":"ubuntu-latest","steps":[{"uses":"actions/checkout@v4"}]}}}}`, blob), false)},
	}}
}
func TestCollectCIPinsRefsAndRequiresFileIdentity(t *testing.T) {
	f := ciFake()
	ci := collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if !ci.Complete || len(ci.Workflows) != 1 || ci.Workflows[0].Document == nil {
		t.Fatalf("%+v", ci)
	}
	for _, r := range f.requests {
		if r.Op == OpWorkflowFile || r.Op == OpWorkflowDirectory {
			if r.Params["sha"] != strings.Repeat("a", 40) {
				t.Fatal("unbound ref")
			}
		}
		if r.Asset != "repo:github:acme/shop" {
			t.Fatal("wrong asset")
		}
	}
	f = ciFake()
	f.results[OpWorkflowFile][0].Response.Body = []byte(strings.ReplaceAll(string(f.results[OpWorkflowFile][0].Response.Body), ".github/workflows/ci.yml", ".github/workflows/other.yml"))
	ci = collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if ci.Complete || ci.Workflows[0].Document != nil {
		t.Fatal("mismatched contents accepted")
	}
	e := Evidence{RepositoriesCI: []RepositoryCI{ci}}
	if !hasVerdict(JudgeCI(e, Context{}), finding.IDGitHubMutableAction, Abstained) {
		t.Fatal("mismatched contents fired")
	}
}
func TestCollectCIDoesNotFollowUnknownDefaultBranch(t *testing.T) {
	for _, name := range []string{"../main", "main"} {
		f := ciFake()
		a := ciAccess()
		a.Repository.DefaultBranch = &name
		if name == "main" {
			f.results[OpBranch][0].Response.Body = []byte(`{"name":"changed","protected":false,"commit":{"sha":"` + strings.Repeat("a", 40) + `"}}`)
		}
		ci := collectRepositoryCI(context.Background(), f, a, "recon")
		if ci.Complete {
			t.Fatal("unknown branch complete")
		}
		for _, r := range f.requests {
			if r.Op == OpBranchRules || r.Op == OpWorkflowDirectory || r.Op == OpWorkflowFile {
				t.Fatal("followed unknown branch")
			}
		}
	}
}
func TestCappedWorkflowPopulationCanFireButNeverDisprove(t *testing.T) {
	f := ciFake()
	blob := strings.Repeat("b", 40)
	items := []string{}
	results := []gate.Result{}
	for i := range 101 {
		name := fmt.Sprintf("%03d.yml", i)
		items = append(items, fmt.Sprintf(`{"name":%q,"path":%q,"type":"file","sha":%q,"size":100}`, name, ".github/workflows/"+name, blob))
		body := strings.ReplaceAll(string(ciFake().results[OpWorkflowFile][0].Response.Body), "ci.yml", name)
		results = append(results, result(fmt.Sprint(i), body, false))
	}
	f.results[OpWorkflowDirectory][0].Response.Body = []byte("[" + strings.Join(items, ",") + "]")
	f.results[OpWorkflowFile] = results
	ci := collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if ci.Complete || len(ci.Workflows) != 100 || ci.Directory.Reason != "limit_reached" {
		t.Fatalf("limit %+v", ci)
	}
	e := Evidence{RepositoriesCI: []RepositoryCI{ci}}
	out := JudgeCI(e, Context{})
	if !hasVerdict(out, finding.IDGitHubMutableAction, Fired) || hasVerdict(out, finding.IDGitHubMutableActionWrite, Disproved) {
		t.Fatal("partial judgment")
	}
}
func TestMissingAndEmptyWorkflowEvidenceDiffer(t *testing.T) {
	f := ciFake()
	f.results[OpWorkflowDirectory][0].Response.Body = []byte("[]")
	ci := collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if !ci.Complete {
		t.Fatal("trusted empty directory unknown")
	}
	if !hasVerdict(JudgeCI(Evidence{RepositoriesCI: []RepositoryCI{ci}}, Context{}), finding.IDGitHubMutableAction, Disproved) {
		t.Fatal("empty directory lacks negative")
	}
	f = ciFake()
	f.results[OpWorkflowDirectory][0].Response.Status = 404
	f.results[OpWorkflowDirectory][0].Reason = "insufficient_permission"
	ci = collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if ci.Complete || !hasVerdict(JudgeCI(Evidence{RepositoriesCI: []RepositoryCI{ci}}, Context{}), finding.IDGitHubMutableAction, Abstained) {
		t.Fatal("404 treated empty")
	}
}
func TestActiveRulesUnknownAndPartial(t *testing.T) {
	f := ciFake()
	f.results[OpBranchRules][0].Response.Body = []byte(`[{"type":"future_rule"}]`)
	ci := collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
	if ci.Branch.Rules.Complete || !hasVerdict(JudgeCI(Evidence{RepositoriesCI: []RepositoryCI{ci}}, Context{}), finding.IDGitHubDefaultBranchUnprotected, Abstained) {
		t.Fatal("unknown rule treated absent")
	}
}

func TestNumericWorkflowFieldsPreserveThreePinningOutcomes(t *testing.T) {
	for _, tc := range []struct {
		reference string
		want      string
	}{
		{`"actions/checkout@v4"`, Fired},
		{`"actions/checkout@` + strings.Repeat("a", 40) + `"`, Disproved},
		{`42`, Abstained},
	} {
		f := ciFake()
		blob := strings.Repeat("b", 40)
		f.results[OpWorkflowFile][0].Response.Body = []byte(fmt.Sprintf(`{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":100,"decoded_bytes":100,"workflow":{"on":"push","jobs":{"build":{"runs-on":"ubuntu-latest","timeout-minutes":20,"steps":[{"uses":%s,"with":{"fetch-depth":0}}]}}}}`, blob, tc.reference))
		ci := collectRepositoryCI(context.Background(), f, ciAccess(), "recon")
		if !hasVerdict(JudgeCI(Evidence{RepositoriesCI: []RepositoryCI{ci}}, Context{}), finding.IDGitHubMutableAction, tc.want) {
			t.Fatalf("reference %s wanted %s", tc.reference, tc.want)
		}
	}
}
