package github

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func ciRead(op string) Read { return Read{Op: op, RequestID: op, Status: 200, Decision: "sent"} }
func docJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		t.Fatal("fixture malformed")
	}
	return m
}
func ciFixture(t *testing.T) (Evidence, Context) {
	doc := docJSON(t, `{"on":"push","permissions":"read-all","jobs":{"build":{"runs-on":"ubuntu-latest","steps":[{"uses":"actions/checkout@`+strings.Repeat("a", 40)+`"}]}}}`)
	d := DefaultEvidence{Read: ciRead(OpRepositoryWorkflow), Setting: &WorkflowDefault{Permissions: new("read")}}
	e := Evidence{OrganizationWorkflow: d, RepositoriesCI: []RepositoryCI{{Asset: "repo:github:acme/shop", Default: d, Complete: true, Directory: ciRead(OpWorkflowDirectory), Branch: BranchEvidence{Read: ciRead(OpBranch), Name: "Main", SHA: strings.Repeat("b", 40), Protected: new(true), Rules: rulePop[BranchRule]()}, Workflows: []WorkflowEvidence{{Read: ciRead(OpWorkflowFile), Path: ".github/workflows/build.yml", SHA: strings.Repeat("b", 40), Document: doc}}}}}
	c := Context{OrganizationAsset: "saas:github:acme", RepositoryContexts: map[string]RepositoryContext{"repo:github:acme/shop": {DeploysTo: "production", Source: "assets.shop"}}}
	return e, c
}
func workflowDoc(t *testing.T, trigger, perm, ref string, run bool) map[string]any {
	steps := []any{map[string]any{"uses": "actions/checkout@" + ref}}
	if trigger == "pull_request_target" {
		steps[0].(map[string]any)["with"] = map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}
	}
	if run {
		steps = append(steps, map[string]any{"run": "npm ci\nnpm test"})
	}
	return map[string]any{"on": trigger, "permissions": perm, "jobs": map[string]any{"build": map[string]any{"runs-on": "ubuntu-latest", "steps": steps}}}
}
func TestEveryGitHubCIRuleFiresDisprovesAndAbstains(t *testing.T) {
	cases := map[string]func(*Evidence){
		finding.IDGitHubOrganizationWorkflowWrite: func(e *Evidence) { e.OrganizationWorkflow.Setting.Permissions = new("write") },
		finding.IDGitHubRepositoryWorkflowWrite:   func(e *Evidence) { e.RepositoriesCI[0].Default.Setting.Permissions = new("write") },
		finding.IDGitHubDefaultBranchUnprotected:  func(e *Evidence) { e.RepositoriesCI[0].Branch.Protected = new(false) },
		finding.IDGitHubMutableAction: func(e *Evidence) {
			e.RepositoriesCI[0].Workflows[0].Document = workflowDoc(t, "push", "read-all", "v4", false)
		},
		finding.IDGitHubMutableActionWrite: func(e *Evidence) {
			e.RepositoriesCI[0].Workflows[0].Document = workflowDoc(t, "push", "write-all", "v4", false)
		},
		finding.IDGitHubPRTargetUnsafe: func(e *Evidence) {
			e.RepositoriesCI[0].Workflows[0].Document = workflowDoc(t, "pull_request_target", "write-all", strings.Repeat("a", 40), true)
		},
	}
	for _, id := range finding.GitHubCIIDs() {
		fire, ok := cases[id]
		if !ok {
			t.Fatalf("missing fixtures for %s", id)
		}
		for _, verdict := range []string{Fired, Disproved, Abstained} {
			t.Run(id+"/"+verdict, func(t *testing.T) {
				e, c := ciFixture(t)
				if verdict == Fired {
					fire(&e)
				}
				if verdict == Abstained {
					e.OrganizationWorkflow.Read.Status = 403
					e.RepositoriesCI[0].Default.Read.Status = 403
					e.RepositoriesCI[0].Branch.Read.Status = 403
					e.RepositoriesCI[0].Workflows[0].Read.Status = 403
				}
				out := JudgeCI(e, c)
				if !hasVerdict(out, id, verdict) {
					t.Fatalf("want %s: %+v", verdict, out)
				}
				for _, j := range out {
					if j.Verdict == Fired && finding.SubjectOf(j.ID) != "" && j.Subject == (Subject{}) {
						t.Fatal("fired without instance")
					}
				}
			})
		}
	}
}
func TestWorkflowPermissionReplacementAndUnknowns(t *testing.T) {
	for _, tc := range []struct {
		name            string
		workflow, job   any
		def             *string
		mutation, known bool
	}{
		{"job replacement", "write-all", map[string]any{"contents": "read"}, new("write"), false, true},
		{"workflow replacement", map[string]any{}, nil, new("write"), false, true},
		{"OIDC only", map[string]any{"id-token": "write"}, nil, new("read"), false, true},
		{"explicit mutation", map[string]any{"contents": "write"}, nil, nil, true, true},
		{"unknown key", map[string]any{"future": "write"}, nil, new("read"), false, false},
		{"unknown default", nil, nil, nil, false, false},
		{"invalid OIDC read", map[string]any{"id-token": "read"}, nil, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, job := map[string]any{}, map[string]any{}
			if tc.workflow != nil {
				doc["permissions"] = tc.workflow
			}
			if tc.job != nil {
				job["permissions"] = tc.job
			}
			d := DefaultEvidence{Read: ciRead(OpRepositoryWorkflow), Setting: &WorkflowDefault{Permissions: tc.def}}
			got := effectivePermissions(doc, job, d)
			if got.Known != tc.known || got.Mutation != tc.mutation {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestWorkflowSupportedAndUnknownCombinations(t *testing.T) {
	type change func(map[string]any)
	cases := []struct {
		name        string
		change      change
		id, verdict string
	}{
		{"ordinary fork", func(d map[string]any) { d["on"] = "pull_request" }, finding.IDGitHubMutableActionWrite, Abstained},
		{"mixed fork push", func(d map[string]any) { d["on"] = []any{"push", "pull_request"} }, finding.IDGitHubMutableActionWrite, Fired},
		{"unsupported event", func(d map[string]any) { d["on"] = "issue_comment" }, finding.IDGitHubMutableActionWrite, Abstained},
		{"matrix", func(d map[string]any) {
			job(d)["strategy"] = map[string]any{"matrix": map[string]any{"node": []any{"18", "20"}}}
		}, finding.IDGitHubMutableActionWrite, Abstained},
		{"conditional step", func(d map[string]any) { step(d, 0)["if"] = "${{ github.actor == 'safe' }}" }, finding.IDGitHubMutableActionWrite, Abstained},
		{"marked reference", func(d map[string]any) { step(d, 0)["uses"] = "[REDACTED:token:40 bytes]" }, finding.IDGitHubMutableAction, Abstained},
		{"immutable SHA", func(d map[string]any) { step(d, 0)["uses"] = "actions/checkout@" + strings.Repeat("a", 40) }, finding.IDGitHubMutableAction, Disproved},
		{"short SHA", func(d map[string]any) { step(d, 0)["uses"] = "actions/checkout@abcdef1" }, finding.IDGitHubMutableAction, Fired},
		{"mutable reusable", func(d map[string]any) {
			d["jobs"] = map[string]any{"build": map[string]any{"uses": "acme/ci/.github/workflows/build.yml@main"}}
		}, finding.IDGitHubMutableActionWrite, Abstained},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, c := ciFixture(t)
			e.RepositoriesCI[0].Workflows[0].Document = workflowDoc(t, "push", "write-all", "v4", false)
			tc.change(e.RepositoriesCI[0].Workflows[0].Document)
			if !hasVerdict(JudgeCI(e, c), tc.id, tc.verdict) {
				t.Fatalf("want %s: %+v", tc.verdict, JudgeCI(e, c))
			}
		})
	}
}
func job(d map[string]any) map[string]any {
	return d["jobs"].(map[string]any)["build"].(map[string]any)
}
func step(d map[string]any, i int) map[string]any { return job(d)["steps"].([]any)[i].(map[string]any) }
func TestPRTargetRequiresSupportedRequestedExecution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(map[string]any)
		verdict string
	}{
		{"request chain", func(d map[string]any) {}, Fired},
		{"opt out still static", func(d map[string]any) { step(d, 0)["with"].(map[string]any)["allow-unsafe-pr-checkout"] = true }, Fired},
		{"checkout alone", func(d map[string]any) { job(d)["steps"] = job(d)["steps"].([]any)[:1] }, Disproved},
		{"literal false", func(d map[string]any) { job(d)["if"] = false }, Disproved},
		{"conditional job", func(d map[string]any) { job(d)["if"] = "${{ true }}" }, Abstained},
		{"Python shell", func(d map[string]any) { step(d, 1)["shell"] = "python" }, Abstained},
		{"Python job shell", func(d map[string]any) { job(d)["defaults"] = map[string]any{"run": map[string]any{"shell": "python"}} }, Abstained},
		{"Python default shell", func(d map[string]any) { d["defaults"] = map[string]any{"run": map[string]any{"shell": "python"}} }, Abstained},
		{"unsupported shell", func(d map[string]any) { step(d, 1)["run"] = "echo hello && npm test" }, Abstained},
		{"unknown before execution", func(d map[string]any) { step(d, 1)["run"] = "echo hello\nnpm test" }, Abstained},
		{"custom working dir", func(d map[string]any) {
			d["defaults"] = map[string]any{"run": map[string]any{"working-directory": "other"}}
		}, Abstained},
		{"dynamic ref", func(d map[string]any) { step(d, 0)["with"].(map[string]any)["ref"] = "${{ inputs.ref }}" }, Abstained},
		{"read job", func(d map[string]any) { job(d)["permissions"] = map[string]any{} }, Disproved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, c := ciFixture(t)
			d := workflowDoc(t, "pull_request_target", "write-all", strings.Repeat("a", 40), true)
			tc.change(d)
			e.RepositoriesCI[0].Workflows[0].Document = d
			out := JudgeCI(e, c)
			if !hasVerdict(out, finding.IDGitHubPRTargetUnsafe, tc.verdict) {
				t.Fatalf("want%s: %+v", tc.verdict, out)
			}
		})
	}
}
func TestPartialWorkflowEvidenceAndRedaction(t *testing.T) {
	e, c := ciFixture(t)
	e.RepositoriesCI[0].Complete = false
	for _, id := range []string{finding.IDGitHubMutableAction, finding.IDGitHubMutableActionWrite, finding.IDGitHubPRTargetUnsafe} {
		if !hasVerdict(JudgeCI(e, c), id, Abstained) {
			t.Fatal("partial pass")
		}
	}
	e.RepositoriesCI[0].Workflows[0].Document = workflowDoc(t, "push", "write-all", "v4", false)
	e.RepositoriesCI[0].Workflows[0].Read.Redactions = []policy.Hit{{Rule: "token", Bytes: 40}}
	if !hasVerdict(JudgeCI(e, c), finding.IDGitHubMutableActionWrite, Fired) {
		t.Fatal("unrelated redaction erased positive")
	}
	out := JudgeCI(e, c)
	for _, j := range out {
		if j.ID == finding.IDGitHubMutableAction && j.Details["superseded_by"] != finding.IDGitHubMutableActionWrite {
			t.Fatal("duplicate not linked")
		}
	}
}
func TestBranchProtectionPresenceOnly(t *testing.T) {
	e, c := ciFixture(t)
	e.RepositoriesCI[0].Branch.Rules.Complete = false
	if !hasVerdict(JudgeCI(e, c), finding.IDGitHubDefaultBranchUnprotected, Disproved) {
		t.Fatal("direct protected object not recognized")
	}
	e.RepositoriesCI[0].Branch.Protected = new(false)
	if !hasVerdict(JudgeCI(e, c), finding.IDGitHubDefaultBranchUnprotected, Abstained) {
		t.Fatal("partial empty rules passed")
	}
	e.RepositoriesCI[0].Branch.Rules = rulePop(BranchRule{Type: "pull_request"})
	if !hasVerdict(JudgeCI(e, c), finding.IDGitHubDefaultBranchUnprotected, Disproved) {
		t.Fatal("active protection missed")
	}
}
func TestExecutionLimitsAndLocalPaths(t *testing.T) {
	for _, v := range []string{strings.Repeat("a", 16<<10+1), strings.Repeat("\n", 100), strings.Repeat("a", 4097)} {
		known, _, limit := execution(v)
		if known || !limit {
			t.Fatal("cap not marked")
		}
	}
	for _, v := range []string{"./../script", "bash ../x", "X=1 npm test", "npm test | tee log", "python3 './script'"} {
		known, _, _ := execution(v)
		if known {
			t.Fatalf("unsafe syntax recognized %q", v)
		}
	}
	for _, v := range []string{"make", "npm ci\nnpm test", "./test.sh", "python3 ./test.py", "yarn run build"} {
		known, exec, _ := execution(v)
		if !known || !exec {
			t.Fatal("supported command missed")
		}
	}
	for _, v := range []struct {
		s       string
		mutable bool
	}{{"docker://alpine:3", true}, {"docker://alpine@sha256:" + strings.Repeat("a", 64), false}} {
		r := actionReference(v.s)
		if !r.Known || r.Mutable != v.mutable {
			t.Fatal("digest judgment")
		}
	}
	if !slices.Contains(finding.GitHubCIIDs(), finding.IDGitHubPRTargetUnsafe) {
		t.Fatal("catalog")
	}
}

func TestInvalidWorkflowStructureAbstains(t *testing.T) {
	mutations := map[string]func(map[string]any, map[string]any){
		"uses_and_run":        func(_ map[string]any, j map[string]any) { j["steps"].([]any)[0].(map[string]any)["run"] = "npm test" },
		"missing_runner":      func(_ map[string]any, j map[string]any) { delete(j, "runs-on") },
		"boolean_runner":      func(_ map[string]any, j map[string]any) { j["runs-on"] = true },
		"empty_runner_labels": func(_ map[string]any, j map[string]any) { j["runs-on"] = []any{} },
		"boolean_event_types": func(d map[string]any, _ map[string]any) {
			d["on"] = map[string]any{"pull_request_target": map[string]any{"types": false}}
		},
		"unknown_event_activity": func(d map[string]any, _ map[string]any) {
			d["on"] = map[string]any{"pull_request_target": map[string]any{"types": []any{"invented_activity"}}}
		},
		"conflicting_event_filters": func(d map[string]any, _ map[string]any) {
			d["on"] = map[string]any{"pull_request_target": map[string]any{"branches": []any{"main"}, "branches-ignore": []any{"dev"}}}
		},
		"direct_job_with": func(_ map[string]any, j map[string]any) { j["with"] = map[string]any{"input": "value"} },
		"direct_job_secrets": func(_ map[string]any, j map[string]any) {
			j["secrets"] = map[string]any{"token": "${{ secrets.TOKEN }}"}
		},
		"invalid_reusable_job_mix": func(_ map[string]any, j map[string]any) { j["uses"] = "acme/shop/.github/workflows/release.yml@main" },
		"boolean_action_inputs":    func(_ map[string]any, j map[string]any) { j["steps"].([]any)[0].(map[string]any)["with"] = false },
	}
	for name, mutate := range mutations {
		for _, unsafe := range []bool{true, false} {
			t.Run(name+"/"+map[bool]string{true: "positive", false: "negative"}[unsafe], func(t *testing.T) {
				e, c := ciFixture(t)
				d := workflowDoc(t, "pull_request_target", "write-all", "v4", unsafe)
				j := d["jobs"].(map[string]any)["build"].(map[string]any)
				mutate(d, j)
				e.RepositoriesCI[0].Workflows[0].Document = d
				out := JudgeCI(e, c)
				for _, id := range []string{finding.IDGitHubPRTargetUnsafe, finding.IDGitHubMutableActionWrite} {
					if !hasVerdict(out, id, Abstained) {
						t.Fatalf("%s must abstain: %+v", id, out)
					}
				}
			})
		}
	}
}

func TestSupportedWorkflowStructureRetainsFindings(t *testing.T) {
	for _, runner := range []any{"ubuntu-latest", []any{"self-hosted", "linux"}, map[string]any{"group": "build", "labels": []any{"linux"}}} {
		e, c := ciFixture(t)
		d := workflowDoc(t, "pull_request_target", "write-all", "v4", true)
		d["on"] = map[string]any{"pull_request_target": map[string]any{"types": []any{"opened", "synchronize"}, "branches": []any{"main"}}}
		d["jobs"].(map[string]any)["build"].(map[string]any)["runs-on"] = runner
		e.RepositoriesCI[0].Workflows[0].Document = d
		out := JudgeCI(e, c)
		for _, id := range []string{finding.IDGitHubPRTargetUnsafe, finding.IDGitHubMutableActionWrite} {
			if !hasVerdict(out, id, Fired) {
				t.Fatalf("supported structure lost %s: %+v", id, out)
			}
		}
	}
}
