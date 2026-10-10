package github

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

const (
	OpOrganizationWorkflow   = "github.organization_workflow_default"
	OpRepositoryWorkflow     = "github.repository_workflow_default"
	OpBranch                 = "github.default_branch"
	OpBranchRules            = "github.active_branch_rules"
	OpWorkflowDirectory      = "github.workflow_directory" //nolint:gosec // compiled operation id, not a credential
	OpWorkflowFile           = "github.workflow_file"      //nolint:gosec // compiled operation id, not a credential
	WorkflowSyntaxVersion    = "github-workflow-syntax:2026-10-10.2"
	WorkflowExecutionVersion = "github-workflow-execution:2026-10-10"
)

func ciOps() []gate.Op {
	base := gate.Op{Provider: "github", Method: gate.GET, Subject: "repo:github:{owner}/{repo}", Params: []gate.Param{{Name: "owner", Type: gate.Login}, {Name: "repo", Type: gate.RepoName}}, Level: gate.Observe, Auth: gate.GitHubToken, APIVersion: "2026-03-10", Accept: []string{"application/json", "application/vnd.github+json"}, MaxBytes: 1 << 20}
	op := func(id, path string, fields []string, params ...gate.Param) gate.Op {
		v := base
		v.ID = id
		v.URL = "https://api.github.com/repos/{owner}/{repo}" + path
		v.Keep = fields
		v.Params = append(slices.Clone(base.Params), params...)
		return v
	}
	defaults := []string{"default_workflow_permissions", "can_approve_pull_request_reviews"}
	org := base
	org.ID = OpOrganizationWorkflow
	org.Subject = "saas:github:{org}"
	org.Params = []gate.Param{{Name: "org", Type: gate.Login}}
	org.URL = "https://api.github.com/orgs/{org}/actions/permissions/workflow"
	org.Keep = defaults
	repo := op(OpRepositoryWorkflow, "/actions/permissions/workflow", defaults)
	branch := op(OpBranch, "/branches/{branch}", []string{"name", "protected", "commit.sha"}, gate.Param{Name: "branch", Type: gate.BranchName})
	rules := op(OpBranchRules, "/rules/branches/{branch}?per_page=100&page={page}", []string{"type"}, gate.Param{Name: "branch", Type: gate.BranchName}, gate.Param{Name: "page", Type: gate.Count, Optional: true})
	rules.List = &gate.List{Items: "$", Kind: gate.KindOther, Next: &gate.Pages{Param: "page"}, MaxPages: 100}
	directory := op(OpWorkflowDirectory, "/contents/.github/workflows?ref={sha}", []string{"name", "path", "type", "sha", "size"}, gate.Param{Name: "sha", Type: gate.CommitSHA})
	directory.List = &gate.List{Items: "$", Kind: gate.KindOther}
	file := op(OpWorkflowFile, "/contents/.github/workflows/{file}?ref={sha}", []string{"name", "path", "type", "sha", "size", "decoded_bytes", "workflow", "yaml_gap", "redaction_marker"}, gate.Param{Name: "file", Type: gate.WorkflowFile}, gate.Param{Name: "sha", Type: gate.CommitSHA})
	file.WorkflowYAML = true
	return []gate.Op{org, repo, branch, rules, directory, file}
}

type WorkflowDefault struct {
	Permissions *string `json:"default_workflow_permissions,omitempty"`
	Approve     *bool   `json:"can_approve_pull_request_reviews,omitempty"`
}
type DefaultEvidence struct {
	Read    Read             `json:"read"`
	Setting *WorkflowDefault `json:"setting,omitempty"`
}
type BranchEvidence struct {
	Read      Read                   `json:"read"`
	Name      string                 `json:"name"`
	Protected *bool                  `json:"protected,omitempty"`
	SHA       string                 `json:"sha"`
	Rules     Population[BranchRule] `json:"rules"`
}
type BranchRule struct {
	Type string `json:"type"`
}
type WorkflowEntry struct {
	Name, Path, Type, SHA string
	Size                  int64
}
type WorkflowEvidence struct {
	RedactionMarker string         `json:"redaction_marker,omitempty"`
	Read            Read           `json:"read"`
	Path            string         `json:"path"`
	SHA             string         `json:"sha"`
	Document        map[string]any `json:"document,omitempty"`
	Gap             string         `json:"gap,omitempty"`
	Bytes           int            `json:"decoded_bytes"`
}
type RepositoryCI struct {
	Asset     string             `json:"asset"`
	Default   DefaultEvidence    `json:"default"`
	Branch    BranchEvidence     `json:"branch"`
	Directory Read               `json:"directory"`
	Workflows []WorkflowEvidence `json:"workflows,omitempty"`
	Complete  bool               `json:"complete"`
	Gaps      []string           `json:"gaps,omitempty"`
}

func (c RepositoryCI) Reads() []Read {
	out := []Read{}
	for _, r := range []Read{c.Default.Read, c.Branch.Read, c.Directory} {
		if r.Op != "" {
			out = append(out, r)
		}
	}
	out = append(out, c.Branch.Rules.Reads...)
	for _, w := range c.Workflows {
		out = append(out, w.Read)
	}
	return out
}
func collectDefault(ctx context.Context, g Sender, req gate.Request) DefaultEvidence {
	r := g.Send(ctx, req)
	d := DefaultEvidence{Read: readOf(req.Op, r)}
	if usable(r) {
		var v WorkflowDefault
		if json.Unmarshal(r.Response.Body, &v) == nil {
			d.Setting = &v
		} else {
			d.Read.Gap = "workflow_default_unrecognized"
		}
	}
	return d
}

// CollectCI reads only exact repository objects already admitted by CollectRepository.
// docs/spec/github-collector.md, "Compiled read plan".
func CollectCI(ctx context.Context, g Sender, e Evidence, org Organization) Evidence {
	if e.Organization != nil {
		e.OrganizationWorkflow = collectDefault(ctx, g, gate.Request{Op: OpOrganizationWorkflow, Asset: org.Asset, Stage: org.Stage, Exists: true, Params: map[string]string{"org": org.Name}})
	}
	for _, access := range e.RepositoriesAccess {
		if access.Repository != nil {
			e.RepositoriesCI = append(e.RepositoriesCI, collectRepositoryCI(ctx, g, access, org.Stage))
		}
	}
	return e
}

var fullSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

func collectRepositoryCI(ctx context.Context, g Sender, a RepositoryAccess, stage string) RepositoryCI {
	c := RepositoryCI{Asset: a.Asset}
	repo := a.Repository
	req := func(op string, extra map[string]string) gate.Request {
		p := map[string]string{"owner": repo.Owner.Login, "repo": repo.Name}
		maps.Copy(p, extra)
		return gate.Request{Op: op, Asset: a.Asset, Stage: stage, Exists: true, Params: p}
	}
	c.Default = collectDefault(ctx, g, req(OpRepositoryWorkflow, nil))
	if repo.DefaultBranch == nil || !gate.ValidBranchName(*repo.DefaultBranch) {
		c.Gaps = append(c.Gaps, "default_branch_unknown")
		return c
	}
	branch := *repo.DefaultBranch
	r := g.Send(ctx, req(OpBranch, map[string]string{"branch": branch}))
	c.Branch.Read = readOf(OpBranch, r)
	var b struct {
		Name      string `json:"name"`
		Protected *bool  `json:"protected"`
		Commit    struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if !usable(r) || json.Unmarshal(r.Response.Body, &b) != nil || b.Name != branch || !fullSHA.MatchString(b.Commit.SHA) {
		c.Branch.Read.Gap = "default_branch_identity_unknown"
		c.Gaps = append(c.Gaps, "default_branch_identity_unknown")
		return c
	}
	c.Branch.Name, c.Branch.SHA, c.Branch.Protected = b.Name, strings.ToLower(b.Commit.SHA), b.Protected
	c.Branch.Rules = collectBranchRules(ctx, g, req(OpBranchRules, map[string]string{"branch": branch}))
	r = g.Send(ctx, req(OpWorkflowDirectory, map[string]string{"sha": c.Branch.SHA}))
	c.Directory = readOf(OpWorkflowDirectory, r)
	if !usable(r) {
		c.Gaps = append(c.Gaps, "workflow_directory_unavailable")
		return c
	}
	var entries []WorkflowEntry
	if string(r.Response.Body) == "null" || json.Unmarshal(r.Response.Body, &entries) != nil || r.Response.Population == nil {
		c.Directory.Gap = "workflow_directory_unrecognized"
		return c
	}
	c.Complete = len(r.Response.Population.Incomplete) == 0 && !r.Response.Population.More
	if len(entries) >= 1000 {
		c.Complete = false
		c.Gaps = append(c.Gaps, "provider_directory_limit")
	}
	slices.SortFunc(entries, func(a, b WorkflowEntry) int { return strings.Compare(a.Path, b.Path) })
	seen := map[string]bool{}
	total := 0
	files := 0
	for _, item := range entries {
		if item.Type != "file" || !gate.ValidWorkflowFile(item.Name) || item.Path != ".github/workflows/"+item.Name || !fullSHA.MatchString(item.SHA) || item.Size < 0 {
			c.Complete = false
			c.Gaps = append(c.Gaps, "workflow_entry_unsupported")
			continue
		}
		if seen[item.Path] {
			c.Complete = false
			c.Gaps = append(c.Gaps, "duplicate_workflow")
			continue
		}
		seen[item.Path] = true
		if files >= 100 || item.Size > gate.WorkflowMaxBytes || total+int(item.Size) > 8<<20 {
			ciLimit(&c, "workflow_collection_limit")
			break
		}
		files++
		result := g.Send(ctx, req(OpWorkflowFile, map[string]string{"file": item.Name, "sha": c.Branch.SHA}))
		w := WorkflowEvidence{Read: readOf(OpWorkflowFile, result), Path: item.Path, SHA: c.Branch.SHA}
		if usable(result) {
			var body struct {
				RedactionMarker       string `json:"redaction_marker"`
				Name, Path, Type, SHA string
				Size                  int64
				Document              map[string]any `json:"workflow"`
				Gap                   string         `json:"yaml_gap"`
				Bytes                 int            `json:"decoded_bytes"`
			}
			if json.Unmarshal(result.Response.Body, &body) != nil || body.Name != item.Name || body.Path != item.Path || body.Type != "file" || !strings.EqualFold(body.SHA, item.SHA) || body.Size != item.Size || body.Bytes < 0 || body.Bytes != int(item.Size) {
				w.Gap = "workflow_file_identity_unknown"
			} else {
				w.Document, w.Gap, w.Bytes = body.Document, body.Gap, body.Bytes
				w.RedactionMarker = body.RedactionMarker
				total += body.Bytes
			}
		} else {
			w.Gap = "workflow_file_unavailable"
		}
		if w.Gap != "" || w.Document == nil {
			c.Complete = false
		}
		c.Workflows = append(c.Workflows, w)
	}
	return c
}
func ciLimit(c *RepositoryCI, gap string) {
	c.Complete = false
	c.Gaps = append(c.Gaps, gap)
	c.Directory.Reason = "limit_reached"
	c.Directory.Detail = "GitHub workflow collection reached its compiled limit"
}

var activeRuleTypes = map[string]bool{"creation": true, "update": true, "deletion": true, "required_linear_history": true, "required_deployments": true, "required_signatures": true, "pull_request": true, "required_status_checks": true, "non_fast_forward": true, "code_scanning": true, "file_path_restriction": true, "max_file_path_length": true, "file_extension_restriction": true, "max_file_size": true, "required_workflows": true}

func collectBranchRules(ctx context.Context, g Sender, req gate.Request) Population[BranchRule] {
	p := Population[BranchRule]{Complete: true, VisibilityComplete: true}
	for range 100 {
		r := g.Send(ctx, req)
		p.Reads = append(p.Reads, readOf(req.Op, r))
		var items []BranchRule
		if !usable(r) || string(r.Response.Body) == "null" || json.Unmarshal(r.Response.Body, &items) != nil {
			uncertain(&p, "active_rules_unavailable")
			return p
		}
		for _, item := range items {
			if activeRuleTypes[item.Type] {
				p.Items = append(p.Items, item)
			} else {
				uncertain(&p, "active_rule_type_unknown")
			}
		}
		pop := r.Response.Population
		if pop == nil {
			uncertain(&p, "population_unknown")
			return p
		}
		for _, gap := range pop.Incomplete {
			uncertain(&p, gap)
		}
		if !pop.More {
			return p
		}
		req.NextOf = r.RequestID
	}
	uncertain(&p, "page_limit")
	return p
}
func ciDetail(path, sha string) string {
	return fmt.Sprintf("%s at default-branch commit %s", path, sha)
}
