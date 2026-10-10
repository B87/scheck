package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/b87/scheck/internal/policy"
	"gopkg.in/yaml.v3"
)

const WorkflowMaxBytes = 512 << 10
const codeWorkflowLimit = "workflow_limit"

var commitSHARE = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
var workflowFileRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,194}\.ya?ml$`)
var branchNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,254}$`)

// CI parameters select a resource within the same repository, never an API path.
// docs/spec/github-collector.md, "Compiled read plan".
func ValidWorkflowFile(v string) bool {
	return workflowFileRE.MatchString(v) && !strings.Contains(v, "..")
}
func ValidBranchName(v string) bool {
	if !branchNameRE.MatchString(v) || strings.Contains(v, "..") || strings.Contains(v, "//") || strings.HasSuffix(v, "/") {
		return false
	}
	for p := range strings.SplitSeq(v, "/") {
		if p == "." || p == ".." || strings.HasSuffix(p, ".lock") || strings.HasSuffix(p, ".") {
			return false
		}
	}
	return true
}
func (c *compiled) ciResource(name string) bool {
	t := c.types[name].Type
	return t == BranchName || t == CommitSHA || t == WorkflowFile
}
func (c *compiled) checkCIResources() error {
	for _, p := range c.Params {
		if !c.ciResource(p.Name) {
			continue
		}
		if c.Provider != "github" || c.Method != GET || c.Subject != "repo:github:{owner}/{repo}" || c.types["owner"].Type != Login || c.types["repo"].Type != RepoName || p.Optional {
			return errors.New("CI resources require an exact compiled GitHub repository GET")
		}
		switch p.Type {
		case BranchName:
			if p.Name != "branch" || (c.path != "/repos/{owner}/{repo}/branches/{branch}" && c.path != "/repos/{owner}/{repo}/rules/branches/{branch}") {
				return errors.New("branch parameter outside compiled branch reads")
			}
		case CommitSHA, WorkflowFile:
			if c.path != "/repos/{owner}/{repo}/contents/.github/workflows" && c.path != "/repos/{owner}/{repo}/contents/.github/workflows/{file}" {
				return errors.New("workflow resource outside compiled contents subtree")
			}
			if c.types["sha"].Type != CommitSHA || len(c.query) != 1 || c.query[0] != [2]string{"ref", "{sha}"} {
				return errors.New("workflow contents must pin ref to a commit SHA")
			}
			if p.Type == WorkflowFile && p.Name != "file" || p.Type == CommitSHA && p.Name != "sha" {
				return errors.New("unknown CI resource parameter")
			}
		}
	}
	if c.WorkflowYAML && (c.Provider != "github" || c.Method != GET || c.path != "/repos/{owner}/{repo}/contents/.github/workflows/{file}" || c.types["file"].Type != WorkflowFile || c.types["sha"].Type != CommitSHA || c.List != nil) {
		return errors.New("workflow decoding requires the compiled contents file read")
	}
	return nil
}

// workflowBody is the sole encoded-content exception to the JSON response pipeline.
// Decode -> redact -> bounded parse; no encoded or decoded source is persisted.
// docs/spec/github-collector.md, "Supported workflow syntax".
func workflowBody(raw []byte, red *policy.Redactor) ([]byte, []policy.Hit, string) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, nil, codeMalformed
	}
	var content, encoding string
	if json.Unmarshal(obj["content"], &content) != nil || json.Unmarshal(obj["encoding"], &encoding) != nil || encoding != "base64" {
		return nil, nil, "workflow_encoding_unknown"
	}
	delete(obj, "content")
	metadata, _ := json.Marshal(obj)
	clean, hits, err := red.RedactJSON(metadata)
	if err != nil {
		return nil, hits, codeMalformed
	}
	var out map[string]any
	if json.Unmarshal(clean, &out) != nil {
		return nil, hits, codeMalformed
	}
	// Upper bound before allocation. GitHub inserts newlines in base64.
	encoded := strings.ReplaceAll(strings.ReplaceAll(content, "\n", ""), "\r", "")
	if len(encoded) > base64.StdEncoding.EncodedLen(WorkflowMaxBytes) {
		return nil, hits, codeWorkflowLimit
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, hits, "workflow_encoding_unknown"
	}
	if len(decoded) > WorkflowMaxBytes {
		return nil, hits, codeWorkflowLimit
	}
	sanitized, dh := red.Redact(decoded)
	hits = append(hits, dh...)
	document, gap := workflowDocument(sanitized)
	if gap == "workflow_structure_limit" {
		return nil, hits, codeWorkflowLimit
	}
	out["decoded_bytes"] = len(decoded)
	if gap != "" {
		out["yaml_gap"] = gap
	} else {
		out["workflow"] = document
	}
	// A marker remains even for rejected YAML, without retaining its source.
	if len(dh) > 0 {
		out["redaction_marker"] = strings.Join(regexp.MustCompile(`\[REDACTED:[^\]\r\n]+\]`).FindAllString(string(sanitized), -1), " ")
	}
	body, _ := json.Marshal(out)
	return body, hits, ""
}
func workflowDocument(raw []byte) (any, string) {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var n yaml.Node
	if d.Decode(&n) != nil {
		return nil, "workflow_yaml_invalid"
	}
	var next yaml.Node
	if err := d.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, "workflow_yaml_multiple_documents"
	}
	if len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, "workflow_yaml_root_unknown"
	}
	count := 0
	return workflowNode(n.Content[0], 0, &count)
}
func workflowNode(n *yaml.Node, depth int, count *int) (any, string) {
	*count++
	if depth > 40 || *count > 20000 {
		return nil, "workflow_structure_limit"
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Tag == "!!merge" || n.Style&yaml.TaggedStyle != 0 {
		return nil, "workflow_yaml_unsupported"
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			*count++
			if *count > 20000 {
				return nil, "workflow_structure_limit"
			}
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
				return nil, "workflow_yaml_key_unknown"
			}
			if _, dup := out[k.Value]; dup {
				return nil, "workflow_yaml_duplicate_key"
			}
			v, gap := workflowNode(n.Content[i+1], depth+1, count)
			if gap != "" {
				return nil, gap
			}
			out[k.Value] = v
		}
		return out, ""
	case yaml.SequenceNode:
		out := []any{}
		for _, child := range n.Content {
			v, gap := workflowNode(child, depth+1, count)
			if gap != "" {
				return nil, gap
			}
			out = append(out, v)
		}
		return out, ""
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, ""
		case "!!null":
			return nil, ""
		case "!!bool":
			if n.Value == "true" {
				return true, ""
			}
			if n.Value == "false" {
				return false, ""
			}
		}
	}
	return nil, "workflow_yaml_type_unknown"
}
