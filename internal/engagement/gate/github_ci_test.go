package gate

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/policy"
)

func TestWorkflowDecodeRedactsBeforeProjectionAndParsing(t *testing.T) {
	secret := "ghp_" + strings.Repeat("s", 36)
	source := "on: push\njobs:\n  build:\n    steps:\n      - run: npm test\n    env:\n      TOKEN: " + secret + "\n"
	raw, _ := json.Marshal(map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(source)), "encoding": "base64", "path": ".github/workflows/test.yml", "type": "file"})
	red, _ := policy.NewRedactor(nil)
	clean, hits, code := workflowBody(raw, red)
	if code != "" || len(hits) == 0 || strings.Contains(string(clean), secret) || strings.Contains(string(clean), base64.StdEncoding.EncodeToString([]byte(source))) || !strings.Contains(string(clean), "[REDACTED:") {
		t.Fatalf("pipeline failed code%s hits%v body%s", code, hits, clean)
	}
	var result map[string]any
	_ = json.Unmarshal(clean, &result)
	if result["workflow"] == nil {
		t.Fatal("valid sanitized YAML lost")
	}
}
func TestWorkflowYAMLUnsupportedAndBounded(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"alias", "x: &x {run: npm test}\njobs: {build: *x}"},
		{"duplicate", "on: push\non: pull_request"},
		{"merge", "jobs: {build: {<<: {run: npm test}}}"},
		{"documents", "on: push\n---\non: pull_request"},
		{"tag", "on: !magic push"},
		{"nonstringkey", "1: push"},
		{"arrayroot", "[push]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, gap := workflowDocument([]byte(tc.source))
			if doc != nil || gap == "" {
				t.Fatal("unsupported YAML accepted")
			}
		})
	}
	for _, source := range []string{"on: push\njobs:\n  build:\n    if: true\n    steps:\n    - run: |\n        npm ci\n        npm test\n", "on: {pull_request_target: null}\npermissions: {contents: read}\njobs: {}"} {
		doc, gap := workflowDocument([]byte(source))
		if gap != "" || doc == nil {
			t.Fatalf("supported syntax: %s", gap)
		}
	}
	source := "root: " + strings.Repeat("[", 42) + "x" + strings.Repeat("]", 42)
	if _, gap := workflowDocument([]byte(source)); gap != "workflow_structure_limit" {
		t.Fatalf("depth cap %s", gap)
	}
	source = "root: [" + strings.Repeat("x,", 20001) + "x]"
	if _, gap := workflowDocument([]byte(source)); gap != "workflow_structure_limit" {
		t.Fatalf("node cap %s", gap)
	}
}
func TestCIResourceBindingsStayInsideCompiledSubtree(t *testing.T) {
	for _, v := range []string{"../main", "feature/../main", "main%2f..%2fkeys", "main?ref=x", "foo//bar", "foo.lock"} {
		if _, err := bindValue(BranchName, v); err == nil {
			t.Errorf("branch accepted %q", v)
		}
	}
	for _, v := range []string{"../x.yml", "x.yml?ref=main", "x/y.yml", "x%2fy.yml", ".git.yml"} {
		if _, err := bindValue(WorkflowFile, v); err == nil {
			t.Errorf("file accepted %q", v)
		}
	}
	if got, err := bindValue(BranchName, "Release/v1"); err != nil || got != "Release/v1" {
		t.Fatal("branch case lost")
	}
	op := Op{ID: "bad", Provider: "github", Method: GET, URL: "https://api.github.com/repos/{owner}/{repo}/keys/{branch}", Subject: "repo:github:{owner}/{repo}", Params: []Param{{Name: "owner", Type: Login}, {Name: "repo", Type: RepoName}, {Name: "branch", Type: BranchName}}, Level: Observe, Accept: []string{"application/json"}, Keep: []string{"id"}, MaxBytes: 1024}
	if _, err := NewRegistry(op); err == nil {
		t.Fatal("CI type escaped subtree")
	}
}

func TestWorkflowNumericScalarsAndTokenReferences(t *testing.T) {
	source := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 20\n    env:\n      GH_TOKEN: ${{ github.token }}\n      OTHER_TOKEN: '${{ secrets.GITHUB_TOKEN }}'\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          ratio: 1.5\n"
	raw, _ := json.Marshal(map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(source)), "encoding": "base64"})
	red, _ := policy.NewRedactor(nil)
	body, hits, code := workflowBody(raw, red)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if code != "" || len(hits) != 0 || out["yaml_gap"] != nil || out["workflow"] == nil {
		t.Fatalf("code=%s hits=%v body=%s", code, hits, body)
	}
	job := out["workflow"].(map[string]any)["jobs"].(map[string]any)["build"].(map[string]any)
	if job["timeout-minutes"] != float64(20) {
		t.Fatalf("lost numeric type: %#v", job)
	}
	for _, value := range []string{".inf", ".nan", "1e999", "9223372036854775808", "0x10", "012", "1_000", "999999999999999999999999999999999999999999999999999999999", "0xffffffffffffffffffffffff", "0o777777777777777777777777777777", "0b11111111111111111111111111111111111111111111111111111111111111111111"} {
		if _, gap := workflowDocument([]byte("value: " + value)); gap != "workflow_yaml_type_unknown" {
			t.Fatalf("numeric %s: %s", value, gap)
		}
	}
}
