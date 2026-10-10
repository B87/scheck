package gate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/policy"
)

func metadataTestOp(t *testing.T) *compiled {
	t.Helper()
	o := Op{ID: "test.alerts", Provider: "github", Method: GET, URL: "https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts?per_page=100&page={page}&hide_secret=true", Subject: "repo:github:{owner}/{repo}", Params: []Param{{Name: "owner", Type: Login}, {Name: "repo", Type: RepoName}, {Name: "page", Type: Count, Optional: true}}, Auth: GitHubToken, Level: Observe, APIVersion: "2026-03-10", Accept: []string{"application/json"}, Keep: []string{"number", "state", "secret_type", "validity", "redaction_marker"}, MaxBytes: 1 << 20, List: &List{Items: "$", Kind: KindOther, Next: &Pages{Param: "page"}, MaxPages: 100}, GitHubMetadata: true}
	reg, err := NewRegistry(o)
	if err != nil {
		t.Fatal(err)
	}
	return reg.ops[o.ID]
}
func TestProviderSecretFieldsNeverSurviveMetadataProjection(t *testing.T) {
	op := metadataTestOp(t)
	red, _ := policy.NewRedactor(nil)
	for _, secret := range []any{"opaque-unrecognized-value", "true", "1", true, 1, map[string]any{"unexpected": "nested-secret-value"}, "ghp_" + strings.Repeat("s", 36)} {
		raw, _ := json.Marshal([]any{map[string]any{"number": 7, "state": "open", "secret_type": "stripe", "validity": "unknown", "secret": secret, "metadata": map[string]string{"opaque": "discard-this-too"}, "url": "https://outside.example/secret", "redaction_marker": "target-forged"}})
		clean, _, code := metadataBody(raw, red, op)
		if code != "" {
			t.Fatal(code)
		}
		doc, _ := parseRedacted(clean)
		out := string(marshal(project(doc, op.keep)))
		if strings.Contains(out, "opaque-unrecognized") || strings.Contains(out, "nested-secret") || strings.Contains(out, "discard-this") || strings.Contains(out, "outside.example") || strings.Contains(out, "target-forged") || !strings.Contains(out, "[REDACTED:") {
			t.Fatalf("projection leaked %s", out)
		}
		if !strings.Contains(out, `"number":7`) || !strings.Contains(out, `"validity":"unknown"`) {
			t.Fatal("safe metadata erased")
		}
	}
}
func TestMetadataMalformedAndDuplicateEvidenceIsDiscarded(t *testing.T) {
	op := metadataTestOp(t)
	red, _ := policy.NewRedactor(nil)
	for _, raw := range []string{`[{"number":7,"state":"open","state":"resolved"}]`, `null`, `{"number":7}`, `["secret"]`, `[{"number":7}] []`, `[{`, strings.Repeat("[", 42) + "0" + strings.Repeat("]", 42)} {
		clean, _, code := metadataBody([]byte(raw), red, op)
		if code == "" || len(clean) != 0 {
			t.Fatal("ambiguous response accepted", raw)
		}
	}
	op.List.Items = "secrets"
	if clean, _, code := metadataBody([]byte(`{}`), red, op); code == "" || len(clean) != 0 {
		t.Fatal("missing list read as empty")
	}
}
func TestMetadataResourceBindingRejectsEscapes(t *testing.T) {
	for _, name := range []string{"../x", "A/B", "A%2fB", "GITHUB_TOKEN", "1BAD", "X?next=bad"} {
		if _, err := bindValue(SecretName, name); err == nil {
			t.Error("bad secret", name)
		}
	}
	for _, n := range []string{"0", "-1", "01", "1/locations", "1?x=2", "9223372036854775808"} {
		if _, err := bindValue(AlertNumber, n); err == nil {
			t.Error("bad number", n)
		}
	}
	if got, err := bindValue(SecretName, "Prod_token"); err != nil || got != "PROD_TOKEN" {
		t.Fatal("name canonicalization")
	}
	op := metadataTestOp(t).Op
	op.URL = "https://api.github.com/repos/{owner}/{repo}/keys/{alert_number}"
	op.Params = append(op.Params, Param{Name: "alert_number", Type: AlertNumber})
	if _, err := NewRegistry(op); err == nil {
		t.Fatal("resource escaped subtree")
	}
}
