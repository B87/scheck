package policy

import (
	"strings"
	"testing"
)

func TestWorkflowReferencesKeepOnlyWholeBuiltInReferences(t *testing.T) {
	red, _ := NewRedactor(nil)
	for _, value := range []string{"${{ github.token }}", "${{secrets.GITHUB_TOKEN}}", `"${{ github.token }}"`, "'${{ secrets.GITHUB_TOKEN }}'"} {
		raw := "GH_TOKEN: " + value + "\n"
		clean, hits := red.WithWorkflowReferences().Redact([]byte(raw))
		if string(clean) != raw || len(hits) != 0 {
			t.Fatalf("reference %s: %s %v", value, clean, hits)
		}
		if _, ordinaryHits := red.Redact([]byte(raw)); len(ordinaryHits) == 0 {
			t.Fatal("changed ordinary redactor")
		}
	}
	for _, value := range []string{"${{ secrets.CUSTOM }}", "${{ github.token || 'literal-password' }}", "${{ github.token }}suffix", "${{ github.token }} literal-password", `"${{ github.token }}" literal-password`, "literal-password"} {
		clean, hits := red.WithWorkflowReferences().Redact([]byte("GH_TOKEN: " + value + "\n"))
		if len(hits) == 0 || strings.Contains(string(clean), "literal-password") || strings.Contains(string(clean), "secrets.CUSTOM") {
			t.Fatalf("unsafe value %s: %s %v", value, clean, hits)
		}
	}
	for _, with := range []*Redactor{red.WithLiteral("credential", "${{ github.token }}"), red.WithLiteral("kv-secret", "${{ github.token }}"), mustWorkflowExtra(t)} {
		clean, hits := with.WithWorkflowReferences().Redact([]byte("GH_TOKEN: ${{ github.token }}\n"))
		if len(hits) == 0 || !strings.Contains(string(clean), "[REDACTED:") {
			t.Fatal("other masking disabled")
		}
	}
	secret := "ghp_" + strings.Repeat("s", 36)
	clean, hits := red.WithWorkflowReferences().Redact([]byte("GH_TOKEN: " + secret))
	if strings.Contains(string(clean), secret) || len(hits) == 0 || !strings.Contains(string(clean), "[REDACTED:") {
		t.Fatal("literal secret retained")
	}
}
func mustWorkflowExtra(t *testing.T) *Redactor {
	t.Helper()
	red, err := NewRedactor([]string{`github\.token`})
	if err != nil {
		t.Fatal(err)
	}
	return red
}
