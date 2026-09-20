package llm

import (
	"os/exec"
	"strings"
	"testing"
)

// The packages that consume the contract compile with no provider
// dependency (docs/SPEC.md §5.1): no adapter, no SDK. The Makefile's
// depcheck target runs the same check in CI; this keeps it in `go test` too.
func TestConsumersHaveNoProviderDependency(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not on PATH")
	}
	for _, pkg := range []string{"agent", "policy", "check", "finding", "report", "llm"} {
		out, err := exec.Command("go", "list", "-deps", "../"+pkg).CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "no Go files") || strings.Contains(string(out), "cannot find") || strings.Contains(string(out), "directory not found") {
				continue // the package does not exist yet
			}
			t.Fatalf("go list ../%s: %v\n%s", pkg, err, out)
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if strings.Contains(line, "/internal/llm/") || strings.Contains(line, "openai") || strings.Contains(line, "anthropic") {
				t.Errorf("internal/%s depends on %s", pkg, line)
			}
		}
	}
}
