package engagement

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestExamplesValidate parses every engagement file under docs/examples and
// checks that docs/examples/README.md names each of them and no other. The
// spec-steward keeps the comments; this test keeps the files inside intake.
func TestExamplesValidate(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "examples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("docs/examples has no engagement files")
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(name, raw, testOpts); err != nil {
			t.Errorf("%s does not validate:\n%v", name, err)
		}
		if !strings.Contains(string(readme), name) {
			t.Errorf("docs/examples/README.md does not name %s", name)
		}
	}
	seen := map[string]bool{}
	for _, name := range regexp.MustCompile(`[a-z0-9-]+\.yaml`).FindAllString(string(readme), -1) {
		if seen[name] {
			continue
		}
		seen[name] = true
		if !slices.Contains(names, name) {
			t.Errorf("docs/examples/README.md names %s, which is not in docs/examples", name)
		}
	}
}
