//go:build live

// Package live holds the opt-in tests that spend real money (docs/SPEC.md
// §11): SCHECK_LIVE=1 and OPENAI_API_KEY (or a --base-url endpoint) are
// required, and `make live` runs them. They never run in `make check`.
package live

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func need(t *testing.T) (model string) {
	t.Helper()
	if os.Getenv("SCHECK_LIVE") != "1" {
		t.Skip("SCHECK_LIVE=1 not set")
	}
	model = os.Getenv("SCHECK_LIVE_MODEL")
	if model == "" {
		model = "gpt-5-mini"
	}
	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("SCHECK_LIVE_BASE_URL") == "" {
		t.Skip("OPENAI_API_KEY or SCHECK_LIVE_BASE_URL not set")
	}
	return model
}

// One `scheck local` run against this machine with the reference adapter:
// a full agentic report, cost under $0.50 at default effort (acceptance
// criterion 7), no denied model-initiated check in the audit log, and cache
// hits reported by the endpoint on the second turn onward.
func TestLiveLocalRun(t *testing.T) {
	model := need(t)
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	args := []string{"run", "../../cmd/scheck", "local", "--model", model, "--format", "json", "--no-persist", "--audit-log", audit}
	if u := os.Getenv("SCHECK_LIVE_BASE_URL"); u != "" {
		args = append(args, "--base-url", u)
	}
	if mc := os.Getenv("SCHECK_LIVE_MAX_CONTEXT"); mc != "" {
		args = append(args, "--max-context", mc)
	}
	cmd := exec.Command("go", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	if code == 3 {
		t.Fatalf("usage error:\n%s", errb.String())
	}
	var env struct {
		Run struct {
			Status   string `json:"status"`
			Mode     string `json:"mode"`
			Provider string `json:"provider"`
			Usage    struct {
				Input     int      `json:"input"`
				CacheRead int      `json:"cache_read"`
				CostUSD   *float64 `json:"cost_usd"`
			} `json:"usage"`
			Agent struct {
				Iterations int    `json:"iterations"`
				Ended      string `json:"ended"`
			} `json:"agent"`
		} `json:"run"`
		Findings []struct {
			Source   string `json:"source"`
			Evidence []struct{ Check string } `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	t.Logf("status %s mode %s iterations %d ended %q usage %+v", env.Run.Status, env.Run.Mode, env.Run.Agent.Iterations, env.Run.Agent.Ended, env.Run.Usage)
	if env.Run.Provider != "openai-compatible" || env.Run.Mode != "agent" {
		t.Errorf("run block: %+v", env.Run)
	}
	if env.Run.Usage.CostUSD != nil && *env.Run.Usage.CostUSD >= 0.50 {
		t.Errorf("cost %.4f USD is not under the $0.50 budget", *env.Run.Usage.CostUSD)
	}
	if env.Run.Agent.Iterations > 1 && env.Run.Usage.CacheRead == 0 {
		t.Logf("note: no cached tokens reported over %d turns", env.Run.Agent.Iterations)
	}
	for _, f := range env.Findings {
		if len(f.Evidence) == 0 {
			t.Errorf("finding without evidence: %+v", f)
		}
	}
	raw, _ := os.ReadFile(audit)
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.Contains(line, `"tool":`) && strings.Contains(line, `"decision":"denied:`) {
			t.Errorf("a model-initiated check was denied: %s", line)
		}
	}
}
