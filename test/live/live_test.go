//go:build live

// Package live holds the opt-in tests that spend real money (docs/SPEC.md
// §11): SCHECK_LIVE=1 and OPENAI_API_KEY (or a --base-url endpoint) are
// required, and `make live` runs them. They never run in `make check`.
//
// `scheck local` and `scheck ssh` assess with the posture rules alone and
// cost nothing in this build (docs/SPEC.md §2.1), so the one path left that
// spends money is the evaluation harness. This test drives it against one
// labeled case: it checks the adapter end to end against the real endpoint
// and records the cost of one agent run.
package live

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func need(t *testing.T) (model string) {
	t.Helper()
	if os.Getenv("SCHECK_LIVE") != "1" {
		t.Skip("SCHECK_LIVE=1 not set")
	}
	model = os.Getenv("SCHECK_LIVE_MODEL")
	if model == "" {
		model = "gpt-5.6-luna"
	}
	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("SCHECK_LIVE_BASE_URL") == "" {
		t.Skip("OPENAI_API_KEY or SCHECK_LIVE_BASE_URL not set")
	}
	return model
}

// One live run of the harness on the clean Linux case: the agent arm
// completes, costs well under the $0.50 of acceptance criterion 7, attempts
// no check the policy denies, and every finding it reports carries evidence.
func TestLiveEvalRun(t *testing.T) {
	model := need(t)
	args := []string{"run", "../../cmd/scheck", "eval", "--model", model, "--suite", "../../testdata/eval",
		"--cases", "linux-clean", "--no-pairs", "--repeat", "1", "--format", "json"}
	if u := os.Getenv("SCHECK_LIVE_BASE_URL"); u != "" {
		args = append(args, "--base-url", u)
	}
	if mc := os.Getenv("SCHECK_LIVE_MAX_CONTEXT"); mc != "" {
		args = append(args, "--max-context", mc)
	}
	cmd := exec.Command("go", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	var res struct {
		Live          bool   `json:"live"`
		Provider      string `json:"provider"`
		Model         string `json:"model"`
		PromptVersion string `json:"prompt_version"`
		Runs          []struct {
			Arm      string   `json:"arm"`
			Status   string   `json:"status"`
			Ended    string   `json:"ended"`
			Checks   int      `json:"checks"`
			Denied   int      `json:"denied_tool_calls"`
			RuledOut []string `json:"ruled_out"`
			Usage    struct {
				Input     int      `json:"input"`
				CacheRead int      `json:"cache_read"`
				CostUSD   *float64 `json:"cost_usd"`
			} `json:"usage"`
			Findings []struct {
				Source   string `json:"source"`
				Evidence []struct {
					Observation string `json:"observation"`
				} `json:"evidence"`
			} `json:"findings"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	if !res.Live || res.Provider != "openai-compatible" || res.Model != model {
		t.Errorf("record header: live=%v provider=%s model=%s", res.Live, res.Provider, res.Model)
	}
	var agent int
	for _, r := range res.Runs {
		if r.Arm != "agent" {
			continue
		}
		agent++
		cost := "unpriced"
		if r.Usage.CostUSD != nil {
			cost = fmt.Sprintf("$%.4f", *r.Usage.CostUSD)
		}
		t.Logf("agent run: status %s ended %q checks %d ruled_out %v input %d cache_read %d cost %s (criterion 7 record, prompt %s)",
			r.Status, r.Ended, r.Checks, r.RuledOut, r.Usage.Input, r.Usage.CacheRead, cost, res.PromptVersion)
		if r.Status != "complete" {
			t.Errorf("agent run did not finish: %s", r.Ended)
		}
		if r.Usage.CostUSD != nil && *r.Usage.CostUSD >= 0.50 {
			t.Errorf("cost %.4f USD is not under the $0.50 budget", *r.Usage.CostUSD)
		}
		if r.Denied > 0 {
			t.Errorf("%d model-initiated check(s) were denied by policy", r.Denied)
		}
		for _, f := range r.Findings {
			if f.Source == "model" && len(f.Evidence) == 0 {
				t.Errorf("model finding without evidence: %+v", f)
			}
		}
	}
	if agent == 0 {
		t.Fatalf("no agent run in the record:\n%s", out.String())
	}
}
