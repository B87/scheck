package llm

import (
	"strings"
	"testing"
)

// The estimate is a conservative bound: it never undercounts the bytes it is
// given, and it grows with every part of the request the provider will see.
func TestEstimateCountsEveryPart(t *testing.T) {
	base := Request{MaxTokens: 100}
	n0 := Estimate(base)
	withSystem := base
	withSystem.System = []Block{{Text: strings.Repeat("x", 3000)}}
	withTools := withSystem
	withTools.Tools = []Tool{{Name: "run_check", Description: strings.Repeat("d", 300), Schema: MustJSON(map[string]any{"type": "object"})}}
	withMsgs := withTools
	withMsgs.Messages = []Message{
		{Role: RoleUser, Text: strings.Repeat("m", 600)},
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "1", Name: "run_check", Input: MustJSON(map[string]string{"id": "x"})}}},
		{Role: RoleUser, ToolResults: []ToolResult{{CallID: "1", Content: strings.Repeat("o", 3000)}}},
	}
	n1, n2, n3 := Estimate(withSystem), Estimate(withTools), Estimate(withMsgs)
	if n0 >= n1 || n1 >= n2 || n2 >= n3 {
		t.Fatalf("estimate not monotone: %d %d %d %d", n0, n1, n2, n3)
	}
	if n1-n0 < 1000 { // 3000 bytes at 3 bytes/token
		t.Errorf("system block under-counted: +%d", n1-n0)
	}
	if n3-n2 < 1000+200 {
		t.Errorf("tool result under-counted: +%d", n3-n2)
	}
}

func TestCheckFit(t *testing.T) {
	r := Request{System: []Block{{Text: strings.Repeat("x", 30000)}}, MaxTokens: 4000}
	if _, err := CheckFit(r, Limits{}); KindOf(err) != ErrUnsupported {
		t.Errorf("unknown limit must be a configuration error, got %v", err)
	}
	if f, err := CheckFit(r, Limits{MaxContext: 12000}); err == nil || KindOf(err) != ErrContextOverflow || f.OK() {
		t.Errorf("10k estimated + 4k reserved must not fit 12k: %v %+v", err, f)
	}
	if f, err := CheckFit(r, Limits{MaxContext: 20000}); err != nil || !f.OK() {
		t.Errorf("should fit: %v %+v", err, f)
	}
	// The output reservation counts: the same request fits when it is smaller.
	r.MaxTokens = 1000
	if _, err := CheckFit(r, Limits{MaxContext: 12000}); err != nil {
		t.Errorf("reservation not counted: %v", err)
	}
}

func TestUsageAdd(t *testing.T) {
	a, b := 0.5, 0.25
	var u Usage
	u.Add(Usage{Input: 10, Output: 1, CostUSD: &a})
	u.Add(Usage{Input: 5, Output: 2, CostUSD: &b})
	if u.Input != 15 || u.Output != 3 || u.CostUSD == nil || *u.CostUSD != 0.75 {
		t.Errorf("priced sum: %+v", u)
	}
	u.Add(Usage{Input: 1})
	if u.CostUSD != nil {
		t.Error("an unpriced turn must make the total unpriced")
	}
	var fresh Usage
	fresh.Add(Usage{Input: 1})
	fresh.Add(Usage{Input: 1, CostUSD: &a})
	if fresh.CostUSD != nil {
		t.Error("a price arriving after an unpriced turn must not become the total")
	}
}
