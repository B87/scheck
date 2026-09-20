package openai

import "strings"

// modelInfo is what the adapter knows about a model family: the context
// window (docs/SPEC.md §5.3: known from validated configuration or reliable
// metadata, never assumed) and the list price per million tokens for the
// cost line (§5.5). A model outside the table needs max_context: and reports
// cost null. Prices are the published OpenAI list prices at the time of
// writing and are only used to fill usage.cost_usd; an operator on another
// endpoint gets tokens and null cost, never an invented number.
type modelInfo struct {
	prefix     string
	maxContext int
	inputUSD   float64 // per 1M input tokens
	cachedUSD  float64 // per 1M cached input tokens
	outputUSD  float64 // per 1M output tokens
	reasoning  bool    // accepts reasoning_effort
	// toolsNeedNone: chat completions accepts function tools only with
	// reasoning_effort=none. Omitting the field lets the endpoint default
	// to medium and reject the request (GPT-5.6 Luna).
	toolsNeedNone bool
}

// models is matched by prefix, longest first, on the model name.
// GPT-5.6 and GPT-6 must outrank the "gpt-5" prefix: "gpt-5.6-luna"
// HasPrefix-matches "gpt-5".
var models = []modelInfo{
	{prefix: "gpt-6-astra", maxContext: 1050000, inputUSD: 10.00, cachedUSD: 1.00, outputUSD: 50.00, reasoning: true},
	{prefix: "gpt-5.6-luna", maxContext: 1050000, inputUSD: 0.20, cachedUSD: 0.02, outputUSD: 1.20, reasoning: true, toolsNeedNone: true},
	{prefix: "gpt-5.6-terra", maxContext: 1050000, inputUSD: 2.00, cachedUSD: 0.20, outputUSD: 12.00, reasoning: true},
	{prefix: "gpt-5.6-sol", maxContext: 1050000, inputUSD: 4.00, cachedUSD: 0.40, outputUSD: 20.00, reasoning: true},
	{prefix: "gpt-5.6", maxContext: 1050000, inputUSD: 4.00, cachedUSD: 0.40, outputUSD: 20.00, reasoning: true}, // alias of Sol
	{prefix: "gpt-5-nano", maxContext: 400000, inputUSD: 0.05, cachedUSD: 0.005, outputUSD: 0.40, reasoning: true},
	{prefix: "gpt-5-mini", maxContext: 400000, inputUSD: 0.25, cachedUSD: 0.025, outputUSD: 2.00, reasoning: true},
	{prefix: "gpt-5", maxContext: 400000, inputUSD: 1.25, cachedUSD: 0.125, outputUSD: 10.00, reasoning: true},
	{prefix: "gpt-4.1-nano", maxContext: 1047576, inputUSD: 0.10, cachedUSD: 0.025, outputUSD: 0.40},
	{prefix: "gpt-4.1-mini", maxContext: 1047576, inputUSD: 0.40, cachedUSD: 0.10, outputUSD: 1.60},
	{prefix: "gpt-4.1", maxContext: 1047576, inputUSD: 2.00, cachedUSD: 0.50, outputUSD: 8.00},
	{prefix: "gpt-4o-mini", maxContext: 128000, inputUSD: 0.15, cachedUSD: 0.075, outputUSD: 0.60},
	{prefix: "gpt-4o", maxContext: 128000, inputUSD: 2.50, cachedUSD: 1.25, outputUSD: 10.00},
	{prefix: "o4-mini", maxContext: 200000, inputUSD: 1.10, cachedUSD: 0.275, outputUSD: 4.40, reasoning: true},
	{prefix: "o3-mini", maxContext: 200000, inputUSD: 1.10, cachedUSD: 0.55, outputUSD: 4.40, reasoning: true},
	{prefix: "o3", maxContext: 200000, inputUSD: 2.00, cachedUSD: 0.50, outputUSD: 8.00, reasoning: true},
	{prefix: "o1", maxContext: 200000, inputUSD: 15.00, cachedUSD: 7.50, outputUSD: 60.00, reasoning: true},
}

// lookup returns the table entry whose prefix matches model.
func lookup(model string) (modelInfo, bool) {
	best, found := modelInfo{}, false
	for _, m := range models {
		if strings.HasPrefix(model, m.prefix) && len(m.prefix) > len(best.prefix) {
			best, found = m, true
		}
	}
	return best, found
}

// cost prices a turn, or returns nil when the model has no known price or
// the endpoint is not OpenAI's (the price table is OpenAI's list).
func (m modelInfo) cost(input, cached, output int) *float64 {
	if m.inputUSD == 0 && m.outputUSD == 0 {
		return nil
	}
	uncached := max(input-cached, 0)
	c := (float64(uncached)*m.inputUSD + float64(cached)*m.cachedUSD + float64(output)*m.outputUSD) / 1e6
	return &c
}
