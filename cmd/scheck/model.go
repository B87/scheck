package main

import (
	"fmt"

	"github.com/b87/scheck/internal/check"

	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/openai"
)

// defaultProvider is the v1 production adapter (docs/spec/model.md §3).
const defaultProvider = "openai-compatible"

// modelSelection is the provider choice of `scheck providers` and the
// evaluation harness, from their flags alone: scheck reads no configuration
// file (docs/spec/host-collector.md, "No configuration file"), and no host
// assessment builds a provider in this build (docs/spec/host-collector.md §2.1).
type modelSelection struct {
	Provider, Model, BaseURL, Effort, Profile string
	MaxContext                                int
}

// modelSelection validates the flags and fills gpt-5.6-luna when the model
// is unset and the endpoint is OpenAI's, so providers and the harness agree;
// a different base URL still needs --model (docs/spec/model.md §3). A bad
// value exits 3 rather than running a recorded evaluation at a default.
func (o *globalOpts) modelSelection() (modelSelection, error) {
	m := modelSelection{Provider: o.Provider, Model: o.Model, BaseURL: o.BaseURL, Effort: o.Effort,
		Profile: o.Profile, MaxContext: o.MaxContext}
	if _, ok := llm.ParseEffort(m.Effort); !ok {
		return m, usageErr("--effort must be low, medium, high or max")
	}
	if _, ok := check.ParseProfile(m.Profile); m.Profile != "" && !ok {
		return m, usageErr("--profile must be baseline or hardened")
	}
	if m.MaxContext < 0 {
		return m, usageErr("--max-context must be a positive number of tokens")
	}
	if m.Model == "" && (m.Provider == "" || m.Provider == openai.Name) {
		m.Model = openai.ResolveModel("", m.BaseURL)
	}
	return m, nil
}

// providerConfig is what an adapter is built from: the operator's
// selection, never a credential.
func (o *globalOpts) providerConfig(m modelSelection) llm.Config {
	effort, _ := llm.ParseEffort(m.Effort)
	return llm.Config{Model: m.Model, BaseURL: m.BaseURL, MaxContext: m.MaxContext, Transcript: o.Transcript, Effort: effort}
}

// validateProvider refuses an unknown or deferred adapter, and a missing
// model where the adapter needs one.
func validateProvider(m modelSelection) error {
	info, ok := llm.Lookup(m.Provider)
	if !ok {
		return fmt.Errorf("provider %q is unknown; `scheck providers` lists the registered ones", m.Provider)
	}
	if info.Deferred {
		return fmt.Errorf("provider %q is not available in this build", m.Provider)
	}
	if m.Model == "" && m.Provider != "mock" {
		return fmt.Errorf("model: not set; --model is required to build %s (no host assessment in this build needs one)", m.Provider)
	}
	return nil
}
