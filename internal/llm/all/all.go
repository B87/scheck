// Package all links every provider adapter into the binary and registers the
// deferred ones, so `scheck providers` lists the whole surface and a
// deferred selection exits 3 "not available in this build" rather than
// "unknown provider" (docs/SPEC.md §5.2).
package all

import (
	"github.com/b87/scheck/internal/llm"
	_ "github.com/b87/scheck/internal/llm/mock"   // registers mock
	_ "github.com/b87/scheck/internal/llm/openai" // registers openai-compatible, the default
)

// Env var names are the names a credential lives under, never a value.
const anthropicKeyVar = "ANTHROPIC_API_KEY" //nolint:gosec // the variable's name, not a secret

func init() {
	llm.Register(llm.Info{Name: "anthropic", Summary: "Claude API (post-v1, M3.1)", Credential: anthropicKeyVar, Deferred: true}, nil)
	llm.Register(llm.Info{Name: "ollama", Summary: "local models, zero egress (post-v1, M3.2)", Deferred: true}, nil)
}
