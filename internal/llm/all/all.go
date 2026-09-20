// Package all links every provider adapter into the binary and registers the
// deferred ones, so `scheck providers` lists the whole surface and a
// deferred selection exits 3 "not available in this build" rather than
// "unknown provider" (docs/SPEC.md §5.2).
package all

import (
	"github.com/b87/scheck/internal/llm"
	_ "github.com/b87/scheck/internal/llm/mock" // registers mock
)

// Env var names are the names a credential lives under, never a value.
const (
	openAIKeyVar    = "OPENAI_API_KEY"    //nolint:gosec // the variable's name, not a secret
	anthropicKeyVar = "ANTHROPIC_API_KEY" //nolint:gosec // the variable's name, not a secret
)

func init() {
	// The reference adapter lands in M2.6; until then it is listed so the
	// default selection fails with the same message as any other missing
	// adapter rather than "unknown provider".
	llm.Register(llm.Info{Name: "openai-compatible", Summary: "OpenAI-compatible chat completions with native tool calling (default; M2.6)", Credential: openAIKeyVar}, nil)
	llm.Register(llm.Info{Name: "anthropic", Summary: "Claude API (post-v1, M3.1)", Credential: anthropicKeyVar, Deferred: true}, nil)
	llm.Register(llm.Info{Name: "ollama", Summary: "local models, zero egress (post-v1, M3.2)", Deferred: true}, nil)
}
