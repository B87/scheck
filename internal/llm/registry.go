package llm

import (
	"fmt"
	"sort"
	"sync"
)

// Config is what a provider needs to be built: the operator's selection
// (docs/SPEC.md §5.2, §9). Credentials are never here; an adapter reads
// them from the environment itself.
type Config struct {
	Model      string
	BaseURL    string
	MaxContext int    // operator-declared context window; 0 = adapter decides or fails
	Transcript string // mock only: the transcript file to replay
	Effort     Effort
	// Env answers environment lookups so tests can inject credentials
	// without touching the process environment. nil means os.LookupEnv.
	Env func(string) (string, bool)
}

// Factory builds a provider from config. It must not perform network I/O.
type Factory func(Config) (Provider, error)

// Info describes a registered provider for `scheck providers` without
// building it: what it needs and whether the environment supplies it.
type Info struct {
	Name       string `json:"name"`
	Summary    string `json:"summary"`
	Credential string `json:"credential"` // env var name, or "" when none is needed
	Deferred   bool   `json:"deferred"`   // registered for surface stability, exits 3
}

type entry struct {
	info    Info
	factory Factory
}

var (
	mu       sync.RWMutex
	registry = map[string]entry{}
)

// Register adds a provider. A duplicate name is a programming error.
func Register(info Info, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[info.Name]; dup {
		panic(fmt.Sprintf("llm: provider %q registered twice", info.Name))
	}
	registry[info.Name] = entry{info, f}
}

// Providers lists every registered provider, sorted by name.
func Providers() []Info {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Info, 0, len(registry))
	for _, e := range registry {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the registration for name.
func Lookup(name string) (Info, Factory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := registry[name]
	return e.info, e.factory, ok
}

// Build constructs the named provider. A deferred provider fails here with
// the usage message the CLI prints (docs/SPEC.md §5.2).
func Build(name string, cfg Config) (Provider, error) {
	info, f, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	if info.Deferred || f == nil {
		return nil, fmt.Errorf("provider %q is not available in this build", name)
	}
	return f(cfg)
}
