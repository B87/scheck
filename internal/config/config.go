// Package config loads scheck.yaml (docs/SPEC.md §9). Every knob narrows: config
// disables checks, denies paths and adds redactions; nothing here widens what
// scheck may execute or reveal, and no credential is ever read from a file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
)

// SSHTarget is a named `targets:` entry.
type SSHTarget struct {
	Host     string `yaml:"host"`
	User     string `yaml:"user"`
	Port     int    `yaml:"port"`
	Identity string `yaml:"identity"`
}

// Config is the merged configuration. Fields belonging to later milestones
// (provider, model, context, ...) are parsed so a file written for v1 loads,
// and ignored until their milestone lands.
type Config struct {
	Provider      string               `yaml:"provider"`
	Model         string               `yaml:"model"`
	BaseURL       string               `yaml:"base_url"`
	Effort        string               `yaml:"effort"`
	MaxContext    int                  `yaml:"max_context"`
	AllowEgress   *bool                `yaml:"allow_egress"`
	Profile       string               `yaml:"profile"`
	Elevate       string               `yaml:"elevate"`
	StateDir      string               `yaml:"state_dir"`
	DisableChecks []string             `yaml:"disable_checks"`
	DenyPaths     []string             `yaml:"deny_paths"`
	RedactExtra   []string             `yaml:"redact_extra"`
	Targets       map[string]SSHTarget `yaml:"targets"`
	Context       yaml.Node            `yaml:"context"`
	// ContextSource is the file whose context: block won (a later file
	// replaces the block whole; per-key merging happens across --context
	// sources, docs/SPEC.md §6.1).
	ContextSource string `yaml:"-"`

	// Sources lists the files that contributed, in merge order.
	Sources []string `yaml:"-"`
}

// Paths returns the default file chain, lowest precedence first: the OS
// user config, then the project file (docs/SPEC.md §9).
func Paths() []string {
	var out []string
	if p, err := UserConfigPath(); err == nil {
		out = append(out, p)
	}
	return append(out, ProjectConfigPath)
}

// Load resolves the default file chain with no flag overrides.
func Load() (*Config, error) { return LoadFiles(Paths()...) }

// LoadFiles merges the given files over the built-in defaults, later ones
// overriding earlier ones per scalar key; list keys are unioned because they
// can only narrow. A missing file is not an error; a malformed one, or one
// with an unknown top-level key, is.
func LoadFiles(paths ...string) (*Config, error) {
	layers, err := LoadLayers(paths...)
	if err != nil {
		return nil, err
	}
	return Resolve(layers, Overrides{}).Config, nil
}

// readFile parses one file. present is false when it does not exist.
func readFile(p string) (*Config, bool, error) {
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("config %s: %w", p, err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && err.Error() != "EOF" {
		return nil, false, fmt.Errorf("config %s: %w", p, err)
	}
	return &c, true, nil
}

func union(a, b []string) []string {
	for _, v := range b {
		if !slices.Contains(a, v) {
			a = append(a, v)
		}
	}
	return a
}

// Validate checks every phase-1 knob. An unknown check id in disable_checks
// is a usage error so a typo cannot silently leave a check enabled.
func (c *Config) Validate() error {
	if _, ok := check.ParseProfile(c.Profile); !ok {
		return fmt.Errorf("config: profile %q is not baseline|hardened", c.Profile)
	}
	switch c.Elevate {
	case "", "none", "sudo":
	default:
		return fmt.Errorf("config: elevate %q is not none|sudo", c.Elevate)
	}
	for _, id := range c.DisableChecks {
		if !known(id) {
			return fmt.Errorf("config: disable_checks: unknown check id %q", id)
		}
	}
	if _, err := policy.NewRedactor(c.RedactExtra); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if _, ok := llm.ParseEffort(c.Effort); !ok {
		return fmt.Errorf("config: effort %q is not low|medium|high|max", c.Effort)
	}
	if c.MaxContext < 0 {
		return fmt.Errorf("config: max_context %d is negative", c.MaxContext)
	}
	// The context: block is validated at load so an unknown accepted-risk id
	// is a usage error before anything runs (docs/SPEC.md §6.2).
	if _, err := operator.Load(operator.Options{ConfigContext: c.Context, ConfigSource: c.ContextSource, KnownFinding: KnownFinding}); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// KnownFinding is the accepted_risks id check (docs/SPEC.md §6.2).
func KnownFinding(id string) bool {
	_, ok := finding.Lookup(id)
	return ok
}

func known(id string) bool {
	for _, c := range check.All() {
		if c.ID == id {
			return true
		}
	}
	return false
}
