// Package config loads scheck.yaml (docs/SPEC.md §9). Every knob narrows: config
// disables checks, denies paths and adds redactions; nothing here widens what
// scheck may execute or reveal, and no credential is ever read from a file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/check"
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
	AllowEgress   *bool                `yaml:"allow_egress"`
	Profile       string               `yaml:"profile"`
	Elevate       string               `yaml:"elevate"`
	StateDir      string               `yaml:"state_dir"`
	DisableChecks []string             `yaml:"disable_checks"`
	DenyPaths     []string             `yaml:"deny_paths"`
	RedactExtra   []string             `yaml:"redact_extra"`
	Targets       map[string]SSHTarget `yaml:"targets"`
	Context       yaml.Node            `yaml:"context"`

	// Sources lists the files that contributed, in merge order.
	Sources []string `yaml:"-"`
}

// Paths returns the default file chain, lowest precedence first.
func Paths() []string {
	var out []string
	if dir, err := os.UserConfigDir(); err == nil {
		out = append(out, filepath.Join(dir, "scheck", "config.yaml"))
	}
	out = append(out, "scheck.yaml")
	return out
}

// Load merges the default file chain. A missing file is not an error; a
// malformed one, or one with an unknown top-level key, is.
func Load() (*Config, error) { return LoadFiles(Paths()...) }

// LoadFiles merges the given files, later ones overriding earlier ones per
// scalar key; list keys are unioned because they can only narrow.
func LoadFiles(paths ...string) (*Config, error) {
	merged := &Config{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("config %s: %w", p, err)
		}
		var c Config
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil && !errors.Is(err, os.ErrNotExist) && err.Error() != "EOF" {
			return nil, fmt.Errorf("config %s: %w", p, err)
		}
		merged.overlay(&c)
		merged.Sources = append(merged.Sources, p)
	}
	return merged, nil
}

func (c *Config) overlay(o *Config) {
	setIf(&c.Provider, o.Provider)
	setIf(&c.Model, o.Model)
	setIf(&c.BaseURL, o.BaseURL)
	setIf(&c.Effort, o.Effort)
	setIf(&c.Profile, o.Profile)
	setIf(&c.Elevate, o.Elevate)
	setIf(&c.StateDir, o.StateDir)
	if o.AllowEgress != nil {
		c.AllowEgress = o.AllowEgress
	}
	c.DisableChecks = union(c.DisableChecks, o.DisableChecks)
	c.DenyPaths = union(c.DenyPaths, o.DenyPaths)
	c.RedactExtra = union(c.RedactExtra, o.RedactExtra)
	if len(o.Targets) > 0 {
		if c.Targets == nil {
			c.Targets = map[string]SSHTarget{}
		}
		maps.Copy(c.Targets, o.Targets)
	}
	if !o.Context.IsZero() {
		c.Context = o.Context
	}
}

func setIf(dst *string, v string) {
	if v != "" {
		*dst = v
	}
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
	return nil
}

func known(id string) bool {
	for _, c := range check.All() {
		if c.ID == id {
			return true
		}
	}
	return false
}
