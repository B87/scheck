package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// Precedence (docs/SPEC.md §9): built-in defaults, then the OS user config,
// then the project scheck.yaml, then flags the operator explicitly set. A
// flag's registered default never overrides a file, which is why Overrides
// carries pointers: nil means "not given".
const (
	SourceDefault = "default"
	SourceFlag    = "flag"
)

// Overrides are the flags that were explicitly set on the command line.
type Overrides struct {
	Profile    *string
	Elevate    *string
	StateDir   *string
	Provider   *string
	Model      *string
	BaseURL    *string
	Effort     *string
	MaxContext *int
	LocalOnly  *bool
}

// Layer is one contributing source, in precedence order.
type Layer struct {
	Source  string
	Present bool // false for a file that does not exist
	Config  Config
}

// Resolved is the effective configuration with provenance: which source set
// each scalar, and which sources contributed to each list entry, so an
// inspection never claims one file owns a merged value (ROADMAP M2.2a).
type Resolved struct {
	Config  *Config
	Layers  []Layer
	Origin  map[string]string            // scalar key -> source
	Entries map[string]map[string]string // list key -> entry -> "src1, src2"
}

// Defaults is the built-in layer (docs/SPEC.md §9).
func Defaults() Config {
	return Config{
		Provider:    "openai-compatible",
		BaseURL:     "https://api.openai.com/v1",
		Profile:     "baseline",
		Elevate:     "none",
		AllowEgress: new(true),
	}
}

// UserConfigPath is the per-user file: $XDG_CONFIG_HOME/scheck/config.yaml
// or ~/.config/scheck/config.yaml on Linux, ~/Library/Application
// Support/scheck/config.yaml on macOS (os.UserConfigDir).
func UserConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "scheck", "config.yaml"), nil
}

// UserConfigDescription names the user path per platform for help text.
func UserConfigDescription() string {
	switch runtime.GOOS {
	case "darwin":
		return "~/Library/Application Support/scheck/config.yaml"
	default:
		return "$XDG_CONFIG_HOME/scheck/config.yaml (default ~/.config/scheck/config.yaml)"
	}
}

// ProjectConfigPath is the project file, relative to the working directory.
const ProjectConfigPath = "scheck.yaml"

// LoadLayers reads the file chain without merging: one Layer per path,
// present or not, in precedence order.
func LoadLayers(paths ...string) ([]Layer, error) {
	var out []Layer
	for _, p := range paths {
		l := Layer{Source: p}
		c, present, err := readFile(p)
		if err != nil {
			return nil, err
		}
		if present {
			l.Present = true
			l.Config = *c
		}
		out = append(out, l)
	}
	return out, nil
}

// Resolve folds defaults, the file layers and the explicit flags into the
// effective configuration, recording provenance as it goes. It does not
// validate; the caller does, so `config validate` and a run share both steps.
func Resolve(layers []Layer, ov Overrides) *Resolved {
	r := &Resolved{Config: &Config{}, Origin: map[string]string{}, Entries: map[string]map[string]string{}}
	all := append([]Layer{{Source: SourceDefault, Present: true, Config: Defaults()}}, layers...)
	r.Layers = all
	for _, l := range all {
		if !l.Present {
			continue
		}
		r.apply(l.Source, &l.Config)
	}
	flag := Config{}
	setStr := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	setStr(&flag.Profile, ov.Profile)
	setStr(&flag.Elevate, ov.Elevate)
	setStr(&flag.StateDir, ov.StateDir)
	setStr(&flag.Provider, ov.Provider)
	setStr(&flag.Model, ov.Model)
	setStr(&flag.BaseURL, ov.BaseURL)
	setStr(&flag.Effort, ov.Effort)
	if ov.MaxContext != nil {
		flag.MaxContext = *ov.MaxContext
	}
	r.apply(SourceFlag, &flag)
	if ov.LocalOnly != nil && *ov.LocalOnly {
		r.Config.AllowEgress = new(false)
		r.Origin["allow_egress"] = SourceFlag + " --local-only"
	}
	return r
}

// apply overlays one layer and records where each value came from.
func (r *Resolved) apply(source string, o *Config) {
	c := r.Config
	scalar := func(key string, dst *string, v string) {
		if v != "" {
			*dst = v
			r.Origin[key] = source
		}
	}
	scalar("provider", &c.Provider, o.Provider)
	scalar("model", &c.Model, o.Model)
	scalar("base_url", &c.BaseURL, o.BaseURL)
	scalar("effort", &c.Effort, o.Effort)
	scalar("profile", &c.Profile, o.Profile)
	scalar("elevate", &c.Elevate, o.Elevate)
	scalar("state_dir", &c.StateDir, o.StateDir)
	if o.MaxContext != 0 {
		c.MaxContext = o.MaxContext
		r.Origin["max_context"] = source
	}
	if o.AllowEgress != nil {
		c.AllowEgress = o.AllowEgress
		r.Origin["allow_egress"] = source
	}
	list := func(key string, dst *[]string, v []string) {
		if len(v) == 0 {
			return
		}
		*dst = union(*dst, v)
		if r.Entries[key] == nil {
			r.Entries[key] = map[string]string{}
		}
		for _, e := range v {
			r.Entries[key][e] = joinSources(r.Entries[key][e], source)
		}
	}
	list("disable_checks", &c.DisableChecks, o.DisableChecks)
	list("deny_paths", &c.DenyPaths, o.DenyPaths)
	list("redact_extra", &c.RedactExtra, o.RedactExtra)
	if len(o.Targets) > 0 {
		if c.Targets == nil {
			c.Targets = map[string]SSHTarget{}
		}
		if r.Entries["targets"] == nil {
			r.Entries["targets"] = map[string]string{}
		}
		for name, t := range o.Targets {
			c.Targets[name] = t
			r.Entries["targets"][name] = source
		}
	}
	if !o.Context.IsZero() {
		c.Context = o.Context
		c.ContextSource = source
		r.Origin["context"] = source
	}
	if source != SourceDefault && source != SourceFlag {
		c.Sources = append(c.Sources, source)
	}
}

func joinSources(have, source string) string {
	if have == "" {
		return source
	}
	if slices.Contains(strings.Split(have, ", "), source) {
		return have
	}
	return have + ", " + source
}

// ScalarKeys lists the scalar settings in display order.
var ScalarKeys = []string{"provider", "model", "base_url", "effort", "max_context", "allow_egress", "profile", "elevate", "state_dir"}

// ListKeys lists the accumulating settings in display order.
var ListKeys = []string{"disable_checks", "deny_paths", "redact_extra"}

// Value renders a scalar setting for display. Credentials never appear in a
// config file, and a base URL that carries user info is stripped of it.
func (r *Resolved) Value(key string) string {
	c := r.Config
	switch key {
	case "provider":
		return c.Provider
	case "model":
		return c.Model
	case "base_url":
		return StripUserInfo(c.BaseURL)
	case "effort":
		return c.Effort
	case "max_context":
		if c.MaxContext == 0 {
			return ""
		}
		return fmt.Sprint(c.MaxContext)
	case "allow_egress":
		if c.AllowEgress == nil {
			return ""
		}
		return fmt.Sprint(*c.AllowEgress)
	case "profile":
		return c.Profile
	case "elevate":
		return c.Elevate
	case "state_dir":
		return c.StateDir
	}
	return ""
}

// List returns a list setting's entries with their sources, sorted.
func (r *Resolved) List(key string) [][2]string {
	var out [][2]string
	for e, src := range r.Entries[key] {
		out = append(out, [2]string{e, src})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// StripUserInfo removes user:password@ from a URL for display.
func StripUserInfo(u string) string {
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	host, tail, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
		u = scheme + "://" + host
		if tail != "" || strings.HasSuffix(rest, "/") {
			u += "/" + tail
		}
		return u + " (credentials stripped)"
	}
	return u
}
