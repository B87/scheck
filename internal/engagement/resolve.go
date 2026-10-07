package engagement

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Source identifies the file a run read, by path and content hash.
type Source struct {
	Path   string `json:"path" yaml:"path"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}

// EffectiveDefaults are the defaults with every unset value filled in.
type EffectiveDefaults struct {
	Probe    string   `json:"probe" yaml:"probe"`
	Scan     string   `json:"scan" yaml:"scan"`
	Throttle Throttle `json:"throttle" yaml:"throttle"`
	Profile  string   `json:"profile" yaml:"profile"`
}

// EffectiveLimits are the limits with every unset value filled in.
type EffectiveLimits struct {
	// Timeout is a duration, or none.
	Timeout string `json:"timeout" yaml:"timeout"`
}

// ResolvedAsset is one asset the run starts from: every root, and every
// assets entry under one, with its settings and the defaults applied.
type ResolvedAsset struct {
	// Name is the assets name, or the canonical id when no entry names it.
	Name string `json:"name" yaml:"name"`
	Ref  `yaml:",inline"`
	// Root is the id of the root the asset equals or falls under.
	Root string `json:"root" yaml:"root"`

	Probe    string   `json:"probe" yaml:"probe"`
	Scan     string   `json:"scan" yaml:"scan"`
	Throttle Throttle `json:"throttle" yaml:"throttle"`

	Jump       string `json:"jump,omitempty" yaml:"jump,omitempty"`
	Identity   string `json:"identity,omitempty" yaml:"identity,omitempty"`
	KnownHosts string `json:"known_hosts,omitempty" yaml:"known_hosts,omitempty"`
	// Timeout is the host collector's run timeout, or empty for its
	// default (docs/spec/host-collector.md §4.4).
	Timeout       string       `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Elevate       string       `json:"elevate,omitempty" yaml:"elevate,omitempty"`
	Profile       string       `json:"profile,omitempty" yaml:"profile,omitempty"`
	DisableChecks []string     `json:"disable_checks,omitempty" yaml:"disable_checks,omitempty"`
	DenyPaths     []string     `json:"deny_paths,omitempty" yaml:"deny_paths,omitempty"`
	Context       *HostContext `json:"context,omitempty" yaml:"context,omitempty"`

	FirstParty *FirstParty `json:"first_party,omitempty" yaml:"first_party,omitempty"`
	DeploysTo  string      `json:"deploys_to,omitempty" yaml:"deploys_to,omitempty"`
	CI         string      `json:"ci,omitempty" yaml:"ci,omitempty"`
}

// Resolved is a validated engagement file with every locator canonical and
// every default applied: what `scheck run --stop-after intake` prints, and
// what the Scope stage starts from. The declarations the later stages read
// (people, access, intent and the rest) are carried as written; references
// in them resolve with Lookup.
type Resolved struct {
	Source     Source            `json:"source" yaml:"source"`
	Schema     int               `json:"schema" yaml:"schema"`
	Engagement Engagement        `json:"engagement" yaml:"engagement"`
	Roots      []Ref             `json:"roots" yaml:"roots"`
	Exclude    []Ref             `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Defaults   EffectiveDefaults `json:"defaults" yaml:"defaults"`
	Limits     EffectiveLimits   `json:"limits" yaml:"limits"`
	// RedactPatterns counts redact_extra. A pattern is never printed: it is
	// often the very string it hides (docs/spec/engagement.md, "Narrowing
	// travels with the engagement").
	RedactPatterns int             `json:"redact_extra_patterns" yaml:"redact_extra_patterns"`
	Assets         []ResolvedAsset `json:"assets" yaml:"assets"`

	People        map[string]Person `json:"people,omitempty" yaml:"people,omitempty"`
	Access        Access            `json:"access,omitzero" yaml:"access,omitempty"`
	Tools         []Tool            `json:"tools,omitempty" yaml:"tools,omitempty"`
	NotUsed       []string          `json:"not_used,omitempty" yaml:"not_used,omitempty"`
	Mail          Mail              `json:"mail,omitzero" yaml:"mail,omitempty"`
	Secrets       Secrets           `json:"secrets,omitzero" yaml:"secrets,omitempty"`
	Data          Data              `json:"data,omitzero" yaml:"data,omitempty"`
	Intent        Intent            `json:"intent,omitzero" yaml:"intent,omitempty"`
	Authorization *Authorization    `json:"authorization,omitempty" yaml:"authorization,omitempty"`

	// Warnings are for the operator, on stderr: a file that validates but
	// would reveal something it means to hide. They never quote a pattern
	// or the string it matched.
	Warnings []string `json:"-" yaml:"-"`

	redactExtra []string
	timeout     time.Duration
	refs        map[string]Ref
}

// RedactExtra returns the operator's redaction patterns, for the runner's
// redactor and the scope gate. Never print them.
func (r *Resolved) RedactExtra() []string { return slices.Clone(r.redactExtra) }

// Timeout is limits.timeout; 0 means none.
func (r *Resolved) Timeout() time.Duration { return r.timeout }

// Lookup resolves a reference as the file writes one: an assets name or a
// root's value exactly as written under roots.
func (r *Resolved) Lookup(ref string) (Ref, bool) {
	ref2, ok := r.refs[ref]
	return ref2, ok
}

// AssetID is the canonical id an accepted risk's asset names: through
// Lookup, or as a canonical id under a root and no exclude.
func (r *Resolved) AssetID(ref string) (string, bool) {
	if found, ok := r.Lookup(ref); ok {
		return found.ID, true
	}
	id, ok := ParseID(ref)
	if !ok || !slices.ContainsFunc(r.Roots, func(root Ref) bool { return Under(id, root) }) ||
		slices.ContainsFunc(r.Exclude, func(x Ref) bool { return x.OrgUnit == "" && Under(id, x) }) {
		return "", false
	}
	return id.ID, true
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func throttleOr(t *Throttle, def Throttle) Throttle {
	if t == nil {
		return def
	}
	return Throttle{Rate: or(t.Rate, def.Rate), Concurrency: or(t.Concurrency, def.Concurrency)}
}

// resolve builds the resolved view of a file that passed validation.
func (v *validator) resolve(assets map[string]Ref) *Resolved {
	f := v.f
	d := EffectiveDefaults{
		Probe:    or(f.Defaults.Probe, "off"),
		Scan:     or(f.Defaults.Scan, "off"),
		Throttle: throttleOr(f.Defaults.Throttle, Throttle{Rate: DefaultRate, Concurrency: DefaultConcurrency}),
		Profile:  or(f.Defaults.Profile, DefaultProfile),
	}
	res := &Resolved{
		Schema:         f.Schema,
		Engagement:     f.Engagement,
		Roots:          v.roots,
		Exclude:        v.excludes,
		Defaults:       d,
		Limits:         EffectiveLimits{Timeout: "none"},
		RedactPatterns: len(f.RedactExtra),
		People:         f.People,
		Access:         f.Access,
		Tools:          f.Tools,
		NotUsed:        f.NotUsed,
		Mail:           f.Mail,
		Secrets:        f.Secrets,
		Data:           f.Data,
		Intent:         f.Intent,
		Authorization:  f.Authorization,
		redactExtra:    slices.Clone(f.RedactExtra),
		refs:           maps.Clone(v.refs),
	}
	maps.Copy(res.refs, assets)
	switch t := f.Limits.Timeout; t {
	case "none":
	case "":
		res.timeout = DefaultTimeout
	default:
		res.timeout, _ = time.ParseDuration(t) // validated
	}
	if res.timeout > 0 {
		res.Limits.Timeout = res.timeout.String()
	}

	// Every root is an asset; an assets entry with the same id names it and
	// sets its settings. Entries under a root follow, by name.
	named := map[string]string{}
	for name, r := range assets {
		named[r.ID] = name
	}
	for _, root := range v.roots {
		name, ok := named[root.ID]
		if !ok {
			res.Assets = append(res.Assets, v.asset(root.ID, root, root, Asset{}, d))
			continue
		}
		res.Assets = append(res.Assets, v.asset(name, assets[name], root, f.Assets[name], d))
	}
	var under []ResolvedAsset
	for name, r := range assets {
		if slices.ContainsFunc(v.roots, func(root Ref) bool { return root.ID == r.ID }) {
			continue
		}
		under = append(under, v.asset(name, r, *v.rootOf(r), f.Assets[name], d))
	}
	slices.SortFunc(under, func(a, b ResolvedAsset) int { return cmp.Compare(a.Name, b.Name) })
	res.Assets = append(res.Assets, under...)
	res.Warnings = redactExtraNames(f, res)
	return res
}

// redactExtraNames warns when a root or an asset's name or locator matches
// a redact_extra pattern: redaction applies to what collectors read, and
// stage documents and the report carry names and locators as written, so
// the string would appear in them unredacted (docs/spec/engagement.md,
// "Narrowing travels with the engagement"). Neither the pattern nor the
// matching value is quoted; positions name them.
func redactExtraNames(f *File, res *Resolved) []string {
	var out []string
	for i, pat := range f.RedactExtra {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // validated
		}
		var where []string
		for j, root := range res.Roots {
			if re.MatchString(root.Written) || re.MatchString(root.ID) {
				where = append(where, fmt.Sprintf("roots[%d]", j))
			}
		}
		n := 0
		for name, a := range f.Assets {
			l := a.Locator
			if re.MatchString(name) || re.MatchString(l.Domain+l.Host+l.URL+l.Network+l.Cloud+l.SaaS+l.Repo) {
				n++
			}
		}
		if n > 0 {
			where = append(where, fmt.Sprintf("%d assets %s", n, map[bool]string{true: "entry", false: "entries"}[n == 1]))
		}
		if len(where) > 0 {
			out = append(out, fmt.Sprintf("%s match redact_extra[%d]: names and locators are written into the stage documents "+
				"and the report as declared, unredacted; rename the asset or narrow the pattern", strings.Join(where, " and "), i))
		}
	}
	return out
}

// asset applies the defaults to one asset. A host's SSH user comes from its
// assets entry, else from its root.
func (v *validator) asset(name string, r, root Ref, a Asset, d EffectiveDefaults) ResolvedAsset {
	if r.Kind == KindHost && r.User == "" && root.ID == r.ID {
		r.User = root.User
	}
	out := ResolvedAsset{
		Name:       name,
		Ref:        r,
		Root:       root.ID,
		Probe:      or(a.Probe, d.Probe),
		Scan:       or(a.Scan, d.Scan),
		Throttle:   throttleOr(a.Throttle, d.Throttle),
		FirstParty: a.FirstParty,
		DeploysTo:  a.DeploysTo,
		CI:         a.CI,
	}
	if r.Kind == KindHost {
		out.Jump = a.Jump
		out.Identity = a.Identity
		out.KnownHosts = a.KnownHosts
		out.Timeout = a.Timeout
		out.Elevate = or(a.Elevate, "none")
		out.Profile = or(a.Profile, d.Profile)
		out.DisableChecks = a.DisableChecks
		out.DenyPaths = a.DenyPaths
		out.Context = a.Context
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
