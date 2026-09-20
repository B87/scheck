// Package operator ingests operator-supplied context (docs/SPEC.md §6): the
// structured block that code consumes deterministically and the prose the
// model reads. Nothing here reaches a model, and nothing here executes: a
// `target:` source is read by the caller through runner.Run like any other
// file, and handed in as text.
//
// Context is untrusted data (§6.4). The worst a hostile source can do is
// distort classification; it cannot widen the command surface, and the only
// way it can move a severity is through the attributed adjustment table.
package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Exposure and environment vocabularies (docs/SPEC.md §6.2).
var (
	Exposures    = []string{"internet", "vpn", "lan", "airgapped"}
	Environments = []string{"prod", "staging", "dev"}
)

// Structured is the §6.2 schema. Every field is optional; unknown fields are
// preserved in Extra and passed through as prose.
type Structured struct {
	Role               string         `yaml:"role,omitempty" json:"role,omitempty"`
	Exposure           string         `yaml:"exposure,omitempty" json:"exposure,omitempty"`
	Environment        string         `yaml:"environment,omitempty" json:"environment,omitempty"`
	DataClassification string         `yaml:"data_classification,omitempty" json:"data_classification,omitempty"`
	Compliance         []string       `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	ExpectedServices   []Service      `yaml:"expected_services,omitempty" json:"expected_services,omitempty"`
	AcceptedRisks      []Risk         `yaml:"accepted_risks,omitempty" json:"accepted_risks,omitempty"`
	Owner              string         `yaml:"owner,omitempty" json:"owner,omitempty"`
	Extra              map[string]any `yaml:",inline" json:"extra,omitempty"`
}

// IsZero reports whether nothing structured was supplied.
func (s Structured) IsZero() bool {
	return s.Role == "" && s.Exposure == "" && s.Environment == "" && s.DataClassification == "" &&
		len(s.Compliance) == 0 && len(s.ExpectedServices) == 0 && len(s.AcceptedRisks) == 0 &&
		s.Owner == "" && len(s.Extra) == 0
}

// Service is one expected listener. Source names the context source that
// declared it, for attribution (§6.4) and for `scheck config show`.
type Service struct {
	Port     int    `yaml:"port" json:"port"`
	Proto    string `yaml:"proto,omitempty" json:"proto"`
	Purpose  string `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	Source   string `yaml:"-" json:"source,omitempty"`
}

// Key is the natural key lists are deduplicated by (§6.1).
func (s Service) Key() string { return fmt.Sprintf("%d/%s", s.Port, s.Proto) }

// Risk is one accepted finding id (§6.2, §6.3).
type Risk struct {
	ID      string `yaml:"id" json:"id"`
	Reason  string `yaml:"reason,omitempty" json:"reason,omitempty"`
	Expires string `yaml:"expires,omitempty" json:"expires,omitempty"` // YYYY-MM-DD
	Source  string `yaml:"-" json:"source,omitempty"`
}

// Expired reports whether the acceptance lapsed before now. An unset date
// never expires.
func (r Risk) Expired(now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", r.Expires)
	if err != nil {
		return false // validated at load; unreachable through Load
	}
	return now.After(t.Add(24 * time.Hour))
}

// Source records one context input in the report header (§7.4).
type Source struct {
	Name      string `json:"source"`
	Kind      string `json:"kind"` // config | implicit | file | note | target
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	// Unresolved marks a target: source that was declared but not read (a
	// local inspection that never contacts the target).
	Unresolved bool `json:"unresolved,omitempty"`
}

// Prose is one verbatim piece of operator text under its source heading.
type Prose struct {
	Source    string `json:"source"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}

// Merged is the outcome of Load: what code consumes, what the model reads,
// and where every part came from.
type Merged struct {
	Structured Structured `json:"structured"`
	// Origins maps a structured scalar or list key to the source that set
	// it last (per-key override, §6.1). List entries carry their own Source.
	Origins  map[string]string `json:"origins"`
	Prose    []Prose           `json:"prose"`
	Sources  []Source          `json:"sources"`
	Budget   int               `json:"budget"`
	Used     int               `json:"used"`
	Warnings []string          `json:"warnings"`
}

// IsEmpty reports whether no source contributed anything.
func (m *Merged) IsEmpty() bool {
	return m == nil || (m.Structured.IsZero() && len(m.Prose) == 0)
}

// Options drive Load.
type Options struct {
	// ConfigContext is scheck.yaml's `context:` block, or a zero node.
	ConfigContext yaml.Node
	ConfigSource  string
	// ImplicitDir is read recursively when it exists (default
	// ./.scheck/context). "" disables the implicit source.
	ImplicitDir string
	// Flags are the --context values, left to right.
	Flags []string
	// Budget is policy.Budgets.ContextBytes.
	Budget int
	// ReadTarget resolves a target: source. nil leaves such sources
	// unresolved (a local-only inspection), which is reported, never
	// silently treated as read.
	ReadTarget func(path string) (string, error)
	// KnownFinding reports whether an accepted_risks id is a catalog finding
	// id; a custom: prefix is always accepted (§6.2).
	KnownFinding func(id string) bool
}

// DefaultTargetPath is what a bare `target:` reads (§6.1).
const DefaultTargetPath = "/etc/scheck/context.md"

// DefaultImplicitDir is the implicit per-project source (§6.1).
const DefaultImplicitDir = ".scheck/context"

// Load reads every source in its defined order — config block, implicit
// directory, then --context flags left to right — validates the structured
// schema, merges per kind and applies the byte budget. A validation failure
// is a usage error for the caller to exit 3 on.
func Load(o Options) (*Merged, error) {
	m := &Merged{Origins: map[string]string{}, Budget: o.Budget, Warnings: []string{}, Prose: []Prose{}, Sources: []Source{}}
	var pieces []piece
	if !o.ConfigContext.IsZero() {
		name := o.ConfigSource
		if name == "" {
			name = "scheck.yaml"
		}
		raw, err := yaml.Marshal(&o.ConfigContext)
		if err != nil {
			return nil, fmt.Errorf("context: %s: %w", name, err)
		}
		pieces = append(pieces, piece{name: name + "#context", kind: "config", raw: raw, structuredNode: &o.ConfigContext})
	}
	if o.ImplicitDir != "" {
		ps, err := readDir(o.ImplicitDir, "implicit")
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, ps...)
	}
	for _, f := range o.Flags {
		ps, err := readFlag(f, o.ReadTarget)
		if err != nil {
			return nil, err
		}
		pieces = append(pieces, ps...)
	}
	for _, p := range pieces {
		if err := m.absorb(p, o); err != nil {
			return nil, err
		}
	}
	m.applyBudget()
	return m, nil
}

// piece is one raw source before merge.
type piece struct {
	name           string
	kind           string
	raw            []byte
	structuredNode *yaml.Node // set when the piece is (or contains) a context: block
	unresolved     bool
}

var proseExts = map[string]bool{".md": true, ".txt": true, ".yaml": true, ".yml": true}

func readDir(dir, kind string) ([]piece, error) {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("context: %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("context: %s is not a directory", dir)
	}
	var paths []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !proseExts[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("context: %s: %w", dir, err)
	}
	// Deterministic: lexical order of the relative path, whatever the
	// filesystem returned.
	sort.Strings(paths)
	var out []piece
	for _, p := range paths {
		pc, err := readFile(p, kind)
		if err != nil {
			return nil, err
		}
		out = append(out, pc)
	}
	return out, nil
}

func readFile(path, kind string) (piece, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return piece{}, fmt.Errorf("context: %w", err)
	}
	if !utf8.Valid(raw) {
		return piece{}, fmt.Errorf("context: %s is not UTF-8 text", path)
	}
	pc := piece{name: filepath.ToSlash(path), kind: kind, raw: raw}
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		if node := contextNode(raw); node != nil {
			pc.structuredNode = node
		}
	}
	return pc, nil
}

// contextNode returns the `context:` mapping of a YAML document, or nil when
// the document is not a mapping with that key.
func contextNode(raw []byte) *yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "context" && root.Content[i+1].Kind == yaml.MappingNode {
			return root.Content[i+1]
		}
	}
	return nil
}

func readFlag(arg string, readTarget func(string) (string, error)) ([]piece, error) {
	switch {
	case strings.HasPrefix(arg, "note:"):
		text := strings.TrimPrefix(arg, "note:")
		if strings.TrimSpace(text) == "" {
			return nil, errors.New("context: note: is empty")
		}
		return []piece{{name: "note:" + shortNote(text), kind: "note", raw: []byte(text)}}, nil
	case arg == "target" || strings.HasPrefix(arg, "target:"):
		path := strings.TrimPrefix(strings.TrimPrefix(arg, "target"), ":")
		if path == "" {
			path = DefaultTargetPath
		}
		name := "target:" + path
		if readTarget == nil {
			return []piece{{name: name, kind: "target", unresolved: true}}, nil
		}
		text, err := readTarget(path)
		if err != nil {
			return nil, fmt.Errorf("context: %s: %w", name, err)
		}
		// On-target context is prose only, whatever its extension: a host
		// must not be able to accept its own risks or declare its own
		// exposure (docs/SPEC.md §6.4).
		return []piece{{name: name, kind: "target", raw: []byte(text)}}, nil
	}
	info, err := os.Stat(arg)
	if err != nil {
		return nil, fmt.Errorf("context: %w", err)
	}
	if info.IsDir() {
		return readDir(arg, "file")
	}
	pc, err := readFile(arg, "file")
	if err != nil {
		return nil, err
	}
	return []piece{pc}, nil
}

func shortNote(text string) string {
	words := strings.Fields(text)
	if len(words) > 4 {
		words = words[:4]
	}
	s := strings.Join(words, " ")
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.TrimSpace(s) + "…"
}

// absorb validates and merges one piece: the structured block per key, and
// everything else as verbatim prose under the source's heading.
func (m *Merged) absorb(p piece, o Options) error {
	src := Source{Name: p.name, Kind: p.kind, Bytes: len(p.raw), Unresolved: p.unresolved}
	if !p.unresolved {
		sum := sha256.Sum256(p.raw)
		src.SHA256 = hex.EncodeToString(sum[:])
	}
	m.Sources = append(m.Sources, src)
	if p.unresolved {
		m.Warnings = append(m.Warnings, p.name+": declared but not read (target context is resolved only during a run)")
		return nil
	}
	if p.structuredNode != nil {
		var s Structured
		if err := p.structuredNode.Decode(&s); err != nil {
			return fmt.Errorf("context: %s: %w", p.name, err)
		}
		if err := validate(&s, o.KnownFinding); err != nil {
			return fmt.Errorf("context: %s: %w", p.name, err)
		}
		m.merge(s, p.name)
		// A YAML file may carry more than its context: block; the rest is
		// prose, so nothing an operator wrote is silently dropped.
		if p.kind != "config" {
			if rest := withoutContext(p.raw); rest != "" {
				m.Prose = append(m.Prose, Prose{Source: p.name, Text: rest})
			}
		}
		return nil
	}
	m.Prose = append(m.Prose, Prose{Source: p.name, Text: string(p.raw)})
	return nil
}

// withoutContext renders a YAML document minus its context: key.
func withoutContext(raw []byte) string {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return ""
	}
	delete(doc, "context")
	if len(doc) == 0 {
		return ""
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return ""
	}
	return string(out)
}

func validate(s *Structured, known func(string) bool) error {
	if s.Exposure != "" && !oneOf(s.Exposure, Exposures) {
		return fmt.Errorf("exposure %q is not one of %s", s.Exposure, strings.Join(Exposures, "|"))
	}
	if s.Environment != "" && !oneOf(s.Environment, Environments) {
		return fmt.Errorf("environment %q is not one of %s", s.Environment, strings.Join(Environments, "|"))
	}
	for i := range s.ExpectedServices {
		svc := &s.ExpectedServices[i]
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("expected_services[%d]: port %d is out of range", i, svc.Port)
		}
		svc.Proto = strings.ToLower(svc.Proto)
		if svc.Proto == "" {
			svc.Proto = "tcp"
		}
		if svc.Proto != "tcp" && svc.Proto != "udp" {
			return fmt.Errorf("expected_services[%d]: proto %q is not tcp|udp", i, svc.Proto)
		}
	}
	for i, r := range s.AcceptedRisks {
		if r.ID == "" {
			return fmt.Errorf("accepted_risks[%d]: id is required", i)
		}
		if !strings.HasPrefix(r.ID, "custom:") && (known == nil || !known(r.ID)) {
			return fmt.Errorf("accepted_risks[%d]: %q is neither a catalog finding id nor a custom: id", i, r.ID)
		}
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return fmt.Errorf("accepted_risks[%d] %s: expires %q is not YYYY-MM-DD", i, r.ID, r.Expires)
			}
		}
	}
	return nil
}

func oneOf(v string, set []string) bool { return slices.Contains(set, v) }

// merge applies per-kind semantics (§6.1): scalars override per key, lists
// concatenate and deduplicate by natural key with the later entry winning.
func (m *Merged) merge(s Structured, source string) {
	set := func(key string, dst *string, v string) {
		if v != "" {
			*dst = v
			m.Origins[key] = source
		}
	}
	set("role", &m.Structured.Role, s.Role)
	set("exposure", &m.Structured.Exposure, s.Exposure)
	set("environment", &m.Structured.Environment, s.Environment)
	set("data_classification", &m.Structured.DataClassification, s.DataClassification)
	set("owner", &m.Structured.Owner, s.Owner)
	if len(s.Compliance) > 0 {
		for _, c := range s.Compliance {
			if !oneOf(c, m.Structured.Compliance) {
				m.Structured.Compliance = append(m.Structured.Compliance, c)
			}
		}
		m.Origins["compliance"] = appendOrigin(m.Origins["compliance"], source)
	}
	for _, svc := range s.ExpectedServices {
		svc.Source = source
		replaced := false
		for i, have := range m.Structured.ExpectedServices {
			if have.Key() == svc.Key() {
				m.Structured.ExpectedServices[i] = svc
				replaced = true
			}
		}
		if !replaced {
			m.Structured.ExpectedServices = append(m.Structured.ExpectedServices, svc)
		}
		m.Origins["expected_services"] = appendOrigin(m.Origins["expected_services"], source)
	}
	for _, r := range s.AcceptedRisks {
		r.Source = source
		replaced := false
		for i, have := range m.Structured.AcceptedRisks {
			if have.ID == r.ID {
				m.Structured.AcceptedRisks[i] = r
				replaced = true
			}
		}
		if !replaced {
			m.Structured.AcceptedRisks = append(m.Structured.AcceptedRisks, r)
		}
		m.Origins["accepted_risks"] = appendOrigin(m.Origins["accepted_risks"], source)
	}
	if len(s.Extra) > 0 {
		if m.Structured.Extra == nil {
			m.Structured.Extra = map[string]any{}
		}
		for k, v := range s.Extra {
			m.Structured.Extra[k] = v
			m.Origins["extra."+k] = source
		}
	}
}

func appendOrigin(have, source string) string {
	if have == "" {
		return source
	}
	if slices.Contains(strings.Split(have, ", "), source) {
		return have
	}
	return have + ", " + source
}

// applyBudget enforces Budgets.ContextBytes over the rendered context: the
// structured block first (it is what code consumes), then prose in source
// order. A piece that crosses the budget is cut with a marker; later pieces
// are dropped with their source marked truncated. Nothing is removed
// silently (§6.1).
func (m *Merged) applyBudget() {
	used := len(m.StructuredText())
	if m.Budget <= 0 {
		m.Used = used
		for _, p := range m.Prose {
			m.Used += len(p.Text)
		}
		return
	}
	for i := range m.Prose {
		p := &m.Prose[i]
		if used+len(p.Text) <= m.Budget {
			used += len(p.Text)
			continue
		}
		keep := max(m.Budget-used, 0)
		for keep > 0 && !utf8.RuneStart(p.Text[keep]) {
			keep--
		}
		dropped := len(p.Text) - keep
		p.Text = p.Text[:keep] + fmt.Sprintf("\n[TRUNCATED:%d bytes]", dropped)
		p.Truncated = true
		used = m.Budget
		m.markTruncated(p.Source)
		m.Warnings = append(m.Warnings, fmt.Sprintf("context: %s truncated by %d bytes (budget %d bytes)", p.Source, dropped, m.Budget))
	}
	m.Used = used
}

func (m *Merged) markTruncated(source string) {
	for i := range m.Sources {
		if m.Sources[i].Name == source {
			m.Sources[i].Truncated = true
		}
	}
}

// StructuredText renders the merged structured block as YAML, which is both
// what `--stop-after context` prints and what the model sees (§6.3).
func (m *Merged) StructuredText() string {
	if m == nil || m.Structured.IsZero() {
		return ""
	}
	out, err := yaml.Marshal(m.Structured)
	if err != nil {
		return ""
	}
	return string(out)
}
