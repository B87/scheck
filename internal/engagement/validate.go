package engagement

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

// Vocabularies of the engagement file (docs/spec/engagement.md).
var (
	Triggers    = []string{"questionnaire", "audit", "funding", "incident", "routine"}
	PersonKinds = []string{"employee", "contractor", "shared", "service", "break_glass"}
	// MFAEnforcements is who must use a second factor, as the operator
	// believes it (docs/spec/engagement.md, "People").
	MFAEnforcements = []string{"everyone", "admins", "some", "none", "unknown"}
	Audiences       = []string{"internet", "vpn", "lan", "localhost", "airgapped"}
	Exposures       = []string{"internet", "vpn", "lan", "airgapped"}
	Environments    = []string{"prod", "staging", "dev"}
	Protos          = []string{"tcp", "udp"}
	Areas           = areaKeys() // finding.Areas: one list for not_used and the report
	Profiles        = []string{"baseline", "hardened"}
	Elevations      = []string{"none", "sudo"}
	DeployTargets   = []string{"production", "staging", "development"}
	// Modes are the probe and scan modes; this build runs only off.
	Modes = []string{"off", "confirm", "auto", "all"}
)

func areaKeys() []string {
	out := make([]string, len(finding.Areas))
	for i, a := range finding.Areas {
		out[i] = string(a)
	}
	return out
}

// Defaults a file does not set, as `scheck init` writes them.
const (
	DefaultRate        = "5/s"
	DefaultConcurrency = 2
	DefaultTimeout     = time.Hour
	DefaultProfile     = "baseline"
)

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	rateRe  = regexp.MustCompile(`^([1-9][0-9]{0,5})/(s|m)$`)
	loginRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)$`)
	// A DKIM selector: RFC 6376's sub-domain syntax, at most 63 characters
	// a label, no underscore (docs/spec/scope.md, "The resolver").
	dkimRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

// Options carry the catalogs the file is checked against, so this package
// needs neither the host catalog nor the finding catalog compiled in.
type Options struct {
	// KnownCheck reports whether id is a host catalog check id.
	KnownCheck func(id string) bool
	// KnownFinding reports whether id is a catalog finding id.
	KnownFinding func(id string) bool
	// FindingSubject returns the subject kind a catalog finding id declares,
	// or "" when its findings are about the asset as a whole.
	FindingSubject func(id string) string
	// HostFinding reports whether a catalog finding id is the host
	// collector's, whose acceptances by subject are listed as not applied
	// rather than refused (docs/spec/engagement.md, "Accepted risks").
	HostFinding func(id string) bool
}

// Load reads and validates the engagement file at name. It contacts nothing.
func Load(name string, opts Options) (*Resolved, error) {
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return Parse(name, raw, opts)
}

// Parse validates raw as the engagement file name and resolves it. Every
// failure is returned at once as Errors, in line order.
func Parse(name string, raw []byte, opts Options) (*Resolved, error) {
	if opts.KnownCheck == nil || opts.KnownFinding == nil || opts.FindingSubject == nil || opts.HostFinding == nil {
		return nil, errors.New("engagement: Options.KnownCheck, Options.KnownFinding, Options.FindingSubject and Options.HostFinding are required")
	}
	p := &parser{file: name, lines: map[string]int{}}
	f := p.parse(raw)
	if f == nil {
		return nil, p.errs
	}
	v := &validator{parser: p, f: f, opts: opts, refs: map[string]Ref{}, assets: map[string]Ref{}}
	res := v.validate()
	if len(p.errs) > 0 {
		slices.SortStableFunc(p.errs, func(a, b Error) int { return a.Line - b.Line })
		return nil, p.errs
	}
	sum := sha256.Sum256(raw)
	res.Source = Source{Path: name, SHA256: hex.EncodeToString(sum[:])}
	return res, nil
}

// validator holds what the semantic checks share: the parsed roots, the
// asset names and what a reference may name.
type validator struct {
	*parser
	f        *File
	opts     Options
	loc      *time.Location
	roots    []Ref
	excludes []Ref
	// refs maps a root's value as written to its ref; assets maps an assets
	// name to its ref (docs/spec/engagement.md, "Identity, references and
	// validation").
	refs   map[string]Ref
	assets map[string]Ref
}

func (v *validator) validate() *Resolved {
	f := v.f
	if f.Schema != Schema {
		v.fail("schema", "must be %d", Schema)
	}
	v.engagement()
	v.scope()
	v.rootsAndExcludes()
	v.defaults()
	v.limits()
	v.redactExtra()
	v.people()
	assets := v.assetsSection()
	v.access()
	v.tools()
	v.mail()
	v.references()
	v.intent()
	v.authorization()
	return v.resolve(assets)
}

func (v *validator) enum(key, val string, allowed []string) bool {
	if slices.Contains(allowed, val) {
		return true
	}
	v.fail(key, "%q is not one of %s", val, strings.Join(allowed, " | "))
	return false
}

func (v *validator) required(key, val string) bool {
	if strings.TrimSpace(val) == "" {
		v.fail(key, "is required")
		return false
	}
	return true
}

// date parses a calendar date in the engagement's time zone. A date lasts
// until 24:00 that day (docs/spec/engagement.md, "Time").
func (v *validator) date(key, val string) {
	if val == "" {
		return
	}
	loc := v.loc
	if loc == nil {
		loc = time.UTC // the zone error is reported on its own key
	}
	if _, err := time.ParseInLocation("2006-01-02", val, loc); err != nil {
		v.fail(key, "%q is not a date written YYYY-MM-DD", val)
	}
}

// timestamp parses RFC 3339 with seconds and an explicit offset.
func (v *validator) timestamp(key, val string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		v.fail(key, "%q is not RFC 3339 with seconds and an offset, such as 2026-10-07T09:00:00+02:00", val)
		return time.Time{}, false
	}
	return t, true
}

func (v *validator) engagement() {
	e := v.f.Engagement
	if v.required("engagement.name", e.Name) && !nameRe.MatchString(e.Name) {
		v.fail("engagement.name", "%q must match ^[a-z0-9][a-z0-9-]{0,62}$: it names the run directory", e.Name)
	}
	if v.required("engagement.timezone", e.Timezone) {
		loc, err := time.LoadLocation(e.Timezone)
		if err != nil || e.Timezone == "Local" {
			v.fail("engagement.timezone", "%q is not an IANA time zone such as Europe/Madrid", e.Timezone)
		} else {
			v.loc = loc
		}
	}
	if v.required("engagement.trigger", e.Trigger) {
		v.enum("engagement.trigger", e.Trigger, Triggers)
	}
}

func (v *validator) scope() {
	switch v.f.Scope {
	case "":
	case "full":
		v.unavailable("scope", "full scope (docs/spec/scope.md, \"Full scope\")")
	default:
		v.fail("scope", "%q: the only value is full, and leaving it out keeps scope to the roots", v.f.Scope)
	}
}

// rootsAndExcludes parses every root and exclude. A name-based exclude must
// fall under a root; a network exclude only narrows and is always accepted;
// a cloud exclude needs an organization root (docs/spec/engagement.md,
// "Validation").
func (v *validator) rootsAndExcludes() {
	if len(v.f.Roots) == 0 {
		v.fail("roots", "at least one root is required: scope has one source, roots")
	}
	seen := map[string]string{}
	for i, l := range v.f.Roots {
		key := fmt.Sprintf("roots[%d]", i)
		if l.OrgUnit != "" {
			v.fail(key+".org_unit", "an organizational unit narrows an exclude, not a root")
		}
		r, ok := v.locator(key, l)
		if !ok {
			continue
		}
		if prev, dup := seen[r.ID]; dup {
			v.fail(key, "declares %s again (first at %s)", r.ID, prev)
			continue
		}
		// A reference names a root by its value as written, so two roots
		// written alike (domain: and host: example.com) could not be told
		// apart by one.
		if prev, clash := v.refs[r.Written]; clash {
			v.fail(key, "is written %q, as %s is: a reference could not tell them apart", r.Written, prev.ID)
			continue
		}
		seen[r.ID] = key
		v.roots = append(v.roots, r)
		v.refs[r.Written] = r
	}
	for i, l := range v.f.Exclude {
		key := fmt.Sprintf("exclude[%d]", i)
		r, ok := v.locator(key, l)
		if !ok {
			continue
		}
		v.excludes = append(v.excludes, r)
		if l.OrgUnit != "" {
			if r.Kind != KindSaaS || r.provider != ProviderGoogleWorkspace {
				v.fail(key+".org_unit", "only a google-workspace exclude takes an organizational unit")
			} else if !strings.HasPrefix(l.OrgUnit, "/") {
				v.fail(key+".org_unit", "%q: an organizational unit path starts with /", l.OrgUnit)
			}
		}
		switch {
		case r.Kind == KindNetwork, r.Kind == KindHost && r.addr.IsValid():
			// Narrowing only; an address's root is known once resolved.
		case r.Kind == KindCloud:
			if !slices.ContainsFunc(v.roots, func(root Ref) bool { return Under(r, root) }) {
				v.fail(key, "%s falls under no root: a cloud project exclude needs its project or an organization root", r.ID)
			}
		case r.Kind == KindURL:
			// A url exclude covers its site over both schemes and its path
			// with or without the slash (Excludes), so it narrows a root
			// when any of those forms falls under one.
			if !slices.ContainsFunc(urlForms(r), func(f Ref) bool { return v.rootOf(f) != nil }) {
				v.fail(key, "%s falls under no root, so it excludes nothing", r.ID)
			}
		default:
			// An exclude covering a root is refused below, by the root.
			if v.rootOf(r) == nil && !slices.ContainsFunc(v.roots, func(root Ref) bool { return Excludes(r, root) }) {
				v.fail(key, "%s falls under no root, so it excludes nothing", r.ID)
			}
		}
	}
	// Exclude always wins over roots (docs/spec/scope.md, "What is in
	// scope"), so a root an exclude covers would never be read: Recon
	// would otherwise collect it.
	for i, root := range v.roots {
		if j := slices.IndexFunc(v.excludes, func(x Ref) bool { return Excludes(x, root) }); j >= 0 {
			v.fail(fmt.Sprintf("roots[%d]", i), "%s is excluded by %s: exclude always wins, so this root would never be read", root.ID, v.excludes[j].ID)
		}
	}
}

// urlForms are the forms of a url exclude Excludes treats alike: either
// scheme, on its port as written or as read (http://x:443/ is read on
// https://x/'s port), and its path with and without a trailing slash.
func urlForms(x Ref) []Ref {
	var out []Ref
	for _, scheme := range []string{"https", "http"} {
		read := x.urlPort()
		if read == map[string]int{"https": 443, "http": 80}[scheme] {
			read = 0
		}
		for _, port := range slices.Compact([]int{x.Port, read}) {
			for _, p := range []string{x.path, strings.TrimSuffix(x.path, "/") + "/"} {
				f := x
				f.scheme, f.Port, f.path, f.ID = scheme, port, p, ""
				out = append(out, f)
			}
		}
	}
	return out
}

// locator parses one locator entry, failing on the kind key's line.
func (v *validator) locator(key string, l Locator) (Ref, bool) {
	kind, val, err := kindOf(l)
	if err != nil {
		v.fail(key, "%v", err)
		return Ref{}, false
	}
	r, err := parseLocator(kind, val)
	if err != nil {
		v.fail(key+"."+string(kind), "%v", err)
		return Ref{}, false
	}
	r.OrgUnit = l.OrgUnit
	return r, true
}

// rootOf returns the first root r equals or falls under.
func (v *validator) rootOf(r Ref) *Ref {
	for i := range v.roots {
		if Under(r, v.roots[i]) {
			return &v.roots[i]
		}
	}
	return nil
}

func (v *validator) mode(key, val string) {
	if val == "" || val == "off" {
		return
	}
	if slices.Contains(Modes, val) {
		v.unavailable(key, "mode %s (probes and scans arrive in 0.0.3; 0.0.2 only reads)", val)
		return
	}
	v.enum(key, val, Modes)
}

func (v *validator) throttle(key string, t *Throttle) {
	if t == nil {
		return
	}
	if t.Rate != "" && !rateRe.MatchString(t.Rate) {
		v.fail(key+".rate", "%q is not a rate such as 5/s or 120/m", t.Rate)
	}
	if _, set := v.lines[key+".concurrency"]; set && t.Concurrency < 1 {
		v.fail(key+".concurrency", "must be 1 or more")
	}
}

func (v *validator) profile(key, val string) {
	if val != "" {
		v.enum(key, val, Profiles)
	}
}

func (v *validator) defaults() {
	d := v.f.Defaults
	v.mode("defaults.probe", d.Probe)
	v.mode("defaults.scan", d.Scan)
	v.throttle("defaults.throttle", d.Throttle)
	v.profile("defaults.profile", d.Profile)
}

// limits: `none` is the only way to turn a limit off, and 0 is rejected
// (docs/spec/scope.md, "Throttle, timeout and cost").
func (v *validator) limits() {
	if t := v.f.Limits.Timeout; t != "" && t != "none" {
		d, err := time.ParseDuration(t)
		switch {
		case err != nil:
			v.fail("limits.timeout", "%q is not a duration such as 45m or 2h; none turns the timeout off", t)
		case d == 0:
			v.fail("limits.timeout", "0 is not \"no limit\": write none to turn the timeout off")
		case d < 0:
			v.fail("limits.timeout", "must be positive")
		}
	}
	if _, set := v.lines["limits.max_cost"]; set {
		v.unavailable("limits.max_cost", "a model cost limit (no model runs before 0.0.4)")
	}
}

// redactExtra compiles each pattern as RE2. The message never quotes the
// pattern, which is often the very string it hides.
func (v *validator) redactExtra() {
	for i, pat := range v.f.RedactExtra {
		key := fmt.Sprintf("redact_extra[%d]", i)
		if pat == "" {
			v.fail(key, "an empty pattern hides nothing")
			continue
		}
		if _, err := regexp.Compile(pat); err != nil {
			reason := "invalid"
			if se, ok := errors.AsType[*syntax.Error](err); ok {
				reason = string(se.Code)
			}
			v.fail(key, "is not a valid RE2 pattern (%s)", reason)
		}
	}
}

func (v *validator) people() {
	byIdent := map[string]string{} // "github:alice" -> the key that declared it
	for _, handle := range sortedKeys(v.f.People) {
		p := v.f.People[handle]
		key := "people." + handle
		if !nameRe.MatchString(handle) {
			v.fail(key, "handle %q must match ^[a-z0-9][a-z0-9-]{0,62}$", handle)
		}
		v.personKind(key, p.Kind)
		for _, id := range []struct {
			field string
			vals  []string
			ok    func(string) bool
			what  string
		}{
			{"workspace", p.Workspace, isAddress, "an address; write it as name@example.com"},
			{"github", p.GitHub, loginRe.MatchString, "a GitHub login (letters, digits and single hyphens, up to 39)"},
		} {
			v.identifiers(key, handle, id.field, id.vals, id.ok, id.what, byIdent)
		}
		switch {
		case strings.Contains(p.Org, "[REDACTED") || strings.Contains(p.Org, "[TRUNCATED"):
			v.fail(key+".org", "is a marker scheck printed in place of a hidden value, not a value; write it out")
		case p.Org != "" && p.Kind != "contractor" && p.Kind != "shared":
			v.fail(key+".org", "names a contractor's company, or the company behind a shared account; %s is %s", handle, kindWords(p.Kind))
		}
		v.usedBy(key, handle, p)
		v.date(key+".left", p.Left)
	}
}

// personKind checks a kind, with the message an operator pasting the recon
// stanza needs: the stanza leaves kind empty on purpose.
func (v *validator) personKind(key, kind string) {
	const kinds = "employee, contractor, shared, service or break_glass"
	switch {
	case kind == "":
		v.fail(key+".kind", "is empty. Say whose account this is: %s. If you cannot tell, find out: "+
			"an admin nobody can name is reported as a finding", kinds)
	case kind == "admin" || kind == "owner":
		v.fail(key+".kind", "%q is not a kind; admins are listed under access.admins. Use %s", kind, kinds)
	case !slices.Contains(PersonKinds, kind):
		v.fail(key+".kind", "%q is not a kind: use %s", kind, kinds)
	}
}

// identifiers checks one list of a person's addresses or logins: each well
// formed, none twice, none another handle's, since a rule could not tell
// two people apart by it.
func (v *validator) identifiers(key, handle, field string, vals []string, ok func(string) bool, what string, byIdent map[string]string) {
	if vals == nil {
		return
	}
	if len(vals) == 0 {
		v.fail(key+"."+field, "an empty list says nothing; remove the key if %s has none", handle)
		return
	}
	for i, val := range vals {
		k := fmt.Sprintf("%s.%s[%d]", key, field, i)
		if strings.Contains(val, "[REDACTED") || strings.Contains(val, "[TRUNCATED") {
			v.fail(k, "is a marker scheck printed in place of a hidden value, not a value; write it out")
			continue
		}
		if !ok(val) {
			v.fail(k, "%q is not %s", val, what)
			continue
		}
		ident := field + ":" + strings.ToLower(val)
		if other, dup := byIdent[ident]; dup {
			if strings.HasPrefix(other, key+".") {
				v.fail(k, "%s is listed twice", val)
			} else {
				v.fail(k, "%s is also %s. One %s belongs to one handle; if several people sign in to it, "+
					"declare it once with kind: shared and used_by", val, other, identWord(field))
			}
			continue
		}
		byIdent[ident] = k
	}
}

// usedBy checks who signs in to a shared account: required on one, refused
// on any other kind, and only people may be named.
func (v *validator) usedBy(key, handle string, p Person) {
	if p.Kind != "shared" {
		if p.UsedBy != nil {
			v.fail(key+".used_by", "only a shared account has used_by; %s is %s", handle, kindWords(p.Kind))
		}
		return
	}
	if len(p.UsedBy) == 0 {
		v.fail(key+".used_by", "is required on a shared account: the handles of the people who sign in to it, "+
			"so the report can say whose departure means rotating it")
		return
	}
	seen := map[string]bool{}
	for i, h := range p.UsedBy {
		k := fmt.Sprintf("%s.used_by[%d]", key, i)
		other, ok := v.f.People[h]
		switch {
		case seen[h]:
			v.fail(k, "%s is listed twice", h)
		case h == handle:
			v.fail(k, "names the account itself; list the people who sign in to it")
		case !ok:
			v.fail(k, "%q is not a handle under people", h)
		case other.Kind == "shared" || other.Kind == "service":
			v.fail(k, "%s is %s, not a person who signs in", h, kindWords(other.Kind))
		}
		seen[h] = true
	}
}

func isAddress(s string) bool {
	m := emailRe.FindStringSubmatch(s)
	return m != nil && checkLabels(strings.ToLower(m[1]), 2) == nil
}

func identWord(field string) string {
	if field == "github" {
		return "login"
	}
	return "address"
}

func kindWords(kind string) string {
	switch kind {
	case "":
		return "of no kind"
	case "employee":
		return "an employee"
	case "break_glass":
		return "a break-glass account"
	case "shared", "service":
		return "a " + kind + " account"
	}
	return "a " + kind
}

func (v *validator) handle(key, h string) {
	if v.required(key, h) {
		if _, ok := v.f.People[h]; !ok {
			v.fail(key, "%q is not a handle under people", h)
		}
	}
}

// assetsSection checks every assets entry: its name, its locator, which
// must equal a root or fall under one, and the settings its kind takes.
func (v *validator) assetsSection() map[string]Ref {
	out := map[string]Ref{}
	byID := map[string]string{}
	for _, name := range sortedKeys(v.f.Assets) {
		a := v.f.Assets[name]
		key := "assets." + name
		if !nameRe.MatchString(name) {
			v.fail(key, "name %q must match ^[a-z0-9][a-z0-9-]{0,62}$", name)
		}
		if a.OrgUnit != "" {
			v.fail(key+".org_unit", "an organizational unit narrows an exclude, not an asset")
		}
		r, ok := v.locator(key, a.Locator)
		if !ok {
			continue
		}
		if v.rootOf(r) == nil {
			v.fail(key+"."+string(r.Kind), "%s falls under no root: an assets entry never adds scope", r.ID)
			continue
		}
		if prev, dup := byID[r.ID]; dup {
			v.fail(key, "describes %s, as %s does: one entry per asset", r.ID, prev)
			continue
		}
		// exclude wins over an asset's own settings (docs/spec/scope.md),
		// so settings for an excluded asset would never apply.
		if i := slices.IndexFunc(v.excludes, func(x Ref) bool { return Excludes(x, r) }); i >= 0 {
			v.fail(key+"."+string(r.Kind), "%s is excluded by %s: exclude always wins, so these settings would never apply", r.ID, v.excludes[i].ID)
			continue
		}
		if root, clash := v.refs[name]; clash && root.ID != r.ID {
			v.fail(key, "the name %q is also a root's value, for %s", name, root.ID)
			continue
		}
		byID[r.ID] = key
		out[name] = r
		v.assets[name] = r
		v.assetSettings(key, r, a)
	}
	return out
}

func (v *validator) assetSettings(key string, r Ref, a Asset) {
	v.mode(key+".probe", a.Probe)
	v.mode(key+".scan", a.Scan)
	v.throttle(key+".throttle", a.Throttle)

	only := func(field string, set bool, kinds ...Kind) {
		if set && !slices.Contains(kinds, r.Kind) {
			names := make([]string, len(kinds))
			for i, k := range kinds {
				names[i] = string(k)
			}
			v.fail(key+"."+field, "applies only to a %s asset; %s is a %s", strings.Join(names, " or "), r.ID, r.Kind)
		}
	}
	only("jump", a.Jump != "", KindHost)
	only("identity", a.Identity != "", KindHost)
	only("known_hosts", a.KnownHosts != "", KindHost)
	only("timeout", a.Timeout != "", KindHost)
	only("elevate", a.Elevate != "", KindHost)
	only("profile", a.Profile != "", KindHost)
	only("disable_checks", a.DisableChecks != nil, KindHost)
	only("deny_paths", a.DenyPaths != nil, KindHost)
	only("context", a.Context != nil, KindHost)
	only("first_party", a.FirstParty != nil, KindDomain, KindURL, KindHost)
	only("deploys_to", a.DeploysTo != "", KindRepo)
	only("ci", a.CI != "", KindRepo)

	if r.Kind == KindHost {
		v.hostSettings(key, r, a)
	}
	if fp := a.FirstParty; fp != nil {
		v.handle(key+".first_party.confirmed_by", fp.ConfirmedBy)
		if v.required(key+".first_party.target", fp.Target) {
			if _, ok := canonicalTarget(fp.Target); !ok {
				v.fail(key+".first_party.target", "%q is neither the name the record points at nor its addresses, such as 198.51.100.7,198.51.100.8", fp.Target)
			}
		}
		if v.required(key+".first_party.date", fp.Date) {
			v.date(key+".first_party.date", fp.Date)
		}
	}
	if a.DeploysTo != "" {
		v.enum(key+".deploys_to", a.DeploysTo, DeployTargets)
	}
	if a.CI != "" && !slices.ContainsFunc(v.f.Tools, func(t Tool) bool { return t.Name == a.CI }) {
		v.fail(key+".ci", "%q is not a tool declared under tools", a.CI)
	}
}

// hostSettings checks a host asset's reach settings, profile, narrowing
// lists and context (docs/spec/engagement.md, "Host context", "Host
// settings"). The narrowing lists only subtract: an unknown check id or a
// deny_paths entry that is relative or / would silently narrow nothing.
func (v *validator) hostSettings(key string, r Ref, a Asset) {
	local := r.Local()
	if a.Jump != "" {
		if local {
			v.fail(key+".jump", "the local host is not reached over SSH")
		} else if j, err := parseLocator(KindHost, a.Jump); err != nil {
			v.fail(key+".jump", "%v", err)
		} else if j.Local() {
			v.fail(key+".jump", "a jump host is reached over SSH; local is the machine running scheck")
		} else if j.ID == r.ID {
			v.fail(key+".jump", "names the host itself; a jump host is the machine you connect through to reach it")
		} else if i := slices.IndexFunc(v.excludes, func(x Ref) bool { return Excludes(x, j) }); i >= 0 {
			// Not an asset, but scheck authenticates there: an excluded
			// address is never contacted (docs/spec/scope.md).
			v.fail(key+".jump", "%s is excluded by %s, and a jump host is contacted: exclude always wins", j.ID, v.excludes[i].ID)
		} else if i := slices.IndexFunc(v.excludes, func(x Ref) bool { _, ok := excludePrefix(x); return ok }); i >= 0 && !r.addr.IsValid() {
			// The hop resolves the host's name, so scheck never sees the
			// address it reaches and cannot hold it to the exclude.
			v.fail(key+".jump", "%s is written as a name and reached through a jump host, which resolves it, so scheck cannot "+
				"check its address against %s: write this host as its address (%s@<address>)", r.ID, v.excludes[i].ID, or(r.User, "user"))
		}
	}
	if a.Identity != "" && local {
		v.fail(key+".identity", "the local host is not reached over SSH")
	}
	if a.KnownHosts != "" && local {
		v.fail(key+".known_hosts", "the local host is not reached over SSH")
	}
	// timeout is the host collector's run timeout
	// (docs/spec/host-collector.md §4.4), not limits.timeout.
	if a.Timeout != "" {
		if d, err := time.ParseDuration(a.Timeout); err != nil || d <= 0 {
			v.fail(key+".timeout", "%q is not a positive duration such as 10m", a.Timeout)
		}
	}
	if a.Elevate != "" {
		v.enum(key+".elevate", a.Elevate, Elevations)
	}
	v.profile(key+".profile", a.Profile)
	for i, id := range a.DisableChecks {
		if !v.opts.KnownCheck(id) {
			v.fail(fmt.Sprintf("%s.disable_checks[%d]", key, i), "%q is not a check in the catalog (scheck catalog lists them)", id)
		}
	}
	for i, p := range a.DenyPaths {
		k := fmt.Sprintf("%s.deny_paths[%d]", key, i)
		switch c := path.Clean(p); {
		case !strings.HasPrefix(p, "/"):
			v.fail(k, "%q is not an absolute path", p)
		case c == "/":
			v.fail(k, "/ would deny every path: disable the checks instead")
		case c != p && c+"/" != p:
			v.fail(k, "%q is not a clean path: write %s", p, c)
		}
	}
	if c := a.Context; c != nil {
		ck := key + ".context"
		if c.Exposure != "" {
			v.enum(ck+".exposure", c.Exposure, Exposures)
		}
		if c.Environment != "" {
			v.enum(ck+".environment", c.Environment, Environments)
		}
		seen := map[string]bool{}
		for i, s := range c.ExpectedServices {
			sk := fmt.Sprintf("%s.expected_services[%d]", ck, i)
			if s.Port < 1 || s.Port > 65535 {
				v.fail(sk+".port", "must be 1-65535")
			}
			if v.required(sk+".proto", s.Proto) {
				v.enum(sk+".proto", s.Proto, Protos)
			}
			if s.Audience != "" {
				v.enum(sk+".audience", s.Audience, Audiences)
			}
			if k := strconv.Itoa(s.Port) + "/" + s.Proto; seen[k] {
				v.fail(sk, "%s is declared twice", k)
			} else {
				seen[k] = true
			}
		}
	}
}

// resolveRef resolves a reference: an assets name, or a root's value
// exactly as written under roots.
func (v *validator) resolveRef(key, ref string) (Ref, bool) {
	if !v.required(key, ref) {
		return Ref{}, false
	}
	if r, ok := v.assets[ref]; ok {
		return r, true
	}
	if r, ok := v.refs[ref]; ok {
		return r, true
	}
	v.fail(key, "%q is neither an assets name nor a root as written under roots", ref)
	return Ref{}, false
}

// acceptedAsset resolves an accepted risk's asset: a reference as the file
// writes one, or the canonical id of an asset under a root and no exclude,
// as the report prints it for an asset found by discovery
// (docs/spec/engagement.md, "Identity, references and validation").
func (v *validator) acceptedAsset(key, ref string) {
	if ref == "" || v.assets[ref].ID != "" || v.refs[ref].ID != "" {
		v.resolveRef(key, ref)
		return
	}
	r, ok := ParseID(ref)
	if !ok || v.rootOf(r) == nil {
		v.fail(key, "%q is neither an assets name, a root as written under roots, nor the canonical id of an asset under a root", ref)
		return
	}
	if i := slices.IndexFunc(v.excludes, func(x Ref) bool { return Excludes(x, r) }); i >= 0 {
		v.fail(key, "%s is excluded by %s, so nothing on it is read or accepted", r.ID, v.excludes[i].ID)
	}
}

// tenantRef resolves a reference that must name a SaaS tenant. It returns
// the tenant's canonical id, so an assets name and the root's value for one
// tenant are told to be the same.
func (v *validator) tenantRef(key, ref string) (string, bool) {
	r, ok := v.resolveRef(key, ref)
	if !ok {
		return "", false
	}
	if r.Kind != KindSaaS {
		v.fail(key, "%q is %s, not a SaaS tenant", ref, r.ID)
		return "", false
	}
	return r.ID, true
}

func (v *validator) access() {
	adminsOf := map[string]string{} // canonical tenant id -> the key that listed it
	for _, tenant := range sortedKeys(v.f.Access.Admins) {
		key := "access.admins." + tenant
		id, ok := v.tenantRef(key, tenant)
		if ok {
			if first, dup := adminsOf[id]; dup {
				v.fail(key, "names the same tenant as %s; list its admins once", first)
			}
			adminsOf[id] = key
		}
		field, provider := tenantIdentifier(id)
		for i, h := range v.f.Access.Admins[tenant] {
			k := fmt.Sprintf("%s[%d]", key, i)
			v.handle(k, h)
			// Admins are matched by identifier: a listed admin with none for
			// this tenant could never be found, so the match would abstain.
			if p, ok := v.f.People[h]; ok && field != "" && len(identifiersOf(p, field)) == 0 {
				v.fail(k, "lists %s, but people.%s has no %s. Add it, or scheck cannot tell whether %s is an admin there",
					h, h, provider, h)
			}
		}
	}
	whereSeen := map[string]int{} // canonical tenant id -> first index
	for i, m := range v.f.Access.MFA {
		key := fmt.Sprintf("access.mfa[%d]", i)
		if id, ok := v.tenantRef(key+".where", m.Where); ok {
			if first, dup := whereSeen[id]; dup {
				v.fail(key+".where", "%s is already declared at access.mfa[%d]", m.Where, first)
			}
			whereSeen[id] = i
		}
		switch m.Enforced {
		case "":
			v.fail(key+".enforced", "is required: everyone, admins, some, none, or unknown if you are not sure")
		case "true", "false", "yes", "no":
			// A yes/no answer turns "I think so" into a declaration a
			// contradiction finding then raises against.
			v.fail(key+".enforced", "%s is ambiguous. Write everyone if every account must use 2-step verification, "+
				"admins if only administrators must, some, none, or unknown", m.Enforced)
		default:
			v.enum(key+".enforced", m.Enforced, MFAEnforcements)
		}
	}
}

func (v *validator) tools() {
	for i, t := range v.f.Tools {
		key := fmt.Sprintf("tools[%d]", i)
		v.required(key+".category", t.Category)
		v.required(key+".name", t.Name)
	}
	seen := map[string]bool{}
	for i, a := range v.f.NotUsed {
		key := fmt.Sprintf("not_used[%d]", i)
		if v.enum(key, a, Areas) && seen[a] {
			v.fail(key, "%s is listed twice", a)
		}
		seen[a] = true
	}
}

// mailDomain parses a mail domain, which must fall under a domain root.
func (v *validator) mailDomain(key, d string) (string, bool) {
	if !v.required(key, d) {
		return "", false
	}
	name, err := parseDomain(d)
	if err != nil {
		v.fail(key, "%v", err)
		return "", false
	}
	if !slices.ContainsFunc(v.roots, func(r Ref) bool { return r.Kind == KindDomain && domainUnder(name, r.name) }) {
		v.fail(key, "%s falls under no domain root", name)
		return "", false
	}
	return name, true
}

func (v *validator) mail() {
	sending := map[string]bool{}
	for i, s := range v.f.Mail.Senders {
		key := fmt.Sprintf("mail.senders[%d]", i)
		if d, ok := v.mailDomain(key+".domain", s.Domain); ok {
			sending[d] = true
		}
		v.required(key+".service", s.Service)
		for j, sel := range s.DKIMSelectors {
			if !dkimRe.MatchString(sel) {
				v.fail(fmt.Sprintf("%s.dkim_selectors[%d]", key, j), "%q is not a DKIM selector", sel)
			}
		}
	}
	for i, d := range v.f.Mail.NoMail {
		key := fmt.Sprintf("mail.no_mail[%d]", i)
		if name, ok := v.mailDomain(key, d); ok && sending[name] {
			v.fail(key, "%s also has a sender under mail.senders", name)
		}
	}
}

func (v *validator) references() {
	for i, s := range v.f.Secrets.Production {
		key := fmt.Sprintf("secrets.production[%d]", i)
		v.required(key+".store", s.Store)
		v.resolveRef(key+".asset", s.Asset)
	}
	for i, d := range v.f.Data.MattersMost {
		key := fmt.Sprintf("data.matters_most[%d]", i)
		v.required(key+".what", d.What)
		v.resolveRef(key+".asset", d.Asset)
	}
	for i, b := range v.f.Data.Backups {
		key := fmt.Sprintf("data.backups[%d]", i)
		v.required(key+".where", b.Where)
	}
}

func (v *validator) intent() {
	in := v.f.Intent
	public := map[string]bool{}
	for _, e := range in.ExposedOnPurpose {
		if ref, err := parseURL(e.URL); err == nil {
			public[ref.ID] = true
		}
	}
	for i, e := range in.NotExposed {
		if ref, err := parseURL(e.URL); err == nil && public[ref.ID] {
			v.fail(fmt.Sprintf("intent.not_exposed[%d].url", i), "the same URL is also declared exposed_on_purpose")
		}
	}
	for _, list := range []struct {
		key     string
		entries []Exposure
	}{{"intent.exposed_on_purpose", in.ExposedOnPurpose}, {"intent.not_exposed", in.NotExposed}} {
		for i, e := range list.entries {
			key := fmt.Sprintf("%s[%d]", list.key, i)
			if v.required(key+".url", e.URL) {
				if r, err := parseLocator(KindURL, e.URL); err != nil {
					v.fail(key+".url", "%v", err)
				} else if v.rootOf(r) == nil {
					v.fail(key+".url", "%s falls under no root: an intent URL is an entry point, never scope of its own", r.ID)
				} else if j := slices.IndexFunc(v.excludes, func(x Ref) bool { return Excludes(x, r) }); j >= 0 {
					v.fail(key+".url", "%s is excluded by %s, so it is never read: exclude always wins", r.ID, v.excludes[j].ID)
				}
			}
			if v.required(key+".audience", e.Audience) {
				v.enum(key+".audience", e.Audience, Audiences)
			}
		}
	}
	for i, a := range in.AcceptedRisks {
		key := fmt.Sprintf("intent.accepted_risks[%d]", i)
		if v.required(key+".id", a.ID) {
			if custom, ok := strings.CutPrefix(a.ID, "custom:"); ok {
				if custom == "" {
					v.fail(key+".id", "custom: needs a name after it")
				}
			} else if !v.opts.KnownFinding(a.ID) {
				v.fail(key+".id", "%q is neither a catalog finding id nor a custom: id", a.ID)
			} else if kind := v.opts.FindingSubject(a.ID); kind != "" && strings.TrimSpace(a.Subject) == "" {
				// An acceptance of the whole id would also accept every
				// instance the asset gains later (docs/spec/engagement.md,
				// "Accepted risks").
				v.fail(key+".subject", "is required: %s is reported per %s, and accepting every one would also accept each new one found later; name the %s, and add one entry per %s to accept",
					a.ID, words(kind), words(kind), words(kind))
			} else if kind == "" && strings.TrimSpace(a.Subject) != "" && !v.opts.HostFinding(a.ID) {
				// Nothing could ever match it, and a reader would believe
				// one instance was accepted.
				v.fail(key+".subject", "%s is about the asset as a whole, not one instance of it; remove subject", a.ID)
			}
		}
		v.acceptedAsset(key+".asset", a.Asset)
		v.required(key+".reason", a.Reason)
		v.handle(key+".accepted_by", a.AcceptedBy)
		v.date(key+".expires", a.Expires)
	}
}

func (v *validator) authorization() {
	a := v.f.Authorization
	if a == nil {
		return
	}
	v.required("authorization.by", a.By)
	if v.required("authorization.date", a.Date) {
		v.date("authorization.date", a.Date)
	}
	for i, w := range a.Windows {
		key := fmt.Sprintf("authorization.windows[%d]", i)
		from, okF := v.timestamp(key+".from", w.From)
		to, okT := v.timestamp(key+".to", w.To)
		if okF && okT && !to.After(from) {
			v.fail(key+".to", "must be after from")
		}
	}
	for i, s := range a.Source {
		key := fmt.Sprintf("authorization.source[%d]", i)
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p {
			v.fail(key, "%q is not a CIDR network such as 203.0.113.10/32", s)
		}
	}
}

// words writes a subject kind as an operator reads it ("oauth_app" as
// "OAuth app").
func words(kind string) string {
	switch kind {
	case "oauth_app":
		return "OAuth app"
	case "dns_name":
		return "DNS name"
	case "dns_record":
		return "DNS record"
	case "dkim_selector":
		return "DKIM selector"
	case "spf_mechanism":
		return "SPF mechanism"
	case "url":
		return "URL"
	case "org_unit":
		return "organizational unit"
	}
	return strings.ReplaceAll(kind, "_", " ")
}

// tenantIdentifier names the people field that matches accounts in a SaaS
// tenant, by its canonical id ("saas:google-workspace:example.com").
func tenantIdentifier(id string) (field, words string) {
	switch {
	case strings.HasPrefix(id, "saas:google-workspace:"):
		return "workspace", "Workspace address"
	case strings.HasPrefix(id, "saas:github:"):
		return "github", "GitHub login"
	}
	return "", ""
}

func identifiersOf(p Person, field string) []string {
	if field == "github" {
		return p.GitHub
	}
	return p.Workspace
}
