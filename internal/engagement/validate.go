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
)

// Vocabularies of the engagement file (docs/spec/engagement.md).
var (
	Triggers      = []string{"questionnaire", "audit", "funding", "incident", "routine"}
	PersonKinds   = []string{"employee", "contractor", "agency", "service", "break_glass"}
	Audiences     = []string{"internet", "vpn", "lan", "localhost", "airgapped"}
	Exposures     = []string{"internet", "vpn", "lan", "airgapped"}
	Environments  = []string{"prod", "staging", "dev"}
	Protos        = []string{"tcp", "udp"}
	Areas         = []string{"identity", "secrets", "cloud", "data", "cicd", "external", "web", "hosts", "email", "logging"}
	Profiles      = []string{"baseline", "hardened"}
	Elevations    = []string{"none", "sudo"}
	DeployTargets = []string{"production", "staging", "development"}
	// Modes are the probe and scan modes; this build runs only off.
	Modes = []string{"off", "confirm", "auto", "all"}
)

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
	dkimRe  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
)

// Options carry the catalogs the file is checked against, so this package
// needs neither the host catalog nor the finding catalog compiled in.
type Options struct {
	// KnownCheck reports whether id is a host catalog check id.
	KnownCheck func(id string) bool
	// KnownFinding reports whether id is a catalog finding id.
	KnownFinding func(id string) bool
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
	if opts.KnownCheck == nil || opts.KnownFinding == nil {
		return nil, errors.New("engagement: Options.KnownCheck and Options.KnownFinding are required")
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
		default:
			if v.rootOf(r) == nil {
				v.fail(key, "%s falls under no root, so it excludes nothing", r.ID)
			}
		}
	}
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
		if na, ok := errors.AsType[notAvailable](err); ok {
			v.unavailable(key+"."+string(kind), "%s", na.what)
		} else {
			v.fail(key+"."+string(kind), "%v", err)
		}
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
	byIdent := map[string]string{}
	for _, handle := range sortedKeys(v.f.People) {
		p := v.f.People[handle]
		key := "people." + handle
		if !nameRe.MatchString(handle) {
			v.fail(key, "handle %q must match ^[a-z0-9][a-z0-9-]{0,62}$", handle)
		}
		if v.required(key+".kind", p.Kind) {
			v.enum(key+".kind", p.Kind, PersonKinds)
		}
		if p.Workspace != "" {
			if m := emailRe.FindStringSubmatch(p.Workspace); m == nil || checkLabels(strings.ToLower(m[1]), 2) != nil {
				v.fail(key+".workspace", "%q is not an email address", p.Workspace)
			}
		}
		if p.GitHub != "" && !loginRe.MatchString(p.GitHub) {
			v.fail(key+".github", "%q is not a GitHub login", p.GitHub)
		}
		for _, id := range []struct{ field, val string }{{"workspace", strings.ToLower(p.Workspace)}, {"github", strings.ToLower(p.GitHub)}} {
			if id.val == "" {
				continue
			}
			k := id.field + ":" + id.val
			if other, dup := byIdent[k]; dup {
				v.fail(key+"."+id.field, "is also %s's: a rule could not tell the two apart", other)
			}
			byIdent[k] = handle
		}
		if p.Org != "" && p.Kind != "contractor" && p.Kind != "agency" {
			v.fail(key+".org", "names a contractor's or agency's company; %s is %s", handle, p.Kind)
		}
		v.date(key+".left", p.Left)
	}
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
		if i := slices.IndexFunc(v.excludes, func(x Ref) bool { return x.OrgUnit == "" && Under(r, x) }); i >= 0 {
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
			v.fail(key+".jump", "is the host itself")
		}
	}
	if a.Identity != "" && local {
		v.fail(key+".identity", "the local host is not reached over SSH")
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

// tenantRef resolves a reference that must name a SaaS tenant.
func (v *validator) tenantRef(key, ref string) {
	if r, ok := v.resolveRef(key, ref); ok && r.Kind != KindSaaS {
		v.fail(key, "%q is %s, not a SaaS tenant", ref, r.ID)
	}
}

func (v *validator) access() {
	for _, tenant := range sortedKeys(v.f.Access.Admins) {
		key := "access.admins." + tenant
		v.tenantRef(key, tenant)
		for i, h := range v.f.Access.Admins[tenant] {
			v.handle(fmt.Sprintf("%s[%d]", key, i), h)
		}
	}
	for i, m := range v.f.Access.MFA {
		key := fmt.Sprintf("access.mfa[%d]", i)
		v.tenantRef(key+".where", m.Where)
		if m.Enforced == nil {
			v.fail(key+".enforced", "is required: true or false")
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
			}
		}
		v.resolveRef(key+".asset", a.Asset)
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
