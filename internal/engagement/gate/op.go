package gate

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Level is an op's impact level (docs/spec/scope.md, "Impact levels").
type Level int

// The four levels, in order of impact.
const (
	Passive Level = iota + 1
	Observe
	Probe
	Scan
)

func (l Level) String() string {
	switch l {
	case Passive:
		return "passive"
	case Observe:
		return "observe"
	case Probe:
		return "probe"
	case Scan:
		return "scan"
	}
	return "level(" + strconv.Itoa(int(l)) + ")"
}

// Method is what an op sends. TLS is a handshake and nothing after it: the
// certificate read of a discovered name.
type Method string

// The methods an op may declare.
const (
	GET  Method = "GET"
	HEAD Method = "HEAD"
	POST Method = "POST"
	TLS  Method = "TLS"
)

// Class says what an op is for. A principal op reads who the credential is
// (GitHub's /user), never a target; a credential exchange is the one POST
// the gate allows (docs/spec/scope.md, "Methods and credentials").
type Class string

// The op classes.
const (
	Read               Class = ""
	Principal          Class = "principal"
	CredentialExchange Class = "credential_exchange" //nolint:gosec // an op class, not a credential
)

// Auth names how a credential binds to an op. The gate attaches it after
// admission; a collector never holds one.
type Auth string

// The credential bindings.
const (
	NoAuth      Auth = ""
	GitHubToken Auth = "github_token"
)

// Kind is what a list op's items are. The excludable kinds need an
// exclusion key, so an excluded item can be dropped before anything is
// stored (docs/spec/scope.md, "Exclusion in responses").
type Kind string

// Item kinds of list ops.
const (
	KindRepo    Kind = "repo"
	KindUser    Kind = "user"
	KindOrgUnit Kind = "org_unit"
	KindProject Kind = "project"
	KindOther   Kind = "other"
	// KindName is a record holding DNS names, a certificate's
	// identities: List.Names says which field (docs/spec/scope.md,
	// "Third-party sources").
	KindName Kind = "name"
)

func (k Kind) excludable() bool {
	return k == KindRepo || k == KindUser || k == KindOrgUnit || k == KindProject
}

// List declares a list response: where its items are, what they are, the
// item field an exclusion matches, and how it pages (docs/spec/scope.md,
// "Exclusion in responses"). Fields are dotted paths into an item.
type List struct {
	// Items is the path of the item array in the body, "$" for a body
	// that is the array. A missing array is an empty page: Google leaves
	// an empty list out.
	Items string
	Kind  Kind
	// ExcludeKey is the item field an exclude matches: a repository's
	// owner/name, a user's or an organizational unit's unit path, a
	// project's id. An item without it is dropped as unattributable.
	ExcludeKey string
	// UserRef is the item field naming a user (an id or an address), for
	// items that reference users: role assignments, group members, tokens.
	// An item whose user is in the excluded-subject set is dropped.
	UserRef string
	// UserKeys are the fields of a user item that may name the user
	// elsewhere (its id, its addresses, its contact addresses). A users
	// list that declares them builds the excluded-subject set: every key
	// of a user it drops is excluded.
	UserKeys []string
	// UserIDs are the fields that identify a user inside the tenant (id,
	// primaryEmail, aliases): the users the list returned, and the
	// tenant's domains, are read from these only, never from a contact
	// address a user put on file.
	UserIDs []string
	// Next says how the list pages; nil for a list read in one response.
	Next *Pages
	// MaxPages is the most pages the gate reads; a list with pages left
	// after it is incomplete ("page_limit").
	MaxPages int
	// Names is the field of a name record holding identities separated by
	// newlines. The gate keeps only valid DNS names, lowercased without a
	// trailing dot, as an array; anything else (an email identity of an
	// S/MIME certificate) is dropped and counted as not_a_name, and a name
	// an exclude covers is dropped and counted by its exclude, before
	// anything is stored. A record left with no name is dropped.
	Names string
}

// Pages declares a list's cursor: the query parameter that carries it and
// where the next one is found. A collector never passes the cursor: it asks
// for the next page by the id of the page before (Request.NextOf), and the
// gate rebuilds the request from the template (docs/spec/scope.md,
// "Connections").
type Pages struct {
	// Param is an optional Cursor or Count parameter, a whole query value.
	Param string
	// Field is the body field holding the next cursor (Google's
	// nextPageToken); empty means the Link header's rel="next" (GitHub).
	Field string
}

// ParamType is a parameter's type. Each has a tight charset; nothing else
// reaches a URL (docs/ROADMAP.md, "Rules for every release": nothing builds
// a request from target output beyond typed parameters).
type ParamType int

// The parameter types.
const (
	// Login is a GitHub user or organization login.
	Login ParamType = iota + 1
	// RepoName is a GitHub repository name.
	RepoName
	// DNSName is a lowercase DNS name of two labels or more.
	DNSName
	// Host is a web origin's host: a DNS name or an address literal (IPv6
	// in brackets), with an optional port.
	Host
	// Scheme is https or http.
	Scheme
	// URLPath is an absolute, normalized path: no dot segments, no query.
	URLPath
	// Cursor is an opaque pagination cursor a provider returned.
	Cursor
	// Count is a page number or size.
	Count
	// UserKey is a Workspace user's id or primary address. A request that
	// names one is checked against the excluded-subject set.
	UserKey
)

// Param is one typed parameter. An optional parameter may be left out; it
// is then dropped from the query.
type Param struct {
	Name     string
	Type     ParamType
	Optional bool
}

// Op is one declared request: the gate's equivalent of a catalog entry
// (docs/spec/scope.md, "Operations"). A collector names an op and its
// parameters; it never builds a URL.
type Op struct {
	ID string
	// Provider is a key of the provider table: the third-party source the
	// op goes to, or "web" for an asset's own site.
	Provider string
	Method   Method
	// URL is the template: scheme, a literal host (a web op's host is
	// {host}), a path and a query, with {name} placeholders.
	URL string
	// Subject is the canonical id template of what the op reads, which
	// must fall under a root and no exclude. Empty for a principal op and
	// a credential exchange.
	Subject string
	Params  []Param
	Class   Class
	Level   Level
	Auth    Auth
	// Accept lists the response content types the op expects.
	Accept []string
	List   *List
	// Keep lists the response fields the op keeps.
	Keep []string
	// MaxBytes caps the response body.
	MaxBytes int64
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// tokenEndpoints are the only hosts a credential exchange may POST to.
var tokenEndpoints = []string{"oauth2.googleapis.com"}

// compiled is a validated op with its template parsed.
type compiled struct {
	Op
	scheme, host, path string
	query              [][2]string // key, template
	types              map[string]Param
	// json says the op's responses are JSON: parsed after redaction,
	// filtered and projected to Keep.
	json bool
	keep keepTree
	// nextKey is the query key that carries the cursor of a paged list.
	nextKey string
	// users says a request for the op names or lists users, so the
	// excluded-subject set must be known before it is sent.
	users bool
}

// neverRead are URL path segments no op may read, lowercased.
var neverRead = []string{"/verificationcodes"}

// neverReadIn is the neverRead segment a URL or path holds once decoded and
// lowercased, "" when none; one that does not decode is read as written.
func neverReadIn(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		s = d
	}
	s = strings.ToLower(s)
	for _, never := range neverRead {
		if strings.Contains(s, never) {
			return never
		}
	}
	return ""
}

// validate is the invariants test of one op: it names the first rule the op
// breaks, checking in a fixed order so that the rule named does not depend
// on how the checks are grouped.
func validate(op Op) (*compiled, error) {
	fail := func(err error) error { return fmt.Errorf("op %q: %v", op.ID, err) }
	prov, err := checkDeclaration(op)
	if err != nil {
		return nil, fail(err)
	}
	c, rawQuery, wholePath, err := parseTemplate(op)
	if err != nil {
		return nil, fail(err)
	}
	u := uses{c: c, seen: map[string]bool{}}
	for _, check := range []func() error{
		func() error { return c.declareParams(prov, wholePath) },
		func() error { return c.checkDestination(prov, rawQuery) },
		func() error { return u.template(rawQuery) },
		u.subject,
		u.unused,
		func() error { return c.checkResponse(prov) },
	} {
		if err := check(); err != nil {
			return nil, fail(err)
		}
	}
	return c, nil
}

// checkDeclaration checks what an op declares about itself: its id, its
// provider, level, method and class, and that it reads nothing that
// returns credentials.
func checkDeclaration(op Op) (provider, error) {
	if op.ID == "" {
		return provider{}, errors.New("has no id")
	}
	prov, ok := providers[op.Provider]
	if !ok {
		return provider{}, fmt.Errorf("provider %q is not in the provider table", op.Provider)
	}
	switch op.Level {
	case Passive, Observe, Probe, Scan:
	default:
		return provider{}, errors.New("declares no level")
	}
	switch op.Method {
	case GET, HEAD, TLS:
	case POST:
		if op.Class != CredentialExchange {
			return provider{}, errors.New("POST is allowed only for a credential exchange")
		}
	default:
		return provider{}, fmt.Errorf("method %q is not GET, HEAD, TLS or POST", op.Method)
	}
	if op.Class == CredentialExchange && op.Method != POST {
		return provider{}, errors.New("a credential exchange is a POST")
	}
	if op.Class != Read && op.Class != Principal && op.Class != CredentialExchange {
		return provider{}, fmt.Errorf("class %q is unknown", op.Class)
	}
	// Reads that return a credential itself, which no finding needs and no
	// redaction rule could recognize: Workspace's verificationCodes.list
	// answers with users' backup sign-in codes (docs/ROADMAP.md, E6). The
	// template is read decoded, as the server reads the path; bind checks
	// the path it builds again.
	if never := neverReadIn(op.URL); never != "" {
		return provider{}, fmt.Errorf("reads %s, which returns credentials and is never declared", never)
	}
	return prov, nil
}

// parseTemplate splits the URL template into scheme, host, path and query.
// A path is literal from its first slash, or one whole placeholder, which
// must then be a URLPath (declareParams).
func parseTemplate(op Op) (c *compiled, rawQuery string, wholePath bool, err error) {
	scheme, rest, ok := strings.Cut(op.URL, "://")
	host, pathQuery := rest, ""
	if after, isWeb := strings.CutPrefix(rest, "{host}"); isWeb {
		host, pathQuery = "{host}", after
	} else if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, pathQuery = rest[:i], rest[i:]
	}
	tmplPath, rawQuery, _ := strings.Cut(pathQuery, "?")
	wholePath = tmplPath != "" && placeholder.FindString(tmplPath) == tmplPath
	if !ok || host == "" || !strings.HasPrefix(tmplPath, "/") && !wholePath || strings.ContainsAny(op.URL, "#@ ") {
		return nil, "", false, fmt.Errorf("URL template %q is not scheme://host/path?query", op.URL)
	}
	return &compiled{Op: op, scheme: scheme, host: host, path: tmplPath, types: map[string]Param{}}, rawQuery, wholePath, nil
}

// declareParams checks each parameter's name and type.
func (c *compiled) declareParams(prov provider, wholePath bool) error {
	for _, p := range c.Params {
		if p.Name == "" || p.Type < Login || p.Type > UserKey {
			return fmt.Errorf("parameter %q has no type", p.Name)
		}
		if _, dup := c.types[p.Name]; dup {
			return fmt.Errorf("parameter %q is declared twice", p.Name)
		}
		c.types[p.Name] = p
	}
	if wholePath && c.types[strings.Trim(c.path, "{}")].Type != URLPath {
		return errors.New("a path that is one placeholder must be a URLPath")
	}
	for _, p := range c.Params {
		// An API's path is declared, never supplied: a URLPath there could
		// name any endpoint of the provider.
		if p.Type == URLPath && !prov.web {
			return fmt.Errorf("parameter %q is a URLPath, which only a web op takes", p.Name)
		}
	}
	if c.Class != Read && (len(c.Params) > 0 || strings.Contains(c.URL, "{")) {
		// Nothing scopes a principal op or a credential exchange but its
		// asset, so nothing in its URL may vary.
		return fmt.Errorf("a %s op takes no parameters", c.Class)
	}
	return nil
}

// checkDestination checks where the op sends: a web op to an asset's own
// site, whose subject is its URL, so what is admitted is what is sent; an
// API op over https to a literal host of its provider.
func (c *compiled) checkDestination(prov provider, rawQuery string) error {
	if !prov.web {
		if c.scheme != "https" {
			return errors.New("an API op is https")
		}
		if strings.Contains(c.host, "{") || !slices.Contains(prov.hosts, c.host) {
			return fmt.Errorf("host %q is not a literal host of provider %q", c.host, c.Provider)
		}
		if c.Class == CredentialExchange && !slices.Contains(tokenEndpoints, c.host) {
			return errors.New("a credential exchange posts only to a declared token endpoint")
		}
		return nil
	}
	switch {
	case c.scheme != "{scheme}" && c.scheme != "https" && c.scheme != "http" || c.host != "{host}":
		return errors.New("a web op's URL starts {scheme}://{host}, or https:// or http:// before {host}")
	case c.Auth != NoAuth:
		return errors.New("a web op never carries a credential")
	case c.Class != Read:
		return errors.New("a web op is a read")
	case rawQuery != "":
		return errors.New("a web op sends no query")
	case c.Subject != "":
		return errors.New("a web op's subject is its URL; it declares none")
	}
	c.Subject = "url:" + c.scheme + "://" + c.host + c.path
	return nil
}

// uses records the placeholders an op's templates use.
type uses struct {
	c    *compiled
	seen map[string]bool
}

// in checks the placeholders s uses: each declared, and an optional one only
// as a whole query value.
func (u uses) in(where, s string, whole bool) error {
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		p, ok := u.c.types[m[1]]
		if !ok {
			return fmt.Errorf("%s uses {%s}, which is not declared", where, m[1])
		}
		if p.Optional && !whole {
			return fmt.Errorf("%s uses optional {%s}; only a whole query value may be optional", where, m[1])
		}
		u.seen[m[1]] = true
	}
	return nil
}

// template checks the URL's placeholders and reads its query, which the
// template writes escaped, as a URL is; bind encodes the query again, so it
// is held decoded.
func (u uses) template(rawQuery string) error {
	c := u.c
	if err := u.in("the URL host", c.scheme+"://"+c.host, false); err != nil {
		return err
	}
	if err := u.in("the URL path", c.path, false); err != nil {
		return err
	}
	for kv := range strings.SplitSeq(rawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		var err error
		if k, err = url.QueryUnescape(k); err != nil {
			return fmt.Errorf("query key %q is not escaped as a URL's is", k)
		}
		if v, err = url.QueryUnescape(v); err != nil {
			return fmt.Errorf("query value %q is not escaped as a URL's is", v)
		}
		whole := placeholder.FindString(v) == v && v != ""
		if err := u.in("the query", v, whole); err != nil {
			return err
		}
		c.query = append(c.query, [2]string{k, v})
	}
	return nil
}

// subject checks the op's subject. Every placeholder that picks the
// target, in the host or the path, is in the subject, so the subject
// admitted is the target sent to. Only the query (a page, a cursor) may
// vary outside it.
func (u uses) subject() error {
	c := u.c
	switch {
	case c.Class == Read && c.Subject == "":
		return errors.New("declares no subject")
	case c.Class != Read && c.Subject != "":
		return fmt.Errorf("a %s op has no subject", c.Class)
	}
	if err := u.in("the subject", c.Subject, false); err != nil {
		return err
	}
	inSubject := map[string]bool{}
	for _, m := range placeholder.FindAllStringSubmatch(c.Subject, -1) {
		inSubject[m[1]] = true
	}
	for _, m := range placeholder.FindAllStringSubmatch(c.scheme+"://"+c.host+c.path, -1) {
		if !inSubject[m[1]] {
			return fmt.Errorf("{%s} picks the target but is not in the subject", m[1])
		}
	}
	for _, kv := range c.query {
		for _, m := range placeholder.FindAllStringSubmatch(kv[1], -1) {
			if t := c.types[m[1]].Type; !inSubject[m[1]] && t != Cursor && t != Count {
				return fmt.Errorf("{%s} in the query is not a page or a cursor, so it must be in the subject", m[1])
			}
		}
	}
	return nil
}

// unused refuses a parameter no template uses.
func (u uses) unused() error {
	for name := range u.c.types {
		if !u.seen[name] {
			return fmt.Errorf("parameter %q is declared but not used", name)
		}
	}
	return nil
}

// checkResponse checks what the op declares about its response: content
// types, a size cap and the fields it keeps.
func (c *compiled) checkResponse(prov provider) error {
	if c.Method != TLS && len(c.Accept) == 0 {
		return errors.New("declares no response content type")
	}
	if c.Method != TLS && c.MaxBytes <= 0 {
		return errors.New("declares no size cap")
	}
	if !prov.web && c.Method == GET && len(c.Keep) == 0 && c.Class != CredentialExchange {
		return errors.New("declares no fields it keeps")
	}
	return c.validateBody()
}

// pageKeys are the query keys a set builder may send its cursor and its
// page size under, per provider.
var pageKeys = map[string]struct{ cursor, size string }{
	"google": {cursor: "pageToken", size: "maxResults"},
}

// wholeTenant checks that a users list building the excluded-subject set
// reads every user: the set replaces the tenant's, so a filter such as
// isAdmin=true would leave the excluded users unclassified. It sends its
// cursor and at most one page size, each once and under the provider's own
// key for it, and no other query but a literal customer.
func (c *compiled) wholeTenant() error {
	l := c.List
	keys, ok := pageKeys[c.Provider]
	if !ok || l.Next == nil {
		return fmt.Errorf("provider %q has no users list that builds the excluded-subject set", c.Provider)
	}
	fail := func(k string) error {
		return fmt.Errorf("a users list that builds the excluded-subject set has no filter %q", k)
	}
	for _, p := range c.Params {
		if p.Name != l.Next.Param && p.Type != Count {
			return fmt.Errorf("a users list that builds the excluded-subject set takes no parameter %q", p.Name)
		}
	}
	used := map[string]int{}
	for _, kv := range c.query {
		name := strings.Trim(kv[1], "{}")
		switch {
		case kv[0] == keys.cursor && kv[1] == "{"+l.Next.Param+"}":
		case kv[0] == keys.size && kv[1] == "{"+name+"}" && c.types[name].Type == Count:
		case kv[0] == "customer" && !strings.Contains(kv[1], "{"):
		default:
			return fail(kv[0])
		}
		if used[kv[0]]++; used[kv[0]] > 1 {
			return fail(kv[0])
		}
		if strings.Contains(kv[1], "{") {
			if used["{"+name+"}"]++; used["{"+name+"}"] > 1 {
				return fail(kv[0])
			}
		}
	}
	return nil
}

var (
	fieldPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	mediaType = regexp.MustCompile(`^([a-z0-9][a-z0-9!#$&^_.+-]*|\*)/([a-z0-9][a-z0-9!#$&^_.+-]*|\*)$`)
)

// isJSON reports whether a media type is JSON: application/json or a
// +json type such as application/vnd.github+json.
func isJSON(t string) bool { return t == "application/json" || strings.HasSuffix(t, "+json") }

// validateBody checks what an op declares about its response: content
// types, the fields it keeps, and a list's items, exclusion and pages.
func (c *compiled) validateBody() error {
	op := c.Op
	jsonTypes := 0
	for _, t := range op.Accept {
		if !mediaType.MatchString(t) {
			return fmt.Errorf("accepts %q, which is not a media type", t)
		}
		if isJSON(t) {
			jsonTypes++
		}
	}
	if jsonTypes > 0 && jsonTypes < len(op.Accept) {
		return errors.New("accepts JSON and other types; a JSON op accepts only JSON")
	}
	c.json = jsonTypes > 0
	if (len(op.Keep) > 0 || op.List != nil) && !c.json {
		return errors.New("keeps fields or lists items, so it accepts only JSON")
	}
	if c.json && op.Method == GET && len(op.Keep) == 0 {
		return errors.New("accepts JSON but declares no fields it keeps")
	}
	for _, k := range op.Keep {
		if !fieldPath.MatchString(k) {
			return fmt.Errorf("keeps %q, which is not a field path", k)
		}
	}
	c.keep = newKeepTree(op.Keep)
	for _, p := range op.Params {
		c.users = c.users || p.Type == UserKey
	}
	l := op.List
	if l == nil {
		return nil
	}
	if l.Items == "" || l.Kind == "" {
		return errors.New("a list op declares its items and their kind")
	}
	if l.Items != "$" && !fieldPath.MatchString(l.Items) {
		return fmt.Errorf("items %q is not $ or a field path", l.Items)
	}
	switch l.Kind {
	case KindRepo, KindUser, KindOrgUnit, KindProject, KindOther, KindName:
	default:
		return fmt.Errorf("item kind %q is unknown", l.Kind)
	}
	if (l.Kind == KindName) != (l.Names != "") {
		return errors.New("a list of name records, and only one, declares its names field")
	}
	if l.Names != "" && !fieldPath.MatchString(l.Names) {
		return fmt.Errorf("names %q is not a field path", l.Names)
	}
	if l.Kind.excludable() && l.ExcludeKey == "" {
		return fmt.Errorf("a list of %s items declares no exclusion key", l.Kind)
	}
	if !l.Kind.excludable() && l.ExcludeKey != "" {
		return fmt.Errorf("a list of %s items has nothing an exclude matches", l.Kind)
	}
	if (len(l.UserKeys) > 0 || len(l.UserIDs) > 0) && l.Kind != KindUser {
		return errors.New("only a users list names the keys of the users it drops")
	}
	if len(l.UserKeys) > 0 && len(l.UserIDs) == 0 {
		return errors.New("a users list that builds the excluded-subject set names the fields that identify a user")
	}
	if len(l.UserKeys) > 0 {
		if err := c.wholeTenant(); err != nil {
			return err
		}
	}
	for _, f := range slices.Concat([]string{l.ExcludeKey, l.UserRef}, l.UserKeys, l.UserIDs) {
		if f != "" && !fieldPath.MatchString(f) {
			return fmt.Errorf("item field %q is not a field path", f)
		}
	}
	c.users = c.users || l.UserRef != ""
	if l.Next == nil {
		if l.MaxPages != 0 {
			return errors.New("declares a page limit but no pages")
		}
		return nil
	}
	if l.MaxPages < 1 {
		return errors.New("a paged list declares its page limit")
	}
	p, ok := c.types[l.Next.Param]
	if !ok || p.Type != Cursor && p.Type != Count || !p.Optional {
		return fmt.Errorf("the cursor %q is not an optional Cursor or Count parameter", l.Next.Param)
	}
	for _, kv := range c.query {
		if kv[1] == "{"+l.Next.Param+"}" {
			c.nextKey = kv[0]
		}
	}
	if c.nextKey == "" {
		return fmt.Errorf("the cursor %q is not a whole query value", l.Next.Param)
	}
	if l.Next.Field != "" && !fieldPath.MatchString(l.Next.Field) {
		return fmt.Errorf("the next-cursor field %q is not a field path", l.Next.Field)
	}
	return nil
}

// Registry is the compiled list of ops a gate admits. It is built from Go
// values only; no flag, file or target adds an op.
type Registry struct {
	ops map[string]*compiled
}

// NewRegistry validates every op and refuses the list on the first broken
// invariant, naming it.
func NewRegistry(ops ...Op) (*Registry, error) {
	r := &Registry{ops: map[string]*compiled{}}
	for _, op := range ops {
		c, err := validate(op)
		if err != nil {
			return nil, err
		}
		if _, dup := r.ops[op.ID]; dup {
			return nil, fmt.Errorf("op %q is registered twice", op.ID)
		}
		if c.List != nil && len(c.List.UserKeys) > 0 {
			for _, o := range r.ops {
				if o.Provider == c.Provider && o.List != nil && len(o.List.UserKeys) > 0 {
					return nil, fmt.Errorf("op %q: %q already builds the %s excluded-subject set", op.ID, o.ID, op.Provider)
				}
			}
		}
		r.ops[op.ID] = c
	}
	return r, nil
}

var (
	loginRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	labelRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	cursorRE = regexp.MustCompile(`^[A-Za-z0-9+/=_.:-]{1,512}$`)
	pathRE   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
)

// bindValue checks one value against its type and returns its canonical
// form: names lowercased, a path as its normalized escaping.
func bindValue(t ParamType, v string) (string, error) {
	switch t {
	case Login:
		if !loginRE.MatchString(v) {
			return "", errors.New("not a GitHub login")
		}
		return strings.ToLower(v), nil
	case RepoName:
		if !repoRE.MatchString(v) || v == "." || v == ".." {
			return "", errors.New("not a repository name")
		}
		return strings.ToLower(v), nil
	case DNSName:
		return dnsName(v)
	case Host:
		return hostValue(v)
	case Scheme:
		if v != "https" && v != "http" {
			return "", errors.New("not https or http")
		}
		return v, nil
	case URLPath:
		if !pathRE.MatchString(v) {
			return "", errors.New("not an absolute path")
		}
		dec, err := url.PathUnescape(v)
		if err != nil {
			return "", errors.New("bad percent-encoding")
		}
		clean := path.Clean(dec)
		if strings.HasSuffix(dec, "/") && clean != "/" {
			clean += "/"
		}
		if clean != dec {
			return "", errors.New("has dot segments or empty segments")
		}
		return (&url.URL{Path: dec}).EscapedPath(), nil
	case Cursor:
		if !cursorRE.MatchString(v) {
			return "", errors.New("not a cursor")
		}
		return v, nil
	case Count:
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 || strconv.Itoa(n) != v {
			return "", errors.New("not a count from 1 to 10000")
		}
		return v, nil
	case UserKey:
		return userKey(v)
	}
	return "", errors.New("unknown type")
}

var (
	userIDRE    = regexp.MustCompile(`^[0-9]{1,30}$`)
	mailLocalRE = regexp.MustCompile(`^[A-Za-z0-9._%+'-]{1,64}$`)
)

// userKey is a Workspace user's numeric id or address, lowercased: the
// form the excluded-subject set holds.
func userKey(v string) (string, error) {
	if userIDRE.MatchString(v) {
		return v, nil
	}
	local, domain, ok := strings.Cut(v, "@")
	if !ok || !mailLocalRE.MatchString(local) {
		return "", errors.New("not a user id or address")
	}
	d, err := dnsName(domain)
	if err != nil {
		return "", errors.New("not a user id or address")
	}
	return strings.ToLower(local) + "@" + d, nil
}

func dnsName(v string) (string, error) {
	d := strings.ToLower(v)
	labels := strings.Split(d, ".")
	if len(d) > 253 || len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", errors.New("not a DNS name")
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", errors.New("not a DNS name")
		}
	}
	return d, nil
}

// hostValue is a name or an address literal with an optional port.
func hostValue(v string) (string, error) {
	var h, port string
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]")
		if end < 0 {
			return "", errors.New("not a host")
		}
		h, port = v[1:end], strings.TrimPrefix(v[end+1:], ":")
		a, err := netip.ParseAddr(h)
		if err != nil || !a.Is6() || a.Zone() != "" || v[end+1:] != "" && !strings.HasPrefix(v[end+1:], ":") {
			return "", errors.New("not a host")
		}
		if a.Is4In6() {
			return "", errors.New("an IPv4-mapped address is written as its IPv4 address")
		}
		// Canonical, so a subject compares equal to the root or exclude
		// written the other way.
		h = "[" + a.String() + "]"
	} else if i := strings.LastIndex(v, ":"); i >= 0 {
		h, port = v[:i], v[i+1:]
		if a, err := netip.ParseAddr(h); err == nil {
			if !a.Is4() {
				return "", errors.New("an IPv6 host is written in brackets")
			}
			h = a.String()
		} else if h, err = dnsName(h); err != nil {
			return "", err
		}
	} else if a, err := netip.ParseAddr(v); err == nil {
		if !a.Is4() {
			return "", errors.New("an IPv6 host is written in brackets")
		}
		h = a.String()
	} else if h, err = dnsName(v); err != nil {
		return "", err
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("not a port")
		}
		return h + ":" + port, nil
	}
	return h, nil
}

// bound is a request bound to its op: the URL to send, the subject to
// admit, and the canonical parameters for the audit line.
type bound struct {
	op      *compiled
	params  map[string]string
	url     *url.URL
	name    string // the host name or address literal, without brackets
	port    uint16
	subject string
}

// bind checks every parameter against its type and fills the templates.
func (c *compiled) bind(in map[string]string) (*bound, error) {
	vals := map[string]string{}
	for name, v := range in {
		p, ok := c.types[name]
		if !ok {
			return nil, fmt.Errorf("parameter %q is not declared", name)
		}
		canon, err := bindValue(p.Type, v)
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %v", name, err)
		}
		vals[name] = canon
	}
	for name, p := range c.types {
		if _, ok := vals[name]; !ok && !p.Optional {
			return nil, fmt.Errorf("parameter %q is missing", name)
		}
	}
	fill := func(s string, escape bool) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string {
			v := vals[m[1:len(m)-1]]
			if escape && c.types[m[1:len(m)-1]].Type != URLPath {
				return url.PathEscape(v)
			}
			return v
		})
	}
	u := &url.URL{Scheme: fill(c.scheme, false), Host: fill(c.host, false)}
	rawPath := fill(c.path, true)
	p, err := url.PathUnescape(rawPath)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawPath = p, rawPath
	if never := neverReadIn(p); never != "" {
		return nil, fmt.Errorf("the path reads %s, which returns credentials and is never sent", never)
	}
	q := url.Values{}
	var keys []string
	for _, kv := range c.query {
		name := strings.Trim(kv[1], "{}")
		if p, ok := c.types[name]; ok && p.Optional && vals[name] == "" {
			continue
		}
		q.Set(kv[0], fill(kv[1], false))
		keys = append(keys, kv[0])
	}
	if len(keys) > 0 {
		u.RawQuery = q.Encode()
	}

	b := &bound{op: c, params: vals, url: u}
	b.name = u.Hostname()
	b.port = map[string]uint16{"https": 443, "http": 80}[u.Scheme]
	if ps := u.Port(); ps != "" {
		n, _ := strconv.ParseUint(ps, 10, 16) // a Host parameter's port is 1–65535
		if uint16(n) == b.port {
			u.Host = strings.TrimSuffix(u.Host, ":"+ps)
		}
		b.port = uint16(n)
	}
	if c.Subject != "" {
		b.subject = placeholder.ReplaceAllStringFunc(c.Subject, func(m string) string {
			if m == "{host}" {
				return u.Host // the default port dropped, as a url id has it
			}
			return vals[m[1:len(m)-1]]
		})
	}
	return b, nil
}
