package gate

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/policy"
)

// The response pipeline (docs/spec/scope.md, "Responses"): read with a
// cap, check the content type, redact the raw bytes, parse the redacted
// ones, drop excluded items, project to the declared fields, cut, store.

// Population is what one page of a list held and what of it reached
// evidence. A population the gate marks incomplete proves presence, never
// absence: a rule may fire on an item it saw, is never disproved, and
// prints a count from it as "at least" (docs/spec/scope.md, "Responses").
type Population struct {
	// Page is the page's number, 1 for the first.
	Page int
	// Items is how many items the page held; Kept how many reached the
	// body.
	Items, Kept int
	// Dropped counts the items taken out, by the exclude entry that took
	// them, "unattributable" for an item without its key, or
	// "out_of_scope". Never by name.
	Dropped []Drop
	// Incomplete names what keeps the list from being the whole
	// population: "dropped" when any item was taken out, "page_limit" when
	// the op's page limit stopped it with pages left, "next_page_unreadable"
	// when the provider's next cursor did not bind.
	Incomplete []string
	// More says another page follows: ask for it with Request.NextOf set
	// to this response's request id.
	More bool
}

// Drop is a count of items one rule took out of a list.
type Drop struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// Unavailable codes the pipeline gives a 2xx response it cannot keep.
const (
	codeContentType   = "unexpected_content_type"
	codeEncoding      = "unexpected_content_encoding"
	codeBomb          = "compression_bomb"
	codeTooLarge      = "response_too_large"
	codeBrokeJSON     = "redaction_broke_structure"
	codeMalformed     = "malformed_response"
	codeExclusionUnkn = "exclusion_unknown"
)

func codeDetail(code string, limit int) string {
	switch code {
	case codeWorkflowLimit:
		return "workflow decoding or YAML structure reached a compiled limit (512 KiB, 20,000 nodes or depth 40)"
	case codeContentType:
		return "the response's content type is not one the op accepts, so its body was hashed and not kept"
	case codeEncoding:
		return "the body was encoded with something other than gzip, which is the only encoding scheck reads"
	case codeBomb:
		return "the body decompressed past the op's cap at more than 100 times its size, so nothing was kept"
	case codeTooLarge:
		return fmt.Sprintf("larger than the op's cap of %d bytes", limit)
	case codeBrokeJSON:
		return "redaction left the JSON unparseable, so nothing was kept"
	case codeMalformed:
		return "the body is not the JSON the op expects, so nothing was kept"
	case codeExclusionUnkn:
		return "the users list has not been read whole, so users in an excluded organizational unit cannot be told apart; the request was not sent"
	}
	return ""
}

// bombRatio is the decompression ratio past the cap that makes a gzip body
// a compression bomb rather than a large page.
const bombRatio = 100

// countingReader counts the bytes read from the wire.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// gzipSource feeds a gzip reader byte by byte, so that n counts the
// compressed bytes decompression consumed, not what a buffer read ahead:
// that count is what tells a bomb from a large page. capped says the
// compressed bytes ran past their own cap.
type gzipSource struct {
	r      *bufio.Reader
	under  *io.LimitedReader
	n      int64
	capped bool
	// ended says the body itself ended cleanly, so a gzip stream that
	// stops short is malformed, not cut by the connection.
	ended bool
}

func (g *gzipSource) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	g.n += int64(n)
	return n, g.check(err)
}

func (g *gzipSource) ReadByte() (byte, error) {
	b, err := g.r.ReadByte()
	if err == nil {
		g.n++
	}
	return b, g.check(err)
}

func (g *gzipSource) check(err error) error {
	if errors.Is(err, io.EOF) {
		if g.under.N <= 0 {
			g.capped = true
		} else {
			g.ended = true
		}
	}
	return err
}

// readBody reads a body up to max+1 decompressed bytes, so the caller can
// tell a body that ended from one it cut. Only gzip is read, and its
// compressed bytes are capped too. code is set for a body the op cannot
// keep; err for one the server stopped sending, which is never a read.
func readBody(resp *http.Response, max int) (raw []byte, wire int64, code string, err error) {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		cr := &countingReader{r: resp.Body}
		raw, err = io.ReadAll(io.LimitReader(cr, int64(max)+1))
		return raw, cr.n, "", err
	case "gzip":
		under := &io.LimitedReader{R: resp.Body, N: int64(2*max + 64<<10)}
		src := &gzipSource{r: bufio.NewReader(under), under: under}
		zr, zerr := gzip.NewReader(src)
		switch {
		case zerr == nil:
		case src.capped:
			return nil, src.n, codeTooLarge, nil
		case errors.Is(zerr, io.EOF) && src.n == 0:
			return nil, 0, "", nil // an empty body
		case corrupt(zerr), src.ended:
			return nil, src.n, codeMalformed, nil
		default:
			return nil, src.n, "", zerr
		}
		raw, err = io.ReadAll(io.LimitReader(zr, int64(max)+1))
		switch {
		case src.capped:
			return nil, src.n, codeTooLarge, nil
		case err != nil && (corrupt(err) || src.ended && errors.Is(err, io.ErrUnexpectedEOF)):
			return nil, src.n, codeMalformed, nil
		case len(raw) > max && src.n*bombRatio < int64(len(raw)):
			return nil, src.n, codeBomb, nil
		}
		return raw, src.n, "", err
	}
	return nil, 0, codeEncoding, nil
}

// corrupt tells a gzip stream that is malformed from a connection that
// broke under it, which is a body cut short.
func corrupt(err error) bool {
	var ce flate.CorruptInputError
	var ie flate.InternalError
	return errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) || errors.As(err, &ce) || errors.As(err, &ie)
}

// accepts reports whether a Content-Type is one the op accepts: an exact
// type, a wildcard, or JSON for JSON (GitHub answers application/json to
// an Accept of application/vnd.github+json).
func accepts(accept []string, contentType string) bool {
	if slices.Contains(accept, "*/*") {
		return true // even a page with no Content-Type
	}
	// A bad parameter still names the type ("text/html; charset").
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		return false
	}
	for _, a := range accept {
		switch {
		case a == "*/*", a == mt, isJSON(a) && isJSON(mt):
			return true
		case strings.HasSuffix(a, "/*") && strings.HasPrefix(mt, strings.TrimSuffix(a, "*")):
			return true
		}
	}
	return false
}

// keepTree is an op's Keep as a tree: a nil child keeps the whole value.
type keepTree map[string]keepTree

func newKeepTree(paths []string) keepTree {
	if len(paths) == 0 {
		return nil
	}
	root := keepTree{}
	for _, p := range paths {
		t := root
		parts := strings.Split(p, ".")
		for i, part := range parts {
			child, seen := t[part]
			if seen && child == nil {
				break // an ancestor is kept whole
			}
			if i == len(parts)-1 {
				t[part] = nil
				break
			}
			if !seen {
				child = keepTree{}
				t[part] = child
			}
			t = child
		}
	}
	return root
}

// omit marks a value projection leaves out.
type omitted struct{}

// project keeps only the declared fields. A field the response lacks stays
// absent, which a rule reads as unknown; null is kept; a value of a shape
// the op did not declare (a string where it keeps fields of an object) is
// left out.
func project(v any, t keepTree) any {
	if t == nil {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, sub := range t {
			if fv, ok := x[k]; ok {
				if pv := project(fv, sub); pv != (omitted{}) {
					out[k] = pv
				}
			}
		}
		return out
	case []any:
		out := []any{}
		for _, e := range x {
			if pv := project(e, t); pv != (omitted{}) {
				out = append(out, pv)
			}
		}
		return out
	case nil:
		return nil
	}
	return omitted{}
}

// fieldAt follows a dotted path through objects.
func fieldAt(v any, path string) (any, bool) {
	for part := range strings.SplitSeq(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[part]; !ok {
			return nil, false
		}
	}
	return v, true
}

// scalarAt is a string or number field as text; "" when it is absent,
// another shape, or carries a redaction marker, which names nothing.
func scalarAt(v any, path string) string {
	f, ok := fieldAt(v, path)
	if !ok {
		return ""
	}
	var s string
	switch x := f.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	}
	if strings.Contains(s, "[REDACTED:") {
		return ""
	}
	return s
}

// stringsAt collects every string a path reaches, through arrays: a user's
// addresses are emails[].address.
func stringsAt(v any, path string) []string {
	head, rest, more := strings.Cut(path, ".")
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, stringsAt(e, path)...)
		}
		return out
	case map[string]any:
		f, ok := x[head]
		if !ok {
			return nil
		}
		if more {
			return stringsAt(f, rest)
		}
		switch y := f.(type) {
		case string:
			return []string{y}
		case json.Number:
			return []string{y.String()}
		case []any:
			var out []string
			for _, e := range y {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

// orgUnitUnder reports whether unit path p is ex or under it, by whole
// segments and case-insensitively, so /Board holds /Board/Sub and not
// /Boardroom (docs/spec/scope.md, "Admission").
func orgUnitUnder(p, ex string) bool {
	ps := strings.Split(strings.Trim(p, "/"), "/")
	es := strings.Split(strings.Trim(ex, "/"), "/")
	if strings.Trim(ex, "/") == "" {
		return true // the root unit holds every unit
	}
	if len(ps) < len(es) {
		return false
	}
	for i := range es {
		if !strings.EqualFold(ps[i], es[i]) {
			return false
		}
	}
	return true
}

// userSet is the excluded-subject set of a tenant: every key of a user in
// an excluded organizational unit, or whose unit is unknown, with the rule
// that took the user out.
type userSet struct {
	excluded map[string]string // user key → the rule that took the user out
	seen     map[string]bool   // every key of every user the list returned
	domains  map[string]bool   // the domains of the addresses it returned
}

// newUserSet starts the set of a tenant with the tenant's own domain from
// its asset id: an address in it the list never returned is unattributable
// even when the list returned no one there.
func newUserSet(asset string) *userSet {
	u := &userSet{excluded: map[string]string{}, seen: map[string]bool{}, domains: map[string]bool{}}
	if d, ok := strings.CutPrefix(asset, "saas:google-workspace:"); ok {
		if d, err := dnsName(d); err == nil {
			u.domains[d] = true
		}
	}
	return u
}

func (u *userSet) clone() *userSet {
	if u == nil {
		return nil
	}
	return &userSet{excluded: maps.Clone(u.excluded), seen: maps.Clone(u.seen), domains: maps.Clone(u.domains)}
}

// add records one user of the list: ids identify it inside the tenant and
// give the tenant's domains; every key, contact addresses too, is excluded
// with it when rule is set ("" when it was kept).
func (u *userSet) add(ids, keys []string, rule string) {
	for _, k := range ids {
		u.seen[k] = true
		if _, d, ok := strings.Cut(k, "@"); ok {
			u.domains[d] = true
		}
	}
	if rule != "" {
		for _, k := range slices.Concat(ids, keys) {
			u.excluded[k] = rule
		}
	}
}

// rule is the rule that takes out an item naming user key k: the rule that
// dropped the user, or "unattributable" for an id or a tenant address the
// list never returned (a user hidden from the list may be an excluded
// one). An address in another domain is "": an external member is
// evidence, not an excluded person. A nil set excludes no one.
func (u *userSet) rule(k string) string {
	if u == nil {
		return ""
	}
	if r := u.excluded[k]; r != "" {
		return r
	}
	if u.seen[k] {
		return ""
	}
	if _, d, isAddr := strings.Cut(k, "@"); !isAddr || u.domains[d] {
		return "unattributable"
	}
	return ""
}

// page is a list page the gate returned with another after it: what the
// next request must repeat, the cursor the gate keeps for it, and the
// excluded-subject set a users list is building.
type page struct {
	asset, op string
	params    map[string]string // canonical, without the cursor
	cursor    string
	n         int
	users     *userSet // never written once the page is stored
	// reading is set while a request for the page after it is in flight,
	// so a next_of is read once at a time and a set never forks.
	reading bool
}

// linkNext finds the rel="next" target of a Link header.
var linkEntry = regexp.MustCompile(`<([^>]*)>\s*((?:;\s*[^;,]*)*)`)
var relNext = regexp.MustCompile(`(?i);\s*rel\s*=\s*"?([^";]*\s)?next(\s[^";]*)?"?\s*(;|$)`)

func linkNext(h string) (string, bool) {
	for _, m := range linkEntry.FindAllStringSubmatch(h, -1) {
		if relNext.MatchString(m[2]) {
			return m[1], true
		}
	}
	return "", false
}

// shaped is a 2xx JSON body after the pipeline: the projected body, the
// list's population, or the code that kept it out.
type shaped struct {
	body []byte
	pop  *Population
	code string
	// next is the page state for a following page; done the
	// excluded-subject set a users list finished.
	next *page
	done *userSet
}

// shape parses the redacted body, drops excluded items, projects to the
// op's fields and reads the next cursor. raw is never parsed: only
// redacted is (docs/spec/scope.md, "Responses").
func (g *Gate) shape(r Request, a admitted, redacted []byte, h http.Header) shaped {
	op := a.b.op
	doc, code := parseRedacted(redacted)
	if code != "" {
		return shaped{code: code}
	}
	if op.List == nil {
		return shaped{body: marshal(project(doc, op.keep))}
	}
	items, code := listItems(op.List, doc)
	if code != "" {
		return shaped{code: code}
	}
	n := 1
	if a.prev != nil {
		n = a.prev.n + 1
	}
	ous := g.scope.OrgUnits(r.Asset)
	kept, pop, building := g.filter(r, a, items, n, ous)
	out := shaped{body: marshal(kept), pop: pop}
	g.pageAfter(&out, r, a, doc, h, building, len(ous) > 0)
	return out
}

// parseRedacted parses a redacted JSON body. RedactJSON keeps the structure
// by construction and checked the raw bytes were one document, so a parse
// failure here means redaction broke it.
func parseRedacted(redacted []byte) (any, string) {
	dec := json.NewDecoder(bytes.NewReader(redacted))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, codeBrokeJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, codeBrokeJSON
	}
	return doc, ""
}

// listItems finds a list's item array; a missing array in an object is an
// empty page, as Google leaves an empty list out.
func listItems(l *List, doc any) ([]any, string) {
	if l.Items == "$" {
		arr, ok := doc.([]any)
		if !ok {
			return nil, codeMalformed
		}
		return arr, ""
	}
	if f, ok := fieldAt(doc, l.Items); ok && f != nil {
		arr, ok := f.([]any)
		if !ok {
			return nil, codeMalformed
		}
		return arr, ""
	}
	if _, isObj := doc.(map[string]any); !isObj {
		return nil, codeMalformed
	}
	return nil, ""
}

// filter drops the page's excluded items before anything is stored and
// projects the rest, counting what it dropped by rule. A users list that
// builds the excluded-subject set adds every user it saw to this page's
// own copy of the set: the page before keeps its own, so nothing another
// request reads is written here.
func (g *Gate) filter(r Request, a admitted, items []any, n int, ous []OrgUnit) ([]any, *Population, *userSet) {
	op, l := a.b.op, a.b.op.List
	var building *userSet
	if len(l.UserKeys) > 0 {
		building = newUserSet(r.Asset)
		if a.prev != nil {
			building = a.prev.users.clone()
		}
	}
	var set *userSet
	if l.UserRef != "" {
		set = g.excludedUsers(r.Asset)
	}
	pop := &Population{Page: n, Items: len(items)}
	counts := map[string]int{}
	kept := []any{}
	dropped := map[string]bool{} // rule and name, so a name in many certificates counts once
	for _, it := range items {
		if l.Names != "" {
			var ok bool
			if it, ok = g.names(l.Names, it, counts, dropped); !ok {
				continue
			}
		}
		rule := g.dropRule(r.Asset, l, it, set, ous)
		if building != nil {
			building.add(userKeysAt(it, l.UserIDs), userKeysAt(it, l.UserKeys), rule)
		}
		if rule == "" {
			kept = append(kept, project(it, op.keep))
			continue
		}
		counts[rule]++
	}
	pop.Kept = len(kept)
	for rule, c := range counts {
		pop.Dropped = append(pop.Dropped, Drop{Rule: rule, Count: c})
	}
	slices.SortFunc(pop.Dropped, func(x, y Drop) int { return strings.Compare(x.Rule, y.Rule) })
	// Something that is not a name was never part of the population.
	if slices.ContainsFunc(pop.Dropped, func(d Drop) bool { return d.Rule != ruleNotAName }) {
		pop.Incomplete = append(pop.Incomplete, "dropped")
	}
	return kept, pop, building
}

// pageAfter reads the next cursor: the page state for the page after this
// one, a list left incomplete, or, on the last page, the excluded-subject
// set a users list finished.
func (g *Gate) pageAfter(out *shaped, r Request, a admitted, doc any, h http.Header, building *userSet, unitExcluded bool) {
	l, pop := a.b.op.List, out.pop
	cursor, found := g.nextCursor(a.b.op, doc, h)
	switch {
	case !found:
		// The set exists only for an excluded unit: with none, nobody is
		// excluded and nothing is refused by it. A list that returned no
		// one while a unit is excluded tells no excluded user apart from a
		// kept one: the set stays unknown.
		if building != nil && unitExcluded && len(building.seen) > 0 {
			out.done = building
		}
	case cursor == "":
		pop.Incomplete = append(pop.Incomplete, "next_page_unreadable")
	case pop.Page >= l.MaxPages:
		pop.Incomplete = append(pop.Incomplete, "page_limit")
	default:
		params := maps.Clone(a.b.params)
		delete(params, l.Next.Param)
		pop.More = true
		out.next = &page{asset: r.Asset, op: r.Op, params: params, cursor: cursor, n: pop.Page, users: building}
	}
}

// ruleNotAName counts identities in a name record that are not DNS names;
// ruleRedacted counts names redact_extra matches, which are dropped, never
// marked: a marker stored as a name would become a request target.
const (
	ruleNotAName = "not_a_name"
	ruleRedacted = "redacted"
)

// names replaces a name record's names field with its valid DNS names
// (List.Names), counting each distinct name it drops once per rule; false
// when none is left.
func (g *Gate) names(field string, item any, counts map[string]int, dropped map[string]bool) (any, bool) {
	drop := func(rule, name string) {
		if k := rule + "\x00" + name; !dropped[k] {
			dropped[k] = true
			counts[rule]++
		}
	}
	obj, ok := item.(map[string]any)
	if !ok {
		counts["unattributable"]++
		return nil, false
	}
	raw, ok := obj[field].(string)
	if !ok {
		// Missing, or not the string of names the op declares: the record
		// cannot be read, and the population is not complete without it.
		counts["unattributable"]++
		return nil, false
	}
	var kept []any
	for entry := range strings.SplitSeq(raw, "\n") {
		written := strings.TrimSuffix(strings.TrimSpace(entry), ".")
		entry = strings.ToLower(written)
		if entry == "" {
			continue
		}
		base, wildcard := strings.CutPrefix(entry, "*.")
		if strings.Contains(entry, "[redacted:") {
			// The body's own redaction marked it: a name hidden, not an
			// identity that was never one.
			drop(ruleRedacted, entry)
			continue
		}
		if d, err := dnsName(base); err != nil || d != base {
			drop(ruleNotAName, entry)
			continue
		}
		// Each name on its own, as written and lowercased: the body was
		// redacted whole, which an anchored or cased pattern misses.
		if g.redact(written) != written || g.redact(entry) != entry || g.redact(base) != base {
			drop(ruleRedacted, base)
			continue
		}
		if x := g.scope.Name(base); x != "" {
			drop(x, base)
			continue
		}
		if wildcard {
			entry = "*." + base
		}
		if !slices.Contains(kept, any(entry)) {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		return nil, false
	}
	out := maps.Clone(obj)
	out[field] = kept
	return out, true
}

// dropRule is the rule that takes an item out of a list, or "" to keep it.
func (g *Gate) dropRule(asset string, l *List, item any, set *userSet, ous []OrgUnit) string {
	if l.Kind.excludable() {
		key := scalarAt(item, l.ExcludeKey)
		if key == "" {
			return "unattributable"
		}
		switch l.Kind {
		case KindRepo, KindProject:
			if l.Kind == KindRepo && strings.Count(key, "/") != 1 {
				return "unattributable"
			}
			st := g.scope.Subject(asset, strings.ReplaceAll(l.Subject, "{key}", strings.ToLower(key)))
			switch {
			case st.ExcludedBy != "":
				return st.ExcludedBy
			case !st.UnderAsset || st.Root == "":
				return "out_of_scope"
			}
		case KindUser, KindOrgUnit:
			if !strings.HasPrefix(key, "/") {
				return "unattributable"
			}
			for _, ou := range ous {
				if orgUnitUnder(key, ou.Path) {
					return ou.ExcludedBy
				}
			}
		}
	}
	if l.UserRef != "" {
		ref := scalarAt(item, l.UserRef)
		if ref == "" {
			return "unattributable"
		}
		// A reference that is not a user id or an address cannot be told
		// apart from an excluded user.
		key, err := userKey(ref)
		if err != nil {
			return "unattributable"
		}
		if rule := set.rule(key); rule != "" {
			return rule
		}
	}
	return ""
}

// nextCursor reads the provider's next cursor and binds it to its type.
// found says the provider pointed at a next page; cursor is "" when that
// pointer did not bind. A Link URL is never used: only its cursor is, and
// the request is rebuilt from the template.
func (g *Gate) nextCursor(op *compiled, doc any, h http.Header) (string, bool) {
	l := op.List
	if l.Next == nil {
		return "", false
	}
	var v string
	if l.Next.Field != "" {
		f, ok := fieldAt(doc, l.Next.Field)
		if !ok || f == nil || f == "" {
			return "", false
		}
		s, _ := f.(string)
		v = s
	} else {
		target, ok := linkNext(strings.Join(h.Values("Link"), ", "))
		if !ok {
			return "", false
		}
		u, err := url.Parse(target)
		if err != nil {
			return "", true
		}
		v = u.Query().Get(op.nextKey)
	}
	canon, err := bindValue(op.types[l.Next.Param].Type, v)
	if err != nil {
		return "", true
	}
	return canon, true
}

// userKeysAt collects the user keys an item holds at the given fields.
func userKeysAt(item any, fields []string) []string {
	var keys []string
	for _, f := range fields {
		for _, v := range stringsAt(item, f) {
			if key, err := userKey(v); err == nil {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// excludedUsers is the asset's excluded-subject set; nil when nothing is
// excluded by organizational unit or the set is unknown.
func (g *Gate) excludedUsers(asset string) *userSet {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.users[asset]
}

// usersKnown reports whether the excluded-subject set of the asset is
// known: nothing is excluded by organizational unit, or a users list was
// read whole (docs/spec/scope.md, "Exclusion in responses").
func (g *Gate) usersKnown(asset string) bool {
	if len(g.scope.OrgUnits(asset)) == 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.users[asset]
	return ok
}

// marshal writes a projected value; it cannot fail on what json.Decode
// produced.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// redactFor is the redactor of an admitted request: the engagement's, plus
// the credential's value when one is attached.
func (g *Gate) redactFor(a admitted) *policy.Redactor {
	if a.cred != nil {
		return g.redactor.WithLiteral("credential", a.cred.secret)
	}
	return g.redactor
}
