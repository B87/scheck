// Browser response rules read only retained gate evidence. Scope and the
// fire/disprove/abstain predicates are docs/spec/web-collector.md,
// "Headers and cookies"; no parser may expand the request surface.
package web

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// URLAsset is declared ownership; it does not grant admission.
type URLAsset struct{ ID, URL string }

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
func (j *judging) urlAsset(raw string) string {
	best, length := "", -1
	for _, a := range j.in.URLAssets {
		if origin(a.URL) == origin(raw) {
			u, _ := url.Parse(a.URL)
			v, _ := url.Parse(raw)
			p := strings.TrimSuffix(u.Path, "/")
			if (v.Path == p || strings.HasPrefix(v.Path, p+"/")) && (len(p) > length || len(p) == length && a.ID < best) {
				best, length = a.ID, len(p)
			}
		}
	}
	if best != "" {
		return best
	}
	u, _ := url.Parse(raw)
	return j.assetOf(u.Hostname())
}
func (j *judging) originAsset(raw string) string {
	best, length := "", -1
	for _, a := range j.in.URLAssets {
		if origin(a.URL) != raw {
			continue
		}
		u, _ := url.Parse(a.URL)
		p := strings.TrimSuffix(u.Path, "/")
		if p == "" {
			return a.ID
		}
		if len(p) > length || len(p) == length && a.ID < best {
			best, length = a.ID, len(p)
		}
	}
	if best != "" {
		return best
	}
	return j.urlAsset(raw)
}
func (j *judging) webVerdict(id, key, kind, reason, excerpt string, ps []Page) Judgment {
	x := Judgment{ID: id, Asset: j.urlAsset(key), Subject: Subject{Kind: kind, Key: key, Label: key}, Verdict: Abstained, Reason: reason, Excerpt: excerpt}
	if kind == "origin" {
		x.Asset = j.originAsset(key)
	}
	for _, p := range ps {
		x.Reads = append(x.Reads, p.RequestID)
	}
	return x
}

var blockMarkers = []struct {
	vendor  string
	markers []string
}{
	{"Cloudflare", []string{"just a moment", "attention required!"}}, {"Akamai", []string{"reference #"}},
	{"Imperva", []string{"incapsula incident id"}}, {"Sucuri", []string{"sucuri website firewall", "access denied - sucuri"}},
	{"AWS WAF", []string{"awswaf", "aws waf"}}, {"Vercel", []string{"vercel security checkpoint"}},
}

func blocked(p Page) string {
	if p.BlockedVendor != "" {
		return p.BlockedVendor
	}
	if p.Status != 403 && p.Status != 429 && p.Status != 503 {
		return ""
	}
	body := strings.ToLower(p.Body)
	for _, v := range blockMarkers {
		for _, m := range v.markers {
			if strings.Contains(body, m) {
				return v.vendor
			}
		}
	}
	return ""
}
func pageReason(p Page) string {
	if v := blocked(p); v != "" {
		return "unavailable:blocked"
	}
	if p.URL == "" || p.Decision == "" {
		return "unavailable:not_read"
	}
	if p.Status == 429 || p.Status >= 500 {
		return "unavailable:http_status"
	}
	if strings.HasPrefix(p.URL, "https:") && (p.TLS == nil || !p.TLS.Verified) {
		return "unavailable:certificate"
	}
	if p.Decision != gate.DecisionSent && p.Decision != "reused" {
		if p.Reason != "" {
			return p.Reason
		}
		return gate.ReasonOf(p.Decision)
	}
	if p.Status < 200 || p.Status >= 400 {
		return "unavailable:http_status"
	}
	return ""
}
func (j *judging) sites() {
	for _, s := range j.in.Evidence.Sites {
		ps := allPages(s)
		// Existing recorded front-page evidence predates Page.URL.
		if len(ps) == 0 {
			s.HTTPS.URL = "https://" + s.Name + "/"
			s.HTTP.URL = "http://" + s.Name + "/"
			ps = allPages(s)
		}
		j.tls(s, ps)
		origins := map[string][]Page{}
		order := []string{}
		for _, p := range ps {
			path := entryOf(p.URL).Path
			if path != "/robots.txt" && path != "/.well-known/security.txt" {
				j.version(p)
			}
			j.secrets(p)
			if s.Declared || p.FirstParty {
				o := origin(p.URL)
				if _, ok := origins[o]; !ok {
					order = append(order, o)
				}
				origins[o] = append(origins[o], p)
			}
		}
		if len(order) > 0 {
			hasHTTP, hasHTTPS := false, false
			for _, o := range order {
				hasHTTP = hasHTTP || strings.HasPrefix(o, "http:")
				hasHTTPS = hasHTTPS || strings.HasPrefix(o, "https:")
			}
			host := s.Name
			tld := preloaded(entryOf("https://" + host + "/").Host)
			if !hasHTTP {
				j.plainHTTP("http://"+host, nil, tld)
			}
			if !hasHTTPS {
				j.hsts("https://"+host, nil, tld)
				j.securityTXT("https://"+host, nil)
			}
		}

		for _, o := range order {
			pages := origins[o]
			u, _ := url.Parse(o)
			tld := preloaded(u.Hostname())
			if u.Scheme == "https" {
				j.hsts(o, pages, tld)
				j.securityTXT(o, pages)
			} else {
				j.plainHTTP(o, pages, tld)
			}
			j.cookies(o, pages)
			j.securityHeaders(o, pages)
		}
	}
}
func (j *judging) hsts(o string, ps []Page, tld string) {
	x := j.webVerdict(finding.IDWebHSTSMissing, o, "origin", "unavailable:not_read", "", ps)
	if tld != "" {
		x.Verdict, x.Reason, x.Excerpt = Disproved, "", "not needed: browsers have ."+tld+" on their built-in HTTPS-only list"
		x.Details = map[string]any{"reason": "tld_preloaded", "tld": tld, "list_version": PreloadVersion}
		j.add(x)
		return
	}
	read, unknown := false, false
	for _, p := range ps {
		if path := entryOf(p.URL).Path; path == "/robots.txt" || path == "/.well-known/security.txt" {
			continue
		}
		if r := pageReason(p); r != "" {
			x.Reason = r
			unknown = true
			continue
		}
		read = true
		v := header(p, "Strict-Transport-Security")
		if marked(v) {
			x.Reason = "unavailable:redacted"
			unknown = true
			continue
		}
		if hstsValid(v) {
			x.Verdict, x.Reason, x.Excerpt = Disproved, "", "response supplies a valid HSTS policy for at least 86400 seconds"
			j.add(x)
			return
		}
	}
	if read && !unknown {
		x.Verdict, x.Reason, x.Excerpt = Fired, "", "No response read supplied a valid HSTS policy for at least 86400 seconds"
	}
	j.add(x)
}

// RFC6797 §6.1: only the first field, one occurrence per directive,
// max-age as decimal or quoted decimal. Unknown extensions do not widen it.
func hstsValid(v string) bool {
	seen := map[string]bool{}
	age := ""
	parts, ok := directiveParts(v)
	if !ok {
		return false
	}
	for _, part := range parts {
		k, val, has := strings.Cut(strings.TrimSpace(part), "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" && !has {
			continue
		}
		if !httpToken(k) || seen[k] {
			return false
		}
		seen[k] = true
		if has {
			val = strings.TrimSpace(val)
			if !httpToken(val) && !quotedValue(val) {
				return false
			}
		}
		if k == "max-age" {
			if !has {
				return false
			}
			age = strings.TrimSpace(val)
			if strings.HasPrefix(age, "\"") {
				age = httpUnquote(age)
			}
		}
		if (k == "includesubdomains" || k == "preload") && has {
			return false
		}
	}
	n, err := strconv.ParseUint(age, 10, 64)
	return err == nil && decimal(age) && n >= 86400
}

// HTTP quoted-pair escapes the next byte literally; it has no hex, octal
// or Unicode escapes. quotedValue has already checked the syntax.
func httpUnquote(v string) string {
	var out strings.Builder
	for i := 1; i < len(v)-1; i++ {
		if v[i] == '\\' {
			i++
		}
		out.WriteByte(v[i])
	}
	return out.String()
}
func (j *judging) plainHTTP(o string, ps []Page, tld string) {
	if len(ps) == 0 {
		ps = []Page{{URL: o + "/"}}
	}
	for _, p := range ps {
		path := entryOf(p.URL).Path
		if path == "/robots.txt" || path == "/.well-known/security.txt" {
			continue
		}
		x := j.webVerdict(finding.IDWebPlaintextHTTP, o, "origin", pageReason(p), "", []Page{p})
		if p.Decision == "unavailable:connection_refused" || p.Decision == "unavailable:timeout" {
			x.Verdict, x.Reason, x.Excerpt = Disproved, "", "HTTP did not answer from this vantage"
		}
		if x.Reason == "" && x.Verdict == Abstained {
			if p.Status >= 300 && p.Status < 400 {
				u, _ := url.Parse(p.URL)
				to, e := u.Parse(header(p, "Location"))
				if e == nil && header(p, "Location") != "" {
					switch to.Scheme {
					case "https":
						x.Verdict, x.Excerpt = Disproved, "HTTP redirects to HTTPS"
					case "http":
						x.Verdict, x.Excerpt = Fired, "HTTP redirects to another HTTP page"
					}
				}
			}
			if p.Status >= 200 && p.Status < 300 && p.Body != "" {
				x.Verdict, x.Excerpt = Fired, "HTTP serves a response body without encryption"
				if passwordForm(p.Body) {
					x.Attributes = []string{"password_form"}
					x.Excerpt += "; the page contains a password input; no form was submitted"
				}
			}
			if x.Verdict == Abstained {
				x.Reason = "unavailable:response_shape"
			}
		}
		if tld != "" {
			y := x
			y.ID = finding.IDWebPlaintextHTTPClients
			y.Attributes = nil
			if p.Decision == "unavailable:timeout" || p.Status >= 300 && x.Verdict == Fired {
				y.Verdict, y.Reason = Abstained, "unavailable:response_shape"
			}
			if y.Verdict == Fired {
				y.Excerpt = "HTTP still serves a body to clients configured to use http://"
			}
			x.Verdict, x.Reason, x.Attributes, x.Excerpt = Disproved, "", nil, "Browsers never use plain HTTP on ."+tld
			j.add(y)
		}
		j.add(x)
	}
}
func sessionName(name string) bool {
	n := strings.ToLower(name)
	return slices.Contains([]string{"session", "sess", "sid", "connect.sid", "phpsessid", "jsessionid", "laravel_session", "jwt", "token"}, n) || strings.HasPrefix(n, "auth") || (strings.HasPrefix(n, "_") && strings.HasSuffix(n, "_session"))
}
func (j *judging) cookies(o string, ps []Page) {
	x := j.webVerdict(finding.IDWebSessionCookieFlags, o, "origin", "unavailable:login_flow", "The login flow was not read, so session cookies were not fully checked", ps)
	x.NotChecked = []string{"Observed cookie names in an anonymous response; the authenticated login flow was not checked"}
	for _, p := range ps {
		if pageReason(p) != "" {
			continue
		}
		for _, v := range headers(p, "Set-Cookie") {
			parts := strings.Split(v, ";")
			name, _, ok := strings.Cut(parts[0], "=")
			name = strings.TrimSpace(name)
			if !ok || !sessionName(name) {
				continue
			}
			attrs := map[string]bool{}
			uncertain := marked(name)
			for _, a := range parts[1:] {
				if marked(a) {
					uncertain = true
				}
				key, _, _ := strings.Cut(strings.TrimSpace(a), "=")
				key = strings.TrimSpace(key)
				if strings.EqualFold(key, "secure") || strings.EqualFold(key, "httponly") {
					attrs[strings.ToLower(key)] = true
				}
			}
			if uncertain {
				continue
			}
			if !attrs["secure"] || !attrs["httponly"] {
				x.Verdict = Fired
				if !slices.Contains(x.Listed, name) {
					x.Listed = append(x.Listed, name)
				}
				x.Excerpt = "Observed session-like cookies lacking Secure or HttpOnly: " + strings.Join(x.Listed, ", ")
			}
		}
	}
	j.add(x)
}

var referrerTokens = []string{"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}

func cspFeatures(s string) (bool, bool) {
	if s == "" || marked(s) {
		return false, false
	}
	valid, frame := false, false
	for part := range strings.SplitSeq(s, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		k := strings.ToLower(f[0])
		if !httpToken(k) {
			return false, false
		}
		if !slices.Contains([]string{"default-src", "script-src", "style-src", "img-src", "connect-src", "object-src", "base-uri", "frame-ancestors"}, k) {
			continue
		}
		if len(f) < 2 {
			return false, false
		}
		for _, src := range f[1:] {
			if !cspSource(src, k == "frame-ancestors") {
				return false, false
			}
		}
		valid = true
		if k == "frame-ancestors" {
			frame = true
		}
	}
	return valid, frame
}

var cspHost = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:\*\.)?[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9*]+)?(?:/[^\s;]*)?$`)
var cspNonceOrHash = regexp.MustCompile(`^'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$`)

func cspSource(v string, frame bool) bool {
	if v == "'self'" || v == "'none'" || v == "*" {
		return true
	}
	if !frame && (v == "'unsafe-inline'" || v == "'unsafe-eval'" || v == "'strict-dynamic'" || cspNonceOrHash.MatchString(v)) {
		return true
	}
	if strings.HasSuffix(v, ":") {
		u, err := url.Parse(v)
		return err == nil && u.Scheme != ""
	}
	return cspHost.MatchString(v)
}
func (j *judging) securityHeaders(o string, ps []Page) {
	x := j.webVerdict(finding.IDWebSecurityHeaders, o, "origin", "unavailable:not_read", "", ps)
	read := false
	unknown := false
	missing := []string{}
	for _, p := range ps {
		if entryOf(p.URL).Path == "/robots.txt" || entryOf(p.URL).Path == "/.well-known/security.txt" {
			continue
		}
		if r := pageReason(p); r != "" {
			unknown = true
			x.Reason = r
			continue
		}
		read = true
		for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"} {
			if marked(header(p, k)) {
				unknown = true
				x.Reason = "unavailable:redacted"
			}
		}
		csp, frame := cspFeatures(header(p, "Content-Security-Policy"))
		if header(p, "Content-Security-Policy") != "" && !csp {
			unknown = true
			x.Reason = "unavailable:header_syntax"
		}
		xfo := strings.ToLower(strings.TrimSpace(header(p, "X-Frame-Options")))
		rp := false
		for t := range strings.SplitSeq(header(p, "Referrer-Policy"), ",") {
			rp = rp || slices.Contains(referrerTokens, strings.TrimSpace(t))
		}
		if header(p, "Referrer-Policy") != "" && !rp {
			unknown = true
			x.Reason = "unavailable:header_syntax"
		}
		for k, ok := range map[string]bool{"X-Content-Type-Options": strings.EqualFold(strings.TrimSpace(header(p, "X-Content-Type-Options")), "nosniff"), "frame protection": frame || xfo == "deny" || xfo == "sameorigin", "Referrer-Policy": rp, "Content-Security-Policy": csp} {
			if !ok && !slices.Contains(missing, k) {
				missing = append(missing, k)
			}
		}
	}
	slices.Sort(missing)
	if read && !unknown {
		x.Reason = ""
		x.Verdict = Disproved
		if len(missing) > 0 {
			x.Verdict = Fired
			x.Listed = missing
			x.Excerpt = "Entry responses lack recognized browser instructions: " + strings.Join(missing, ", ")
		}
	}
	j.add(x)
}

var versionBanner = regexp.MustCompile(`(?i)\b[a-z][a-z0-9_.+-]*[/ ]v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][a-z0-9.-]+)?`)
var numericVersion = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?$`)
var commitHash = regexp.MustCompile(`^[a-fA-F0-9]{7,64}$`)

func (j *judging) version(p Page) {
	x := j.webVerdict(finding.IDWebVersionDisclosed, p.URL, "url", pageReason(p), "", []Page{p})
	if x.Reason != "" {
		j.add(x)
		return
	}
	vs := []string{}
	for _, k := range []string{"Server", "X-Powered-By"} {
		for _, v := range headers(p, k) {
			if m := versionBanner.FindString(v); m != "" {
				vs = append(vs, k+": "+m)
			}
		}
	}
	media := strings.ToLower(header(p, "Content-Type"))
	known := false
	if strings.Contains(media, "text/html") {
		known = true
		for _, t := range htmlTags(p.Body) {
			if t.name == "meta" && strings.EqualFold(t.attrs["name"], "generator") {
				if m := versionBanner.FindString(t.attrs["content"]); m != "" {
					vs = append(vs, "generator: "+m)
				}
			}
		}
		if p.Truncated && !strings.Contains(strings.ToLower(p.Body), "</head>") {
			known = false
		}
	}
	if strings.Contains(media, "application/json") && !p.Truncated && !marked(p.Body) {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(p.Body), &obj) == nil && obj != nil {
			known = true
			for _, k := range []string{"version", "build", "commit"} {
				var v string
				if json.Unmarshal(obj[k], &v) == nil && (numericVersion.MatchString(v) || (k == "commit" && commitHash.MatchString(v))) {
					vs = append(vs, k+": "+v)
				}
			}
		}
	}
	if len(vs) > 0 {
		x.Verdict, x.Reason, x.Excerpt = Fired, "", strings.Join(vs, "; ")
	} else if known && !p.Truncated && !marked(p.Body) && !marked(header(p, "Server")) && !marked(header(p, "X-Powered-By")) {
		x.Verdict, x.Reason = Disproved, ""
	} else {
		x.Reason = "unavailable:response_shape"
	}
	j.add(x)
}

var secretDetectors = []string{"private-key", "github-token", "slack-token", "google-access-token", "google-refresh-token", "google-client-secret", "stripe-key", "npm-token", "slack-webhook"}

func (j *judging) secrets(p Page) {
	reason := pageReason(p)
	counts := map[string]int{}
	if reason == "" {
		for _, hit := range p.Redactions {
			if slices.Contains(secretDetectors, hit.Rule) {
				counts[hit.Rule]++
			}
		}
	}
	for _, det := range secretDetectors {
		key := det + ":" + p.URL
		x := j.webVerdict(finding.IDWebSecretInResponse, p.URL, "secret_location", reason, "", []Page{p})
		x.Subject.Key, x.Subject.Label = key, det+" in "+p.URL
		x.NotChecked = []string{"Only this response was read; scripts and other pages were not read; credential validity was not tested"}
		if n := counts[det]; n > 0 {
			x.Verdict, x.Reason = Fired, ""
			atLeast := ""
			if p.Truncated {
				atLeast = "at least "
				x.Reason = "truncated"
			}
			x.Excerpt = fmt.Sprintf("%s%d %s token match(es) were removed from the captured response before reporting", atLeast, n, det)
			x.Details = map[string]any{"detector": det, "count": n}
			if det == "slack-webhook" {
				x.Attributes = []string{"slack_webhook"}
			}
		} else if reason == "" && strings.Contains(strings.ToLower(header(p, "Content-Type")), "text/html") && !p.Truncated && !marked(p.Body) && len(p.Redactions) == 0 {
			x.Verdict = Disproved
		} else if reason == "" {
			x.Reason = "unavailable:response_shape"
		}
		j.add(x)
	}
}
func (j *judging) securityTXT(o string, ps []Page) {
	x := j.webVerdict(finding.IDWebSecurityTXT, o, "origin", "unavailable:not_read", "", nil)
	for _, p := range ps {
		if entryOf(p.URL).Path != "/.well-known/security.txt" {
			matched := false
			for _, from := range ps {
				if from.RequestID == p.RedirectOf && entryOf(from.URL).Path == "/.well-known/security.txt" {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		x.Reads = append(x.Reads, p.RequestID)
		if blocked(p) != "" {
			x.Reason = "unavailable:blocked"
			continue
		}
		if p.Status == 404 && (p.Decision == gate.DecisionSent || p.Decision == gate.DecisionReused) && p.TLS != nil && p.TLS.Verified {
			x.Verdict, x.Reason, x.Excerpt = Fired, "", "security.txt returned 404"
			continue
		}
		if r := pageReason(p); r != "" {
			x.Reason = r
			continue
		}
		if p.Status >= 300 {
			x.Reason = "unavailable:redirect_not_entry_point"
			continue
		}
		if p.Truncated || marked(p.Body) {
			x.Reason = "unavailable:response_shape"
			continue
		}
		if !strings.Contains(strings.ToLower(header(p, "Content-Type")), "text/plain") {
			x.Reason = "unavailable:response_shape"
			continue
		}
		contacts := 0
		expires := []time.Time{}
		bad, canonical, canonicalMatch := false, false, false
		body, ok := cleartextContact(p.Body)
		if !ok {
			x.Reason = "unavailable:security_txt"
			continue
		}
		for line := range strings.SplitSeq(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				bad = true
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToLower(k) {
			case "contact":
				if !contactURI(v) {
					bad = true
				} else {
					contacts++
				}
			case "expires":
				t, e := time.Parse(time.RFC3339, v)
				if e != nil {
					bad = true
				} else {
					expires = append(expires, t)
				}
			case "canonical":
				canonical = true
				canonicalMatch = canonicalMatch || v == p.URL
			}
		}
		if !bad && contacts == 0 {
			x.Verdict, x.Reason, x.Excerpt = Fired, "", "security.txt has no Contact"
			continue
		}
		if bad || len(expires) != 1 || (canonical && !canonicalMatch) {
			x.Reason = "unavailable:security_txt"
			continue
		}
		x.Verdict, x.Reason, x.Excerpt = Disproved, "", "security.txt publishes a contact and future expiry; contact delivery and signature trust were not tested"
		if contacts == 0 || !expires[0].After(j.in.Now) {
			x.Verdict, x.Excerpt = Fired, "security.txt lacks a Contact or has expired"
		}
	}
	j.add(x)
}

func httpToken(v string) bool {
	if v == "" {
		return false
	}
	for _, b := range []byte(v) {
		if b <= 32 || b >= 127 || strings.ContainsRune("()<>@,;:\"/[]?={}", rune(b)) {
			return false
		}
	}
	return true
}
func quotedValue(v string) bool {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return false
	}
	escaped := false
	for i := 1; i < len(v)-1; i++ {
		b := v[i]
		if b < 32 && b != '\t' || b == 127 {
			return false
		}
		if escaped {
			escaped = false
			continue
		}
		switch b {
		case '\\':
			escaped = true
		case '"':
			return false
		}
	}
	return !escaped
}
func directiveParts(v string) ([]string, bool) {
	var out []string
	start := 0
	quoted, escaped := false, false
	for i, b := range []byte(v) {
		if escaped {
			escaped = false
			continue
		}
		if quoted && b == '\\' {
			escaped = true
			continue
		}
		if b == '"' {
			quoted = !quoted
		}
		if b == ';' && !quoted {
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	out = append(out, v[start:])
	return out, true
}
func contactURI(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.User != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Hostname() != ""
	case "mailto":
		a, e := mail.ParseAddress(u.Opaque)
		return e == nil && a.Address == u.Opaque && strings.Contains(u.Opaque, "@")
	case "tel":
		return telephone.MatchString(u.Opaque)
	}
	return false
}

// Clear-signed RFC9116 files are read as text; signature trust is not assessed.
func cleartextContact(s string) (string, bool) {
	if !strings.HasPrefix(s, "-----BEGIN PGP SIGNED MESSAGE-----") {
		return s, true
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	_, s, ok := strings.Cut(s, "\n\n")
	if !ok {
		return "", false
	}
	s, _, ok = strings.Cut(s, "-----BEGIN PGP SIGNATURE-----")
	if !ok {
		return "", false
	}
	return strings.ReplaceAll(s, "\n- ", "\n"), true
}

var telephone = regexp.MustCompile(`^\+[0-9][0-9().-]*[0-9]$`)
