package gate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// The pipeline's own invariants: what a JSON op, a list and its pages
// declare (docs/spec/scope.md, "Operations", "Responses").
func TestRegistryBodyInvariants(t *testing.T) {
	list := testOps[2] // github.org_repos
	users := testOps[7]
	for _, tc := range []struct {
		name string
		op   Op
		edit func(*Op)
		want string
	}{
		{"JSON mixed with HTML", list, func(o *Op) { o.Accept = []string{"application/json", "text/html"} }, "only JSON"},
		{"fields kept from HTML", list, func(o *Op) { o.Accept = []string{"text/html"} }, "accepts only JSON"},
		{"a kept field that is not a path", list, func(o *Op) { o.Keep = []string{"name[0]"} }, "not a field path"},
		{"an accepted type that is not a media type", list, func(o *Op) { o.Accept = []string{"json"} }, "not a media type"},
		{"items that are not a path", list, func(o *Op) {
			o.List = &List{Items: "a..b", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name"}
		}, "not $ or a field path"},
		{"an unknown item kind", list, func(o *Op) { o.List = &List{Items: "$", Kind: "pet"} }, "unknown"},
		{"an exclusion key on an unexcludable kind", list, func(o *Op) { o.List = &List{Items: "$", Kind: KindOther, ExcludeKey: "x"} }, "nothing an exclude matches"},
		{"user keys on a repository list", list, func(o *Op) {
			o.List = &List{Items: "$", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name", UserKeys: []string{"id"}}
		}, "only a users list"},
		{"pages without a limit", list, func(o *Op) {
			o.List = &List{Items: "$", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name", Next: &Pages{Param: "page"}}
		}, "page limit"},
		{"a limit without pages", list, func(o *Op) {
			o.List = &List{Items: "$", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name", MaxPages: 2}
		}, "no pages"},
		{"a required cursor", list, func(o *Op) { o.Params[2].Optional = false }, "optional Cursor or Count"},
		{"a cursor that is not a parameter", list, func(o *Op) {
			o.List = &List{Items: "$", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name", Next: &Pages{Param: "after"}, MaxPages: 2}
		}, "optional Cursor or Count"},
		{"a cursor field that is not a path", users, func(o *Op) {
			l := *o.List
			l.Next = &Pages{Param: "page_token", Field: "next token"}
			o.List = &l
		}, "not a field path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := tc.op
			op.Params = append([]Param(nil), tc.op.Params...)
			tc.edit(&op)
			if _, err := NewRegistry(op); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func orgRepos() Request {
	return Request{Op: "github.org_repos", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org", "per_page": "100"}}
}

func jsonReply(status int, body string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(body))
	}
}

// E4 test 4: an excluded repository in a list is absent from the evidence
// and the audit log; the drop is audited by count, never by name, and the
// population is incomplete. An item without its key and one outside the
// root go too.
func TestListDropsExcludedItems(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.scope.excluded = map[string]string{"repo:github:example-org/payroll-secret": "exclude[0]"}
	w.ops = slices.Clone(w.ops)
	w.ops[2].MaxBytes = 1 << 12
	w.github(jsonReply(200, `[
		{"full_name":"example-org/shop","name":"shop","private_note":"kept out by projection"},
		{"full_name":"Example-Org/Payroll-Secret","name":"payroll-secret"},
		{"name":"no-full-name"},
		{"full_name":"other-org/fork","name":"fork"}
	]`))
	res := w.gate().Send(context.Background(), orgRepos())
	if !res.OK() {
		t.Fatalf("%+v", res)
	}
	if got := string(res.Response.Body); got != `[{"name":"shop"}]` {
		t.Errorf("body %s", got)
	}
	p := res.Response.Population
	want := []Drop{{"exclude[0]", 1}, {"out_of_scope", 1}, {"unattributable", 1}}
	if p == nil || p.Items != 4 || p.Kept != 1 || !reflect.DeepEqual(p.Dropped, want) || !slices.Contains(p.Incomplete, "dropped") {
		t.Fatalf("population %+v", p)
	}
	log := w.audit.String()
	for _, name := range []string{"payroll", "Payroll", "no-full-name", "other-org", "private_note"} {
		if strings.Contains(log, name) {
			t.Errorf("the audit log names %q", name)
		}
	}
	last := w.audit.entries(t)
	if r := last[len(last)-1]; r.Event != "result" || !reflect.DeepEqual(r.Dropped, want) {
		t.Errorf("the result line does not count the drops: %+v", r)
	}
}

// E4 test 11: a Link to another host is never used. Only its cursor is,
// bound to its type, and the next request is rebuilt from the template; a
// collector cannot pass the cursor or invent a page; the page limit and an
// unreadable cursor leave the list incomplete. E4 test 19: a list cut by
// the page limit is incomplete, and a rule over it fires, is never
// disproved and counts "at least".
func TestPagesAreRebuiltFromTheTemplate(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.ops = slices.Clone(w.ops)
	w.ops[2].MaxBytes = 1 << 12
	srv := w.github(func(rw http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		n := int(page[0] - '0')
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Link", fmt.Sprintf(`<https://evil.example.net/orgs/x/repos?per_page=1&page=%d&token=abc>; rel="next", <https://api.github.com/x?page=9>; rel="last"`, n+1))
		_, _ = fmt.Fprintf(rw, `[{"full_name":"example-org/r%d","name":"r%d"}]`, n, n)
	})
	g := w.gate()
	var prev Result
	for n := 1; n <= 3; n++ {
		r := orgRepos()
		if n > 1 {
			r.NextOf = prev.RequestID
		}
		prev = g.Send(context.Background(), r)
		if !prev.OK() || prev.Response.Population.Page != n {
			t.Fatalf("page %d: %+v", n, prev)
		}
	}
	reqs := srv.requests()
	for i, r := range reqs {
		want := "/orgs/example-org/repos"
		if r.Host != "api.github.com" || r.URL.Path != want || r.URL.Query().Get("token") != "" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("request %d was not rebuilt from the template: %s %s", i, r.Host, r.URL)
		}
		if i > 0 && r.URL.Query().Get("page") != fmt.Sprint(i+1) {
			t.Errorf("request %d asked for page %q", i, r.URL.Query().Get("page"))
		}
	}
	p := prev.Response.Population
	if p.More || !slices.Contains(p.Incomplete, "page_limit") {
		t.Errorf("the third page of three with more left: %+v", p)
	}

	// The rule side of an incomplete population (D14): it fires on what it
	// saw and counts "at least"; seen empty, it abstains.
	var items []map[string]string
	_ = json.Unmarshal(prev.Response.Body, &items)
	recs := check.Records{Partial: len(p.Incomplete) > 0}
	for _, it := range items {
		recs.Items = append(recs.Items, check.Record{check.FieldName: it["name"]})
	}
	if v := (finding.AnyRecord{}).Eval(recs); v.Status != finding.Matched || !strings.Contains(v.Excerpt, "at least 1") {
		t.Errorf("a rule over an incomplete list: %+v", v)
	}
	if v := (finding.AnyRecord{}).Eval(check.Records{Partial: true}); v.Status != finding.NotAssessed {
		t.Errorf("an incomplete empty list disproved a rule: %+v", v)
	}

	fresh := g.Send(context.Background(), orgRepos())
	before := srv.hits.Load()
	cursor := orgRepos()
	cursor.Params["page"] = "2"
	invented := orgRepos()
	invented.NextOf = "g999999"
	spent := orgRepos()
	spent.NextOf = "g000001" // page 1 of the first read, whose page 2 was kept
	changed := orgRepos()
	changed.NextOf = fresh.RequestID
	changed.Params["per_page"] = "5"
	for _, tc := range []struct {
		name   string
		r      Request
		detail string
	}{
		{"a cursor from the collector", cursor, "filled by the gate"},
		{"an invented page", invented, "names no page"},
		{"a spent page", spent, "names no page"},
		{"changed parameters", changed, "repeats the parameters"},
	} {
		if res := g.Send(context.Background(), tc.r); res.Decision != "refused:bind" || !strings.Contains(res.Detail, tc.detail) {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
	if srv.hits.Load() != before {
		t.Error("a refused page reached the server")
	}
}

func TestUnreadableNextCursor(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.github(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Link", `<https://api.github.com/orgs/example-org/repos?page=two>; rel="next"`)
		_, _ = rw.Write([]byte(`[]`))
	})
	res := w.gate().Send(context.Background(), orgRepos())
	if p := res.Response.Population; !res.OK() || p.More || !slices.Contains(p.Incomplete, "next_page_unreadable") {
		t.Fatalf("%+v %+v", res, p)
	}
}

// workspace serves a users list in two pages: users in /Board, /Board/Sub,
// /Boardroom and one with no unit, then role assignments and tokens.
func workspace(t *testing.T, usersStatus int) (*world, *server) {
	w := newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	srv := w.google(workspaceReply(usersStatus))
	return w, srv
}

// workspaceReply answers the Workspace ops: two pages of users (in /Board,
// /board/Sub, /Boardroom and none), role assignments and tokens.
func workspaceReply(usersStatus int) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
		switch {
		case strings.HasSuffix(r.URL.Path, "/users") && usersStatus != 200:
			rw.WriteHeader(usersStatus)
			_, _ = rw.Write([]byte(`{"error":{"code":500}}`))
		case strings.HasSuffix(r.URL.Path, "/users") && r.URL.Query().Get("pageToken") == "":
			_, _ = rw.Write([]byte(`{"users":[
				{"id":"101","primaryEmail":"chair@example.com","orgUnitPath":"/Board","isAdmin":true},
				{"id":"102","primaryEmail":"sub@example.com","orgUnitPath":"/board/Sub","emails":[{"address":"alias@example.com"}]}
			],"nextPageToken":"tok-2"}`))
		case strings.HasSuffix(r.URL.Path, "/users"):
			_, _ = rw.Write([]byte(`{"users":[
				{"id":"103","primaryEmail":"room@example.com","orgUnitPath":"/Boardroom","isAdmin":true},
				{"id":"104","primaryEmail":"nounit@example.com"}
			]}`))
		case strings.HasSuffix(r.URL.Path, "/roleassignments"):
			_, _ = rw.Write([]byte(`{"items":[
				{"roleId":"1","assignedTo":"101"},{"roleId":"1","assignedTo":"103"},
				{"roleId":"2","assignedTo":"104"},{"roleId":"3"},{"roleId":"4","assignedTo":"ALIAS@example.com"},
				{"roleId":"5","assignedTo":"contractor@gmail.com"}
			]}`))
		default:
			_, _ = rw.Write([]byte(`{"items":[{"clientId":"c1","scopes":["x"]}]}`))
		}
	}
}

func wsReq(op string, params map[string]string) Request {
	return Request{Op: op, Asset: "saas:google-workspace:example.com", Params: params}
}

// E4 tests 3 and 5: before the users list is read whole, nothing that
// names or lists users is sent; once it is, per-user ops on users in /Board
// and /Board/Sub are refused and /Boardroom is sent, and items referencing
// excluded users are dropped, as is one without its key.
func TestExcludedSubjectSet(t *testing.T) {
	w, srv := workspace(t, 200)
	g := w.gate()
	ctx := context.Background()
	tokens := func(user string) Result { return g.Send(ctx, wsReq("ws.user_tokens", map[string]string{"user": user})) }
	roles := func() Result { return g.Send(ctx, wsReq("ws.role_assignments", nil)) }

	if res := tokens("103"); res.Decision != "unavailable:exclusion_unknown" || res.Reason != "unavailable:exclusion_unknown" {
		t.Fatalf("before the users list: %+v", res)
	}
	if res := roles(); res.Decision != "unavailable:exclusion_unknown" {
		t.Fatalf("before the users list: %+v", res)
	}
	if srv.hits.Load() != 0 {
		t.Fatal("a request that needs the set was sent before it was known")
	}

	first := g.Send(ctx, wsReq("ws.users", nil))
	if !first.OK() || !first.Response.Population.More || string(first.Response.Body) != `[]` {
		t.Fatalf("page 1: %+v %s %+v", first, first.Response.Body, first.Response.Population)
	}
	// Half a users list is not a known set.
	if res := tokens("103"); res.Decision != "unavailable:exclusion_unknown" {
		t.Fatalf("after one page: %+v", res)
	}
	next := wsReq("ws.users", nil)
	next.NextOf = first.RequestID
	second := g.Send(ctx, next)
	if !second.OK() || second.Response.Population.More || string(second.Response.Body) != `[{"isAdmin":true,"primaryEmail":"room@example.com"}]` {
		t.Fatalf("page 2: %+v %s", second, second.Response.Body)
	}
	if got := srv.requests()[1].URL.Query().Get("pageToken"); got != "tok-2" {
		t.Errorf("the second page asked for %q", got)
	}

	for user, want := range map[string]string{
		"101": "refused:excluded", "CHAIR@example.com": "refused:excluded", // /Board
		"102": "refused:excluded", "alias@example.com": "refused:excluded", // /Board/Sub, case-insensitive
		"104": "refused:excluded", // no unit: it may be excluded
		"103": "sent",             // /Boardroom
	} {
		if res := tokens(user); res.Decision != want {
			t.Errorf("tokens of %s: %+v", user, res)
		}
	}

	res := roles()
	if !res.OK() || string(res.Response.Body) != `[{"assignedTo":"103","roleId":"1"},{"assignedTo":"contractor@gmail.com","roleId":"5"}]` {
		t.Fatalf("role assignments: %+v %s", res, res.Response.Body)
	}
	want := []Drop{{"exclude[1]", 2}, {"unattributable", 2}}
	if got := res.Response.Population.Dropped; !reflect.DeepEqual(got, want) {
		t.Errorf("dropped %+v, want %+v", got, want)
	}
	// Users the test never asked about by name appear nowhere: the drops
	// were counted, not listed.
	for _, name := range []string{"sub@example.com", "nounit@example.com"} {
		if strings.Contains(w.audit.String(), name) {
			t.Errorf("the audit log names %s", name)
		}
	}
}

// When the users list failed, the set stays unknown, and an op that
// references users is unavailable, never stored unfiltered.
func TestFailedUsersListLeavesTheSetUnknown(t *testing.T) {
	w, srv := workspace(t, 403)
	g := w.gate()
	if res := g.Send(context.Background(), wsReq("ws.users", nil)); res.OK() {
		t.Fatalf("%+v", res)
	}
	hits := srv.hits.Load()
	if res := g.Send(context.Background(), wsReq("ws.role_assignments", nil)); res.Decision != "unavailable:exclusion_unknown" || res.Response != nil {
		t.Fatalf("%+v", res)
	}
	if srv.hits.Load() != hits {
		t.Error("an op whose items could not be filtered was sent")
	}
}

// With no organizational unit excluded, the set is known to be empty and
// nothing waits for the users list.
func TestNoExcludedUnitNeedsNoUsersList(t *testing.T) {
	w, _ := workspace(t, 200)
	w.scope.orgUnits = nil
	res := w.gate().Send(context.Background(), wsReq("ws.role_assignments", nil))
	if !res.OK() || res.Response.Population.Kept != 5 {
		t.Fatalf("%+v %s", res, res.Response.Body)
	}
}

// With no unit excluded, reading the users list excludes no one: an
// address it never returned is sent, before the list and after it alike.
func TestUsersListExcludesNoOneWithoutAnExcludedUnit(t *testing.T) {
	for _, users := range []string{`{"users":[]}`, `{"users":[{"id":"1","primaryEmail":"ann@example.com","orgUnitPath":"/"}]}`} {
		w := newWorld(t)
		w.google(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/users") {
				_, _ = rw.Write([]byte(users))
				return
			}
			_, _ = rw.Write([]byte(`{"items":[{"clientId":"c1","scopes":["x"]}]}`))
		})
		g := w.gate()
		if res := g.Send(context.Background(), wsReq("ws.users", nil)); !res.OK() {
			t.Fatalf("%+v", res)
		}
		if res := g.Send(context.Background(), wsReq("ws.user_tokens", map[string]string{"user": "chair@example.com"})); res.Decision != "sent" {
			t.Errorf("%s: an address the list never returned, with nothing excluded: %+v", users, res)
		}
	}
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// E4 test 13: a gzip bomb, a content-type mismatch, another encoding and a
// body that is not JSON each give their unavailable code with nothing
// stored; a gzip body is read; a token inside JSON is redacted and the
// result still parses.
func TestPipelineCodes(t *testing.T) {
	access := "ya" + "29." + strings.Repeat("Qz8", 14)
	for _, tc := range []struct {
		name, decision string
		reply          http.HandlerFunc
		body           string
	}{
		{"gzip JSON", "sent", func(rw http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "gzip" {
				rw.WriteHeader(400)
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Content-Encoding", "gzip")
			_, _ = rw.Write(gzipped([]byte(`{"login":"example-org","plan":{"name":"team","seats":3},"extra":1}`)))
		}, `{"login":"example-org","plan":{"name":"team"}}`},
		{"a token in a JSON member", "sent", jsonReply(200, `{"login":"example-org","access_token":"`+access+`"}`),
			`{"access_token":"[REDACTED:google-access-token:` + fmt.Sprint(len(access)) + ` bytes]","login":"example-org"}`},
		{"a gzip bomb", "unavailable:compression_bomb", func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Content-Encoding", "gzip")
			_, _ = rw.Write(gzipped(bytes.Repeat([]byte(" "), 4<<20)))
		}, ""},
		{"HTML for JSON", "unavailable:unexpected_content_type", func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "text/html")
			_, _ = rw.Write([]byte(`<html>login internal.example.net</html>`))
		}, ""},
		{"brotli", "unavailable:unexpected_content_encoding", func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Content-Encoding", "br")
			_, _ = rw.Write([]byte{0x1b, 0x00})
		}, ""},
		{"not JSON", "unavailable:malformed_response", jsonReply(200, `{"login":`), ""},
		{"trailing data", "unavailable:malformed_response", jsonReply(200, `{"login":"a"} {"login":"b"}`), ""},
		{"corrupt gzip", "unavailable:malformed_response", func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Content-Encoding", "gzip")
			z := gzipped([]byte(`{"login":"example-org"}`))
			z[len(z)-5] ^= 0xff // the checksum
			_, _ = rw.Write(z)
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.env["GITHUB_TOKEN"] = testToken
			w.github(tc.reply)
			res := w.gate().Send(context.Background(), Request{Op: "github.org", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org"}})
			if res.Decision != tc.decision {
				t.Fatalf("%+v", res)
			}
			if tc.body == "" && res.Response.Body != nil {
				t.Errorf("kept %q", res.Response.Body)
			}
			if tc.body != "" && string(res.Response.Body) != tc.body {
				t.Errorf("body %s, want %s", res.Response.Body, tc.body)
			}
			if res.Response.Body != nil && !json.Valid(res.Response.Body) {
				t.Error("the kept body does not parse")
			}
			log := w.audit.String()
			if strings.Contains(log, access) || strings.Contains(log, "internal.example.net") || strings.Contains(log, "<html>") {
				t.Errorf("the audit log holds the body: %s", log)
			}
			if tc.decision == "unavailable:unexpected_content_type" {
				if e := w.audit.entries(t); e[len(e)-1].OutputHash == "" {
					t.Error("a body not kept is hashed")
				}
			}
		})
	}
}

// Redaction cannot change a document's structure: a redact_extra pattern
// written across members matches nothing, and a span that would run from
// one string to a later one (a PEM header in one user, its footer in
// another) stays inside its string. The excluded user between them is
// still dropped, and the set still holds it (review finding, step 2).
func TestRedactionKeepsTheStructure(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.extra = []string{`n":"ex`}
	w.github(jsonReply(200, `{"login":"example-org"}`))
	res := w.gate().Send(context.Background(), Request{Op: "github.org", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org"}})
	if !res.OK() || string(res.Response.Body) != `{"login":"example-org"}` {
		t.Fatalf("%+v", res)
	}

	w = newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/users") {
			_, _ = rw.Write([]byte(`{"users":[
				{"id":"100","primaryEmail":"a@example.com","orgUnitPath":"/Sales","name":"-----BEGIN PRIVATE KEY-----"},
				{"id":"101","primaryEmail":"chair@example.com","orgUnitPath":"/Board"},
				{"id":"105","primaryEmail":"b@example.com","orgUnitPath":"/Sales","name":"-----END PRIVATE KEY-----"}]}`))
			return
		}
		_, _ = rw.Write([]byte(`{"items":[{"clientId":"chair-private-app"}]}`))
	})
	g := w.gate()
	users := g.Send(context.Background(), wsReq("ws.users", nil))
	if p := users.Response.Population; !users.OK() || p.Items != 3 || p.Kept != 2 || len(p.Dropped) != 1 {
		t.Fatalf("%+v %+v", users, p)
	}
	if res := g.Send(context.Background(), wsReq("ws.user_tokens", map[string]string{"user": "chair@example.com"})); res.Decision != "refused:excluded" {
		t.Fatalf("the excluded user's tokens: %+v", res)
	}
}

// A body of another type on an error status is not kept, and the status
// decides: a 404 for robots.txt answered with an HTML page is a 404.
func TestErrorStatusDecidesOverTheBody(t *testing.T) {
	w := newWorld(t)
	w.ops = append(slices.Clone(w.ops), Op{ID: "web.robots", Provider: "web", Method: GET, URL: "https://{host}/robots.txt",
		Params: []Param{{Name: "host", Type: Host}}, Level: Observe, Accept: []string{"text/plain"}, MaxBytes: 256})
	w.scope.sites = map[string]SitePaths{"https://www.example.com": {Paths: []string{"/robots.txt"}}}
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "93.184.216.34", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(404)
		_, _ = rw.Write([]byte("<html>not here</html>"))
	})
	res := w.gate().Send(context.Background(), Request{Op: "web.robots", Asset: "domain:example.com", Params: map[string]string{"host": "www.example.com"}})
	if !res.OK() || res.Response.Status != 404 || res.Response.Body != nil {
		t.Fatalf("%+v", res)
	}
}

func TestProjection(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"a":{"b":1,"c":2},"d":[{"e":1,"f":2},{"e":3}],"g":null,"h":"x","i":5}`), &doc)
	got := string(marshal(project(doc, newKeepTree([]string{"a.b", "d.e", "g", "h.x", "missing", "i", "i.j"}))))
	if want := `{"a":{"b":1},"d":[{"e":1},{"e":3}],"g":null,"i":5}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestLinkNext(t *testing.T) {
	for h, want := range map[string]string{
		`<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"`: "https://api.github.com/x?page=2",
		`<https://a/?page=1>; rel="prev", <https://a/?page=3>; rel=next`:                               "https://a/?page=3",
		`<https://a/?page=3>; rel="prev next"`:                                                         "https://a/?page=3",
		`<https://a/?page=3>; rel="nextish"`:                                                           "",
		`<https://a/?page=9>; rel="last"`:                                                              "",
	} {
		if got, _ := linkNext(h); got != want {
			t.Errorf("linkNext(%s) = %q, want %q", h, got, want)
		}
	}
}

func TestOrgUnitUnder(t *testing.T) {
	for _, tc := range []struct {
		p, ex string
		want  bool
	}{
		{"/Board", "/Board", true}, {"/Board/Sub", "/Board", true}, {"/board/sub", "/Board/", true},
		{"/Boardroom", "/Board", false}, {"/", "/Board", false}, {"/Sales", "/", true},
	} {
		if got := orgUnitUnder(tc.p, tc.ex); got != tc.want {
			t.Errorf("orgUnitUnder(%q, %q) = %v", tc.p, tc.ex, got)
		}
	}
}

// A gzip body larger than the cap that is not a bomb is cut like any
// other text.
func TestLargeGzipTextIsCut(t *testing.T) {
	w := newWorld(t)
	page := make([]byte, 0, 64<<10)
	for i := 0; len(page) < 60<<10; i++ {
		page = fmt.Appendf(page, "<p>line %d of a page that compresses like a page does %x</p>\n", i, i*7919)
	}
	var sent atomic.Int32
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "93.184.216.34", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		rw.Header().Set("Content-Type", "text/html")
		rw.Header().Set("Content-Encoding", "gzip")
		_, _ = rw.Write(gzipped(page))
	})
	res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
	if !res.OK() || !res.Response.Truncated || !strings.Contains(string(res.Response.Body), "[TRUNCATED:") {
		t.Fatalf("%+v", res)
	}
}

// Review findings, step 2: the set builder is one whole-tenant list per
// provider; a second, filtered one would replace the set with a partial
// one.
func TestOneSetBuilderPerProvider(t *testing.T) {
	users := testOps[7]
	admins := users
	admins.ID = "ws.admins"
	if _, err := NewRegistry(users, admins); err == nil || !strings.Contains(err.Error(), "already builds") {
		t.Errorf("two builders: %v", err)
	}
	filtered := users
	filtered.URL = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&query=isAdmin%3Dtrue&pageToken={page_token}"
	if _, err := NewRegistry(filtered); err == nil || !strings.Contains(err.Error(), `no filter "query"`) {
		t.Errorf("a filtered builder: %v", err)
	}
}

// A next_of is read once at a time, so two requests never build two sets
// from one page.
func TestAPageIsReadOnceAtATime(t *testing.T) {
	w, _ := workspace(t, 200)
	g := w.gate()
	first := g.Send(context.Background(), wsReq("ws.users", nil))
	g.mu.Lock()
	g.pages[first.RequestID].reading = true
	g.mu.Unlock()
	next := wsReq("ws.users", nil)
	next.NextOf = first.RequestID
	if res := g.Send(context.Background(), next); res.Decision != "refused:bind" || !strings.Contains(res.Detail, "already being read") {
		t.Fatalf("%+v", res)
	}
	g.mu.Lock()
	g.pages[first.RequestID].reading = false
	g.mu.Unlock()
	if res := g.Send(context.Background(), next); !res.OK() {
		t.Fatalf("%+v", res)
	}
}

// A user reference that is neither an id nor an address is dropped as
// unattributable; it could be an excluded user written another way.
func TestUnparseableUserReference(t *testing.T) {
	w := newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/users") {
			_, _ = rw.Write([]byte(`{"users":[{"id":"101","primaryEmail":"chair@example.com","orgUnitPath":"/Board"}]}`))
			return
		}
		_, _ = rw.Write([]byte(`{"items":[{"roleId":"1","assignedTo":"user:chair@example.com"},{"roleId":"2","assignedTo":"1234567890123456789012345678901"}]}`))
	})
	g := w.gate()
	g.Send(context.Background(), wsReq("ws.users", nil))
	res := g.Send(context.Background(), wsReq("ws.role_assignments", nil))
	if !res.OK() || string(res.Response.Body) != `[]` || !reflect.DeepEqual(res.Response.Population.Dropped, []Drop{{"unattributable", 2}}) {
		t.Fatalf("%+v %s", res, res.Response.Body)
	}
}

// A 2xx with no body is kept as its status; a list has a body.
func TestEmptySuccessIsTheStatus(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.github(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })
	g := w.gate()
	res := g.Send(context.Background(), Request{Op: "github.org", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org"}})
	if !res.OK() || res.Response.Status != 204 || res.Response.Body != nil {
		t.Fatalf("%+v", res)
	}
	if res := g.Send(context.Background(), orgRepos()); res.Decision != "unavailable:malformed_response" {
		t.Fatalf("an empty list: %+v", res)
	}
}

func TestAccepts(t *testing.T) {
	for _, tc := range []struct {
		accept []string
		ct     string
		want   bool
	}{
		{[]string{"*/*"}, "", true},
		{[]string{"text/html"}, "text/html; charset", true},
		{[]string{"text/html"}, "", false},
		{[]string{"text/*"}, "text/plain; charset=utf-8", true},
		{[]string{"application/vnd.github+json"}, "application/json; charset=utf-8", true},
		{[]string{"application/json"}, "text/html", false},
	} {
		if got := accepts(tc.accept, tc.ct); got != tc.want {
			t.Errorf("accepts(%v, %q) = %v", tc.accept, tc.ct, got)
		}
	}
}

// A gzip stream cut short inside a body the server finished sending is
// malformed, not a reset.
func TestTruncatedGzipIsMalformed(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	z := gzipped([]byte(`{"login":"example-org","plan":{"name":"` + strings.Repeat("team", 200) + `"}}`))
	w.github(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Encoding", "gzip")
		_, _ = rw.Write(z[:len(z)/2])
	})
	res := w.gate().Send(context.Background(), Request{Op: "github.org", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org"}})
	if res.Decision != "unavailable:malformed_response" || res.Response.Body != nil {
		t.Fatalf("%+v", res)
	}
}

// A filter cannot ride in on a parameter typed like a cursor: the set
// builder takes its own cursor and one page size, each a whole value
// (re-review finding, step 2).
func TestSetBuilderTakesNoDisguisedFilter(t *testing.T) {
	users := testOps[7]
	disguised := users
	disguised.URL = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&query={q}&pageToken={page_token}"
	disguised.Params = append(slices.Clone(users.Params), Param{Name: "q", Type: Cursor, Optional: true})
	partial := users
	partial.URL = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&query=orgUnitPath%3D{n}&pageToken={page_token}"
	partial.Params = append(slices.Clone(users.Params), Param{Name: "n", Type: Count})
	asSize := func(url string) Op {
		o := users
		o.URL = url
		o.Params = append(slices.Clone(users.Params), Param{Name: "size", Type: Count})
		return o
	}
	const base = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer"
	reused := users
	reused.URL = base + "&query={page_token}&pageToken={page_token}"
	for name, op := range map[string]Op{
		"a second cursor": disguised, "a partial template": partial, "the cursor twice": reused,
		"a page size as a query":  asSize(base + "&query={size}&pageToken={page_token}"),
		"a page size twice":       asSize(base + "&maxResults={size}&query={size}&pageToken={page_token}"),
		"a page size as a switch": asSize(base + "&showDeleted={size}&pageToken={page_token}"),
	} {
		if _, err := NewRegistry(op); err == nil || !strings.Contains(err.Error(), "excluded-subject set") {
			t.Errorf("%s: %v", name, err)
		}
	}
	sized := users
	sized.URL = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults={size}&pageToken={page_token}"
	sized.Params = append(slices.Clone(users.Params), Param{Name: "size", Type: Count})
	if _, err := NewRegistry(sized); err != nil {
		t.Errorf("a page size: %v", err)
	}
}

// A user the users list never returned cannot be told apart from an
// excluded one the principal could not see: its id or tenant address is
// unattributable, and a per-user op on it is refused. An address in
// another domain is an external member and stays.
func TestUnseenUsersAreUnattributable(t *testing.T) {
	w := newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/users") {
			_, _ = rw.Write([]byte(`{"users":[{"id":"103","primaryEmail":"room@example.com","orgUnitPath":"/Boardroom"}]}`))
			return
		}
		_, _ = rw.Write([]byte(`{"items":[{"roleId":"1","assignedTo":"103"},{"roleId":"2","assignedTo":"999"},
			{"roleId":"3","assignedTo":"hidden@example.com"},{"roleId":"4","assignedTo":"guest@partner.example"}]}`))
	})
	g := w.gate()
	g.Send(context.Background(), wsReq("ws.users", nil))
	res := g.Send(context.Background(), wsReq("ws.role_assignments", nil))
	if !res.OK() || string(res.Response.Body) != `[{"assignedTo":"103","roleId":"1"},{"assignedTo":"guest@partner.example","roleId":"4"}]` {
		t.Fatalf("%+v %s", res, res.Response.Body)
	}
	if res := g.Send(context.Background(), wsReq("ws.user_tokens", map[string]string{"user": "999"})); res.Decision != "refused:excluded" {
		t.Errorf("a per-user op on an unseen user: %+v", res)
	}
}

// Only the fields that identify a user inside the tenant say who the list
// returned and which domains are the tenant's: a contact address on file
// neither makes its domain the tenant's nor makes its owner "seen".
func TestContactAddressesDoNotWidenTheTenant(t *testing.T) {
	w := newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/users") {
			_, _ = rw.Write([]byte(`{"users":[{"id":"1","primaryEmail":"ann@example.com","orgUnitPath":"/Eng",
				"emails":[{"address":"ann.home@gmail.com","type":"home"},{"address":"hidden@example.com","type":"other"}]}]}`))
			return
		}
		_, _ = rw.Write([]byte(`{"items":[{"roleId":"1","assignedTo":"stranger@gmail.com"},{"roleId":"2","assignedTo":"hidden@example.com"}]}`))
	})
	g := w.gate()
	g.Send(context.Background(), wsReq("ws.users", nil))
	res := g.Send(context.Background(), wsReq("ws.role_assignments", nil))
	if !res.OK() || string(res.Response.Body) != `[{"assignedTo":"stranger@gmail.com","roleId":"1"}]` {
		t.Fatalf("%+v %s", res, res.Response.Body)
	}
}

// The tenant's own domain is the tenant's even when the users list returned
// no one in it: an address there the list never returned is
// unattributable. A list that returned no one at all while a unit is
// excluded tells no excluded user apart, so the set stays unknown.
func TestTenantDomainIsTheTenants(t *testing.T) {
	for _, tc := range []struct {
		name, users string
		want        string
	}{
		{"users elsewhere", `{"users":[{"id":"103","primaryEmail":"room@other.example","orgUnitPath":"/Boardroom"}]}`, "refused:excluded"},
		{"no users member", `{}`, "unavailable:exclusion_unknown"},
		{"an empty list", `{"users":[]}`, "unavailable:exclusion_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
			var sent atomic.Int32
			w.google(func(rw http.ResponseWriter, r *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/users") {
					_, _ = rw.Write([]byte(tc.users))
					return
				}
				sent.Add(1)
				_, _ = rw.Write([]byte(`{"items":[]}`))
			})
			g := w.gate()
			if res := g.Send(context.Background(), wsReq("ws.users", nil)); !res.OK() {
				t.Fatalf("%+v", res)
			}
			if res := g.Send(context.Background(), wsReq("ws.user_tokens", map[string]string{"user": "chair@example.com"})); res.Decision != tc.want {
				t.Errorf("tokens of an address in the tenant's domain: %+v", res)
			}
			if sent.Load() != 0 {
				t.Error("a per-user op on an address the list never returned was sent")
			}
		})
	}
}

// A users list whose last page is empty keeps the users the pages before it
// returned: the set is known, and refuses and sends as those pages decide.
func TestUsersListEndingOnAnEmptyPage(t *testing.T) {
	w := newWorld(t)
	w.scope.orgUnits = map[string][]OrgUnit{"saas:google-workspace:example.com": {{Path: "/Board", ExcludedBy: "exclude[1]"}}}
	var tokens atomic.Int32
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/users") {
			tokens.Add(1)
			_, _ = rw.Write([]byte(`{"items":[]}`))
			return
		}
		switch r.URL.Query().Get("pageToken") {
		case "":
			_, _ = rw.Write([]byte(`{"users":[{"id":"101","primaryEmail":"chair@example.com","orgUnitPath":"/Board"}],"nextPageToken":"p2"}`))
		case "p2":
			_, _ = rw.Write([]byte(`{"users":[{"id":"103","primaryEmail":"room@example.com","orgUnitPath":"/Eng"}],"nextPageToken":"p3"}`))
		default:
			_, _ = rw.Write([]byte(`{"users":[]}`))
		}
	})
	g := w.gate()
	prev := g.Send(context.Background(), wsReq("ws.users", nil))
	for prev.OK() && prev.Response.Population.More {
		next := wsReq("ws.users", nil)
		next.NextOf = prev.RequestID
		prev = g.Send(context.Background(), next)
	}
	if !prev.OK() {
		t.Fatalf("%+v", prev)
	}
	for user, want := range map[string]string{
		"101": "refused:excluded", "chair@example.com": "refused:excluded", // /Board
		"999": "refused:excluded", "hidden@example.com": "refused:excluded", // never returned
		"103": "sent", "guest@partner.example": "sent",
	} {
		if res := g.Send(context.Background(), wsReq("ws.user_tokens", map[string]string{"user": user})); res.Decision != want {
			t.Errorf("tokens of %s: %+v", user, res)
		}
	}
	if n := tokens.Load(); n != 2 {
		t.Errorf("%d per-user requests sent, want 2", n)
	}
}
