package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func wsInventoryOps() []Op {
	ops := wsFoundationOps()
	identity := &UserIdentity{ID: "id", Primary: "primaryEmail", Customer: "customerId", Unit: "orgUnitPath", Aliases: []string{"aliases", "nonEditableAliases"}}
	units := ops[3]
	units.ID = "workspace.units"
	units.URL = "https://admin.googleapis.com/admin/directory/v1/customer/{customer}/orgunits?orgUnitPath=/&type=all_including_parent"
	units.Keep = []string{"orgUnitId", "orgUnitPath", "parentOrgUnitId", "parentOrgUnitPath", "name"}
	units.List = &List{Items: "organizationUnits", Kind: KindOrgUnit, ExcludeKey: "orgUnitPath", MaxItems: 1000, Envelope: "admin#directory#orgUnits", Tree: &UnitTree{ID: "orgUnitId", ParentID: "parentOrgUnitId", ParentPath: "parentOrgUnitPath", Name: "name"}}
	users := ops[3]
	users.ID = "workspace.users"
	users.URL = "https://admin.googleapis.com/admin/directory/v1/users?customer={customer}&projection=full&viewType=admin_view&maxResults=100&pageToken={page_token}"
	users.Params = append(users.Params, Param{Name: "page_token", Type: Cursor, Optional: true})
	users.Keep = []string{"id", "primaryEmail", "customerId", "orgUnitPath", "aliases", "nonEditableAliases", "isAdmin", "name.fullName"}
	users.UserIdentity = identity
	users.List = &List{Items: "users", Kind: KindUser, ExcludeKey: "orgUnitPath", Envelope: "admin#directory#users", MaxItems: 1000, UserKeys: []string{"id", "primaryEmail", "aliases", "nonEditableAliases"}, UserIDs: []string{"id", "primaryEmail", "aliases", "nonEditableAliases"}, Next: &Pages{Param: "page_token", Field: "nextPageToken"}, MaxPages: 10}
	detail := users
	detail.ID = "workspace.user_detail"
	detail.URL = "https://admin.googleapis.com/admin/directory/v1/users/{user}?projection=full&viewType=admin_view"
	detail.Subject = workspacePrefix + "{domain}/users/{user}"
	detail.Params = []Param{{Name: "domain", Type: DNSName}, {Name: "user", Type: UserKey}}
	detail.List = nil
	delegated := detail
	delegated.ID = "workspace.delegated_user"
	return append(ops, units, users, detail, delegated)
}

const unitEnvelope = `{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"id:root","orgUnitPath":"/"},{"orgUnitId":"id:board","orgUnitPath":"/Board","parentOrgUnitId":"id:root"},{"orgUnitId":"id:sub","orgUnitPath":"/Board/Sub","parentOrgUnitPath":"/Board"},{"orgUnitId":"id:room","orgUnitPath":"/Boardroom","parentOrgUnitPath":"/"}]}`

func wsInventoryRequest(op string) Request {
	return Request{Op: op, Asset: wsAsset, Stage: "recon", Exists: true, Params: map[string]string{"domain": "example.com"}}
}
func userRow(id, email, unit string) string {
	return fmt.Sprintf(`{"id":%q,"primaryEmail":%q,"customerId":"C-opaque-123","orgUnitPath":%q,"isAdmin":false}`, id, email, unit)
}

func TestWorkspaceUnitTreeMustBeCompleteBeforeUserContact(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"valid", unitEnvelope, 200, true},
		{"root only", `{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"id:r","orgUnitPath":"/","name":"Company"}]}`, 200, true},
		{"wrong envelope", `{}`, 200, false},
		{"duplicate key", strings.Replace(unitEnvelope, `"orgUnitPath":"/"`, `"orgUnitPath":"/Outside","orgUnitPath":"/"`, 1), 200, false},
		{"null array", `{"kind":"admin#directory#orgUnits","organizationUnits":null}`, 200, false},
		{"missing root", strings.ReplaceAll(unitEnvelope, `"orgUnitPath":"/"`, `"orgUnitPath":"/Other"`), 200, false},
		{"orphan", strings.ReplaceAll(unitEnvelope, `"parentOrgUnitPath":"/Board"`, `"parentOrgUnitPath":"/Unknown"`), 200, false},
		{"parent mismatch", strings.ReplaceAll(unitEnvelope, `"parentOrgUnitId":"id:root"`, `"parentOrgUnitId":"id:sub"`), 200, false},
		{"traversal", strings.ReplaceAll(unitEnvelope, `/Board/Sub`, `/Board/../Sub`), 200, false},
		{"duplicate id", strings.ReplaceAll(unitEnvelope, `id:sub`, `id:board`), 200, false},
		{"unavailable", `{"excluded":"secret-excluded@example.com"}`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsInventoryOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/orgunits") {
					jsonReply(tc.status, tc.body)(rw, r)
					return
				}
				if r.URL.Path == "/admin/directory/v1/users" {
					jsonReply(200, `{"kind":"admin#directory#users"}`)(rw, r)
					return
				}
				bootstrap(rw, r)
			})
			g := w.gate()
			if reads := wsBootstrap(g); len(reads) != 3 || !reads[2].OK() {
				t.Fatal(reads)
			}
			r := g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			if r.OK() != tc.valid {
				t.Fatal(r)
			}
			before := len(api.requests())
			users := g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			if tc.valid {
				if !users.OK() {
					t.Fatal(users)
				}
			} else if users.Decision != "unavailable:exclusion_unknown" || len(api.requests()) != before {
				t.Fatal(users)
			}
			if strings.Contains(w.audit.String(), "secret-excluded@example.com") {
				t.Fatal("failure leaked identity")
			}
		})
	}
}

func TestWorkspaceExclusionsAndCurrentStableIDAdmission(t *testing.T) {
	w := newWorld(t)
	w.ops = wsInventoryOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	w.scope.orgUnits = map[string][]OrgUnit{wsAsset: {{Path: "/board", ExcludedBy: "exclude[0]"}}}
	kept := userRow("123", "alice@secondary.example", "/Boardroom")
	excluded := userRow("456", "hidden@example.com", "/Board/Sub")
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true},{"domainName":"secondary.example","verified":true}]}`, `{}`)
	api := w.google(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/directory/v1/customer/C-opaque-123/orgunits":
			jsonReply(200, unitEnvelope)(rw, r)
		case "/admin/directory/v1/users":
			if r.URL.Query().Get("customer") != "C-opaque-123" || r.URL.Query().Has("domain") {
				t.Error("wrong tenant selector")
			}
			jsonReply(200, `{"kind":"admin#directory#users","users":[`+kept+`,`+excluded+`]}`)(rw, r)
		case "/admin/directory/v1/users/123":
			jsonReply(200, kept)(rw, r)
		default:
			bootstrap(rw, r)
		}
	})
	g := w.gate()
	wsBootstrap(g)
	units := g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	if !units.OK() || strings.Contains(string(units.Response.Body), `"/Board"`) {
		t.Fatal(units)
	}
	users := g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	if !users.OK() || strings.Contains(string(users.Response.Body), "hidden") || users.Response.Population.Kept != 1 {
		t.Fatal(users)
	}
	before := len(api.requests())
	for _, key := range []string{"456", "hidden@example.com", "alice@secondary.example", "outside@example.net"} {
		r := wsInventoryRequest("workspace.user_detail")
		r.Params["user"] = key
		res := g.Send(context.Background(), r)
		if res.OK() || len(api.requests()) != before {
			t.Fatal(res)
		}
	}
	r := wsInventoryRequest("workspace.user_detail")
	r.Params["user"] = "123"
	if res := g.Send(context.Background(), r); !res.OK() {
		t.Fatal(res)
	}
	b, _ := json.Marshal(g.Entries())
	if strings.Contains(string(b)+w.audit.String(), "hidden@example.com") {
		t.Fatal("excluded identity persisted")
	}
	if len(g.Successes()) != 0 || len(g.Reused()) != 0 {
		t.Fatal("Workspace evidence reused")
	}
}

func TestWorkspaceUserPaginationConflictsAndUnknownMembersBlockDetails(t *testing.T) {
	for _, tc := range []struct {
		name, last string
		loop       bool
	}{
		{"foreign customer", strings.ReplaceAll(userRow("124", "b@example.com", "/"), "C-opaque-123", "foreign"), false},
		{"unknown unit", userRow("124", "b@example.com", "/Unknown"), false},
		{"conflicting duplicate", strings.ReplaceAll(userRow("123", "alice@example.com", "/"), `"isAdmin":false`, `"isAdmin":true`), false},
		{"colliding primary", userRow("124", "alice@example.com", "/"), false},
		{"malformed member", `"not an account"`, false},
		{"cursor loop", ``, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsInventoryOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			first := userRow("123", "alice@example.com", "/")
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/orgunits") {
					jsonReply(200, unitEnvelope)(rw, r)
					return
				}
				if r.URL.Path == "/admin/directory/v1/users" {
					if r.URL.Query().Get("pageToken") == "" {
						jsonReply(200, `{"kind":"admin#directory#users","users":[`+first+`],"nextPageToken":"next"}`)(rw, r)
					} else if tc.loop {
						jsonReply(200, `{"kind":"admin#directory#users","nextPageToken":"next"}`)(rw, r)
					} else {
						jsonReply(200, `{"kind":"admin#directory#users","users":[`+tc.last+`]}`)(rw, r)
					}
					return
				}
				bootstrap(rw, r)
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			request := wsInventoryRequest("workspace.users")
			firstResult := g.Send(context.Background(), request)
			if !firstResult.OK() || !firstResult.Response.Population.More {
				t.Fatal(firstResult)
			}
			request.NextOf = firstResult.RequestID
			last := g.Send(context.Background(), request)
			if !last.OK() || last.Response.Population.More || len(last.Response.Population.Incomplete) == 0 {
				t.Fatal(last)
			}
			before := len(api.requests())
			detail := wsInventoryRequest("workspace.user_detail")
			detail.Params["user"] = "123"
			res := g.Send(context.Background(), detail)
			if res.OK() || len(api.requests()) != before {
				t.Fatal(res)
			}
		})
	}
}

func TestWorkspaceEmptyContinuationDuplicatesAndDetailRecognition(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		valid        bool
	}{
		{"valid", userRow("123", "alice@example.com", "/"), true},
		{"empty", ``, false},
		{"different customer", strings.ReplaceAll(userRow("123", "alice@example.com", "/"), "C-opaque-123", "foreign"), false},
		{"renamed", userRow("123", "renamed@example.com", "/"), false},
		{"unit moved", userRow("123", "alice@example.com", "/Board"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsInventoryOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			user := userRow("123", "alice@example.com", "/")
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/orgunits") {
					jsonReply(200, unitEnvelope)(rw, r)
					return
				}
				if r.URL.Path == "/admin/directory/v1/users" {
					switch r.URL.Query().Get("pageToken") {
					case "":
						jsonReply(200, `{"kind":"admin#directory#users","nextPageToken":"second"}`)(rw, r)
					case "second":
						jsonReply(200, `{"kind":"admin#directory#users","users":[`+user+`,`+user+`]}`)(rw, r)
					}
					return
				}
				if r.URL.Path == "/admin/directory/v1/users/123" {
					jsonReply(200, tc.detail)(rw, r)
					return
				}
				bootstrap(rw, r)
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			req := wsInventoryRequest("workspace.users")
			first := g.Send(context.Background(), req)
			if !first.OK() || !first.Response.Population.More || first.Response.Population.Kept != 0 {
				t.Fatal(first)
			}
			req.NextOf = first.RequestID
			last := g.Send(context.Background(), req)
			if !last.OK() || last.Response.Population.Kept != 1 || last.Response.Population.More {
				t.Fatal(last)
			}
			before := len(api.requests())
			bad := wsInventoryRequest("workspace.users")
			bad.Params["page_token"] = "arbitrary"
			if res := g.Send(context.Background(), bad); res.Decision != "refused:bind" || len(api.requests()) != before {
				t.Fatal(res)
			}
			detail := wsInventoryRequest("workspace.user_detail")
			detail.Params["user"] = "123"
			res := g.Send(context.Background(), detail)
			if res.OK() != tc.valid || !tc.valid && res.Response != nil && len(res.Response.Body) > 0 {
				t.Fatal(res)
			}
		})
	}
}

func TestWorkspaceUnitsPopulationCapAndFailedRefreshRevokeAdmission(t *testing.T) {
	w := newWorld(t)
	w.ops = wsInventoryOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	fail := false
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	api := w.google(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/orgunits") {
			if fail {
				jsonReply(403, `{}`)(rw, r)
			} else {
				jsonReply(200, unitEnvelope)(rw, r)
			}
			return
		}
		bootstrap(rw, r)
	})
	g := w.gate()
	wsBootstrap(g)
	if r := g.Send(context.Background(), wsInventoryRequest("workspace.units")); !r.OK() {
		t.Fatal(r)
	}
	fail = true
	if r := g.Send(context.Background(), wsInventoryRequest("workspace.units")); r.OK() {
		t.Fatal(r)
	}
	before := len(api.requests())
	if r := g.Send(context.Background(), wsInventoryRequest("workspace.users")); r.Decision != "unavailable:exclusion_unknown" || len(api.requests()) != before {
		t.Fatal(r)
	}
	l := wsInventoryOps()[4].List
	items := make([]any, 1001)
	if g.workspaceUnits(wsAsset, l, items) {
		t.Fatal("cap admitted")
	}
}

func TestWorkspaceDelegatedSubjectIsGateSelectedAndFreshlyVerified(t *testing.T) {
	for _, tc := range []struct {
		name, subject, detail string
		verified              bool
	}{
		{"primary", "alice@example.com", userRow("123", "alice@example.com", "/"), true},
		{"alias", "old@example.com", userRow("123", "alice@example.com", "/"), true},
		{"unknown", "missing@example.com", userRow("123", "alice@example.com", "/"), false},
		{"contradictory detail", "alice@example.com", userRow("123", "renamed@example.com", "/"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsInventoryOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/orgunits") {
					jsonReply(200, unitEnvelope)(rw, r)
					return
				}
				if r.URL.Path == "/admin/directory/v1/users" {
					user := strings.TrimSuffix(userRow("123", "alice@example.com", "/"), "}") + `,"aliases":["old@example.com"]}`
					jsonReply(200, `{"kind":"admin#directory#users","users":[`+user+`]}`)(rw, r)
					return
				}
				if r.URL.Path == "/admin/directory/v1/users/123" {
					if r.URL.Query().Has("customer") {
						t.Error("invented users.get selector")
					}
					jsonReply(200, tc.detail)(rw, r)
					return
				}
				bootstrap(rw, r)
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			// Foundation tests separately verify the signed service-account exchange.
			// This immutable test snapshot isolates delegated subject admission.
			g.workspaceSource.kind = "service_account"
			g.workspaceSource.issuer = "assessment@project.iam.gserviceaccount.com"
			g.workspaceSource.subject = tc.subject
			w.env["SCHECK_WORKSPACE_SUBJECT"] = tc.subject
			before := len(api.requests())
			for _, key := range []string{"123", "outside@example.com"} {
				r := wsInventoryRequest("workspace.delegated_user")
				r.Params["user"] = key
				res := g.Send(context.Background(), r)
				if res.Decision != "refused:tenant_binding" || len(api.requests()) != before {
					t.Fatal(res)
				}
			}
			result := g.Send(context.Background(), wsInventoryRequest("workspace.delegated_user"))
			if result.OK() != tc.verified {
				t.Fatal(result)
			}
			if tc.name == "unknown" && len(api.requests()) != before {
				t.Fatal("unadmitted subject contacted")
			}
			if (g.workspace[wsAsset].principal != "") == !tc.verified {
				t.Fatal("unverified principal retained")
			}
			if len(g.Successes()) != 0 || len(g.Reused()) != 0 {
				t.Fatal("verified user enabled reuse")
			}
		})
	}
}

func TestWorkspaceUserEnvelopeRejectsAmbiguousOrNullPopulation(t *testing.T) {
	for _, body := range []string{
		`{"kind":"admin#directory#users","users":null}`,
		`{"kind":"admin#directory#users","users":[],"users":[]}`,
		`{"kind":"admin#directory#users","users":[` + strings.Replace(userRow("123", "alice@example.com", "/"), `"customerId":"C-opaque-123"`, `"customerId":"foreign","customerId":"C-opaque-123"`, 1) + `]}`,
	} {
		w := newWorld(t)
		w.ops = wsInventoryOps()
		wsAuthorized(t, w)
		wsTokenServer(w, wsTokenBody(), 200)
		bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
		api := w.google(func(rw http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/orgunits") {
				jsonReply(200, unitEnvelope)(rw, r)
				return
			}
			if r.URL.Path == "/admin/directory/v1/users" {
				jsonReply(200, body)(rw, r)
				return
			}
			bootstrap(rw, r)
		})
		g := w.gate()
		wsBootstrap(g)
		g.Send(context.Background(), wsInventoryRequest("workspace.units"))
		result := g.Send(context.Background(), wsInventoryRequest("workspace.users"))
		if result.OK() {
			t.Fatal("ambiguous inventory admitted", result)
		}
		before := len(api.requests())
		detail := wsInventoryRequest("workspace.user_detail")
		detail.Params["user"] = "123"
		if result = g.Send(context.Background(), detail); result.OK() || len(api.requests()) != before {
			t.Fatal(result)
		}
	}
}

func TestWorkspaceUserAdmissionPopulationCap(t *testing.T) {
	s := &workspaceSession{customer: "C-opaque-123", units: map[string]bool{"/": true}}
	g := &Gate{workspace: map[string]*workspaceSession{wsAsset: s}}
	g.workspaceUsersStart(wsAsset)
	registry, err := NewRegistry(wsInventoryOps()...)
	if err != nil {
		t.Fatal(err)
	}
	op := registry.ops["workspace.users"]
	for i := range 1000 {
		var row any
		if err := json.Unmarshal([]byte(userRow(fmt.Sprint(i+100), fmt.Sprintf("user%d@example.com", i), "/")), &row); err != nil {
			t.Fatal(err)
		}
		if rule := g.workspaceUserItem(wsAsset, op, row, ""); rule != "" {
			t.Fatal(i, rule)
		}
	}
	out := shaped{pop: &Population{}}
	g.workspaceUsersDone(wsAsset, &out)
	if !s.usersComplete {
		t.Fatal("exact cap without continuation must remain complete")
	}
	var extra any
	if err := json.Unmarshal([]byte(userRow("9999", "extra@example.com", "/")), &extra); err != nil {
		t.Fatal(err)
	}
	if rule := g.workspaceUserItem(wsAsset, op, extra, ""); rule != "item_limit" {
		t.Fatal(rule)
	}
	g.workspaceUsersDone(wsAsset, &out)
	if s.usersComplete {
		t.Fatal("over-cap population admitted detail reads")
	}
}

func TestWorkspaceRefreshRevokesOldContinuations(t *testing.T) {
	for _, refresh := range []string{"users", "units", "binding"} {
		t.Run(refresh, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsInventoryOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			initial := 0
			failUnits := false
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/orgunits") {
					if failUnits {
						jsonReply(403, `{}`)(rw, r)
					} else {
						jsonReply(200, unitEnvelope)(rw, r)
					}
					return
				}
				if r.URL.Path == "/admin/directory/v1/users" {
					if r.URL.Query().Get("pageToken") != "" {
						jsonReply(200, `{"kind":"admin#directory#users"}`)(rw, r)
					} else {
						initial++
						if initial == 1 {
							jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("123", "alice@example.com", "/")+`],"nextPageToken":"old"}`)(rw, r)
						} else {
							jsonReply(403, `{}`)(rw, r)
						}
					}
					return
				}
				bootstrap(rw, r)
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			first := g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			if !first.OK() || !first.Response.Population.More {
				t.Fatal(first)
			}
			switch refresh {
			case "users":
				g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			case "units":
				failUnits = true
				g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			case "binding":
				wsBootstrap(g)
				g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			}
			before := len(api.requests())
			next := wsInventoryRequest("workspace.users")
			next.NextOf = first.RequestID
			if result := g.Send(context.Background(), next); result.OK() || len(api.requests()) != before {
				t.Fatal(result)
			}
			detail := wsInventoryRequest("workspace.user_detail")
			detail.Params["user"] = "123"
			if result := g.Send(context.Background(), detail); result.OK() || len(api.requests()) != before {
				t.Fatal(result)
			}
		})
	}
}

func TestWorkspacePresentUnreadableCursorPreventsDetails(t *testing.T) {
	for _, cursor := range []string{`null`, `""`, `123`, `{}`} {
		w := newWorld(t)
		w.ops = wsInventoryOps()
		wsAuthorized(t, w)
		wsTokenServer(w, wsTokenBody(), 200)
		bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
		api := w.google(func(rw http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/orgunits") {
				jsonReply(200, unitEnvelope)(rw, r)
				return
			}
			if r.URL.Path == "/admin/directory/v1/users" {
				jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("123", "alice@example.com", "/")+`],"nextPageToken":`+cursor+`}`)(rw, r)
				return
			}
			bootstrap(rw, r)
		})
		g := w.gate()
		wsBootstrap(g)
		g.Send(context.Background(), wsInventoryRequest("workspace.units"))
		result := g.Send(context.Background(), wsInventoryRequest("workspace.users"))
		if !result.OK() || len(result.Response.Population.Incomplete) == 0 {
			t.Fatal(result)
		}
		before := len(api.requests())
		detail := wsInventoryRequest("workspace.user_detail")
		detail.Params["user"] = "123"
		if result = g.Send(context.Background(), detail); result.OK() || len(api.requests()) != before {
			t.Fatal(result)
		}
	}
}
