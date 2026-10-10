package gate

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func wsAccessOps() []Op {
	ops := wsInventoryOps()
	assignments := ops[3]
	assignments.ID = "workspace.user_assignments"
	assignments.URL = "https://admin.googleapis.com/admin/directory/v1/customer/{customer}/roleassignments?maxResults=100&pageToken={page_token}&userKey={user}&includeIndirectRoleAssignments=true"
	assignments.Subject = workspacePrefix + "{domain}/users/{user}"
	assignments.Params = append(assignments.Params, Param{Name: "user", Type: UserKey}, Param{Name: "page_token", Type: Cursor, Optional: true})
	assignments.PreserveMalformed = true
	assignments.Keep = []string{"roleAssignmentId", "roleId", "assignedTo", "assigneeType", "scopeType", "orgUnitId", "condition", "expirationDetails.expireTime"}
	assignments.List = &List{Items: "items", Kind: KindOther, Envelope: "admin#directory#roleAssignments", MaxItems: 1000, MaxPages: 10, Next: &Pages{Param: "page_token", Field: "nextPageToken"}, Assignment: &AssignmentRefs{Assignee: "assignedTo", Type: "assigneeType", Scope: "scopeType", Unit: "orgUnitId"}}
	privileges := ops[3]
	privileges.ID = "workspace.privileges"
	privileges.URL = "https://admin.googleapis.com/admin/directory/v1/customer/{customer}/roles/ALL/privileges"
	privileges.Keep = []string{"serviceId", "privilegeName", "isOuScopable"}
	privileges.List = &List{Items: "items", Kind: KindOther, Envelope: "admin#directory#privileges", MaxItems: 1000, Children: "childPrivileges", MaxDepth: 32}
	return append(ops, assignments, privileges)
}
func TestWorkspaceAssignmentAdmissionAndScopeProjection(t *testing.T) {
	for _, tc := range []struct {
		name, row string
		kept      bool
	}{
		{"malformed expiry", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"CUSTOMER","expirationDetails":true}`, true},
		{"direct user", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"CUSTOMER"}`, true},
		{"indirect group", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"group1","assigneeType":"GROUP","scopeType":"CUSTOMER"}`, true},
		{"foreign user", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"SECRET_UNADMITTED","assigneeType":"USER","scopeType":"CUSTOMER"}`, false},
		{"unknown type", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"SECRET_UNADMITTED","scopeType":"CUSTOMER"}`, false},
		{"excluded scope", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"ORG_UNIT","orgUnitId":"id:board"}`, false},
		{"unknown scope", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"ORG_UNIT","orgUnitId":"SECRET_UNKNOWN_UNIT"}`, false},
		{"retained scope", `{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"ORG_UNIT","orgUnitId":"id:room","expirationDetails":{"expireTime":"2026-10-11T00:00:00Z","secret":"OMITTED_EXPIRY"},"extra":"OMITTED_EXTRA"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsAccessOps()
			w.scope.orgUnits = map[string][]OrgUnit{wsAsset: {{Path: "/Board", ExcludedBy: "board"}}}
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/orgunits"):
					jsonReply(200, unitEnvelope)(rw, r)
				case r.URL.Path == "/admin/directory/v1/users":
					jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("123", "alice@example.com", "/Boardroom")+`]}`)(rw, r)
				case strings.HasSuffix(r.URL.Path, "/roleassignments"):
					if r.URL.Query().Get("userKey") != "123" || r.URL.Query().Get("includeIndirectRoleAssignments") != "true" {
						t.Error(r.URL)
					}
					jsonReply(200, `{"kind":"admin#directory#roleAssignments","items":[`+tc.row+`]}`)(rw, r)
				default:
					bootstrap(rw, r)
				}
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			req := wsInventoryRequest("workspace.user_assignments")
			req.Params["user"] = "123"
			result := g.Send(context.Background(), req)
			if !result.OK() {
				t.Fatal(result)
			}
			body := string(result.Response.Body)
			if (body != "[]") != tc.kept || strings.Contains(body, "SECRET_") || strings.Contains(body, "OMITTED_") {
				t.Fatal(body)
			}
			if tc.name == "malformed expiry" && !strings.Contains(body, `"expirationDetails":null`) {
				t.Fatal("malformed expiry lost its presence", body)
			}
			if !tc.kept && len(result.Response.Population.Incomplete) == 0 {
				t.Fatal("dropped reference claimed complete")
			}
			before := len(api.requests())
			req.Params["user"] = "unknown@example.com"
			if g.Send(context.Background(), req).OK() || len(api.requests()) != before {
				t.Fatal("unadmitted user contacted")
			}
		})
	}
}
func TestWorkspaceAssignmentTenantBudgetAndRefresh(t *testing.T) {
	w := newWorld(t)
	w.ops = wsAccessOps()
	wsAuthorized(t, w)
	wsTokenServer(w, wsTokenBody(), 200)
	bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
	w.google(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/orgunits"):
			jsonReply(200, unitEnvelope)(rw, r)
		case r.URL.Path == "/admin/directory/v1/users":
			jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("123", "alice@example.com", "/")+`]}`)(rw, r)
		case strings.HasSuffix(r.URL.Path, "/roleassignments"):
			jsonReply(200, `{"kind":"admin#directory#roleAssignments","items":[{"roleAssignmentId":"a","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"CUSTOMER"}]}`)(rw, r)
		default:
			bootstrap(rw, r)
		}
	})
	g := w.gate()
	wsBootstrap(g)
	g.Send(context.Background(), wsInventoryRequest("workspace.units"))
	g.Send(context.Background(), wsInventoryRequest("workspace.users"))
	g.workspace[wsAsset].assignmentObservations = 9999
	req := wsInventoryRequest("workspace.user_assignments")
	req.Params["user"] = "123"
	if !g.Send(context.Background(), req).OK() {
		t.Fatal("exact bound rejected")
	}
	if result := g.Send(context.Background(), req); !strings.HasSuffix(result.Reason, "limit_reached") {
		t.Fatal(result)
	}
	wsBootstrap(g)
	if g.workspace[wsAsset].assignmentObservations != 0 {
		t.Fatal("new binding retained old budget")
	}
}
func TestWorkspaceRecursiveProjectionBounded(t *testing.T) {
	for _, depth := range []int{2, 33} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsAccessOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			row := `{"serviceId":"00haapch16h1ysv","privilegeName":"USERS_RESET_PASSWORD","unknown":"OMITTED_TREE"}`
			for range depth - 1 {
				row = `{"serviceId":"00haapch16h1ysv","privilegeName":"USERS_ALL","childPrivileges":[` + row + `]}`
			}
			w.google(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/privileges") {
					jsonReply(200, `{"kind":"admin#directory#privileges","items":[`+row+`]}`)(rw, r)
				} else {
					bootstrap(rw, r)
				}
			})
			g := w.gate()
			wsBootstrap(g)
			result := g.Send(context.Background(), wsInventoryRequest("workspace.privileges"))
			if result.OK() != (depth <= 32) {
				t.Fatal(result)
			}
			if result.Response != nil && strings.Contains(string(result.Response.Body), "OMITTED_TREE") {
				t.Fatal("recursive projection leaked field")
			}
		})
	}
}

func TestWorkspaceAssignmentPopulationCapAcrossPages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second int
		more   bool
		ok     bool
	}{{"exact", 400, false, true}, {"exact with more", 400, true, true}, {"over", 401, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = wsAccessOps()
			wsAuthorized(t, w)
			wsTokenServer(w, wsTokenBody(), 200)
			bootstrap := wsReply(`{"domains":[{"domainName":"example.com","verified":true}]}`, `{}`)
			api := w.google(func(rw http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/orgunits"):
					jsonReply(200, unitEnvelope)(rw, r)
				case r.URL.Path == "/admin/directory/v1/users":
					jsonReply(200, `{"kind":"admin#directory#users","users":[`+userRow("123", "alice@example.com", "/")+`]}`)(rw, r)
				case strings.HasSuffix(r.URL.Path, "/roleassignments"):
					n, offset, cursor := 600, 0, `,"nextPageToken":"page2"`
					if r.URL.Query().Get("pageToken") != "" {
						n, offset, cursor = tc.second, 600, ""
						if tc.more {
							cursor = `,"nextPageToken":"page3"`
						}
					}
					rows := make([]string, n)
					for i := range n {
						rows[i] = fmt.Sprintf(`{"roleAssignmentId":"a%d","roleId":"r","assignedTo":"123","assigneeType":"USER","scopeType":"CUSTOMER"}`, offset+i)
					}
					jsonReply(200, `{"kind":"admin#directory#roleAssignments","items":[`+strings.Join(rows, ",")+`]`+cursor+`}`)(rw, r)
				default:
					bootstrap(rw, r)
				}
			})
			g := w.gate()
			wsBootstrap(g)
			g.Send(context.Background(), wsInventoryRequest("workspace.units"))
			g.Send(context.Background(), wsInventoryRequest("workspace.users"))
			req := wsInventoryRequest("workspace.user_assignments")
			req.Params["user"] = "123"
			first := g.Send(context.Background(), req)
			if !first.OK() || !first.Response.Population.More {
				t.Fatal(first)
			}
			req.NextOf = first.RequestID
			second := g.Send(context.Background(), req)
			if second.OK() != tc.ok {
				t.Fatal(second)
			}
			if tc.more {
				if second.Response.Population.More || !slices.Contains(second.Response.Population.Incomplete, "item_limit") {
					t.Fatal(second)
				}
				before := len(api.requests())
				req.NextOf = second.RequestID
				if g.Send(context.Background(), req).OK() || len(api.requests()) != before {
					t.Fatal("sent beyond population cap")
				}
			}
		})
	}
}

func TestMalformedProjectionPreservesUnknownAndSupportedSiblings(t *testing.T) {
	for _, scalar := range []string{`true`, `123`, `"UNDECLARED_SECRET"`} {
		for _, field := range []string{"expirationDetails", "rolePrivileges"} {
			path := field + ".expireTime"
			if field == "rolePrivileges" {
				path = field + ".privilegeName"
			}
			doc, code := parseRedacted([]byte(`{"` + field + `":` + scalar + `}`))
			if code != "" {
				t.Fatal(code)
			}
			body := string(marshal(projectFields(doc, newKeepTree([]string{path}), true)))
			if body != `{"`+field+`":null}` {
				t.Fatal(body)
			}
		}
	}
	doc, code := parseRedacted([]byte(`{"rolePrivileges":[true,{"privilegeName":"USERS_ALL","secret":"UNDECLARED_SECRET"}]}`))
	if code != "" {
		t.Fatal(code)
	}
	body := string(marshal(projectFields(doc, newKeepTree([]string{"rolePrivileges.privilegeName"}), true)))
	if body != `{"rolePrivileges":[null,{"privilegeName":"USERS_ALL"}]}` {
		t.Fatal(body)
	}
	// Existing collectors retain their declared projection semantics.
	if got := string(marshal(project(doc, newKeepTree([]string{"rolePrivileges.privilegeName"})))); got != `{"rolePrivileges":[{"privilegeName":"USERS_ALL"}]}` {
		t.Fatal(got)
	}
}
