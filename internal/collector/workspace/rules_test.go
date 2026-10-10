package workspace

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
)

func ruleFixture() (Evidence, Context) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	u := User{ID: "1", Primary: "alice@example.com", Customer: "C123", Unit: "/", Suspended: new(false), Archived: new(false), IsAdmin: new(false), CreationTime: new("2025-01-01T00:00:00Z"), LastLoginTime: new("2026-10-10T11:00:00Z")}
	read := Read{Op: OpUsers, RequestID: OpUsers, Decision: "sent", Status: 200}
	e := Evidence{Users: Population[User]{Items: []User{u}, Complete: true, Reads: []Read{read}}, Access: AccessEvidence{Roles: Population[Role]{Complete: true, Items: []Role{}, Reads: []Read{{Op: OpRoles, RequestID: OpRoles, Decision: "sent", Status: 200}}}, Privileges: Population[Privilege]{Complete: true, Items: []Privilege{}, Reads: []Read{{Op: OpPrivileges, RequestID: OpPrivileges, Decision: "sent", Status: 200}}}, Accounts: []AccountAccess{{ID: "1", Assignments: Population[Assignment]{Complete: true, Items: []Assignment{}, Reads: []Read{{Op: OpUserAssignments, RequestID: OpUserAssignments, Decision: "sent", Status: 200}}}, Detail: &u, DetailRead: Read{Op: OpUserDetail, RequestID: OpUserDetail, Decision: "sent", Status: 200}}}}}
	c := Context{People: []Person{{Handle: "alice", Kind: "employee", Addresses: []string{u.Primary}}}, ExpectedAdmins: []string{"alice"}, AdminsDeclared: true, AssessedAt: now, Zone: time.UTC}
	return e, c
}
func getRule(t *testing.T, out []finding.Judgment, id string) finding.Judgment {
	t.Helper()
	for _, j := range out {
		if j.ID == id {
			return j
		}
	}
	t.Fatalf("missing rule %s", id)
	return finding.Judgment{}
}
func TestEveryWorkspaceRuleFiresDisprovesAndAbstains(t *testing.T) {
	type tweak func(*Evidence, *Context)
	cases := map[string]struct{ fire, negative, unknown tweak }{
		finding.IDIdentityUnexpectedAdmin: {func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.ExpectedAdmins = []string{} }, func(e *Evidence, _ *Context) { e.Users.Items[0].IsAdmin = new(true) }, func(e *Evidence, c *Context) { c.AdminsDeclared = false; e.Users.Items[0].IsAdmin = new(true) }},
		finding.IDIdentityUnattributedAdmin: {func(e *Evidence, c *Context) {
			e.Users.Items[0].IsAdmin = new(true)
			c.People[0].Addresses = []string{"other@example.com"}
		}, func(e *Evidence, _ *Context) { e.Users.Items[0].IsAdmin = new(true) }, func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.People = nil }},
		finding.IDIdentityExternalAdmin:         {func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.People[0].Kind = "contractor" }, func(e *Evidence, _ *Context) { e.Users.Items[0].IsAdmin = new(true) }, func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.People[0].Kind = "" }},
		finding.IDIdentitySharedAdmin:           {func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.People[0].Kind = "shared" }, func(e *Evidence, _ *Context) { e.Users.Items[0].IsAdmin = new(true) }, func(e *Evidence, c *Context) { e.Users.Items[0].IsAdmin = new(true); c.People[0].Kind = "" }},
		finding.IDIdentityFormerPersonHasAccess: {func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-09" }, func(e *Evidence, c *Context) { c.People[0].Left = "2026-10-09"; e.Users.Items[0].Suspended = new(true) }, func(e *Evidence, c *Context) { c.People[0].Left = "2026-10-09"; e.Users.Items[0].Suspended = nil }},
		IDTooManySuperAdmins: {func(e *Evidence, _ *Context) {
			for i := range 4 {
				u := e.Users.Items[0]
				u.ID = string(rune('2' + i))
				u.Primary = u.ID + "@example.com"
				u.IsAdmin = new(true)
				e.Users.Items = append(e.Users.Items, u)
			}
		}, func(_ *Evidence, _ *Context) {}, func(e *Evidence, _ *Context) { e.Users.Complete = false }},
		IDStaleAccount:  {func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = new("2026-01-01T00:00:00Z") }, func(_ *Evidence, _ *Context) {}, func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail = nil }},
		IDNeverSignedIn: {func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = new(neverLogin) }, func(_ *Evidence, _ *Context) {}, func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = nil }},
		IDSuspendedAdminAssignment: {func(e *Evidence, _ *Context) {
			e.Users.Items[0].Suspended = new(true)
			e.Users.Items[0].IsAdmin = new(true)
		}, func(_ *Evidence, _ *Context) {}, func(e *Evidence, _ *Context) { e.Users.Items[0].Suspended = nil }},
	}
	for _, id := range RuleIDs() {
		tc, ok := cases[id]
		if !ok {
			t.Fatal("missing fixtures", id)
		}
		for _, variant := range []struct {
			name, want string
			change     tweak
		}{{"fires", Fired, tc.fire}, {"disproves", Disproved, tc.negative}, {"abstains", Abstained, tc.unknown}} {
			t.Run(id+"/"+variant.name, func(t *testing.T) {
				e, c := ruleFixture()
				variant.change(&e, &c)
				j := getRule(t, Judge(e, "saas:google-workspace:example.com", c), id)
				if j.Verdict != variant.want {
					t.Fatalf("want %s got %+v", variant.want, j)
				}
				def, ok := finding.Lookup(id)
				if !ok || def.Area != finding.AreaIdentity {
					t.Fatal("missing definition", id)
				}
				if id != IDTooManySuperAdmins && def.Subject != "account" {
					t.Fatal("wrong subject", id)
				}
			})
		}
	}
}
func TestWorkspaceSupportedIndirectPrivilegesAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		assignment Assignment
		want       string
	}{
		{"direct", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER"}, Fired},
		{"indirect group", Assignment{ID: "a", Role: "r", Assignee: "group1", Type: "GROUP", Scope: "CUSTOMER"}, Fired},
		{"future expiry", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER", Expiration: json.RawMessage(`{"expireTime":"2026-10-11T00:00:00Z"}`)}, Fired},
		{"expired", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER", Expiration: json.RawMessage(`{"expireTime":"2026-10-09T00:00:00Z"}`)}, Disproved},
		{"expiry instant", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER", Expiration: json.RawMessage(`{"expireTime":"2026-10-10T12:00:00Z"}`)}, Disproved},
		{"null expiry", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER", Expiration: json.RawMessage(`null`)}, Abstained},
		{"condition", Assignment{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER", Condition: json.RawMessage(`"true"`)}, Abstained},
		{"wrong beneficiary", Assignment{ID: "a", Role: "r", Assignee: "2", Type: "USER", Scope: "CUSTOMER"}, Abstained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, c := ruleFixture()
			c.People[0].Addresses = []string{"other@example.com"}
			e.Users.Items[0].Suspended = new(true)
			e.Access.Roles.Items = []Role{{ID: "r", Privileges: []Privilege{{Service: "00haapch16h1ysv", Name: "USERS_RESET_PASSWORD"}, {Service: "unknown", Name: "unknown"}}}}
			e.Access.Accounts[0].Assignments.Items = []Assignment{tc.assignment}
			j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment)
			if j.Verdict != tc.want {
				t.Fatalf("want%s got%+v", tc.want, j)
			}
		})
	}
}
func TestWorkspaceInactivityCalendarBoundaries(t *testing.T) {
	z, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{30, 90} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			e, c := ruleFixture()
			c.Zone = z
			c.AssessedAt = time.Date(2026, 11, 1, 12, 0, 0, 0, z)
			boundary := c.AssessedAt.AddDate(0, 0, -days).Add(delta)
			id := IDStaleAccount
			if days == 30 {
				id = IDNeverSignedIn
				e.Access.Accounts[0].Detail.LastLoginTime = new(neverLogin)
				e.Access.Accounts[0].Detail.CreationTime = new(boundary.Format(time.RFC3339Nano))
			} else {
				e.Access.Accounts[0].Detail.LastLoginTime = new(boundary.Format(time.RFC3339Nano))
			}
			j := getRule(t, Judge(e, "asset", c), id)
			want := Disproved
			if delta < 0 {
				want = Fired
			}
			if j.Verdict != want {
				t.Fatalf("days%d delta%s got%+v", days, delta, j)
			}
		}
	}
}
func TestWorkspaceUnknownAndConflictingEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Evidence, *Context)
		id     string
	}{
		{"alias leaver", func(e *Evidence, c *Context) {
			c.People[0].Left = "2026-10-09"
			c.People[0].Addresses = []string{"old@example.com"}
			e.Users.Items[0].Aliases = []string{"old@example.com"}
		}, finding.IDIdentityFormerPersonHasAccess},
		{"today leaving", func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-10" }, finding.IDIdentityFormerPersonHasAccess},
		{"security conflict", func(e *Evidence, _ *Context) {
			e.Users.Items[0].IsAdmin = new(true)
			e.Access.Accounts[0].Conflict = true
		}, finding.IDIdentityUnexpectedAdmin},
		{"future login", func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = new("2027-01-01T00:00:00Z") }, IDStaleAccount},
		{"login before creation", func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = new("2024-01-01T00:00:00Z") }, IDStaleAccount},
		{"unfamiliar never", func(e *Evidence, _ *Context) { e.Access.Accounts[0].Detail.LastLoginTime = new("1970-01-01T00:00:00Z") }, IDNeverSignedIn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, c := ruleFixture()
			tc.change(&e, &c)
			j := getRule(t, Judge(e, "asset", c), tc.id)
			if j.Verdict != Abstained {
				t.Fatal(j)
			}
		})
	}
}
func TestWorkspaceAdminCountExemptionsAndRatio(t *testing.T) {
	e, c := ruleFixture()
	e.Users.Items = nil
	c.People = nil
	for i := range 5 {
		u := User{ID: string(rune('1' + i)), Primary: string(rune('a'+i)) + "@example.com", IsAdmin: new(true), Suspended: new(false), Archived: new(false)}
		e.Users.Items = append(e.Users.Items, u)
		c.People = append(c.People, Person{Handle: u.ID, Kind: "break_glass", Addresses: []string{u.Primary}})
	}
	j := getRule(t, Judge(e, "asset", c), IDTooManySuperAdmins)
	if j.Verdict != Abstained || j.Details["super_admins"] != 3 {
		t.Fatal(j)
	}
	e.Users.Complete = false
	j = getRule(t, Judge(e, "asset", c), IDTooManySuperAdmins)
	if j.Verdict != Abstained {
		t.Fatal(j)
	}
	e, c = ruleFixture()
	e.Access.Accounts[0].Assignments.Complete = false
	e.Users.Items[0].IsAdmin = new(true)
	c.People[0].Left = "2026-10-09"
	j = getRule(t, Judge(e, "asset", c), finding.IDIdentityFormerPersonHasAccess)
	if j.Verdict != Fired || !slices.Contains(j.Attributes, "admin") {
		t.Fatal(j)
	}
}

func TestWorkspaceReviewRegressions(t *testing.T) {
	t.Run("nested privileged descendant", func(t *testing.T) {
		e, c := ruleFixture()
		e.Users.Items[0].Suspended = new(true)
		e.Access.Roles.Items = []Role{{ID: "r", Privileges: []Privilege{{Service: "00haapch16h1ysv", Name: "UNFAMILIAR_PARENT"}}}}
		e.Access.Privileges.Items = []Privilege{{Service: "00haapch16h1ysv", Name: "OUTER", Children: []Privilege{{Service: "00haapch16h1ysv", Name: "UNFAMILIAR_PARENT", Children: []Privilege{{Service: "00haapch16h1ysv", Name: "USERS_RESET_PASSWORD"}}}}}}
		e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER"}}
		if j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment); j.Verdict != Fired {
			t.Fatal(j)
		}
	})
	t.Run("unfamiliar leaf not safe", func(t *testing.T) {
		e, c := ruleFixture()
		e.Users.Items[0].Suspended = new(true)
		p := Privilege{Service: "00haapch16h1ysv", Name: "UNKNOWN"}
		e.Access.Roles.Items = []Role{{ID: "r", Privileges: []Privilege{p}}}
		e.Access.Privileges.Items = []Privilege{p}
		e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER"}}
		if j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment); j.Verdict != Abstained {
			t.Fatal(j)
		}
	})
	t.Run("possible service alias", func(t *testing.T) {
		e, c := ruleFixture()
		e.Users.Items[0].Aliases = []string{"service@example.com"}
		c.People = append(c.People, Person{Handle: "service", Kind: "service", Addresses: []string{"service@example.com"}})
		e.Access.Accounts[0].Detail.LastLoginTime = new("2026-01-01T00:00:00Z")
		if j := getRule(t, Judge(e, "asset", c), IDStaleAccount); j.Verdict != Abstained {
			t.Fatal(j)
		}
	})
	t.Run("leaver missing address", func(t *testing.T) {
		e, c := ruleFixture()
		c.People[0].Left = "2026-10-09"
		c.People[0].Addresses = nil
		if j := getRule(t, Judge(e, "asset", c), finding.IDIdentityFormerPersonHasAccess); j.Verdict != Abstained {
			t.Fatal(j)
		}
	})
	t.Run("empty condition", func(t *testing.T) {
		current, known := currentAssignment(Assignment{Condition: json.RawMessage(`""`)}, time.Now())
		if !current || !known {
			t.Fatal("empty unconditional grant rejected")
		}
	})
	t.Run("exempt conflict does not subtract", func(t *testing.T) {
		e, c := ruleFixture()
		e.Users.Items[0].IsAdmin = new(true)
		c.People[0].Kind = "service"
		e.Access.Accounts[0].Conflict = true
		for i := range 4 {
			u := e.Users.Items[0]
			u.ID = string(rune('2' + i))
			u.Primary = u.ID + "@example.com"
			e.Users.Items = append(e.Users.Items, u)
		}
		if j := getRule(t, Judge(e, "asset", c), IDTooManySuperAdmins); j.Verdict != Fired || j.Details["super_admins"] != 4 {
			t.Fatal(j)
		}
	})
}

func TestProjectedMalformedEvidenceAbstainsAndPreservesPositiveSibling(t *testing.T) {
	for _, body := range []string{`{"roleId":"r","rolePrivileges":[null]}`, `{"roleId":"r","rolePrivileges":null}`} {
		e, c := ruleFixture()
		e.Users.Items[0].Suspended = new(true)
		var role Role
		if err := json.Unmarshal([]byte(body), &role); err != nil {
			t.Fatal(err)
		}
		e.Access.Roles.Items = []Role{role}
		e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "a", Role: "r", Assignee: "1", Type: "USER", Scope: "CUSTOMER"}}
		if j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment); j.Verdict != Abstained {
			t.Fatal(j)
		}
		e.Access.Roles.Items[0].Privileges = append(e.Access.Roles.Items[0].Privileges, Privilege{Service: "00haapch16h1ysv", Name: "USERS_ALL"})
		if j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment); j.Verdict != Fired {
			t.Fatal(j)
		}
		e.Access.Accounts[0].Assignments.Items[0].Expiration = json.RawMessage(`null`)
		if j := getRule(t, Judge(e, "asset", c), IDSuspendedAdminAssignment); j.Verdict != Abstained {
			t.Fatal(j)
		}
	}
}
func TestLoginConflictRejectsRegressionToNever(t *testing.T) {
	e, c := ruleFixture()
	e.Access.Accounts[0].Detail.LastLoginTime = new(neverLogin)
	e.Access.Accounts[0].Conflict = securityConflict(e.Users.Items[0], *e.Access.Accounts[0].Detail)
	if !e.Access.Accounts[0].Conflict {
		t.Fatal("actual login regressed to never without conflict")
	}
	if j := getRule(t, Judge(e, "asset", c), IDNeverSignedIn); j.Verdict != Abstained {
		t.Fatal(j)
	}
	list := e.Users.Items[0]
	list.LastLoginTime = new(neverLogin)
	fresh := list
	fresh.LastLoginTime = new("2026-10-10T11:00:00Z")
	if securityConflict(list, fresh) {
		t.Fatal("legitimate first login became a conflict")
	}
}
