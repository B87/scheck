package workspace

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// stepUser is an active non-administrator with complete, empty assignments.
func stepUser(id, unit string, enforced, enrolled *bool) User {
	return User{ID: id, Primary: id + "@example.com", Customer: "C123", Unit: unit, Suspended: new(false), Archived: new(false), IsAdmin: new(false), Enforced: enforced, Enrolled: enrolled}
}

func stepFixture(users ...User) (Evidence, Context) {
	e, c := ruleFixture()
	c.People = nil
	e.Units.Items = []Unit{{ID: "root", Path: "/"}, {ID: "sales", Path: "/Sales", ParentPath: "/"}, {ID: "eng", Path: "/Eng", ParentPath: "/"}}
	e.Users.Items = users
	e.Access.Accounts = nil
	for _, u := range users {
		e.Access.Accounts = append(e.Access.Accounts, AccountAccess{ID: u.ID, Assignments: Population[Assignment]{Complete: true, Items: []Assignment{}, Reads: []Read{{Op: OpUserAssignments, RequestID: "a" + u.ID, Decision: "sent", Status: 200}}}})
	}
	return e, c
}

// withDetail records a fresh detail as Collect does, flagging a 2-step
// difference from the list.
func withDetail(e *Evidence, i int, d User) {
	e.Access.Accounts[i].Detail = &d
	e.Access.Accounts[i].TwoStepUnknown = twoStepConflict(e.Users.Items[i], d)
}

func unitOutcome(t *testing.T, out []finding.Judgment, key string) (finding.Judgment, bool) {
	t.Helper()
	for _, j := range out {
		if j.ID == IDTwoStepNotEnforced && j.Subject.Key == key {
			return j, true
		}
	}
	return finding.Judgment{}, false
}

func accountOutcome(t *testing.T, out []finding.Judgment, primary string) finding.Judgment {
	t.Helper()
	for _, j := range out {
		if j.ID == IDAdminWithoutTwoStep && j.Subject.Label == primary {
			return j
		}
	}
	t.Fatalf("missing admin 2-step outcome for %s", primary)
	return finding.Judgment{}
}

func mustUnit(t *testing.T, e Evidence, c Context, key, want string) finding.Judgment {
	t.Helper()
	j, ok := unitOutcome(t, Judge(e, "asset", c), key)
	if !ok || j.Verdict != want {
		t.Fatalf("unit %s: want %s, got %+v (present %t)", key, want, j, ok)
	}
	return j
}

func TestTwoStepUnitGroupingListedOrderAndDetails(t *testing.T) {
	e, c := stepFixture(
		stepUser("zed", "/Sales", new(false), new(false)),
		stepUser("amy", "/Sales", new(false), new(true)),
		stepUser("max", "/Sales", new(false), nil),
		stepUser("bob", "/sales", new(true), new(true)),
		stepUser("eve", "/Eng", new(true), new(true)),
	)
	j := mustUnit(t, e, c, "/sales", Fired)
	if j.Subject.Kind != "org_unit" || j.Subject.Label != "/Sales" {
		t.Fatal(j.Subject)
	}
	if want := []string{"zed@example.com", "amy@example.com", "max@example.com"}; !slices.Equal(j.Listed, want) {
		t.Fatal(j.Listed)
	}
	if j.Details["affected"] != 3 || j.Details["not_enrolled"] != 1 || j.Details["enrolled"] != 1 || j.Details["enrollment_unknown"] != 1 || j.Details["active_observed"] != 4 || j.Details["state_unknown"] != 0 || j.Details["population_complete"] != true {
		t.Fatal(j.Details)
	}
	if !strings.Contains(j.Excerpt, "not currently required for 3 active accounts in unit /Sales (isEnforcedIn2Sv: false)") || !strings.Contains(j.Excerpt, "1 not enrolled, 1 enrolled, 1 unknown") || !strings.Contains(j.Excerpt, "Not enrolled: zed@example.com. Enrolled: amy@example.com. Enrollment unknown: max@example.com.") || !strings.Contains(j.Excerpt, twoStepParagraph) || strings.Contains(j.Excerpt, "at least") {
		t.Fatal(j.Excerpt)
	}
	for _, claim := range []string{"policy is", "disabled", "grace period of"} {
		if strings.Contains(j.Excerpt, claim) {
			t.Fatal("claims unit policy or grace", j.Excerpt)
		}
	}
	mustUnit(t, e, c, "/eng", Disproved)
	if _, ok := unitOutcome(t, Judge(e, "asset", c), "/"); ok {
		t.Fatal("a unit with no accounts was judged")
	}
}

func TestTwoStepUnitFiresOnPartialAndUnknownEvidence(t *testing.T) {
	e, c := stepFixture(stepUser("a", "/", new(false), new(false)), stepUser("b", "/", nil, nil))
	j := mustUnit(t, e, c, "/", Fired)
	if !strings.Contains(j.Excerpt, "at least 1 active account in") || j.Details["state_unknown"] != 1 {
		t.Fatal(j)
	}
	e, c = stepFixture(stepUser("a", "/", new(false), new(false)))
	e.Users.Complete = false
	j = mustUnit(t, e, c, "/", Fired)
	if !strings.Contains(j.Excerpt, "at least 1") || j.Details["population_complete"] != false {
		t.Fatal(j)
	}
}

func TestTwoStepUnitAbstentions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Evidence)
	}{
		{"missing flag", func(e *Evidence) { e.Users.Items[1].Enforced = nil }},
		{"unknown activity", func(e *Evidence) { e.Users.Items[1].Suspended = nil }},
		{"list true detail false", func(e *Evidence) {
			d := e.Users.Items[1]
			d.Enforced = new(false)
			withDetail(e, 1, d)
		}},
		{"list false detail true", func(e *Evidence) {
			e.Users.Items[1].Enforced = new(false)
			d := e.Users.Items[1]
			d.Enforced = new(true)
			withDetail(e, 1, d)
		}},
		{"rejected fresh detail", func(e *Evidence) {
			e.Users.Items[1].Enforced = new(false)
			e.Access.Accounts[1].TwoStepUnknown = true
		}},
		{"step-3 security conflict", func(e *Evidence) {
			e.Users.Items[1].Enforced = new(false)
			e.Access.Accounts[1].Conflict = true
		}},
		{"exclusion or any drop", func(e *Evidence) { e.Users.Complete = false }},
		{"unit not in tree", func(e *Evidence) {
			e.Units.Items = []Unit{{ID: "root", Path: "/"}}
		}},
		{"case-ambiguous tree", func(e *Evidence) {
			e.Units.Items = append(e.Units.Items, Unit{ID: "sales2", Path: "/SALES", ParentPath: "/"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, c := stepFixture(stepUser("a", "/Sales", new(true), new(true)), stepUser("b", "/Sales", new(true), new(true)))
			tc.change(&e)
			j := mustUnit(t, e, c, "/sales", Abstained)
			if len(j.NotChecked) == 0 {
				t.Fatal("abstention without explanation", j)
			}
		})
	}
	t.Run("not in tree still fires", func(t *testing.T) {
		e, c := stepFixture(stepUser("a", "/Gone", new(false), new(false)))
		j := mustUnit(t, e, c, "/gone", Fired)
		if !strings.Contains(j.Excerpt, "unit not found in the unit list") {
			t.Fatal(j.Excerpt)
		}
	})
	t.Run("ambiguous path note", func(t *testing.T) {
		e, c := stepFixture(stepUser("a", "/Sales", new(true), new(true)))
		e.Units.Items = append(e.Units.Items, Unit{ID: "sales2", Path: "/SALES", ParentPath: "/"})
		if !slices.ContainsFunc(twoStepNotes(e, "asset", c), func(n Note) bool { return strings.Contains(n.Detail, "written with different capitals") }) {
			t.Fatal("ambiguous unit path not noted")
		}
	})
}

func TestTwoStepInactiveExemptionsAndAssetLevel(t *testing.T) {
	suspended := stepUser("s", "/Eng", new(false), new(false))
	suspended.Suspended = new(true)
	archived := stepUser("r", "/Eng", new(false), new(false))
	archived.Archived = new(true)
	e, c := stepFixture(suspended, archived, stepUser("a", "/", new(true), new(true)))
	if _, ok := unitOutcome(t, Judge(e, "asset", c), "/eng"); ok {
		t.Fatal("inactive-only unit judged")
	}
	mustUnit(t, e, c, "/", Disproved)
	if j := accountOutcome(t, Judge(e, "asset", c), "s@example.com"); j.Verdict != Disproved {
		t.Fatal(j)
	}

	e, c = stepFixture(suspended)
	j := getRule(t, Judge(e, "asset", c), IDTwoStepNotEnforced)
	if j.Verdict != Abstained || j.Subject != (finding.Subject{}) || len(j.NotChecked) == 0 {
		t.Fatal("no active accounts", j)
	}
	e, c = stepFixture()
	j = getRule(t, Judge(e, "asset", c), IDTwoStepNotEnforced)
	if j.Verdict != Abstained || j.Subject != (finding.Subject{}) {
		t.Fatal("empty population", j)
	}

	// No kind is exempt (docs/spec/engagement.md, kinds).
	e, c = stepFixture(stepUser("svc", "/", new(false), new(false)), stepUser("glass", "/", new(false), new(false)))
	c.People = []Person{{Handle: "svc", Kind: "service", Addresses: []string{"svc@example.com"}}, {Handle: "glass", Kind: "break_glass", Addresses: []string{"glass@example.com"}}}
	e.Users.Items[1].IsAdmin = new(true)
	e.Users.Items[0].CreationTime = new("2026-10-10T11:00:00Z")
	out := Judge(e, "asset", c)
	if j, _ := unitOutcome(t, out, "/"); j.Verdict != Fired || len(j.Listed) != 2 {
		t.Fatal(j)
	}
	if j := accountOutcome(t, out, "glass@example.com"); j.Verdict != Fired {
		t.Fatal("break-glass admin exempted", j)
	}
}

func TestAdminWithoutTwoStepOutcomes(t *testing.T) {
	directory := func(name string) Role {
		return Role{ID: "r", Privileges: []Privilege{{Service: "00haapch16h1ysv", Name: name}}}
	}
	for _, tc := range []struct {
		name   string
		change func(*Evidence)
		want   string
		text   string
	}{
		{"super admin", func(e *Evidence) { e.Users.Items[0].IsAdmin = new(true) }, Fired, "super administrator (isAdmin: true)"},
		{"customer-wide delegate", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("USERS_RESET_PASSWORD")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "CUSTOMER"}}
		}, Fired, "USERS_RESET_PASSWORD"},
		{"unit-scoped delegate", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("USERS_ALL")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "ORG_UNIT", Unit: "sales"}}
		}, Fired, "ORG_UNIT sales"},
		{"enforced but unenrolled admin", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = new(true)
			e.Users.Items[0].Enforced = new(true)
		}, Fired, "a password alone may sign it in"},
		{"enrolled with unknown admin", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = nil
			e.Users.Items[0].Enrolled = new(true)
		}, Disproved, "does not establish the verification method"},
		{"suspended admin", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = new(true)
			e.Users.Items[0].Suspended = new(true)
		}, Disproved, "suspended or archived"},
		{"known not admin", func(_ *Evidence) {}, Disproved, "no administrative privilege recognized"},
		{"expired delegate", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("USERS_ALL")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "CUSTOMER", Expiration: json.RawMessage(`{"expireTime":"2026-10-01T00:00:00Z"}`)}}
		}, Disproved, ""},
		{"narrow privilege only", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("USERS_RETRIEVE")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "CUSTOMER"}}
		}, Disproved, ""},
		{"unknown enrollment", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = new(true)
			e.Users.Items[0].Enrolled = nil
		}, Abstained, ""},
		{"unknown privilege", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("SOMETHING_NEW")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "CUSTOMER"}}
		}, Abstained, ""},
		{"unknown condition", func(e *Evidence) {
			e.Access.Roles.Items = []Role{directory("USERS_ALL")}
			e.Access.Accounts[0].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "a", Type: "USER", Scope: "CUSTOMER", Condition: json.RawMessage(`"api.getAttribute('x')"`)}}
		}, Abstained, ""},
		{"missing isAdmin", func(e *Evidence) { e.Users.Items[0].IsAdmin = nil }, Abstained, ""},
		{"unknown activity", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = new(true)
			e.Users.Items[0].Archived = nil
		}, Abstained, ""},
		{"incomplete assignments", func(e *Evidence) { e.Access.Accounts[0].Assignments.Complete = false }, Abstained, ""},
		{"enrollment conflict", func(e *Evidence) {
			e.Users.Items[0].IsAdmin = new(true)
			d := e.Users.Items[0]
			d.Enrolled = new(true)
			withDetail(e, 0, d)
		}, Abstained, "conflicted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, c := stepFixture(stepUser("a", "/", new(false), new(false)))
			tc.change(&e)
			j := accountOutcome(t, Judge(e, "asset", c), "a@example.com")
			if j.Verdict != tc.want || !strings.Contains(j.Excerpt, tc.text) {
				t.Fatalf("want %s with %q, got %+v", tc.want, tc.text, j)
			}
			if j.Has("contradiction") {
				t.Fatal("enrollment raised as a contradiction")
			}
		})
	}
	t.Run("service admin fires", func(t *testing.T) {
		e, c := stepFixture(stepUser("a", "/", new(true), new(false)))
		e.Users.Items[0].IsAdmin = new(true)
		c.People = []Person{{Handle: "svc", Kind: "service", Addresses: []string{"a@example.com"}}}
		c.MFA, c.MFASource = "everyone", "access.mfa[0]"
		if j := accountOutcome(t, Judge(e, "asset", c), "a@example.com"); j.Verdict != Fired || len(j.Sources) != 0 {
			t.Fatal(j)
		}
	})
}

func TestTwoStepDeclarationComparison(t *testing.T) {
	raised := func(j finding.Judgment) bool {
		return j.Has("contradiction") && slices.Equal(j.Sources, []string{"access.mfa[0]"}) && strings.Contains(j.Why, "so this ranks one step higher") && slices.Equal(j.NotChecked, []string{federationCaveat})
	}
	base := func() (Evidence, Context) {
		admin := stepUser("boss", "/Eng", new(false), new(false))
		admin.IsAdmin = new(true)
		delegate := stepUser("help", "/Sales", new(false), new(true))
		e, c := stepFixture(admin, delegate, stepUser("ok", "/", new(true), new(true)))
		e.Access.Roles.Items = []Role{{ID: "r", Privileges: []Privilege{{Service: "00haapch16h1ysv", Name: "USERS_ALL"}}}}
		e.Access.Accounts[1].Assignments.Items = []Assignment{{ID: "x", Role: "r", Assignee: "help", Type: "USER", Scope: "CUSTOMER"}}
		c.MFASource = "access.mfa[0]"
		return e, c
	}
	for _, tc := range []struct {
		mfa               string
		eng, sales, admin bool
	}{
		{"everyone", true, true, false},
		{"admins", true, false, false},
		{"some", false, false, false},
		{"none", false, false, false},
		{"unknown", false, false, false},
		{"", false, false, false},
	} {
		t.Run("declared "+tc.mfa, func(t *testing.T) {
			e, c := base()
			c.MFA = tc.mfa
			if tc.mfa == "" {
				c.MFASource = ""
			}
			out := Judge(e, "asset", c)
			eng, _ := unitOutcome(t, out, "/eng")
			sales, _ := unitOutcome(t, out, "/sales")
			root, _ := unitOutcome(t, out, "/")
			if eng.Verdict != Fired || sales.Verdict != Fired || root.Verdict != Disproved {
				t.Fatal(eng, sales, root)
			}
			if raised(eng) != tc.eng || raised(sales) != tc.sales || raised(root) {
				t.Fatalf("raise mismatch: eng %+v sales %+v", eng, sales)
			}
			if !raised(eng) && (eng.Why != "" || len(eng.Sources) != 0 || len(eng.NotChecked) != 0) {
				t.Fatal("caveat or source on an unraised instance", eng)
			}
			if j := accountOutcome(t, out, "boss@example.com"); j.Verdict != Fired || raised(j) {
				t.Fatal(j)
			}
		})
	}
	some := func(change func(*Evidence)) bool {
		e, c := stepFixture(stepUser("a", "/", new(false), new(false)), stepUser("b", "/Eng", new(false), new(true)))
		c.MFA, c.MFASource = "some", "access.mfa[0]"
		change(&e)
		j, _ := unitOutcome(t, Judge(e, "asset", c), "/")
		return j.Verdict == Fired && raised(j)
	}
	if !some(func(*Evidence) {}) {
		t.Fatal("some not raised when every active account is off")
	}
	if some(func(e *Evidence) { e.Users.Complete = false }) {
		t.Fatal("some raised on a partial population")
	}
	if some(func(e *Evidence) { e.Users.Items[1].Enforced = new(true) }) {
		t.Fatal("some raised with one account required")
	}
	if some(func(e *Evidence) { e.Users.Items[1].Enforced = nil }) {
		t.Fatal("some raised with one account unknown")
	}
}

func TestTwoStepNotes(t *testing.T) {
	has := func(notes []Note, text string) bool {
		return slices.ContainsFunc(notes, func(n Note) bool { return strings.Contains(n.Detail, text) })
	}
	admin := stepUser("boss", "/", new(true), new(false))
	admin.IsAdmin = new(true)
	unknownAdmin := stepUser("maybe", "/", new(true), new(false))
	unknownAdmin.IsAdmin = nil
	e, c := stepFixture(admin, unknownAdmin, stepUser("new", "/", new(true), new(false)), stepUser("off", "/", new(false), new(false)))
	notes := twoStepNotes(e, "asset", c)
	if !has(notes, "Organizational-unit policy, grace periods, configuration groups") {
		t.Fatal("limits note missing", notes)
	}
	if !has(notes, "Google requires 2-step verification for 2 accounts that it reports as not yet enrolled: maybe@example.com, new@example.com.") || has(notes, "boss@example.com") {
		t.Fatal("grace note", notes)
	}
	if !has(notes, "Google reports 1 of 4 active accounts in this Workspace not currently required") || !has(notes, "You did not say who must use it; declare it under access.mfa") {
		t.Fatal("undeclared readout", notes)
	}
	c.MFA = "unknown"
	e.Users.Complete = false
	notes = twoStepNotes(e, "asset", c)
	if !has(notes, "at least 1 active account in this Workspace not currently required") || !has(notes, "list of users was incomplete") || !has(notes, "do not know") || !has(notes, "for at least 2 accounts") {
		t.Fatal("partial unknown readout", notes)
	}
	e, c = stepFixture(stepUser("a", "/", new(true), new(true)), stepUser("b", "/", new(false), new(true)))
	c.MFA = "none"
	if !has(twoStepNotes(e, "asset", c), "Google reports 1 active account currently required to use 2-step verification, more than you declared.") {
		t.Fatal("none better note")
	}
	e, c = stepFixture(stepUser("a", "/", new(true), new(true)))
	for mfa, text := range map[string]string{"everyone": "as you declared", "some": "more than you declared"} {
		c.MFA = mfa
		if !has(twoStepNotes(e, "asset", c), "every active account currently required to use 2-step verification, "+text) {
			t.Fatal(mfa)
		}
	}
	e.Users.Complete = false
	c.MFA = "everyone"
	if has(twoStepNotes(e, "asset", c), "as you declared") {
		t.Fatal("matching note on a partial population")
	}
	if twoStepNotes(Evidence{}, "asset", c) != nil {
		t.Fatal("2-step notes without a users read")
	}
}

// A fresh detail the collector cannot accept leaves the 2-step state unknown;
// a failed detail read falls back to the list (docs/spec/workspace-collector.md,
// "Dates and fresh evidence").
func TestCollectFreshDetailTwoStepEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		status       int
		reason, want string
	}{
		{"null flag", `{"id":"123","primaryEmail":"a@example.com","customerId":"C123","orgUnitPath":"/","suspended":false,"archived":false,"isAdmin":false,"isEnforcedIn2Sv":null}`, 200, "", Abstained},
		{"conflicting flag", `{"id":"123","primaryEmail":"a@example.com","customerId":"C123","orgUnitPath":"/","suspended":false,"archived":false,"isAdmin":false,"isEnforcedIn2Sv":true}`, 200, "", Abstained},
		{"refused detail", ``, 200, "unavailable:malformed_response", Abstained},
		{"agreeing detail", `{"id":"123","primaryEmail":"a@example.com","customerId":"C123","orgUnitPath":"/","suspended":false,"archived":false,"isAdmin":false,"isEnforcedIn2Sv":false}`, 200, "", Fired},
		{"denied detail", ``, 403, "insufficient_permission", Fired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
				switch r.Op {
				case OpUsers:
					return inventoryResult(r.Op, `[{"id":"123","primaryEmail":"a@example.com","customerId":"C123","orgUnitPath":"/","suspended":false,"archived":false,"isAdmin":false,"isEnforcedIn2Sv":false,"isEnrolledIn2Sv":false}]`)
				case OpRoles, OpPrivileges, OpUserAssignments:
					return inventoryResult(r.Op, `[]`)
				case OpUserDetail:
					res := gate.Result{RequestID: r.Op, Decision: "sent", Reason: tc.reason, Response: &gate.Response{Status: tc.status, Body: []byte(tc.detail)}}
					return res
				}
				return inventoryFixture(r.Op)
			})
			e := Collect(context.Background(), sender, Target{Asset: "saas:google-workspace:example.com", Stage: "recon"}, Context{})
			j, ok := unitOutcome(t, e.Judgments, "/")
			if !ok || j.Verdict != tc.want {
				t.Fatalf("want %s got %+v", tc.want, j)
			}
		})
	}
}

func TestListAccountsCapsTheText(t *testing.T) {
	many := []string{}
	for i := range 25 {
		many = append(many, string(rune('a'+i))+"@example.com")
	}
	text := listAccounts(many[:18], many[18:22], many[22:])
	if !strings.Contains(text, "Enrolled: s@example.com, t@example.com.") || strings.Contains(text, "u@example.com") || !strings.Contains(text, "And 5 more, listed in the JSON report (--format json).") {
		t.Fatal(text)
	}
}

func TestTwoStepReviewWording(t *testing.T) {
	has := func(notes []Note, text string) bool {
		return slices.ContainsFunc(notes, func(n Note) bool { return strings.Contains(n.Detail, text) })
	}
	t.Run("raise explains the contradicting fact", func(t *testing.T) {
		admin := stepUser("boss", "/", new(false), new(false))
		admin.IsAdmin = new(true)
		e, c := stepFixture(admin)
		c.MFASource = "access.mfa[0]"
		for mfa, want := range map[string]string{
			"everyone": "You declared that every account must use 2-step verification in this tenant, so this ranks one step higher.",
			"admins":   "and Google does not require it for 1 super administrator in this unit, so this ranks one step higher.",
			"some":     "but Google requires it for no active account in the tenant, so this ranks one step higher.",
		} {
			c.MFA = mfa
			j, _ := unitOutcome(t, Judge(e, "asset", c), "/")
			if !strings.Contains(j.Why, want) || strings.Count(j.Why, ". ") != 0 {
				t.Fatal(mfa, j.Why)
			}
		}
	})
	t.Run("status conflict names its cause", func(t *testing.T) {
		e, c := stepFixture(stepUser("a", "/", new(false), new(false)))
		e.Access.Accounts[0].Conflict = true
		if j := accountOutcome(t, Judge(e, "asset", c), "a@example.com"); j.Verdict != Abstained || !strings.Contains(j.Excerpt, "suspension, archive or administrator status") {
			t.Fatal(j)
		}
	})
	t.Run("unjudged units and unknown administrators are named", func(t *testing.T) {
		maybe := stepUser("maybe", "/Sales", new(false), new(false))
		maybe.IsAdmin = nil
		e, c := stepFixture(stepUser("erin", "/Eng", nil, new(true)), maybe)
		notes := twoStepNotes(e, "asset", c)
		if !has(notes, "1 organizational unit: /Eng (1 account with a missing, unreadable or conflicting flag or activity status). Treat these units as not checked, not as fine.") {
			t.Fatal(notes)
		}
		if !has(notes, "Google reports 1 account not enrolled in 2-step verification whose administrative status scheck could not establish: maybe@example.com.") {
			t.Fatal(notes)
		}
		e.Access.Accounts[1].TwoStepUnknown = true
		if !has(twoStepNotes(e, "asset", c), "maybe@example.com (account id maybe) conflicted or were unreadable") {
			t.Fatal("conflict note does not name the account")
		}
	})
	t.Run("admins match needs every administrator known", func(t *testing.T) {
		admin := stepUser("boss", "/", new(true), new(true))
		admin.IsAdmin = new(true)
		e, c := stepFixture(admin, stepUser("x", "/", new(true), new(true)))
		c.MFA = "admins"
		if !has(twoStepNotes(e, "asset", c), "every super administrator observed currently required to use 2-step verification, as you declared. Required is not the same as enrolled") {
			t.Fatal("admins match note missing")
		}
		e.Users.Items[1].IsAdmin = nil
		if has(twoStepNotes(e, "asset", c), "as you declared") {
			t.Fatal("admins match with an account of unknown admin status")
		}
		e.Users.Items[1].IsAdmin = new(true)
		e.Users.Items[1].Suspended = nil
		if has(twoStepNotes(e, "asset", c), "as you declared") {
			t.Fatal("admins match with a super administrator of unknown activity")
		}
	})
	t.Run("nothing undeclared and all required", func(t *testing.T) {
		e, c := stepFixture(stepUser("a", "/", new(true), new(true)))
		if !has(twoStepNotes(e, "asset", c), "Google reports that every active account in this Workspace (1 active account) is currently required") {
			t.Fatal(twoStepNotes(e, "asset", c))
		}
	})
}

func TestTwoStepReviewNits(t *testing.T) {
	e, c := stepFixture(stepUser("a", "/", new(true), new(false)))
	e.Users.Complete = false
	notes := twoStepNotes(e, "asset", c)
	if slices.ContainsFunc(notes, func(n Note) bool { return strings.Contains(n.Detail, "at least 0") }) || !slices.ContainsFunc(notes, func(n Note) bool {
		return strings.Contains(n.Detail, "No observed active account in this Workspace was reported without")
	}) {
		t.Fatal(notes)
	}
	e, c = stepFixture(stepUser("a", "/", new(false), new(false)))
	e.Access.Accounts[0].TwoStepUnknown = true
	e.Access.Accounts[0].DetailRead = Read{Op: OpUserDetail, RequestID: "g000099", Decision: "sent", Status: 200, Reason: "unavailable:malformed_response"}
	out := Judge(e, "asset", c)
	if j := accountOutcome(t, out, "a@example.com"); j.Verdict != Abstained || !slices.Contains(j.Reads, "g000099") {
		t.Fatal(j)
	}
	if j, _ := unitOutcome(t, out, "/"); j.Verdict != Abstained || !slices.Contains(j.Reads, "g000099") {
		t.Fatal(j)
	}
}
