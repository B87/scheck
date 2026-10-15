package engagement

import (
	"slices"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// The table's invariants (docs/spec/engagement.md, "Plan selection and
// follow-ups"): every read is a declared gate op whose every parameter
// comes from the trigger's subject or a declared repository with the op's
// own type, and the table is acyclic and at most two deep.
func TestFollowUpTableInvariants(t *testing.T) {
	depth := map[string]int{}
	for _, row := range followUpTable {
		if row.ID == "" || depth[row.ID] != 0 {
			t.Fatalf("row %q: no id, or declared twice", row.ID)
		}
		depth[row.ID] = row.Depth
	}
	for _, row := range followUpTable {
		i := slices.IndexFunc(gateOps, func(o gate.Op) bool { return o.ID == row.Op })
		if i < 0 {
			t.Fatalf("%s: op %q is not declared to the gate", row.ID, row.Op)
		}
		op := gateOps[i]
		if len(op.Params) != len(row.Params) {
			t.Fatalf("%s: op %s takes %d parameters, the row gives %d", row.ID, op.ID, len(op.Params), len(row.Params))
		}
		for _, p := range op.Params {
			src, ok := row.Params[p.Name]
			if !ok {
				t.Fatalf("%s: parameter %q has no source", row.ID, p.Name)
			}
			if ty, known := sourceTypes[src]; !known || ty != p.Type {
				t.Fatalf("%s: parameter %q from %q is not of the op's type", row.ID, p.Name, src)
			}
		}
		if _, ok := finding.Lookup(row.Finding); !ok || row.Collector == "" || row.run == nil {
			t.Fatalf("%s: trigger %q on %q, or no loop", row.ID, row.Finding, row.Collector)
		}
		if row.Cap <= 0 || row.Depth < 1 || row.Depth > maxFollowUpDepth {
			t.Fatalf("%s: cap %d, depth %d", row.ID, row.Cap, row.Depth)
		}
		// A row reads only rows strictly shallower: no cycle can form.
		want := 1
		for _, after := range row.After {
			d, ok := depth[after]
			if !ok || d >= row.Depth {
				t.Fatalf("%s: reads %q, which is not a shallower row", row.ID, after)
			}
			want = max(want, d+1)
		}
		if row.Depth != want {
			t.Fatalf("%s: depth %d, its triggers make it %d", row.ID, row.Depth, want)
		}
	}
	if len(followUpTable) != 1 || followUpTable[0].Op != githubc.OpCollaboratorPermission || followUpTable[0].Cap != 20 {
		t.Fatalf("the 0.0.2 table is F1 alone: %+v", followUpTable)
	}
}

// Each pair's outcome, as check.json words it.
func TestFollowUpOutcome(t *testing.T) {
	for _, c := range []struct {
		read githubc.Read
		want string
	}{
		{githubc.Read{Decision: "sent", Status: 200}, "read"},
		{githubc.Read{Decision: "reused", Status: 200}, "read"},
		{githubc.Read{Decision: "sent", Status: 404}, "not_found"},
		{githubc.Read{Decision: "sent", Status: 403, Reason: "insufficient_permission"}, "denied"},
		{githubc.Read{Decision: "unavailable:server_error", Status: 502, Reason: "unavailable:server_error"}, "failed"},
		{githubc.Read{Decision: "not_sent", Reason: githubc.ReasonFollowUpCap}, "not_sent"},
		{githubc.Read{Decision: "refused:rate_limit", Reason: "limit_reached"}, "not_sent"},
		{githubc.Read{Decision: "unavailable:deadline", Reason: "limit_reached", Sent: true}, "failed"},
		{githubc.Read{Decision: "sent", Status: 403, Reason: "limit_reached"}, "failed"},
	} {
		if got := followUpOutcome(c.read); got != c.want {
			t.Errorf("%+v: %s, want %s", c.read, got, c.want)
		}
	}
}

// The coverage count says asked only of a pair that reached GitHub, and
// names the stop of one the gate cut before sending.
func TestPermissionAsks(t *testing.T) {
	n := permissionAsks(githubc.Evidence{Permissions: []githubc.PermissionRead{
		{Read: githubc.Read{Decision: "sent", Status: 200, Sent: true}},
		{Read: githubc.Read{Decision: "unavailable:deadline", Reason: "limit_reached", Sent: true, Detail: "in flight"}},
		{Read: githubc.Read{Decision: "refused:rate_limit", Reason: "limit_reached", Detail: "the rate limit"}},
		{Read: githubc.Read{Decision: "not_sent", Reason: githubc.ReasonFollowUpCap}},
	}})
	if n.Opened != 4 || n.Asked != 2 || n.Stopped != "the rate limit" || !n.Capped {
		t.Fatalf("%+v", n)
	}
}

// A 401 on one organization's permission read refuses that root; another
// GitHub root Check left collected, sharing the token, is incomplete with
// the stop's detail (docs/spec/engagement.md, "Plan selection and
// follow-ups").
func TestFollowUpRefusalAndStopOnTwoRoots(t *testing.T) {
	file := `schema: 1
engagement: {name: two, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}, {saas: "github:beta"}]
`
	res, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: res, recon: &ReconDoc{Assets: []ReconAsset{
		{Name: "saas:github:acme", ID: "saas:github:acme", Root: "saas:github:acme", Status: StatusCollected, GitHub: &githubc.Evidence{}},
		{Name: "saas:github:beta", ID: "saas:github:beta", Root: "saas:github:beta", Status: StatusCollected, GitHub: &githubc.Evidence{}},
	}}}
	const detail = "GitHub did not accept the token in GITHUB_TOKEN (expired, revoked or mistyped)"
	r.followUpRefused(0, githubc.Read{Reason: "refused", Kind: "access", Detail: detail})
	r.followUpStopped(1, detail)
	a, b := r.recon.Assets[0], r.recon.Assets[1]
	if a.Status != StatusRefused || a.Refusal != "access" || len(r.out.Refused) != 1 || r.out.Refused[0].Asset != "saas:github:acme" {
		t.Fatalf("refused root: %+v / %+v", a, r.out.Refused)
	}
	if b.Status != StatusIncomplete || b.Reason != ReasonLimitReached || b.Detail != "the follow-up reads stopped: "+detail ||
		len(r.out.Incomplete) != 1 || r.out.Incomplete[0].Asset != "saas:github:beta" {
		t.Fatalf("stopped root: %+v / %+v", b, r.out.Incomplete)
	}
	if r.out.ExitCode() != 3 {
		t.Fatalf("exit %d", r.out.ExitCode())
	}
}

// Only a reading dates an asset, decided per request: a failed read or a
// send line alone never does, nor the DNS lookup of a request's host
// (docs/spec/report.md, "Coverage").
func TestAnswered(t *testing.T) {
	lines := func(id string, es ...gate.Entry) []gate.Entry {
		for i := range es {
			es[i].RequestID = id
		}
		return es
	}
	got := answered(slices.Concat(
		lines("ok", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "sent"}, gate.Entry{Event: "send", Decision: "sent"}, gate.Entry{Event: "result", Status: 200, Decision: "sent"}),
		lines("401", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "sent"}, gate.Entry{Event: "send", Decision: "sent"}, gate.Entry{Event: "result", Status: 401, Decision: "sent"}),
		lines("too_large", gate.Entry{Event: "send", Decision: "sent"}, gate.Entry{Event: "result", Status: 200, Decision: "unavailable:response_too_large"}),
		lines("404", gate.Entry{Event: "send", Decision: "sent"}, gate.Entry{Event: "result", Status: 404, Decision: "sent"}),
		lines("502", gate.Entry{Event: "send", Decision: "sent"}, gate.Entry{Event: "result", Status: 502}),
		lines("in_flight", gate.Entry{Event: "send", Decision: "sent"}),
		lines("reused", gate.Entry{Event: "reused", Decision: "reused"}),
		lines("txt", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer"}),
		lines("nxdomain", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "unavailable:nxdomain"}),
		lines("dns_timeout", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "unavailable:timeout"}),
		lines("refused", gate.Entry{Event: "refused", Decision: "refused:scope"}),
		lines("dangling", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "unavailable:nxdomain"}, gate.Entry{Event: "refused", Decision: "unavailable:nxdomain"}),
		lines("private", gate.Entry{Event: "dns"}, gate.Entry{Event: "dns_answer", Decision: "sent"}, gate.Entry{Event: "refused", Decision: "refused:address_not_public"}),
		lines("token", gate.Entry{Event: "send", Op: "workspace.credential_exchange"}, gate.Entry{Event: "result", Op: "workspace.credential_exchange", Status: 200, Decision: "sent"}),
		lines("mirror", gate.Entry{Event: "mirror", Decision: "sent"}),
	))
	for id, want := range map[string]bool{"ok": true, "401": false, "too_large": false, "404": true, "502": false, "in_flight": false,
		"reused": true, "txt": true, "nxdomain": true, "dns_timeout": false, "refused": false, "dangling": false, "private": false, "token": false, "mirror": false} {
		if got[id] != want {
			t.Errorf("%s: %v", id, got[id])
		}
	}
}
