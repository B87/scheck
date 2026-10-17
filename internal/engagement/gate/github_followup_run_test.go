package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// The F1 loop through the real gate (docs/spec/engagement.md, "Plan
// selection and follow-ups"): three people who left, still members, and
// seven production repositories whose lists show none of them open 21
// pairs. The loop asks breadth first, the most recent leaver first, stops
// at the cap of 20 and records the 21st not sent, asks a failed pair once,
// sends only the declared op with the trigger's login, and ends. The cap
// and the failure change neither status nor exit code.
func TestFollowUpLoopTerminatesUnderTheCap(t *testing.T) {
	out, check, dir, asked := followUpRun(t, func(w http.ResponseWriter, repo, login string, _ int) bool {
		if repo == "r0" && login == "dave" {
			w.WriteHeader(502)
			return true
		}
		return false
	})
	if len(out.Report.Incomplete) != 0 || len(out.Report.Refused) != 0 {
		t.Fatalf("the cap or a failed read changed a status: incomplete %+v refused %+v", out.Report.Incomplete, out.Report.Refused)
	}
	if len(check.FollowUps) != 21 {
		t.Fatalf("%d pairs recorded, want 21: %+v", len(check.FollowUps), check.FollowUps)
	}
	sent, capped := 0, 0
	for i, f := range check.FollowUps {
		if f.Row != "F1" || f.Op != "github.collaborator_permission" || f.Trigger.Verdict != "fired" || f.Trigger.Subject != f.Params["username"] ||
			f.Asset != "repo:github:acme/"+f.Params["repo"] || f.Params["owner"] != "acme" {
			t.Fatalf("pair %d: %+v", i, f)
		}
		if f.Outcome == "not_sent" {
			capped++
			if f.Reason != "follow_up_cap" || i != 20 {
				t.Fatalf("pair %d cut: %+v", i, f)
			}
			continue
		}
		sent++
	}
	if sent != 20 || capped != 1 {
		t.Fatalf("sent %d, capped %d", sent, capped)
	}
	// Breadth first, the most recent leaving date first: dave, carol, erin.
	for i, want := range []string{"dave", "carol", "erin", "dave", "carol", "erin"} {
		if check.FollowUps[i].Params["username"] != want {
			t.Fatalf("order at %d: %s, want %s", i, check.FollowUps[i].Params["username"], want)
		}
	}
	if f := check.FollowUps[0]; f.Outcome != "failed" || f.Params["repo"] != "r0" {
		t.Fatalf("the failed pair: %+v", f)
	}
	// A pair is asked once in a session, a failed one included; the gate's
	// retries of the same request are its own.
	if len(asked) != 20 {
		t.Fatalf("asked %d distinct pairs: %v", len(asked), asked)
	}
	for k, n := range asked {
		if n > 1 && k != "r0|dave" {
			t.Fatalf("%s asked %d times", k, n)
		}
	}
	// Cut by the cap, it is still not established and says why.
	fb, err := os.ReadFile(dir.File("findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fb), "was not asked: scheck sends GitHub at most 20 permission requests per run") ||
		!strings.Contains(string(fb), "could not be read: server error") {
		t.Fatal("findings.json lacks the cap's or the failure's cause")
	}

}

// permissionAnswer answers a permission read itself when it returns true;
// n counts the permission reads so far, the first being 1.
type permissionAnswer func(w http.ResponseWriter, repo, login string, n int) bool

func followUpRun(t *testing.T, answer permissionAnswer) (*engagement.Outcome, engagement.CheckDoc, *engagement.RunDir, map[string]int) {
	t.Helper()
	var repos []string
	file := `schema: 1
engagement: {name: follow, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}]
assets:
`
	for i := range 7 {
		name := fmt.Sprintf("r%d", i)
		repos = append(repos, name)
		file += fmt.Sprintf("  %s: {repo: \"github:acme/%s\", deploys_to: production}\n", name, name)
	}
	file += `people:
  alice: {kind: employee, github: [alice]}
  carol: {kind: employee, github: [carol], left: "2026-10-01"}
  dave: {kind: employee, github: [dave], left: "2026-10-05"}
  erin: {kind: employee, github: [erin], left: "2026-09-01"}
access:
  admins: {"github:acme": [alice]}
  mfa: [{where: "github:acme", enforced: everyone}]
`
	opts := inventoryOptions()
	opts.KnownFinding = finding.Known
	opts.FindingSubject = func(id string) string { return string(finding.SubjectOf(id)) }
	res, err := engagement.Parse("follow.yaml", []byte(file), opts)
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("z", 36))
	members := `[{"id":1,"login":"alice","type":"User"},{"id":4,"login":"carol","type":"User"},{"id":5,"login":"dave","type":"User"},{"id":6,"login":"erin","type":"User"}]`
	object := func(name string) string {
		return fmt.Sprintf(`{"id":%d,"name":%q,"full_name":"acme/%s","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private"}`, 10+len(name), name, name)
	}
	var list []string
	for _, r := range repos {
		list = append(list, object(r))
	}
	var mu sync.Mutex
	asked := map[string]int{}
	total := 0
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("write %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case p == "/orgs/acme":
			fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":true,"default_repository_permission":"read"}`)
		case p == "/user/memberships/orgs/acme":
			fmt.Fprint(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
		case p == "/orgs/acme/members":
			switch {
			case r.URL.Query().Get("filter") == "2fa_disabled":
				fmt.Fprint(w, `[]`)
			case r.URL.Query().Get("role") == "admin":
				fmt.Fprint(w, `[{"id":1,"login":"alice","type":"User"}]`)
			default:
				fmt.Fprint(w, members)
			}
		case p == "/orgs/acme/outside_collaborators", p == "/orgs/acme/invitations":
			fmt.Fprint(w, `[]`)
		case p == "/orgs/acme/repos":
			fmt.Fprint(w, "["+strings.Join(list, ",")+"]")
		case p == "/orgs/acme/actions/permissions/workflow", strings.HasSuffix(p, "/actions/permissions/workflow"):
			fmt.Fprint(w, `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`)
		case p == "/orgs/acme/actions/secrets", strings.HasSuffix(p, "/actions/secrets"):
			fmt.Fprint(w, `{"secrets":[]}`)
		case strings.HasSuffix(p, "/permission"):
			parts := strings.Split(p, "/") // /repos/acme/<repo>/collaborators/<login>/permission
			mu.Lock()
			asked[parts[3]+"|"+parts[5]]++
			total++
			n := total
			mu.Unlock()
			if answer(w, parts[3], parts[5], n) {
				return
			}
			fmt.Fprintf(w, `{"permission":"none","role_name":"","user":{"id":%d,"login":%q,"type":"User","permissions":{"admin":false,"maintain":false,"push":false,"triage":false,"pull":false}}}`, map[string]int{"carol": 4, "dave": 5, "erin": 6}[parts[5]], parts[5])
		case strings.HasSuffix(p, "/collaborators"), strings.HasSuffix(p, "/keys"), strings.HasSuffix(p, "/alerts"):
			fmt.Fprint(w, `[{"id":1,"login":"alice","type":"User","role_name":"admin","permissions":{"admin":true,"pull":true,"push":true,"triage":true,"maintain":true}}]`)
		case strings.HasPrefix(p, "/repos/acme/") && strings.Count(p, "/") == 3:
			fmt.Fprint(w, object(strings.TrimPrefix(p, "/repos/acme/")))
		default:
			t.Errorf("unexpected path %s", p)
			w.WriteHeader(500)
		}
	})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dir, err := engagement.CreateRunDir(t.TempDir(), "follow", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: []byte(file), Started: at, Session: at, NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	cb, err := os.ReadFile(dir.File("check.json"))
	if err != nil {
		t.Fatal(err)
	}
	var check engagement.CheckDoc
	if err = json.Unmarshal(cb, &check); err != nil {
		t.Fatal(err)
	}
	return out, check, dir, asked
}

// A rate limit on a permission read stops the follow-up: the root Check
// left collected is incomplete, limit_reached, exit 2, and every pair left
// is recorded not sent; the read that was sent says it could not be read.
func TestFollowUpLoopStopsAtALimit(t *testing.T) {
	out, check, dir, asked := followUpRun(t, func(w http.ResponseWriter, _, _ string, n int) bool {
		if n == 3 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.WriteHeader(403)
			return true
		}
		return false
	})
	if out.ExitCode() != 2 || len(out.Report.Incomplete) != 1 || out.Report.Incomplete[0].Reason != "limit_reached" ||
		!strings.HasPrefix(out.Report.Incomplete[0].Detail, "the follow-up reads stopped: ") {
		t.Fatalf("exit %d incomplete %+v", out.ExitCode(), out.Report.Incomplete)
	}
	notSent := 0
	for i, f := range check.FollowUps {
		switch {
		case i == 2 && (f.Outcome != "failed" || f.Reason != "limit_reached" || f.Request == ""):
			t.Fatalf("the limited read: %+v", f)
		case i > 2 && (f.Outcome != "not_sent" || f.Reason != "limit_reached"):
			t.Fatalf("pair %d after the stop: %+v", i, f)
		case i > 2:
			notSent++
		}
	}
	if notSent == 0 {
		t.Fatal("nothing recorded after the stop")
	}
	sent := 0
	for _, n := range asked {
		sent += n
	}
	if sent != 3 {
		t.Fatalf("%d permission requests after a limit stopped the loop at the third: %v", sent, asked)
	}
	fb, err := os.ReadFile(dir.File("findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fb), "could not be read: GitHub's rate limit") || !strings.Contains(string(fb), "was not asked: the run stopped first") {
		t.Fatal("findings.json lacks the limit's causes")
	}
}

// A credential GitHub stops accepting refuses the root, exit 3.
func TestFollowUpLoopRefusal(t *testing.T) {
	out, check, dir, asked := followUpRun(t, func(w http.ResponseWriter, _, _ string, _ int) bool {
		w.WriteHeader(401)
		return true
	})
	if out.ExitCode() != 3 || len(out.Report.Refused) != 1 || out.Report.Refused[0].Kind != "access" {
		t.Fatalf("exit %d refused %+v", out.ExitCode(), out.Report.Refused)
	}
	if len(out.Report.Incomplete) != 0 {
		t.Fatalf("the refused root is also incomplete: %+v", out.Report.Incomplete)
	}
	// Nothing more is sent with a token GitHub no longer accepts.
	sent := 0
	for _, n := range asked {
		sent += n
	}
	if sent != 1 {
		t.Fatalf("%d requests with a rejected token: %v", sent, asked)
	}
	if len(check.FollowUps) != 21 {
		t.Fatalf("%d pairs recorded, want 21", len(check.FollowUps))
	}
	if f := check.FollowUps[0]; f.Outcome != "denied" || f.Request == "" {
		t.Fatalf("the refused pair: %+v", f)
	}
	for i, f := range check.FollowUps[1:] {
		if f.Outcome != "not_sent" || f.Reason != "limit_reached" || f.Request != "" {
			t.Fatalf("pair %d after the refusal: %+v", i+1, f)
		}
	}
	fb, err := os.ReadFile(dir.File("findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fb), "was not asked: the run stopped first (GitHub did not accept the token in GITHUB_TOKEN") {
		t.Fatal("findings.json lacks the refusal's cause")
	}
}
