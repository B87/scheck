//go:build live

package live

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/bounded"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// The recall probe of docs/ROADMAP-RESEARCH.md ("Open questions for R2",
// question 7): before anyone builds the R3 adapter, find out whether Jev can
// answer the `vendor` question at all.
//
// That question asks the model to recall what the world ships — is
// /usr/bin/sudo a standard SUID binary, is rapportd an Apple component, is
// com.docker.vmnetd.plist deliberately installed software — rather than to
// judge text it was handed. It is the one question in the set that leans on
// recall instead of on the supplied state, and two of the four phase 2
// false-positive classes rest on it. If Jev cannot separate a distribution's
// own components from a planted one, the design has to move `vendor` into a
// package-provenance catalog check and re-scope the experiment.
//
// The probe is deliberately not an adapter. It sends the arm's real states
// (bounded.StateFor over recorded fixtures) and the frozen question wording
// (bounded.Questions), so what it measures is what a run would send. Nothing
// but recorded fixture data leaves this machine.
//
//	SCHECK_LIVE=1 TYPESAFE_API_KEY=… make probe
const (
	jevEndpoint = "https://api.typesafe.ai/v1/systemone"
	jevModel    = "jev-1.13.0" // pinned: never an alias in a record
	// vendorThreshold is bounded.DefaultThresholds().NotStandard, the level
	// below which a decision rule treats an item as not a standard component.
	vendorThreshold = 0.3
)

// expectation labels one enumerated item: true when a correct `vendor`
// answer is high (this is something the platform or an administrator
// installed), false when it is low (this is the planted one).
var expectVendor = map[string]bool{
	// Ubuntu's own SUID binaries.
	"suid:/usr/bin/newgrp": true, "suid:/usr/bin/chfn": true, "suid:/usr/bin/mount": true,
	"suid:/usr/bin/su": true, "suid:/usr/bin/chsh": true, "suid:/usr/bin/umount": true,
	"suid:/usr/bin/gpasswd": true, "suid:/usr/bin/passwd": true, "suid:/usr/bin/sudo": true,
	// Ubuntu's own enabled units.
	"unit:cron.service": true, "unit:e2scrub_reap.service": true, "unit:getty@.service": true,
	"unit:systemd-pstore.service": true, "unit:ufw.service": true, "unit:ssh.socket": true,
	"unit:remote-fs.target": true, "unit:apt-daily-upgrade.timer": true, "unit:apt-daily.timer": true,
	"unit:dpkg-db-backup.timer": true, "unit:e2scrub_all.timer": true, "unit:fstrim.timer": true,
	"unit:motd-news.timer": true,
	// macOS's own listeners. Linux's are absent on purpose: `ss` names the
	// owning process only for a privileged session, so those candidates are
	// insufficient and never judged.
	"listener:53019/tcp": true, "listener:7000/tcp": true, "listener:5000/tcp": true,
	// Third-party macOS software an administrator installed on purpose.
	"launchd:/Library/LaunchDaemons/com.docker.vmnetd.plist":        true,
	"launchd:/Library/LaunchDaemons/com.docker.socket.plist":        true,
	"launchd:/Library/LaunchDaemons/com.nordvpn.macos.helper.plist": true,
	// The planted ones: nothing ships these.
	"unit:agent.service":        false,
	"suid:/opt/tool/bin/helper": false,
}

type probeItem struct {
	key   string
	kind  bounded.Kind
	state bounded.State
	qs    []bounded.Question
}

// capture is an Answerer that keeps the request and answers benignly, so
// nothing is filed. It is how the probe gets the exact state and questions a
// run would send, follow-up reads included — building them by hand would
// measure a paraphrase, which is the bug the first probe run had.
type capture struct {
	seen map[string]bounded.Request
}

func (c *capture) Source() string { return "probe-capture" }

func (c *capture) Answer(_ context.Context, req bounded.Request) (map[string]float64, error) {
	c.seen[req.ItemKey] = req
	return map[string]float64{"explained": 1, "vendor": 1, "hallmarks": 0, "sensitive": 0, "person": 1}, nil
}

// collect runs the real arm over one recorded fixture with a capturing
// answer source, and keeps the requests the probe has a label for.
func collect(t *testing.T, dir string, elevate runner.Elevation, seen map[string]bool) []probeItem {
	t.Helper()
	fx, err := fixture.Load(dir)
	if err != nil {
		t.Fatalf("fixture %s: %v", dir, err)
	}
	red, err := policy.NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red,
		Budgets: policy.DefaultBudgets(), Audit: policy.NewAudit(io.Discard), Elevate: elevate}
	sheet := baseline.Run(context.Background(), r, baseline.Plan(fx.Platform(), nil), nil)
	cap := &capture{seen: map[string]bounded.Request{}}
	if _, err := bounded.Run(context.Background(), bounded.Options{Sheet: sheet, Runner: r,
		Store: finding.NewStore(finding.Input{Sheet: sheet}), Answers: cap, Budgets: policy.DefaultBudgets()}); err != nil {
		t.Fatalf("bounded run on %s: %v", dir, err)
	}
	var out []probeItem
	for key, req := range cap.seen {
		if _, labeled := expectVendor[key]; !labeled || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, probeItem{key: key, kind: req.Kind, state: req.State, qs: req.Questions})
	}
	return out
}

type jevRequest struct {
	State     bounded.State               `json:"state"`
	Model     string                      `json:"model"`
	Questions map[string]bounded.Question `json:"questions"`
}

type jevResponse struct {
	Model   string `json:"model"`
	Answers map[string]struct {
		Type string  `json:"type"`
		Noul float64 `json:"noul"`
	} `json:"answers"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// ask sends one item's questions in one request, with bounded backoff on the
// two retryable statuses. The key is read here and never printed.
func ask(ctx context.Context, key string, it probeItem) (jevResponse, error) {
	qs := map[string]bounded.Question{}
	for _, q := range it.qs {
		qs[q.ID] = q
	}
	body, err := json.Marshal(jevRequest{State: it.state, Model: jevModel, Questions: qs})
	if err != nil {
		return jevResponse{}, err
	}
	var last error
	for attempt := range 4 {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			case <-ctx.Done():
				return jevResponse{}, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, jevEndpoint, bytes.NewReader(body))
		if err != nil {
			return jevResponse{}, err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			last = err
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			var out jevResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				return jevResponse{}, fmt.Errorf("decode: %w", err)
			}
			return out, nil
		case http.StatusTooManyRequests, 529:
			last = fmt.Errorf("status %d", resp.StatusCode)
			continue
		default:
			// The body may quote the request; it never contains the key.
			return jevResponse{}, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
	}
	return jevResponse{}, last
}

func TestJevVendorRecallProbe(t *testing.T) {
	if os.Getenv("SCHECK_LIVE") != "1" {
		t.Skip("SCHECK_LIVE=1 not set")
	}
	key := os.Getenv("TYPESAFE_API_KEY")
	if key == "" {
		t.Skip("TYPESAFE_API_KEY not set")
	}
	fx := func(p ...string) string { return filepath.Join(append([]string{"..", "..", "testdata"}, p...)...) }
	seen := map[string]bool{}
	var items []probeItem
	items = append(items, collect(t, fx("fixtures", "ubuntu"), runner.ElevateSudo, seen)...)
	items = append(items, collect(t, fx("fixtures", "macos"), runner.ElevateNone, seen)...)
	items = append(items, collect(t, fx("eval", "cases", "linux-unit-in-tmp"), runner.ElevateSudo, seen)...)
	items = append(items, collect(t, fx("eval", "cases", "linux-suid-in-world-writable"), runner.ElevateSudo, seen)...)
	items = append(items, collect(t, fx("eval", "cases", "macos-filevault-off"), runner.ElevateNone, seen)...)
	if len(items) < 20 {
		t.Fatalf("only %d labeled items enumerated; the fixtures or the labels moved", len(items))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	type result struct {
		key      string
		kind     bounded.Kind
		want     bool
		vendor   float64
		answers  map[string]float64
		others   map[string]float64
		fields   map[string]string
		model    string
		inTokens int
	}
	var results []result
	var tokens int
	models := map[string]int{}
	for _, it := range items {
		resp, err := ask(ctx, key, it)
		if err != nil {
			t.Fatalf("%s: %v", it.key, err)
		}
		a, ok := resp.Answers["vendor"]
		if !ok || a.Type != "noul" {
			t.Fatalf("%s: no usable vendor answer: %+v", it.key, resp.Answers)
		}
		others, answers := map[string]float64{}, map[string]float64{}
		for id, ans := range resp.Answers {
			answers[id] = ans.Noul
			if id != "vendor" {
				others[id] = ans.Noul
			}
		}
		tokens += resp.Usage.InputTokens
		models[resp.Model]++
		results = append(results, result{it.key, it.kind, expectVendor[it.key], a.Noul, answers, others, it.state.Item, resp.Model, resp.Usage.InputTokens})
	}

	// Report before judging, so a failing probe is still a readable record.
	t.Logf("model(s): %v, %d input tokens, about $%.4f at $42/billion", models, tokens, float64(tokens)*42e-9)
	t.Logf("%-56s %-8s %6s  %s", "item", "want", "vendor", "other answers")
	var lowestShipped, highestPlanted = 1.0, 0.0
	var wrong []string
	for _, r := range results {
		want := "standard"
		if !r.want {
			want = "planted"
		}
		mark := "  "
		got := r.vendor >= vendorThreshold
		if got != r.want {
			mark, wrong = "<<", append(wrong, fmt.Sprintf("%s (want %s, vendor %.2f)", r.key, want, r.vendor))
		}
		if r.want && r.vendor < lowestShipped {
			lowestShipped = r.vendor
		}
		if !r.want && r.vendor > highestPlanted {
			highestPlanted = r.vendor
		}
		t.Logf("%-56s %-8s %6.2f %s %v", r.key, want, r.vendor, mark, r.others)
	}
	t.Logf("vendor separation (diagnostic, not the gate): lowest standard %.2f, highest planted %.2f, threshold %.2f; %d item(s) on the wrong side: %s",
		lowestShipped, highestPlanted, vendorThreshold, len(wrong), strings.Join(wrong, "; "))

	// The gate is what the decision rules do with these answers, not whether
	// one question separates on its own: the design's whole claim is that
	// code combines several answers, and a weak `vendor` is survivable when
	// an affirmative signal carries the decision.
	var falsePositives, caught []string
	for _, r := range results {
		it := bounded.Item{Kind: r.kind, Key: r.key, Answers: r.answers, Fields: r.fields}
		d := bounded.Decide(it, bounded.DefaultThresholds())
		switch {
		case d.File && r.want:
			falsePositives = append(falsePositives, fmt.Sprintf("%s — %s", r.key, d.Reason))
		case d.File:
			caught = append(caught, fmt.Sprintf("%s — %s", r.key, d.Reason))
		case !d.File && !r.want:
			t.Errorf("planted item not caught: %s — %s", r.key, d.Reason)
		}
	}
	t.Logf("decision rules: %d planted item(s) caught, %d false positive(s) over %d items", len(caught), len(falsePositives), len(results))
	for _, c := range caught {
		t.Logf("  caught: %s", c)
	}
	for _, f := range falsePositives {
		t.Logf("  FALSE POSITIVE: %s", f)
	}
	if len(falsePositives) > 0 {
		t.Errorf("%d false positive(s) on items nothing should be filed about:\n  %s",
			len(falsePositives), strings.Join(falsePositives, "\n  "))
	}
}
