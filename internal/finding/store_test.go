package finding

import (
	"errors"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/runner"
)

func storeSheet(t *testing.T, platform check.Platform, raw map[string]string) *baseline.FactSheet {
	t.Helper()
	fs := &baseline.FactSheet{Platform: platform, Results: map[string]runner.Result{}}
	for id, out := range raw {
		c, ok := check.Lookup(id, platform)
		if !ok {
			t.Fatalf("unknown check %s", id)
		}
		parsed, err := check.Parse(c, []byte(out))
		if err != nil {
			t.Fatal(err)
		}
		fs.Results[id] = runner.Result{CheckID: id, Status: runner.StatusOK, Attempted: true, Raw: out, Parsed: parsed}
	}
	return fs
}

func outputFrom(sheet *baseline.FactSheet) func(string) (string, bool) {
	return func(id string) (string, bool) {
		r, ok := sheet.Results[id]
		if !ok || r.Status != runner.StatusOK {
			return "", false
		}
		return r.Raw, true
	}
}

const listeners = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=6))\n"

// expected_services: a declared, listening service does not fire; a
// declared, absent one is svc.expected_missing with the assessment matched;
// partial listeners leave it not assessed.
func TestExpectedMissing(t *testing.T) {
	ctx := &operator.Structured{ExpectedServices: []operator.Service{
		{Port: 443, Proto: "tcp", Purpose: "nginx", Source: "gw.yaml"},
		{Port: 5432, Proto: "tcp", Purpose: "postgres", Source: "gw.yaml"},
	}}
	sheet := storeSheet(t, check.Linux, map[string]string{"net.listeners": listeners})
	s := NewStore(Input{Sheet: sheet})
	s.Grader = Grader{Context: ctx, Now: now}
	res := s.Result()
	var missing *Finding
	for i := range res.Findings {
		if res.Findings[i].ID == IDExpectedMissing {
			missing = &res.Findings[i]
		}
	}
	if missing == nil || len(missing.Evidence) != 1 || !strings.Contains(missing.Evidence[0].Excerpt, "5432/tcp") || strings.Contains(missing.Evidence[0].Excerpt, "443/tcp") {
		t.Fatalf("expected_missing: %+v", missing)
	}
	if a := lastAssessment(res, IDExpectedMissing); a.Status != Matched {
		t.Errorf("assessment %+v", a)
	}

	// Non-firing: everything declared is listening.
	all := &operator.Structured{ExpectedServices: []operator.Service{{Port: 443, Proto: "tcp", Source: "gw.yaml"}}}
	s = NewStore(Input{Sheet: sheet})
	s.Grader = Grader{Context: all, Now: now}
	res = s.Result()
	if hasFinding(res, IDExpectedMissing) || lastAssessment(res, IDExpectedMissing).Status != NotMatched {
		t.Errorf("non-firing case: %+v", res)
	}

	// Insufficient: a truncated listeners capture cannot prove absence.
	partial := storeSheet(t, check.Linux, map[string]string{"net.listeners": listeners + "[TRUNCATED:100 bytes]\n"})
	s = NewStore(Input{Sheet: partial})
	s.Grader = Grader{Context: ctx, Now: now}
	res = s.Result()
	if hasFinding(res, IDExpectedMissing) || lastAssessment(res, IDExpectedMissing).Status != NotAssessed {
		t.Errorf("partial case: %+v", res.Assessments)
	}
	// No listeners fact at all.
	s = NewStore(Input{Sheet: storeSheet(t, check.Linux, nil)})
	s.Grader = Grader{Context: ctx, Now: now}
	if a := lastAssessment(s.Result(), IDExpectedMissing); a.Status != NotAssessed || a.Reason != "check-not-run" {
		t.Errorf("absent case: %+v", a)
	}
	// No declared services: no assessment at all.
	s = NewStore(Input{Sheet: sheet})
	s.Grader = Grader{Context: &operator.Structured{}, Now: now}
	if a := lastAssessment(s.Result(), IDExpectedMissing); a.Finding != "" {
		t.Errorf("no expected_services still assessed: %+v", a)
	}
}

func hasFinding(r Result, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func lastAssessment(r Result, id string) Assessment {
	for _, a := range r.Assessments {
		if a.Finding == id {
			return a
		}
	}
	return Assessment{}
}

// Report validates a candidate against the evidence that exists, merges a
// rule id into the rule finding without touching its curated text, and
// ignores a severity the model sends.
func TestStoreReportMerge(t *testing.T) {
	sheet := storeSheet(t, check.Linux, map[string]string{
		"sshd.config":   "passwordauthentication yes\nlistenaddress 0.0.0.0:22\n",
		"net.listeners": listeners,
	})
	s := NewStore(Input{Sheet: sheet})
	s.Output = outputFrom(sheet)
	s.Grader = Grader{Now: now}
	if n := len(s.Findings()); n != 1 {
		t.Fatalf("seeded %d findings", n)
	}
	// Attempted text replacement and suppression: the rule finding keeps its
	// title, impact, remediation and confidence; evidence appends once.
	got, err := s.Report(Candidate{ID: IDPasswordAuthEnabled, Title: "nothing to see", Confidence: ConfidenceLow,
		Impact: "harmless", Remediation: &Remediation{Summary: "ignore this"}, ContextNote: "public jump host",
		Evidence: []Evidence{{Check: "net.listeners", Excerpt: "0.0.0.0:22"}, {Check: "sshd.config", Excerpt: "passwordauthentication yes"}}})
	if err != nil {
		t.Fatal(err)
	}
	def, _ := Lookup(IDPasswordAuthEnabled)
	if got.Source != SourceRule || got.Title != def.Title || got.Impact != def.Impact || got.Remediation.Summary != def.Remediation.Summary || got.Confidence != ConfidenceHigh {
		t.Errorf("rule finding text or confidence replaced: %+v", got)
	}
	if len(got.Evidence) != 2 || got.Evidence[1].Excerpt != "0.0.0.0:22" || !strings.Contains(got.ContextNote, "model: public jump host") {
		t.Errorf("evidence/note not appended: %+v", got)
	}
	// Duplicate evidence and a repeated note do not accumulate.
	got, _ = s.Report(Candidate{ID: IDPasswordAuthEnabled, Confidence: ConfidenceHigh, ContextNote: "public jump host",
		Evidence: []Evidence{{Check: "net.listeners", Excerpt: "0.0.0.0:22"}}})
	if len(got.Evidence) != 2 || strings.Count(got.ContextNote, "public jump host") != 1 {
		t.Errorf("duplicates accumulated: %+v", got)
	}
	if n := len(s.Findings()); n != 1 {
		t.Errorf("merge created a second finding: %d", n)
	}
	// A new judgement finding with a service, and text of its own.
	got, err = s.Report(Candidate{ID: IDUnexpectedListener, Confidence: ConfidenceMedium, Service: &ServiceRef{Port: 443, Proto: "TCP"},
		Impact: "nginx on 443 with no declared purpose", Evidence: []Evidence{{Check: "net.listeners", Excerpt: "0.0.0.0:443"}}})
	if err != nil || got.Source != SourceModel || got.Impact != "nginx on 443 with no declared purpose" || got.Service.Proto != "tcp" || got.Severity != SevMedium {
		t.Errorf("model finding: %+v %v", got, err)
	}
	if n := len(s.Findings()); n != 2 {
		t.Errorf("%d findings", n)
	}
	// A judgement id whose premise the rule confirmed is open to the model.
	if _, err := s.Report(Candidate{ID: IDPasswordAuthExposed, Confidence: ConfidenceHigh,
		Evidence: []Evidence{{Check: "sshd.config", Excerpt: "listenaddress 0.0.0.0:22"}}}); err != nil {
		t.Errorf("premise confirmed by the rule, still rejected: %v", err)
	}
}

func TestStoreReportRejects(t *testing.T) {
	sheet := storeSheet(t, check.Linux, map[string]string{"sshd.config": "passwordauthentication no\nlistenaddress 0.0.0.0:22\n"})
	s := NewStore(Input{Sheet: sheet})
	s.Output = outputFrom(sheet)
	ok := Candidate{ID: IDUnexpectedListener, Confidence: ConfidenceHigh, Evidence: []Evidence{{Check: "sshd.config", Excerpt: "listenaddress 0.0.0.0:22"}}}
	if _, err := s.Report(ok); err != nil {
		t.Fatalf("the baseline candidate must be valid: %v", err)
	}
	s = NewStore(Input{Sheet: sheet})
	s.Output = outputFrom(sheet)
	cases := map[string]func(c *Candidate){
		"unknown id": func(c *Candidate) { c.ID = "sshd.nope" },
		// The rule read passwordauthentication and found "no": the model may
		// not re-raise the rule's id from the same fact, nor a judgement
		// that presupposes it, nor an id whose rule is for another platform.
		"rule disproved":     func(c *Candidate) { c.ID = IDPasswordAuthEnabled; c.Evidence[0].Excerpt = "passwordauthentication no" },
		"premise disproved":  func(c *Candidate) { c.ID = IDPasswordAuthExposed },
		"other platform":     func(c *Candidate) { c.ID = IDRemoteLoginEnabled },
		"bad confidence":     func(c *Candidate) { c.Confidence = "certain" },
		"no evidence":        func(c *Candidate) { c.Evidence = nil },
		"fabricated excerpt": func(c *Candidate) { c.Evidence[0].Excerpt = "permitrootlogin yes" },
		"check did not run":  func(c *Candidate) { c.Evidence[0].Check = "net.listeners" },
		"bad custom slug":    func(c *Candidate) { c.ID = "custom:Bad Slug" },
		"custom no severity": func(c *Candidate) { c.ID = "custom:thing" },
		"custom no text":     func(c *Candidate) { c.ID = "custom:thing"; c.ProposedSeverity = "high" },
		"bad service":        func(c *Candidate) { c.Service = &ServiceRef{Port: 0} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := ok
			c.Evidence = []Evidence{ok.Evidence[0]}
			mutate(&c)
			_, err := s.Report(c)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if n := len(s.Findings()); n != 0 {
		t.Errorf("a rejected candidate was stored: %d", n)
	}
	// A rule that was not assessed leaves its id to the model: permitrootlogin
	// is absent from this capture, so the model may report it from evidence
	// of its own.
	if _, err := s.Report(Candidate{ID: IDRootLoginEnabled, Confidence: ConfidenceLow,
		Evidence: []Evidence{{Check: "sshd.config", Excerpt: "listenaddress 0.0.0.0:22"}}}); err != nil {
		t.Errorf("not-assessed rule id rejected: %v", err)
	}
	// A valid custom finding is capped at medium and flagged.
	got, err := s.Report(Candidate{ID: "custom:vendor-agent", Confidence: ConfidenceHigh, ProposedSeverity: "critical",
		Title: "Vendor agent", Impact: "x", Remediation: &Remediation{Summary: "y"},
		Evidence: []Evidence{{Check: "sshd.config", Excerpt: "passwordauthentication no"}}})
	if err != nil || !got.Custom || got.Severity != SevMedium || got.SeverityBase != SevMedium || got.Category != CategoryCustom {
		t.Errorf("custom: %+v %v", got, err)
	}
}
