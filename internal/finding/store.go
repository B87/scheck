package finding

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// Store owns every finding of a run and the merge contract of docs/SPEC.md
// §7.2 and §7.5. Phase 1 seeds it with the posture rules' findings; phase 2
// hands it candidates through Report. The store validates, merges and
// grades; the agent loop never edits a finding, which is what keeps the
// loop one path and severity in code.
type Store struct {
	Grader Grader
	// Output returns the redacted output of a check that ran in this run,
	// so a candidate's evidence excerpt can be validated against what the
	// check actually said. nil accepts no model evidence.
	Output func(checkID string) (string, bool)

	sheet       Input
	findings    []Finding
	assessments []Assessment
	byID        map[string]int
}

// NewStore evaluates the posture rules over in and seeds the store.
func NewStore(in Input) *Store {
	res := Evaluate(in)
	s := &Store{sheet: in, findings: res.Findings, assessments: res.Assessments, byID: map[string]int{}}
	for i, f := range s.findings {
		s.byID[f.ID] = i
	}
	return s
}

// Candidate is what report_finding carries (§5.7, §7.3): the model
// classifies and supplies evidence; it never supplies severity, and one it
// sends anyway is ignored, not rejected.
type Candidate struct {
	ID               string       `json:"id"`
	Title            string       `json:"title,omitempty"`
	Confidence       string       `json:"confidence"`
	Evidence         []Evidence   `json:"evidence"`
	Impact           string       `json:"impact,omitempty"`
	Remediation      *Remediation `json:"remediation,omitempty"`
	ContextNote      string       `json:"context_note,omitempty"`
	ProposedSeverity string       `json:"proposed_severity,omitempty"` // custom: only
	Service          *ServiceRef  `json:"service,omitempty"`
}

// ServiceRef names the listener a network finding is about, so the
// expected_services table can grade it (§6.3).
type ServiceRef struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// Key matches operator.Service.Key.
func (s ServiceRef) Key() string { return fmt.Sprintf("%d/%s", s.Port, strings.ToLower(s.Proto)) }

var customSlug = regexp.MustCompile(`^custom:[a-z0-9][a-z0-9_-]{2,63}$`)

// ErrInvalid is wrapped by every validation failure Report returns, so the
// tool can send the message back to the model as an error result.
var ErrInvalid = errors.New("invalid finding")

// Report validates a candidate and either merges it into an existing finding
// with the same id or adds it as a model finding. The returned finding is
// graded. An invalid candidate leaves the store untouched.
func (s *Store) Report(c Candidate) (Finding, error) {
	f, err := s.validate(c)
	if err != nil {
		return Finding{}, err
	}
	if i, seen := s.byID[f.ID]; seen {
		s.findings[i] = merge(s.findings[i], f)
		graded, _ := s.Grader.Grade(s.findings[i])
		return graded, nil
	}
	s.byID[f.ID] = len(s.findings)
	s.findings = append(s.findings, f)
	graded, _ := s.Grader.Grade(f)
	return graded, nil
}

func (s *Store) validate(c Candidate) (Finding, error) {
	f := Finding{ID: c.ID, Source: SourceModel, Platform: string(s.sheet.platform()), Adjustments: []Adjustment{},
		Status: StatusOpen, ContextNote: c.ContextNote, Service: c.Service}
	switch c.Confidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		f.Confidence = c.Confidence
	default:
		return f, fmt.Errorf("%w: confidence must be high|medium|low, got %q", ErrInvalid, c.Confidence)
	}
	if len(c.Evidence) == 0 {
		return f, fmt.Errorf("%w: at least one evidence entry {check, excerpt} is required", ErrInvalid)
	}
	for i, ev := range c.Evidence {
		if ev.Check == "" || strings.TrimSpace(ev.Excerpt) == "" {
			return f, fmt.Errorf("%w: evidence[%d] needs both check and excerpt", ErrInvalid, i)
		}
		if s.Output == nil {
			return f, fmt.Errorf("%w: evidence[%d]: no check output is available to validate against", ErrInvalid, i)
		}
		out, ok := s.Output(ev.Check)
		if !ok {
			return f, fmt.Errorf("%w: evidence[%d]: check %q did not run in this session; cite a check whose output you have seen", ErrInvalid, i, ev.Check)
		}
		if !excerptIn(ev.Excerpt, out) {
			return f, fmt.Errorf("%w: evidence[%d]: excerpt is not in the output of %s; quote the output verbatim", ErrInvalid, i, ev.Check)
		}
		f.Evidence = appendEvidence(f.Evidence, Evidence{Check: ev.Check, Excerpt: strings.TrimSpace(ev.Excerpt)})
	}
	if c.Service != nil {
		if c.Service.Port < 1 || c.Service.Port > 65535 {
			return f, fmt.Errorf("%w: service.port %d is out of range", ErrInvalid, c.Service.Port)
		}
		p := strings.ToLower(c.Service.Proto)
		if p == "" {
			p = "tcp"
		}
		if p != "tcp" && p != "udp" {
			return f, fmt.Errorf("%w: service.proto must be tcp|udp", ErrInvalid)
		}
		f.Service = &ServiceRef{Port: c.Service.Port, Proto: p}
	}
	if strings.HasPrefix(c.ID, "custom:") {
		if !customSlug.MatchString(c.ID) {
			return f, fmt.Errorf("%w: a custom id is custom:<slug> with [a-z0-9_-], 3..64 characters", ErrInvalid)
		}
		sev := Severity(c.ProposedSeverity)
		if sev.Rank() < 0 {
			return f, fmt.Errorf("%w: a custom finding needs proposed_severity critical|high|medium|low|info", ErrInvalid)
		}
		if sev.Rank() > SevMedium.Rank() {
			sev = SevMedium // capped at medium (§7.1); the grader records the cap
		}
		if c.Title == "" || c.Impact == "" || c.Remediation == nil || c.Remediation.Summary == "" {
			return f, fmt.Errorf("%w: a custom finding needs title, impact and remediation.summary", ErrInvalid)
		}
		f.Custom, f.Title, f.Category = true, c.Title, CategoryCustom
		f.SeverityBase, f.Severity = sev, sev
		f.Impact, f.Remediation = c.Impact, *c.Remediation
		return f, nil
	}
	def, ok := Lookup(c.ID)
	if !ok {
		return f, fmt.Errorf("%w: unknown finding id %q; use a catalog id (%s) or custom:<slug>", ErrInvalid, c.ID, strings.Join(IDs(), ", "))
	}
	f.Title, f.Category, f.SeverityBase, f.Severity = def.Title, def.Category, def.BaseSeverity, def.BaseSeverity
	f.Impact, f.Remediation = def.Impact, def.Remediation
	// For a model-only finding the Def's text is the default and the
	// model's, when present, replaces impact and remediation (§7.1). A rule
	// finding keeps its curated text: merge decides that.
	if c.Impact != "" {
		f.Impact = c.Impact
	}
	if c.Remediation != nil && c.Remediation.Summary != "" {
		f.Remediation = *c.Remediation
	}
	return f, nil
}

// merge folds a validated model candidate into an existing finding (§7.5):
// a rule finding keeps source, title, impact, remediation and confidence;
// validated evidence and an attributed note append without duplicates.
// A model finding merging into a model finding keeps the first text and
// the higher confidence.
func merge(have, in Finding) Finding {
	for _, ev := range in.Evidence {
		have.Evidence = appendEvidence(have.Evidence, ev)
	}
	if in.ContextNote != "" && !strings.Contains(have.ContextNote, in.ContextNote) {
		if have.ContextNote != "" {
			have.ContextNote += " "
		}
		have.ContextNote += "model: " + in.ContextNote
	}
	if have.Service == nil {
		have.Service = in.Service
	}
	if have.Source == SourceModel && in.Confidence != "" && Rank(in.Confidence) > Rank(have.Confidence) {
		have.Confidence = in.Confidence
	}
	return have
}

// excerptIn reports whether the excerpt appears in the output, comparing
// with whitespace folded so a model that reflowed a line is not refused for
// it, while a fabricated line still is.
func excerptIn(excerpt, output string) bool {
	fold := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	e := fold(excerpt)
	return e != "" && strings.Contains(fold(output), e)
}

// Result grades every finding, adds the context-derived findings
// (`svc.expected_missing`, `risk.acceptance_expired`) and returns the
// report's findings and assessments, findings ordered by severity.
func (s *Store) Result() Result {
	res := Result{Findings: []Finding{}, Assessments: append([]Assessment{}, s.assessments...)}
	for _, f := range s.findings {
		g, _ := s.Grader.Grade(f)
		res.Findings = append(res.Findings, g)
	}
	platform := string(s.sheet.platform())
	missing, a := s.expectedMissing()
	if a != nil {
		res.Assessments = append(res.Assessments, *a)
	}
	for _, f := range missing {
		g, _ := s.Grader.Grade(f)
		res.Findings = append(res.Findings, g)
	}
	for _, f := range s.Grader.ExpiredAcceptances(platform) {
		g, _ := s.Grader.Grade(f)
		res.Findings = append(res.Findings, g)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Open() != b.Open() {
			return a.Open()
		}
		if a.Severity != b.Severity {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.ID < b.ID
	})
	return res
}

// Findings returns the graded findings without the context-derived ones,
// for the loop to show the model what has been reported so far.
func (s *Store) Findings() []Finding {
	out := make([]Finding, 0, len(s.findings))
	for _, f := range s.findings {
		g, _ := s.Grader.Grade(f)
		out = append(out, g)
	}
	return out
}

// listenersCheck is the one fact expected_services is compared against.
const listenersCheck = "net.listeners"

// expectedMissing compares the declared services with the listeners fact
// (§6.3). It is a negative claim, so it needs complete evidence: an
// unavailable or partial listeners fact leaves it not assessed.
func (s *Store) expectedMissing() ([]Finding, *Assessment) {
	ctx := s.Grader.Context
	if ctx == nil || len(ctx.ExpectedServices) == 0 {
		return nil, nil
	}
	a := &Assessment{Finding: IDExpectedMissing, Check: listenersCheck}
	if s.sheet.Sheet == nil {
		a.Status, a.Reason = NotAssessed, "check-not-run"
		return nil, a
	}
	r, ran := s.sheet.Sheet.Results[listenersCheck]
	switch {
	case !ran:
		a.Status, a.Reason = NotAssessed, "check-not-run"
		return nil, a
	case r.Status != runner.StatusOK:
		a.Status, a.Reason = NotAssessed, "check-"+string(r.Status)+":"+reasonCode(r)
		return nil, a
	}
	recs, ok := r.Parsed.(check.Records)
	if !ok {
		a.Status, a.Reason = NotAssessed, "unexpected-parsed-shape"
		return nil, a
	}
	if recs.Partial {
		a.Status, a.Reason = NotAssessed, "partial-output"
		return nil, a
	}
	listening := map[string]bool{}
	for _, rec := range recs.Items {
		listening[strings.ToLower(rec[check.FieldPort]+"/"+rec[check.FieldProtocol])] = true
	}
	var findings []Finding
	def, _ := Lookup(IDExpectedMissing)
	var f *Finding
	for _, svc := range ctx.ExpectedServices {
		key := fmt.Sprintf("%d/%s", svc.Port, svc.Proto)
		if listening[key] {
			continue
		}
		ev := Evidence{Check: listenersCheck, Excerpt: fmt.Sprintf("no listener on %s; %s declares %s (%s)", key, svc.Source, key, svc.Purpose)}
		if f == nil {
			findings = append(findings, Finding{
				ID: def.ID, Title: def.Title, Category: def.Category,
				SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity,
				Adjustments: []Adjustment{}, Status: StatusOpen, Source: SourceRule,
				Confidence: ConfidenceHigh, Platform: string(s.sheet.platform()),
				Evidence: []Evidence{ev}, Impact: def.Impact, Remediation: def.Remediation,
			})
			f = &findings[0]
			continue
		}
		f.Evidence = appendEvidence(f.Evidence, ev)
	}
	if f == nil {
		a.Status, a.Reason = NotMatched, "every-declared-service-is-listening"
	} else {
		a.Status, a.Reason = Matched, "declared-service-not-listening"
	}
	return findings, a
}

func (in Input) platform() check.Platform {
	if in.Sheet == nil {
		return ""
	}
	return in.Sheet.Platform
}
