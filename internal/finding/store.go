package finding

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	// Output resolves one immutable observation from this run,
	// so a candidate's evidence excerpt can be validated against what the
	// check actually said. nil accepts no model evidence.
	Output func(observation string) (runner.Result, bool)

	sheet       Input
	findings    []Finding
	assessments []Assessment
	byID        map[string]int
	ruledOut    []RuledOut
}

// Verdicts a report_finding call may carry (§5.7).
const (
	VerdictOpen     = "open"
	VerdictRuledOut = "ruled_out"
)

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
	ID string `json:"id"`
	// Verdict is open (the default) or ruled_out; a ruled-out candidate goes
	// through RuleOut and is never a finding (§5.7).
	Verdict          string       `json:"verdict,omitempty"`
	Note             string       `json:"note,omitempty"` // ruled_out: why the id does not apply
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
	// An open report supersedes an earlier ruling-out of the same id: the
	// model changed its mind on evidence, and a finding and its own denial
	// cannot both stand in one run.
	s.ruledOut = slices.DeleteFunc(s.ruledOut, func(r RuledOut) bool { return r.ID == f.ID })
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
		return f, fmt.Errorf("%w: at least one evidence entry {observation, excerpt} is required", ErrInvalid)
	}
	var err error
	if f.Evidence, err = s.evidence(c.Evidence); err != nil {
		return f, err
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
	if err := s.ruleAllows(def); err != nil {
		return f, err
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

// evidence validates every cited excerpt against the exact observation it
// names (§5.7): the observation must exist in this run with a successful
// capture, and the excerpt must appear in that capture, whitespace folded.
func (s *Store) evidence(in []Evidence) ([]Evidence, error) {
	var out []Evidence
	for i, ev := range in {
		if ev.Observation == "" || strings.TrimSpace(ev.Excerpt) == "" {
			return nil, fmt.Errorf("%w: evidence[%d] needs both observation and excerpt", ErrInvalid, i)
		}
		if s.Output == nil {
			return nil, fmt.Errorf("%w: evidence[%d]: no check output is available to validate against", ErrInvalid, i)
		}
		res, ok := s.Output(ev.Observation)
		if !ok || res.Status != runner.StatusOK || (ev.Check != "" && ev.Check != res.CheckID) {
			return nil, fmt.Errorf("%w: evidence[%d]: observation %q has no usable output in this session", ErrInvalid, i, ev.Observation)
		}
		if !excerptIn(ev.Excerpt, res.Raw) {
			return nil, fmt.Errorf("%w: evidence[%d]: excerpt is not in the output of %s; quote the output verbatim", ErrInvalid, i, ev.Observation)
		}
		out = appendEvidence(out, Evidence{Observation: ev.Observation, Check: res.CheckID, Excerpt: strings.TrimSpace(ev.Excerpt)})
	}
	return out, nil
}

// RuleOut records a hypothesis the model checked and closed (§5.7). It
// files nothing: the id must be a catalog id or a well-formed custom slug,
// must not be a finding of this run (a rule finding is the floor and a
// reported one is the model's own claim; a context_note is the way to
// qualify either), needs a note saying why, and any evidence it cites is
// validated exactly like a finding's. Ruling out the same id twice merges
// the notes.
func (s *Store) RuleOut(c Candidate) (RuledOut, error) {
	r := RuledOut{ID: c.ID, Note: strings.TrimSpace(c.Note)}
	if strings.HasPrefix(c.ID, "custom:") {
		if !customSlug.MatchString(c.ID) {
			return r, fmt.Errorf("%w: a custom id is custom:<slug> with [a-z0-9_-], 3..64 characters", ErrInvalid)
		}
	} else if _, ok := Lookup(c.ID); !ok {
		return r, fmt.Errorf("%w: unknown finding id %q; use a catalog id (%s) or custom:<slug>", ErrInvalid, c.ID, strings.Join(IDs(), ", "))
	}
	if i, seen := s.byID[c.ID]; seen {
		return r, fmt.Errorf("%w: %s is a %s finding of this run and cannot be ruled out; report it with a context_note to qualify it", ErrInvalid, c.ID, s.findings[i].Source)
	}
	if r.Note == "" {
		return r, fmt.Errorf("%w: a ruled-out verdict needs a note saying what was checked and why %s does not apply", ErrInvalid, c.ID)
	}
	var err error
	if r.Evidence, err = s.evidence(c.Evidence); err != nil {
		return r, err
	}
	for i := range s.ruledOut {
		if s.ruledOut[i].ID != r.ID {
			continue
		}
		have := &s.ruledOut[i]
		if !strings.Contains(have.Note, r.Note) {
			have.Note += " " + r.Note
		}
		for _, ev := range r.Evidence {
			have.Evidence = appendEvidence(have.Evidence, ev)
		}
		return *have, nil
	}
	s.ruledOut = append(s.ruledOut, r)
	return r, nil
}

// ruleAllows applies what the posture rules already know to a catalog id the
// model wants to report (docs/SPEC.md §7.5). A rule-covered id belongs to
// the rule on its platform: an id whose rules are all bound to another
// platform does not exist on this host; an id whose rule read complete
// evidence and found it not matched cannot be re-raised by the model from
// the same facts (the model may still add to a finding the rule raised); and
// a judgement id whose premise a rule disproved has nothing to stand on. A
// not-assessed rule leaves the id to the model, since the rule had no
// usable evidence and the model may have obtained some.
func (s *Store) ruleAllows(def Def) error {
	platform := s.sheet.platform()
	if rs := rulesFor(def.ID); len(rs) > 0 && platform != "" {
		applicable := false
		for _, r := range rs {
			if r.Platform == check.Any || r.Platform == platform {
				applicable = true
			}
		}
		if !applicable {
			return fmt.Errorf("%w: %s is not a %s finding; its posture rule applies to another platform", ErrInvalid, def.ID, platform)
		}
	}
	if _, seeded := s.byID[def.ID]; !seeded {
		if a, disproved := s.disproved(def.ID); disproved {
			return fmt.Errorf("%w: the posture rule for %s read %s and found it not matched (%s); the rule's reading of that fact stands, so report a different id or cite a fact the rule did not read", ErrInvalid, def.ID, a.Check, a.Reason)
		}
	}
	for _, id := range def.Premise {
		if _, seeded := s.byID[id]; seeded {
			continue
		}
		if a, disproved := s.disproved(id); disproved {
			return fmt.Errorf("%w: %s presupposes %s, which the posture rule disproved from %s (%s)", ErrInvalid, def.ID, id, a.Check, a.Reason)
		}
	}
	return nil
}

// disproved reports whether a posture rule for the id evaluated its check
// on complete, recognized evidence and found the condition absent.
func (s *Store) disproved(id string) (Assessment, bool) {
	for _, a := range s.assessments {
		if a.Finding == id && a.Status == NotMatched {
			return a, true
		}
	}
	return Assessment{}, false
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
	res := Result{Findings: []Finding{}, Assessments: append([]Assessment{}, s.assessments...), RuledOut: append([]RuledOut{}, s.ruledOut...)}
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
	a.Observation = r.Observation
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
		ev := Evidence{Observation: r.Observation, Check: listenersCheck, Excerpt: fmt.Sprintf("no listener on %s; %s declares %s (%s)", key, svc.Source, key, svc.Purpose)}
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
