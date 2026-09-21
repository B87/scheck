// Package bounded is the R1 experiment of docs/ROADMAP-RESEARCH.md, under
// docs/SPEC.md §5.9: code owns the workflow and a System One model answers
// one narrow question per candidate item.
//
// It exists because the phase 2 record (docs/eval/phase2-results.md) failed
// on the loop's own terms — the model never called a tool — and because its
// false positives were context judgements filed from the absence of an
// explanation. So the shape here inverts control: code enumerates the
// candidates from the fact sheet, code applies the deterministic filters,
// code runs a fixed per-kind follow-up read through runner.RunAs, the model
// answers a few independent yes/no questions about one item, and code
// decides what to file through finding.Store.Report.
//
// Two rules hold throughout and are tested, not just written here:
//
//   - Nothing is filed from the absence of an explanation. Every decision
//     rule needs an affirmative signal (an entry that shows hallmarks of
//     persistence, a binary that is not a standard component), because
//     "nobody told me about this" is what produced the phase 2 false
//     positives.
//   - Evidence that is unavailable, truncated or redacted is insufficient.
//     Such an item is never sent to a model and never filed.
//
// No CLI run reaches this package: internal/eval is its only caller, and a
// scripted answer source makes no quality claim whatsoever.
package bounded

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
)

// Kind is one candidate kind. Each kind has its own enumeration, its own
// follow-up read, its own questions and its own decision rule, and maps to
// exactly one judgement finding id (docs/SPEC.md §5.9).
type Kind string

// The four kinds, in enumeration order.
const (
	KindListener    Kind = "listener"
	KindPersistence Kind = "persistence"
	KindSUID        Kind = "suid"
	KindAdmin       Kind = "admin"
)

// Kinds lists the kinds in enumeration order.
var Kinds = []Kind{KindListener, KindPersistence, KindSUID, KindAdmin}

// FindingID is the catalog id a kind may file. Nothing else may be filed.
var FindingID = map[Kind]string{
	KindListener:    finding.IDUnexpectedListener,
	KindPersistence: finding.IDUnexpectedPersist,
	KindSUID:        finding.IDUnexpectedSUID,
	KindAdmin:       finding.IDUnexpectedAdmin,
}

// Item statuses. Only a judged item is ever sent to an answer source.
const (
	StatusJudged       = "judged"       // sent, answered, decided
	StatusFiltered     = "filtered"     // code resolved it; never sent
	StatusInsufficient = "insufficient" // evidence unavailable, truncated or redacted; never sent
	StatusNoAnswer     = "no_answer"    // sent, but the answer was missing or unusable
	StatusOverBudget   = "over_budget"  // the item budget ended the arm before this item
)

// Item is one candidate: a record from the fact sheet, what code read about
// it, what the model was asked, and what code decided.
type Item struct {
	Kind        Kind               `json:"kind"`
	Key         string             `json:"key"`
	Platform    string             `json:"platform"`
	Check       string             `json:"check"`
	Observation string             `json:"observation"`
	Excerpt     string             `json:"excerpt"`
	Fields      map[string]string  `json:"fields"`
	FollowUp    *FollowUp          `json:"follow_up,omitempty"`
	Status      string             `json:"status"`
	Reason      string             `json:"reason,omitempty"`
	Answers     map[string]float64 `json:"answers,omitempty"`
	Filed       string             `json:"filed,omitempty"`
	Decision    string             `json:"decision,omitempty"`
}

// FollowUp is the one bounded read code ran for an item, from the fixed
// per-kind table. It is recorded whether or not it produced output: an
// unavailable follow-up is an answer ("the definition could not be read"),
// not an error.
type FollowUp struct {
	Check       string `json:"check"`
	Path        string `json:"path"`
	Observation string `json:"observation,omitempty"`
	Status      string `json:"status"`
	Output      string `json:"-"` // sent as state, never stored in the record
	Reason      string `json:"reason,omitempty"`
}

// Request is one item's question set and the state it is answered against.
// ItemKey and Kind are for the caller's bookkeeping; a live adapter sends
// State and Questions only.
type Request struct {
	ItemKey   string
	Kind      Kind
	State     State
	Questions []Question
}

// Answerer answers one item's questions. Implementations: scripted (R1),
// an available generative model (R2) and Jev (R3). It is the only seam
// where an answer enters this package.
type Answerer interface {
	// Answer returns one probability in [0,1] per question id. A missing,
	// malformed or out-of-range value files nothing and marks the item.
	Answer(ctx context.Context, req Request) (map[string]float64, error)
	// Source names the answer source in the record, so scripted, generative
	// and Jev answers are never presented as one another's performance.
	Source() string
}

// Options drive Run.
type Options struct {
	Sheet      *baseline.FactSheet
	Runner     *runner.Runner
	Store      *finding.Store
	Context    *operator.Merged
	Profile    check.Profile
	Answers    Answerer
	Thresholds Thresholds
	Budgets    policy.Budgets
	// MaxItems bounds how many candidates are judged in one run; 0 uses
	// DefaultMaxItems. Reaching it ends the arm by name, like every other
	// budget.
	MaxItems int
}

// DefaultMaxItems bounds one run's judged candidates.
const DefaultMaxItems = 128

// Result is the record of one bounded run.
type Result struct {
	Source           string   `json:"source"`
	QuestionsVersion string   `json:"questions_version"`
	Items            []Item   `json:"items"`
	Requests         int      `json:"requests"`
	FollowUps        int      `json:"follow_ups"`
	Filed            []string `json:"filed"`
	Ended            string   `json:"ended"`
	Errors           []string `json:"errors,omitempty"`
}

// Counts returns how many items ended in each status.
func (r *Result) Counts() map[string]int {
	out := map[string]int{}
	for _, it := range r.Items {
		out[it.Status]++
	}
	return out
}

// Run is the whole arm: enumerate, resolve, ask, decide, file. It returns an
// error only when it could not run at all; everything else is recorded.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Sheet == nil || o.Runner == nil || o.Store == nil {
		return nil, errors.New("bounded: sheet, runner and store are required")
	}
	if o.Answers == nil {
		return nil, errors.New("bounded: an answer source is required")
	}
	if o.Thresholds == (Thresholds{}) {
		o.Thresholds = DefaultThresholds()
	}
	if o.MaxItems <= 0 {
		o.MaxItems = DefaultMaxItems
	}
	maxFollowUps := o.Budgets.AgentChecks
	if maxFollowUps <= 0 {
		maxFollowUps = policy.DefaultBudgets().AgentChecks
	}
	if o.Store.Output == nil {
		// Evidence is validated against the exact observation it cites
		// (§5.7); without this the store accepts nothing.
		o.Store.Output = o.Runner.Observations().Get
	}
	rv := &resolver{opts: o}
	res := &Result{Source: o.Answers.Source(), QuestionsVersion: QuestionsVersion(), Items: []Item{}, Filed: []string{}, Ended: "complete"}
	items := Enumerate(o.Sheet, o.Context)
	judged := 0
	for i := range items {
		it := &items[i]
		if it.Status != StatusJudged {
			continue
		}
		if judged >= o.MaxItems {
			it.Status, it.Reason, res.Ended = StatusOverBudget, "item budget", "budget: items"
			continue
		}
		judged++
		if rv.reads < maxFollowUps && rv.resolve(ctx, it) {
			res.FollowUps++
		}
		qs := Questions(it.Kind)
		answers, err := o.Answers.Answer(ctx, Request{ItemKey: it.Key, Kind: it.Kind, State: StateFor(*it, o.Context), Questions: qs})
		res.Requests++
		if err != nil {
			it.Status, it.Reason = StatusNoAnswer, err.Error()
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", it.Key, err))
			if ctx.Err() != nil {
				res.Ended = "budget: run timeout"
				break
			}
			continue
		}
		clean, err := validAnswers(qs, answers)
		if err != nil {
			it.Status, it.Reason = StatusNoAnswer, err.Error()
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", it.Key, err))
			continue
		}
		it.Answers = clean
		d := Decide(*it, o.Thresholds)
		it.Decision = d.Reason
		if !d.File {
			continue
		}
		f, err := o.Store.Report(candidate(*it, d))
		if err != nil {
			it.Reason = err.Error()
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", it.Key, err))
			continue
		}
		it.Filed = f.ID
		res.Filed = append(res.Filed, f.ID)
	}
	res.Items = items
	sort.Strings(res.Filed)
	res.Filed = dedup(res.Filed)
	return res, nil
}

// candidate turns a decision into the report_finding-shaped candidate the
// store validates. Severity is absent on purpose: it is code's (§7.1), and
// the confidence word is derived from the decision, never from the model.
func candidate(it Item, d Decision) finding.Candidate {
	c := finding.Candidate{
		ID:          FindingID[it.Kind],
		Confidence:  d.Confidence,
		ContextNote: d.Reason,
		Evidence:    []finding.Evidence{{Observation: it.Observation, Check: it.Check, Excerpt: it.Excerpt}},
	}
	if it.FollowUp != nil && it.FollowUp.Observation != "" && it.FollowUp.Excerpt() != "" {
		c.Evidence = append(c.Evidence, finding.Evidence{Observation: it.FollowUp.Observation, Check: it.FollowUp.Check, Excerpt: it.FollowUp.Excerpt()})
	}
	if it.Kind == KindListener {
		if port, proto, ok := servicePort(it); ok {
			c.Service = &finding.ServiceRef{Port: port, Proto: proto}
		}
	}
	return c
}

// Excerpt is the follow-up's first meaningful line, quoted verbatim so the
// store can validate it against the observation.
func (f *FollowUp) Excerpt() string {
	for l := range strings.SplitSeq(f.Output, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || check.HasMarker(l) {
			continue
		}
		return l
	}
	return ""
}

func dedup(in []string) []string {
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}
