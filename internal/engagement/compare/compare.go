// Package compare compares two engagement reports of the same engagement
// for remediation follow-up: what was fixed, what is still open, what is
// new, what moved, and what the later run could not say
// (docs/spec/runs.md, "Comparing two runs").
//
// It works on the two reports alone. It contacts nothing, runs nothing, reads
// no file and imports no collector: a fixed finding is a claim, and the
// package makes it only from what the two reports record of how each rule
// decided. Everything it prints was already redacted in the reports it reads.
package compare

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
)

// SchemaVersion is the comparison's JSON schema version
// (docs/engagement-comparison-schema.json).
const SchemaVersion = "1.0"

// Input is one run's report, read and checked by the caller.
type Input struct {
	Report *report.Report
	// SHA256 is the digest of the report's bytes.
	SHA256 string
	// Directory is the run directory, empty for a report file on its own.
	Directory string
	// RunRecordChecked says the report's bytes matched the hash its run
	// directory recorded; a report file on its own cannot say so.
	RunRecordChecked bool
}

// Refusal is a pair of runs that cannot be compared. The caller exits 3.
type Refusal struct{ Why string }

func (r *Refusal) Error() string { return r.Why }

func refuse(format string, args ...any) error { return &Refusal{Why: fmt.Sprintf(format, args...)} }

// Category is what became of one finding instance between the runs.
type Category string

// The categories. new, first_reported and reopened are what got worse or
// appeared; fixed is the one claim that needs the strictest evidence.
const (
	New           Category = "new"
	FirstReported Category = "first_reported"
	Reopened      Category = "reopened"
	Fixed         Category = "fixed"
	StillOpen     Category = "still_open"
	AcceptedSince Category = "accepted_since"
	StillAccepted Category = "still_accepted"
	NotConfirmed  Category = "not_confirmed"
	NotRechecked  Category = "not_rechecked"
)

var categoryOrder = []Category{New, FirstReported, Reopened, Fixed, StillOpen, AcceptedSince, StillAccepted, NotConfirmed, NotRechecked}

// Causes: why a finding is not fixed or new but "not confirmed", "not
// checked again" or "reported for the first time". A closed vocabulary; the
// text words each.
const (
	CauseAssetNotInRun      = "asset_not_in_run"
	CauseAssetNotRead       = "asset_not_read"
	CauseAssetNotListed     = "asset_not_listed"
	CauseRuleNotAssessed    = "rule_not_assessed"
	CauseRuleUndecided      = "rule_undecided"
	CauseIncomplete         = "incomplete_population"
	CauseRulesChanged       = "rules_changed"
	CauseDeclarationChanged = "declaration_changed"
	CausePrincipalChanged   = "principal_changed"
	CauseVantageChanged     = "vantage_changed"
	CauseAssetReplaced      = "asset_replaced"
	CauseSubjectUnmatchable = "subject_unmatchable"
	CauseSubjectReplaced    = "subject_replaced"
	CauseSuperseded         = "superseded"
	CauseAcceptanceExpired  = "acceptance_expired"
	CauseAcceptanceEnded    = "acceptance_ended"
)

// Note tokens on an instance.
const (
	NoteRevocationUnchecked = "revocation_not_checked"
	NoteTimeDependent       = "date_dependent"
)

// Comparison is the result.
type Comparison struct {
	SchemaVersion string           `json:"schema_version"`
	Engagement    string           `json:"engagement"`
	Earlier       Side             `json:"earlier"`
	Later         Side             `json:"later"`
	Comparable    Comparability    `json:"comparable"`
	Summary       Counts           `json:"summary"`
	Instances     []Instance       `json:"instances"`
	Assets        []AssetChange    `json:"assets"`
	Coverage      []CoverageChange `json:"coverage"`
	PeopleLeft    []PersonChange   `json:"people_left"`
	Exit          Exit             `json:"exit"`
}

// Side identifies one of the two runs.
type Side struct {
	Directory        *string   `json:"directory"`
	Started          time.Time `json:"started"`
	CollectedFrom    time.Time `json:"collected_from"`
	CollectedTo      time.Time `json:"collected_to"`
	Timezone         string    `json:"timezone"`
	ScheckVersion    string    `json:"scheck_version"`
	RulesVersion     string    `json:"rules_version"`
	SchemaVersion    string    `json:"schema_version"`
	SourceSHA256     string    `json:"source_sha256"`
	ReportSHA256     string    `json:"report_sha256"`
	RunRecordChecked bool      `json:"run_record_checked"`
	BuiltFrom        string    `json:"built_from"`
	Vantage          string    `json:"vantage,omitempty"`
	ExitCode         int       `json:"exit_code"`
	// OperatorRedactionRules counts the redact_extra patterns the report was
	// redacted with; the patterns themselves are never in a report.
	OperatorRedactionRules int `json:"operator_redaction_rules"`
}

// Comparability says what the pair can support. A false field narrows the
// claims, never the run: the instances carry the causes.
type Comparability struct {
	// SameRules is true when both runs are the same release build of
	// scheck. Only then may a finding that is gone be fixed or one that
	// appears be new: a rule change is the commonest way a finding vanishes
	// without a fix.
	SameRules bool `json:"same_rules"`
	// SameFile is true when the engagement file's hash is equal.
	SameFile bool `json:"same_file"`
	// VantageChanged: the runs read from different network positions.
	VantageChanged bool `json:"vantage_changed"`
	// RedactionRulesDiffer: the runs were redacted with a different number
	// of redact_extra patterns, so a name the later run hides may be in the
	// earlier text. Subjects only the earlier run holds are withheld.
	RedactionRulesDiffer bool `json:"redaction_rules_differ"`
	// HoursApart counts from the earlier run's last collection to the
	// later run's first.
	HoursApart int `json:"hours_apart"`
	// PrincipalChanges lists assets read as a different principal.
	PrincipalChanges []string `json:"principal_changes"`
}

// Counts totals the instances by category.
type Counts struct {
	EarlierOpen int `json:"earlier_open"`
	// EarlierAccepted counts the earlier run's accepted findings; the
	// categories below cover open and accepted ones alike.
	EarlierAccepted int `json:"earlier_accepted"`
	Fixed           int `json:"fixed"`
	StillOpen       int `json:"still_open"`
	AcceptedSince   int `json:"accepted_since"`
	StillAccepted   int `json:"still_accepted"`
	NotConfirmed    int `json:"not_confirmed"`
	NotRechecked    int `json:"not_rechecked"`
	New             int `json:"new"`
	FirstReported   int `json:"first_reported"`
	Reopened        int `json:"reopened"`
	Moved           int `json:"moved"`
	Renamed         int `json:"renamed"`
}

// Ref is one run's view of an instance.
type Ref struct {
	Asset     string  `json:"asset"`
	AssetName string  `json:"asset_name"`
	BoundID   *string `json:"bound_id"`
	// Subject is the instance; null for the asset itself, and for an
	// instance the redaction rules of the two runs make unsafe to print
	// (SubjectWithheld).
	Subject         *report.Subject `json:"subject"`
	SubjectWithheld bool            `json:"subject_withheld,omitempty"`
	Severity        string          `json:"severity"`
	Status          string          `json:"status"`
}

// Instance is one finding instance across the two runs.
type Instance struct {
	Category Category `json:"category"`
	Cause    string   `json:"cause,omitempty"`
	// Reason is the assessment's or asset's reason token behind a cause.
	Reason  string `json:"reason,omitempty"`
	ID      string `json:"id"`
	Title   string `json:"title"`
	Area    string `json:"area"`
	Earlier *Ref   `json:"earlier"`
	Later   *Ref   `json:"later"`
	// Identity says how the two runs' instances were joined: same key, the
	// asset moved (same bound id), the subject was renamed (same provider
	// id), or both.
	Identity   string        `json:"identity,omitempty"`
	Severity   *SevChange    `json:"severity_change,omitempty"`
	Acceptance *AcceptChange `json:"acceptance_change,omitempty"`
	// NotChecked is the earlier finding's own not-checked lines, kept on a
	// fixed instance: what the rule never saw still holds.
	NotChecked []string `json:"not_checked,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// SevChange is a severity that differs on an instance present in both runs.
type SevChange struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Added and Removed are the chain steps that differ, each with its
	// source. The comparison never recomputes a severity; it prints each
	// run's own chain.
	Added   []Step `json:"added"`
	Removed []Step `json:"removed"`
	// BaseChanged: the base severity differs (a rule or table changed).
	BaseChanged bool `json:"base_changed"`
	// LoweredByDeclaration: it went down and a declaration step in the
	// engagement file was added or removed.
	LoweredByDeclaration bool `json:"lowered_by_declaration"`
}

// Step is one adjustment of a severity chain.
type Step struct {
	Rule   string `json:"rule"`
	By     string `json:"by"`
	Delta  string `json:"delta"`
	Source string `json:"source"`
	// Declared: the step rests on a declaration in the engagement file, not
	// on something read.
	Declared bool `json:"declared"`
}

// AcceptChange is an acceptance that differs between the runs.
type AcceptChange struct {
	FromStatus string  `json:"from_status"`
	ToStatus   string  `json:"to_status"`
	AcceptedBy string  `json:"accepted_by,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	Expires    *string `json:"expires"`
}

// AssetChange is an asset that was added, left, moved, was replaced, or
// was read differently.
type AssetChange struct {
	Change string `json:"change"` // added | removed | moved | replaced | status | principal
	Asset  string `json:"asset"`
	Name   string `json:"name"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// CoverageChange is a coverage row whose mark differs.
type CoverageChange struct {
	Area string `json:"area"`
	Tool string `json:"tool,omitempty"`
	From string `json:"from"`
	To   string `json:"to"`
}

// PersonChange is a left person's line whose state differs.
type PersonChange struct {
	Handle   string  `json:"handle"`
	Provider string  `json:"provider"`
	Asset    *string `json:"asset"`
	From     string  `json:"from"`
	To       string  `json:"to"`
}

// Exit is the comparison's own exit code: 0, 1, 2 or 3 and nothing else.
type Exit struct {
	Code    int      `json:"code"`
	Reasons []string `json:"reasons"`
	// OpenAtOrAboveThreshold counts the later run's open findings at or
	// above their asset's threshold: what exit 0 does not say is fixed.
	OpenAtOrAboveThreshold int `json:"open_at_or_above_threshold"`
}

// Compare compares an earlier run with a later one. A pair that cannot be
// compared is a *Refusal.
func Compare(earlier, later Input) (*Comparison, error) {
	e, l := earlier.Report, later.Report
	if e == nil || l == nil {
		return nil, errors.New("compare: a report is missing")
	}
	if e.Engagement.Name != l.Engagement.Name {
		return nil, refuse("these are runs of different engagements (%s and %s); a comparison of two engagements would mix their data", clean(e.Engagement.Name), clean(l.Engagement.Name))
	}
	if earlier.SHA256 != "" && earlier.SHA256 == later.SHA256 || e.Run.Started.Equal(l.Run.Started) {
		return nil, refuse("these are the same run: there is nothing to compare")
	}
	if e.Run.Started.After(l.Run.Started) {
		return nil, refuse("the first run started %s, after the second (%s): give the earlier run first", e.Run.Started.UTC().Format(time.RFC3339), l.Run.Started.UTC().Format(time.RFC3339))
	}
	p := newPair(earlier, later)
	c := &Comparison{
		SchemaVersion: SchemaVersion,
		Engagement:    e.Engagement.Name,
		Earlier:       side(earlier),
		Later:         side(later),
		Comparable:    p.comparable(),
		Instances:     []Instance{},
	}
	p.instances(c)
	p.assets(c)
	p.coverage(c)
	p.people(c)
	sortInstances(c.Instances)
	c.Summary = count(c.Instances, e)
	p.exit(c)
	return c, nil
}

func side(in Input) Side {
	r := in.Report
	var dir *string
	if in.Directory != "" {
		d := in.Directory
		dir = &d
	}
	return Side{
		Directory: dir, Started: r.Run.Started, CollectedFrom: r.Engagement.Collected.From, CollectedTo: r.Engagement.Collected.To,
		Timezone: r.Engagement.Timezone, ScheckVersion: r.ScheckVersion, RulesVersion: r.RulesVersion, SchemaVersion: r.SchemaVersion,
		SourceSHA256: r.Engagement.Source.SHA256, ReportSHA256: in.SHA256, RunRecordChecked: in.RunRecordChecked,
		BuiltFrom: r.Engagement.BuiltFrom, Vantage: r.Run.Vantage, ExitCode: r.Exit.Code,
		OperatorRedactionRules: r.Redaction.Operator.Rules,
	}
}

// releaseBuild says a version names a build: a development or uncommitted
// build names none, so two of them are never "the same rules".
func releaseBuild(v string) bool { return releaseTag.MatchString(v) }

// releaseTag is the form a release is built with ({{ .Tag }}); every other
// version (dev, a describe string with commits after the tag, -dirty) names
// no build that can be installed again.
var releaseTag = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

func count(in []Instance, e *report.Report) Counts {
	var n Counts
	for _, f := range e.Findings {
		switch f.Status {
		case "open":
			n.EarlierOpen++
		case "accepted":
			n.EarlierAccepted++
		}
	}
	for _, i := range in {
		switch i.Category {
		case Fixed:
			n.Fixed++
		case StillOpen:
			n.StillOpen++
		case AcceptedSince:
			n.AcceptedSince++
		case StillAccepted:
			n.StillAccepted++
		case NotConfirmed:
			n.NotConfirmed++
		case NotRechecked:
			n.NotRechecked++
		case New:
			n.New++
		case FirstReported:
			n.FirstReported++
		case Reopened:
			n.Reopened++
		}
		switch i.Identity {
		case "moved":
			n.Moved++
		case "renamed":
			n.Renamed++
		case "moved_renamed":
			n.Moved++
			n.Renamed++
		}
	}
	return n
}

func sortInstances(in []Instance) {
	rank := func(c Category) int { return slices.Index(categoryOrder, c) }
	sev := func(i Instance) int {
		if i.Later != nil {
			return finding.Severity(i.Later.Severity).Rank()
		}
		return finding.Severity(i.Earlier.Severity).Rank()
	}
	key := func(i Instance) string {
		r := i.Later
		if r == nil {
			r = i.Earlier
		}
		s := ""
		if r.Subject != nil {
			s = r.Subject.Key
		}
		return i.ID + "\x00" + r.Asset + "\x00" + s
	}
	slices.SortStableFunc(in, func(a, b Instance) int {
		if d := rank(a.Category) - rank(b.Category); d != 0 {
			return d
		}
		if d := sev(b) - sev(a); d != 0 {
			return d
		}
		return strings.Compare(key(a), key(b))
	})
}
