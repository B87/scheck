// Package report builds the engagement report (docs/spec/engagement.md,
// "The report"): coverage by risk area, the ranked findings, what was not
// checked and why, and the exit code, from what a run collected. It reads
// collected evidence and never contacts a target. Its JSON shape is
// docs/engagement-report-schema.json; the text renderer is beside it.
package report

import (
	"time"

	hostreport "github.com/b87/scheck/internal/report"
)

// SchemaVersion is the engagement report's JSON schema version. It may
// change freely until 0.0.2 is published (AGENTS.md, "Conventions").
const SchemaVersion = "1.0"

// Report is the engagement report. Field order and names follow
// docs/engagement-report-schema.json.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ScheckVersion string       `json:"scheck_version"`
	RulesVersion  string       `json:"rules_version"`
	Run           Run          `json:"run"`
	Engagement    Engagement   `json:"engagement"`
	Notice        Notice       `json:"notice"`
	Refused       []Shortfall  `json:"refused"`
	Incomplete    []Shortfall  `json:"incomplete"`
	Exit          Exit         `json:"exit"`
	Summary       Summary      `json:"summary"`
	Coverage      []Row        `json:"coverage"`
	Findings      []Finding    `json:"findings"`
	Assessments   []Assessment `json:"assessments"`
	Acceptances   []Acceptance `json:"acceptances"`
	Excluded      []Excluded   `json:"excluded"`
	Redaction     Redaction    `json:"redaction"`
	Egress        Egress       `json:"egress"`
	Assets        []Asset      `json:"assets"`
	Notes         []Note       `json:"notes"`
}

// Run identifies the run the report is about.
type Run struct {
	Started   time.Time `json:"started"`
	Directory *string   `json:"directory"`
	Resumed   bool      `json:"resumed"`
	// Command runs the engagement again ("scheck run engagement.yaml").
	Command string `json:"command,omitempty"`
}

// Engagement is the header's material.
type Engagement struct {
	Name          string         `json:"name"`
	Operator      *string        `json:"operator"`
	Timezone      string         `json:"timezone"`
	Trigger       *string        `json:"trigger"`
	BuiltFrom     string         `json:"built_from"` // file | host
	Source        Source         `json:"source"`
	Collected     Span           `json:"collected"`
	Method        Method         `json:"method"`
	Authorization *Authorization `json:"authorization"`
	EditedByHand  []string       `json:"edited_by_hand"`
}

// Source names the engagement as read. Path is nil for --host.
type Source struct {
	Path   *string `json:"path"`
	SHA256 string  `json:"sha256"`
}

// Span is a time range.
type Span struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Method is how the engagement assessed: rules and a checklist in 0.0.2.
type Method struct {
	Assessment string   `json:"assessment"`
	Plan       string   `json:"plan"`
	LevelsUsed []string `json:"levels_used"`
}

// Authorization is the operator's declaration, never verified.
type Authorization struct {
	By      string   `json:"by"`
	Date    string   `json:"date"`
	Windows []Span   `json:"windows,omitempty"`
	Source  []string `json:"source,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// Notice is the handling notice: the report names people and topology and
// is written for the operator.
type Notice struct {
	PersonalData     bool   `json:"personal_data"`
	InternalTopology bool   `json:"internal_topology"`
	Audience         string `json:"audience"`
}

// Shortfall is one refused or incomplete asset (docs/spec/engagement.md,
// "Incompleteness and refusals").
type Shortfall struct {
	Asset     string `json:"asset"`
	AssetName string `json:"asset_name"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
	// Echo is what a remote shell returned in place of the canary,
	// redacted and cut. It is attacker-influenced text from a host that
	// failed its trust check, so the JSON carries it and the text never
	// prints it (docs/spec/engagement.md, "Incompleteness and refusals").
	Echo string `json:"echo,omitempty"`
	// Kind names a refusal: host_key_unknown, host_key_changed, their
	// jump_ forms, excluded, jump_excluded, access or canary.
	Kind   string  `json:"kind,omitempty"`
	Effect *Effect `json:"effect,omitempty"`
}

// Effect is what a cut collection lost.
type Effect struct {
	ChecksRun       int  `json:"checks_run"`
	ChecksUnknown   int  `json:"checks_unknown"`
	ChecksNotRun    int  `json:"checks_not_run"`
	RequestsNotSent int  `json:"requests_not_sent,omitempty"`
	Kept            bool `json:"kept"`
}

// Exit is the exit code and why.
type Exit struct {
	Code       int                  `json:"code"`
	Reasons    []ExitReason         `json:"reasons"`
	Thresholds map[string]Threshold `json:"thresholds"`
}

// ExitReason is one condition that set or contributed to the exit code.
type ExitReason struct {
	Code  int    `json:"code"`
	Why   string `json:"why"`
	Asset string `json:"asset,omitempty"`
}

// Threshold is an asset's lowest open severity that counts toward exit 1.
type Threshold struct {
	Severity string `json:"severity"`
	Basis    string `json:"basis"`
}

// Summary is "Fix these first" and the counts the not-a-clean-bill
// statement prints.
type Summary struct {
	Items []Item `json:"items"`
	// More counts the items past the fifth that also rank at medium or
	// above: the summary never says "nothing else" while there are.
	More  int        `json:"more"`
	Below Below      `json:"below"`
	Areas AreaCounts `json:"areas"`
	Rules RuleCounts `json:"rules"`
}

// Item is one ranked entry of "Fix these first".
type Item struct {
	Rank      int      `json:"rank"`
	Kind      string   `json:"kind"` // finding_id | person
	IDs       []string `json:"ids"`
	Person    *string  `json:"person"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Keys      []Key    `json:"keys"`
	Assets    []string `json:"assets"`
	RankBasis []string `json:"rank_basis"`
}

// Below counts what "Fix these first" leaves out.
type Below struct {
	Low      int `json:"low"`
	Info     int `json:"info"`
	Accepted int `json:"accepted"`
}

// AreaCounts are disjoint counts over the ten risk areas.
type AreaCounts struct {
	Assessed      int `json:"assessed"`
	Partial       int `json:"partial"`
	NotAssessed   int `json:"not_assessed"`
	NotApplicable int `json:"not_applicable"`
	Total         int `json:"total"`
}

// RuleCounts are the selected rules and how many decided.
type RuleCounts struct {
	Selected        int `json:"selected"`
	Decided         int `json:"decided"`
	WithoutEvidence int `json:"without_evidence"`
}

// Row is one coverage row.
type Row struct {
	Area                string         `json:"area"`
	Tool                string         `json:"tool,omitempty"`
	Mark                string         `json:"mark"`
	Reasons             []ReasonDetail `json:"reasons"`
	Detail              string         `json:"detail,omitempty"`
	Population          *Population    `json:"population,omitempty"`
	AssetsCovered       []string       `json:"assets_covered,omitempty"`
	AssetsExcluded      []string       `json:"assets_excluded,omitempty"`
	Principals          []Principal    `json:"principals,omitempty"`
	Collected           *Span          `json:"collected,omitempty"`
	Caps                []Cap          `json:"caps,omitempty"`
	Narrowing           []Narrowing    `json:"narrowing,omitempty"`
	DeclaredNotVerified []Note         `json:"declared_not_verified,omitempty"`
	UnattributedMembers *int           `json:"unattributed_members,omitempty"`
	SubItems            []SubItem      `json:"sub_items,omitempty"`
	PlannedIn           string         `json:"planned_in,omitempty"`
}

// SubItem is a rule, or a family sharing a finding id, on an asset; for a
// host, a host domain that carries a rule.
type SubItem struct {
	Name       string         `json:"name"`
	Asset      string         `json:"asset"`
	Mark       string         `json:"mark"`
	Reasons    []ReasonDetail `json:"reasons"`
	Population *Population    `json:"population,omitempty"`
	Rules      []string       `json:"rules,omitempty"`
	// Judged is what the rules that decided judge, as phrases: a "checked"
	// area rests on these and nothing else.
	Judged []string `json:"judged,omitempty"`
	// ReadNotJudged is what was read in the area that no rule judges.
	ReadNotJudged []string `json:"read_not_judged,omitempty"`
}

// ReasonDetail is one reason from the closed list and its detail.
type ReasonDetail struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Population is what a mark counts.
type Population struct {
	Kind    string `json:"kind"`
	InScope int    `json:"in_scope"`
	Read    int    `json:"read"`
}

// Cap is a limit on what was read, and how the part read was chosen.
type Cap struct {
	What      string `json:"what"`
	Of        int    `json:"of"`
	Cap       int    `json:"cap"`
	Selection string `json:"selection"`
}

// Principal is who the data was read as. Env names the environment
// variable a credential came from, never its value.
type Principal struct {
	Identity     string   `json:"identity"`
	Elevation    string   `json:"elevation,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	ScopesSource string   `json:"scopes_source"` // provider | declared | unknown
	Env          string   `json:"env,omitempty"`
}

// Narrowing is one narrowing entry of the engagement file and what it
// removed.
type Narrowing struct {
	Entry       string   `json:"entry"`
	Removed     []string `json:"removed"`
	DeniedReads *int     `json:"denied_reads,omitempty"`
}

// Note is a note for the readout: never a finding, never counted.
type Note struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}

// Key is a finding instance's join key.
type Key struct {
	ID      string  `json:"id"`
	Asset   string  `json:"asset"`
	Subject *string `json:"subject"`
}

// Subject is the instance a finding is about.
type Subject struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	Label      string `json:"label"`
	ProviderID string `json:"provider_id,omitempty"`
	Person     string `json:"person,omitempty"`
}

// Finding is one finding instance (docs/spec/engagement.md, "Findings").
type Finding struct {
	Key             Key             `json:"key"`
	AssetName       string          `json:"asset_name"`
	BoundID         *string         `json:"bound_id"`
	Subject         *Subject        `json:"subject"`
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Area            string          `json:"area"`
	Category        string          `json:"category"`
	ExposureFinding bool            `json:"exposure_finding"`
	SeverityBase    string          `json:"severity_base"`
	Severity        string          `json:"severity"`
	Adjustments     []Adjustment    `json:"adjustments"`
	Status          string          `json:"status"`
	Acceptance      *FindingAccept  `json:"acceptance,omitempty"`
	Rule            Rule            `json:"rule"`
	Evidence        []Evidence      `json:"evidence"`
	Derived         []Derived       `json:"derived,omitempty"`
	Affected        *Affected       `json:"affected,omitempty"`
	Impact          string          `json:"impact"`
	WhyHere         []string        `json:"why_here"`
	NotChecked      []string        `json:"not_checked"`
	Remediation     Remediation     `json:"remediation"`
	AcceptTemplate  *AcceptTemplate `json:"accept_template,omitempty"`
}

// Adjustment is one step of a severity chain. By is collector for the
// collector's own table, engagement for the engagement's.
type Adjustment struct {
	Rule   string    `json:"rule"`
	By     string    `json:"by"`
	Delta  string    `json:"delta"`
	Source SourceRef `json:"source"`
}

// SourceRef is either a declaration (File and Key) or a fact (Observation
// and Excerpt).
type SourceRef struct {
	File        string `json:"file,omitempty"`
	Key         string `json:"key,omitempty"`
	Observation string `json:"observation,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
}

// FindingAccept is the acceptance an accepted finding is under.
type FindingAccept struct {
	Entry               string  `json:"entry"`
	Reason              string  `json:"reason"`
	AcceptedBy          string  `json:"accepted_by"`
	Expires             *string `json:"expires"`
	Expired             bool    `json:"expired"`
	CoversEveryInstance bool    `json:"covers_every_instance"`
}

// Rule is what produced a finding and every input it read.
type Rule struct {
	Kind  string   `json:"kind"` // single_fact | multi_fact
	Reads []string `json:"reads"`
}

// Evidence is observed (a fact) or declared (the engagement file).
type Evidence struct {
	Kind        string     `json:"kind"` // observed | declared
	Asset       string     `json:"asset,omitempty"`
	Check       string     `json:"check,omitempty"`
	Request     string     `json:"request,omitempty"`
	Observation string     `json:"observation,omitempty"`
	Source      string     `json:"source,omitempty"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
	Principal   string     `json:"principal,omitempty"`
	Excerpt     string     `json:"excerpt"`
}

// Derived is a value computed against collection time.
type Derived struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

// Affected lists secondary subjects, capped.
type Affected struct {
	Count  int      `json:"count"`
	Listed []string `json:"listed"`
	Cap    int      `json:"cap"`
	OfNote []OfNote `json:"of_note,omitempty"`
}

// OfNote is an affected subject that matters more than the rest.
type OfNote struct {
	Key string `json:"key"`
	Why string `json:"why"`
}

// Remediation is text for the human; scheck never runs it.
type Remediation struct {
	Summary  string   `json:"summary"`
	Steps    []string `json:"steps,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Caveat   string   `json:"caveat,omitempty"`
	Where    string   `json:"where,omitempty"`
}

// AcceptTemplate is the ready-to-paste intent.accepted_risks entry for an
// open finding. Reason and AcceptedBy are left empty for the risk's owner.
type AcceptTemplate struct {
	ID                   string      `json:"id"`
	Asset                string      `json:"asset"`
	Subject              string      `json:"subject,omitempty"`
	BySubject            bool        `json:"by_subject"`
	SubjectNote          string      `json:"subject_note,omitempty"`
	Reason               string      `json:"reason"`
	AcceptedBy           string      `json:"accepted_by"`
	AcceptedByCandidates []Candidate `json:"accepted_by_candidates"`
	Expires              string      `json:"expires"`
	NeedsPeople          bool        `json:"needs_people"`
}

// Candidate is a people handle who could own an acceptance, and why.
type Candidate struct {
	Handle string `json:"handle"`
	Why    string `json:"why"`
}

// Assessment is one selected rule on one asset.
type Assessment struct {
	Outcomes     []AssessmentOutcome `json:"outcomes,omitempty"`
	ID           string              `json:"id"`
	Asset        string              `json:"asset"`
	Status       string              `json:"status"`
	Instances    int                 `json:"instances"`
	Complete     bool                `json:"complete"`
	Reason       string              `json:"reason,omitempty"`
	Reads        []string            `json:"reads"`
	Observations []string            `json:"observations,omitempty"`
}

// AssessmentOutcome retains a subject-specific observed decision and its detail.
type AssessmentOutcome struct {
	Subject Subject        `json:"subject"`
	Outcome string         `json:"outcome"`
	Detail  map[string]any `json:"detail"`
}

// Acceptance is one intent.accepted_risks entry and what became of it.
type Acceptance struct {
	Entry      string  `json:"entry"`
	ID         string  `json:"id"`
	Asset      string  `json:"asset"`
	Subject    *string `json:"subject"`
	AcceptedBy string  `json:"accepted_by"`
	Expires    *string `json:"expires"`
	Outcome    string  `json:"outcome"`
	Why        string  `json:"why,omitempty"`
	Findings   []Key   `json:"findings"`
}

// Excluded is one exclude entry and whether it matched.
type Excluded struct {
	Entry   string `json:"entry"`
	Matched *bool  `json:"matched"`
	Detail  string `json:"detail,omitempty"`
}

// Redaction holds counts only, never a pattern.
type Redaction struct {
	Builtin  map[string]int    `json:"builtin"`
	Operator OperatorRedaction `json:"operator"`
}

// OperatorRedaction counts the engagement's redact_extra rules and their
// matches.
type OperatorRedaction struct {
	Rules   int `json:"rules"`
	Matches int `json:"matches"`
}

// Asset is one asset in scope and what became of it.
type Asset struct {
	Name      string  `json:"name"`
	ID        string  `json:"id"`
	BoundID   *string `json:"bound_id"`
	Kind      string  `json:"kind"`
	Root      bool    `json:"root"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason,omitempty"`
	Detail    string  `json:"detail,omitempty"`
	Collector *string `json:"collector,omitempty"`
	// Via is the jump host a host was reached through; nothing ran on it.
	Via       string     `json:"via,omitempty"`
	Principal *Principal `json:"principal,omitempty"`
	Collected *Span      `json:"collected,omitempty"`
	Evidence  *string    `json:"evidence,omitempty"`
	// Checks counts a host's plan: what ran, what gave no usable answer,
	// and what a cut collection never reached.
	Checks   *Checks              `json:"checks,omitempty"`
	Envelope *hostreport.Envelope `json:"envelope,omitempty"`
	// Kept says a resume kept the host from the earlier session that
	// collected it. Its captures were never stored, so --include-evidence
	// adds none to its envelope rather than empty ones.
	Kept  bool    `json:"kept,omitempty"`
	Trace []Trace `json:"trace"`
}

// Trace is one command or request attempted on an asset.
type Trace struct {
	Observation  string            `json:"observation,omitempty"`
	Check        string            `json:"check,omitempty"`
	Request      string            `json:"request,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
	At           time.Time         `json:"at"`
	Decision     string            `json:"decision"`
	OutputSHA256 string            `json:"output_sha256,omitempty"`
}
