package report

import (
	"time"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	hostreport "github.com/b87/scheck/internal/report"
)

// Input is everything the report is built from: the engagement as
// resolved, and what each asset's collection produced. It is in the
// report's own terms, so this package never imports the engagement or a
// collector, and never contacts a target.
type Input struct {
	PrincipalChanges []PrincipalChange
	Vantage          string
	Observations     map[string]Observation
	LevelsUsed       []string
	RulesVersion     string
	Version          string
	// Name, Operator, Trigger and the rest of the header, as declared.
	Name     string
	Operator string
	Trigger  string // "" for --host
	// Zone is engagement.timezone, in which dates and acceptances are read.
	Zone *time.Location
	// FromHost marks an engagement built by --host; Path is the file's path
	// as read ("" for --host) and SHA256 its hash.
	FromHost      bool
	Path          string
	SHA256        string
	Authorization *Authorization
	Started       time.Time
	// Finished closes the collection span; zero is Started.
	Finished time.Time
	// Directory is the run directory, "" under --no-persist.
	Directory string
	// Session is when this session started: a kept reading's age is
	// counted to it.
	Session time.Time
	// Resumed says an earlier session of the run left what this one kept;
	// EditedByHand names the files it used although they changed since
	// they were written (docs/spec/runs.md, "Stop and resume").
	Resumed      bool
	EditedByHand []string

	Assets []AssetInput
	// NotUsed are the areas the operator declared do not apply.
	NotUsed []string
	// OtherTools are the declared tools no collector reads, by name.
	OtherTools []string
	// Declarations are declared facts no rule verifies, by the area whose
	// row prints them.
	Declarations []Declaration
	// DataMattersMost are the asset ids data.matters_most names.
	DataMattersMost []string
	// MattersMost are the data.matters_most entries naming an asset in
	// scope, in file order, for the summary's readout.
	MattersMost []MatterInput
	Acceptances []AcceptanceInput
	// Excludes are the exclude entries as written; ExcludeMatches counts,
	// by entry, the names discovery dropped for it, nil when no discovery
	// ran.
	Excludes       []string
	ExcludeMatches map[string]int
	// Egress is what left this machine; nil is nothing.
	Egress *EgressInput
	// People says whether the engagement names anyone; Candidates are the
	// handles an acceptance's owner is suggested from.
	People     bool
	Candidates []Candidate
	// Departed are the people with a declared leaving date, by handle, and
	// the providers they declare an account at; their accounts are what
	// the collectors attributed (docs/spec/report.md, "People who left").
	Departed []Departure
	// ContextNotes are what Analyze found where the evidence and a
	// declaration disagree, or a declaration reached nothing: listed with
	// the notes, and on their area's row when they name one.
	ContextNotes []ContextNote
	// RedactExtra is the number of operator redaction rules.
	RedactExtra int
	// Rerun is the command that runs this engagement again ("scheck run
	// engagement.yaml"), printed where running again closes a gap.
	Rerun string
}

// The kinds of context note (docs/spec/engagement.md, "Context notes").
const (
	NoteContextWorkspaceDomain = "context_workspace_domain"
	NoteContextDeploysTo       = "context_deploys_to"
	NoteContextNotUsed         = "context_not_used"
)

// ContextNote is one context note: no id, no severity, no exit effect.
// Area is the not_used area it contradicts, "" for none.
type ContextNote struct {
	Area string
	Note
}

// Departure is one person with a declared leaving date: the date as
// written and the providers ("workspace", "github") the person declares an
// account at.
type Departure struct {
	Handle, Left string
	Providers    []string
}

// MatterInput is one data.matters_most entry: its key
// (data.matters_most[i]), the asset id it names and what the data is.
type MatterInput struct{ Key, Asset, What string }

// AssetInput is one asset in scope after Recon.
type AssetInput struct {
	NetworkPrincipal     *Principal
	InventoryNotes       []Note
	InventoryRead        bool
	PopulationIncomplete bool
	NetworkTrace         []Trace
	WebShortfalls        []Shortfall
	Redactions           []policy.Hit
	WebNotes             []Note
	MailNotes            []Note
	Unfingerprinted      []string
	Name                 string
	ID                   string
	Kind                 string
	Root                 bool
	// Status and Reason are Recon's (collected, incomplete, failed,
	// refused, not_collected) and the coverage reason when not collected.
	Status string
	Reason string
	Detail string
	// Profile is a host asset's profile, which sets its threshold even
	// when the host was never reached.
	Profile string
	// Coverage are a network collector's coverage plans for the asset, one
	// per area, worded by the collector and marked by the report.
	Coverage []CoveragePlan
	// Selections are how far each kind of a collector's budgeted reads
	// reached among what Plan selected, with the finding ids that rest on
	// each (docs/spec/report.md, "Coverage").
	Selections []finding.KindSelection
	// OldestCollectedAt is the collection time of the oldest successful
	// observation the asset rests on; zero when nothing was read for it.
	OldestCollectedAt time.Time
	// NoProduction says a GitHub root declares no deploys_to: production
	// repository, so a departed person's push to production is not judged.
	NoProduction bool
	// PermissionAsks counts the permission follow-up's pairs (F1) on a
	// GitHub root, nil when none was open.
	PermissionAsks *FollowUpCount
	// Echo is a canary mismatch's echo, redacted and cut; JSON only.
	Echo string
	// Refusal is a refused asset's kind: host_key_unknown,
	// host_key_changed, jump_host_key_unknown, jump_host_key_changed,
	// excluded, jump_excluded, access or canary.
	Refusal string
	// Contact is how far reaching a host over SSH got: connected,
	// unreached (a connection was attempted, directly or through its jump
	// host, and none opened), or "" when none was attempted; JumpContact
	// the same for its jump host, Via.
	Contact, JumpContact string
	// Via is a host's jump host, user@host:port, "" when reached directly.
	Via string
	// Trace is the asset's audit log entries, in order: every command a
	// collection attempt sent, refused and failed ones included.
	Trace []policy.AuditEntry
	// Host is set for a host asset that was collected, in full or in part.
	Host *HostInput
	// Kept says a resume kept the host from the earlier session that
	// collected it: this session did not contact it.
	Kept bool
	// Collector names the network collector that read the asset ("web"),
	// and Judged are its rules' verdicts there, each fired one with the
	// severity chain Analyze gave it.
	Collector string
	Judged    []Judgment
	// ReadWith is the root a declared domain asset was read with, its
	// names among the root's.
	ReadWith string
}

// HostInput is a host asset's collection.
type HostInput struct {
	Envelope hostreport.Envelope
	// Chains are the engagement's steps on a posture finding after the
	// host collector's table, by finding id; the envelope keeps the
	// collector's severity (docs/spec/engagement.md, "Stacking").
	Chains map[string]*finding.Chain
	// Graded is when its accepted risks were graded: the start of the
	// session that collected it, which a resume may have kept; zero is the
	// run's start.
	Graded time.Time
	// User is who the host was read as.
	User string
	// Planned are the check ids the plan held, so checks a cut collection
	// never reached are counted.
	Planned []string
	// Lost is the transport failure that cut the collection, "" if none.
	Lost string
	// AppPaths is how many application folders the asset declares; the
	// creds.app_env_N slots past it were never meant to run.
	AppPaths int
	// Disabled and DenyPaths are the asset's narrowing, each with its entry
	// in the file.
	Disabled  []Entry
	DenyPaths []Entry
	// ExpectedServices is how many expected_services the asset declares;
	// no rule compares them with listeners before E9.
	ExpectedServices int
	// ExpectedSource is where they are declared.
	ExpectedSource string
	// Evidence is the asset's evidence file in the run directory, "" under
	// --no-persist.
	Evidence string
}

// Entry is one value of a list in the engagement file and where it is.
type Entry struct {
	Value  string
	Source string // "<file> assets.deploy.disable_checks[0]"
}

// Declaration is a declared fact scheck did not verify.
type Declaration struct {
	Area   string
	Source string
	Detail string
}

// AcceptanceInput is one intent.accepted_risks entry as resolved.
type AcceptanceInput struct {
	Entry string // "<file> intent.accepted_risks[i]"
	ID    string
	// Asset is the reference as written; AssetID the canonical id it names.
	Asset      string
	AssetID    string
	Subject    string
	Reason     string
	AcceptedBy string
	Expires    string
}

// Observation is the original collection metadata, including reused evidence.
type Observation struct {
	Principal   string // Optional collector-specific actor for local evidence.
	CollectedAt time.Time
	Vantage     string
}

// FollowUpCount is how far a follow-up got: the pairs it opened, how many
// it asked, and whether the cap or a limit (Stopped, its detail) cut the
// rest (docs/spec/report.md, "Coverage").
type FollowUpCount struct {
	Opened, Asked int
	Capped        bool
	Stopped       string
}
