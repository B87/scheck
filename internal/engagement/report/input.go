package report

import (
	"time"

	"github.com/b87/scheck/internal/policy"
	hostreport "github.com/b87/scheck/internal/report"
)

// Input is everything the report is built from: the engagement as
// resolved, and what each asset's collection produced. It is in the
// report's own terms, so this package never imports the engagement or a
// collector, and never contacts a target.
type Input struct {
	RulesVersion string
	Exposures    []ExposureInput
	Version      string
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
	// Resumed says an earlier session of the run left what this one kept;
	// EditedByHand names the files it used although they changed since
	// they were written (docs/spec/engagement.md, "Stop and resume").
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
	Acceptances     []AcceptanceInput
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
	// RedactExtra is the number of operator redaction rules.
	RedactExtra int
	// Rerun is the command that runs this engagement again ("scheck run
	// engagement.yaml"), printed where running again closes a gap.
	Rerun string
}

// AssetInput is one asset in scope after Recon.
type AssetInput struct {
	Redactions      []policy.Hit
	WebNotes        []Note
	MailNotes       []Note
	Unfingerprinted []string
	Name            string
	ID              string
	Kind            string
	Root            bool
	// Status and Reason are Recon's (collected, incomplete, failed,
	// refused, not_collected) and the coverage reason when not collected.
	Status string
	Reason string
	Detail string
	// Profile is a host asset's profile, which sets its threshold even
	// when the host was never reached.
	Profile string
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
	// and Judged are its rules' verdicts there.
	Collector string
	Judged    []Judgment
	// ReadWith is the root a declared domain asset was read with, its
	// names among the root's.
	ReadWith string
}

// HostInput is a host asset's collection.
type HostInput struct {
	Envelope hostreport.Envelope
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

// ExposureInput is an exact declared public URL and its reason.
type ExposureInput struct{ URL, Reason, Source string }
