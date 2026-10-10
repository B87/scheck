// Package engagement reads and validates the engagement file
// (docs/spec/engagement.md, "Intake: the engagement file"). Validation runs
// before any target contact: nothing in this package executes, resolves a
// name or opens a connection.
//
// The file is the rules of engagement. Every key either narrows what a run
// may do (exclude, disable_checks, deny_paths, redact_extra) or records what
// the operator declared; nothing in it can add a check, allow a path the
// compiled policy denies, or reveal a redacted value (docs/spec/engagement.md,
// "One command, one file").
package engagement

// Schema is the only engagement file schema this build reads. The file may
// change freely until 0.0.2 is published (AGENTS.md, "Conventions").
const Schema = 1

// File is the engagement file as written. Every string that holds a time is
// decoded as a string and parsed explicitly (docs/spec/engagement.md, "Time"),
// never through YAML's own timestamp type.
type File struct {
	Schema        int               `yaml:"schema,omitempty" json:"schema,omitempty"`
	Engagement    Engagement        `yaml:"engagement,omitempty" json:"engagement"`
	Scope         string            `yaml:"scope,omitempty" json:"scope,omitempty"`
	Roots         []Locator         `yaml:"roots,omitempty" json:"roots,omitempty"`
	Exclude       []Locator         `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Defaults      Defaults          `yaml:"defaults,omitempty" json:"defaults"`
	Limits        Limits            `yaml:"limits,omitempty" json:"limits"`
	RedactExtra   []string          `yaml:"redact_extra,omitempty" json:"redact_extra,omitempty"`
	People        map[string]Person `yaml:"people,omitempty" json:"people,omitempty"`
	Access        Access            `yaml:"access,omitempty" json:"access"`
	Tools         []Tool            `yaml:"tools,omitempty" json:"tools,omitempty"`
	NotUsed       []string          `yaml:"not_used,omitempty" json:"not_used,omitempty"`
	Mail          Mail              `yaml:"mail,omitempty" json:"mail"`
	Secrets       Secrets           `yaml:"secrets,omitempty" json:"secrets"`
	Data          Data              `yaml:"data,omitempty" json:"data"`
	Intent        Intent            `yaml:"intent,omitempty" json:"intent"`
	Authorization *Authorization    `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Assets        map[string]Asset  `yaml:"assets,omitempty" json:"assets,omitempty"`
}

// Engagement names the run and the operator's frame of reference.
type Engagement struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Operator string `yaml:"operator,omitempty" json:"operator,omitempty"`
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Trigger  string `yaml:"trigger,omitempty" json:"trigger,omitempty"`
}

// Locator is one root, exclude or asset locator: exactly one kind key is set.
// OrgUnit narrows a google-workspace exclude to an organizational unit.
type Locator struct {
	Domain  string `yaml:"domain,omitempty" json:"domain,omitempty"`
	Network string `yaml:"network,omitempty" json:"network,omitempty"`
	Host    string `yaml:"host,omitempty" json:"host,omitempty"`
	URL     string `yaml:"url,omitempty" json:"url,omitempty"`
	Cloud   string `yaml:"cloud,omitempty" json:"cloud,omitempty"`
	SaaS    string `yaml:"saas,omitempty" json:"saas,omitempty"`
	Repo    string `yaml:"repo,omitempty" json:"repo,omitempty"`
	OrgUnit string `yaml:"org_unit,omitempty" json:"org_unit,omitempty"`
}

// Throttle is a request rate (`5/s`, `120/m`) and a concurrency.
type Throttle struct {
	Rate        string `yaml:"rate,omitempty" json:"rate,omitempty"`
	Concurrency int    `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
}

// Defaults apply to every asset, declared or discovered. Profile is read
// only by host assets.
type Defaults struct {
	Probe    string    `yaml:"probe,omitempty" json:"probe,omitempty"`
	Scan     string    `yaml:"scan,omitempty" json:"scan,omitempty"`
	Throttle *Throttle `yaml:"throttle,omitempty" json:"throttle,omitempty"`
	Profile  string    `yaml:"profile,omitempty" json:"profile,omitempty"`
}

// Limits bound the whole run (docs/spec/scope.md, "Throttle, timeout and
// cost"). `none` turns a limit off; `0` is rejected.
type Limits struct {
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	MaxCost string `yaml:"max_cost,omitempty" json:"max_cost,omitempty"`
}

// Person is one entry of `people`, keyed by handle: a person, or a shared,
// service or break-glass account (docs/spec/engagement.md, "People"). A
// person may hold several addresses and logins; every rule matches over all
// of them.
type Person struct {
	Kind      string   `yaml:"kind,omitempty" json:"kind,omitempty"`
	Org       string   `yaml:"org,omitempty" json:"org,omitempty"`
	Workspace []string `yaml:"workspace,omitempty" json:"workspace,omitempty"`
	GitHub    []string `yaml:"github,omitempty" json:"github,omitempty"`
	// UsedBy names who signs in to a shared account, so a departure among
	// them says to rotate its password.
	UsedBy []string `yaml:"used_by,omitempty" json:"used_by,omitempty"`
	Left   string   `yaml:"left,omitempty" json:"left,omitempty"`
}

// Access is who is expected to hold admin roles, and where MFA is enforced.
type Access struct {
	Admins map[string][]string `yaml:"admins,omitempty" json:"admins,omitempty"`
	MFA    []MFA               `yaml:"mfa,omitempty" json:"mfa,omitempty"`
}

// MFA is one declared enforcement: who the operator believes must use a
// second factor in that tenant, one of MFAEnforcements. `unknown` is an
// answer, not a gap: the contradiction rule abstains on it.
type MFA struct {
	Where    string `yaml:"where,omitempty" json:"where,omitempty"`
	Enforced string `yaml:"enforced,omitempty" json:"enforced,omitempty"`
}

// Tool is one declared SaaS tool or provider.
type Tool struct {
	Category string `yaml:"category,omitempty" json:"category,omitempty"`
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
}

// Mail declares who sends mail as each domain, and which domains send none.
type Mail struct {
	Senders []Sender `yaml:"senders,omitempty" json:"senders,omitempty"`
	NoMail  []string `yaml:"no_mail,omitempty" json:"no_mail,omitempty"`
}

// Sender is one service sending as a domain, with its DKIM selectors.
type Sender struct {
	Domain        string   `yaml:"domain,omitempty" json:"domain,omitempty"`
	Service       string   `yaml:"service,omitempty" json:"service,omitempty"`
	DKIMSelectors []string `yaml:"dkim_selectors,omitempty" json:"dkim_selectors,omitempty"`
}

// Secrets declares where production secrets live.
type Secrets struct {
	Production []SecretStore `yaml:"production,omitempty" json:"production,omitempty"`
}

// SecretStore is one declared store on an asset.
type SecretStore struct {
	Store string `yaml:"store,omitempty" json:"store,omitempty"`
	Asset string `yaml:"asset,omitempty" json:"asset,omitempty"`
}

// Data declares what matters most and where the backups are.
type Data struct {
	MattersMost []DataItem `yaml:"matters_most,omitempty" json:"matters_most,omitempty"`
	Backups     []Backup   `yaml:"backups,omitempty" json:"backups,omitempty"`
}

// DataItem ties what matters most to an asset.
type DataItem struct {
	What  string `yaml:"what,omitempty" json:"what,omitempty"`
	Asset string `yaml:"asset,omitempty" json:"asset,omitempty"`
}

// Backup is a declaration, not a reference: Account may name an account
// outside scope (docs/spec/engagement.md, "Identity, references and validation").
type Backup struct {
	Where   string `yaml:"where,omitempty" json:"where,omitempty"`
	Account string `yaml:"account,omitempty" json:"account,omitempty"`
}

// Intent is what is exposed on purpose, what must not be reachable, and the
// risks accepted at the readout.
type Intent struct {
	ExposedOnPurpose []Exposure     `yaml:"exposed_on_purpose,omitempty" json:"exposed_on_purpose,omitempty"`
	NotExposed       []Exposure     `yaml:"not_exposed,omitempty" json:"not_exposed,omitempty"`
	AcceptedRisks    []AcceptedRisk `yaml:"accepted_risks,omitempty" json:"accepted_risks,omitempty"`
}

// Exposure is one entry point and its declared audience.
type Exposure struct {
	URL      string `yaml:"url,omitempty" json:"url,omitempty"`
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	Reason   string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// AcceptedRisk follows docs/spec/host-collector.md §5.2 for ID and adds the
// asset, the instance key, who accepted it and until when.
type AcceptedRisk struct {
	ID         string `yaml:"id,omitempty" json:"id,omitempty"`
	Asset      string `yaml:"asset,omitempty" json:"asset,omitempty"`
	Subject    string `yaml:"subject,omitempty" json:"subject,omitempty"`
	Reason     string `yaml:"reason,omitempty" json:"reason,omitempty"`
	AcceptedBy string `yaml:"accepted_by,omitempty" json:"accepted_by,omitempty"`
	Expires    string `yaml:"expires,omitempty" json:"expires,omitempty"`
}

// Authorization is the operator's declaration of who approved probes and
// scans, when, and from where (docs/spec/scope.md, "Authorization").
type Authorization struct {
	By      string   `yaml:"by,omitempty" json:"by,omitempty"`
	Date    string   `yaml:"date,omitempty" json:"date,omitempty"`
	Windows []Window `yaml:"windows,omitempty" json:"windows,omitempty"`
	Source  []string `yaml:"source,omitempty" json:"source,omitempty"`
	Note    string   `yaml:"note,omitempty" json:"note,omitempty"`
}

// Window is one authorization window, RFC 3339 with seconds and an offset.
type Window struct {
	From string `yaml:"from,omitempty" json:"from,omitempty"`
	To   string `yaml:"to,omitempty" json:"to,omitempty"`
}

// Asset is one entry of `assets`: a locator that equals or falls under a
// root, and settings for that asset. The host settings are read only on a
// host asset, FirstParty only on a domain, url or host, DeploysTo and CI only
// on a repository.
type Asset struct {
	Locator `yaml:",inline"`

	Probe    string    `yaml:"probe,omitempty" json:"probe,omitempty"`
	Scan     string    `yaml:"scan,omitempty" json:"scan,omitempty"`
	Throttle *Throttle `yaml:"throttle,omitempty" json:"throttle,omitempty"`

	Jump          string       `yaml:"jump,omitempty" json:"jump,omitempty"`
	Identity      string       `yaml:"identity,omitempty" json:"identity,omitempty"`
	KnownHosts    string       `yaml:"known_hosts,omitempty" json:"known_hosts,omitempty"`
	Timeout       string       `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Elevate       string       `yaml:"elevate,omitempty" json:"elevate,omitempty"`
	Profile       string       `yaml:"profile,omitempty" json:"profile,omitempty"`
	DisableChecks []string     `yaml:"disable_checks,omitempty" json:"disable_checks,omitempty"`
	DenyPaths     []string     `yaml:"deny_paths,omitempty" json:"deny_paths,omitempty"`
	Context       *HostContext `yaml:"context,omitempty" json:"context,omitempty"`

	FirstParty *FirstParty `yaml:"first_party,omitempty" json:"first_party,omitempty"`

	DeploysTo string `yaml:"deploys_to,omitempty" json:"deploys_to,omitempty"`
	CI        string `yaml:"ci,omitempty" json:"ci,omitempty"`
	// Public records deliberate public repository visibility; absence is not
	// a declaration (docs/spec/github-collector.md, "Context and subjects").
	Public   *bool  `yaml:"public,omitempty" json:"public,omitempty"`
	Checkout string `yaml:"checkout,omitempty" json:"checkout,omitempty"`
}

// HostContext is the host collector's structured context, these four fields
// and nothing else (docs/spec/host-collector.md §5.2; docs/spec/engagement.md,
// "Host context").
type HostContext struct {
	Role             string    `yaml:"role,omitempty" json:"role,omitempty"`
	Exposure         string    `yaml:"exposure,omitempty" json:"exposure,omitempty"`
	Environment      string    `yaml:"environment,omitempty" json:"environment,omitempty"`
	ExpectedServices []Service `yaml:"expected_services,omitempty" json:"expected_services,omitempty"`
}

// Service is one expected listener on a host.
type Service struct {
	Port     int    `yaml:"port,omitempty" json:"port"`
	Proto    string `yaml:"proto,omitempty" json:"proto"`
	Purpose  string `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
}

// FirstParty is the operator's confirmation that a name's server is
// theirs, bound to where the name pointed then and valid for a year
// (docs/spec/scope.md, "First-party evidence"): written by hand in 0.0.2,
// by the Scope stage from 0.0.3.
type FirstParty struct {
	ConfirmedBy string `yaml:"confirmed_by,omitempty" json:"confirmed_by,omitempty"`
	Date        string `yaml:"date,omitempty" json:"date,omitempty"`
	// Target is the first CNAME hop outside every root, else the
	// addresses, comma-separated.
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
}
