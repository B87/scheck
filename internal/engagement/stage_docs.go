package engagement

import (
	"strings"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/report"
)

// Header opens every stage document.
type Header struct {
	Stage      string    `json:"stage"`
	Engagement string    `json:"engagement"`
	Started    time.Time `json:"started"`
	Source     Source    `json:"source"`
}

// ScopeDoc is scope.json: the assets the run starts from, the first-party
// evidence each web asset has, what discovery found under each domain root
// and what is excluded (docs/spec/scope.md, "What is in scope",
// "Discovery"). It is for the operator to read, and it says which names
// Recon reads; the gate decides from the engagement file, never from this
// document.
type ScopeDoc struct {
	Header
	Discovery string       `json:"discovery"`
	Roots     []Ref        `json:"roots"`
	Exclude   []Ref        `json:"exclude"`
	Assets    []ScopeAsset `json:"assets"`
	// Resolver is the DNS resolver discovery asked; nil without a domain
	// root.
	Resolver *Resolver     `json:"resolver,omitempty"`
	Domains  []ScopeDomain `json:"domains,omitempty"`
	// PointsAt lists the services outside every root that names under a
	// root point at.
	PointsAt []PointsAt `json:"points_at,omitempty"`
}

// ScopeAsset is one asset in scope and the collector that will read it.
type ScopeAsset struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	Root string `json:"root"`
	// Collector names the built collector, or is empty when none reads the kind yet.
	Collector string `json:"collector,omitempty"`
	// FirstParty is the evidence that a domain, url or host asset's server
	// is the operator's, empty when there is none (docs/spec/scope.md,
	// "First-party evidence"); it is not asked of other kinds.
	FirstParty *Evidence `json:"first_party,omitempty"`
}

// Evidence is one kind of first-party evidence: a url, host or network
// root (the file's own) or the operator's confirmation, printed as such.
type Evidence struct {
	// Kind is url_root, host_root, network_root or operator; expired,
	// future or moved for a confirmation past its year, dated after the
	// run, or whose name no longer points at its target, none of which is
	// evidence.
	Kind string `json:"kind"`
	// Root is the root that is the evidence, for a root.
	Root        string `json:"root,omitempty"`
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	Date        string `json:"date,omitempty"`
	Target      string `json:"target,omitempty"`
}

// counts reports whether the evidence is first-party evidence.
func (e *Evidence) counts() bool {
	return e != nil && e.Kind != "expired" && e.Kind != "future" && e.Kind != "moved" && e.Kind != "suspended"
}

// String is the evidence as the Scope stage prints it.
func (e *Evidence) String() string {
	switch {
	case e == nil:
		return "none"
	case e.Kind == "operator":
		return "operator confirmed (" + e.ConfirmedBy + ", " + e.Date + ")"
	case e.Kind == "expired":
		return "none: the confirmation of " + e.Date + " expired"
	case e.Kind == "future":
		return "none: the confirmation is dated " + e.Date + ", after this run"
	case e.Kind == "suspended":
		return "none: the provider returned an unconfigured-service fingerprint"
	case e.Kind == "moved":
		return "none: confirmed for " + e.Target + ", which the name no longer points at"
	case e.Kind == "network_root":
		return "inside " + e.Root
	}
	return strings.ReplaceAll(e.Kind, "_", " ")
}

// ReconDoc is recon.json, the asset map.
type ReconDoc struct {
	Header
	Attribution              []Attribution             `json:"attribution,omitempty"`
	PeopleCandidates         []PeopleCandidate         `json:"people_candidates,omitempty"`
	PeopleInvitationComments []PeopleInvitationComment `json:"people_invitation_comments,omitempty"`
	PeopleCandidatesPartial  bool                      `json:"people_candidates_partial,omitempty"`
	PeopleSource             string                    `json:"people_source,omitempty"`
	PeopleTenantOrder        []string                  `json:"people_tenant_order,omitempty"`
	Assets                   []ReconAsset              `json:"assets"`
	Resolver                 *Resolver                 `json:"resolver,omitempty"`
}

// How far reaching a host got, in recon.json and the report.
const (
	ContactConnected = "connected"
	ContactUnreached = "unreached"
)

// contact is a ReconAsset's Contact from a transport's progress.
func contact(dialled, connected bool) string {
	switch {
	case connected:
		return ContactConnected
	case dialled:
		return ContactUnreached
	}
	return ""
}

// ReconAsset is what Recon read from one asset.
type ReconAsset struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Kind   Kind   `json:"kind"`
	Root   string `json:"root"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Echo is a canary mismatch's echo, redacted and cut, apart from the
	// detail so text output never prints it.
	Echo string `json:"echo,omitempty"`
	// Refusal names a refused asset's kind: host_key_unknown,
	// host_key_changed, access or canary.
	Refusal string `json:"refusal,omitempty"`
	// Contact is how far reaching a host over SSH got: connected,
	// unreached (a connection was attempted, directly or through its jump
	// host, and none opened), or empty when none was attempted;
	// JumpContact the same for its jump host. ResolvedHere are the names
	// this machine resolved to reach it, its own or its jump host's;
	// ResolvedByJump the name its jump host resolved.
	Contact        string   `json:"contact,omitempty"`
	JumpContact    string   `json:"jump_contact,omitempty"`
	ResolvedHere   []string `json:"resolved_here,omitempty"`
	ResolvedByJump string   `json:"resolved_by_jump,omitempty"`
	// Host, Facts and Observations are the host collector's
	// (docs/spec/host-collector.md §6.4), post-redaction.
	Host         *report.Host                  `json:"host,omitempty"`
	Facts        map[string]report.Fact        `json:"facts,omitempty"`
	Observations map[string]report.Observation `json:"observations,omitempty"`
	// Web is what the web collector read under a domain root, redacted by
	// the gate (docs/spec/web-collector.md, "Reads"), and Judged its rules'
	// verdicts on it.
	GitHub *githubc.Evidence  `json:"github,omitempty"`
	Web    *web.Evidence      `json:"web,omitempty"`
	Judged []finding.Judgment `json:"judged,omitempty"`
}

// PlanDoc is plan.json. Plan passes through empty until 0.0.2 E9.
type PlanDoc struct {
	Header
	Method    string   `json:"method"`
	Checklist []string `json:"checklist"`
	// Hosts lists each collected host's planned checks and the checks its
	// disable_checks removed, so the plan reconciles with audit.jsonl.
	Hosts []PlanHost `json:"hosts"`
}

// PlanHost is one host asset's baseline plan.
type PlanHost struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"`
	Planned  []string `json:"planned"`
	Disabled []string `json:"disabled"`
}

// CheckDoc is the Check stage's output: no follow-up is opened until 0.0.2
// E9, so it writes no evidence and no file.
type CheckDoc struct {
	Header
	FollowUps []string `json:"follow_ups"`
}
