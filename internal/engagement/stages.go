package engagement

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/user"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
)

// Stages are the engagement's stages in order (docs/spec/engagement.md,
// "Stages").
var Stages = []string{"intake", "scope", "recon", "plan", "check", "analyze", "report"}

// LastStage is the last stage: Report writes report.json and report.txt
// (docs/spec/engagement.md, "The report").
const LastStage = "report"

// Reasons an asset was not collected, as coverage names them
// (docs/spec/engagement.md, "The report", "Coverage").
const (
	ReasonCollectorNotBuilt = "collector_not_built"
	ReasonFailed            = "failed"
	ReasonLimitReached      = "limit_reached"
)

// ReasonRefused is a host that refused us for a reason on the positive
// list of docs/spec/engagement.md, "Exit codes" (host key, authentication,
// identity, canary): the run goes on and exits 3.
const ReasonRefused = "refused"

// Asset statuses after Recon.
const (
	StatusCollected    = "collected"
	StatusIncomplete   = "incomplete"
	StatusFailed       = "failed"
	StatusRefused      = "refused"
	StatusNotCollected = "not_collected"
)

// RunOptions are a run's inputs besides the resolved file: the flags of
// "One command, one file" that are run settings, never file keys.
type RunOptions struct {
	// Raw is the engagement file as read, or as --host built it.
	Raw []byte
	// Dir is the run directory; nil under --no-persist.
	Dir *RunDir
	// StopAfter ends the run after that stage; "" runs through LastStage.
	StopAfter string
	Started   time.Time
	Version   string
	Log       func(format string, args ...any)
	// RecordFixtures records every host exec into that directory (the
	// hidden --record-fixtures flag).
	RecordFixtures string
	// Collect reaches a host asset; nil is hostasset.Collect. Tests replace
	// it to collect from a fixture.
	Collect func(context.Context, hostasset.Options) (*hostasset.Collection, error)
	// NewGate builds the run's scope gate; nil is gate.New. Tests replace
	// it to reach fake servers through the gate's own test seams.
	NewGate func(gate.Config) (*gate.Gate, error)
	// Resume is what the run directory's earlier sessions left; nil for a
	// new run. Started is then the run's first start.
	Resume *Prior
	// Session is when this session started: the time scope, confirmations
	// and accepted risks are read at. Zero is Started, or now on a resume.
	Session time.Time
}

// Refusal is a run stopped for a reason the operator has to fix before any
// target is contacted, or by the policy while one is: exit 3.
type Refusal struct{ Err error }

func (r *Refusal) Error() string { return r.Err.Error() }
func (r *Refusal) Unwrap() error { return r.Err }

func refuse(format string, args ...any) error {
	return &Refusal{Err: fmt.Errorf(format, args...)}
}

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
	// Collector is "host", or empty when no collector reads the kind yet.
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
	Assets []ReconAsset `json:"assets"`
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
	Web    *web.Evidence  `json:"web,omitempty"`
	Judged []web.Judgment `json:"judged,omitempty"`
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

// FindingsDoc is findings.json: each rule's outcome per asset, and what was
// refused or left incomplete, as the report carries them.
type FindingsDoc struct {
	Header
	Refused    []ereport.Shortfall `json:"refused"`
	Incomplete []ereport.Shortfall `json:"incomplete"`
	Assets     []AssessedAsset     `json:"assets"`
	// Open counts open findings at or above their asset's threshold: the
	// number that makes the run exit 1.
	Open int `json:"open_at_or_above_threshold"`
	// AcceptancesNotApplied names each intent.accepted_risks entry the
	// host grader could not apply, and why.
	AcceptancesNotApplied []string `json:"acceptances_not_applied,omitempty"`
}

// AssessedAsset is Analyze's outcome for one asset.
type AssessedAsset struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Evidence is the host collector's envelope, relative to the run
	// directory.
	Evidence    string               `json:"evidence,omitempty"`
	Threshold   string               `json:"threshold,omitempty"`
	Open        int                  `json:"open_at_or_above_threshold"`
	Assessments []finding.Assessment `json:"assessments,omitempty"`
	Findings    []finding.Finding    `json:"findings,omitempty"`
}

// Outcome is how a run ended.
type Outcome struct {
	// Stage is the last stage run, and Document its output: the report
	// itself once Report ran.
	Stage    string
	Document any
	// Refused names each host that refused us (exit 3); the run went on
	// past them.
	Refused []ereport.Shortfall
	// Incomplete says why the run is incomplete (exit 2); empty when it
	// is not.
	Incomplete []ereport.Shortfall
	// Warnings are for the operator, on stderr.
	Warnings []string
	// Open counts the open findings at or above their asset's threshold
	// once Analyze ran (exit 1).
	Open int
	// Report is the engagement report once Analyze ran.
	Report *ereport.Report
}

// ExitCode is the run's exit code, in the precedence 3, 2, 1, 0
// (docs/spec/engagement.md, "Exit codes").
func (o *Outcome) ExitCode() int {
	switch {
	case o.Report != nil:
		return o.Report.Exit.Code
	case len(o.Refused) > 0:
		return 3
	case len(o.Incomplete) > 0:
		return 2
	case o.Open > 0:
		return 1
	}
	return 0
}

// Describe is a shortfall as one line for stderr: who, why and the detail.
func Describe(s ereport.Shortfall) string {
	out := s.AssetName + ": " + s.Reason
	if s.Reason == ReasonRefused {
		out = s.AssetName
	}
	if s.Detail != "" && s.Reason != ReasonCollectorNotBuilt {
		out += ": " + s.Detail
	}
	return out
}

// run is one run in progress.
type run struct {
	res    *Resolved
	o      RunOptions
	header func(stage string) Header
	// hosts holds each collected host asset by name.
	hosts map[string]*hostasset.Collection
	// notApplied names the accepted risks the host grader cannot apply.
	notApplied []string
	// traces holds each host asset's audit entries, by name.
	traces map[string][]policy.AuditEntry
	zone   *time.Location
	recon  *ReconDoc
	out    Outcome
	// auditFile is the run directory's audit.jsonl, or io.Discard.
	auditFile io.Writer
	// gate is the run's scope gate, built when something sends through
	// it.
	gate     *gate.Gate
	webScope *scope
	// scoped is what the Scope stage found; reconResolver what this
	// session's control lookup found of the resolver Recon reads through.
	scoped        *ScopeDoc
	reconResolver *Resolver
	// session is when this session started.
	session time.Time
	// manifest is run.json, nil under --no-persist.
	manifest *Manifest
	// edited are the files an earlier session wrote that the resume used
	// although they changed since.
	edited []string
	// graded is when each host's accepted risks were graded, by name.
	graded map[string]time.Time
	// kept names the hosts an earlier session collected, which this one
	// did not contact.
	kept map[string]bool
}

// Run runs the stages of a resolved engagement up to StopAfter, writing
// each stage's output into the run directory as it goes
// (docs/spec/engagement.md, "Stages", "Runs, state and configuration").
// It returns a *Refusal for exit 3 before any target is contacted; a host
// that refuses us later is recorded in Outcome.Refused and the run goes on.
// Any other error leaves the run incomplete.
func Run(ctx context.Context, res *Resolved, o RunOptions) (*Outcome, error) {
	stop := o.StopAfter
	if stop == "" {
		stop = LastStage
	}
	last := slices.Index(Stages, stop)
	if last < 0 || last > slices.Index(Stages, LastStage) {
		return nil, refuse("--stop-after must be one of %s", strings.Join(Stages, "|"))
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Collect == nil {
		o.Collect = hostasset.Collect
	}
	if o.Started.IsZero() {
		o.Started = time.Now()
	}
	if t := res.Timeout(); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	if err := Preflight(res, o.Dir != nil || last < slices.Index(Stages, "scope")); err != nil {
		return nil, err
	}
	r := &run{res: res, o: o, hosts: map[string]*hostasset.Collection{}, traces: map[string][]policy.AuditEntry{}, zone: time.UTC,
		auditFile: io.Discard, session: o.Session, graded: map[string]time.Time{}, kept: map[string]bool{}}
	if r.session.IsZero() {
		r.session = o.Started
		if o.Resume != nil {
			r.session = time.Now()
		}
	}
	if o.Dir != nil {
		if err := r.openManifest(); err != nil {
			return nil, err
		}
		// What this session sent is recorded once it ends, however it
		// ends, so a later session's report can count it.
		defer r.closeSession()
	}
	if o.Dir != nil && last >= slices.Index(Stages, "scope") {
		f, err := o.Dir.OpenAppend("audit.jsonl")
		if err != nil {
			return nil, fmt.Errorf("run directory: audit log: %w", err)
		}
		defer func() { _ = f.Close() }()
		r.auditFile = f
	}
	if z, err := time.LoadLocation(res.Engagement.Timezone); err == nil {
		r.zone = z
	}
	r.header = func(stage string) Header {
		return Header{Stage: stage, Engagement: res.Engagement.Name, Started: o.Started.UTC(), Source: res.Source}
	}
	steps := []func(context.Context) (any, error){r.intake, r.scope, r.reconStage, r.plan, r.check, r.analyze, r.reportStage}
	for i, step := range steps[:last+1] {
		doc, err := step(ctx)
		if err != nil {
			return nil, err
		}
		r.out.Stage, r.out.Document = Stages[i], doc
		if err := r.keepRequests(); err != nil {
			return nil, err
		}
		o.Log("stage %s done", Stages[i])
	}
	return &r.out, nil
}

// write stores a stage's file and records its hash in run.json, so a resume
// can tell the file was edited by hand.
func (r *run) write(name string, doc any) error {
	if r.o.Dir == nil {
		return nil
	}
	raw, ok := doc.([]byte)
	if !ok {
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return fmt.Errorf("run directory: %s: %w", name, err)
		}
		raw = append(b, '\n')
	}
	err := r.o.Dir.Write(name, raw)
	if err == nil {
		r.manifest.Files[name] = sha(raw)
		err = r.saveManifest()
	}
	if err != nil {
		return fmt.Errorf("run directory: %s: %w", name, err)
	}
	return nil
}

// Preflight refuses, before any target is contacted or any run directory
// created, a host asset this build cannot reach, and a run that would send
// through the gate without keeping its audit log (persist is false under
// --no-persist).
func Preflight(res *Resolved, persist bool) error {
	// The gate's audit log is the record of what was sent, and only a run
	// directory keeps it: a root or asset the gate would send for is
	// refused by its kind, whether or not its collector is built yet; a url
	// asset may sit under a host root (docs/spec/scope.md, "Audit").
	if !persist {
		kinds := make([]Kind, 0, len(res.Roots)+len(res.Assets))
		for _, root := range res.Roots {
			kinds = append(kinds, root.Kind)
		}
		for _, a := range res.Assets {
			kinds = append(kinds, a.Kind)
		}
		for _, k := range kinds {
			if k != KindHost {
				return refuse("--no-persist cannot be used when scheck sends network requests: the audit log is the " +
					"record of what was sent. Use --state-dir to keep the run somewhere disposable.")
			}
		}
	}
	for _, a := range res.Assets {
		if a.Kind != KindHost {
			continue
		}
		if !a.Local() && a.User == "" {
			return refuse("assets %s: %s has no SSH user: write it into the locator as user@%s", a.Name, a.ID, a.Address())
		}
		if j, ok := jumpOf(a); ok && j.User == "" {
			return refuse("assets %s: jump %s has no SSH user: write it as user@%s", a.Name, j.Host, j.Host)
		}
	}
	return nil
}

// intake keeps the file as read. Validation guarantees it holds no
// credential, but it holds the redact_extra patterns, which are often the
// very strings they hide: those are masked in the copy, and the header
// names the original by path and hash.
func (r *run) intake(context.Context) (any, error) {
	if r.o.Dir == nil {
		return r.res, nil
	}
	raw, err := maskRedactExtra(r.o.Raw, r.res)
	if err != nil {
		return nil, fmt.Errorf("engagement.yaml: %w", err)
	}
	return r.res, r.write("engagement.yaml", raw)
}

// maskRedactExtra returns raw with every redact_extra entry replaced by a
// marker and every remaining match of a pattern (in a comment, a name)
// redacted; the result is still a valid engagement file. A file with no
// redact_extra is returned as read.
func maskRedactExtra(raw []byte, res *Resolved) ([]byte, error) {
	patterns := res.RedactExtra()
	if len(patterns) == 0 {
		return raw, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, errors.New("the file as read is empty")
	}
	if root := doc.Content[0]; root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value != "redact_extra" {
				continue
			}
			for _, item := range root.Content[i+1].Content {
				item.Value = fmt.Sprintf("[REDACTED:redact_extra:%d bytes]", len(item.Value))
				item.Style = 0
			}
		}
	}
	var buf bytes.Buffer
	// The original's hash is in every stage document's source; written
	// here, 64 hex digits would read as a credential to the file's own
	// validation.
	fmt.Fprintf(&buf, "# %s, with its redact_extra masked; its sha256 is in each stage document's source.\n", res.Source.Path)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	red, err := policy.NewRedactor(patterns)
	if err != nil {
		return nil, errors.New("redact_extra: a pattern does not compile")
	}
	out, _ := red.Redact(buf.Bytes())
	return out, nil
}

// scope lists the declared roots and assets entries with their first-party
// evidence, and expands each domain root by passive discovery through the
// gate (docs/spec/scope.md, "Discovery"). It contacts no server of the
// company's: only crt.sh and the DNS resolver.
func (r *run) scope(ctx context.Context) (any, error) {
	// A resume keeps Scope's document while what Scope read from the file
	// is unchanged and it found no gap to close; the gate still decides
	// every request from the file (docs/spec/engagement.md, "Stop and
	// resume").
	inputs := scopeInputs(r.res, r.o.Version, r.session)
	if p := r.o.Resume; p != nil && p.Scope != nil && inputs != "" && inputs == p.Manifest.ScopeInputs && p.Scope.complete() {
		r.o.Log("scope: kept from an earlier session")
		r.used("scope.json")
		r.scoped = p.Scope
		return p.Scope, nil
	}
	if r.manifest != nil {
		r.manifest.ScopeInputs = inputs
	}
	doc := &ScopeDoc{Header: r.header("scope"), Roots: r.res.Roots, Exclude: r.res.Exclude,
		Discovery: "none: no domain root"}
	if doc.Exclude == nil {
		doc.Exclude = []Ref{}
	}
	for _, a := range r.res.Assets {
		sa := ScopeAsset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root, FirstParty: r.res.firstParty(a, r.session)}
		if a.Kind == KindHost {
			sa.Collector = "host"
		}
		doc.Assets = append(doc.Assets, sa)
	}
	if slices.ContainsFunc(r.res.Roots, func(x Ref) bool { return x.Kind == KindDomain }) {
		g, err := r.gateFor(ctx)
		if err != nil {
			return nil, err
		}
		d := &discovery{res: r.res, g: g, at: r.session, log: r.o.Log}
		doc.Domains, doc.Resolver, doc.PointsAt = d.run(ctx)
		doc.Discovery = "certificate transparency (crt.sh) and DNS"
	}
	if err := redactEvidence(doc, r.res.RedactExtra()); err != nil {
		return nil, err
	}
	r.scoped = doc
	return doc, r.write("scope.json", doc)
}

// redactEvidence redacts each confirmation's target in scope.json as the
// gate redacts the chain it is compared with: the gate compares the
// target as written, and only the document is redacted (AGENTS.md rule 5).
func redactEvidence(doc *ScopeDoc, extra []string) error {
	red, err := policy.NewRedactor(extra)
	if err != nil {
		return err
	}
	redact := func(ev *Evidence) {
		if ev != nil && ev.Target != "" {
			ev.Target, _ = red.RedactString(ev.Target)
		}
	}
	for i := range doc.Assets {
		redact(doc.Assets[i].FirstParty)
	}
	for i := range doc.Domains {
		for j := range doc.Domains[i].Names {
			redact(doc.Domains[i].Names[j].FirstParty)
		}
	}
	return nil
}

// defaultGate builds a run's gate when RunOptions.NewGate is nil; this
// package's tests replace it with one that reaches nothing.
var defaultGate = gate.New

// gateFor builds the run's gate on first use: the engagement file's scope
// measured at the run's start, its redact_extra, the run's audit log and
// the deadline limits.timeout put on ctx (docs/spec/scope.md, "The scope
// gate").
func (r *run) gateFor(ctx context.Context) (*gate.Gate, error) {
	if r.gate != nil {
		return r.gate, nil
	}
	reg, err := gate.NewRegistry(slices.Concat(discoveryOps, web.Ops)...)
	if err != nil {
		return nil, err
	}
	r.webScope = r.res.GateScope(r.session).(*scope)
	cfg := gate.Config{Registry: reg, Scope: r.webScope, RedactExtra: r.res.RedactExtra(),
		Audit: policy.NewAudit(r.auditFile), Version: r.o.Version, Session: 1}
	if p := r.o.Resume; p != nil {
		cfg.Prior, cfg.Session = p.Requests, len(r.manifest.Sessions)
	}
	if d, ok := ctx.Deadline(); ok {
		cfg.Deadline = d
	}
	if a := r.res.Authorization; a != nil {
		// Validation parsed every window, so neither time is zero.
		for _, w := range a.Windows {
			from, _ := time.Parse(time.RFC3339, w.From)
			to, _ := time.Parse(time.RFC3339, w.To)
			cfg.Windows = append(cfg.Windows, gate.Window{From: from, To: to})
		}
	}
	newGate := r.o.NewGate
	if newGate == nil {
		newGate = defaultGate
	}
	if r.gate, err = newGate(cfg); err != nil {
		return nil, err
	}
	for _, n := range r.gate.Notes() {
		r.o.Log("%s", n)
	}
	return r.gate, nil
}

// collectDomain reads a domain root through the gate with the web collector
// (docs/spec/web-collector.md, "Reads"): its mail domains' records, its NS,
// the names those records point at, and the names Scope chose to read; and
// judges them with its rules together with Scope's lookups.
func (r *run) collectDomain(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	if ctx.Err() != nil {
		ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
		ra.Detail = "limits.timeout ended the engagement before this asset was read"
		r.incomplete(a, ra)
		return ra
	}
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	r.o.Log("recon: %s (%s)", a.Name, a.ID)
	r.checkResolver(ctx, g, a)
	ev := web.Collect(ctx, g, r.webDomain(a))
	ra.Web = &ev
	ra.Judged = web.Judge(r.webInput(a, ev))
	r.suspendConfirmations(ra.Judged)
	ra.Status = StatusCollected
	if ctx.Err() != nil || ev.Cut() {
		ra.Status, ra.Reason = StatusIncomplete, ReasonLimitReached
		ra.Detail = fmt.Sprintf("limits.timeout (%s) ended the engagement while it was read", r.res.Limits.Timeout)
		r.incomplete(a, ra)
	}
	return ra
}

// webInput is what the web collector's rules judge under a domain root:
// the names Scope looked up, what it could not list, whether the resolver
// invents answers, and what Recon read.
func (r *run) webInput(a ResolvedAsset, ev web.Evidence) web.Input {
	in := web.Input{Asset: a.ID, Root: a.name, Evidence: ev}
	for _, m := range ev.Mail {
		context := web.MailContext{Domain: m.Domain}
		for _, sender := range r.res.Mail.Senders {
			if strings.TrimSuffix(strings.ToLower(sender.Domain), ".") != m.Domain {
				continue
			}
			selectors := []string{}
			for _, sel := range sender.DKIMSelectors {
				selectors = append(selectors, strings.ToLower(sel))
			}
			context.Senders = append(context.Senders, web.MailSender{Service: sender.Service, Selectors: selectors})
		}
		for _, domain := range r.res.Mail.NoMail {
			if strings.TrimSuffix(strings.ToLower(domain), ".") == m.Domain {
				context.NoMail = true
			}
		}
		in.MailContext = append(in.MailContext, context)
	}
	if r.recon != nil {
		for _, ra := range r.recon.Assets {
			if ra.Web != nil && ra.ID != a.ID {
				in.MailPolicies = append(in.MailPolicies, ra.Web.Mail...)
			}
		}
	}
	if r.scoped == nil {
		in.Gaps = append(in.Gaps, web.Gap{Reason: "unavailable:not_listed", Detail: "Scope did not run"})
		return in
	}
	// Scope's names were answered by the resolver Scope asked, Recon's
	// reads by this session's: each must be known not to invent answers
	// (a resumed session may be on another network).
	in.Doubt = cmp.Or(resolverDoubt(r.scoped.Resolver), resolverDoubt(r.reconResolver))
	for _, sd := range r.scoped.Domains {
		if sd.Root != a.ID {
			continue
		}
		if sd.Control != nil {
			n := webName(*sd.Control)
			in.Wildcard = &n
		}
		if sd.CT != "ok" {
			in.Gaps = append(in.Gaps, web.Gap{Reason: "unavailable:ct_source", Detail: "certificate transparency did not answer"})
		}
		for _, d := range sd.Dropped {
			// An excluded name or a non-name was never part of the root's
			// names; anything else dropped hides names.
			if !strings.HasPrefix(d.Rule, "exclude[") && d.Rule != "not_a_name" {
				in.Gaps = append(in.Gaps, web.Gap{Reason: "unavailable:" + d.Rule, Detail: fmt.Sprintf("%d dropped (%s)", d.Count, d.Rule)})
			}
		}
		for _, sn := range sd.Names {
			// A name under a more specific domain root is that root's.
			if r.innerRoot(a, sn.Name) {
				continue
			}
			in.Names = append(in.Names, webName(sn))
		}
	}
	return in
}

// resolverDoubt is why no answer of a resolver stands, "" when it is known
// not to invent them.
func resolverDoubt(res *Resolver) string {
	switch {
	case res == nil:
		return "unavailable:resolver_unchecked"
	case res.Rewrites:
		return "unavailable:resolver_rewrites"
	case !res.Known():
		return "unavailable:resolver_unchecked"
	}
	return ""
}

// checkResolver sends this session's control lookup under invalid., once,
// before Recon reads any domain root through the gate's resolver.
func (r *run) checkResolver(ctx context.Context, g *gate.Gate, a ResolvedAsset) {
	if r.reconResolver != nil {
		return
	}
	ctl := g.Resolve(ctx, gate.Resolve{Asset: a.ID, Name: randomLabel() + ".invalid", Stage: "recon", Control: true})
	r.reconResolver = &Resolver{Address: g.Resolver(), Rewrites: ctl.Lookup.Outcome == gate.OutcomeAddresses,
		Control: string(ctl.Lookup.Outcome)}
	if ctl.Decision != gate.DecisionSent {
		r.reconResolver.Control = ctl.Decision
	}
}

// innerRoot reports a name under a domain root more specific than a.
func (r *run) innerRoot(a ResolvedAsset, name string) bool {
	return slices.ContainsFunc(r.res.Roots, func(o Ref) bool {
		return o.Kind == KindDomain && o.name != a.name && domainUnder(o.name, a.name) && domainUnder(name, o.name)
	})
}

// webDomain is what the web collector reads under a domain root: the mail
// domains under it, the root first, with the DKIM selectors declared for
// each, and the names Scope chose to read.
func (r *run) webDomain(a ResolvedAsset) web.Domain {
	d := web.Domain{Asset: a.ID, Name: a.name, Stage: "recon"}
	selectors := map[string][]string{}
	order := []string{a.name}
	// A mail domain is read under the most specific root holding it, once.
	add := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if domainUnder(name, a.name) && !r.innerRoot(a, name) && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	for _, s := range r.res.Mail.Senders {
		add(s.Domain)
		dom := strings.TrimSuffix(strings.ToLower(s.Domain), ".")
		for _, sel := range s.DKIMSelectors {
			if sel = strings.ToLower(sel); !slices.Contains(selectors[dom], sel) {
				selectors[dom] = append(selectors[dom], sel)
			}
		}
	}
	for _, n := range r.res.Mail.NoMail {
		add(n)
	}
	for _, name := range order {
		d.Mail = append(d.Mail, web.MailDomain{Name: name, Selectors: selectors[name]})
	}
	if r.scoped != nil {
		for _, sd := range r.scoped.Domains {
			if sd.Root != a.ID {
				continue
			}
			if sd.Control != nil && resolverDoubt(r.scoped.Resolver) == "" && resolverDoubt(r.reconResolver) == "" &&
				web.NeedsWildcardPage(webName(*sd.Control)) {
				d.Names = append(d.Names, sd.Control.Name)
			}
			for _, sn := range sd.Names {
				if sn.Read && !r.innerRoot(a, sn.Name) {
					d.Names = append(d.Names, sn.Name)
				}
			}
		}
	}
	return d
}

// reconStage runs every declared read per asset: the host collector on
// host assets and the web collector on domain roots. A root of a kind with
// no collector yet is recorded as not collected and makes the run
// incomplete.
func (r *run) reconStage(ctx context.Context) (any, error) {
	doc := &ReconDoc{Header: r.header("recon")}
	// What the session reached is on record as each host ends, so a stage
	// error after one still counts its contact when the session closes.
	r.recon = doc
	// Every asset's commands go to audit.jsonl and are also kept per asset,
	// so the report carries each asset's trace even under --no-persist
	// (docs/spec/engagement.md, "Text and JSON").
	isRoot := func(a ResolvedAsset) bool { return a.Root == a.ID }
	// A transport error quotes what the target or a resolver said (an
	// address a name resolved to, a jump host's refusal): redacted before
	// it is stored or printed (AGENTS.md rule 5).
	red, err := policy.NewRedactor(r.res.RedactExtra())
	if err != nil {
		return nil, err
	}
	for _, a := range r.res.Assets {
		ra := ReconAsset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root}
		switch {
		case a.Kind == KindDomain && isRoot(a):
			ra = r.collectDomain(ctx, a, ra)
		case a.Kind != KindHost:
			ra.Status, ra.Reason = StatusNotCollected, ReasonCollectorNotBuilt
			ra.Detail = "no collector reads " + string(a.Kind) + " assets in this build"
			if isRoot(a) {
				r.incomplete(a, ra)
			}
		default:
			var trace bytes.Buffer
			audit := policy.NewAudit(io.MultiWriter(&trace, r.auditFile))
			opts := r.hostOptions(a, audit)
			inputs := hostInputs(opts, r.res.Exclude, r.o.Version)
			if kept, ok := r.keptHost(a, inputs); ok {
				ra = kept
				break
			}
			if ctx.Err() != nil {
				ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
				ra.Detail = "limits.timeout ended the engagement before this asset was read"
				r.incomplete(a, ra)
				break
			}
			r.o.Log("recon: %s (%s)", a.Name, a.ID)
			var reach hostasset.Reach
			opts.Reach = &reach
			c, err := r.o.Collect(ctx, opts)
			r.traces[a.Name] = readTrace(&trace)
			ra.ResolvedHere, ra.ResolvedByJump = reach.Resolved, reach.ByJump
			ra.Contact, ra.JumpContact = contact(reach.Dialled, reach.Connected), contact(reach.JumpDialled, reach.JumpConnected)
			if err != nil {
				he, ok := errors.AsType[*hostasset.Error](err)
				detail, _ := red.RedactString(err.Error())
				switch {
				case !ok:
					doc.Assets = append(doc.Assets, ra)
					return nil, err
				case ctx.Err() != nil:
					// limits.timeout ended the engagement while this host
					// was reached: whatever the error says, the cause is
					// the limit, never a refusal.
					ra.Status, ra.Reason, ra.Detail = StatusNotCollected, ReasonLimitReached,
						"limits.timeout ended the engagement while it was reached: "+detail
					r.incomplete(a, ra)
				case he.Usage:
					// Refused on the positive list: the host is not
					// reached, the others still are, and the run exits 3
					// with what it collected written.
					ra.Status, ra.Reason, ra.Detail, ra.Echo, ra.Refusal = StatusRefused, ReasonRefused, detail, he.Echo, he.Kind
					r.out.Refused = append(r.out.Refused, ereport.Shortfall{Asset: a.ID, AssetName: a.Name,
						Reason: ReasonRefused, Detail: ra.Detail, Echo: ra.Echo, Kind: ra.Refusal})
				default:
					ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, detail
					r.incomplete(a, ra)
				}
				break
			}
			r.hosts[a.Name] = c
			env := c.Envelope()
			ra.Status = StatusCollected
			if !c.Complete() {
				// Say which limit cut it: a lost session, the engagement's
				// limits.timeout, or the host collector's own run timeout
				// (docs/spec/engagement.md, "Incompleteness and refusals").
				ra.Status, ra.Reason = StatusIncomplete, ReasonLimitReached
				switch {
				case c.Lost() != "":
					ra.Reason, ra.Detail = ReasonFailed, strings.Join(env.Run.Warnings, "; ")
				case ctx.Err() != nil:
					ra.Detail = fmt.Sprintf("limits.timeout (%s) ended the engagement while it was read", r.res.Limits.Timeout)
				default:
					ra.Detail = "the host collector's timeout (" + hostTimeout(a) + ") stopped it"
				}
				r.incomplete(a, ra)
			}
			ra.Host, ra.Facts, ra.Observations = &env.Host, env.Facts, env.Observations
			r.graded[a.Name] = r.session
			if err := r.recordHost(a, c, inputs, ra); err != nil {
				doc.Assets = append(doc.Assets, ra)
				return nil, err
			}
		}
		doc.Assets = append(doc.Assets, ra)
	}
	// Judge again after all roots are read so inherited mail policy can use
	// already-collected organizational evidence regardless of root order.
	// No new request is made (docs/spec/web-collector.md, "Email").
	for i, ra := range doc.Assets {
		if ra.Web == nil {
			continue
		}
		for _, a := range r.res.Assets {
			if a.ID == ra.ID {
				doc.Assets[i].Judged = web.Judge(r.webInput(a, *ra.Web))
				break
			}
		}
	}
	// A declared domain under a root the web collector read was read with
	// it: its names were among the root's.
	for i, ra := range doc.Assets {
		if ra.Kind != KindDomain || ra.Root == ra.ID {
			continue
		}
		for _, root := range doc.Assets {
			if root.ID == ra.Root && root.Web != nil {
				doc.Assets[i].Status, doc.Assets[i].Reason = root.Status, root.Reason
				doc.Assets[i].Detail = "read with " + root.Name
			}
		}
	}
	if r.scoped != nil {
		if err := r.write("scope.json", r.scoped); err != nil {
			return nil, err
		}
	}
	return doc, r.write("recon.json", doc)
}

// jumpOf is a host asset's jump host, parsed (validated at load).
func jumpOf(a ResolvedAsset) (hostasset.Hop, bool) {
	if a.Jump == "" {
		return hostasset.Hop{}, false
	}
	j, err := parseLocator(KindHost, a.Jump)
	if err != nil {
		return hostasset.Hop{}, false
	}
	return hostasset.Hop{User: j.User, Host: j.Address(), Port: j.Port}, true
}

// hostTimeout names a host's run timeout and where it was set.
func hostTimeout(a ResolvedAsset) string {
	if a.Timeout != "" {
		return a.Timeout + ", assets." + a.Name + ".timeout"
	}
	return policy.DefaultBudgets().RunTimeout.String() + ", the default"
}

func (r *run) incomplete(a ResolvedAsset, ra ReconAsset) {
	r.out.Incomplete = append(r.out.Incomplete, ereport.Shortfall{Asset: a.ID, AssetName: a.Name, Reason: ra.Reason, Detail: ra.Detail})
}

// readTrace reads back the audit entries one asset's collection wrote.
func readTrace(buf *bytes.Buffer) []policy.AuditEntry {
	var out []policy.AuditEntry
	sc := bufio.NewScanner(buf)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e policy.AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// hostOptions is everything the host collector receives for an asset: its
// reach, profile, elevation, narrowing and context, and the engagement's
// redact_extra. Nothing else reaches it.
func (r *run) hostOptions(a ResolvedAsset, audit *policy.Audit) hostasset.Options {
	o := hostasset.Options{
		Local: a.Local(), Host: a.Address(), Port: a.Port, User: a.User, Identity: a.Identity,
		KnownHosts: a.KnownHosts, Elevate: a.Elevate, Profile: a.Profile,
		DisableChecks: a.DisableChecks, DenyPaths: a.DenyPaths, RedactExtra: r.res.RedactExtra(),
		Audit: audit, Version: r.o.Version, Now: r.session, RecordFixtures: r.o.RecordFixtures,
		ContextSource: r.res.Source.Path + " assets." + a.Name,
		Log:           func(f string, args ...any) { r.o.Log(a.Name+": "+f, args...) },
	}
	o.RunTimeout, _ = time.ParseDuration(a.Timeout) // validated; "" keeps the default
	o.Allow = r.res.allowAddress
	if j, ok := jumpOf(a); ok {
		o.Jump = &j
	}
	o.Context = r.hostContext(a)
	return o
}

// hostContext is the asset's context and the accepted risks that name it,
// in the host collector's shape (docs/spec/host-collector.md §5.2), each
// risk attributed to its own entry, a later entry for the same id winning.
// An acceptance with a subject is not passed: the host grader accepts a
// whole finding id, and a narrower acceptance must not widen into that.
// When host findings carry instance keys it becomes applicable; until then
// it is named in findings.json and on stderr, never dropped silently.
func (r *run) hostContext(a ResolvedAsset) *operator.Structured {
	var s operator.Structured
	if c := a.Context; c != nil {
		s.Role, s.Exposure, s.Environment = c.Role, c.Exposure, c.Environment
		for _, svc := range c.ExpectedServices {
			s.ExpectedServices = append(s.ExpectedServices, operator.Service{Port: svc.Port, Proto: svc.Proto,
				Purpose: svc.Purpose, Audience: svc.Audience})
		}
	}
	for i, risk := range r.res.Intent.AcceptedRisks {
		id, ok := r.res.AssetID(risk.Asset)
		if !ok || id != a.ID || strings.HasPrefix(risk.ID, "custom:") {
			continue
		}
		key := fmt.Sprintf("intent.accepted_risks[%d]", i)
		if risk.Subject != "" {
			r.notApplied = append(r.notApplied, fmt.Sprintf("%s (%s on %s, subject %s) not applied: host findings carry no instance key in this build, and accepting the whole id would widen it",
				key, risk.ID, a.Name, risk.Subject))
			continue
		}
		s.AcceptedRisks = slices.DeleteFunc(s.AcceptedRisks, func(have operator.Risk) bool { return have.ID == risk.ID })
		s.AcceptedRisks = append(s.AcceptedRisks, operator.Risk{ID: risk.ID, Reason: risk.Reason, Expires: risk.Expires,
			Source: r.res.Source.Path + " " + key, Zone: r.zone})
	}
	if s.IsZero() {
		return nil
	}
	return &s
}

// plan passes through empty until 0.0.2 E9: the posture rules that apply to
// a host are its catalog's, and nothing narrows or orders them yet.
func (r *run) plan(context.Context) (any, error) {
	doc := &PlanDoc{Header: r.header("plan"), Method: "rules only; the plan is a checklist", Checklist: []string{}, Hosts: []PlanHost{}}
	for _, a := range r.res.Assets {
		c, ok := r.hosts[a.Name]
		if !ok {
			continue
		}
		disabled := a.DisableChecks
		if disabled == nil {
			disabled = []string{}
		}
		doc.Hosts = append(doc.Hosts, PlanHost{Name: a.Name, ID: a.ID, Planned: c.Planned(), Disabled: disabled})
	}
	return doc, r.write("plan.json", doc)
}

// check runs the follow-ups rules named: none until 0.0.2 E9.
func (r *run) check(context.Context) (any, error) {
	return &CheckDoc{Header: r.header("check"), FollowUps: []string{}}, nil
}

// analyze reads each host asset's posture rules over its facts, from the
// host collector's envelope Recon wrote under evidence/
// (docs/spec/engagement.md, "Runs, state and configuration"), and builds
// the report from them.
func (r *run) analyze(context.Context) (any, error) {
	doc := &FindingsDoc{Header: r.header("analyze")}
	evidence := map[string]string{}
	for _, ra := range r.recon.Assets {
		aa := AssessedAsset{Name: ra.Name, ID: ra.ID, Status: ra.Status, Reason: ra.Reason}
		if c, ok := r.hosts[ra.Name]; ok {
			env := c.Envelope()
			aa.Threshold = string(c.Threshold())
			aa.Assessments, aa.Findings = env.Assessments, env.Findings
			if r.o.Dir != nil {
				// Recon wrote it, or an earlier session did for a kept host.
				aa.Evidence = "evidence/" + fileName(ra.Name) + ".json"
				evidence[ra.Name] = aa.Evidence
			}
		}
		doc.Assets = append(doc.Assets, aa)
	}
	r.out.Report = ereport.Build(r.reportInput(evidence))
	doc.Refused, doc.Incomplete = r.out.Report.Refused, r.out.Report.Incomplete
	// The counts are the report's, so findings.json, the report and the
	// exit code agree per asset and in total.
	for i := range doc.Assets {
		doc.Assets[i].Open = 0
	}
	for _, f := range r.out.Report.Findings {
		if th, ok := r.out.Report.Exit.Thresholds[f.Key.Asset]; ok && f.Status == finding.StatusOpen &&
			finding.Severity(f.Severity).AtLeast(finding.Severity(th.Severity)) {
			doc.Open++
			for i := range doc.Assets {
				if doc.Assets[i].ID == f.Key.Asset {
					doc.Assets[i].Open++
				}
			}
		}
	}
	r.out.Open = doc.Open
	doc.AcceptancesNotApplied = r.notApplied
	r.out.Warnings = append(r.out.Warnings, r.notApplied...)
	return doc, r.write("findings.json", doc)
}

// reportStage writes the engagement report, JSON and text; the text is
// always at default verbosity (docs/spec/engagement.md, "What never
// appears").
func (r *run) reportStage(context.Context) (any, error) {
	if r.o.Dir == nil {
		return r.out.Report, nil
	}
	var js, txt bytes.Buffer
	if err := ereport.WriteJSON(&js, r.out.Report, false); err != nil {
		return nil, err
	}
	if err := ereport.WriteText(&txt, r.out.Report, ereport.Options{}); err != nil {
		return nil, err
	}
	if err := r.write("report.json", js.Bytes()); err != nil {
		return nil, err
	}
	return r.out.Report, r.write("report.txt", txt.Bytes())
}

// reportInput is everything the report reads, in its own terms: the
// engagement as resolved and what each asset's collection produced.
func (r *run) reportInput(evidence map[string]string) ereport.Input {
	res := r.res
	in := ereport.Input{
		Version: r.o.Version, Name: res.Engagement.Name, Operator: res.Engagement.Operator,
		Trigger: res.Engagement.Trigger, Zone: r.zone, FromHost: res.fromHost,
		Path: res.Source.Path, SHA256: res.Source.SHA256, Started: r.o.Started, Finished: time.Now(),
		NotUsed: res.NotUsed, People: len(res.People) > 0, RedactExtra: res.RedactPatterns,
	}
	// A resume names the file by the absolute path it read: the path the
	// first session typed is relative to that session's directory. A path
	// that starts with "-" would read as a flag.
	file := res.Source.Path
	if r.o.Resume != nil && r.manifest != nil && r.manifest.File != "" {
		file = r.manifest.File
	}
	if strings.HasPrefix(file, "-") {
		file = "./" + file
	}
	in.Rerun = "scheck run " + file
	if in.FromHost {
		// --host writes a trigger only so the file it builds validates; the
		// operator declared none.
		in.Path, in.Trigger = "", ""
		in.Rerun = "scheck run --host " + r.hostLocator() + " (with the same flags)"
	}
	if r.o.Dir != nil {
		in.Directory = r.o.Dir.Path
	}
	in.Resumed, in.EditedByHand = r.o.Resume != nil, slices.Clone(r.edited)
	if a := res.Authorization; a != nil {
		auth := &ereport.Authorization{By: a.By, Date: a.Date, Source: a.Source, Note: a.Note}
		for _, w := range a.Windows {
			from, _ := time.Parse(time.RFC3339, w.From)
			to, _ := time.Parse(time.RFC3339, w.To)
			auth.Windows = append(auth.Windows, ereport.Span{From: from, To: to})
		}
		in.Authorization = auth
	}
	for _, ra := range r.recon.Assets {
		asset, _ := r.asset(ra.Name)
		ai := ereport.AssetInput{Name: ra.Name, ID: ra.ID, Kind: string(ra.Kind), Root: ra.Root == ra.ID, Profile: asset.Profile,
			Status: ra.Status, Reason: ra.Reason, Detail: ra.Detail, Echo: ra.Echo, Refusal: ra.Refusal,
			Contact: ra.Contact, JumpContact: ra.JumpContact, Trace: r.traces[ra.Name], Kept: r.kept[ra.Name]}
		if j, ok := jumpOf(asset); ok {
			ai.Via = j.String()
		}
		if c, ok := r.hosts[ra.Name]; ok {
			ai.Host = r.hostInput(asset, c, evidence[ra.Name])
			ai.Host.Graded = r.graded[ra.Name]
		}
		if ra.Kind == KindDomain && ra.Web == nil && strings.HasPrefix(ra.Detail, "read with ") {
			ai.ReadWith = ra.Root
		}
		if ra.Web != nil {
			ai.Collector = "web"
			wi := r.webInput(asset, *ra.Web)
			ai.Unfingerprinted = web.Unfingerprinted(wi)
			for _, n := range web.MailNotes(wi) {
				ai.MailNotes = append(ai.MailNotes, ereport.Note{Kind: "mail_context", Source: n.Domain, Detail: n.Detail})
			}
			for _, j := range ra.Judged {
				ai.Judged = append(ai.Judged, ereport.Judgment{ID: j.ID, Asset: j.Asset, Verdict: j.Verdict, Reason: j.Reason,
					Reads: j.Reads, Excerpt: j.Excerpt, NotChecked: j.NotChecked, Context: j.Context,
					Subject: ereport.Subject{Kind: j.Subject.Kind, Key: j.Subject.Key, Label: j.Subject.Label}})
			}
		}
		in.Assets = append(in.Assets, ai)
	}
	for i, t := range res.Tools {
		if r.toolIsRoot(t.Name) {
			continue
		}
		in.OtherTools = append(in.OtherTools, t.Name)
		// A tool in an area's category with no root of its own
		// half-declares that area: its row is kept, never folded
		// (docs/spec/engagement.md, "The fold line").
		if area, ok := toolAreas[t.Category]; ok {
			in.Declarations = append(in.Declarations, ereport.Declaration{Area: area,
				Source: fmt.Sprintf("%s tools[%d]", res.Source.Path, i),
				Detail: t.Name + " is declared under tools, but no root names it, so it was not read"})
		}
	}
	for i, b := range res.Data.Backups {
		detail := "backups declared in " + b.Where
		if b.Account != "" {
			detail += " (" + b.Account + ")"
		}
		in.Declarations = append(in.Declarations, ereport.Declaration{Area: "data",
			Source: fmt.Sprintf("%s data.backups[%d]", res.Source.Path, i), Detail: detail + ", not verified"})
	}
	for i, st := range res.Secrets.Production {
		in.Declarations = append(in.Declarations, ereport.Declaration{Area: "secrets",
			Source: fmt.Sprintf("%s secrets.production[%d]", res.Source.Path, i),
			Detail: "production secrets declared in " + st.Store + " on " + st.Asset + ", not read"})
	}
	for _, d := range res.Data.MattersMost {
		if id, ok := res.AssetID(d.Asset); ok {
			in.DataMattersMost = append(in.DataMattersMost, id)
		}
	}
	for i, risk := range res.Intent.AcceptedRisks {
		id, _ := res.AssetID(risk.Asset)
		in.Acceptances = append(in.Acceptances, ereport.AcceptanceInput{
			Entry: fmt.Sprintf("%s intent.accepted_risks[%d]", res.Source.Path, i), ID: risk.ID,
			Asset: risk.Asset, AssetID: id, Subject: risk.Subject, Reason: risk.Reason,
			AcceptedBy: risk.AcceptedBy, Expires: risk.Expires})
	}
	for _, x := range res.Exclude {
		in.Excludes = append(in.Excludes, x.ID)
	}
	if r.scoped != nil && len(r.scoped.Domains) > 0 {
		in.ExcludeMatches = r.excludeMatches()
	}
	in.Egress = r.egress()
	handles := make([]string, 0, len(res.People))
	for h, p := range res.People {
		if p.Kind == "employee" && p.Left == "" {
			handles = append(handles, h)
		}
	}
	sort.Strings(handles)
	for _, h := range handles {
		in.Candidates = append(in.Candidates, ereport.Candidate{Handle: h, Why: "employee"})
	}
	return in
}

// excludeMatches counts, by exclude, the names discovery dropped for it:
// from certificate transparency, and names it or whose chain it covered.
func (r *run) excludeMatches() map[string]int {
	out := map[string]int{}
	for i, x := range r.res.Exclude {
		entry := excludeEntry(i)
		n := 0
		for _, d := range r.scoped.Domains {
			for _, dr := range d.Dropped {
				if dr.Rule == entry {
					n += dr.Count
				}
			}
			for _, name := range d.Names {
				if name.ExcludedBy == entry {
					n++
				}
			}
		}
		out[x.ID] += n
	}
	return out
}

// egress is what left this machine through the gate and the host
// collector (docs/spec/engagement.md, "What left this machine"), in this
// session and every earlier one of the run, an earlier one that did not
// end named as unrecorded.
func (r *run) egress() *ereport.EgressInput {
	e := r.sessionEgress()
	// The report counts this session's contacts from the assets.
	e.Contacts = nil
	if r.manifest != nil {
		for _, sess := range r.manifest.Sessions[:len(r.manifest.Sessions)-1] {
			mergeEgress(e, sess.Egress)
			if !sess.Ended {
				e.Unrecorded = append(e.Unrecorded, sess.Started)
			}
		}
	}
	return e
}

// sessionEgress is what this session sent.
func (r *run) sessionEgress() *ereport.EgressInput {
	e := &ereport.EgressInput{UserAgent: gate.UserAgent(r.o.Version)}
	if r.gate != nil {
		uses, sites := r.gate.Egress()
		for _, u := range uses {
			e.Sources = append(e.Sources, ereport.SourceInput{Source: u.Source, Operator: u.Operator, Host: u.Host,
				Sent: u.Subjects, Requests: u.Requests, Credentials: u.Credentials, RootControls: u.RootControls,
				InvalidControl: u.InvalidControl, ScopedResolversIgnored: u.ScopedResolversIgnored})
		}
		byName := map[string]int{}
		for _, st := range sites {
			i, ok := byName[st.Name]
			if !ok {
				i = len(e.Sites)
				byName[st.Name] = i
				e.Sites = append(e.Sites, ereport.SiteInput{Name: st.Name})
			}
			e.Sites[i].Requests += st.Requests
			e.Sites[i].FirstParty = e.Sites[i].FirstParty || st.FirstParty
		}
	}
	// The names SSH resolved, as the transport recorded them: a host's
	// own or its jump host's here, a host's behind a jump host there.
	if r.recon != nil {
		for _, ra := range r.recon.Assets {
			if r.kept[ra.Name] {
				// An earlier session reached it, and recorded so.
				continue
			}
			if ra.Kind == KindHost {
				hc := ereport.HostContact{ID: ra.ID, Status: ra.Status, Contact: ra.Contact, JumpContact: ra.JumpContact,
					SideEffects: ereport.SideEffects(ra.Observations)}
				if a, ok := r.asset(ra.Name); ok {
					if j, ok := jumpOf(a); ok {
						hc.Via = j.String()
					}
				}
				e.Contacts = append(e.Contacts, hc)
			}
			e.SSHResolved = append(e.SSHResolved, ra.ResolvedHere...)
			if ra.ResolvedByJump != "" {
				e.SSHResolvedByJump = append(e.SSHResolvedByJump, ra.ResolvedByJump)
			}
		}
	}
	for _, l := range []*[]string{&e.SSHResolved, &e.SSHResolvedByJump} {
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
	return e
}

// hostLocator is the --host locator of a one-host engagement, as a rerun
// command names it.
func (r *run) hostLocator() string {
	for _, a := range r.res.Assets {
		if a.Kind != KindHost {
			continue
		}
		if a.Local() {
			return "local"
		}
		loc := a.Address()
		if strings.Contains(loc, ":") {
			loc = "[" + loc + "]"
		}
		if a.User != "" {
			loc = a.User + "@" + loc
		}
		if a.Port != 0 && a.Port != 22 {
			loc += ":" + strconv.Itoa(a.Port)
		}
		return loc
	}
	return ""
}

// hostInput is a collected host asset as the report reads it.
func (r *run) hostInput(a ResolvedAsset, c *hostasset.Collection, evidence string) *ereport.HostInput {
	src := r.res.Source.Path + " assets." + a.Name
	h := &ereport.HostInput{Envelope: c.Envelope(), User: a.User, Planned: c.Planned(), Lost: c.Lost(),
		Evidence: evidence}
	if a.Local() {
		h.User = "the user running scheck"
		if u, err := user.Current(); err == nil && u.Username != "" {
			h.User = u.Username
		}
	}
	for i, id := range a.DisableChecks {
		h.Disabled = append(h.Disabled, ereport.Entry{Value: id, Source: fmt.Sprintf("%s.disable_checks[%d]", src, i)})
	}
	for i, p := range a.DenyPaths {
		h.DenyPaths = append(h.DenyPaths, ereport.Entry{Value: p, Source: fmt.Sprintf("%s.deny_paths[%d]", src, i)})
	}
	if a.Context != nil && len(a.Context.ExpectedServices) > 0 {
		h.ExpectedServices = len(a.Context.ExpectedServices)
		h.ExpectedSource = src + ".context.expected_services"
	}
	return h
}

func (r *run) asset(name string) (ResolvedAsset, bool) {
	for _, a := range r.res.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return ResolvedAsset{}, false
}

// toolAreas maps a tool's declared category to the area its collector
// would read.
var toolAreas = map[string]string{
	"identity": "identity", "idp": "identity", "code": "cicd", "ci": "cicd", "cloud": "cloud",
	"email": "email", "dns": "email", "logging": "logging", "monitoring": "logging",
}

// toolIsRoot reports whether a declared tool is also a declared root (a
// google-workspace tool and its tenant), so it gets no row of its own.
func (r *run) toolIsRoot(tool string) bool {
	return slices.ContainsFunc(r.res.Roots, func(root Ref) bool { return strings.HasPrefix(root.ID, "saas:"+tool+":") })
}

// fileName makes an asset name, which may be a canonical id, safe as a file
// name.
func fileName(name string) string {
	return strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			return c
		}
		return '_'
	}, name)
}

func webName(sn ScopeName) web.Name {
	return web.Name{Name: sn.Name, Status: sn.Status, Detail: sn.Detail, Outcome: sn.Outcome,
		Chain: sn.Chain, Addresses: sn.Addresses, FinalInRoot: sn.FinalInRoot, Request: sn.RequestID}
}

// Positive fingerprints narrow the live scope and mark the persisted
// confirmation as suspended (docs/spec/web-collector.md, "Never claim a name").
func (r *run) suspendConfirmations(judged []web.Judgment) {
	for _, j := range judged {
		if j.Verdict != web.Fired || (j.ID != finding.IDDNSTakeoverCandidate && j.ID != finding.IDDNSUnclaimedAtProvider) {
			continue
		}
		names := append([]string{j.Subject.Key}, j.Members...)
		for _, name := range names {
			if strings.HasPrefix(name, "*.") {
				continue
			}
			if r.webScope != nil {
				r.webScope.suspended.Store(name, true)
			}
			if r.scoped == nil {
				continue
			}
			suspend := func(e *Evidence) {
				if e != nil && e.Kind == "operator" {
					e.Kind = "suspended"
				}
			}
			for i := range r.scoped.Assets {
				a := &r.scoped.Assets[i]
				if ref, ok := parseSubject(a.ID); ok && ref.name == name {
					suspend(a.FirstParty)
				}
			}
			for i := range r.scoped.Domains {
				for k := range r.scoped.Domains[i].Names {
					n := &r.scoped.Domains[i].Names[k]
					if n.Name == name {
						suspend(n.FirstParty)
					}
				}
			}
		}
	}
}
