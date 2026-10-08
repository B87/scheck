package engagement

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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

// ScopeDoc is scope.json: until 0.0.2 E4, the declared roots as written,
// without discovery.
type ScopeDoc struct {
	Header
	Discovery string       `json:"discovery"`
	Roots     []Ref        `json:"roots"`
	Exclude   []Ref        `json:"exclude"`
	Assets    []ScopeAsset `json:"assets"`
}

// ScopeAsset is one asset in scope and the collector that will read it.
type ScopeAsset struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	Root string `json:"root"`
	// Collector is "host", or empty when no collector reads the kind yet.
	Collector string `json:"collector,omitempty"`
}

// ReconDoc is recon.json, the asset map.
type ReconDoc struct {
	Header
	Assets []ReconAsset `json:"assets"`
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
	// Host, Facts and Observations are the host collector's
	// (docs/spec/host-collector.md §6.4), post-redaction.
	Host         *report.Host                  `json:"host,omitempty"`
	Facts        map[string]report.Fact        `json:"facts,omitempty"`
	Observations map[string]report.Observation `json:"observations,omitempty"`
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
	if err := Preflight(res); err != nil {
		return nil, err
	}
	r := &run{res: res, o: o, hosts: map[string]*hostasset.Collection{}, traces: map[string][]policy.AuditEntry{}, zone: time.UTC}
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
		o.Log("stage %s done", Stages[i])
	}
	return &r.out, nil
}

func (r *run) write(name string, doc any) error {
	if r.o.Dir == nil {
		return nil
	}
	var err error
	if raw, ok := doc.([]byte); ok {
		err = r.o.Dir.Write(name, raw)
	} else {
		err = r.o.Dir.WriteJSON(name, doc)
	}
	if err != nil {
		return fmt.Errorf("run directory: %s: %w", name, err)
	}
	return nil
}

// Preflight refuses, before any target is contacted or any run directory
// created, a host asset this build cannot reach.
func Preflight(res *Resolved) error {
	for _, a := range res.Assets {
		if a.Kind != KindHost {
			continue
		}
		if a.Jump != "" {
			return refuse("assets %s: jump: not available in this build (0.0.2 E1c)", a.Name)
		}
		if !a.Local() && a.User == "" {
			return refuse("assets %s: %s has no SSH user: write it into the locator as user@%s", a.Name, a.ID, a.Address())
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

// scope resolves the roots as written (discovery arrives in 0.0.2 E4).
func (r *run) scope(context.Context) (any, error) {
	doc := &ScopeDoc{Header: r.header("scope"), Roots: r.res.Roots, Exclude: r.res.Exclude,
		Discovery: "none: the roots as written; discovery arrives in 0.0.2 E4"}
	if doc.Exclude == nil {
		doc.Exclude = []Ref{}
	}
	for _, a := range r.res.Assets {
		sa := ScopeAsset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root}
		if a.Kind == KindHost {
			sa.Collector = "host"
		}
		doc.Assets = append(doc.Assets, sa)
	}
	return doc, r.write("scope.json", doc)
}

// reconStage runs every declared read per asset: in this build, the host
// collector on host assets. A root of a kind with no collector yet is
// recorded as not collected and makes the run incomplete.
func (r *run) reconStage(ctx context.Context) (any, error) {
	doc := &ReconDoc{Header: r.header("recon")}
	// Every asset's commands go to audit.jsonl and are also kept per asset,
	// so the report carries each asset's trace even under --no-persist
	// (docs/spec/engagement.md, "Text and JSON").
	auditFile := io.Discard
	if r.o.Dir != nil {
		f, err := os.OpenFile(r.o.Dir.File("audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("run directory: audit log: %w", err)
		}
		defer func() { _ = f.Close() }()
		auditFile = f
	}
	isRoot := func(a ResolvedAsset) bool { return a.Root == a.ID }
	for _, a := range r.res.Assets {
		ra := ReconAsset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root}
		switch {
		case a.Kind != KindHost:
			ra.Status, ra.Reason = StatusNotCollected, ReasonCollectorNotBuilt
			ra.Detail = "no collector reads " + string(a.Kind) + " assets in this build"
			if isRoot(a) {
				r.incomplete(a, ra)
			}
		case ctx.Err() != nil:
			ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
			ra.Detail = "limits.timeout ended the engagement before this asset was read"
			r.incomplete(a, ra)
		default:
			r.o.Log("recon: %s (%s)", a.Name, a.ID)
			var trace bytes.Buffer
			audit := policy.NewAudit(io.MultiWriter(&trace, auditFile))
			c, err := r.o.Collect(ctx, r.hostOptions(a, audit))
			r.traces[a.Name] = readTrace(&trace)
			if err != nil {
				he, ok := errors.AsType[*hostasset.Error](err)
				switch {
				case !ok:
					return nil, err
				case ctx.Err() != nil:
					// limits.timeout ended the engagement while this host
					// was reached: whatever the error says, the cause is
					// the limit, never a refusal.
					ra.Status, ra.Reason, ra.Detail = StatusNotCollected, ReasonLimitReached,
						"limits.timeout ended the engagement while it was reached: "+err.Error()
					r.incomplete(a, ra)
				case he.Usage:
					// Refused on the positive list: the host is not
					// reached, the others still are, and the run exits 3
					// with what it collected written.
					ra.Status, ra.Reason, ra.Detail, ra.Echo, ra.Refusal = StatusRefused, ReasonRefused, err.Error(), he.Echo, he.Kind
					r.out.Refused = append(r.out.Refused, ereport.Shortfall{Asset: a.ID, AssetName: a.Name,
						Reason: ReasonRefused, Detail: ra.Detail, Echo: ra.Echo, Kind: ra.Refusal})
				default:
					ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
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
		}
		doc.Assets = append(doc.Assets, ra)
	}
	r.recon = doc
	return doc, r.write("recon.json", doc)
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
		Audit: audit, Version: r.o.Version, Now: r.o.Started, RecordFixtures: r.o.RecordFixtures,
		ContextSource: r.res.Source.Path + " assets." + a.Name,
		Log:           func(f string, args ...any) { r.o.Log(a.Name+": "+f, args...) },
	}
	o.RunTimeout, _ = time.ParseDuration(a.Timeout) // validated; "" keeps the default
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

// analyze runs each host asset's posture rules over its facts, writes the
// host collector's envelope under evidence/ (docs/spec/engagement.md,
// "Runs, state and configuration"), and builds the report from them.
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
				aa.Evidence = "evidence/" + fileName(ra.Name) + ".json"
				evidence[ra.Name] = aa.Evidence
				path := r.o.Dir.File(aa.Evidence)
				env.Run.Persisted = &path
				if err := r.write(aa.Evidence, env); err != nil {
					return nil, err
				}
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
		Trigger: res.Engagement.Trigger, Zone: r.zone, FromHost: res.Source.Path == hostSource,
		Path: res.Source.Path, SHA256: res.Source.SHA256, Started: r.o.Started, Finished: time.Now(),
		NotUsed: res.NotUsed, People: len(res.People) > 0, RedactExtra: res.RedactPatterns,
	}
	in.Rerun = "scheck run " + res.Source.Path
	if in.FromHost {
		// --host writes a trigger only so the file it builds validates; the
		// operator declared none.
		in.Path, in.Trigger = "", ""
		in.Rerun = "scheck run --host " + r.hostLocator() + " (with the same flags)"
	}
	if r.o.Dir != nil {
		in.Directory = r.o.Dir.Path
	}
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
			Trace: r.traces[ra.Name]}
		if c, ok := r.hosts[ra.Name]; ok {
			ai.Host = r.hostInput(asset, c, evidence[ra.Name])
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
