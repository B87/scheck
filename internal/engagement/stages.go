package engagement

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/engagement/hostasset"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
)

// Stages are the engagement's stages in order (docs/spec/engagement.md,
// "Stages").
var Stages = []string{"intake", "scope", "recon", "plan", "check", "analyze", "report"}

// LastStage is the last stage this build runs: Report arrives in 0.0.2 E2,
// so findings.json is a run's last output until then.
const LastStage = "analyze"

// Reasons an asset was not collected, as coverage names them
// (docs/spec/engagement.md, "The report's coverage").
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
}

// CheckDoc is the Check stage's output: no follow-up is opened until 0.0.2
// E9, so it writes no evidence and no file.
type CheckDoc struct {
	Header
	FollowUps []string `json:"follow_ups"`
}

// FindingsDoc is findings.json: each rule's outcome per asset.
type FindingsDoc struct {
	Header
	Assets []AssessedAsset `json:"assets"`
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
	// Stage is the last stage run, and Document its output.
	Stage    string
	Document any
	// Refused names each host that refused us (exit 3); the run went on
	// past them.
	Refused []string
	// Incomplete says why the run is incomplete (exit 2); empty when it
	// is not.
	Incomplete []string
	// Warnings are for the operator, on stderr.
	Warnings []string
	// Open is FindingsDoc.Open once Analyze ran (exit 1).
	Open int
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
	recon      *ReconDoc
	out        Outcome
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
		return nil, refuse("--stop-after %s is not available in this build: the report arrives in 0.0.2 E2", stop)
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
	r := &run{res: res, o: o, hosts: map[string]*hostasset.Collection{}}
	r.header = func(stage string) Header {
		return Header{Stage: stage, Engagement: res.Engagement.Name, Started: o.Started.UTC(), Source: res.Source}
	}
	steps := []func(context.Context) (any, error){r.intake, r.scope, r.reconStage, r.plan, r.check, r.analyze}
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
	var audit *policy.Audit
	if r.o.Dir != nil {
		var err error
		if audit, err = policy.OpenAudit(r.o.Dir.File("audit.jsonl")); err != nil {
			return nil, fmt.Errorf("run directory: %w", err)
		}
		defer func() { _ = audit.Close() }()
	}
	isRoot := func(a ResolvedAsset) bool { return a.Root == a.ID }
	for _, a := range r.res.Assets {
		ra := ReconAsset{Name: a.Name, ID: a.ID, Kind: a.Kind, Root: a.Root}
		switch {
		case a.Kind != KindHost:
			ra.Status, ra.Reason = StatusNotCollected, ReasonCollectorNotBuilt
			ra.Detail = "no collector reads " + string(a.Kind) + " assets in this build"
			if isRoot(a) {
				r.incomplete(a.Name, ra.Reason)
			}
		case ctx.Err() != nil:
			ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
			ra.Detail = "limits.timeout ended the engagement before this asset was read"
			r.incomplete(a.Name, ra.Reason)
		default:
			r.o.Log("recon: %s (%s)", a.Name, a.ID)
			c, err := r.o.Collect(ctx, r.hostOptions(a, audit))
			if err != nil {
				he, ok := errors.AsType[*hostasset.Error](err)
				switch {
				case !ok:
					return nil, err
				case he.Usage:
					// Refused on the positive list: the host is not
					// reached, the others still are, and the run exits 3
					// with what it collected written.
					ra.Status, ra.Reason, ra.Detail = StatusRefused, ReasonRefused, err.Error()
					r.out.Refused = append(r.out.Refused, a.Name+": "+err.Error())
				case ctx.Err() != nil:
					ra.Status, ra.Reason, ra.Detail = StatusNotCollected, ReasonLimitReached, err.Error()
					r.incomplete(a.Name, ra.Reason+": limits.timeout ended the engagement while it was reached")
				default:
					ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
					r.incomplete(a.Name, ra.Reason+": "+err.Error())
				}
				break
			}
			r.hosts[a.Name] = c
			env := c.Envelope()
			ra.Status = StatusCollected
			if !c.Complete() {
				ra.Status, ra.Reason = StatusIncomplete, ReasonLimitReached
				if c.Lost() != "" {
					ra.Reason = ReasonFailed
				}
				ra.Detail = strings.Join(env.Run.Warnings, "; ")
				r.incomplete(a.Name, ra.Reason+": "+ra.Detail)
			}
			ra.Host, ra.Facts, ra.Observations = &env.Host, env.Facts, env.Observations
		}
		doc.Assets = append(doc.Assets, ra)
	}
	r.recon = doc
	return doc, r.write("recon.json", doc)
}

func (r *run) incomplete(who, why string) {
	r.out.Incomplete = append(r.out.Incomplete, who+": "+why)
}

// hostOptions is everything the host collector receives for an asset: its
// reach, profile, elevation, narrowing and context, and the engagement's
// redact_extra. Nothing else reaches it.
func (r *run) hostOptions(a ResolvedAsset, audit *policy.Audit) hostasset.Options {
	o := hostasset.Options{
		Local: a.Local(), Host: a.Address(), Port: a.Port, User: a.User, Identity: a.Identity,
		KnownHosts: a.KnownHosts, Elevate: a.Elevate, Profile: a.Profile,
		DisableChecks: a.DisableChecks, DenyPaths: a.DenyPaths, RedactExtra: r.res.RedactExtra(),
		Audit: audit, Version: r.o.Version,
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
		ref, ok := r.res.Lookup(risk.Asset)
		if !ok || ref.ID != a.ID || strings.HasPrefix(risk.ID, "custom:") {
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
			Source: r.res.Source.Path + " " + key})
	}
	if s.IsZero() {
		return nil
	}
	return &s
}

// plan passes through empty until 0.0.2 E9: the posture rules that apply to
// a host are its catalog's, and nothing narrows or orders them yet.
func (r *run) plan(context.Context) (any, error) {
	doc := &PlanDoc{Header: r.header("plan"), Method: "rules only; the plan is a checklist", Checklist: []string{}}
	return doc, r.write("plan.json", doc)
}

// check runs the follow-ups rules named: none until 0.0.2 E9.
func (r *run) check(context.Context) (any, error) {
	return &CheckDoc{Header: r.header("check"), FollowUps: []string{}}, nil
}

// analyze runs each host asset's posture rules over its facts and writes
// the host collector's envelope under evidence/ (docs/spec/engagement.md,
// "Runs, state and configuration").
func (r *run) analyze(context.Context) (any, error) {
	doc := &FindingsDoc{Header: r.header("analyze")}
	for _, ra := range r.recon.Assets {
		aa := AssessedAsset{Name: ra.Name, ID: ra.ID, Status: ra.Status, Reason: ra.Reason}
		if c, ok := r.hosts[ra.Name]; ok {
			env := c.Envelope()
			aa.Threshold = string(c.Threshold())
			aa.Open = c.OpenFindings()
			aa.Assessments, aa.Findings = env.Assessments, env.Findings
			if r.o.Dir != nil {
				aa.Evidence = "evidence/" + fileName(ra.Name) + ".json"
				path := r.o.Dir.File(aa.Evidence)
				env.Run.Persisted = &path
				if err := r.write(aa.Evidence, env); err != nil {
					return nil, err
				}
			}
			doc.Open += aa.Open
		}
		doc.Assets = append(doc.Assets, aa)
	}
	r.out.Open = doc.Open
	doc.AcceptancesNotApplied = r.notApplied
	r.out.Warnings = append(r.out.Warnings, r.notApplied...)
	return doc, r.write("findings.json", doc)
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
