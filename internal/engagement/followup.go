package engagement

import (
	"cmp"
	"context"
	"slices"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
)

// The follow-up table (docs/spec/engagement.md, "Plan selection and
// follow-ups"): a row is a trigger, one declared gate op, where each of its
// parameters comes from, a cap and a depth. No model picks a read. F1b is
// answered by Check's access pass and F2 by Workspace tier 1, so neither
// is a row; the depth allowance of 2 is unused in 0.0.2.

// gateOps are every op a run's gate declares: Scope's discovery and each
// collector's. A follow-up row names one of them.
var gateOps = slices.Concat(discoveryOps, web.Ops, githubc.Ops, workspace.Ops)

// maxFollowUpDepth bounds the table: a row's trigger may read the answers
// of rows above it, at most this deep.
const maxFollowUpDepth = 2

// paramSource is where a follow-up parameter's value comes from. The
// invariants test checks each against the op's declared type.
type paramSource string

// The parameter sources.
const (
	// fromSubjectLogin is the trigger judgment's subject: a declared GitHub
	// login.
	fromSubjectLogin paramSource = "subject.github_login"
	// fromRepositoryOwner and fromRepositoryName are a declared
	// deploys_to: production repository of the trigger's organization.
	fromRepositoryOwner paramSource = "repository.owner"
	fromRepositoryName  paramSource = "repository.name"
)

// sourceTypes is the gate type each source yields.
var sourceTypes = map[paramSource]gate.ParamType{
	fromSubjectLogin:    gate.CollaboratorLogin,
	fromRepositoryOwner: gate.Login,
	fromRepositoryName:  gate.RepoName,
}

// followUp is one row.
type followUp struct {
	ID string
	// Collector and Finding name the judgments that trigger the row; which
	// verdicts and reasons open a pair is the collector's to say.
	Collector, Finding string
	Op                 string
	Params             map[string]paramSource
	Cap                int
	Depth              int
	// After are the rows whose answers this row's trigger reads.
	After []string
	run   func(r *run, ctx context.Context, row followUp, doc *CheckDoc)
}

var followUpTable = []followUp{{
	ID: "F1", Collector: "github", Finding: finding.IDIdentityFormerPersonHasAccess, Op: githubc.OpCollaboratorPermission,
	Params: map[string]paramSource{"owner": fromRepositoryOwner, "repo": fromRepositoryName, "username": fromSubjectLogin},
	Cap:    20, Depth: 1, run: (*run).followPermissions,
}}

// FollowUp is one pair a follow-up opened or cut, as check.json records
// it: execution facts only. Trigger.Verdict says why the read was sent,
// never a posture verdict.
type FollowUp struct {
	Row     string            `json:"row"`
	Trigger FollowUpTrigger   `json:"trigger"`
	Op      string            `json:"op"`
	Asset   string            `json:"asset"`
	Params  map[string]string `json:"params"`
	Outcome string            `json:"outcome"`
	Reason  string            `json:"reason,omitempty"`
	Request string            `json:"request,omitempty"`
}

// FollowUpTrigger is the judgment that opened a pair.
type FollowUpTrigger struct {
	ID      string `json:"id"`
	Asset   string `json:"asset"`
	Subject string `json:"subject"`
	Person  string `json:"person"`
	Verdict string `json:"verdict"`
}

// followUps runs the table's rows in depth order, after Check's planned
// reads, under the run's deadline.
func (r *run) followUps(ctx context.Context, doc *CheckDoc) {
	rows := slices.Clone(followUpTable)
	slices.SortStableFunc(rows, func(a, b followUp) int { return a.Depth - b.Depth })
	for _, row := range rows {
		row.run(r, ctx, row, doc)
	}
}

// sentCounter forwards to the gate and keeps the last result, so the cap
// counts what the gate sent or answered from its ledger.
type sentCounter struct {
	g    *gate.Gate
	last gate.Result
}

func (s *sentCounter) Send(ctx context.Context, req gate.Request) gate.Result {
	s.last = s.g.Send(ctx, req)
	return s.last
}

// permissionPair is one open F1 pair and the root it belongs to.
type permissionPair struct {
	root   int
	login  githubc.PermissionLogin
	target githubc.PermissionTarget
}

func (p permissionPair) key() string {
	return p.target.Repo.Asset + "|" + p.target.Login
}

// followPermissions is F1's loop. Each round judges every GitHub root
// again in memory over what Recon, Check and earlier rounds read, and asks
// each open login its next open production repository, fired logins
// first, then the most recent leaving date, handle and login. A pair is
// attempted once a session whatever came of it, so the loop ends; past the
// cap or a limit a pair is recorded not sent.
func (r *run) followPermissions(ctx context.Context, row followUp, doc *CheckDoc) {
	sent, stop := 0, ""
	attempted := map[string]bool{}
	stopped := map[int]bool{}
	refused := map[int]githubc.Read{}
	for {
		var round []permissionPair
		for i, ra := range r.recon.Assets {
			production := r.productionRepositories(ra.ID)
			if ra.GitHub == nil || ra.Root != ra.ID || ra.Status == StatusRefused || len(production) == 0 {
				continue
			}
			a, ok := r.asset(ra.Name)
			if !ok {
				continue
			}
			c := r.githubContext(a)
			for _, pl := range githubc.PermissionOpen(githubc.JudgeAccess(*ra.GitHub, c), *ra.GitHub, c, production) {
				p := permissionPair{root: i, login: pl, target: pl.Open[0]}
				if !attempted[p.key()] {
					round = append(round, p)
				}
			}
		}
		if len(round) == 0 {
			break
		}
		slices.SortStableFunc(round, func(a, b permissionPair) int {
			if a.login.Fired != b.login.Fired {
				if a.login.Fired {
					return -1
				}
				return 1
			}
			return cmp.Or(strings.Compare(b.login.Left, a.login.Left), strings.Compare(a.login.Handle, b.login.Handle),
				strings.Compare(a.login.Login, b.login.Login), strings.Compare(a.target.Repo.Asset, b.target.Repo.Asset))
		})
		for _, p := range round {
			attempted[p.key()] = true
			var pr githubc.PermissionRead
			switch {
			case stop == "" && ctx.Err() != nil:
				stop = "the run's timeout passed"
				fallthrough
			case stop != "":
				pr = githubc.PermissionNotAsked(p.target, githubc.ReasonLimitReached, stop)
				stopped[p.root] = true
			case sent >= row.Cap:
				pr = githubc.PermissionNotAsked(p.target, githubc.ReasonFollowUpCap, "")
			default:
				g, err := r.gateFor(ctx)
				if err != nil {
					stop = err.Error()
					pr = githubc.PermissionNotAsked(p.target, githubc.ReasonLimitReached, stop)
					stopped[p.root] = true
					break
				}
				s := &sentCounter{g: g}
				pr = githubc.CollectPermission(ctx, s, p.target, "check")
				if s.last.Sent || s.last.Decision == gate.DecisionReused {
					sent++
				}
				switch {
				case pr.Read.Reason == "refused":
					// GitHub no longer accepts the token: nothing more is
					// sent with it.
					refused[p.root] = pr.Read
					stop = cmp.Or(pr.Read.Detail, "GitHub did not accept the credential")
				case s.last.Repeats || pr.Read.Reason == githubc.ReasonLimitReached:
					stop = cmp.Or(pr.Read.Detail, "a limit was reached")
					stopped[p.root] = true
				}
			}
			r.recordPermission(doc, row, p, pr)
		}
	}
	for i, read := range refused {
		r.followUpRefused(i, read)
	}
	for i := range stopped {
		if _, ok := refused[i]; !ok {
			r.followUpStopped(i, stop)
		}
	}
}

// productionRepositories are the repositories declared deploys_to:
// production under a GitHub root: the engagement's, never the collector's.
func (r *run) productionRepositories(root string) []string {
	var out []string
	for _, a := range r.res.Assets {
		if a.Kind == KindRepo && a.Root == root && a.DeploysTo == "production" {
			out = append(out, a.ID)
		}
	}
	return out
}

// recordPermission keeps a pair's entry with Check's evidence for its root
// and in check.json's follow-ups.
func (r *run) recordPermission(doc *CheckDoc, row followUp, p permissionPair, pr githubc.PermissionRead) {
	ra := &r.recon.Assets[p.root]
	ev := *ra.GitHub
	ev.Permissions = append(slices.Clone(ev.Permissions), pr)
	ra.GitHub = &ev
	i := slices.IndexFunc(doc.Assets, func(ca CheckAsset) bool { return ca.ID == ra.ID && ca.GitHub != nil })
	if i >= 0 {
		doc.Assets[i].GitHub.Permissions = append(doc.Assets[i].GitHub.Permissions, pr)
	}
	t := p.login.Trigger
	doc.FollowUps = append(doc.FollowUps, FollowUp{Row: row.ID, Op: row.Op, Asset: p.target.Repo.Asset,
		Trigger: FollowUpTrigger{ID: t.ID, Asset: t.Asset, Subject: t.Subject, Person: t.Person, Verdict: t.Verdict},
		Params:  map[string]string{"owner": p.target.Repo.Owner, "repo": p.target.Repo.Name, "username": p.target.Login},
		Outcome: followUpOutcome(pr.Read), Reason: pr.Read.Reason, Request: pr.Read.RequestID})
	if githubc.PermissionNotSent(pr.Read) {
		// The gate's refused line is in the audit log; the pair was not sent.
		doc.FollowUps[len(doc.FollowUps)-1].Request = ""
	}
}

// followUpOutcome is what came of one pair, as check.json says it.
func followUpOutcome(read githubc.Read) string {
	switch {
	case githubc.PermissionNotSent(read):
		return "not_sent"
	case read.Reason == githubc.ReasonLimitReached:
		return "failed"
	case strings.HasPrefix(read.Reason, "insufficient_permission") || read.Reason == "refused" || read.Status == 401 || read.Status == 403:
		return "denied"
	case read.Status == 404 && read.Reason == "":
		return "not_found"
	case read.Status == 200 && read.Reason == "" && !read.Truncated:
		return "read"
	}
	return "failed"
}

// followUpRefused records a refusal the gate gave a follow-up: exit 3 for
// its root, as any refusal in Check.
func (r *run) followUpRefused(i int, read githubc.Read) {
	ra := &r.recon.Assets[i]
	a, _ := r.asset(ra.Name)
	if ra.Status == StatusRefused {
		return
	}
	if ra.Status != StatusCollected {
		r.out.Incomplete = slices.DeleteFunc(r.out.Incomplete, func(s ereport.Shortfall) bool { return s.Asset == a.ID })
	}
	ra.Status, ra.Reason, ra.Refusal, ra.Detail = StatusRefused, ReasonRefused, read.Kind, read.Detail
	r.githubShortfall(a, *ra)
}

// followUpStopped records a limit that stopped the follow-up before every
// pair was asked: incomplete, only for a root Check left collected.
func (r *run) followUpStopped(i int, detail string) {
	ra := &r.recon.Assets[i]
	if ra.Status != StatusCollected {
		return
	}
	a, _ := r.asset(ra.Name)
	ra.Status, ra.Reason, ra.Detail = StatusIncomplete, ReasonLimitReached, "the follow-up reads stopped: "+detail
	r.githubShortfall(a, *ra)
}

// permissionAsks is the coverage count of a root's F1 pairs: how many were
// opened, how many asked, and what stopped the rest.
func permissionAsks(e githubc.Evidence) *ereport.FollowUpCount {
	if len(e.Permissions) == 0 {
		return nil
	}
	n := &ereport.FollowUpCount{Opened: len(e.Permissions)}
	for _, p := range e.Permissions {
		switch {
		case !githubc.PermissionNotSent(p.Read):
			n.Asked++
		case p.Read.Reason == githubc.ReasonFollowUpCap:
			n.Capped = true
		default:
			n.Stopped = cmp.Or(n.Stopped, p.Read.Detail, "a limit was reached")
		}
	}
	return n
}
