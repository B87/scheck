// Package severity is the engagement's closed severity table
// (docs/spec/engagement.md, "Severity in context"): which declarations and
// attributes move a fired judgment's severity, in what order, and where
// each step stops. Analyze grades every fired judgment with it; the report
// renders the chains and decides none.
package severity

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/finding"
)

// Declarations are what the table reads of the engagement file, each with
// the key it cites.
type Declarations struct {
	// Exposed are intent.exposed_on_purpose entries, by canonical URL.
	Exposed []Exposed
	// MattersMost are data.matters_most entries naming an asset in scope.
	MattersMost []Matter
	// Production are the repositories declared deploys_to: production, by
	// asset id.
	Production map[string]Production
	// Internet are the hosts whose context declares exposure: internet, by
	// asset id, each with its key.
	Internet map[string]string
}

// Exposed is one URL declared exposed on purpose.
type Exposed struct{ URL, Reason, Key string }

// Matter is one data.matters_most entry: the asset id it names, the
// asset's name, what the data is, and its key (data.matters_most[i]).
type Matter struct{ Asset, Name, What, Key string }

// Production is a repository's production declaration and its key.
type Production struct{ Name, Key string }

// rule is one row of the table.
type rule struct {
	name string
	// ids are the findings the row may move, nil for any.
	ids []string
	// pastHigh says the step may take a finding from high to critical.
	pastHigh bool
	// lower is exposed_on_purpose: to info, and terminal.
	lower bool
	// match is whether the row applies, what it rests on, and its
	// sentence ("" for none).
	match func(d Declarations, in instance) (finding.Ref, string, bool)
	// notApplied, when the row does not match, is a step said but not
	// taken: what it rests on and its sentence.
	notApplied func(d Declarations, in instance) (finding.Ref, string, bool)
}

type instance struct {
	def   finding.Def
	j     finding.Judgment
	owner string
}

// The ceiling wordings (docs/spec/engagement.md, "Ceilings").
const (
	whyCeiling = "capped at high: the cloud firewall and the service's own sign-in were not read, so scheck cannot say anyone can use this now."
	whyExposed = "not applied: declared exposed on purpose (%s)."
)

func whyPastHigh(rule string) string { return finding.WhyPastHigh(rule) }

// productionIDs are the findings a production declaration on their
// repository raises.
var productionIDs = []string{finding.IDGitHubWritableDeployKey, finding.IDGitHubRepositoryWorkflowWrite,
	finding.IDGitHubDefaultBranchUnprotected, finding.IDGitHubPRTargetUnsafe}

// internetIDs are the findings a host's declared internet exposure raises.
var internetIDs = []string{finding.IDDBListensUnfiltered, finding.IDSvcListensBeyond, finding.IDSensitiveListens}

// rules is the table, in the order it is applied. A row it does not name
// does not exist.
var rules = []rule{
	{name: "exposed_on_purpose", lower: true, match: func(d Declarations, in instance) (finding.Ref, string, bool) {
		if in.def.Exposure != finding.IsExposure {
			return finding.Ref{}, "", false
		}
		for _, e := range d.Exposed {
			if e.URL == in.j.Subject.Key {
				return finding.Ref{Key: e.Key}, "You declared this URL exposed on purpose: " + e.Reason, true
			}
		}
		return finding.Ref{}, "", false
	}},
	{name: "data_matters_most", match: func(d Declarations, in instance) (finding.Ref, string, bool) {
		if !mattersMost(in.def, in.owner) {
			return finding.Ref{}, "", false
		}
		for _, m := range d.MattersMost {
			if m.Asset == in.owner {
				what := ""
				if m.What != "" {
					what = " as holding " + m.What
				}
				return finding.Ref{Key: m.Key}, "You listed " + m.Name + " under data.matters_most" + what + ", so this ranks one step higher.", true
			}
		}
		return finding.Ref{}, "", false
	}},
	{name: "deploys_to:production", match: func(d Declarations, in instance) (finding.Ref, string, bool) {
		p, ok := d.Production[in.owner]
		if !ok || !slices.Contains(productionIDs, in.j.ID) {
			return finding.Ref{}, "", false
		}
		return finding.Ref{Key: p.Key}, "This repository is declared to deploy to production, so this rating rises one step.", true
	}},
	{name: "exposure:internet", ids: internetIDs, match: func(d Declarations, in instance) (finding.Ref, string, bool) {
		key, ok := d.Internet[in.owner]
		return finding.Ref{Key: key}, "You declared this host internet-facing, so this ranks one step higher.", ok
	}},
	{name: "contradiction", pastHigh: true, match: func(_ Declarations, in instance) (finding.Ref, string, bool) {
		// A contradiction rests on the declaration the observation
		// disproves; without one there is nothing it contradicts.
		a, ok := attribute(in.j, "contradiction")
		if !ok || a.Ref.Key == "" {
			return finding.Ref{}, "", false
		}
		return a.Ref, ownWords(in.j, "What was observed contradicts what you declared at "+a.Ref.Key+", so this ranks one step higher."), true
	}},
	{name: "attribute:admin", ids: []string{finding.IDIdentityFormerPersonHasAccess}, pastHigh: true,
		match: func(d Declarations, in instance) (finding.Ref, string, bool) {
			// An owner holds admin everywhere; a repository's admin counts
			// where the repository is declared production.
			if ref, why, ok := cites("admin", "This person left and still holds administrator rights, so this ranks one step higher.")(d, in); ok {
				return ref, why, true
			}
			if _, prod := d.Production[in.owner]; prod {
				return cites("repository_admin", "This person left and still holds administrator rights, so this ranks one step higher.")(d, in)
			}
			return finding.Ref{}, "", false
		}},
	{name: "attribute:production_write", ids: []string{finding.IDIdentityFormerPersonHasAccess}, pastHigh: true,
		match: func(d Declarations, in instance) (finding.Ref, string, bool) {
			a, ok := attribute(in.j, "write")
			p, prod := d.Production[in.owner]
			if !ok || !prod {
				return finding.Ref{}, "", false
			}
			return refOf(in.j, a.Ref), ownWords(in.j, "This person left and can still push to "+repoName(in.owner, p)+", which you declared deploys to production, so this ranks one step higher."), true
		},
		notApplied: productionWriteUnsettled},
	{name: "attribute:admin", ids: []string{workspace.IDExternalForwarding},
		match: cites("admin", "This mailbox belongs to a super administrator, so this ranks one step higher.")},
	{name: "attribute:admin_grantor", ids: []string{workspace.IDOAuthBroadScope},
		match: cites("admin_grantor", "An administrator account granted this app, so this ranks one step higher.")},
	{name: "attribute:public_repository", ids: []string{finding.IDGitHubSecretScanningOpen, finding.IDGitHubHistoryCredential}, pastHigh: true,
		match: func(_ Declarations, in instance) (finding.Ref, string, bool) {
			// Its sentence is the raise itself, whatever else the
			// collector said about the secret.
			a, ok := attribute(in.j, "public_repository")
			return refOf(in.j, a.Ref), "This finding concerns a secret in an observed public repository, so the rating rises to critical. Credential usability was not tested.", ok
		}},
}

// repoName is a repository as the chain names it, owner/name.
func repoName(asset string, p Production) string {
	if name, ok := strings.CutPrefix(asset, "repo:github:"); ok {
		return name
	}
	return p.Name
}

// productionWriteUnsettled is R4 not applied: a left person's GitHub
// access fired, no production repository establishes their push access,
// and one did not settle it as absent. The collector lists, on the one
// judgment per login that carries them, the repositories it read where
// push is held or unsettled; production is decided here
// (docs/spec/engagement.md, R4).
func productionWriteUnsettled(d Declarations, in instance) (finding.Ref, string, bool) {
	var causes []finding.Attribute
	for _, a := range in.j.Attributes {
		if _, prod := d.Production[a.Asset]; !prod {
			continue
		}
		switch a.Name {
		case "write_held":
			return finding.Ref{}, "", false
		case "write_unsettled":
			causes = append(causes, a)
		}
	}
	if len(causes) == 0 {
		return finding.Ref{}, "", false
	}
	slices.SortStableFunc(causes, func(x, y finding.Attribute) int { return strings.Compare(x.Asset, y.Asset) })
	why := "not applied: write access to production repositories was not established (" + causes[0].Ref.Excerpt
	if n := len(causes) - 1; n == 1 {
		why += "; and 1 more production repository"
	} else if n > 1 {
		why += fmt.Sprintf("; and %d more production repositories", n)
	}
	return causes[0].Ref, why + ").", true
}

// cites matches a judgment carrying the attribute, resting on what the
// collector cited, with the row's sentence unless the collector said why.
func cites(attr, why string) func(Declarations, instance) (finding.Ref, string, bool) {
	return func(_ Declarations, in instance) (finding.Ref, string, bool) {
		if a, ok := attribute(in.j, attr); ok {
			return refOf(in.j, a.Ref), ownWords(in.j, why), true
		}
		return finding.Ref{}, "", false
	}
}

// ownWords is a fact-sourced row's sentence, unless the collector already
// said why this instance matters: its words are the specific ones.
func ownWords(j finding.Judgment, why string) string {
	if j.Why != "" {
		return ""
	}
	return why
}

// refOf completes what a step rests on: a fact defaults to the judgment's
// first read and its excerpt.
func refOf(j finding.Judgment, ref finding.Ref) finding.Ref {
	if ref.Key == "" && ref.Observation == "" && len(j.Reads) > 0 {
		ref.Observation = j.Reads[0]
	}
	if ref.Key == "" && ref.Excerpt == "" {
		ref.Excerpt = j.Excerpt
	}
	return ref
}

func attribute(j finding.Judgment, name string) (finding.Attribute, bool) {
	for _, a := range j.Attributes {
		if a.Name == name {
			return a, true
		}
	}
	return finding.Attribute{}, false
}

// mattersMost says data.matters_most moves the finding on its owner
// (finding.Def.MattersMostRaises).
func mattersMost(def finding.Def, owner string) bool { return def.MattersMostRaises(owner) }

// Grade is a fired judgment's chain under the asset that owns it: the
// collector's own steps first, then the table's rows in order, each at
// most once and none skipped because an earlier one applied
// (docs/spec/engagement.md, "Stacking"). An unknown id has no chain.
func Grade(j finding.Judgment, owner string, d Declarations) *finding.Chain {
	def, ok := finding.Lookup(j.ID)
	if !ok {
		return nil
	}
	return chain(def, j, owner, d, def.BaseSeverity)
}

// chain grades j from start: the collector's attribute steps, then the
// table.
func chain(def finding.Def, j finding.Judgment, owner string, d Declarations, start finding.Severity) *finding.Chain {
	in := instance{def: def, j: j, owner: owner}
	c := &finding.Chain{Base: start, Severity: start, Moves: []finding.Move{}}
	for _, raise := range def.Attributes {
		if a, ok := attribute(j, raise.Name); ok {
			step(c, def, finding.Move{Rule: "attribute:" + raise.Name, By: finding.ByCollector, Delta: raise.Delta, Ref: refOf(j, a.Ref), Why: raise.Why}, raise.PastHigh)
		}
	}
	exposed := ""
	for _, row := range rules {
		if row.ids != nil && !slices.Contains(row.ids, j.ID) {
			continue
		}
		ref, why, ok := row.match(d, in)
		if !ok {
			if row.notApplied == nil {
				continue
			}
			if ref, why, ok := row.notApplied(d, in); ok && exposed == "" {
				c.Moves = append(c.Moves, finding.Move{Rule: row.name, By: finding.ByEngagement, Delta: +1, From: c.Severity, To: c.Severity,
					Ref: ref, Stopped: finding.StoppedNotEstablished, Why: why})
			}
			continue
		}
		m := finding.Move{Rule: row.name, By: finding.ByEngagement, Delta: +1, Ref: ref, Why: why}
		if exposed != "" {
			// Exposed on purpose is terminal: the step is said, not taken.
			m.From, m.To, m.Stopped, m.Why = c.Severity, c.Severity, finding.StoppedExposed, fmt.Sprintf(whyExposed, exposed)
			c.Moves = append(c.Moves, m)
			continue
		}
		if row.lower {
			m.Delta = finding.SevInfo.Rank() - c.Severity.Rank()
			exposed = ref.Key
		}
		step(c, def, m, row.pastHigh)
	}
	return c
}

// GradeHost is the engagement's steps on a host posture finding, after the
// host collector's own table (host-collector.md §5.3) left it at sev: the
// table's rows in order, as Grade applies them (docs/spec/engagement.md,
// "Stacking"). The host collector's chain stays its own, so the chain's
// Base is the severity after the host table, not the definition's base;
// nil when no row applies.
func GradeHost(id string, sev finding.Severity, owner string, d Declarations) *finding.Chain {
	def, ok := finding.Lookup(id)
	if !ok {
		return nil
	}
	c := chain(def, finding.Judgment{ID: id}, owner, d, sev)
	if len(c.Moves) == 0 {
		return nil
	}
	return c
}

// step applies one move and words a stop the reader must see: a cap.
func step(c *finding.Chain, def finding.Def, m finding.Move, pastHigh bool) {
	c.Step(m, pastHigh, def.Ceiling)
	last := &c.Moves[len(c.Moves)-1]
	switch last.Stopped {
	case finding.StoppedCeiling:
		last.Why = whyCeiling
	case finding.StoppedPastHigh:
		last.Why = whyPastHigh(m.Rule)
	case finding.StoppedScaleEnd:
		last.Why = ""
	}
}

// Fired is a collector's verdict for a judgment that holds.
const Fired = "fired"

// GradeAll gives every fired judgment its chain, replacing any it held: a
// collector never grades. owner is the asset a judgment belongs to when
// it names none.
func GradeAll(js []finding.Judgment, owner string, d Declarations) {
	for i := range js {
		j := &js[i]
		j.Chain = nil
		if j.Verdict != Fired || j.Details["superseded_by"] != nil {
			continue
		}
		o := j.Asset
		if o == "" {
			o = owner
		}
		j.Chain = Grade(*j, o, d)
	}
}
