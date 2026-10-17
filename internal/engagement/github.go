package engagement

import (
	"context"
	"fmt"
	"slices"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// collectGitHub reads a GitHub root's inventory in Recon: the principal,
// and for an organization its metadata, populations, MFA lists, workflow
// default and Actions secrets. Check reads each repository in Plan's order
// (checkGitHub); Analyze judges them (docs/spec/github-collector.md,
// "Reporting and coverage"; docs/spec/runs.md, "Verdicts are not
// evidence").
func (r *run) collectGitHub(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	r.o.Log("recon: %s (%s)", a.Name, a.ID)
	p := githubc.ResolvePrincipal(ctx, g, a.ID, "recon")
	if note := githubc.AssessmentCredential(p); note.Capability == githubc.CapabilityBeyondReads {
		r.o.Log("warning: %s", note.Detail)
	}
	ev := githubc.Evidence{Principal: p}
	if a.Kind != KindRepo {
		ev = githubc.CollectInventory(ctx, g, githubc.Organization{Asset: a.ID, Name: strings.TrimPrefix(a.ID, "saas:github:"), Stage: "recon"}, p)
	}
	ra.GitHub = &ev
	ra.Status, ra.Reason, ra.Refusal, ra.Detail = githubStatus(ctx, ev.Reads(), a.Kind == KindRepo)
	if ra.Detail == "" {
		ra.Detail = "GitHub inventory read; Check reads each repository in Plan's order."
	}
	r.githubShortfall(a, ra)
	if r.manifest != nil {
		session := &r.manifest.Sessions[len(r.manifest.Sessions)-1]
		if session.Principals == nil {
			session.Principals = map[string]GitHubPrincipal{}
		}
		session.Principals[a.ID] = GitHubPrincipal{Identity: ev.Principal.Identity, Label: principalLabel(ev.Principal)}
	}
	return ra
}

// githubShortfall records a GitHub root that did not end collected.
func (r *run) githubShortfall(a ResolvedAsset, ra ReconAsset) {
	if ra.Status == StatusRefused {
		r.out.Refused = append(r.out.Refused, ereport.Shortfall{Asset: a.ID, AssetName: a.Name, Reason: ra.Reason, Kind: ra.Refusal, Detail: ra.Detail})
	} else if ra.Status != StatusCollected {
		r.incomplete(a, ra)
	}
}

// githubStatus is a GitHub root's status from its reads: refused, cut by a
// limit, failed, or collected. A root whose inventory gave nothing is not
// collected; a repository root reads only its principal in Recon, so
// waived says Check is still to read it.
func githubStatus(ctx context.Context, reads []githubc.Read, waived bool) (status, reason, refusal, detail string) {
	status = StatusCollected
	targetRead := waived
	for _, read := range reads {
		if read.Op != githubc.OpPrincipal && githubReadOK(read) {
			targetRead = true
		}
		if read.Reason == "refused" && (read.Kind == "access" || read.Kind == "mirror") {
			return StatusRefused, ReasonRefused, read.Kind, read.Detail
		}
		if read.Reason == "limit_reached" || read.Decision == "unavailable:response_too_large" || read.Truncated || (read.Population != nil && slices.Contains(read.Population.Incomplete, "page_limit")) || ctx.Err() != nil {
			status, reason, detail = StatusIncomplete, ReasonLimitReached, read.Detail
			if detail == "" {
				detail = read.Op + ": a response or page limit stopped collection"
			}
		} else if reason != ReasonLimitReached && strings.HasPrefix(read.Decision, "unavailable:") && read.Decision != "unavailable:unsupported_principal" && read.Decision != "unavailable:owner_authority" {
			status, reason, detail = StatusIncomplete, ReasonFailed, read.Op+": "+read.Decision
		}
	}
	if status == StatusCollected && !targetRead {
		status, reason, detail = StatusNotCollected, "insufficient_permission:github_organization", "no organization inventory could be read"
		for _, read := range reads {
			if read.Reason == "no_credentials" {
				reason, detail = read.Reason, read.Detail
				break
			}
		}
	}
	return status, reason, "", detail
}

// planGitHub orders each GitHub root's repositories by the tier table
// (docs/spec/engagement.md, "Plan selection and follow-ups"). It sends
// nothing.
func (r *run) planGitHub() []githubc.Selection {
	out := []githubc.Selection{}
	for _, ra := range r.recon.Assets {
		a, ok := r.asset(ra.Name)
		if !ok || ra.GitHub == nil || ra.Root != ra.ID {
			continue
		}
		var declared []githubc.RepositoryTarget
		if a.Kind == KindRepo {
			declared = append(declared, githubTarget(a.ID))
		}
		for _, repo := range r.res.Assets {
			if repo.Kind == KindRepo && repo.Root == a.ID && repo.ID != a.ID {
				declared = append(declared, githubTarget(repo.ID))
			}
		}
		sel := githubc.Select(*ra.GitHub, r.githubContext(a), declared, r.checkouts())
		if r.leaverWithLogin() && len(r.productionRepositories(ra.ID)) > 0 {
			sel.Notes = append(sel.Notes, "After these reads, Check may ask GitHub for a departed person's permission on each production repository (at most 20 requests, not counted in the budget).")
		}
		out = append(out, sel)
	}
	return out
}

// leaverWithLogin says some person with a left date declares a GitHub
// login: the permission follow-up may then ask about them.
func (r *run) leaverWithLogin() bool {
	for _, p := range r.res.People {
		if p.Left != "" && len(p.GitHub) > 0 {
			return true
		}
	}
	return false
}

func (r *run) checkouts() map[string]string {
	out := map[string]string{}
	for _, asset := range r.res.Assets {
		if asset.Kind == KindRepo && asset.Checkout != "" {
			out[asset.ID] = asset.Checkout
		}
	}
	return out
}

// checkGitHub reads each selection's repositories in Check, breadth first
// by kind under the budget, then joins them to Recon's inventory in memory
// for Analyze; recon.json keeps what Recon read and check.json what Check
// did.
func (r *run) checkGitHub(ctx context.Context, doc *CheckDoc) error {
	for _, sel := range r.planned.GitHub {
		i := slices.IndexFunc(r.recon.Assets, func(ra ReconAsset) bool { return ra.ID == sel.Asset })
		if i < 0 || r.recon.Assets[i].GitHub == nil {
			continue
		}
		ra := &r.recon.Assets[i]
		a, _ := r.asset(ra.Name)
		g, err := r.gateFor(ctx)
		if err != nil {
			return err
		}
		r.o.Log("check: %s (%s), %d repositories in plan order", a.Name, a.ID, len(sel.Order))
		rep := githubc.CollectRepositories(ctx, g, sel, githubc.CheckInput{Stage: "check", Checkouts: r.checkouts()})
		doc.Assets = append(doc.Assets, CheckAsset{Name: ra.Name, ID: ra.ID, GitHub: &rep})
		ev := ra.GitHub.With(rep)
		ra.GitHub = &ev
		// Judged again over Recon's and Check's reads together. A refusal in
		// Check is recorded whatever Recon left; a limit or failure only
		// when Recon left the root collected, so it is never counted twice.
		status, reason, refusal, detail := githubStatus(ctx, ev.Reads(), false)
		switch {
		case ra.Status == StatusRefused:
		case status == StatusRefused:
			if ra.Status != StatusCollected {
				r.out.Incomplete = slices.DeleteFunc(r.out.Incomplete, func(s ereport.Shortfall) bool { return s.Asset == a.ID })
			}
			ra.Status, ra.Reason, ra.Refusal, ra.Detail = status, reason, refusal, detail
			r.githubShortfall(a, *ra)
		case ra.Status == StatusCollected && status != StatusCollected:
			ra.Status, ra.Reason, ra.Detail = status, reason, detail
			r.githubShortfall(a, *ra)
		case ra.Status == StatusCollected:
			ra.Detail = "GitHub identity, repository-access and configured CI evidence collected; coverage shows the rules assessed and remaining limits."
		}
		audited := true
		for _, h := range rep.History {
			if h.Read.Op != "" && audited {
				audited = g.RecordMirrorAttempt(h.Asset, "check", h.Read.RequestID, h.Read.Decision, h.Read.Gap, h.Objects, h.Commits, h.Blobs, h.Read.ObservedAt) == nil
			}
		}
		if !audited && ra.Status != StatusRefused {
			// The mirror's record could not be written: the root failed,
			// replacing a limit or failure Recon recorded for it.
			r.out.Incomplete = slices.DeleteFunc(r.out.Incomplete, func(s ereport.Shortfall) bool { return s.Asset == a.ID })
			ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, "mirror audit could not be written"
			r.githubShortfall(a, *ra)
		}
	}
	r.reconcileGitHubRepositories(r.recon)
	r.populateGitHubPeople(r.recon)
	populateWorkspacePeople(r.recon)
	doc.Attribution, doc.PeopleCandidates, doc.PeopleInvitationComments = r.recon.Attribution, r.recon.PeopleCandidates, r.recon.PeopleInvitationComments
	doc.PeopleCandidatesPartial, doc.PeopleSource, doc.PeopleTenantOrder = r.recon.PeopleCandidatesPartial, r.recon.PeopleSource, r.recon.PeopleTenantOrder
	return nil
}

func principalLabel(p githubc.PrincipalRead) string {
	if p.Account == nil || p.Identity == "" {
		return "unknown"
	}
	return fmt.Sprintf("%s (user ID %d)", p.Account.Login, p.Account.ID)
}

func (r *run) githubPrincipalChanges() []ereport.PrincipalChange {
	var out []ereport.PrincipalChange
	if r.o.Resume == nil {
		return out
	}
	for _, ra := range r.recon.Assets {
		if ra.GitHub == nil {
			continue
		}
		current := principalLabel(ra.GitHub.Principal)
		sessions := r.o.Resume.Manifest.Sessions
		for _, session := range slices.Backward(sessions) {
			if old, ok := session.Principals[ra.ID]; ok {
				if old.Identity != "" && ra.GitHub.Principal.Identity != "" && old.Identity != ra.GitHub.Principal.Identity {
					out = append(out, ereport.PrincipalChange{Asset: ra.ID, From: old.Label, To: current})
				}
				break
			}
		}
	}
	return out
}

func inventoryCount[T any](name string, pop githubc.Population[T]) string {
	read := false
	for _, r := range pop.Reads {
		read = read || githubReadOK(r)
	}
	if !read {
		return name + ": not read"
	}
	qualifier := "observed "
	if !pop.Complete {
		qualifier = "at least "
	}
	return fmt.Sprintf("%s: %s%d", name, qualifier, len(pop.Items))
}

func (r *run) githubReportInput(ra ReconAsset, judged []githubc.Judgment, ai *ereport.AssetInput) {
	ev := ra.GitHub
	ai.Collector = "github"
	ai.Judged = append(ai.Judged, judged...)
	if r.checked != nil {
		for _, ca := range r.checked.Assets {
			if ca.ID == ra.ID && ca.GitHub != nil {
				ai.Selections = ca.GitHub.Kinds()
			}
		}
	}
	ai.PermissionAsks = permissionAsks(*ev)
	ai.NoProduction = len(r.productionRepositories(ra.ID)) == 0
	p := ev.Principal
	note := githubc.AssessmentCredential(p)
	kind := "github_credential"
	if note.Capability == githubc.CapabilityBeyondReads {
		kind = "github_credential_warning"
	}
	ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: kind, Source: ra.ID, Detail: note.Detail})
	source := "unknown"
	if len(p.Scopes) > 0 {
		source = "provider"
	}
	ai.PopulationIncomplete = !ev.Members.Complete || !ev.Members.VisibilityComplete || !ev.Owners.Complete || !ev.Owners.VisibilityComplete
	ai.InventoryNotes = append(ai.InventoryNotes, r.githubPeopleNotes(ra.ID, *ev, judged)...)
	ai.NetworkPrincipal = &ereport.Principal{Identity: principalLabel(p), Scopes: p.Scopes, ScopesSource: source}
	ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: strings.Join([]string{
		inventoryCount("members", ev.Members), inventoryCount("owners", ev.Owners), inventoryCount("outside collaborators", ev.OutsideCollaborators), inventoryCount("pending invitations", ev.Invitations), inventoryCount("repositories visible to this credential", ev.Repositories),
	}, "; ") + "."})
	ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: "The credential may hide private repositories or concealed memberships. Completing pagination does not establish a complete organization inventory."})
	if p.Identity == "" {
		ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: "GitHub principal could not be identified. Earlier authenticated GitHub evidence was not reused."})
	}
	for _, population := range []struct {
		name string
		gaps []string
	}{
		{"members", ev.Members.Gaps}, {"owners", ev.Owners.Gaps}, {"outside collaborators", ev.OutsideCollaborators.Gaps}, {"pending invitations", ev.Invitations.Gaps}, {"repositories", ev.Repositories.Gaps},
	} {
		if len(population.gaps) > 0 {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: population.name + ": inventory gaps (" + githubc.InventoryGapText(population.gaps) + ")"})
		}
	}
	for _, repo := range ev.RepositoriesAccess {
		for _, pop := range []struct {
			name string
			gaps []string
		}{{repo.Asset + " collaborators", repo.Collaborators.Gaps}, {repo.Asset + " deploy keys", repo.DeployKeys.Gaps}} {
			if len(pop.gaps) > 0 {
				ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: repo.Asset, Detail: pop.name + ": " + githubc.InventoryGapText(pop.gaps)})
			}
		}
	}
	ai.InventoryNotes = append(ai.InventoryNotes, githubCINotes(*ev, judged)...)
	ai.InventoryNotes = append(ai.InventoryNotes, githubAlertNotes(*ev)...)
	readHistory, completeHistory := 0, 0
	for _, h := range ev.RepositoriesHistory {
		detail := "Mirror history was not read. " + githubc.HistoryGapText(h.Gaps)
		if h.RemoteKnown && (h.Objects > 0 || h.Complete) {
			readHistory++
			qualifier := "at least "
			if h.Complete {
				qualifier = ""
				completeHistory++
			}
			detail = fmt.Sprintf("Supported mirror history: %s%d commits and %d blob visits read. Traversal gaps: %s.", qualifier, h.Commits, h.Blobs, githubc.HistoryGapText(h.Gaps))
		}
		detail += " Detector misses, deleted/unadvertised refs, reflogs, submodule/LFS payloads and credential usability remain unassessed."
		ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: h.Asset, Detail: detail})
		if slices.Contains(h.Gaps, "mirror_refs_differ") {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_history_followup", Source: h.Asset, Detail: "Mirror refs differ from the observed GitHub refs; update your authorized mirror and resume. scheck never fetches or modifies the mirror."})
		}
	}
	if len(ev.RepositoriesHistory) > 0 {
		ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: fmt.Sprintf("A mirror is the local repository copy supplied for this check; its origin is its saved repository connection. Supported mirror history read for %d of %d selected repositories; %d complete supported traversals with matching observed refs. Hidden repositories and history outside the supported traversal remain unassessed.", readHistory, len(ev.RepositoriesHistory), completeHistory)})
	}

	for _, read := range ev.PermissionReads() {
		ai.Redactions = append(ai.Redactions, read.Redactions...)
	}
	for _, read := range ev.Reads() {
		ai.Redactions = append(ai.Redactions, read.Redactions...)
		if read.Op != githubc.OpPrincipal && githubReadOK(read) {
			ai.InventoryRead = true
		}
		for _, note := range githubc.ReadNotes(read) {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: note.Detail})
		}
	}
	if r.gate != nil {
		for _, e := range r.gate.Entries() {
			if e.Asset == ra.ID || slices.ContainsFunc(slices.Concat(ev.Reads(), ev.PermissionReads()), func(read githubc.Read) bool { return read.RequestID == e.RequestID }) {
				ai.NetworkTrace = append(ai.NetworkTrace, ereport.Trace{Request: e.RequestID, Params: e.Params, At: e.Time, Decision: e.Decision, OutputSHA256: e.OutputHash})
			}
		}
	}
}

func githubReadOK(read githubc.Read) bool {
	return (read.Decision == "sent" || read.Decision == "reused") && read.Status == 200 && read.Reason == "" && read.Gap == "" && !read.Truncated
}

// Repository reads collected through an organization still belong to their exact
// asset in report coverage (docs/spec/github-collector.md, "Reporting and coverage").
func partitionGitHubJudgments(assets []ereport.AssetInput) {
	byID := map[string]int{}
	for i, a := range assets {
		byID[a.ID] = i
	}
	for i := range assets {
		if assets[i].Collector != "github" {
			continue
		}
		kept := make([]ereport.Judgment, 0, len(assets[i].Judged))
		for _, j := range assets[i].Judged {
			target, found := byID[j.Asset]
			if !found || target == i || assets[target].Collector != "github" {
				kept = append(kept, j)
				continue
			}
			assets[target].Judged = append(assets[target].Judged, j)
			assets[target].NetworkPrincipal = assets[i].NetworkPrincipal
			for _, trace := range assets[i].NetworkTrace {
				if slices.Contains(j.Reads, trace.Request) && !slices.ContainsFunc(assets[target].NetworkTrace, func(existing ereport.Trace) bool { return existing.Request == trace.Request }) {
					assets[target].NetworkTrace = append(assets[target].NetworkTrace, trace)
				}
			}
		}
		assets[i].Judged = kept
	}
}

// githubCoverageReasons words each GitHub abstention's reason as coverage
// prints it. It is the report's edge: findings.json keeps the evidence
// reason (docs/spec/github-collector.md, "Reporting and coverage").
func githubCoverageReasons(assets []ereport.AssetInput) {
	for i := range assets {
		if assets[i].Collector != "github" {
			continue
		}
		assets[i].Judged = slices.Clone(assets[i].Judged)
		for k := range assets[i].Judged {
			assets[i].Judged[k].Reason = githubc.CoverageReason(assets[i].Judged[k].Reason)
		}
	}
}

func githubTarget(id string) githubc.RepositoryTarget {
	key := strings.TrimPrefix(id, "repo:github:")
	owner, name, _ := strings.Cut(key, "/")
	return githubc.RepositoryTarget{Asset: id, Owner: owner, Name: name}
}
func (r *run) githubContext(a ResolvedAsset) githubc.Context {
	c := githubc.Context{OrganizationAsset: a.ID, Zone: r.zone, RepositoryContexts: map[string]githubc.RepositoryContext{}}
	keys := sortedKeys(r.res.People)
	for _, h := range keys {
		p := r.res.People[h]
		c.People = append(c.People, githubc.Person{Handle: h, Kind: p.Kind, GitHub: p.GitHub, Left: p.Left, UsedBy: p.UsedBy})
	}
	c.ExpectedOwners, c.OwnersDeclared = r.res.AdminsFor(a.ID)
	c.MFA, c.MFASource = r.res.MFAFor(a.ID)
	for _, repo := range r.res.Assets {
		if repo.Kind == KindRepo {
			c.RepositoryContexts[repo.ID] = githubc.RepositoryContext{Public: repo.Public, DeploysTo: repo.DeploysTo, Source: "assets." + repo.Name}
		}
	}
	for i, s := range r.res.Secrets.Production {
		if id, ok := r.res.AssetID(s.Asset); ok {
			c.SecretStores = append(c.SecretStores, githubc.Declared{Asset: id, Key: fmt.Sprintf("secrets.production[%d]", i)})
		}
	}
	for i, m := range r.res.Data.MattersMost {
		if id, ok := r.res.AssetID(m.Asset); ok {
			c.MattersMost = append(c.MattersMost, githubc.Declared{Asset: id, Key: fmt.Sprintf("data.matters_most[%d]", i)})
		}
	}
	return c
}

// reconcileGitHubRepositories describes the actual object read for each declared
// repository collected under its organization (docs/spec/github-collector.md, "Reads").
func (r *run) reconcileGitHubRepositories(doc *ReconDoc) {
	for i, a := range doc.Assets {
		if a.Kind != KindRepo || a.Root == a.ID || !strings.HasPrefix(a.Root, "saas:github:") {
			continue
		}
		doc.Assets[i].Status, doc.Assets[i].Reason, doc.Assets[i].Detail = StatusNotCollected, ReasonFailed, "repository metadata was not read under its organization"
		for _, root := range doc.Assets {
			if root.ID != a.Root || root.GitHub == nil {
				continue
			}
			for _, access := range root.GitHub.RepositoriesAccess {
				if access.Asset != a.ID {
					continue
				}
				read := access.RepositoryRead
				if githubReadOK(read) {
					doc.Assets[i].Status, doc.Assets[i].Reason, doc.Assets[i].Detail = StatusCollected, "", "read with "+root.Name
				} else {
					doc.Assets[i].Detail = read.Detail
					if doc.Assets[i].Detail == "" {
						doc.Assets[i].Detail = "repository metadata was unavailable or could not be recognized"
					}
				}
				if read.Reason == "refused" && (read.Kind == "access" || read.Kind == "mirror") {
					doc.Assets[i].Status, doc.Assets[i].Reason, doc.Assets[i].Refusal = StatusRefused, ReasonRefused, read.Kind
				}
				if read.Reason == "limit_reached" || read.Truncated || read.Decision == "unavailable:response_too_large" {
					doc.Assets[i].Status, doc.Assets[i].Reason = StatusIncomplete, ReasonLimitReached
				}
			}
		}
	}
}
