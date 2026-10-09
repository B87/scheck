package engagement

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// collectGitHub reads and judges GitHub identity and repository access
// (docs/spec/github-collector.md, "Reporting and coverage").
func (r *run) collectGitHub(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	r.o.Log("recon: %s (%s)", a.Name, a.ID)
	p := githubc.ResolvePrincipal(ctx, g, a.ID, "recon")
	var ev githubc.Evidence
	if a.Kind == KindRepo {
		target := githubTarget(a.ID)
		ev = githubc.Evidence{Principal: p, RepositoriesAccess: []githubc.RepositoryAccess{githubc.CollectRepository(ctx, g, target, "recon")}}
	} else {
		org := githubc.Organization{Asset: a.ID, Name: strings.TrimPrefix(a.ID, "saas:github:"), Stage: "recon"}
		ev = githubc.Collect(ctx, g, org, p)
		targets := []githubc.RepositoryTarget{}
		for _, repo := range ev.Repositories.Items {
			targets = append(targets, githubTarget("repo:github:"+repo.FullName))
		}
		for _, repo := range r.res.Assets {
			if repo.Kind == KindRepo && repo.Root == a.ID {
				targets = append(targets, githubTarget(repo.ID))
			}
		}
		ev = githubc.CollectAccess(ctx, g, org, ev, targets)
	}
	ev.Judgments = githubc.Judge(ev, r.githubContext(a))
	ra.GitHub = &ev
	ra.Status = StatusCollected
	targetRead := false
	for _, read := range ev.Reads() {
		if read.Op != githubc.OpPrincipal && githubReadOK(read) {
			targetRead = true
		}
		if read.Reason == "refused" && read.Kind == "access" {
			ra.Status, ra.Reason, ra.Refusal, ra.Detail = StatusRefused, ReasonRefused, "access", read.Detail
			break
		}
		if read.Reason == "limit_reached" || read.Decision == "unavailable:response_too_large" || read.Truncated || (read.Population != nil && slices.Contains(read.Population.Incomplete, "page_limit")) || ctx.Err() != nil {
			ra.Status, ra.Reason, ra.Detail = StatusIncomplete, ReasonLimitReached, read.Detail
			if ra.Detail == "" {
				ra.Detail = read.Op + ": a response or page limit stopped collection"
			}
		} else if ra.Reason != ReasonLimitReached && strings.HasPrefix(read.Decision, "unavailable:") && read.Decision != "unavailable:unsupported_principal" && read.Decision != "unavailable:owner_authority" {
			ra.Status, ra.Reason, ra.Detail = StatusIncomplete, ReasonFailed, read.Op+": "+read.Decision
		}
	}
	if ra.Status == StatusCollected && !targetRead {
		ra.Status, ra.Reason, ra.Detail = StatusNotCollected, "insufficient_permission:github_organization", "no organization inventory could be read"
		for _, read := range ev.Reads() {
			if read.Reason == "no_credentials" {
				ra.Reason, ra.Detail = read.Reason, read.Detail
				break
			}
		}
	}
	if ra.Detail == "" {
		ra.Detail = "GitHub identity and repository-access evidence collected; coverage shows the rules assessed and remaining limits."
	}
	if ra.Status == StatusRefused {
		r.out.Refused = append(r.out.Refused, ereport.Shortfall{Asset: a.ID, AssetName: a.Name, Reason: ra.Reason, Kind: ra.Refusal, Detail: ra.Detail})
	} else if ra.Status != StatusCollected {
		r.incomplete(a, ra)
	}
	if r.manifest != nil {
		session := &r.manifest.Sessions[len(r.manifest.Sessions)-1]
		if session.Principals == nil {
			session.Principals = map[string]GitHubPrincipal{}
		}
		session.Principals[a.ID] = GitHubPrincipal{Identity: ev.Principal.Identity, Label: principalLabel(ev.Principal)}
	}
	return ra
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

func (r *run) githubReportInput(ra ReconAsset, ai *ereport.AssetInput) {
	ev := ra.GitHub
	ai.Collector = "github"
	for _, j := range ev.Judgments {
		reason := j.Reason
		if reason == "insufficient_evidence" {
			reason = "unavailable:github_evidence"
		}
		mapped := ereport.Judgment{ID: j.ID, Asset: j.Asset, Verdict: j.Verdict, Reason: reason, Reads: j.Reads, Excerpt: j.Excerpt, NotChecked: j.NotChecked, Context: j.Context, Attributes: j.Attributes, Listed: j.Listed, Details: j.Details, Sources: j.Source}
		if j.Subject != nil {
			mapped.Subject = ereport.Subject{Kind: j.Subject.Kind, Key: j.Subject.Key, Label: j.Subject.Label, ProviderID: j.Subject.ProviderID, Person: j.Subject.Person}
		}
		ai.Judged = append(ai.Judged, mapped)
	}
	p := ev.Principal
	source := "unknown"
	if len(p.Scopes) > 0 {
		source = "provider"
	}
	ai.PopulationIncomplete = !ev.Members.Complete || !ev.Members.VisibilityComplete || !ev.Owners.Complete || !ev.Owners.VisibilityComplete
	ai.InventoryNotes = append(ai.InventoryNotes, r.githubPeopleNotes(ra.ID, *ev)...)
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
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: population.name + ": inventory gaps (" + inventoryGapText(population.gaps) + ")"})
		}
	}
	for _, repo := range ev.RepositoriesAccess {
		for _, pop := range []struct {
			name string
			gaps []string
		}{{repo.Asset + " collaborators", repo.Collaborators.Gaps}, {repo.Asset + " deploy keys", repo.DeployKeys.Gaps}} {
			if len(pop.gaps) > 0 {
				ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: repo.Asset, Detail: pop.name + ": " + inventoryGapText(pop.gaps)})
			}
		}
	}
	for _, read := range ev.Reads() {
		ai.Redactions = append(ai.Redactions, read.Redactions...)
		if read.Op != githubc.OpPrincipal && githubReadOK(read) {
			ai.InventoryRead = true
		}
		if read.Reused {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": reused evidence observed at " + read.ObservedAt.UTC().Format("2006-01-02T15:04:05Z") + "; current access was not validated"})
		}
		if read.Population != nil && len(read.Population.Incomplete) > 0 {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": population incomplete (" + inventoryGapText(read.Population.Incomplete) + ")"})
		}
		if read.Reason != "" || read.Gap != "" {
			detail := read.Detail
			if read.Reason == "insufficient_permission" {
				switch read.Op {
				case githubc.OpDeployKeys:
					detail += ". Ask the repository owner to authorize Administration read permission for this credential, then resume"
				case githubc.OpCollaborators:
					detail += ". Ask the repository owner to authorize Metadata read and confirm this account has sufficient repository privilege to list collaborators, then resume"
				case githubc.OpRepository, githubc.OpRepositories:
					detail += ". Ask the owner to authorize Metadata read for the intended repositories, then resume"
				case githubc.OpPrincipal, githubc.OpOrganization:
				default:
					detail += ". Ask the GitHub organization owner to authorize Members read and confirm the required organization role, then resume"
				}
			}
			if detail == "" {
				detail = read.Reason + " " + read.Gap
			}
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": " + strings.TrimSpace(detail)})
		}
	}
	if r.gate != nil {
		for _, e := range r.gate.Entries() {
			if e.Asset == ra.ID || slices.ContainsFunc(ev.Reads(), func(read githubc.Read) bool { return read.RequestID == e.RequestID }) {
				ai.NetworkTrace = append(ai.NetworkTrace, ereport.Trace{Request: e.RequestID, Params: e.Params, At: e.Time, Decision: e.Decision, OutputSHA256: e.OutputHash})
			}
		}
	}
}

func inventoryGapText(gaps []string) string {
	explanations := map[string]string{
		"member_visibility_unknown":                  "complete membership visibility was not established",
		"owner_visibility_unknown":                   "organization-owner visibility was not established",
		"repository_visibility_unknown":              "the credential may hide repositories",
		"repository_collaborator_visibility_unknown": "the credential may hide repository collaborators",
		"owner_authority_unknown":                    "organization-owner authority was not established",
		"duplicate_item":                             "duplicate entries were returned and counted once",
		"unrecognized_item":                          "some returned entries could not be recognized",
		"unrecognized_population":                    "the returned list could not be recognized",
		"read_unavailable":                           "a required read did not succeed",
		"population_unknown":                         "list completeness could not be established",
		"pagination_unrecognized":                    "the next page could not be identified",
		"page_limit":                                 "the page limit was reached",
	}
	out := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		if phrase := explanations[gap]; phrase != "" {
			out = append(out, phrase)
		} else {
			out = append(out, strings.ReplaceAll(gap, "_", " "))
		}
	}
	return strings.Join(out, "; ")
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

func githubTarget(id string) githubc.RepositoryTarget {
	key := strings.TrimPrefix(id, "repo:github:")
	owner, name, _ := strings.Cut(key, "/")
	return githubc.RepositoryTarget{Asset: id, Owner: owner, Name: name}
}
func (r *run) githubContext(a ResolvedAsset) githubc.Context {
	c := githubc.Context{OrganizationAsset: a.ID, Today: r.session.In(r.zone).Format("2006-01-02"), RepositoryContexts: map[string]githubc.RepositoryContext{}}
	keys := sortedKeys(r.res.People)
	for _, h := range keys {
		p := r.res.People[h]
		c.People = append(c.People, githubc.Person{Handle: h, Kind: p.Kind, GitHub: p.GitHub, Left: p.Left, UsedBy: p.UsedBy})
	}
	for where, handles := range r.res.Access.Admins {
		if ref, ok := r.res.Lookup(where); ok && ref.ID == a.ID {
			c.OwnersDeclared = true
			c.ExpectedOwners = handles
		}
	}
	for i, m := range r.res.Access.MFA {
		if ref, ok := r.res.Lookup(m.Where); ok && ref.ID == a.ID {
			c.MFA = m.Enforced
			c.MFASource = "access.mfa[" + strconv.Itoa(i) + "]"
		}
	}
	for _, repo := range r.res.Assets {
		if repo.Kind == KindRepo {
			c.RepositoryContexts[repo.ID] = githubc.RepositoryContext{Public: repo.Public, DeploysTo: repo.DeploysTo, Source: "assets." + repo.Name}
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
				if read.Reason == "refused" && read.Kind == "access" {
					doc.Assets[i].Status, doc.Assets[i].Reason, doc.Assets[i].Refusal = StatusRefused, ReasonRefused, "access"
				}
				if read.Reason == "limit_reached" || read.Truncated || read.Decision == "unavailable:response_too_large" {
					doc.Assets[i].Status, doc.Assets[i].Reason = StatusIncomplete, ReasonLimitReached
				}
			}
		}
	}
}
