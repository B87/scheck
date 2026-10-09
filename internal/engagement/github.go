package engagement

import (
	"context"
	"fmt"
	"slices"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// collectGitHub reads inventory, never judging security controls
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
	ev := githubc.Collect(ctx, g, githubc.Organization{Asset: a.ID, Name: strings.TrimPrefix(a.ID, "saas:github:"), Stage: "recon"}, p)
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
		} else if ra.Reason != ReasonLimitReached && strings.HasPrefix(read.Decision, "unavailable:") && read.Decision != "unavailable:unsupported_principal" {
			ra.Status, ra.Reason, ra.Detail = StatusIncomplete, ReasonFailed, read.Op+": "+read.Decision
		}
	}
	if ra.Status == StatusCollected && !targetRead {
		ra.Status, ra.Reason, ra.Detail = StatusNotCollected, "insufficient_permission", "no organization inventory could be read"
		for _, read := range ev.Reads() {
			if read.Reason == "no_credentials" {
				ra.Reason, ra.Detail = read.Reason, read.Detail
				break
			}
		}
	}
	if ra.Detail == "" {
		ra.Detail = "GitHub inventory only. No GitHub security control was assessed."
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
	p := ev.Principal
	source := "unknown"
	if len(p.Scopes) > 0 {
		source = "provider"
	}
	ai.NetworkPrincipal = &ereport.Principal{Identity: principalLabel(p), Scopes: p.Scopes, ScopesSource: source}
	ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: strings.Join([]string{
		inventoryCount("members", ev.Members), inventoryCount("owners", ev.Owners), inventoryCount("outside collaborators", ev.OutsideCollaborators), inventoryCount("pending invitations", ev.Invitations), inventoryCount("repositories visible to this credential", ev.Repositories),
	}, "; ") + ". GitHub security rules are not implemented in this build. No GitHub security control was assessed."})
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
	for _, read := range ev.Reads() {
		ai.Redactions = append(ai.Redactions, read.Redactions...)
		if read.Op != githubc.OpPrincipal && githubReadOK(read) {
			ai.InventoryRead = true
		}
		if read.Reused {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": reused evidence observed at " + read.ObservedAt.UTC().Format("2006-01-02T15:04:05Z") + "; current access was not validated"})
		}
		if read.Population != nil && len(read.Population.Incomplete) > 0 {
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": population incomplete (" + strings.Join(read.Population.Incomplete, ", ") + ")"})
		}
		if read.Reason != "" || read.Gap != "" {
			detail := read.Detail
			if read.Reason == "insufficient_permission" && read.Op != githubc.OpOrganization && read.Op != githubc.OpRepositories && read.Op != githubc.OpPrincipal {
				detail += ". Ask the GitHub organization owner to authorize organization Members read permission for this credential, then resume the run"
			}
			if detail == "" {
				detail = read.Reason + " " + read.Gap
			}
			ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: "github_inventory", Source: ra.ID, Detail: read.Op + ": " + strings.TrimSpace(detail)})
		}
	}
	if r.gate != nil {
		for _, e := range r.gate.Entries() {
			if e.Asset == ra.ID {
				ai.NetworkTrace = append(ai.NetworkTrace, ereport.Trace{Request: e.RequestID, Params: e.Params, At: e.Time, Decision: e.Decision, OutputSHA256: e.OutputHash})
			}
		}
	}
}

func inventoryGapText(gaps []string) string {
	explanations := map[string]string{
		"member_visibility_unknown":     "complete membership visibility was not established",
		"owner_visibility_unknown":      "organization-owner visibility was not established",
		"repository_visibility_unknown": "the credential may hide repositories",
		"duplicate_item":                "duplicate entries were returned and counted once",
		"unrecognized_item":             "some returned entries could not be recognized",
		"unrecognized_population":       "the returned list could not be recognized",
		"read_unavailable":              "a required read did not succeed",
		"population_unknown":            "list completeness could not be established",
		"pagination_unrecognized":       "the next page could not be identified",
		"page_limit":                    "the page limit was reached",
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
