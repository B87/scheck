package engagement

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
)

// collectWorkspace leaves the protocol and note wording in the collector
// (docs/spec/workspace-collector.md, "Reporting and coverage").
func (r *run) collectWorkspace(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	r.o.Log("recon: %s (%s)", a.Name, a.ID)
	ev := workspace.Collect(ctx, g, workspace.Target{Asset: a.ID, Stage: "recon"}, r.workspaceView(a))
	ra.Workspace = &ev
	for _, note := range ev.Notes {
		if note.Kind == "workspace_credential_warning" {
			r.o.Log("warning: %s", note.Detail)
		}
	}
	o := ev.Outcome()
	ra.Status, ra.Detail = StatusCollected, o.Detail
	if o.Status != workspace.OutcomeComplete {
		ra.Status, ra.Reason = StatusIncomplete, cmp.Or(o.Reason, ReasonFailed)
		r.incomplete(a, ra)
	}
	return ra
}

// workspaceView is what the engagement file tells the Workspace collector
// about a tenant: Recon reads with it and Analyze judges with it.
func (r *run) workspaceView(a ResolvedAsset) workspace.Context {
	view := workspace.Context{AssessedAt: r.session, Zone: r.zone}
	if auth := r.res.Authorization; auth != nil {
		for _, m := range auth.Mailboxes {
			if m.ID() == a.ID {
				from, until := mailboxSpan(m.Date, m.Expires, r.res.loc)
				now := time.Now()
				view.MailApproval = &workspace.MailApproval{By: m.By, Date: m.Date, Expires: m.Expires, Current: !now.Before(from) && now.Before(until)}
				break
			}
		}
	}
	view.ExpectedAdmins, view.AdminsDeclared = r.res.AdminsFor(a.ID)
	view.MFA, view.MFASource = r.res.MFAFor(a.ID)
	for _, b := range r.res.Assets {
		if b.Kind == KindDomain {
			view.DeclaredDomains = append(view.DeclaredDomains, strings.TrimPrefix(b.ID, "domain:"))
		}
	}
	for _, handle := range sortedKeys(r.res.People) {
		p := r.res.People[handle]
		view.People = append(view.People, workspace.Person{Handle: handle, Addresses: p.Workspace, Kind: p.Kind, Left: p.Left, UsedBy: p.UsedBy})
	}
	return view
}

func (r *run) workspaceReportInput(ra ReconAsset, judged []finding.Judgment, ai *ereport.AssetInput) {
	e := ra.Workspace
	ai.Collector = "workspace"
	ai.Judged = judged
	ai.InventoryRead = len(e.Users.Reads) > 0 && e.Users.Reads[0].Status == 200 && e.Users.Reads[0].Reason == ""
	ai.PopulationIncomplete = !e.Users.Complete || !e.Units.Complete
	ai.Coverage = e.Coverage(judged)
	identity, source := "unknown", "unknown"
	if e.DelegatedUser != nil {
		identity = "delegated Workspace account " + e.DelegatedUser.Primary + " (id " + e.DelegatedUser.ID + ")"
	}
	if e.Binding.ScopesKnown {
		source = "provider"
	}
	ai.NetworkPrincipal = &ereport.Principal{Identity: identity, Scopes: e.Binding.Scopes, ScopesSource: source}
	for _, note := range e.Notes {
		ai.InventoryNotes = append(ai.InventoryNotes, ereport.Note{Kind: note.Kind, Source: note.Source, Detail: note.Detail})
	}
	for _, read := range e.Reads() {
		ai.Redactions = append(ai.Redactions, read.Redactions...)
	}
	if r.gate != nil {
		for _, entry := range r.gate.Entries() {
			if entry.Asset == ra.ID {
				ai.NetworkTrace = append(ai.NetworkTrace, ereport.Trace{Request: entry.RequestID, Params: entry.Params, At: entry.Time, Decision: entry.Decision, OutputSHA256: entry.OutputHash})
			}
		}
	}
}

// mailSignedIn reports whether the Workspace profile selected mail forwarding
// for asset, whether that profile is known, and how many mailboxes this run
// asked Google to act as.
func (r *run) mailSignedIn(asset string) (selected, known bool, n int) {
	if r.recon == nil {
		return false, false, 0
	}
	for _, ra := range r.recon.Assets {
		if ra.ID != asset || ra.Workspace == nil {
			continue
		}
		ev := ra.Workspace
		known = ev.Binding.Profile != ""
		selected = slices.Contains(ev.Binding.Surfaces, gate.WorkspaceGmailForwarding)
		for _, m := range ev.Mail.Accounts {
			if m.AutoRead.ActedAs || m.FiltersRead.ActedAs {
				n++
			}
		}
	}
	return selected, known, n
}

// Attribution is copied as identity evidence, without guessing a person's kind.
func populateWorkspacePeople(doc *ReconDoc) {
	for _, asset := range doc.Assets {
		if asset.Workspace == nil {
			continue
		}
		e := asset.Workspace
		tenant := strings.TrimPrefix(asset.ID, "saas:")
		doc.PeopleTenantOrder = append(doc.PeopleTenantOrder, tenant)
		doc.PeopleCandidatesPartial = doc.PeopleCandidatesPartial || !e.Users.Complete
		for _, a := range e.Attribution {
			doc.Attribution = append(doc.Attribution, Attribution{Tenant: tenant, Key: a.Key, ProviderID: a.ProviderID, Handle: a.Handle, MatchedBy: a.MatchedBy})
		}
	}
}
