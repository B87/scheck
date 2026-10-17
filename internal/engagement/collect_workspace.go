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

// planWorkspace orders each Workspace tenant's accounts for the per-user
// reads (docs/spec/engagement.md, "Plan selection and follow-ups"). It
// sends nothing.
func (r *run) planWorkspace() []workspace.UserSelection {
	out := []workspace.UserSelection{}
	for _, ra := range r.recon.Assets {
		a, ok := r.asset(ra.Name)
		if !ok || ra.Workspace == nil || ra.Root != ra.ID {
			continue
		}
		out = append(out, workspace.Select(*ra.Workspace, ra.ID, r.workspaceView(a)))
	}
	return out
}

// checkWorkspace reads each tenant's per-user OAuth grants and forwarding
// in Check, then joins them to Recon's evidence in memory for Analyze;
// recon.json keeps what Recon read and check.json what Check did.
func (r *run) checkWorkspace(ctx context.Context, doc *CheckDoc) error {
	for _, sel := range r.planned.Workspace {
		i := slices.IndexFunc(r.recon.Assets, func(ra ReconAsset) bool { return ra.ID == sel.Asset })
		if i < 0 || r.recon.Assets[i].Workspace == nil {
			continue
		}
		ra := &r.recon.Assets[i]
		a, _ := r.asset(ra.Name)
		g, err := r.gateFor(ctx)
		if err != nil {
			return err
		}
		r.o.Log("check: %s (%s), %d accounts in plan order", a.Name, a.ID, len(sel.Order))
		ev := workspace.CollectUsers(ctx, g, workspace.Target{Asset: a.ID, Stage: "check"}, *ra.Workspace, r.workspaceView(a), sel)
		// A warning about scheck's own credentials that Check's reads raised
		// (the OAuth or forwarding token) reaches stderr as Recon's did.
		for _, note := range ev.Notes {
			if note.Kind == "workspace_credential_warning" && !slices.Contains(ra.Workspace.Notes, note) {
				r.o.Log("warning: %s", note.Detail)
			}
		}
		ra.Workspace = &ev
		doc.Assets = append(doc.Assets, CheckAsset{Name: ra.Name, ID: ra.ID, Workspace: &WorkspaceCheck{OAuth: ev.OAuth, Mail: ev.Mail}})
		checked, short := checkedWorkspace(*ra, ev.Outcome())
		*ra = checked
		if short {
			r.incomplete(a, *ra)
		}
	}
	return nil
}

// checkedWorkspace is a tenant's status after Check: Check's reads can only
// leave a collected tenant incomplete, and short says to record that
// shortfall; a tenant Recon left short keeps its own, never a second.
func checkedWorkspace(ra ReconAsset, o workspace.Outcome) (ReconAsset, bool) {
	if ra.Status != StatusCollected {
		return ra, false
	}
	ra.Detail = o.Detail
	if o.Status == workspace.OutcomeComplete {
		return ra, false
	}
	ra.Status, ra.Reason = StatusIncomplete, cmp.Or(o.Reason, ReasonFailed)
	return ra, true
}

// workspaceView is what the engagement file tells the Workspace collector
// about a tenant: Recon reads with it and Analyze judges with it.
func (r *run) workspaceView(a ResolvedAsset) workspace.Context {
	view := workspace.Context{Zone: r.zone}
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
