package report

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// mattersMost is the summary's readout of each data.matters_most entry
// (docs/spec/report.md, "Data that matters most"): the findings on its
// asset this answer raises, and how many of the checks it raises decided.
// "Nothing found" is said only over checks that decided: a short list must
// not read as "the data that matters most is fine" when it was never
// judged.
func (b *builder) mattersMost() []MattersMost {
	out := []MattersMost{}
	for _, m := range b.in.MattersMost {
		e := MattersMost{Key: m.Key, Asset: m.Asset, Name: m.Asset, What: m.What, Reasons: []string{}}
		i := slices.IndexFunc(b.in.Assets, func(a AssetInput) bool { return a.ID == m.Asset })
		if i < 0 {
			e.Outcome, e.Reasons = "not_read", []string{"not_collected"}
			out = append(out, e)
			continue
		}
		a := b.in.Assets[i]
		e.Name = a.Name
		raises := func(id string) bool {
			def, ok := finding.Lookup(id)
			return ok && def.MattersMostRaises(m.Asset)
		}
		for _, f := range b.r.Findings {
			if f.Key.Asset == m.Asset && (f.Status == finding.StatusOpen || f.Status == finding.StatusAccepted) && raises(f.ID) {
				e.Raised++
			}
		}
		count := map[string]int{}
		var order []string
		for _, as := range b.r.Assessments {
			// A rule that cannot apply here (another platform's) is not a
			// check this answer raises on the asset.
			if as.Asset != m.Asset || !raises(as.ID) || as.Status == finding.NotApplicable {
				continue
			}
			e.Checks++
			// Decided means it fired, or was disproved over everything it
			// had to read: a disproval over a partial read proves nothing
			// absent (docs/spec/scope.md, "Responses").
			if as.Status == finding.Matched || (as.Status == finding.NotMatched && as.Complete) {
				continue
			}
			e.Undecided++
			// Disproved over part of what is there, with no more specific
			// reason: it could show a problem but not rule one out.
			reason := cmp.Or(as.Reason, "unavailable:incomplete_read")
			if count[reason] == 0 {
				order = append(order, reason)
			}
			count[reason]++
		}
		// The reason covering most undecided checks first, ties in the
		// order the assessments list them.
		slices.SortStableFunc(order, func(x, y string) int { return count[y] - count[x] })
		e.Reasons = append(e.Reasons, order...)
		switch {
		case a.Status != "collected" && a.Status != "incomplete" && e.Raised == 0:
			e.Outcome, e.Reasons = "not_read", []string{cmp.Or(a.Reason, a.Status)}
			e.Checks, e.Undecided = 0, 0
		case e.Raised > 0:
			e.Outcome = "raised"
		case e.Checks > 0 && e.Undecided == 0:
			e.Outcome = "read"
		case e.Undecided < e.Checks:
			e.Outcome = "partial"
		default:
			e.Outcome = "not_judged"
		}
		out = append(out, e)
	}
	return out
}

// named says data.matters_most names the asset.
func (t *text) named(id string) bool {
	return slices.ContainsFunc(t.r.Summary.MattersMost, func(m MattersMost) bool { return m.Asset == id })
}

// mattersFirstAssets is the report's assets with those named in
// data.matters_most first, the order otherwise kept (docs/spec/report.md,
// "Not checked").
func (t *text) mattersFirstAssets() []Asset {
	out := slices.Clone(t.r.Assets)
	slices.SortStableFunc(out, func(x, y Asset) int { return boolFirst(t.named(x.ID), t.named(y.ID)) })
	return out
}

// mattersFirstShortfalls orders shortfalls the same way.
func (t *text) mattersFirstShortfalls(in []Shortfall) []Shortfall {
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(x, y Shortfall) int { return boolFirst(t.named(x.Asset), t.named(y.Asset)) })
	return out
}

// mattersLine is one readout line in text.
func (t *text) mattersLine(m MattersMost) string {
	head := t.name(m.Asset) + " (" + clean(m.What) + "): "
	undecided := ""
	if m.Undecided > 0 {
		undecided = t.undecided(m) + " (" + t.mattersReason(m) + ")"
	}
	switch m.Outcome {
	case "raised":
		line := head + count(m.Raised, "finding", "findings") + " on it that this answer raises"
		if undecided != "" {
			line += "; " + undecided
		}
		return line + "."
	case "read":
		return head + "read; every check this answer raises decided, and none found anything it raises."
	case "partial":
		return head + "read; " + undecided + "; the other " + strconv.Itoa(m.Checks-m.Undecided) + " found nothing it raises."
	case "not_judged":
		if m.Checks == 0 {
			return head + "read, but this version of scheck has no check this answer raises for it; nothing on it was raised."
		}
		none := "none of the " + strconv.Itoa(m.Checks) + " checks this answer raises could decide"
		if m.Checks == 1 {
			none = "the one check this answer raises could not decide"
		}
		return head + "read, but " + none + " (" + t.mattersReason(m) + "); nothing on it was raised."
	}
	return head + "not read in this run (" + t.mattersReason(m) + "); nothing on it was checked or raised."
}

// undecided is "U of the M checks this answer raises could not decide".
func (t *text) undecided(m MattersMost) string {
	if m.Checks == 1 {
		return "the one check this answer raises could not decide"
	}
	return strconv.Itoa(m.Undecided) + " of the " + strconv.Itoa(m.Checks) + " checks this answer raises could not decide"
}

// mattersReason words the entry's first reason, and says when there are
// others; Not checked lists them, items on this asset first.
func (t *text) mattersReason(m MattersMost) string {
	if len(m.Reasons) == 0 {
		return "no reason was recorded"
	}
	var why string
	if m.Outcome == "not_read" {
		switch r := m.Reasons[0]; {
		case strings.HasPrefix(m.Asset, "cloud:"):
			why = "this version of scheck does not read cloud projects"
		case r == "collector_not_built":
			why = "this version of scheck does not read it"
		case r == "refused":
			why = "refused before anything was read"
		case r == "failed":
			why = "it could not be reached or read"
		default:
			why = "it was not read"
		}
	} else {
		why = strings.TrimSuffix(t.reasonText(ReasonDetail{Reason: m.Reasons[0]}), ".")
	}
	if len(m.Reasons) > 1 {
		why += ", and other reasons; see Not checked"
	}
	return why
}
