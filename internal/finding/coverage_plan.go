package finding

// Decided says a judgment settled its subject: fired or disproved, with no
// reason left open. Coverage marking and the collectors that word coverage
// read it alike (docs/spec/report.md, "Coverage").
func (j Judgment) Decided() bool { return j.Verdict != "abstained" && j.Reason == "" }

// CoveragePlan is a network collector's coverage for one asset in one area:
// the rule groups it decides, in order, and what it does not read. The
// collector words it; the engagement report marks each group from the
// judgments and the asset's population state (docs/spec/report.md,
// "Coverage").
type CoveragePlan struct {
	Area Area
	// Label starts the row's reason, naming the collector ("Workspace").
	Label  string
	Groups []CoverageGroup
	// Incomplete is the wording every group carries when the asset's
	// population is incomplete; whether it is stays the asset's to say.
	Incomplete CoverageReason
	// Unread are sub-items no rule decides and nothing reads: always not
	// assessed, with a no_rule detail.
	Unread []CoverageUnread
	// RowAlso ends the row's reason: what else nothing assessed.
	RowAlso string
}

// CoverageGroup is one coverage sub-item over the rule ids it names.
type CoverageGroup struct {
	Name  string
	Rules []string
	// Always marks a group judged for every read subject, so no judgment
	// means not assessed with Empty, never not applicable.
	Always bool
	Empty  CoverageReason
	// Limit is what the group's rules check and do not, a no_rule detail.
	Limit string
	// Gap is required evidence the collector could not complete: a group
	// with decisions is partial, one without is not assessed.
	Gap *CoverageReason
	// NotOnPlan is set when the selected profile does not read the group:
	// it is not assessed with only this reason, and never called unassessed.
	NotOnPlan *CoverageReason
	// Collapse prints the abstentions with Collapse.Reason as this one line
	// instead of one line each; they still count as undecided.
	Collapse *CoverageReason
	// Unassessed names the group in the row's reason when nothing in it was
	// decided; empty leaves it out.
	Unassessed string
}

// CoverageUnread is a sub-item nothing reads.
type CoverageUnread struct {
	Name, Detail string
	// Unassessed names it in the row's reason.
	Unassessed string
}

// CoverageReason is a coverage reason code and its collector-worded detail.
type CoverageReason struct{ Reason, Detail string }
