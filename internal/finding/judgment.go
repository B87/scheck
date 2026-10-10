package finding

// Subject identifies the instance judged by a collector. An empty Subject is
// an asset-wide judgment (docs/spec/report.md, "Findings").
type Subject struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	Label      string `json:"label"`
	ProviderID string `json:"provider_id,omitempty"`
	Person     string `json:"person,omitempty"`
}

// Judgment is a collector rule's decision over redacted evidence. Reads name
// gate requests; Sources name operator declarations. The engagement report
// applies severity and coverage policy (docs/spec/report.md, "Findings").
type Judgment struct {
	ID         string         `json:"id"`
	Asset      string         `json:"asset"`
	Subject    Subject        `json:"subject,omitzero"`
	Verdict    string         `json:"verdict"`
	Reason     string         `json:"reason,omitempty"`
	Reads      []string       `json:"reads"`
	Excerpt    string         `json:"excerpt,omitempty"`
	NotChecked []string       `json:"not_checked,omitempty"`
	Attributes []string       `json:"attributes,omitempty"`
	Listed     []string       `json:"listed,omitempty"`
	Sources    []string       `json:"source,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	Context    string         `json:"context,omitempty"`
	// Members retains the names represented by a wildcard judgment for
	// takeover-confirmation suspension; it is not rendered by the report.
	Members []string `json:"members,omitempty"`
}
