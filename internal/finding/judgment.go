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
// gate requests; Sources name operator declarations; Attributes are facts a
// severity step may read, each with what establishes it. A judgment carries
// no severity: Analyze grades it (docs/spec/engagement.md, "Severity in
// context"), and the report renders the chain (docs/spec/report.md,
// "Findings").
type Judgment struct {
	ID         string      `json:"id"`
	Asset      string      `json:"asset"`
	Subject    Subject     `json:"subject,omitzero"`
	Verdict    string      `json:"verdict"`
	Reason     string      `json:"reason,omitempty"`
	Reads      []string    `json:"reads"`
	Excerpt    string      `json:"excerpt,omitempty"`
	NotChecked []string    `json:"not_checked,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
	Listed     []string    `json:"listed,omitempty"`
	// OfNote are listed subjects that matter more than the rest (an
	// administrator who granted an OAuth app), with why.
	OfNote  []OfNote       `json:"of_note,omitempty"`
	Sources []string       `json:"source,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	// Why is the collector's one sentence on why this instance matters as
	// rated, printed with the steps' own.
	Why string `json:"why,omitempty"`
	// Chain is the severity Analyze gave a fired judgment. A collector never
	// sets it: Analyze replaces whatever it holds.
	Chain *Chain `json:"chain,omitempty"`
	// Members retains the names represented by a wildcard judgment for
	// takeover-confirmation suspension; it is not rendered by the report.
	Members []string `json:"members,omitempty"`
}

// OfNote is one listed subject that matters more than the rest.
type OfNote struct {
	Key string `json:"key"`
	Why string `json:"why"`
}

// Has reports whether the judgment carries the attribute.
func (j Judgment) Has(name string) bool {
	for _, a := range j.Attributes {
		if a.Name == name {
			return true
		}
	}
	return false
}
