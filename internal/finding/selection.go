package finding

// Selection names what chose the part of a population a collector read
// when a budget or a cap stopped it short, in the report's JSON shape
// (docs/spec/report.md, "Coverage"; docs/spec/engagement.md, "Plan
// selection and follow-ups"). Tier counts are among the items read.
type Selection struct {
	// Kind is the kind of read the population counts, the collector's word.
	Kind     string          `json:"kind,omitempty"`
	Unit     string          `json:"unit"`
	Tiers    []SelectionTier `json:"tiers"`
	Fallback string          `json:"fallback,omitempty"`
	Read     int             `json:"read"`
	InScope  int             `json:"in_scope"`
	// InScopeAtLeast is true when the population's own list was not
	// complete, so InScope is a lower bound.
	InScopeAtLeast bool `json:"in_scope_at_least,omitempty"`
	// Spent and Budget are a budgeted population's requests: what was
	// sent against it and the compiled budget; zero without one.
	Spent  int `json:"spent,omitempty"`
	Budget int `json:"budget,omitempty"`
}

// SelectionTier is one tier of a selection: what put its items there,
// the declaration or observation it came from, and how many were read.
// A tier with an empty Source is the fallback order's.
type SelectionTier struct {
	Basis  string `json:"basis"`
	Source string `json:"source,omitempty"`
	Count  int    `json:"count"`
}

// KindSelection is one kind of read a collector sent under its
// selection: the finding ids that rest on it, the population it reached,
// and, when the budget stopped it before every selected item, the
// detail of that cut (a `sampled` coverage reason, never limit_reached).
type KindSelection struct {
	Kind      string    `json:"kind"`
	Rules     []string  `json:"rules"`
	Cut       string    `json:"cut,omitempty"`
	Selection Selection `json:"selection"`
}
