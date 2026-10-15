package finding

// Ref is what a severity step rests on: a declaration of the engagement
// file (Key) or a fact a collector read (Observation and Excerpt)
// (docs/spec/engagement.md, "Severity in context").
type Ref struct {
	Key         string `json:"key,omitempty"`
	Observation string `json:"observation,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
}

// Attribute is a fact a collector rule established about one instance
// that a severity step may read ("contradiction", "admin",
// "public_repository", "password_form"), with what establishes it.
type Attribute struct {
	Name string `json:"name"`
	// Asset is the asset the fact is about when it is not the judgment's
	// own: a left person's write on another repository.
	Asset string `json:"asset,omitempty"`
	Ref   Ref    `json:"ref,omitzero"`
}

// AttributeRaise is a step a collector owns: the definition declares it,
// and it applies when the judgment carries the attribute.
type AttributeRaise struct {
	Name     string
	Delta    int
	PastHigh bool
	// Why is the sentence the report prints when the step moves it.
	Why string
}

// The ways a step can fail to move a severity; each is recorded in the
// chain and never counted as an adjustment.
const (
	StoppedScaleEnd = "scale_end" // already at critical (or info)
	StoppedPastHigh = "past_high" // the step may not pass high
	StoppedCeiling  = "ceiling"   // the definition's ceiling
	StoppedExposed  = "exposed"   // an earlier exposed_on_purpose step is terminal
	// StoppedNotEstablished is a step whose fact was not established:
	// said, not taken (attribute:production_write, docs/spec/engagement.md, R4).
	StoppedNotEstablished = "not_established"
	ByCollector           = "collector"  // the collector's own table
	ByEngagement          = "engagement" // the engagement's table
)

// Move is one step of a severity chain. A step that did not move the
// severity says why in Stopped, and From equals To.
type Move struct {
	Rule    string   `json:"rule"`
	By      string   `json:"by"`
	Delta   int      `json:"delta"`
	From    Severity `json:"from"`
	To      Severity `json:"to"`
	Ref     Ref      `json:"ref,omitzero"`
	Stopped string   `json:"stopped,omitempty"`
	Why     string   `json:"why,omitempty"`
}

// Chain is a finding's severity from its base through every step.
type Chain struct {
	Base     Severity `json:"base"`
	Severity Severity `json:"severity"`
	Moves    []Move   `json:"moves"`
}

// Shift moves a severity by delta steps, clamped to the scale.
func (s Severity) Shift(delta int) Severity {
	scale := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	r := s.Rank() + delta
	r = max(0, min(len(scale)-1, r))
	return scale[r]
}

// Step applies one move to the chain: delta steps, stopped at high
// unless pastHigh, at the definition's ceiling, and at the scale's end.
// The move is recorded either way; it returns whether the severity moved.
func (c *Chain) Step(m Move, pastHigh bool, ceiling Severity) bool {
	m.From = c.Severity
	next := c.Severity.Shift(m.Delta)
	// A cap is said only where it stopped a move that would otherwise
	// have happened: a step from critical meets the scale's end.
	switch {
	case next == c.Severity:
		m.Stopped = StoppedScaleEnd
	case m.Delta > 0 && ceiling != "" && next.Rank() > ceiling.Rank():
		next, m.Stopped = maxSev(c.Severity, ceiling), StoppedCeiling
	case m.Delta > 0 && !pastHigh && next.Rank() > SevHigh.Rank():
		next, m.Stopped = maxSev(c.Severity, SevHigh), StoppedPastHigh
	}
	m.To = next
	c.Moves = append(c.Moves, m)
	moved := next != c.Severity
	c.Severity = next
	return moved
}

func maxSev(a, b Severity) Severity {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}
