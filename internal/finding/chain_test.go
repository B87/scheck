package finding

import "testing"

// A definition's ceiling binds every step, past-high or not, and a
// lowering step is never capped.
func TestChainStepCeilingAndPastHigh(t *testing.T) {
	c := &Chain{Base: SevMedium, Severity: SevMedium}
	c.Step(Move{Rule: "exposure:internet", By: ByCollector, Delta: +1}, true, SevHigh)
	c.Step(Move{Rule: "contradiction", By: ByEngagement, Delta: +1}, true, SevHigh)
	if c.Severity != SevHigh || c.Moves[1].Stopped != StoppedCeiling || c.Moves[1].To != SevHigh {
		t.Fatal(c)
	}
	c = &Chain{Base: SevHigh, Severity: SevHigh}
	c.Step(Move{Rule: "data_matters_most", Delta: +1}, false, "")
	if c.Severity != SevHigh || c.Moves[0].Stopped != StoppedPastHigh {
		t.Fatal(c)
	}
	c.Step(Move{Rule: "contradiction", Delta: +1}, true, "")
	c.Step(Move{Rule: "exposed_on_purpose", Delta: -4}, false, SevHigh)
	if c.Severity != SevInfo || c.Moves[2].Stopped != "" {
		t.Fatal(c)
	}
}
