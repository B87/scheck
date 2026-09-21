package bounded

import (
	"fmt"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// Thresholds are the probabilities a decision rule compares against. They
// are provisional: nothing here is calibrated until a live record measures
// them on held-out cases (docs/ROADMAP-RESEARCH.md, "Decision rules and
// thresholds", and R3). They are part of QuestionsVersion, so a record
// always says which numbers produced it.
type Thresholds struct {
	// Unexplained is the level below which the context is taken to say
	// nothing about an item. It is deliberately low: silence is not a
	// judgement, and on its own it files nothing.
	Unexplained float64 `json:"unexplained"`
	// NotStandard is the level below which an item is taken not to be a
	// component of the platform or of installed software.
	NotStandard float64 `json:"not_standard"`
	// Affirmative is the level a positive signal must reach: hallmarks of
	// intrusion, or an exposure that matters.
	Affirmative float64 `json:"affirmative"`
	// Strong is the level at which one signal alone is enough.
	Strong float64 `json:"strong"`
}

// DefaultThresholds are the provisional levels.
func DefaultThresholds() Thresholds {
	return Thresholds{Unexplained: 0.2, NotStandard: 0.3, Affirmative: 0.6, Strong: 0.8}
}

// Decision is what code concluded for one item.
type Decision struct {
	File       bool
	Confidence string // high|medium|low, from the decision, never from the model
	Reason     string
}

// Decide applies the kind's rule to that item's probabilities. The rules are
// tabulated in docs/ROADMAP-RESEARCH.md ("Decision rules and thresholds");
// keep the two together.
//
// Every rule needs an affirmative signal. Nothing is filed because the
// operator context failed to mention something: that is what produced the
// phase 2 false positives (a declared listener, a workstation's own launch
// daemons, an active firewall), and it is a property of the operator's
// notes, not of the host.
func Decide(it Item, th Thresholds) Decision {
	a := it.Answers
	switch it.Kind {
	case KindListener:
		// A listener is filed when the program behind it is not a component
		// anyone ships and the context states no purpose for the port. A
		// sensitive service raises the confidence; it never files on its own,
		// because ssh and screen sharing are sensitive by design.
		if a[QVendor] < th.NotStandard && a[QExplained] < th.Unexplained {
			return filing(a[QSensitive] >= th.Affirmative,
				fmt.Sprintf("the listening program is not a recognized component (%.2f) and the context states no purpose for port %s (%.2f)",
					a[QVendor], it.Fields["port"], a[QExplained]))
		}
		return Decision{Reason: explainNot(a, QVendor, QExplained)}
	case KindPersistence:
		if a[QHallmarks] >= th.Strong {
			return filing(true, fmt.Sprintf("the entry's command shows hallmarks of persistence used by an intruder (%.2f)", a[QHallmarks]))
		}
		if a[QHallmarks] >= th.Affirmative && a[QVendor] < th.NotStandard {
			return filing(false, fmt.Sprintf("the entry shows hallmarks of intrusion (%.2f) and is not part of this platform or of installed software (%.2f)",
				a[QHallmarks], a[QVendor]))
		}
		return Decision{Reason: explainNot(a, QHallmarks, QVendor)}
	case KindSUID:
		writable := it.Fields["directory_is_world_writable"] == "true"
		if a[QVendor] < th.NotStandard && (writable || a[QHallmarks] >= th.Affirmative) && a[QExplained] < th.Unexplained {
			why := fmt.Sprintf("the binary is not one this platform ships (%.2f)", a[QVendor])
			if writable {
				// The correlation is code's: the directory listing said so.
				why += " and its directory " + it.Fields["directory"] + " is world-writable"
			} else {
				why += fmt.Sprintf(" and its path shows it was not installed by a package manager (%.2f)", a[QHallmarks])
			}
			return filing(writable, why)
		}
		return Decision{Reason: explainNot(a, QVendor, QHallmarks)}
	case KindAdmin:
		if a[QPerson] < th.NotStandard && a[QExplained] < th.Unexplained {
			return filing(false, fmt.Sprintf("the account is not a person's login (%.2f) and the context states no purpose for its %s (%.2f)",
				a[QPerson], it.Fields["rights"], a[QExplained]))
		}
		return Decision{Reason: explainNot(a, QPerson, QExplained)}
	}
	return Decision{Reason: "no rule for this kind"}
}

func filing(strong bool, reason string) Decision {
	c := finding.ConfidenceMedium
	if strong {
		c = finding.ConfidenceHigh
	}
	return Decision{File: true, Confidence: c, Reason: reason}
}

// explainNot says why an item was considered and not filed, in the same
// probabilities the rule read, so a reader of the record can see the
// decision rather than infer it.
func explainNot(a map[string]float64, ids ...string) string {
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%s=%.2f", id, a[id]))
	}
	return "considered, not filed (" + strings.Join(parts, " ") + ")"
}
