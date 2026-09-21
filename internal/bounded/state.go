package bounded

import (
	"maps"
	"strings"

	"github.com/b87/scheck/internal/operator"
)

// stateVersion changes whenever the state builder changes what a question is
// answered against. It is part of QuestionsVersion.
const stateVersion = "state-1"

// definitionBudget bounds the follow-up text carried into one state. Accuracy
// falls as state grows with content unrelated to the decision (jev-1.13
// limitation 5), and the state budget is 32k tokens for state plus the
// longest question.
const definitionBudget = 4 << 10

// State is what one question is answered against: this item, what code read
// about this item, and only the context fields that bear on it. Never the
// fact sheet, never another candidate, never an unrelated check's output.
type State struct {
	Host             HostState         `json:"host"`
	Item             map[string]string `json:"item"`
	Evidence         string            `json:"evidence_line"`
	Definition       string            `json:"definition,omitempty"`
	DefinitionNote   string            `json:"definition_note,omitempty"`
	DeclaredServices []DeclaredService `json:"declared_services,omitempty"`
	OperatorNotes    string            `json:"operator_notes,omitempty"`
}

// HostState is the operator's description of the host. Every field is always
// present: "not declared" is an answer a literal reader can use, an absent
// field is not.
type HostState struct {
	Platform    string `json:"platform"`
	Role        string `json:"role"`
	Environment string `json:"environment"`
	Exposure    string `json:"exposure"`
	Owner       string `json:"owner"`
}

// DeclaredService is one expected_services entry, carried only when it bears
// on this item.
type DeclaredService struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Purpose  string `json:"purpose,omitempty"`
	Audience string `json:"audience,omitempty"`
}

// StateFor builds one item's state. It is the only place an item's evidence
// becomes model input, and it carries nothing that belongs to another item.
func StateFor(it Item, ctx *operator.Merged) State {
	s := State{
		Host:     HostState{Platform: orUnknown(it.Platform), Role: "not declared", Environment: "not declared", Exposure: "not declared", Owner: "not declared"},
		Item:     map[string]string{},
		Evidence: it.Excerpt,
	}
	maps.Copy(s.Item, it.Fields)
	if ctx != nil {
		st := ctx.Structured
		s.Host.Role = orNotDeclared(st.Role)
		s.Host.Environment = orNotDeclared(st.Environment)
		s.Host.Exposure = orNotDeclared(st.Exposure)
		s.Host.Owner = orNotDeclared(st.Owner)
		// Declared services bear on a listener, by port and protocol. On any
		// other kind they are unrelated detail, which is a distractor.
		if it.Kind == KindListener {
			for _, d := range st.ExpectedServices {
				if strings.EqualFold(d.Key(), it.Fields["port"]+"/"+it.Fields["protocol"]) {
					s.DeclaredServices = append(s.DeclaredServices, DeclaredService{Port: d.Port, Proto: d.Proto, Purpose: d.Purpose, Audience: d.Audience})
				}
			}
		}
		// Operator prose is the operator's own words and may explain any
		// kind. It is data: the injection corpus is the boundary test.
		var prose []string
		for _, p := range ctx.Prose {
			if t := strings.TrimSpace(p.Text); t != "" {
				prose = append(prose, t)
			}
		}
		s.OperatorNotes = strings.Join(prose, "\n\n")
	}
	if it.FollowUp != nil {
		switch {
		case it.FollowUp.Output != "":
			s.Definition = clip(it.FollowUp.Output, definitionBudget)
		default:
			s.DefinitionNote = "could not be read: " + it.FollowUp.Status + " " + it.FollowUp.Reason
		}
	}
	return s
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

func orNotDeclared(v string) string {
	if strings.TrimSpace(v) == "" {
		return "not declared"
	}
	return v
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[state budget: the rest of this file was not sent]"
}
