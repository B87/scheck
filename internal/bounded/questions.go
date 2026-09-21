package bounded

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Question is one yes/no judgement about one item, in the shape a System One
// endpoint takes (a Noul: instructions plus what true and false mean). The
// wording is data, versioned with QuestionsVersion, because a threshold is
// only meaningful for the exact question it was measured on.
//
// The wording follows jev-1.13's documented limitations, which
// docs/ROADMAP-RESEARCH.md tabulates against the place each one is handled:
// it states its conditions literally, names the state field it is about,
// asks for no counting, no date arithmetic and no second hop, and never asks
// "is this unexpected?", which is two judgements in one.
type Question struct {
	ID           string    `json:"-"`
	Type         string    `json:"type"` // always "noul": one form per judgement
	Instructions string    `json:"instructions"`
	Criteria     *Criteria `json:"criteria,omitempty"`
}

// Criteria says what a yes and a no mean, which is where the boundary of a
// judgement is pinned down.
type Criteria struct {
	True  string `json:"true"`
	False string `json:"false"`
}

// Question ids. One kind's questions are independent of one another and are
// asked in one request, so no answer can see another (the vendor's
// structural invariants do not hold between questions either way).
const (
	QExplained = "explained" // the operator context accounts for this item
	QVendor    = "vendor"    // this item is a standard or deliberately installed component
	QHallmarks = "hallmarks" // this item shows hallmarks of intrusion
	QSensitive = "sensitive" // this listener exposes an administrative service
	QPerson    = "person"    // this account belongs to a person who administers the host
)

func noul(id, instructions, yes, no string) Question {
	return Question{ID: id, Type: "noul", Instructions: instructions, Criteria: &Criteria{True: yes, False: no}}
}

// questions is the frozen question set, one list per kind.
var questions = map[Kind][]Question{
	KindListener: {
		noul(QExplained,
			"The operator context in `host` and `declared_services` states a purpose for a service listening on the port in `item.port` of this host.",
			"The declared role, environment, services or notes state a purpose for a service on this port.",
			"Nothing in the operator context states a purpose for a service on this port, or no operator context was supplied."),
		noul(QVendor,
			"The listening program named in `item.process` is a standard component of the operating system in `host.platform`, or part of software an administrator installs deliberately.",
			"The program is a known part of this operating system or of ordinary installed software.",
			"The program is unknown, is named to resemble a system component without being one, or no program name was captured."),
		noul(QSensitive,
			"A service of the kind named in `item.process`, reachable on the port in `item.port`, gives another host administrative control, remote access to a session, or access to stored data.",
			"The service administers the host, grants remote access, or serves a database or file store.",
			"The service does none of these, or what it does cannot be told from the state."),
	},
	KindPersistence: {
		noul(QExplained,
			"The operator context in `host` states a purpose for the entry in `item` running on this host at boot or on a schedule.",
			"The declared role, environment or notes state a purpose for this entry.",
			"Nothing in the operator context states a purpose for this entry, or no operator context was supplied."),
		noul(QHallmarks,
			"The command in `item` or the definition in `definition` downloads and runs code, runs a program from a temporary or hidden directory, decodes an encoded payload, or imitates the name of a system component.",
			"At least one of those is present in the command or the definition.",
			"None of those is present, or no definition was available to read."),
		noul(QVendor,
			"The entry in `item` is part of the operating system in `host.platform`, or part of software an administrator installs deliberately.",
			"The entry ships with this operating system or with ordinary installed software.",
			"The entry is not something this operating system or ordinary installed software provides."),
	},
	KindSUID: {
		noul(QVendor,
			"The program at `item.path` is a set-user-ID program that ships with the operating system in `host.platform`, or with software an administrator installs deliberately.",
			"The program is a known set-user-ID program of this operating system or of ordinary installed software.",
			"The program is unknown, or is not something this operating system or ordinary installed software provides."),
		noul(QHallmarks,
			"The path in `item.path` or the ownership in `definition` shows a program that was copied or built in place rather than installed by a package manager: a home directory, a temporary directory, a hidden directory, a non-root owner, or a name imitating a system tool.",
			"At least one of those is present.",
			"None of those is present, or the ownership could not be read."),
		noul(QExplained,
			"The operator context in `host` states a purpose for the program at `item.path` holding set-user-ID rights on this host.",
			"The declared role, environment or notes state a purpose for this program.",
			"Nothing in the operator context states a purpose for this program, or no operator context was supplied."),
	},
	KindAdmin: {
		noul(QExplained,
			"The operator context in `host` states a purpose for the account in `item.account` holding the administrative rights in `item.rights`.",
			"The declared role, environment, owner or notes state a purpose for this account holding those rights.",
			"Nothing in the operator context states a purpose for this account holding those rights, or no operator context was supplied."),
		noul(QPerson,
			"The account in `item.account` is the login of a person who administers this host, rather than a service account, an application account or an account left behind by software.",
			"The account belongs to a person.",
			"The account belongs to a service or an application, or who it belongs to cannot be told from the state."),
	},
}

// Questions returns the frozen question list for a kind.
func Questions(k Kind) []Question { return questions[k] }

// validAnswers keeps one probability per asked question and rejects an
// answer set that is missing one or carries a value outside [0,1]: a
// malformed answer files nothing (docs/ROADMAP-RESEARCH.md R1). A Noul
// answer is a bare probability with no separate confidence, so this range
// test is the whole of what an answer may be.
func validAnswers(qs []Question, in map[string]float64) (map[string]float64, error) {
	out := make(map[string]float64, len(qs))
	for _, q := range qs {
		v, ok := in[q.ID]
		if !ok {
			return nil, fmt.Errorf("no answer for %q", q.ID)
		}
		// NaN fails every comparison, which is why this is written as a
		// range test and not as a negation of one.
		if !(v >= 0 && v <= 1) {
			return nil, fmt.Errorf("answer for %q is %v, outside [0,1]", q.ID, v)
		}
		out[q.ID] = v
	}
	return out, nil
}

// QuestionsVersion identifies everything a probability depends on: the
// question wording, the decision thresholds and the state builder. A record
// carries it so no threshold is ever read against a different question
// (docs/SPEC.md §5.9).
func QuestionsVersion() string {
	forms := map[Kind][]string{}
	for k, qs := range questions {
		for _, q := range qs {
			forms[k] = append(forms[k], fmt.Sprintf("%s|%s|%s|%s|%s", q.ID, q.Type, q.Instructions, q.Criteria.True, q.Criteria.False))
		}
	}
	payload, _ := json.Marshal(struct {
		Questions  map[Kind][]string
		Thresholds Thresholds
		State      string
	}{forms, DefaultThresholds(), stateVersion})
	sum := sha256.Sum256(payload)
	return "bq-" + hex.EncodeToString(sum[:])[:12]
}
