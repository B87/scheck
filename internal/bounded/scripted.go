package bounded

import (
	"context"
	"fmt"
	"maps"
	"os"

	"gopkg.in/yaml.v3"
)

// Scripted is the R1 answer source: answers an author wrote, replayed by
// item key. It exercises the whole arm — enumeration, filters, follow-up
// reads, state, decision, filing — with no network and no cost.
//
// A scripted run makes no quality claim of any kind. It says what this code
// does with a given set of probabilities, never what a model would answer.
type Scripted struct {
	Note     string                        `yaml:"note"`
	Defaults map[Kind]map[string]float64   `yaml:"defaults"`
	Items    map[string]map[string]float64 `yaml:"items"`
}

// LoadScripted reads an answer file.
func LoadScripted(path string) (*Scripted, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bounded: scripted answers: %w", err)
	}
	var s Scripted
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("bounded: scripted answers %s: %w", path, err)
	}
	return &s, nil
}

// Source names this answer source in every record it produces.
func (s *Scripted) Source() string { return "scripted" }

// Answer replays the kind's defaults, overridden per item. An item with no
// answer at all is reported as such: the caller files nothing and marks it.
func (s *Scripted) Answer(_ context.Context, req Request) (map[string]float64, error) {
	base, hasKind := s.Defaults[req.Kind]
	over, hasItem := s.Items[req.ItemKey]
	if !hasKind && !hasItem {
		return nil, fmt.Errorf("no scripted answer for %s", req.ItemKey)
	}
	out := make(map[string]float64, len(req.Questions))
	maps.Copy(out, base)
	maps.Copy(out, over)
	return out, nil
}
