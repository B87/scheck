package main

import (
	"encoding/json"
	"io"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/version"
)

// Discovery uses argv arrays and explicit parameter types so callers never
// reconstruct commands from the human explanation (docs/SPEC.md §8).
type checkDescription struct {
	ID          string             `json:"id"`
	Description string             `json:"description"`
	Platform    check.Platform     `json:"platform"`
	Domain      check.Domain       `json:"domain"`
	Argv        []string           `json:"argv"`
	Params      []paramDescription `json:"params"`
	Parser      check.ParserKind   `json:"parser"`
	Baseline    bool               `json:"baseline"`
	MinProfile  string             `json:"min_profile"`
	Elevated    bool               `json:"elevated"`
	ExitOK      []int              `json:"exit_ok"` // null when any_exit is true
	AnyExit     bool               `json:"any_exit"`
	PathUse     check.PathUse      `json:"path_use"`
	Extract     string             `json:"extract"`
	Canary      bool               `json:"canary"`
	Budget      budgetDescription  `json:"budget"`
}
type paramDescription struct {
	Name string          `json:"name"`
	Kind check.ParamKind `json:"kind"`
	Enum []string        `json:"enum,omitempty"`
	Min  int             `json:"min"`
	Max  int             `json:"max"`
}
type budgetDescription struct {
	SoftMS      int64 `json:"soft_ms"`
	HardMS      int64 `json:"hard_ms"`
	OutputBytes int   `json:"output_bytes"`
}

func writeDiscovery(w io.Writer, kind, platform, profile, elevation string, checks []check.Check) error {
	entries := make([]checkDescription, 0, len(checks))
	for _, c := range checks {
		params := make([]paramDescription, 0, len(c.Params))
		for _, p := range c.Params {
			params = append(params, paramDescription{p.Name, p.Kind, p.Enum, p.Min, p.Max})
		}
		anyExit := c.ExitAllowed(-12345)
		exitOK := c.ExitOK
		if anyExit {
			exitOK = nil
		} else if exitOK == nil {
			exitOK = []int{0}
		}
		entries = append(entries, checkDescription{
			ID: c.ID, Description: c.Description, Platform: c.Platform, Domain: c.Domain,
			Argv: c.Argv, Params: params, Parser: c.Parser, Baseline: c.Baseline,
			MinProfile: c.MinProfile.String(), Elevated: c.Elevated, ExitOK: exitOK, AnyExit: anyExit,
			PathUse: c.PathUse, Extract: c.Extract, Canary: c.Canary,
			Budget: budgetDescription{c.Budget.Soft.Milliseconds(), c.Budget.Hard.Milliseconds(), c.Budget.Output},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		SchemaVersion string             `json:"schema_version"`
		Kind          string             `json:"kind"`
		Version       string             `json:"scheck_version"`
		Platform      string             `json:"platform"`
		Profile       string             `json:"profile,omitempty"`
		Elevation     string             `json:"elevation,omitempty"`
		Checks        []checkDescription `json:"checks"`
	}{"1.0", kind, version.Version, platform, profile, elevation, entries})
}

// commandOutput honors Cobra's injected writer as well as --out for discovery.
func (o *globalOpts) commandOutput(fallback io.Writer) (io.Writer, func(), error) {
	if o.Out == "" {
		return fallback, func() {}, nil
	}
	w, err := o.output()
	if err != nil {
		return nil, nil, err
	}
	return w, func() { _ = w.Close() }, nil
}
