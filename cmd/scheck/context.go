package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/version"
)

// writeContext prints the merged operator context (`--stop-after context`,
// docs/SPEC.md §8): in text, the same block the model will read plus the
// accounting line; in JSON, the structured map, the prose pieces and the
// per-source hashes and budget.
func writeContext(w io.Writer, m *operator.Merged, format string) error {
	if m == nil {
		m = &operator.Merged{}
	}
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			SchemaVersion string `json:"schema_version"`
			Kind          string `json:"kind"`
			Version       string `json:"scheck_version"`
			*operator.Merged
		}{"1.0", "context", version.Version, m})
	}
	if m.IsEmpty() {
		fmt.Fprintln(w, "no operator context: pass --context FILE|DIR|note:TEXT|target[:PATH], add a context: block to scheck.yaml, or files under .scheck/context/")
	} else {
		if _, err := io.WriteString(w, m.Block()); err != nil {
			return err
		}
	}
	fmt.Fprintln(w, m.Summary())
	for _, s := range m.Sources {
		state := ""
		switch {
		case s.Unresolved:
			state = " (unresolved)"
		case s.Truncated:
			state = " (truncated)"
		}
		fmt.Fprintf(w, "  %s  %d bytes  sha256 %s%s\n", s.Name, s.Bytes, shortHash(s.SHA256), state)
	}
	return nil
}

func shortHash(h string) string {
	if h == "" {
		return "-"
	}
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}
