package compare

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the comparison as indented JSON
// (docs/engagement-comparison-schema.json). Every string is a field of one
// of the two reports, already redacted; nothing is added from any evidence
// file.
func WriteJSON(w io.Writer, c *Comparison) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}
