package report

import (
	"bytes"
	"encoding/json"
	"io"

	hostreport "github.com/b87/scheck/internal/report"
)

// WriteJSON renders the report as indented JSON
// (docs/engagement-report-schema.json). Each host asset's envelope is the
// host collector's JSON whole, and includeEvidence adds the redacted
// captures to it as `--include-evidence` does for the host report
// (docs/spec/host-collector.md §6.4); nothing persisted carries them.
func WriteJSON(w io.Writer, r *Report, includeEvidence bool) error {
	assets := make([]any, len(r.Assets))
	for i, a := range r.Assets {
		if a.Envelope == nil {
			assets[i] = a
			continue
		}
		var buf bytes.Buffer
		if err := hostreport.WriteJSONEvidence(&buf, *a.Envelope, includeEvidence); err != nil {
			return err
		}
		assets[i] = struct {
			Asset
			Envelope json.RawMessage `json:"envelope"`
		}{a, json.RawMessage(bytes.TrimSpace(buf.Bytes()))}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		*Report
		Assets []any `json:"assets"`
	}{r, assets})
}
