package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Parse turns raw (already redacted and truncated) stdout into the structured
// value stored in the fact sheet. A parse failure is reported by the runner
// as `unavailable: parse error`, never as a panic; the raw text is kept.
func Parse(kind ParserKind, raw []byte) (any, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // BOM
	switch kind {
	case ParseRaw:
		return string(raw), nil
	case ParseLines:
		return parseLines(raw), nil
	case ParseKV:
		return parseKV(raw), nil
	case ParseJSON:
		var v any
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, fmt.Errorf("json: empty output")
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unknown parser %q", kind)
	}
}

func parseLines(raw []byte) []string {
	out := []string{}
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// parseKV reads "key=value", "key: value" or "key value" lines into a map.
// The separator is whichever of '=', ':' or whitespace comes first in the
// line (so "listenaddress [::]:22" splits on the space), keys are lowercased
// and trimmed, values keep their case and lose surrounding quotes. Lines
// without a separator and comment lines are skipped; a repeated key keeps
// its first value.
func parseKV(raw []byte) map[string]string {
	out := map[string]string{}
	for _, l := range parseLines(raw) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		sep := strings.IndexAny(l, "=: \t")
		if sep <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(l[:sep]))
		v := strings.TrimSpace(l[sep+1:])
		v = strings.TrimSpace(strings.TrimLeft(v, "=:"))
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, dup := out[k]; !dup {
			out[k] = v
		}
	}
	return out
}
