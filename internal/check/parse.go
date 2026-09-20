package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Parse turns raw (already redacted and truncated) stdout into the structured
// value stored in the fact sheet. A parse failure is reported by the runner
// as `unavailable: parse error`, never as a panic; the raw text is kept.
//
// The whole check is the input, not just its ParserKind, because a typed
// shape (docs/SPEC.md §3) is produced from several tools' output formats and
// the catalog's own argv is what says which one to expect.
func Parse(c Check, raw []byte) (any, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // BOM
	if IsTyped(c.Parser) {
		return parseRecords(c, raw)
	}
	switch c.Parser {
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
		return nil, fmt.Errorf("unknown parser %q", c.Parser)
	}
}

func parseLines(raw []byte) []string {
	out := []string{}
	for l := range strings.SplitSeq(string(raw), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// kvAssign matches "KEY=value": an unquoted key with no whitespace, the shape
// os-release and `timedatectl show` use.
var kvAssign = regexp.MustCompile(`^([^\s:=]+)=(.*)$`)

// kvColon matches "Some Key:<space>value": a colon-terminated label, which is
// the only form whose key may contain spaces (`sestatus`, `sw_vers`). The key
// may not itself contain a colon, so `sshd -T`'s "listenaddress [::]:22" does
// not match and falls through to the whitespace split.
var kvColon = regexp.MustCompile(`^([^:=]+):[ \t]+(\S.*)$`)

// parseKV reads "key=value", "key: value" or "key value" lines into a map.
// The forms are tried in that order rather than splitting on the first of
// several separators, because a value can contain a colon ("listenaddress
// [::]:22") and a key can contain a space ("SELinux status: enabled"). Keys
// are lowercased and trimmed, values keep their case and lose surrounding
// quotes. Lines without a separator and comment lines are skipped; a repeated
// key keeps its first value.
func parseKV(raw []byte) map[string]string {
	out := map[string]string{}
	for _, l := range parseLines(raw) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") || isMarkerLine(l) {
			continue
		}
		var k, v string
		switch {
		case kvAssign.MatchString(l):
			m := kvAssign.FindStringSubmatch(l)
			k, v = m[1], m[2]
		case kvColon.MatchString(l):
			m := kvColon.FindStringSubmatch(l)
			k, v = m[1], m[2]
		default:
			sep := strings.IndexAny(l, " \t")
			if sep <= 0 {
				continue
			}
			// "key = value" with spaces around the separator reaches here;
			// the separator itself is not part of the value.
			k, v = l[:sep], strings.TrimLeft(strings.TrimSpace(l[sep+1:]), "=:")
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, dup := out[k]; !dup {
			out[k] = v
		}
	}
	return out
}
