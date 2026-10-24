package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

// ErrNotJSON is RedactJSON's answer for bytes that are not one JSON
// document; nothing was redacted or returned.
var ErrNotJSON = errors.New("not one JSON document")

var jsonSecretKey = regexp.MustCompile(`(?i)^` + secretKey + `$`)

// RedactJSON redacts a JSON document value by value: every string, key and
// number is redacted as text with its escapes decoded, and written back
// encoded. The scope gate uses it for a JSON body before parsing it
// (docs/spec/scope.md, "Responses"). Redacting the document as one text
// would let a span start in one string and end in a later one: the result
// can still parse, with every item between the two gone, and an excluded
// user among them. Value by value, no span crosses a string, structure is
// kept by construction, and an escape (\n before a token, \/ inside one)
// cannot hide a secret from a rule.
//
// Under a key that looks secret (json-secret), every scalar is redacted
// whole, in an array too; a number becomes a string holding its marker.
// The narrower rule's marker stands only when one hit covered the whole
// value. An object under such a key is read member by member, since
// "secret_scanning": {"status": …} is configuration. Two keys redacted to
// the same marker stay two members, which a decoder keeps one of.
func (r *Redactor) RedactJSON(b []byte) ([]byte, []Hit, error) {
	if !json.Valid(b) {
		return nil, nil, ErrNotJSON
	}
	var out bytes.Buffer
	out.Grow(len(b))
	var hits []Hit
	// stack holds, per open array, whether it sits under a secret key;
	// false for an object.
	var stack []bool
	pending := false // the next value is a secret key's
	secretValue := func() bool {
		v := pending || len(stack) > 0 && stack[len(stack)-1]
		pending = false
		return v
	}
	whole := func(text string, h []Hit) (string, []Hit) {
		if len(h) == 1 && h[0].Bytes == len(text) {
			return Marker(h[0].Rule, h[0].Bytes), h
		}
		return Marker("json-secret", len(text)), []Hit{{"json-secret", len(text)}}
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '"':
			end := stringEnd(b, i)
			lit := b[i:end]
			var s string
			_ = json.Unmarshal(lit, &s) // json.Valid checked the document
			red, h := r.RedactString(s)
			if nextByte(b, end) == ':' {
				pending = jsonSecretKey.MatchString(s) && !jsonPlainKey.MatchString(s)
			} else if secretValue() && !jsonTrivialValue.MatchString(s) {
				red, h = whole(s, h)
			}
			hits = append(hits, h...)
			if len(h) == 0 {
				out.Write(lit)
			} else {
				out.Write(encodeJSONString(red))
			}
			i = end
		case c == '-' || c >= '0' && c <= '9' || c == 't' || c == 'f' || c == 'n':
			end := i
			for end < len(b) && !bytes.ContainsRune([]byte(" \t\r\n,]}:"), rune(b[end])) {
				end++
			}
			tok := b[i:end]
			red, h := r.Redact(tok)
			// true, false, null, 0 and 1 are settings; any other number
			// under a secret-shaped key is a value (jsonTrivialValue).
			plain := c == 't' || c == 'f' || c == 'n' || jsonTrivialValue.Match(tok)
			if secretValue() && !plain {
				var w string
				w, h = whole(string(tok), h)
				red = []byte(w)
			}
			hits = append(hits, h...)
			if len(h) == 0 {
				out.Write(tok)
			} else {
				out.Write(encodeJSONString(string(red)))
			}
			i = end
		default:
			switch c {
			case '[':
				stack = append(stack, secretValue())
			case '{':
				pending = false
				stack = append(stack, false)
			case ']', '}':
				stack = stack[:len(stack)-1]
			}
			out.WriteByte(c)
			i++
		}
	}
	return out.Bytes(), hits, nil
}

// stringEnd is the index just past the string literal that starts at i.
func stringEnd(b []byte, i int) int {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(b)
}

// nextByte is the first byte after i that is not white space.
func nextByte(b []byte, i int) byte {
	for ; i < len(b); i++ {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return b[i]
		}
	}
	return 0
}

func encodeJSONString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
