package check

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseKV(t *testing.T) {
	in := "port 22\nlistenaddress [::]:22\nProductName:\tmacOS\nNAME=\"Ubuntu\"\naws_access_key_id = X\n# comment\nnosep\nport 23\n"
	got, err := Parse(ParseKV, []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"port": "22", "listenaddress": "[::]:22", "productname": "macOS", "name": "Ubuntu", "aws_access_key_id": "X"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParseLinesAndJSON(t *testing.T) {
	got, _ := Parse(ParseLines, []byte("\xef\xbb\xbfa\r\n\n b \n"))
	if !reflect.DeepEqual(got, []string{"a", " b "}) {
		t.Errorf("lines: %#v", got)
	}
	if _, err := Parse(ParseJSON, []byte("")); err == nil {
		t.Error("empty json accepted")
	}
	if _, err := Parse(ParseJSON, []byte("{\"a\":1")); err == nil {
		t.Error("malformed json accepted")
	}
	if v, err := Parse(ParseJSON, []byte(`{"a":[1]}`)); err != nil || v.(map[string]any)["a"] == nil {
		t.Errorf("json: %v %v", v, err)
	}
	if _, err := Parse("xml", nil); err == nil {
		t.Error("unknown parser accepted")
	}
}

// Malformed and edge-case input for every parser kind must degrade, never
// panic (roadmap M1.3).
func TestParseEdgeCases(t *testing.T) {
	cases := []struct {
		kind ParserKind
		in   string
		want any
		err  bool
	}{
		{ParseRaw, "", "", false},
		{ParseLines, "", []string{}, false},
		{ParseLines, "   \n\t\n", []string{}, false},
		{ParseLines, "a\r\nb\r\n", []string{"a", "b"}, false},
		{ParseLines, "a\nb", []string{"a", "b"}, false}, // truncated: no trailing newline
		{ParseKV, "", map[string]string{}, false},
		{ParseKV, "\xef\xbb\xbfA=1\r\nB: two\r\n", map[string]string{"a": "1", "b": "two"}, false},
		{ParseKV, "key=", map[string]string{"key": ""}, false},
		{ParseKV, "=value\n:x\n", map[string]string{}, false},
		{ParseKV, "dup=1\ndup=2\n", map[string]string{"dup": "1"}, false},
		{ParseKV, "cut=va", map[string]string{"cut": "va"}, false}, // truncated mid-value
		{ParseKV, "[TRUNCATED:12 bytes]", map[string]string{}, false},
		{ParseJSON, "   ", nil, true},
		{ParseJSON, `{"a":1}trailing`, nil, true},
		{ParseJSON, `[1,2`, nil, true},
		{ParseJSON, `null`, nil, false},
		{ParseJSON, `[]`, []any{}, false},
	}
	for i, tc := range cases {
		got, err := Parse(tc.kind, []byte(tc.in))
		if (err != nil) != tc.err {
			t.Errorf("case %d (%s %q): err=%v want error=%v", i, tc.kind, tc.in, err, tc.err)
			continue
		}
		if !tc.err && !reflect.DeepEqual(got, tc.want) {
			t.Errorf("case %d (%s %q): got %#v want %#v", i, tc.kind, tc.in, got, tc.want)
		}
	}
	// 1 MiB of garbage must parse (or fail) quickly and quietly.
	big := []byte(strings.Repeat("\x00\xff=\n", 256<<10))
	for _, k := range []ParserKind{ParseRaw, ParseLines, ParseKV, ParseJSON} {
		_, _ = Parse(k, big)
	}
}
