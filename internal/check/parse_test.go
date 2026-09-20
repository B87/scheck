package check

import (
	"reflect"
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
