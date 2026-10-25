package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every golden report scheck pins is a report ReadJSON reads: the reader and
// the writer are the same contract.
func TestReadJSONReadsEveryGolden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no goldens: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadJSON(bytes.NewReader(raw)); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

func TestReadJSONRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"not json", `nope`, "not a scheck engagement report"},
		{"no version", `{}`, "no schema_version"},
		{"other major", `{"schema_version":"2.0"}`, "reads 1.x only"},
		{"newer minor", `{"schema_version":"1.99"}`, "newer than this build reads"},
		{"not a version", `{"schema_version":"one"}`, "not MAJOR.MINOR"},
		{"unknown field", `{"schema_version":"1.0","surprise":1}`, "does not match schema"},
		{"field in another case", `{"schema_version":"1.0","Run":{}}`, "unknown field"},
		{"duplicate key", `{"schema_version":"1.0","schema_version":"1.0"}`, "written twice"},
		{"duplicate nested key", `{"schema_version":"1.0","exit":{"code":0,"code":1}}`, "written twice"},
		{"unknown nested field", `{"schema_version":"1.0","run":{"surprise":1}}`, "does not match schema"},
	} {
		_, err := ReadJSON(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestReadJSONDropsTheEmbeddedEnvelope(t *testing.T) {
	in := `{"schema_version":"1.0","assets":[{"name":"a","id":"host:203.0.113.5:22","bound_id":null,"kind":"host","root":true,"status":"collected","oldest_collected_at":null,"trace":[],"envelope":{"schema_version":"9.9","anything":{"evidence":"x"}}}]}`
	r, err := ReadJSON(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 1 || r.Assets[0].Envelope != nil || r.Assets[0].ID != "host:203.0.113.5:22" {
		t.Errorf("assets: %+v", r.Assets)
	}
}
