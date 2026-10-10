package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestSecretLocationsNeverReturnValuesAndPreserveLines(t *testing.T) {
	body := []byte("ordinary\npassword=opaque-password\nBearer 12345678abcdefgh\n")
	hits, _ := SecretLocations(body, "")
	if len(hits) != 2 || hits[0].Line != 2 || hits[1].Line != 3 {
		t.Fatal(hits)
	}
	for _, hit := range hits {
		if strings.Contains(hit.Marker, "opaque-password") {
			t.Fatal(hit)
		}
	}
	r, _ := NewRedactor([]string{"ordinary"})
	if len(r.ExtraRedactionCounts(body)) != 1 {
		t.Fatal("extra missing")
	}
	if hits, _ := SecretLocations([]byte("ordinary"), ""); len(hits) != 0 {
		t.Fatal("extra filed")
	}
}
func TestSecretLocationsBoundedAndIgnoreMarkerText(t *testing.T) {
	if hits, _ := SecretLocations([]byte("[REDACTED:credential:44 bytes]"), ""); len(hits) > 0 {
		t.Fatal(hits)
	}
	hits, _ := SecretLocations(bytes.Repeat([]byte("password=opaque\n"), 12000), "")
	if len(hits) != 10001 {
		t.Fatal(len(hits))
	}
	if hits[10000].Line != 10001 {
		t.Fatal(hits[10000])
	}
}

func TestSecretLocationsSkippedCandidateExhaustionIsIncomplete(t *testing.T) {
	body := []byte(strings.Repeat("password=no\n", 10001) + "password=actually-sensitive\n")
	_, complete := SecretLocations(body, "")
	if complete {
		t.Fatal("raw candidate exhaustion was treated as complete")
	}
}
