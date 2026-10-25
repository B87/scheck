package report

import "testing"

// A capture a redaction rule replaced or cut names no machine: hashing it
// would give every such host one identity.
func TestUsableIDRefusesMarkedCaptures(t *testing.T) {
	for raw, want := range map[string]bool{
		"0123456789abcdef0123456789abcdef\n":   true,
		"":                                     false,
		"  \n":                                 false,
		"[REDACTED:extra:0:32 bytes]":          false,
		"[redacted:extra:0:32 bytes]":          false,
		"0123456789abcdef[TRUNCATED:16 bytes]": false,
		"prefix [REDACTED:ssh_private_key:1 bytes] end": false,
	} {
		if got := usableID(raw); got != want {
			t.Errorf("%q: %v, want %v", raw, got, want)
		}
	}
}
