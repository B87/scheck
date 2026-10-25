package report

import "testing"

// A capture a redaction rule replaced or cut names no machine: hashing it
// would give every such host one identity. Neither does a placeholder an
// image ships.
func TestUsableIDRefusesWhatNamesNoMachine(t *testing.T) {
	for raw, want := range map[string]bool{
		"0123456789abcdef0123456789abcdef\n":   true,
		"4C4C4544-0042-5310-8052-B8C04F333232": true,
		"":                                     false,
		"  \n":                                 false,
		"uninitialized":                        false,
		"0123456789abcdef":                     false,
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
