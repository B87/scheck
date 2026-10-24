package check

import "testing"

// A redaction marker inside a path (redact_extra) can make two different
// folders look alike, so the line is not a record and the set is partial: a
// rule may still fire from it, never clear anything.
func TestFindLSPathWithAMarkerMakesTheSetPartial(t *testing.T) {
	in := "1 4 drwx------ 2 a a 4096 Oct  3 10:11 /srv/[REDACTED:extra:8 bytes]\n" +
		"2 4 -rw-r--r-- 1 a a 9 Oct  3 10:11 /srv/[REDACTED:extra:8 bytes]/.env\n"
	r := records(t, Check{ID: "x", Parser: ParseFindLS, Argv: []string{"find"}}, in)
	if !r.Partial || r.Len() != 0 {
		t.Errorf("%+v", r)
	}
}
