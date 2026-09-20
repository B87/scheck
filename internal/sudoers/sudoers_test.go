package sudoers

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
)

// Every elevated check on every platform must render, i.e. its binary has a
// known absolute path. Adding an elevated check without updating the table
// fails here, not on a target.
func TestGenerateCoversCatalog(t *testing.T) {
	for _, p := range []check.Platform{check.Linux, check.MacOS} {
		out, err := Generate(p, "ops")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range check.ForPlatform(p, check.ProfileHardened) {
			if c.Elevated && !strings.Contains(out, "# "+c.ID+"\n") {
				t.Errorf("%s: %s missing from fragment:\n%s", p, c.ID, out)
			}
			if !c.Elevated && strings.Contains(out, "# "+c.ID+"\n") {
				t.Errorf("%s: non-elevated %s granted", p, c.ID)
			}
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") || line == "" {
				continue
			}
			if !strings.HasPrefix(line, "ops ALL=(root) NOPASSWD: /") || strings.Contains(line, "NOPASSWD: ALL") {
				t.Errorf("%s: grant line is not a single absolute command: %s", p, line)
			}
		}
	}
	out, _ := Generate(check.Linux, "ops")
	if !strings.Contains(out, "ops ALL=(root) NOPASSWD: /usr/sbin/sshd -T  # sshd.config") {
		t.Errorf("sshd line missing:\n%s", out)
	}
}

func TestGenerateRefusesUnknownBinary(t *testing.T) {
	check.Reset()
	t.Cleanup(check.Reset)
	check.Register(check.Check{ID: "x.y", Platform: check.Linux, Argv: []string{"mystery", "--flag"}, Parser: check.ParseRaw, Elevated: true})
	if _, err := Generate(check.Linux, "ops"); err == nil {
		t.Fatal("unknown binary must fail generation")
	}
}

func TestEscape(t *testing.T) {
	if got := escape("%A:%a,x=1"); got != `%A\:%a\,x\=1` {
		t.Errorf("escape = %q", got)
	}
}
