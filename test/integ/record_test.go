//go:build integration

package integ

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b87/scheck/test/containers"
)

// TestRecordFixtures regenerates testdata/fixtures/{ubuntu,fedora} from the
// containers, with the sudoers fragment installed so elevated checks are
// recorded too. Run with SCHECK_RECORD=1 (make fixtures).
func TestRecordFixtures(t *testing.T) {
	if os.Getenv("SCHECK_RECORD") == "" {
		t.Skip("set SCHECK_RECORD=1 to re-record fixtures")
	}
	bin := containers.BuildScheck(t)
	root, _ := filepath.Abs("../..")
	for _, name := range []string{"ubuntu", "fedora"} {
		t.Run(name, func(t *testing.T) {
			c := containers.Start(t, name)
			frag, _, code := containers.Run(t, bin, "sudoers", "--platform", "linux", "--user", "ops")
			if code != 0 {
				t.Fatal("sudoers failed")
			}
			if out, err := c.ExecInput(t, frag, "sh", "-c", "cat > /etc/sudoers.d/scheck && chmod 440 /etc/sudoers.d/scheck"); err != nil {
				t.Fatalf("install: %v %s", err, out)
			}
			dir := filepath.Join(root, "testdata", "fixtures", name)
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			_, errOut, code := containers.Run(t, bin, "ssh", "ops@"+c.Addr(), "--identity", c.Identity, "--known-hosts", c.KnownHosts,
				"--sudo", "--stop-after", "facts", "--out", filepath.Join(t.TempDir(), "facts.json"), "--record-fixtures", dir, "-v")
			if code != 0 {
				t.Fatalf("record: %d\n%s", code, errOut)
			}
			t.Log(errOut)
		})
	}
}
