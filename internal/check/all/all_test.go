package all

import (
	"testing"

	"github.com/b87/scheck/internal/check"
)

// The complete compiled-in catalog must satisfy every invariant. This is
// the test a reviewer reads to believe the command surface is closed.
func TestCatalogInvariants(t *testing.T) {
	all := check.All()
	if len(all) == 0 {
		t.Fatal("empty catalog")
	}
	for _, v := range check.Validate(all) {
		t.Error(v)
	}
}

func TestCatalogShape(t *testing.T) {
	for _, p := range []check.Platform{check.Linux, check.MacOS} {
		if len(check.Baseline(p)) == 0 {
			t.Errorf("%s: empty baseline", p)
		}
		for _, id := range []string{"fs.realpath", "fs.stat", "text.cat", "sys.platform", "sys.uid"} {
			if _, ok := check.Lookup(id, p); !ok {
				t.Errorf("%s: %s missing", p, id)
			}
		}
		for _, c := range check.Baseline(p) {
			if len(c.Params) != 0 {
				t.Errorf("%s: baseline check %s has params; baseline entries must be fully literal", p, c.ID)
			}
			if c.Description == "" {
				t.Errorf("%s: %s has no description", p, c.ID)
			}
		}
	}
}
