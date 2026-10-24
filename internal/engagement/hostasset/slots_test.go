package hostasset

import (
	"context"
	"slices"
	"testing"

	"github.com/b87/scheck/internal/check"
)

// Each declared application folder runs its own catalog slot after the
// baseline, through the runner, and joins the plan; slots past the declared
// folders do not exist in the plan (docs/spec/host-collector.md §3, G5).
func TestAppPathSlotsRunAfterTheBaseline(t *testing.T) {
	c, err := Collect(context.Background(), Options{Target: load(t, "ubuntu"), Elevate: "sudo", Profile: "baseline",
		Version: "test", AppPaths: []string{"/srv/shop", "/srv/api"}})
	if err != nil {
		t.Fatal(err)
	}
	p := c.Planned()
	if !slices.Contains(p, check.AppEnvID(1)) || !slices.Contains(p, check.AppEnvID(2)) || slices.Contains(p, check.AppEnvID(3)) {
		t.Fatalf("planned %v", p)
	}
	if p[len(p)-1] != check.AppEnvID(2) {
		t.Errorf("slots run after the baseline: %v", p[len(p)-3:])
	}
	// The fixture holds no listing of the folders, so the slot is an
	// unavailable fact, never a pass.
	if f, ok := c.Evidence().Facts[check.AppEnvID(1)]; !ok || f.Status == "ok" {
		t.Errorf("slot 1 fact %+v", f)
	}
	// disable_checks narrows a slot like any check.
	d, err := Collect(context.Background(), Options{Target: load(t, "ubuntu"), Elevate: "sudo", Profile: "baseline",
		Version: "test", AppPaths: []string{"/srv/shop"}, DisableChecks: []string{check.AppEnvID(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(d.Planned(), check.AppEnvID(1)) {
		t.Errorf("a disabled slot was planned: %v", d.Planned())
	}
}

// A deny_paths entry on or around the home trees disables the fixed home
// walk, which path policy cannot see into; it only ever narrows.
func TestGuardHomeWalk(t *testing.T) {
	const id = "creds.home_files"
	for _, tc := range []struct {
		deny []string
		want bool
	}{
		{nil, false}, {[]string{"/srv/backups"}, false}, {[]string{"/home/ceo"}, true}, {[]string{"/home"}, true},
		{[]string{"/Users/ana/private"}, true}, {[]string{"/private/var/root/secrets"}, true}, {[]string{"/private/var/www"}, false}, {[]string{"/homework"}, false}, {[]string{"/"}, true},
	} {
		if got := slices.Contains(guardWalks(nil, tc.deny), id); got != tc.want {
			t.Errorf("deny %v: disabled=%v, want %v", tc.deny, got, tc.want)
		}
	}
}
