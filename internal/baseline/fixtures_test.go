package baseline

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// Recorded fixtures (testdata/fixtures/<name>) replay a full phase 1 run
// offline. ubuntu and fedora were recorded with --sudo and the sudoers
// fragment installed; macos was recorded unprivileged on a workstation.
func TestFixtureReplay(t *testing.T) {
	type expect struct {
		elevate runner.Elevation
		ok      map[string]func(t *testing.T, r runner.Result)
		minOK   int
	}
	kv := func(key, want string) func(*testing.T, runner.Result) {
		return func(t *testing.T, r runner.Result) {
			if got := r.Parsed.(map[string]string)[key]; got != want {
				t.Errorf("%s: %s = %q, want %q", r.CheckID, key, got, want)
			}
		}
	}
	nonEmptyLines := func(t *testing.T, r runner.Result) {
		if len(r.Parsed.([]string)) == 0 {
			t.Errorf("%s: no lines", r.CheckID)
		}
	}
	rawMatch := func(re string) func(*testing.T, runner.Result) {
		return func(t *testing.T, r runner.Result) {
			if !regexp.MustCompile(re).MatchString(r.Raw) {
				t.Errorf("%s: raw %q does not match %s", r.CheckID, r.Raw, re)
			}
		}
	}
	fixtures := map[string]expect{
		"ubuntu": {elevate: runner.ElevateSudo, minOK: 20, ok: map[string]func(*testing.T, runner.Result){
			"os.release":             kv("id", "ubuntu"),
			"sshd.config":            kv("passwordauthentication", "no"),
			"accounts.passwd_status": nonEmptyLines,
			"pkg.apt_upgradable":     nonEmptyLines,
			"privesc.sudoers_d":      nonEmptyLines,
			"host.machine_id":        rawMatch(`^[0-9a-f]{32}\s*$`),
		}},
		"fedora": {elevate: runner.ElevateSudo, minOK: 18, ok: map[string]func(*testing.T, runner.Result){
			"os.release":           kv("id", "fedora"),
			"sshd.config":          kv("passwordauthentication", "no"),
			"pkg.dnf_check_update": func(*testing.T, runner.Result) {},
			"privesc.sudoers":      nonEmptyLines,
		}},
		"macos": {elevate: runner.ElevateNone, minOK: 20, ok: map[string]func(*testing.T, runner.Result){
			"os.release":         kv("productname", "macOS"),
			"host.platform_uuid": rawMatch(`^[0-9A-F-]{36}$`),
			"disk.fdesetup":      rawMatch(`FileVault is (On|Off)`),
			"integrity.csrutil":  rawMatch(`enabled|disabled`),
			"fw.global":          rawMatch(`Firewall is (enabled|disabled)`),
			"accounts.users":     nonEmptyLines,
			"net.listeners":      nonEmptyLines,
		}},
	}
	for name, ex := range fixtures {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "fixtures", name)
			if _, err := os.Stat(dir); err != nil {
				t.Skipf("fixture %s not recorded", name)
			}
			fx, err := fixture.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			red, _ := policy.NewRedactor(nil)
			r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red,
				Budgets: policy.DefaultBudgets(), Elevate: ex.elevate}
			plan := Plan(fx.Platform(), nil)
			sheet := Run(context.Background(), r, plan, nil)
			if sheet.Incomplete || len(sheet.Order) != len(plan) {
				t.Fatalf("incomplete: %d/%d", len(sheet.Order), len(plan))
			}
			okCount := 0
			for _, id := range sheet.Order {
				res := sheet.Results[id]
				if res.Status == runner.StatusDenied {
					t.Errorf("%s: denied: %s", id, res.Reason)
				}
				if res.Status == runner.StatusOK {
					okCount++
				}
				if check, want := ex.ok[id]; want {
					if res.Status != runner.StatusOK {
						t.Errorf("%s: %s: %s", id, res.Status, res.Reason)
						continue
					}
					check(t, res)
				}
			}
			if okCount < ex.minOK {
				t.Errorf("only %d checks ok, want >= %d", okCount, ex.minOK)
			}
			// Every plan entry on this platform is exercised by the fixture.
			for _, c := range plan {
				if _, ok := sheet.Results[c.ID]; !ok {
					t.Errorf("%s missing from results", c.ID)
				}
			}
			_ = check.All
		})
	}
}
