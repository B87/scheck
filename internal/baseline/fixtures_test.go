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
	// Typed shapes (docs/SPEC.md §3) must survive a real recorded capture,
	// not just a hand-written line: atLeast asserts the record count and that
	// the named field is populated on every record.
	atLeast := func(n int, field string) func(*testing.T, runner.Result) {
		return func(t *testing.T, r runner.Result) {
			recs, ok := r.Parsed.(check.Records)
			if !ok {
				t.Fatalf("%s: parsed %T, want typed records", r.CheckID, r.Parsed)
			}
			if recs.Len() < n {
				t.Errorf("%s: %d records, want >= %d", r.CheckID, recs.Len(), n)
			}
			for _, rec := range recs.Items {
				if rec[field] == "" {
					t.Errorf("%s: record without %s: %v", r.CheckID, field, rec)
				}
			}
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
			"accounts.passwd_status": atLeast(10, check.FieldStatus),
			"pkg.apt_upgradable":     atLeast(0, check.FieldName),
			"privesc.sudoers_d":      nonEmptyLines,
			"host.machine_id":        rawMatch(`^[0-9a-f]{32}\s*$`),
			"accounts.passwd":        atLeast(10, check.FieldShell),
			"accounts.shadow_meta":   atLeast(1, check.FieldMode),
			"persist.units":          atLeast(5, check.FieldState),
			"net.listeners":          atLeast(2, check.FieldPort),
		}},
		"fedora": {elevate: runner.ElevateSudo, minOK: 18, ok: map[string]func(*testing.T, runner.Result){
			"os.release":           kv("id", "fedora"),
			"sshd.config":          kv("passwordauthentication", "no"),
			"pkg.dnf_check_update": atLeast(5, check.FieldVersion),
			"privesc.sudoers":      nonEmptyLines,
		}},
		"macos": {elevate: runner.ElevateNone, minOK: 20, ok: map[string]func(*testing.T, runner.Result){
			"os.release":         kv("productname", "macOS"),
			"host.platform_uuid": rawMatch(`^[0-9A-F-]{36}$`),
			"disk.fdesetup":      rawMatch(`FileVault is (On|Off)`),
			"persist.launchctl":  atLeast(20, check.FieldLabel),
			"pkg.softwareupdate": atLeast(1, check.FieldName),
			"integrity.csrutil":  rawMatch(`enabled|disabled`),
			"fw.global":          rawMatch(`Firewall is (enabled|disabled)`),
			"accounts.users":     atLeast(20, check.FieldUID),
			"net.listeners":      atLeast(1, check.FieldPort),
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
