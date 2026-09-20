package baseline

import (
	"context"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/fixture"
)

func newRunner(fx *fixture.Target) *runner.Runner {
	red, _ := policy.NewRedactor(nil)
	return &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red,
		Budgets: policy.DefaultBudgets(), Elevate: runner.ElevateNone}
}

func TestPlanHonoursDisable(t *testing.T) {
	all := Plan(check.Linux, nil)
	less := Plan(check.Linux, []string{"net.listeners"})
	if len(less) != len(all)-1 {
		t.Fatalf("disable_checks did not subtract: %d vs %d", len(less), len(all))
	}
	for _, c := range less {
		if c.ID == "net.listeners" || c.Platform == check.MacOS {
			t.Errorf("unexpected %s/%s in linux plan", c.ID, c.Platform)
		}
	}
}

func TestRunRecordsUnavailableNeverFatal(t *testing.T) {
	fx := fixture.New(target.Linux,
		fixture.Exec{Argv: []string{"uname", "-s"}, Stdout: "Linux\n"},
		fixture.Exec{Argv: []string{"id", "-u"}, Stdout: "1000\n"},
	)
	sheet := Run(context.Background(), newRunner(fx), Plan(check.Linux, nil), nil)
	if sheet.Incomplete || len(sheet.Order) != len(Plan(check.Linux, nil)) {
		t.Fatalf("sheet: %+v", sheet)
	}
	if sheet.Raw("sys.platform") != "Linux" {
		t.Errorf("platform raw = %q", sheet.Raw("sys.platform"))
	}
	if r, _ := sheet.Get("net.listeners"); r.Status != runner.StatusUnavailable {
		t.Errorf("missing binary must be unavailable: %+v", r)
	}
	if r, _ := sheet.Get("sshd.config"); r.Status != runner.StatusUnavailable || r.Reason != "requires elevated read" {
		t.Errorf("elevated under none: %+v", r)
	}
}

func TestRunStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sheet := Run(ctx, newRunner(fixture.New(target.Linux)), Plan(check.Linux, nil), nil)
	if !sheet.Incomplete || len(sheet.Order) != 0 {
		t.Fatalf("sheet: %+v", sheet)
	}
}

func TestDetectRoot(t *testing.T) {
	if !DetectRoot(context.Background(), newRunner(fixture.New(target.Linux, fixture.Exec{Argv: []string{"id", "-u"}, Stdout: "0\n"}))) {
		t.Error("uid 0 not detected")
	}
	if DetectRoot(context.Background(), newRunner(fixture.New(target.Linux, fixture.Exec{Argv: []string{"id", "-u"}, Stdout: "501\n"}))) {
		t.Error("uid 501 detected as root")
	}
}

// Even a modified plan cannot introduce argv: definitions resolve inside runner.
func TestPlanCannotSupplyExecutableDefinition(t *testing.T) {
	fx := fixture.New(target.Linux, fixture.Exec{Argv: []string{"uname", "-s"}, Stdout: "Linux"})
	plan := []check.Check{{ID: "sys.platform", Argv: []string{"touch", "/tmp/should-never-run"}}, {ID: "unknown.check", Argv: []string{"touch", "/tmp/also-forbidden"}}}
	sheet := Run(context.Background(), newRunner(fx), plan, nil)
	if len(fx.Calls) != 1 || len(fx.Calls[0]) != 2 || fx.Calls[0][0] != "uname" || fx.Calls[0][1] != "-s" {
		t.Fatalf("non-catalog argv: %v", fx.Calls)
	}
	if sheet.Results["unknown.check"].Status != runner.StatusDenied {
		t.Fatal("unknown plan ID accepted")
	}
	for _, r := range sheet.Results {
		if _, ok := sheet.Observations.Get(r.Observation); !ok {
			t.Fatalf("missing baseline observation %+v", r)
		}
	}
}
