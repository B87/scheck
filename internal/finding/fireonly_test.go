package finding

import (
	"slices"
	"testing"

	"github.com/b87/scheck/internal/check"
)

// Any rule that reads a find listing on macOS must be FireOnly: BSD find
// prints a newline in a name raw, so the listing can be forged by a local
// user and must never clear anything. The invariant catches a rule by the
// parser of the check it reads, whatever its predicate.
func TestMacOSFindListingRulesMustBeFireOnly(t *testing.T) {
	saved := slices.Clone(rules)
	t.Cleanup(func() { rules = saved })
	for _, bad := range []Rule{
		{Finding: IDSSHKeyExposed, Check: "creds.home_files", Platform: check.MacOS, When: AnyRecord{}},
		{Finding: IDEnvFileExposed, Check: "creds.app_env_1", Platform: check.Any, When: CredFiles{Kind: CredEnv}},
	} {
		rules = append(slices.Clone(saved), bad)
		found := false
		for _, v := range ValidateRules() {
			found = found || v.Rule == RuleFireOnly
		}
		if !found {
			t.Errorf("%s via %s on %s was not refused", bad.Finding, bad.Check, bad.Platform)
		}
	}
	rules = saved
	for _, v := range ValidateRules() {
		if v.Rule == RuleFireOnly {
			t.Errorf("the compiled-in table breaks it: %v", v)
		}
	}
}
