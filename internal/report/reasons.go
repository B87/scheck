package report

import (
	"sort"
	"strings"
)

// reasonClass describes one family of "this check produced no fact", with the
// words a person can act on. The runner's reason strings are the input
// (internal/runner); the classes here are the report's contract with the
// reader (docs/SPEC.md §7.6).
type reasonClass struct {
	prefix string // runner reason prefix that selects this class
	title  string // "6 <title>"
	remedy string
	// detailed lists each check with its own reason instead of a flat id
	// list, for classes where the reason differs per check.
	detailed bool
	// match claims a reason the prefix does not, for a condition the runner
	// cannot see: a remote shell reports a missing binary as exit 127, not as
	// an exec error (docs/SPEC.md §4.3 — over SSH the shell runs the command).
	match func(string) bool
	// strip removes prefix from the per-check detail, because the group
	// heading already said it.
	strip bool
}

// reasonClasses is ordered: the first matching prefix wins, and the order is
// also the order the groups are printed in.
var reasonClasses = []reasonClass{
	{prefix: "run deadline exceeded", title: "reached the whole-run deadline", remedy: "re-run with a larger --timeout if the run needs more time."},
	{prefix: "run canceled", title: "were interrupted", remedy: "re-run if the cancellation was unintended."},
	{
		prefix: "requires elevated read",
		title:  "need an elevated read",
		remedy: "re-run with --sudo. On macOS run `sudo -v` first, or install the fragment " +
			"printed by `scheck sudoers` so no password is needed.",
	},
	{
		prefix:   "sudo: ",
		strip:    true,
		title:    "were refused by sudo",
		detailed: true,
		remedy: "install the fragment printed by `scheck sudoers`, or cache the credential " +
			"with `sudo -v` before the run. scheck never prompts for a password.",
	},
	{
		prefix:   "not found: ",
		strip:    true,
		match:    missingBinary,
		title:    "need a command this host does not have",
		detailed: true,
		remedy: "nothing to do unless you expected the tool to be installed; the subsystem " +
			"it inspects was not examined.",
	},
	{
		prefix:   "timeout after ",
		strip:    true,
		title:    "ran out of time",
		detailed: true,
		remedy:   "investigate why the command is slow; --timeout changes the whole-run deadline, not the per-check limit.",
	},
	{
		prefix:   "exec error: ",
		strip:    true,
		title:    "could not be executed on the target",
		detailed: true,
		remedy:   "a transport problem, not a host finding; re-run and check connectivity.",
	},
	{
		prefix:   "exit ",
		title:    "exited with an error",
		detailed: true,
		remedy:   "`scheck explain <check-id>` prints the command; run it by hand to see why.",
	},
	{
		prefix:   "parse error: ",
		strip:    true,
		title:    "produced output scheck could not read",
		detailed: true,
		remedy:   "re-run with -vv to see the output, then report the check id as a bug.",
	},
	{
		prefix:   "extract: ",
		strip:    true,
		title:    "did not contain the expected field",
		detailed: true,
		remedy:   "report the check id and tool version as a bug; full stdout is withheld by the catalog extraction rule.",
	},
	{
		prefix:   "metadata-only path",
		strip:    true,
		title:    "asked for a path scheck may only stat, on a platform with no stat check",
		detailed: true,
		remedy:   "a scheck gap, not a host problem: the platform catalog needs an fs.stat entry.",
	},
	{
		prefix:   "unknown check id",
		title:    "are not in the catalog",
		detailed: false,
		remedy:   "this is a scheck bug: the plan named a check that does not exist.",
	},
}

// missingBinary recognises the shell's own "command not found", which is the
// shape a missing binary takes when a shell runs the command rather than the
// exec failing outright.
func missingBinary(reason string) bool {
	return strings.HasPrefix(reason, "exit 127") || strings.Contains(reason, "command not found")
}

// fallbackClass catches a reason no class claims, including every path-policy
// denial, whose reason already begins with the rule that refused it.
var fallbackClass = reasonClass{
	title:    "were refused by the path policy or an unrecognised reason",
	detailed: true,
	remedy: "the rule that refused is named per check; policy only narrows what may run, " +
		"so nothing on the host needs changing.",
}

type reasonGroup struct {
	reasonClass
	rows []row
}

// groupByReason buckets rows into the reason classes, preserving class order
// and sorting ids inside a bucket.
func groupByReason(rows []row) []reasonGroup {
	byTitle := map[string]*reasonGroup{}
	var order []*reasonGroup
	for _, r := range rows {
		cls := classify(r.fact.Reason)
		g := byTitle[cls.title]
		if g == nil {
			g = &reasonGroup{reasonClass: cls}
			byTitle[cls.title] = g
			order = append(order, g)
		}
		g.rows = append(g.rows, r)
	}
	sort.SliceStable(order, func(i, j int) bool {
		return classRank(order[i].title) < classRank(order[j].title)
	})
	out := make([]reasonGroup, 0, len(order))
	for _, g := range order {
		sort.Slice(g.rows, func(i, j int) bool { return g.rows[i].id < g.rows[j].id })
		out = append(out, *g)
	}
	return out
}

func classify(reason string) reasonClass {
	for _, c := range reasonClasses {
		if c.prefix != "" && strings.HasPrefix(reason, c.prefix) {
			return c
		}
		if c.match != nil && c.match(reason) {
			return c
		}
	}
	return fallbackClass
}

func classRank(title string) int {
	for i, c := range reasonClasses {
		if c.title == title {
			return i
		}
	}
	return len(reasonClasses)
}

// reasonDetail is what a detailed group prints next to a check id: the reason
// without the prefix the group heading already said.
func reasonDetail(reason string) string {
	cls := classify(reason)
	if cls.strip && strings.HasPrefix(reason, cls.prefix) {
		if rest := strings.TrimSpace(strings.TrimPrefix(reason, cls.prefix)); rest != "" {
			return rest
		}
	}
	if reason == "" {
		return "no reason recorded"
	}
	return reason
}
