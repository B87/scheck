package finding

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// Rule turns one fact into one finding when the fact's meaning needs no
// judgement (docs/SPEC.md §7.5). One rule reads one check: a conclusion that
// needs two facts is the model's job in phase 2.
type Rule struct {
	Finding  string         // finding id; the Def supplies title, severity, impact, remediation
	Check    string         // the one check whose fact this rule reads
	Platform check.Platform // macos | linux | any
	When     Predicate
}

// Assessment statuses (docs/SPEC.md §7.5). Only Matched emits a finding, and
// NotMatched means this predicate was disproved by sufficient evidence — not
// that the host or the domain is secure.
const (
	Matched       = "matched"
	NotMatched    = "not_matched"
	NotApplicable = "not_applicable"
	NotAssessed   = "not_assessed"
)

// Assessment is one rule's coverage record: whether it could be evaluated at
// all, and why. Assessments are not findings and never trigger exit 1.
type Assessment struct {
	Observation string `json:"observation,omitempty"`
	Finding     string `json:"finding"`
	Check       string `json:"check"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

// Verdict is a predicate's reading of one fact.
type Verdict struct {
	Status  string
	Reason  string
	Excerpt string
}

func matched(reason, excerpt string) Verdict {
	return Verdict{Status: Matched, Reason: reason, Excerpt: excerpt}
}
func notMatched(reason, excerpt string) Verdict {
	return Verdict{Status: NotMatched, Reason: reason, Excerpt: excerpt}
}
func notAssessed(reason string) Verdict { return Verdict{Status: NotAssessed, Reason: reason} }

// Predicate reads a parsed fact and returns one of three answers, never two.
// The third answer is the point: a predicate may fire only on a complete,
// recognized value proving its condition, and may report "not matched" only
// when the evidence disproves it. Unknown output, a missing field, a redacted
// value or a truncated capture is `not_assessed` — never a pass
// (docs/SPEC.md §7.5).
type Predicate interface {
	Eval(parsed any) Verdict
	// Accepts reports whether this predicate can read a check parsed that
	// way. The invariants test uses it so a rule can never be bound to a
	// check whose shape it cannot read.
	Accepts(check.ParserKind) bool
	String() string
}

// KeyEquals fires when a kv fact's key holds exactly Value. Known lists the
// values this key is understood to take; a value outside it is unrecognized
// evidence, so the rule is not assessed rather than passed.
type KeyEquals struct {
	Key   string
	Value string
	Known []string
}

func (p KeyEquals) Accepts(k check.ParserKind) bool { return k == check.ParseKV }
func (p KeyEquals) String() string                  { return fmt.Sprintf("%s = %q", p.Key, p.Value) }

func (p KeyEquals) Eval(parsed any) Verdict {
	kv, ok := parsed.(map[string]string)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	v, present := kv[p.Key]
	if !present {
		return notAssessed("key-absent")
	}
	if check.HasMarker(v) {
		return notAssessed("value-redacted-or-truncated")
	}
	excerpt := p.Key + " " + v
	got := strings.ToLower(strings.TrimSpace(v))
	if got == strings.ToLower(p.Value) {
		return matched("recognized-matching-value", excerpt)
	}
	if !known(got, p.Known) {
		return notAssessed("unrecognized-value")
	}
	return notMatched("recognized-other-value", excerpt)
}

// RawMatch fires when a raw fact matches Regexp. Requires is what makes the
// output recognizable at all: when it does not match, the tool said something
// this rule does not understand, and an unrecognized answer is not a pass.
type RawMatch struct {
	Regexp   string
	Requires string
}

func (p RawMatch) Accepts(k check.ParserKind) bool { return k == check.ParseRaw }
func (p RawMatch) String() string                  { return "raw matches /" + p.Regexp + "/" }

func (p RawMatch) Eval(parsed any) Verdict {
	s, ok := parsed.(string)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	if check.HasMarker(s) {
		return notAssessed("value-redacted-or-truncated")
	}
	line := strings.Join(strings.Fields(s), " ")
	if p.Requires != "" && !regexp.MustCompile(p.Requires).MatchString(line) {
		return notAssessed("unrecognized-state")
	}
	if regexp.MustCompile(p.Regexp).MatchString(line) {
		return matched("recognized-matching-state", line)
	}
	return notMatched("recognized-other-state", line)
}

// AnyLine fires when any line of a lines fact matches. An existential
// condition can be proved from partial output — a line that matches is a line
// that exists, even if a redaction hid part of it — but its absence cannot, so
// output that carried a marker is not assessed when nothing matched.
type AnyLine struct {
	Regexp string
}

func (p AnyLine) Accepts(k check.ParserKind) bool { return k == check.ParseLines }
func (p AnyLine) String() string                  { return "any line matches /" + p.Regexp + "/" }

func (p AnyLine) Eval(parsed any) Verdict {
	lines, ok := parsed.([]string)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	re := regexp.MustCompile(p.Regexp)
	partial := false
	for _, l := range lines {
		// A line that is only a marker is a record of removed bytes, not a
		// line of output: it must never satisfy an existential predicate.
		if check.IsMarkerLine(l) {
			partial = true
			continue
		}
		if check.HasMarker(l) {
			partial = true // bytes were removed from this line
		}
		if re.MatchString(l) {
			return matched("matching-line", strings.Join(strings.Fields(l), " "))
		}
	}
	if partial {
		return notAssessed("partial-output")
	}
	return notMatched("no-matching-line", "")
}

// FieldEquals fires when any record of a typed shape holds Value in Field.
// Known lists the values the field is understood to take, for the same reason
// KeyEquals has one.
type FieldEquals struct {
	Field string
	Value string
	Known []string
}

func (p FieldEquals) Accepts(k check.ParserKind) bool { return check.IsTyped(k) }
func (p FieldEquals) String() string {
	return fmt.Sprintf("a record with %s = %q", p.Field, p.Value)
}

func (p FieldEquals) Eval(parsed any) Verdict {
	recs, ok := parsed.(check.Records)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	unrecognized := false
	for _, rec := range recs.Items {
		v := strings.TrimSpace(rec[p.Field])
		if v == "" || check.HasMarker(v) {
			unrecognized = true
			continue
		}
		if strings.EqualFold(v, p.Value) {
			return matched("recognized-matching-record", recordExcerpt(rec))
		}
		if !known(strings.ToLower(v), p.Known) {
			unrecognized = true
		}
	}
	if recs.Partial {
		return notAssessed("partial-output")
	}
	if unrecognized {
		return notAssessed("unrecognized-value")
	}
	return notMatched("no-matching-record", "")
}

// AnyRecord fires when a typed shape produced any record at all: the
// existence of the record is the condition ("updates are pending").
type AnyRecord struct{}

func (p AnyRecord) Accepts(k check.ParserKind) bool { return check.IsTyped(k) }
func (p AnyRecord) String() string                  { return "any record" }

func (p AnyRecord) Eval(parsed any) Verdict {
	recs, ok := parsed.(check.Records)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	if recs.Len() > 0 {
		excerpt := recordExcerpt(recs.Items[0])
		if recs.Len() > 1 {
			excerpt += fmt.Sprintf(" (+%d more)", recs.Len()-1)
		}
		return matched("records-present", excerpt)
	}
	if recs.Partial {
		return notAssessed("partial-output")
	}
	return notMatched("no-records", "")
}

// FieldOutside fires when a record holds a recognized value that is not in
// Allowed — an unexpected file mode, for instance. Recognize is the shape a
// readable value has; anything else is not assessed, because "unreadable" is
// neither inside nor outside the allowed set.
type FieldOutside struct {
	Field     string
	Allowed   []string
	Recognize string
}

func (p FieldOutside) Accepts(k check.ParserKind) bool { return check.IsTyped(k) }
func (p FieldOutside) String() string {
	return fmt.Sprintf("%s outside %s", p.Field, strings.Join(p.Allowed, ", "))
}

func (p FieldOutside) Eval(parsed any) Verdict {
	recs, ok := parsed.(check.Records)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	if recs.Len() == 0 {
		return notAssessed("no-records")
	}
	re := regexp.MustCompile(p.Recognize)
	for _, rec := range recs.Items {
		v := strings.TrimSpace(rec[p.Field])
		if v == "" || check.HasMarker(v) || !re.MatchString(v) {
			return notAssessed("unrecognized-value")
		}
		if !known(v, p.Allowed) {
			return matched("recognized-value-outside-expected-set", recordExcerpt(rec))
		}
	}
	return notMatched("recognized-expected-value", recordExcerpt(recs.Items[0]))
}

func known(v string, set []string) bool {
	for _, k := range set {
		if strings.EqualFold(v, k) {
			return true
		}
	}
	return false
}

// excerptFields is the order a record's fields read in an excerpt, so the
// evidence line is stable across runs and diffable.
var excerptFields = []string{
	check.FieldName, check.FieldLabel, check.FieldStatus, check.FieldState,
	check.FieldVersion, check.FieldMode, check.FieldSymbolic, check.FieldUser,
	check.FieldGroup, check.FieldUID, check.FieldShell, check.FieldProtocol,
	check.FieldAddress, check.FieldPort, check.FieldProcess, check.FieldPID,
}

func recordExcerpt(rec check.Record) string {
	var parts []string
	for _, f := range excerptFields {
		if v := rec[f]; v != "" {
			parts = append(parts, f+"="+v)
		}
	}
	if len(parts) == 0 {
		return "(empty record)"
	}
	return strings.Join(parts, " ")
}

// rules is the compiled-in posture rule table (docs/SPEC.md §7.5 seed table).
// Every entry is validated against the check catalog and the finding catalog
// by ValidateRules.
var rules = []Rule{
	{Finding: IDFileVaultOff, Check: "disk.fdesetup", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)FileVault is (On|Off)`, Regexp: `(?i)FileVault is Off`}},
	{Finding: IDSIPDisabled, Check: "integrity.csrutil", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)status:\s*(enabled|disabled)`, Regexp: `(?i)status:\s*disabled`}},
	{Finding: IDGatekeeperDisabled, Check: "integrity.spctl", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)assessments (enabled|disabled)`, Regexp: `(?i)assessments disabled`}},
	{Finding: IDAppFirewallDisabled, Check: "fw.global", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)State = [0-9]+`, Regexp: `(?i)State = 0\b`}},
	{Finding: IDRemoteLoginEnabled, Check: "remote.login", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)remote login:\s*(on|off)`, Regexp: `(?i)remote login:\s*on`}},
	{Finding: IDNTPDisabled, Check: "time.ntp", Platform: check.MacOS,
		When: RawMatch{Requires: `(?i)network time:\s*(on|off)`, Regexp: `(?i)network time:\s*off`}},
	{Finding: IDPasswordAuthEnabled, Check: "sshd.config", Platform: check.Any,
		When: KeyEquals{Key: "passwordauthentication", Value: "yes", Known: []string{"yes", "no"}}},
	{Finding: IDRootLoginEnabled, Check: "sshd.config", Platform: check.Any,
		When: KeyEquals{Key: "permitrootlogin", Value: "yes",
			Known: []string{"yes", "no", "without-password", "prohibit-password", "forced-commands-only"}}},
	{Finding: IDEmptyPassword, Check: "accounts.passwd_status", Platform: check.Linux,
		When: FieldEquals{Field: check.FieldStatus, Value: "NP", Known: []string{"p", "l", "np"}}},
	{Finding: IDShadowPermissions, Check: "accounts.shadow_meta", Platform: check.Linux,
		When: FieldOutside{Field: check.FieldMode, Allowed: []string{"0", "600", "640"}, Recognize: `^[0-7]{1,4}$`}},
	{Finding: IDSELinuxDisabled, Check: "mac.sestatus", Platform: check.Linux,
		When: KeyEquals{Key: "selinux status", Value: "disabled", Known: []string{"enabled", "disabled"}}},
	{Finding: IDAuditdInactive, Check: "log.auditd", Platform: check.Linux,
		When: RawMatch{
			Requires: `(?i)^(active|inactive|failed|activating|deactivating|reloading|unknown)$`,
			Regexp:   `(?i)^(inactive|failed)$`}},
	{Finding: IDNTPUnsynced, Check: "time.timedatectl", Platform: check.Linux,
		When: KeyEquals{Key: "ntpsynchronized", Value: "no", Known: []string{"yes", "no"}}},
	// `pkg.*` in the spec's seed table is one rule per concrete catalog id,
	// not a wildcard: a rule always names the single check it reads.
	{Finding: IDUpdatesPending, Check: "pkg.apt_upgradable", Platform: check.Linux, When: AnyRecord{}},
	{Finding: IDUpdatesPending, Check: "pkg.dnf_check_update", Platform: check.Linux, When: AnyRecord{}},
	{Finding: IDUpdatesPending, Check: "pkg.zypper_lp", Platform: check.Linux, When: AnyRecord{}},
	{Finding: IDUpdatesPending, Check: "pkg.softwareupdate", Platform: check.MacOS, When: AnyRecord{}},
	{Finding: IDWorldWritablePresent, Check: "fs.world_writable", Platform: check.Any, When: AnyLine{Regexp: `\S`}},
}

// Rules returns the posture rule table, sorted by (finding, check) so a
// report's assessment order does not depend on the table's source order.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Finding != out[j].Finding {
			return out[i].Finding < out[j].Finding
		}
		return out[i].Check < out[j].Check
	})
	return out
}

// rulesFor returns the rules that raise a finding id.
func rulesFor(findingID string) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Finding == findingID {
			out = append(out, r)
		}
	}
	return out
}

// RulesFor returns the rules that read a given check id, for `scheck explain`.
func RulesFor(checkID string) []Rule {
	var out []Rule
	for _, r := range Rules() {
		if r.Check == checkID {
			out = append(out, r)
		}
	}
	return out
}
