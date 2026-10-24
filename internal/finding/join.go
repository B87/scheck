package finding

import (
	"fmt"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// JoinPredicate reads a rule's check together with its With check of the
// same host, joined per account (docs/spec/host-collector.md §6.5, "Two
// checks"). Eval, from Predicate, is the reading when the With check gave no
// usable fact: it may still disprove from the first check alone, never fire.
// ReasonWithUnread is a join predicate's reason when it needed the With
// check and had none; the evaluator replaces it with that check's own reason.
const ReasonWithUnread = "with-unread"

type JoinPredicate interface {
	Predicate
	EvalWith(parsed, with any) Verdict
	// AcceptsWith reports whether the predicate can read the With check
	// parsed that way, for the invariants test.
	AcceptsWith(check.ParserKind) bool
}

// StatusWithLoginShell fires when an account's status is Value and its shell
// in the With check (accounts.passwd) lets someone log in: an empty password
// is a weakness only on an account a person or a process can sign in to.
// Each account is decided on its own and the answers combined: one account
// that fires is enough, and the rule is disproved only when every account
// with that status is shown to refuse logins.
type StatusWithLoginShell struct {
	Field string
	Value string
	Known []string
}

func (p StatusWithLoginShell) Accepts(k check.ParserKind) bool     { return check.IsTyped(k) }
func (p StatusWithLoginShell) AcceptsWith(k check.ParserKind) bool { return k == check.ParseAccounts }
func (p StatusWithLoginShell) String() string {
	return fmt.Sprintf("an account with %s = %q and a login shell", p.Field, p.Value)
}

func (p StatusWithLoginShell) Eval(parsed any) Verdict { return p.EvalWith(parsed, nil) }

func (p StatusWithLoginShell) EvalWith(parsed, with any) Verdict {
	return p.Decide(parsed, with).Verdict
}

// AccountOutcome is the join's answer for one account with the status:
// Matched when it has a login shell, NotMatched when its shell refuses
// logins, NotAssessed with a reason when the shell is unknown.
type AccountOutcome struct {
	Account string
	// UID is the account's uid in the With check, "" when not read there.
	UID                  string
	Status               string
	Reason               string
	Excerpt, WithExcerpt string
}

// JoinOutcome is the join decided per account, and the rule's verdict
// over them.
type JoinOutcome struct {
	Accounts []AccountOutcome
	Verdict  Verdict
}

// Decide is EvalWith with each account's answer, so an engagement rule
// that needs the accounts (accounts.empty_password_remote) reads the same
// decision as the posture rule.
func (p StatusWithLoginShell) Decide(parsed, with any) JoinOutcome {
	recs, ok := parsed.(check.Records)
	if !ok {
		return JoinOutcome{Verdict: notAssessed("unexpected-parsed-shape")}
	}
	// `passwd -S -a` always lists root: an empty listing is a broken read,
	// never a host with no accounts.
	if recs.Len() == 0 {
		return JoinOutcome{Verdict: notAssessed("no-records")}
	}
	var out JoinOutcome
	var candidates []check.Record
	unrecognized := false
	for _, rec := range recs.Items {
		v := strings.TrimSpace(rec[p.Field])
		name := strings.TrimSpace(rec[check.FieldName])
		// An account whose state is not recognized may have the status:
		// it is undecided, never left out. A marked name is never echoed.
		undecided := AccountOutcome{Account: name, Status: NotAssessed, Reason: "unrecognized-value"}
		if name == "" || check.HasMarker(name) {
			undecided.Account = "(an account whose name was not read)"
		}
		if v == "" || check.HasMarker(v) || name == "" || check.HasMarker(name) {
			unrecognized = true
			out.Accounts = append(out.Accounts, undecided)
			continue
		}
		if strings.EqualFold(v, p.Value) {
			candidates = append(candidates, rec)
		} else if !known(strings.ToLower(v), p.Known) {
			unrecognized = true
			out.Accounts = append(out.Accounts, undecided)
		}
	}
	shells, shellsOK := with.(check.Records)
	var fired, refused []string
	var withExcerpts []string
	unknown := ""
	for _, rec := range candidates {
		name := strings.TrimSpace(rec[check.FieldName])
		a := AccountOutcome{Account: name, Status: NotAssessed, Excerpt: recordExcerpt(rec)}
		if !shellsOK {
			unknown, a.Reason = ReasonWithUnread, ReasonWithUnread
			out.Accounts = append(out.Accounts, a)
			continue
		}
		acct, last, found := accountNamed(shells, name)
		if !found {
			unknown, a.Reason = "account-not-in-passwd", "account-not-in-passwd"
			out.Accounts = append(out.Accounts, a)
			continue
		}
		if !marked(acct) {
			a.UID = strings.TrimSpace(acct[check.FieldUID])
		}
		shell, hasShell := acct[check.FieldShell]
		switch {
		case !hasShell || marked(acct):
			unknown = "shell-unknown"
		case last && shells.Partial:
			// The line before a truncation marker may be cut anywhere: a
			// shell of "" or "/sbin/sh" may be "/usr/sbin/nologin" cut short.
			unknown = "account-line-cut"
		case check.RefusesLogin(shell):
			refused = append(refused, recordExcerpt(rec))
			a.Status, a.WithExcerpt = NotMatched, recordExcerpt(acct)
		case check.InteractiveShell(shell):
			fired = append(fired, recordExcerpt(rec))
			ex := recordExcerpt(acct)
			if strings.TrimSpace(shell) == "" {
				ex += " shell=(empty, runs /bin/sh)"
			}
			withExcerpts = append(withExcerpts, ex)
			a.Status, a.WithExcerpt = Matched, ex
		default:
			unknown = "unrecognized-shell:" + strings.TrimSpace(shell)
		}
		if a.Status == NotAssessed {
			a.Reason = unknown
		}
		out.Accounts = append(out.Accounts, a)
	}
	if len(fired) > 0 {
		v := matched("recognized-matching-record-with-login-shell", strings.Join(fired, "; "))
		v.WithExcerpt = strings.Join(withExcerpts, "; ")
		out.Verdict = v
		return out
	}
	switch {
	case recs.Partial:
		out.Verdict = notAssessed("partial-output")
	case unrecognized:
		out.Verdict = notAssessed("unrecognized-value")
	case unknown != "":
		out.Verdict = notAssessed(unknown)
	case len(refused) > 0:
		out.Verdict = notMatched("matching-records-refuse-login", strings.Join(refused, "; "))
	default:
		out.Verdict = notMatched("no-matching-record", "")
	}
	return out
}

// DecideJoin is the join of the posture rule that produces id on a host's
// two facts, per account; ok is false when no such rule joins two checks.
// with is nil when its check gave no usable fact.
func DecideJoin(id string, parsed, with any) (JoinOutcome, bool) {
	for _, r := range rules {
		if d, ok := r.When.(StatusWithLoginShell); ok && r.Finding == id && r.With != "" {
			return d.Decide(parsed, with), true
		}
	}
	return JoinOutcome{}, false
}

// accountNamed finds an account's line by name, the first as getpwnam does,
// and says whether it is the listing's last line, which a truncation may have
// cut. A missing line in a truncated listing is unknown to the caller either
// way.
func accountNamed(recs check.Records, name string) (rec check.Record, last, found bool) {
	for i, r := range recs.Items {
		n := r[check.FieldName]
		// NIS compat lines (`+`, `+@group`, `-name`) are not accounts.
		if strings.HasPrefix(n, "+") || strings.HasPrefix(n, "-") {
			continue
		}
		if n == name {
			return r, i == len(recs.Items)-1, true
		}
	}
	return nil, false, false
}

// marked reports whether any field of a record holds a redaction or
// truncation marker, or a piece of one: /etc/passwd is split on colons, which
// a marker contains, so its opening part can land in one field and the rest
// in the next.
func marked(rec check.Record) bool {
	for _, v := range rec {
		if strings.Contains(v, "[REDACTED") || strings.Contains(v, "[TRUNCATED") || check.HasMarker(v) {
			return true
		}
	}
	return false
}
