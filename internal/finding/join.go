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
	recs, ok := parsed.(check.Records)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	// `passwd -S -a` always lists root: an empty listing is a broken read,
	// never a host with no accounts.
	if recs.Len() == 0 {
		return notAssessed("no-records")
	}
	var candidates []check.Record
	unrecognized := false
	for _, rec := range recs.Items {
		v := strings.TrimSpace(rec[p.Field])
		name := strings.TrimSpace(rec[check.FieldName])
		if v == "" || check.HasMarker(v) || name == "" || check.HasMarker(name) {
			unrecognized = true
			continue
		}
		if strings.EqualFold(v, p.Value) {
			candidates = append(candidates, rec)
		} else if !known(strings.ToLower(v), p.Known) {
			unrecognized = true
		}
	}
	shells, shellsOK := with.(check.Records)
	var fired, refused []string
	var withExcerpts []string
	unknown := ""
	for _, rec := range candidates {
		name := strings.TrimSpace(rec[check.FieldName])
		if !shellsOK {
			unknown = ReasonWithUnread
			continue
		}
		acct, last, found := accountNamed(shells, name)
		if !found {
			unknown = "account-not-in-passwd"
			continue
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
		case check.InteractiveShell(shell):
			fired = append(fired, recordExcerpt(rec))
			ex := recordExcerpt(acct)
			if strings.TrimSpace(shell) == "" {
				ex += " shell=(empty, runs /bin/sh)"
			}
			withExcerpts = append(withExcerpts, ex)
		default:
			unknown = "unrecognized-shell:" + strings.TrimSpace(shell)
		}
	}
	if len(fired) > 0 {
		v := matched("recognized-matching-record-with-login-shell", strings.Join(fired, "; "))
		v.WithExcerpt = strings.Join(withExcerpts, "; ")
		return v
	}
	switch {
	case recs.Partial:
		return notAssessed("partial-output")
	case unrecognized:
		return notAssessed("unrecognized-value")
	case unknown != "":
		return notAssessed(unknown)
	case len(refused) > 0:
		return notMatched("matching-records-refuse-login", strings.Join(refused, "; "))
	}
	return notMatched("no-matching-record", "")
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
