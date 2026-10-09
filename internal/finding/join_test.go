package finding

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// The empty-password rule reads `passwd -S -a` and /etc/passwd, and decides
// each account with an empty password by its shell (docs/spec/host-collector.md
// §6.5, "Two checks"). The fixtures are the security consultant's E5a list:
// F fires, D is disproved, I is insufficient evidence.
func TestEmptyPasswordNeedsALoginShell(t *testing.T) {
	const (
		ubuntu = "root:x:0:0:root:/root:/bin/bash\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n" +
			"ops:x:1000:1000::/home/ops:/bin/bash\n"
		fedora = "root:x:0:0:root:/root:/bin/bash\nsync:x:5:0:sync:/sbin:/bin/sync\nhalt:x:7:0:halt:/sbin:/sbin/halt\n"
	)
	type tc struct {
		name, status string
		passwd       *string // nil: accounts.passwd absent from the sheet
		want, reason string
		excerpt      []string // each must be in the evidence
		notExcerpt   string   // must not be
	}
	str := func(s string) *string { return &s }
	cases := []tc{
		{name: "F1 a login shell", status: "root L\nops NP", passwd: str(ubuntu), want: Matched,
			excerpt: []string{"name=ops status=NP", "shell=/bin/bash"}},
		{name: "F2 root", status: "root NP", passwd: str(ubuntu), want: Matched, excerpt: []string{"name=root"}},
		{name: "F3 an empty shell field runs /bin/sh", status: "root L\nsvc NP", passwd: str(ubuntu + "svc:x:1002:1002::/home/svc:\n"), want: Matched},
		{name: "F4 fires on a truncated status listing", status: "root L\nops NP\n[TRUNCATED:900 bytes]", passwd: str(ubuntu), want: Matched},
		{name: "F5 fires on the account it can decide", status: "ops NP\nx NP", passwd: str(ubuntu + "x:x:1003:1003::/:/opt/menu\n"),
			want: Matched, excerpt: []string{"name=ops"}, notExcerpt: "name=x "},
		{name: "F6 every account is evidence", status: "ops NP\ndeploy NP", passwd: str(ubuntu + "deploy:x:1001:1001::/home/deploy:/usr/bin/zsh\n"),
			want: Matched, excerpt: []string{"name=ops", "name=deploy"}},
		{name: "D1 nologin, the golden's real case", status: "root L\nbackup NP", passwd: str(ubuntu), want: NotMatched, reason: "matching-records-refuse-login"},
		{name: "D2 every account locked", status: "root L\nbackup L\nops P", passwd: str(ubuntu), want: NotMatched, reason: "no-matching-record"},
		{name: "D3 single-command shells", status: "root L\nhalt NP\nsync NP", passwd: str(fedora), want: NotMatched},
		{name: "D4 libuser's spellings", status: "root LK\nops PS", passwd: str(ubuntu), want: NotMatched},
		{name: "D5 no empty password needs no shells", status: "root L\nops P", passwd: nil, want: NotMatched},
		{name: "I1 shells unread", status: "root L\nbackup NP", passwd: nil, want: NotAssessed, reason: "with-check-not-run"},
		{name: "I2 the account's line truncated away", status: "backup NP", passwd: str("root:x:0:0:root:/root:/bin/bash\n[TRUNCATED:900 bytes]"), want: NotAssessed, reason: "account-not-in-passwd"},
		{name: "I3 a marker in the account's line", status: "backup NP", passwd: str("backup:x:34:34:backup:/var/backups:[REDACTED:x:17 bytes]\n"), want: NotAssessed, reason: "account-not-in-passwd"},
		{name: "I3b a marker split across fields never shifts the shell", status: "alice NP",
			passwd: str("alice:[REDACTED:kv-secret:1 bytes]:1000:1000:/bin/false:/home/alice:/bin/bash\n"), want: NotAssessed, reason: "account-not-in-passwd"},
		{name: "I3c an eighth field is not an account", status: "alice NP",
			passwd: str("alice:x:1000:1000::/home/alice:/usr/sbin/nologin:extra\n"), want: NotAssessed, reason: "account-not-in-passwd"},
		{name: "I4 the account has no line", status: "backup NP", passwd: str("root:x:0:0:root:/root:/bin/bash\n"), want: NotAssessed, reason: "account-not-in-passwd"},
		{name: "I5 an unrecognized shell", status: "x NP", passwd: str("x:x:1003:1003::/:/opt/vendor/menu\n"), want: NotAssessed, reason: "unrecognized-shell:/opt/vendor/menu"},
		{name: "I6 an empty listing is a broken read", status: "", passwd: str(ubuntu), want: NotAssessed, reason: "no-records"},
		{name: "I7 truncated with nothing found", status: "root L\n[TRUNCATED:900 bytes]", passwd: str(ubuntu), want: NotAssessed, reason: "partial-output"},
		{name: "I8 one cleared, one unknown", status: "backup NP\nx NP", passwd: str(ubuntu + "x:x:1003:1003::/:/opt/menu\n"), want: NotAssessed},
		{name: "I10 an unknown status", status: "root L\nops ?", passwd: str(ubuntu), want: NotAssessed, reason: "unrecognized-value"},
		{name: "the account's line cut by truncation", status: "bob NP", passwd: str("root:x:0:0:root:/root:/bin/bash\nbob:x:1001:1001::/home/bob:\n[TRUNCATED:900 bytes]"),
			want: NotAssessed, reason: "account-line-cut"},
		{name: "a shell cut to look interactive", status: "halt NP", passwd: str("halt:x:7:0:halt:/sbin:/sbin/sh\n[TRUNCATED:900 bytes]"),
			want: NotAssessed, reason: "account-line-cut"},
		{name: "an empty shell says why it fired", status: "svc NP", passwd: str("svc:x:1002:1002::/home/svc:\n"),
			want: Matched, excerpt: []string{"shell=(empty, runs /bin/sh)"}},
		{name: "a short record names no shell", status: "ops NP", passwd: str("ops 1000\n"), want: NotAssessed, reason: "shell-unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := map[string]string{"accounts.passwd_status": c.status}
			if c.passwd != nil {
				raw["accounts.passwd"] = *c.passwd
			}
			res := Evaluate(Input{Sheet: sheet(t, check.Linux, raw)})
			a, _ := assessmentFor(res, IDEmptyPassword, "accounts.passwd_status")
			if a.Status != c.want || (c.reason != "" && a.Reason != c.reason) {
				t.Fatalf("got %s (%s), want %s (%s)", a.Status, a.Reason, c.want, c.reason)
			}
			var ev []string
			for _, f := range res.Findings {
				if f.ID == IDEmptyPassword {
					for _, e := range f.Evidence {
						ev = append(ev, e.Check+": "+e.Excerpt)
					}
				}
			}
			all := strings.Join(ev, "\n")
			for _, want := range c.excerpt {
				if !strings.Contains(all, want) {
					t.Errorf("evidence lacks %q:\n%s", want, all)
				}
			}
			if c.notExcerpt != "" && strings.Contains(all+" ", c.notExcerpt) {
				t.Errorf("evidence names %q:\n%s", c.notExcerpt, all)
			}
		})
	}
}

// A denied or disabled /etc/passwd read leaves an empty password undecided,
// and the reason is that check's, so coverage names it: the rule never fires
// without a shell and never passes an NP account. The denied result carries
// records, so only the status keeps the rule from reading them.
func TestEmptyPasswordWithShellsDeniedOrDisabled(t *testing.T) {
	bash := "ops:x:1000:1000::/home/ops:/bin/bash\n"
	fs := sheet(t, check.Linux, map[string]string{"accounts.passwd_status": "root L\nops NP", "accounts.passwd": bash})
	w := fs.Results["accounts.passwd"]
	w.Status, w.ReasonCode, w.Observation = runner.StatusDenied, "path_denied", "accounts.passwd#1"
	fs.Results["accounts.passwd"] = w
	a, _ := assessmentFor(Evaluate(Input{Sheet: fs}), IDEmptyPassword, "accounts.passwd_status")
	if a.Status != NotAssessed || a.Reason != "with-check-denied:path_denied" || a.With != "accounts.passwd" || a.WithObservation != "accounts.passwd#1" {
		t.Fatalf("denied shells: %+v", a)
	}
	fs = sheet(t, check.Linux, map[string]string{"accounts.passwd_status": "root L\nops NP", "accounts.passwd": bash})
	a, _ = assessmentFor(Evaluate(Input{Sheet: fs, Disabled: []string{"accounts.passwd"}}), IDEmptyPassword, "accounts.passwd_status")
	if a.Status != NotAssessed || a.Reason != "with-check-disabled-by-config" {
		t.Fatalf("disabled shells: %+v", a)
	}
	// With no account lacking a password, the shells are not needed.
	fs = sheet(t, check.Linux, map[string]string{"accounts.passwd_status": "root L\nops P"})
	if a, _ := assessmentFor(Evaluate(Input{Sheet: fs, Disabled: []string{"accounts.passwd"}}), IDEmptyPassword, "accounts.passwd_status"); a.Status != NotMatched {
		t.Fatalf("nothing to join: %+v", a)
	}
}

// Skipping either check leaves the rule not assessed, so explain lists it
// under both.
func TestRulesForNamesTheSecondCheck(t *testing.T) {
	for _, id := range []string{"accounts.passwd_status", "accounts.passwd"} {
		found := false
		for _, r := range RulesFor(id) {
			found = found || r.Finding == IDEmptyPassword
		}
		if !found {
			t.Errorf("RulesFor(%s) lacks the empty-password rule", id)
		}
	}
}
