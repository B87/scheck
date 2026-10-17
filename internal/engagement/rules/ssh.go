package rules

import (
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// The checks R2 reads beyond net.listeners.
const (
	checkPasswdStatus = "accounts.passwd_status"
	checkPasswd       = "accounts.passwd"
	checkSSHD         = "sshd.config"
)

// Reasons R2 abstains with.
const (
	reasonAccounts   = "unavailable:accounts"
	reasonSSHConfig  = "unavailable:sshd_config"
	reasonSSHListens = "unavailable:sshd_listener"
)

// notCheckedSSH is what every R2 judgment leaves unread.
const notCheckedSSH = "Settings inside Match blocks of sshd_config were not read, and whether PAM accepts an empty " +
	"password (pam_unix nullok, on by default on Debian, Ubuntu and Fedora) was not read"

func init() {
	registry = append(registry, Rule{
		ID: finding.IDEmptyPasswordRemote, Platform: check.Linux,
		Reads: []Read{{ReadCheck, checkPasswdStatus}, {ReadCheck, checkPasswd}, {ReadCheck, checkSSHD}, {ReadCheck, checkListeners}},
		Judge: emptyPasswordRemote,
		Group: "Accounts with no password that SSH lets in", Unbuilt: "this version of scheck has no rule for it on this platform",
		HostDomain: check.DomainSSHD,
		Incomplete: finding.CoverageReason{Reason: reasonSSHListens, Detail: "whether sshd listens beyond this host could not be read"},
	})
}

// condition is one of R2's conditions: it holds, disproves the rule, or is
// unknown with a reason.
type condition struct {
	holds, disproves bool
	reason, detail   string
	excerpt          Excerpt
}

func unknownCondition(reason, detail string) condition {
	return condition{reason: reason, detail: detail}
}

// emptyPasswordRemote is R2, accounts.empty_password_remote: an account
// accounts.empty_password fires for that sshd lets in with no password
// from beyond the host (docs/spec/engagement.md, "The multi-fact rules of
// 0.0.2"). One judgment per host; the accounts are listed.
func emptyPasswordRemote(v *View) []Outcome {
	abstain := func(reason, detail string) []Outcome {
		return []Outcome{{Verdict: Abstained, Reason: reason, NotChecked: []string{detail, notCheckedSSH}}}
	}
	ps, why := v.Fact(checkPasswdStatus)
	if why != "" {
		return abstain(reasonAccounts, "the account password states could not be read ("+why+")")
	}
	pw, whyPasswd := v.Fact(checkPasswd)
	join, _ := finding.DecideJoin(finding.IDEmptyPassword, ps.Parsed, pw.Parsed)
	if join.Verdict.Reason == finding.ReasonWithUnread && whyPasswd != "" {
		join.Verdict.Reason = whyPasswd
	}
	if join.Verdict.Status == finding.NotMatched {
		return []Outcome{{Verdict: Disproved, NotChecked: []string{notCheckedSSH},
			Excerpts: []Excerpt{{checkPasswdStatus, orNone(join.Verdict.Excerpt, "no account with an empty password and a login shell")}}}}
	}
	var candidates []finding.AccountOutcome
	for _, a := range join.Accounts {
		if a.Status == finding.Matched {
			candidates = append(candidates, a)
		}
	}
	if len(candidates) == 0 {
		return abstain(reasonAccounts, "whether an account with an empty password can log in was not established ("+join.Verdict.Reason+")")
	}
	cfg, why := v.Fact(checkSSHD)
	kv, typed := cfg.Parsed.(map[string]string)
	switch {
	case why != "" || !typed:
		return abstain(reasonSSHConfig, "sshd's effective settings could not be read ("+why+")")
	case cfg.Partial:
		return abstain(reasonSSHConfig, "sshd's effective settings were cut short, so a user or group list after the cut could not be ruled out")
	case kv["permitemptypasswords"] == "" || kv["port"] == "":
		return abstain(reasonSSHConfig, "sshd's effective settings were not recognized")
	}
	conds := []condition{emptyAllowed(kv), passwordMethod(kv), methods(kv), lists(kv), sshListens(v, kv)}
	for _, c := range conds {
		if c.disproves {
			return []Outcome{{Verdict: Disproved, Excerpts: []Excerpt{c.excerpt}, NotChecked: []string{notCheckedSSH}}}
		}
	}
	for _, c := range conds {
		if !c.holds {
			return abstain(c.reason, c.detail)
		}
	}
	// sshd applies permitrootlogin to uid 0, whatever the account's name.
	var fired []finding.AccountOutcome
	var undecided []string
	for _, a := range join.Accounts {
		if a.Status == finding.NotAssessed {
			undecided = append(undecided, a.Account+" ("+a.Reason+")")
		}
	}
	rootUnknown := false
	for _, a := range candidates {
		if a.UID == "0" || a.UID == "" {
			switch kv["permitrootlogin"] {
			case "yes":
				// sshd lets it in whatever its uid.
			case "no", "prohibit-password", "without-password", "forced-commands-only":
				if a.UID == "" {
					rootUnknown = true
					undecided = append(undecided, a.Account+" (uid not read)")
				}
				continue
			default:
				rootUnknown = true
				undecided = append(undecided, a.Account+" (permitrootlogin "+kv["permitrootlogin"]+" not recognized)")
				continue
			}
		}
		fired = append(fired, a)
	}
	if len(fired) == 0 {
		if rootUnknown {
			return abstain(reasonSSHConfig, "whether sshd lets these accounts in was not established: "+strings.Join(undecided, ", "))
		}
		if len(undecided) > 0 {
			return abstain(reasonAccounts, "whether these accounts have an empty password and can log in was not established: "+strings.Join(undecided, ", "))
		}
		return []Outcome{{Verdict: Disproved, NotChecked: []string{notCheckedSSH},
			Excerpts: []Excerpt{{checkSSHD, "permitrootlogin " + kv["permitrootlogin"]}}}}
	}
	o := Outcome{Verdict: Fired, NotChecked: []string{notCheckedSSH}}
	if len(undecided) > 0 || ps.Partial {
		// What fired is shown; the list is a lower bound.
		o.Incomplete = true
		line := "Other accounts were not decided"
		if len(undecided) > 0 {
			line += ": " + strings.Join(undecided, ", ")
		}
		o.NotChecked = append(o.NotChecked, line)
	}
	var status, passwd, names []string
	for _, a := range fired {
		names = append(names, a.Account)
		status, passwd = append(status, a.Excerpt), append(passwd, a.WithExcerpt)
	}
	o.Listed = names
	settings := []string{"permitemptypasswords yes", conds[1].excerpt.Text, "authenticationmethods " + kv["authenticationmethods"]}
	if slices.ContainsFunc(fired, func(a finding.AccountOutcome) bool { return a.UID == "0" || a.UID == "" }) {
		settings = append(settings, "permitrootlogin yes")
	}
	o.Excerpts = []Excerpt{{checkPasswdStatus, strings.Join(status, "; ")}, {checkPasswd, strings.Join(passwd, "; ")},
		{checkSSHD, strings.Join(settings, "; ")}, conds[4].excerpt}
	return []Outcome{o}
}

func orNone(s, none string) string {
	if s == "" {
		return none
	}
	return s
}

// emptyAllowed is permitemptypasswords: with no, sshd refuses an empty
// password for every method, PAM's keyboard-interactive included.
func emptyAllowed(kv map[string]string) condition {
	switch v := kv["permitemptypasswords"]; v {
	case "yes":
		return condition{holds: true}
	case "no":
		return condition{disproves: true, excerpt: Excerpt{checkSSHD, "permitemptypasswords no"}}
	default:
		return unknownCondition(reasonSSHConfig, "sshd's permitemptypasswords value was not recognized")
	}
}

// passwordMethod is a method that takes a password: password
// authentication, or keyboard-interactive through PAM (OpenSSH before 8.7
// prints it as challengeresponseauthentication).
func passwordMethod(kv map[string]string) condition {
	kbdKey := "kbdinteractiveauthentication"
	if _, ok := kv[kbdKey]; !ok {
		kbdKey = "challengeresponseauthentication"
	}
	pa, kbd, pam := kv["passwordauthentication"], kv[kbdKey], kv["usepam"]
	for _, v := range []string{pa, kbd, pam} {
		if v != "yes" && v != "no" {
			return unknownCondition(reasonSSHConfig, "sshd's password, keyboard-interactive or PAM setting was not recognized")
		}
	}
	switch {
	case pa == "yes":
		return condition{holds: true, excerpt: Excerpt{checkSSHD, "passwordauthentication yes"}}
	case kbd == "yes" && pam == "yes":
		return condition{holds: true, excerpt: Excerpt{checkSSHD, kbdKey + " yes; usepam yes"}}
	}
	return condition{disproves: true, excerpt: Excerpt{checkSSHD, "passwordauthentication " + pa + "; " + kbdKey + " " + kbd + "; usepam " + pam}}
}

// methods is authenticationmethods: any, or every list requiring a key.
func methods(kv map[string]string) condition {
	v := kv["authenticationmethods"]
	if v == "any" {
		return condition{holds: true}
	}
	if v == "" {
		return unknownCondition(reasonSSHConfig, "sshd's authenticationmethods setting was not shown")
	}
	for alt := range strings.FieldsSeq(v) {
		if !slices.Contains(strings.Split(alt, ","), "publickey") {
			return unknownCondition(reasonSSHConfig, "sshd requires authentication methods ("+v+") this version of scheck does not judge")
		}
	}
	return condition{disproves: true, excerpt: Excerpt{checkSSHD, "authenticationmethods " + v}}
}

// lists is sshd's user and group lists, printed only when set: one limits
// who may sign in, which this version does not compare with the accounts.
func lists(kv map[string]string) condition {
	for _, k := range []string{"allowusers", "denyusers", "allowgroups", "denygroups"} {
		if _, set := kv[k]; set {
			return unknownCondition(reasonSSHConfig, "sshd limits who may sign in ("+k+"), and this version of scheck does not compare it with the accounts")
		}
	}
	return condition{holds: true}
}

// sshListens is sshd listening beyond loopback: a listener owned by sshd
// on any port, or by systemd's socket activation or an owner not shown on
// a port sshd's settings name.
func sshListens(v *View, kv map[string]string) condition {
	f, why := v.Fact(checkListeners)
	recs, typed := f.Parsed.(check.Records)
	if why != "" || !typed {
		return unknownCondition(reasonSSHListens, "the listening sockets could not be read ("+why+")")
	}
	ports := map[int]bool{}
	if p, err := strconv.Atoi(kv["port"]); err == nil {
		ports[p] = true
	}
	// listenaddress prints as "0.0.0.0:22" or "[::]:22".
	if i := strings.LastIndex(kv["listenaddress"], ":"); i >= 0 {
		if n, err := strconv.Atoi(kv["listenaddress"][i+1:]); err == nil {
			ports[n] = true
		}
	}
	ls, portsOK := listeners(recs)
	complete := !f.Partial && portsOK
	for _, l := range ls {
		if l.loopback || l.proto != "tcp" {
			continue
		}
		if !l.known {
			complete = false
			continue
		}
		if l.process == "sshd" || ports[l.port] && (l.process == "systemd" || l.process == "") {
			return condition{holds: true, excerpt: Excerpt{checkListeners, l.excerpt()}}
		}
		// An owner not shown, or a socket activator, may be sshd on a port
		// its settings do not name (an ssh.socket ListenStream override).
		if l.process == "" || slices.Contains([]string{"systemd", "inetd", "xinetd"}, l.process) {
			complete = false
		}
	}
	if !complete {
		return unknownCondition(reasonSSHListens, "whether sshd listens beyond this host could not be established")
	}
	return condition{disproves: true, excerpt: Excerpt{checkListeners, "sshd listens on no address beyond localhost"}}
}
