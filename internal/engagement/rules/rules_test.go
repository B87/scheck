package rules

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
)

// fakeFacts is a host's facts by check id; a missing id was not run.
type fakeFacts struct {
	platform check.Platform
	facts    map[string]finding.Fact
	why      map[string]string
	partial  bool
}

func (f fakeFacts) Platform() check.Platform { return f.platform }

func (f fakeFacts) Fact(id string) (finding.Fact, string) {
	if why, ok := f.why[id]; ok {
		return finding.Fact{Check: id, Observation: id + "#1"}, why
	}
	fact, ok := f.facts[id]
	if !ok {
		return finding.Fact{Check: id}, "check-not-run"
	}
	fact.Check, fact.Observation = id, id+"#1"
	fact.Partial = fact.Partial || f.partial
	return fact, ""
}

// ss is a net.listeners record set: "proto addr:port process" per line,
// the process "-" when the owner is not shown.
func ss(lines ...string) finding.Fact {
	recs := check.Records{Kind: check.ParseListeners, Items: []check.Record{}}
	for _, l := range lines {
		f := strings.Fields(l)
		i := strings.LastIndex(f[1], ":")
		state := "LISTEN"
		if f[0] == "udp" {
			state = "UNCONN"
		}
		rec := check.Record{check.FieldProtocol: f[0], check.FieldState: state,
			check.FieldAddress: strings.Trim(f[1][:i], "[]"), check.FieldPort: f[1][i+1:]}
		if f[2] != "-" {
			rec[check.FieldProcess] = f[2]
		}
		recs.Items = append(recs.Items, rec)
	}
	return finding.Fact{Parsed: recs}
}

// noFirewall is a Linux host with no host firewall: ufw and firewalld
// absent, an empty nftables ruleset, the nf_tables backend.
func noFirewall(listeners finding.Fact) fakeFacts {
	return fakeFacts{platform: check.Linux,
		facts: map[string]finding.Fact{checkListeners: listeners, checkNFT: {Parsed: ""},
			checkBackend: {Parsed: "/usr/sbin/xtables-nft-multi\n"}, checkOSRelease: {Parsed: map[string]string{"ID": "ubuntu"}}},
		why: map[string]string{checkUFW: "check-unavailable:command_missing", checkFirewalld: "check-unavailable:command_missing"}}
}

// withUFW is a Linux host whose ufw prints lines.
func withUFW(listeners finding.Fact, lines ...string) fakeFacts {
	f := noFirewall(listeners)
	delete(f.why, checkUFW)
	f.facts[checkUFW] = finding.Fact{Parsed: lines}
	return f
}

const (
	pgAll      = "tcp 0.0.0.0:5432 postgres"
	sshAll     = "tcp 0.0.0.0:22 sshd"
	ufwActive  = "Status: active"
	ufwDeny    = "Default: deny (incoming), allow (outgoing), disabled (routed)"
	ufwAllowIn = "Default: allow (incoming), allow (outgoing), disabled (routed)"
)

type fixture struct {
	name    string
	host    Host
	subject string // "" for the host
	verdict string
	reason  string
}

func host(f fakeFacts, services ...Service) Host {
	return Host{Asset: "host:db1:22", Name: "db1", Facts: f, Context: Context{Services: services}}
}

func with(f fakeFacts, edit func(fakeFacts)) fakeFacts { edit(f); return f }

var dbFixtures = []fixture{
	{"no host firewall", host(noFirewall(ss(pgAll, sshAll)), Service{Port: 5432, Proto: "tcp", Audience: "lan", Key: "assets.db1.context.expected_services[0]"}),
		"5432/tcp", Fired, ""},
	{"ufw allows it from anywhere", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "To Action From", "-- ------ ----", "5432/tcp ALLOW IN Anywhere")),
		"5432/tcp", Fired, ""},
	{"ufw allows everything in", host(withUFW(ss(pgAll), ufwActive, ufwAllowIn)), "5432/tcp", Fired, ""},
	{"ufw rate-limits a range", host(withUFW(ss("tcp [::]:6379 redis-server"), ufwActive, ufwDeny, "6000:7000/tcp (v6) LIMIT IN Anywhere (v6)")),
		"6379/tcp", Fired, ""},
	{"ufw allows a udp memcached", host(withUFW(ss("udp 0.0.0.0:11211 memcached"), ufwActive, ufwDeny, "11211 ALLOW IN Anywhere")),
		"11211/udp", Fired, ""},
	{"only on localhost", host(noFirewall(ss("tcp 127.0.0.1:5432 postgres", "tcp [::1]:5432 postgres", sshAll))), "", Disproved, ""},
	{"ufw denies by default", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere")), "5432/tcp", Disproved, ""},
	{"ufw allows only one network", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "5432/tcp ALLOW IN 10.0.0.0/8")), "5432/tcp", Disproved, ""},
	{"ufw denies before it allows", host(withUFW(ss(pgAll), ufwActive, ufwAllowIn, "5432 DENY IN Anywhere")), "5432/tcp", Disproved, ""},
	{"java on Elasticsearch's port, no firewall", host(noFirewall(ss("tcp 0.0.0.0:9200 java"))), "9200/tcp", Fired, ""},
	{"java on the transport port, ufw denies", host(withUFW(ss("tcp 0.0.0.0:9300 java"), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere")), "9300/tcp", Disproved, ""},
	{"java on loopback", host(noFirewall(ss("tcp 127.0.0.1:9200 java"))), "", Disproved, ""},
	{"java on another port", host(noFirewall(ss("tcp 0.0.0.0:8080 java"))), "", Disproved, ""},
	{"owner not shown on Elasticsearch's port", host(noFirewall(ss("tcp 0.0.0.0:9200 -"))), "9200/tcp", Abstained, reasonListenerOwner},
	{"Docker publishes Elasticsearch's port", host(noFirewall(ss("tcp 0.0.0.0:9200 docker-proxy"))), "9200/tcp", Abstained, reasonContainerPort},
	{"java over udp on Elasticsearch's port", host(noFirewall(ss("udp 0.0.0.0:9300 java"))), "", Disproved, ""},
	{"another program on a database port", host(noFirewall(ss("tcp 0.0.0.0:9000 php-fpm8.2", sshAll))), "", Disproved, ""},
	{"listeners not read", host(with(noFirewall(ss()), func(f fakeFacts) { f.why[checkListeners] = "check-denied:sudo_refused" })), "", Abstained, reasonListeners},
	{"firewalld running", host(with(noFirewall(ss(pgAll)), func(f fakeFacts) {
		delete(f.why, checkFirewalld)
		f.facts[checkFirewalld] = finding.Fact{Parsed: "running\n"}
	})), "5432/tcp", Abstained, "unavailable:firewall_firewalld"},
	{"nftables holds rules", host(with(noFirewall(ss(pgAll)), func(f fakeFacts) { f.facts[checkNFT] = finding.Fact{Parsed: "table inet filter {\n}\n"} })),
		"5432/tcp", Abstained, "unavailable:firewall_nft"},
	{"legacy iptables", host(with(noFirewall(ss(pgAll)), func(f fakeFacts) { f.facts[checkBackend] = finding.Fact{Parsed: "/usr/sbin/xtables-legacy-multi\n"} })),
		"5432/tcp", Abstained, "unavailable:firewall_backend"},
	{"iptables in /sbin on Alpine", host(with(noFirewall(ss(pgAll)), func(f fakeFacts) {
		f.facts[checkBackend] = finding.Fact{Parsed: ""}
		f.facts[checkOSRelease] = finding.Fact{Parsed: map[string]string{"id": "alpine"}}
	})), "5432/tcp", Abstained, "unavailable:firewall_backend"},
	{"Docker publishes it", host(noFirewall(ss("tcp 0.0.0.0:5432 docker-proxy"))), "5432/tcp", Abstained, reasonContainerPort},
	{"owner not shown on a database port", host(noFirewall(ss("tcp 0.0.0.0:5432 -"))), "5432/tcp", Abstained, reasonListenerOwner},
	{"owner not shown elsewhere", host(noFirewall(ss("tcp 0.0.0.0:8443 -"))), "", Abstained, reasonListenerOwner},
	{"a ufw rule bound to an interface", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "5432/tcp on wg0 ALLOW IN Anywhere")),
		"5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"a ufw line in no shape ufw prints", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "PostgreSQL ALLOW IN Anywhere")), "5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"a logged ufw rule", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "5432/tcp                   ALLOW IN    Anywhere                   (log)")),
		"5432/tcp", Fired, ""},
	{"a logged IPv6 ufw rule", host(withUFW(ss("tcp [::]:5432 postgres", "tcp 0.0.0.0:5432 postgres"), ufwActive, ufwDeny,
		"5432/tcp (v6)              ALLOW IN    Anywhere (v6)              (log-all)")), "5432/tcp", Fired, ""},
	{"a commented ufw rule", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "5432/tcp ALLOW IN Anywhere # replica sync")), "5432/tcp", Fired, ""},
	{"an application profile before the port", host(withUFW(ss(pgAll), ufwActive, ufwDeny,
		"22/tcp (OpenSSH)           ALLOW IN    Anywhere", "22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)", "5432/tcp ALLOW IN Anywhere")),
		"5432/tcp", Fired, ""},
	{"a deny to localhost only", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "127.0.0.1 5432/tcp DENY IN Anywhere", "5432/tcp ALLOW IN Anywhere")),
		"5432/tcp", Fired, ""},
	{"a deny to one address under an allow default", host(withUFW(ss(pgAll), ufwActive, ufwAllowIn, "10.0.0.5 5432/tcp DENY IN Anywhere")),
		"5432/tcp", Fired, ""},
	{"an allow to one of the host's addresses", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "203.0.113.5 5432/tcp ALLOW IN Anywhere")),
		"5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"ufw allows by source port alone", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "Anywhere                   ALLOW IN    53")), "5432/tcp", Fired, ""},
	{"ufw allows the port by source port alone", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "5432/tcp ALLOW IN 53/tcp")), "5432/tcp", Fired, ""},
	{"ufw allows udp by source port alone", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "Anywhere                   ALLOW IN    53/udp")), "5432/tcp", Disproved, ""},
	{"ufw denies by source port alone", host(withUFW(ss(pgAll), ufwActive, ufwAllowIn, "5432/tcp DENY IN 53/tcp")), "5432/tcp", Fired, ""},
	{"a network with a protocol", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "Anywhere ALLOW IN 192.168.1.0/24/tcp", "10.0.0.0/24/tcp DENY IN Anywhere")),
		"5432/tcp", Disproved, ""},
	{"another protocol and a profile named with on", host(withUFW(ss(pgAll), ufwActive, ufwDeny, "Anywhere/gre ALLOW IN Anywhere/gre",
		"32400/tcp (Plex on LAN)    ALLOW IN    Anywhere", "5432/tcp ALLOW IN Anywhere")), "5432/tcp", Fired, ""},
	{"an IPv6 source makes an IPv6 rule", host(withUFW(ss("tcp [::]:5432 postgres", "tcp 0.0.0.0:5432 postgres"), ufwActive, ufwDeny, "5432/tcp ALLOW IN 2001:db8::/32")),
		"5432/tcp", Disproved, ""},
	{"ufw lists no IPv6 rule", host(withUFW(ss("tcp 0.0.0.0:5432 postgres", "tcp [::]:5432 postgres"), ufwActive, ufwDeny, "5432/tcp ALLOW IN 10.0.0.0/8")),
		"5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"ufw output cut short", host(with(withUFW(ss(pgAll), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere"), func(f fakeFacts) {
		u := f.facts[checkUFW]
		u.Partial = true
		f.facts[checkUFW] = u
	})), "5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"ufw status unrecognized", host(withUFW(ss(pgAll), "Estado: activo")), "5432/tcp", Abstained, "unavailable:firewall_ufw"},
	{"listeners cut short", host(with(noFirewall(ss(sshAll)), func(f fakeFacts) {
		fact := f.facts[checkListeners]
		fact.Partial = true
		f.facts[checkListeners] = fact
	})), "", Abstained, ""},
}

// verdictOn is the rule's judgment on subject ("" for the host).
func verdictOn(t *testing.T, js []finding.Judgment, subject string) finding.Judgment {
	t.Helper()
	for _, j := range js {
		if j.Subject.Key == subject {
			return j
		}
	}
	t.Fatalf("no judgment on %q: %+v", subject, js)
	return finding.Judgment{}
}

func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range All() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return Rule{}
}

// Every rule fires, is disproved and abstains on its fixtures, reads only
// what it declares, and reads everything it declares in some fixture
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2").
func TestRulesFireDisproveAndAbstain(t *testing.T) {
	if v := Validate(All()); len(v) > 0 {
		t.Fatalf("the rule table breaks its invariants: %v", v)
	}
	fixtures := map[string][]fixture{finding.IDDBListensUnfiltered: dbFixtures, finding.IDEmptyPasswordRemote: sshFixtures, finding.IDSvcListensBeyond: svcFixtures, finding.IDSensitiveListens: sensitiveFixtures,
		finding.IDPHPFixMissing: phpFixtures, finding.IDNodeFixMissing: nodeFixFixtures, finding.IDNodeLineUnsupported: nodeLineFixtures}
	for _, r := range All() {
		fs := fixtures[r.ID]
		used := map[Read]bool{}
		verdicts := map[string]bool{}
		for _, fx := range fs {
			v := &View{host: fx.host, rule: r}
			outcomes := r.Judge(v)
			if len(v.undeclared) > 0 {
				t.Errorf("%s/%s reads what it did not declare: %v", r.ID, fx.name, v.undeclared)
			}
			for _, u := range v.used {
				used[u] = true
			}
			js, _ := run(r, fx.host)
			j := verdictOn(t, js, fx.subject)
			if j.Verdict != fx.verdict || fx.reason != "" && j.Reason != fx.reason {
				t.Errorf("%s/%s: %s (%s), want %s (%s): %+v", r.ID, fx.name, j.Verdict, j.Reason, fx.verdict, fx.reason, outcomes)
			}
			verdicts[j.Verdict] = true
		}
		for _, want := range []string{Fired, Disproved, Abstained} {
			if !verdicts[want] {
				t.Errorf("%s has no %s fixture", r.ID, want)
			}
		}
		for _, read := range r.Reads {
			if !used[read] {
				t.Errorf("%s declares %s:%s, which no fixture reads", r.ID, read.Kind, read.Name)
			}
		}
	}
}

// A read known to be incomplete proves presence, never absence: with every
// fact marked partial, no fixture is disproved; with the listeners alone
// partial, what fired still fires.
func TestAnIncompleteReadNeverDisproves(t *testing.T) {
	for _, fx := range append(slices.Clone(sshFixtures), svcFixtures...) {
		f := fx.host.Facts.(fakeFacts)
		f.partial = true
		h := fx.host
		h.Facts = f
		js, _ := run(ruleByID(t, finding.IDEmptyPasswordRemote), h)
		svc, _ := run(ruleByID(t, finding.IDSvcListensBeyond), h)
		js = append(js, svc...)
		for _, j := range js {
			if j.Verdict == Disproved {
				t.Errorf("%s: disproved on an incomplete read: %+v", fx.name, j)
			}
		}
	}
	r := ruleByID(t, finding.IDDBListensUnfiltered)
	for _, fx := range dbFixtures {
		f := fx.host.Facts.(fakeFacts)
		f.partial = true
		h := fx.host
		h.Facts = f
		js, _ := run(r, h)
		for _, j := range js {
			if j.Verdict == Disproved {
				t.Errorf("%s: disproved on an incomplete read: %+v", fx.name, j)
			}
		}
		if fx.verdict != Fired {
			continue
		}
		f = fx.host.Facts.(fakeFacts)
		f.facts = maps.Clone(f.facts)
		l := f.facts[checkListeners]
		l.Partial = true
		f.facts[checkListeners] = l
		h.Facts = f
		js, _ = run(r, h)
		if verdictOn(t, js, fx.subject).Verdict != Fired {
			t.Errorf("%s: an incomplete listener read withdrew what fired", fx.name)
		}
	}
}

// A fired judgment cites the listener and each firewall fact it rests on,
// raises on a contradicted declaration, and names what it did not read.
func TestAFiredDatabaseCitesWhatItRestsOn(t *testing.T) {
	res := Judge([]Host{dbFixtures[0].host})["host:db1:22"]
	j := verdictOn(t, res.Judged, "5432/tcp")
	var checks []string
	for _, f := range j.Facts {
		checks = append(checks, f.Check)
		if f.Observation != f.Check+"#1" || f.Excerpt == "" {
			t.Errorf("fact %+v has no observation or excerpt", f)
		}
	}
	if want := []string{checkListeners, checkUFW, checkFirewalld, checkNFT, checkBackend}; !slices.Equal(checks, want) {
		t.Errorf("cites %v, want %v", checks, want)
	}
	if !j.Has("contradiction") || !slices.Contains(j.Sources, "assets.db1.context.expected_services[0]") {
		t.Errorf("no contradiction from the declared audience: %+v", j)
	}
	if j.Subject.Label != "postgres" || len(j.NotChecked) < 2 {
		t.Errorf("subject or not-checked wrong: %+v", j)
	}
	if len(res.Coverage) != 3 || res.Coverage[0].Area != finding.AreaData || len(res.Coverage[0].Groups) != 1 || res.Coverage[1].Area != finding.AreaHosts || res.Coverage[2].Area != finding.AreaExternal {
		t.Errorf("coverage %+v", res.Coverage)
	}
}

// A host the rule is not built for gets no verdict, and its coverage says
// it was not judged.
func TestAMacOSHostIsNotJudged(t *testing.T) {
	res := Judge([]Host{{Asset: "host:mac:22", Name: "mac", Facts: fakeFacts{platform: check.MacOS}}})["host:mac:22"]
	if len(res.Judged) != 0 || len(res.Coverage) != 3 || len(res.Coverage[0].Unread) != 1 || len(res.Coverage[2].Unread) != 2 ||
		len(res.Coverage[0].Groups) != 0 || len(res.Coverage[1].Groups) != 0 || len(res.Coverage[2].Groups) != 0 {
		t.Errorf("a macOS host was judged: %+v", res)
	}
}

// An internet audience keeps the base rating and says why.
func TestAnInternetAudienceSaysWhy(t *testing.T) {
	h := host(noFirewall(ss(pgAll)), Service{Port: 5432, Proto: "tcp", Audience: "internet", Key: "k"})
	j := verdictOn(t, Judge([]Host{h})[h.Asset].Judged, "5432/tcp")
	if j.Why != whyInternet || j.Has("contradiction") {
		t.Errorf("%+v", j)
	}
}

// accounts is a host with these passwd -S states and /etc/passwd shells,
// "name:STATE:shell[:uid]" per account; root's uid is 0, others' 1000.
func accountFacts(f fakeFacts, accounts ...string) fakeFacts {
	status := check.Records{Kind: check.ParsePasswdStatus, Items: []check.Record{}}
	passwd := check.Records{Kind: check.ParseAccounts, Items: []check.Record{}}
	for _, a := range accounts {
		p := strings.Split(a, ":")
		uid := "1000"
		if p[0] == "root" {
			uid = "0"
		}
		if len(p) > 3 {
			uid = p[3]
		}
		status.Items = append(status.Items, check.Record{check.FieldName: p[0], check.FieldStatus: p[1]})
		passwd.Items = append(passwd.Items, check.Record{check.FieldName: p[0], check.FieldUID: uid, check.FieldHome: "/home/" + p[0], check.FieldShell: p[2]})
	}
	f.facts[checkPasswdStatus] = finding.Fact{Parsed: status}
	f.facts[checkPasswd] = finding.Fact{Parsed: passwd}
	return f
}

// sshd is sshd -T's settings with edits: "key value", or "key" to remove.
func sshd(f fakeFacts, edits ...string) fakeFacts {
	kv := map[string]string{"port": "22", "listenaddress": "0.0.0.0:22", "permitemptypasswords": "yes", "passwordauthentication": "yes",
		"kbdinteractiveauthentication": "no", "usepam": "yes", "authenticationmethods": "any", "permitrootlogin": "prohibit-password"}
	for _, e := range edits {
		k, v, set := strings.Cut(e, " ")
		if !set {
			delete(kv, k)
			continue
		}
		kv[k] = v
	}
	f.facts[checkSSHD] = finding.Fact{Parsed: kv}
	return f
}

// sshHost is a Linux host whose sshd listens on every address, with alice
// having no password and a login shell.
func sshHost(edits ...string) fakeFacts {
	return sshd(accountFacts(noFirewall(ss(sshAll)), "root:L:/bin/bash", "alice:NP:/bin/bash"), edits...)
}

var sshFixtures = []fixture{
	{"password login with an empty password", host(sshHost()), "", Fired, ""},
	{"keyboard-interactive through PAM", host(sshHost("passwordauthentication no", "kbdinteractiveauthentication yes")), "", Fired, ""},
	{"an older sshd's challenge-response", host(sshHost("passwordauthentication no", "kbdinteractiveauthentication", "challengeresponseauthentication yes")), "", Fired, ""},
	{"socket-activated sshd", host(with(sshHost(), func(f fakeFacts) { f.facts[checkListeners] = ss("tcp 0.0.0.0:22 systemd") })), "", Fired, ""},
	{"root with a password login allowed", host(sshd(accountFacts(noFirewall(ss(sshAll)), "root:NP:/bin/bash"), "permitrootlogin yes")), "", Fired, ""},
	{"sshd refuses empty passwords", host(sshHost("permitemptypasswords no")), "", Disproved, ""},
	{"no account without a password", host(sshd(accountFacts(noFirewall(ss(sshAll)), "root:L:/bin/bash", "alice:P:/bin/bash"))), "", Disproved, ""},
	{"the empty-password account cannot log in", host(sshd(accountFacts(noFirewall(ss(sshAll)), "backup:NP:/usr/sbin/nologin"))), "", Disproved, ""},
	{"no password method", host(sshHost("passwordauthentication no")), "", Disproved, ""},
	{"every method needs a key", host(sshHost("authenticationmethods publickey,password")), "", Disproved, ""},
	{"root only, and root logs in with keys only", host(sshd(accountFacts(noFirewall(ss(sshAll)), "root:NP:/bin/bash"))), "", Disproved, ""},
	{"a second uid-0 account and root logs in with keys only", host(sshd(accountFacts(noFirewall(ss(sshAll)), "toor:NP:/bin/bash:0"))), "", Disproved, ""},
	{"socket activation on a port sshd does not name", host(with(sshHost(), func(f fakeFacts) {
		f.facts[checkListeners] = ss("tcp 127.0.0.1:22 sshd", "tcp 0.0.0.0:2222 systemd")
	})), "", Abstained, reasonSSHListens},
	{"root with keys only beside an unrecognized password state", host(sshd(accountFacts(noFirewall(ss(sshAll)), "root:NP:/bin/bash", "bob:XX:/bin/bash"))),
		"", Abstained, reasonAccounts},
	{"sshd only on localhost", host(with(sshHost(), func(f fakeFacts) { f.facts[checkListeners] = ss("tcp 127.0.0.1:22 sshd") })), "", Disproved, ""},
	{"sshd's settings not read", host(with(sshHost(), func(f fakeFacts) { f.why[checkSSHD] = "check-denied:sudo_refused" })), "", Abstained, reasonSSHConfig},
	{"sshd's settings cut short", host(with(sshHost(), func(f fakeFacts) {
		c := f.facts[checkSSHD]
		c.Partial = true
		f.facts[checkSSHD] = c
	})), "", Abstained, reasonSSHConfig},
	{"a user list limits who may sign in", host(sshHost("allowusers deploy")), "", Abstained, reasonSSHConfig},
	{"methods scheck does not judge", host(sshHost("authenticationmethods password,keyboard-interactive")), "", Abstained, reasonSSHConfig},
	{"listeners not read", host(with(sshHost(), func(f fakeFacts) { f.why[checkListeners] = "check-denied:sudo_refused" })), "", Abstained, reasonSSHListens},
	{"an owner not shown on another port", host(with(sshHost(), func(f fakeFacts) { f.facts[checkListeners] = ss("tcp 127.0.0.1:22 sshd", "tcp 0.0.0.0:2222 -") })),
		"", Abstained, reasonSSHListens},
	{"password states not read", host(with(sshHost(), func(f fakeFacts) { f.why[checkPasswdStatus] = "check-denied:sudo_refused" })), "", Abstained, reasonAccounts},
	{"a shell scheck does not know", host(sshd(accountFacts(noFirewall(ss(sshAll)), "alice:NP:/opt/odd/shell"))), "", Abstained, reasonAccounts},
	{"root's login setting not recognized", host(sshd(accountFacts(noFirewall(ss(sshAll)), "root:NP:/bin/bash"), "permitrootlogin maybe")), "", Abstained, reasonSSHConfig},
}

// R2 lists the accounts it fired for and cites each fact.
func TestAnEmptyPasswordOverSSHListsItsAccounts(t *testing.T) {
	js, _ := run(ruleByID(t, finding.IDEmptyPasswordRemote), sshFixtures[0].host)
	j := verdictOn(t, js, "")
	if !slices.Equal(j.Listed, []string{"alice"}) || len(j.Facts) != 4 || j.Subject.Kind != "" {
		t.Errorf("%+v", j)
	}
	js, _ = run(ruleByID(t, finding.IDEmptyPasswordRemote), sshFixtures[4].host)
	if j := verdictOn(t, js, ""); !slices.Equal(j.Listed, []string{"root"}) || !strings.Contains(j.Facts[2].Excerpt, "permitrootlogin yes") {
		t.Errorf("%+v", j)
	}
	// An account whose shell is not known is not listed, and the list says
	// it is a lower bound.
	for _, other := range []string{"bob:NP:/opt/odd/shell", "bob:XX:/bin/bash"} {
		lowerBound(t, host(sshd(accountFacts(noFirewall(ss(sshAll)), "alice:NP:/bin/bash", other))))
	}
}

// lowerBound says R2 fired for alice alone on h and named bob as
// undecided, its list a lower bound.
func lowerBound(t *testing.T, h Host) {
	t.Helper()
	js, incomplete := run(ruleByID(t, finding.IDEmptyPasswordRemote), h)
	j := verdictOn(t, js, "")
	if j.Verdict != Fired || !slices.Equal(j.Listed, []string{"alice"}) || !incomplete ||
		!slices.ContainsFunc(j.NotChecked, func(s string) bool { return strings.Contains(s, "bob") }) {
		t.Errorf("an undecided account was not named: %+v", j)
	}
}

// Each fact the rule reads, alone marked partial, never lets a fixture be
// disproved.
func TestEachIncompleteReadAloneNeverDisproves(t *testing.T) {
	for id, fs := range map[string][]fixture{finding.IDDBListensUnfiltered: dbFixtures, finding.IDEmptyPasswordRemote: sshFixtures} {
		r := ruleByID(t, id)
		for _, fx := range fs {
			base := fx.host.Facts.(fakeFacts)
			v := &View{host: fx.host, rule: r}
			r.Judge(v)
			for _, touched := range v.touched {
				check := touched.Check
				if _, ok := base.facts[check]; !ok {
					continue
				}
				f := base
				f.facts = maps.Clone(base.facts)
				fact := f.facts[check]
				fact.Partial = true
				f.facts[check] = fact
				h := fx.host
				h.Facts = f
				js, _ := run(r, h)
				for _, j := range js {
					if j.Verdict == Disproved {
						t.Errorf("%s/%s: disproved with %s partial: %+v", id, fx.name, check, j)
					}
				}
			}
		}
	}
}

// A java process is read as Elasticsearch or OpenSearch from its port alone,
// so every judgment about one, fired, disproved or abstained, says so and
// says the program was not confirmed.
func TestAJavaJudgmentHedgesWhatItIs(t *testing.T) {
	hedge := "A java process on 9200/tcp is read as Elasticsearch or OpenSearch from its port; which program it is was not confirmed"
	for _, tc := range []struct {
		name    string
		host    Host
		verdict string
	}{
		{"fired", host(noFirewall(ss("tcp 0.0.0.0:9200 java"))), Fired},
		{"disproved", host(withUFW(ss("tcp 0.0.0.0:9200 java"), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere")), Disproved},
		{"abstained", host(with(noFirewall(ss("tcp 0.0.0.0:9200 java")), func(f fakeFacts) {
			delete(f.why, checkFirewalld)
			f.facts[checkFirewalld] = finding.Fact{Parsed: "running\n"}
		})), Abstained},
	} {
		j := verdictOn(t, Judge([]Host{tc.host})["host:db1:22"].Judged, "9200/tcp")
		if j.Verdict != tc.verdict || !slices.Contains(j.NotChecked, hedge) {
			t.Errorf("%s: verdict %q, not checked %q", tc.name, j.Verdict, j.NotChecked)
		}
	}
}
