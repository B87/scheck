package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func svcHost(f fakeFacts, exposure string, services ...Service) Host {
	h := host(f, services...)
	h.Context.Exposure = exposure
	return h
}

func declare(port int, audience string) Service {
	return Service{Port: port, Proto: "tcp", Audience: audience, Key: "assets.db1.context.expected_services[0]"}
}

const appAll = "tcp 0.0.0.0:8080 node"

var svcFixtures = []fixture{
	{"localhost service on every address, no firewall", svcHost(noFirewall(ss(appAll)), "lan", declare(8080, "localhost")), "8080/tcp", Fired, ""},
	{"localhost service on a private address", svcHost(noFirewall(ss("tcp 10.0.0.4:8080 node")), "", declare(8080, "localhost")), "8080/tcp", Fired, ""},
	{"localhost service, ufw allows it", svcHost(withUFW(ss(appAll), ufwActive, ufwDeny, "8080/tcp ALLOW IN Anywhere"), "internet", declare(8080, "localhost")), "8080/tcp", Fired, ""},
	{"lan service on every address of an internet host", svcHost(noFirewall(ss(appAll)), "internet", declare(8080, "lan")), "8080/tcp", Fired, ""},
	{"vpn service on a public address of an internet host", svcHost(noFirewall(ss("tcp 203.0.113.5:8080 node")), "internet", declare(8080, "vpn")), "8080/tcp", Fired, ""},
	{"a known program on a database port", svcHost(noFirewall(ss("tcp 0.0.0.0:9000 php-fpm8.2")), "", declare(9000, "localhost")), "9000/tcp", Fired, ""},
	{"localhost service on loopback only", svcHost(noFirewall(ss("tcp 127.0.0.1:8080 node")), "internet", declare(8080, "localhost")), "8080/tcp", Disproved, ""},
	{"ufw filters it", svcHost(withUFW(ss(appAll), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere"), "internet", declare(8080, "localhost")), "8080/tcp", Disproved, ""},
	{"ufw allows only a network", svcHost(withUFW(ss(appAll), ufwActive, ufwDeny, "8080/tcp ALLOW IN 10.0.0.0/8"), "internet", declare(8080, "lan")), "8080/tcp", Disproved, ""},
	{"ufw filters a lan service on a host not internet-facing", svcHost(withUFW(ss(appAll), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere"), "lan", declare(8080, "lan")), "8080/tcp", Disproved, ""},
	{"lan service on loopback of an internet host", svcHost(noFirewall(ss("tcp 127.0.0.1:8080 node")), "internet", declare(8080, "lan")), "8080/tcp", Disproved, ""},
	{"no service declared for a narrower audience", svcHost(noFirewall(ss(appAll)), "internet", declare(8080, "internet")), "", Abstained, reasonNoDeclaration},
	{"lan service on a host not internet-facing", svcHost(noFirewall(ss(appAll)), "lan", declare(8080, "lan")), "8080/tcp", Abstained, reasonAudienceNetwork},
	{"lan service on a private address of an internet host", svcHost(noFirewall(ss("tcp 10.0.0.4:8080 node")), "internet", declare(8080, "lan")), "8080/tcp", Abstained, reasonBindNetwork},
	{"Docker publishes it", svcHost(noFirewall(ss("tcp 0.0.0.0:8080 docker-proxy")), "", declare(8080, "localhost")), "8080/tcp", Abstained, reasonContainerPort},
	{"firewalld running", svcHost(with(noFirewall(ss(appAll)), func(f fakeFacts) {
		delete(f.why, checkFirewalld)
		f.facts[checkFirewalld] = finding.Fact{Parsed: "running\n"}
	}), "", declare(8080, "localhost")), "8080/tcp", Abstained, "unavailable:firewall_firewalld"},
	{"listeners not read", svcHost(with(noFirewall(ss()), func(f fakeFacts) { f.why[checkListeners] = "check-denied:sudo_refused" }), "", declare(8080, "localhost")),
		"8080/tcp", Abstained, reasonListeners},
	{"iptables in /sbin on Alpine", svcHost(with(noFirewall(ss(appAll)), func(f fakeFacts) {
		f.facts[checkBackend] = finding.Fact{Parsed: ""}
		f.facts[checkOSRelease] = finding.Fact{Parsed: map[string]string{"ID": "alpine"}}
	}), "", declare(8080, "localhost")), "8080/tcp", Abstained, "unavailable:firewall_backend"},
	{"a listener's port unreadable", svcHost(noFirewall(ss("tcp 0.0.0.0:abc node")), "", declare(8080, "localhost")), "8080/tcp", Abstained, reasonListeners},
	{"loopback only beside an unreadable port", svcHost(noFirewall(ss("tcp 127.0.0.1:8080 node", "tcp 0.0.0.0:abc node")), "internet", declare(8080, "localhost")),
		"8080/tcp", Abstained, reasonListeners},
	{"Docker on a port that is not a database's", svcHost(noFirewall(ss("tcp 0.0.0.0:8080 docker-proxy")), "internet", declare(8080, "lan")), "8080/tcp", Abstained, reasonContainerPort},
	{"IPv4 filtered, IPv6 open on a private address", svcHost(withUFW(ss(appAll, "tcp [fd00::1]:8080 node"), ufwActive, ufwDeny,
		"8080/tcp (v6) ALLOW IN Anywhere (v6)"), "internet", declare(8080, "lan")), "8080/tcp", Abstained, reasonBindNetwork},
	{"IPv4 open on a private address, IPv6 public but denied", svcHost(withUFW(ss("tcp 10.0.0.4:8080 node", "tcp [2001:db8::1]:8080 node"), ufwActive, ufwDeny,
		"8080/tcp ALLOW IN Anywhere", "8080/tcp (v6) DENY IN Anywhere (v6)"), "internet", declare(8080, "lan")), "8080/tcp", Abstained, reasonBindNetwork},
	{"airgapped is no audience", svcHost(noFirewall(ss(appAll)), "", declare(8080, "airgapped")), "8080/tcp", Abstained, reasonAudience},
}

// A port R1 judges gives R3 no subject, nor does a declared port nothing
// listens on: svc.expected_missing owns that.
func TestR3LeavesDatabasesAndMissingServicesAlone(t *testing.T) {
	r := ruleByID(t, finding.IDSvcListensBeyond)
	for _, h := range []Host{
		svcHost(noFirewall(ss(pgAll)), "internet", declare(5432, "localhost")),
		svcHost(noFirewall(ss("tcp 0.0.0.0:5432 -")), "internet", declare(5432, "localhost")),
		svcHost(noFirewall(ss(sshAll)), "internet", declare(8080, "localhost")),
	} {
		if js, _ := run(r, h); len(js) != 1 || js[0].Subject.Key != "" || js[0].Verdict != Disproved {
			t.Errorf("R3 judged %+v", js)
		}
	}
	// Both rules over one host: exactly R1 on the database port.
	h := svcHost(noFirewall(ss(pgAll)), "internet", declare(5432, "localhost"))
	if js := Judge([]Host{h})[h.Asset].Judged; slices.ContainsFunc(js, func(j finding.Judgment) bool { return j.ID == finding.IDSvcListensBeyond && j.Subject.Key != "" }) {
		t.Errorf("R3 on R1's port: %+v", js)
	}
}

// What fired cites the declaration it contradicts and says why here; a
// filtered port passed over a source rule says whom it lets in.
func TestR3CitesItsDeclaration(t *testing.T) {
	r := ruleByID(t, finding.IDSvcListensBeyond)
	js, _ := run(r, svcHost(noFirewall(ss(appAll)), "internet", declare(8080, "localhost")))
	j := verdictOn(t, js, "8080/tcp")
	if !j.Has("contradiction") || !slices.Contains(j.Sources, "assets.db1.context.expected_services[0]") || j.Subject.Label != "node" ||
		!strings.Contains(j.Why, "internet-facing") || len(j.NotChecked) != 2 {
		t.Fatalf("%+v", j)
	}
	js, _ = run(r, svcHost(withUFW(ss(appAll), ufwActive, ufwDeny, "8080/tcp ALLOW IN 10.0.0.0/8"), "internet", declare(8080, "lan")))
	if j := verdictOn(t, js, "8080/tcp"); !slices.Contains(j.NotChecked, "ufw allows this port from 10.0.0.0/8; whether those addresses are only your lan was not judged") {
		t.Fatalf("%+v", j.NotChecked)
	}
	js, _ = run(r, svcHost(noFirewall(ss("tcp 0.0.0.0:8080 docker-proxy")), "", declare(8080, "localhost")))
	if j := verdictOn(t, js, "8080/tcp"); !strings.HasPrefix(j.NotChecked[0], "Docker publishes 8080/tcp on 0.0.0.0, though you declared it for localhost only") {
		t.Fatalf("%+v", j.NotChecked)
	}
}

// R1 and R3 never judge the same port: Docker on a port that is not a
// database's is R3's alone.
func TestDockerOffADatabasePortIsR3s(t *testing.T) {
	h := svcHost(noFirewall(ss("tcp 0.0.0.0:8080 docker-proxy")), "", declare(8080, "localhost"))
	n := 0
	for _, j := range Judge([]Host{h})[h.Asset].Judged {
		if j.Subject.Key == "8080/tcp" {
			n++
			if j.ID != finding.IDSvcListensBeyond {
				t.Errorf("%+v", j)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d judgments on 8080/tcp", n)
	}
	// Nor does it leave R1's read incomplete.
	for _, j := range Judge([]Host{h})[h.Asset].Judged {
		if j.ID == finding.IDDBListensUnfiltered && j.Subject.Key == "" && (j.Verdict != Disproved || j.Reason != "") {
			t.Fatalf("R1's host verdict: %+v", j)
		}
	}
}
