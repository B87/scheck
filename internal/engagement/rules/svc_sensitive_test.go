package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func sensHost(f fakeFacts, services ...Service) Host { return host(f, services...) }

var sensitiveFixtures = []fixture{
	{"docker API on every address, no firewall", sensHost(noFirewall(ss("tcp 0.0.0.0:2375 dockerd"))), "2375/tcp", Fired, ""},
	{"telnet daemon", sensHost(noFirewall(ss("tcp 0.0.0.0:23 in.telnetd"))), "23/tcp", Fired, ""},
	{"inetd listening on the telnet port", sensHost(noFirewall(ss("tcp 0.0.0.0:23 xinetd"))), "23/tcp", Fired, ""},
	{"VNC on its display port", sensHost(noFirewall(ss("tcp 0.0.0.0:5901 Xvnc"))), "5901/tcp", Fired, ""},
	{"snmp over udp", sensHost(noFirewall(ss("udp 0.0.0.0:161 snmpd"))), "161/udp", Fired, ""},
	{"jupyter on any port", sensHost(noFirewall(ss("tcp 0.0.0.0:9999 jupyter-lab"))), "9999/tcp", Fired, ""},
	{"ufw allows it from anywhere", sensHost(withUFW(ss("tcp 0.0.0.0:445 smbd"), ufwActive, ufwDeny, "445/tcp ALLOW IN Anywhere")), "445/tcp", Fired, ""},
	{"declared for the lan", sensHost(noFirewall(ss("tcp 0.0.0.0:3389 xrdp")), declare(3389, "lan")), "3389/tcp", Fired, ""},
	{"docker API on loopback only", sensHost(noFirewall(ss("tcp 127.0.0.1:2375 dockerd", sshAll))), "", Disproved, ""},
	{"ufw filters it", sensHost(withUFW(ss("tcp 0.0.0.0:2375 dockerd"), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere")), "2375/tcp", Disproved, ""},
	{"nothing in the table listens", sensHost(noFirewall(ss(sshAll, "tcp 0.0.0.0:443 nginx"))), "", Disproved, ""},
	{"a process of that name on another port", sensHost(noFirewall(ss("tcp 0.0.0.0:8080 dockerd", sshAll))), "", Disproved, ""},
	{"gnome remote desktop", sensHost(noFirewall(ss("tcp 0.0.0.0:3389 gnome-remote-de"))), "3389/tcp", Fired, ""},
	{"k3s embeds the kubelet", sensHost(noFirewall(ss("tcp 0.0.0.0:10250 k3s-server"))), "10250/tcp", Fired, ""},
	{"the read-only kubelet port", sensHost(noFirewall(ss("tcp 0.0.0.0:10255 kubelet"))), "10255/tcp", Fired, ""},
	{"socket activation of the docker API", sensHost(noFirewall(ss("tcp 0.0.0.0:2375 systemd"))), "2375/tcp", Fired, ""},
	{"an ftp daemon on another port", sensHost(noFirewall(ss("tcp 0.0.0.0:2121 vsftpd"))), "2121/tcp", Fired, ""},
	{"a program scheck does not know on a table port", sensHost(noFirewall(ss("tcp 0.0.0.0:3389 someremote"))), "3389/tcp", Abstained, reasonListenerOwner},
	{"a table service and another program on one port", sensHost(withUFW(ss("tcp 0.0.0.0:8888 jupyter-lab", "tcp [::]:8888 nginx"),
		ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere", "8888/tcp (v6) ALLOW IN Anywhere (v6)")), "8888/tcp", Abstained, reasonListenerOwner},
	{"docker publishes a table port", sensHost(noFirewall(ss("tcp 0.0.0.0:2375 docker-proxy"))), "2375/tcp", Abstained, reasonContainerPort},
	{"owner not shown on a table port", sensHost(noFirewall(ss("tcp 0.0.0.0:2375 -"))), "2375/tcp", Abstained, reasonListenerOwner},
	{"firewalld running", sensHost(with(noFirewall(ss("tcp 0.0.0.0:2375 dockerd")), func(f fakeFacts) {
		delete(f.why, checkFirewalld)
		f.facts[checkFirewalld] = finding.Fact{Parsed: "running\n"}
	})), "2375/tcp", Abstained, "unavailable:firewall_firewalld"},
	{"iptables in /sbin on Alpine", sensHost(with(noFirewall(ss("tcp 0.0.0.0:2375 dockerd")), func(f fakeFacts) {
		f.facts[checkBackend] = finding.Fact{Parsed: ""}
		f.facts[checkOSRelease] = finding.Fact{Parsed: map[string]string{"ID": "alpine"}}
	})), "2375/tcp", Abstained, "unavailable:firewall_backend"},
	{"listeners not read", sensHost(with(noFirewall(ss()), func(f fakeFacts) { f.why[checkListeners] = "check-denied:sudo_refused" })), "", Abstained, reasonListeners},
}

// R6 gives the port to the table, not R3: a declared table port has no R3
// subject, and an unauthenticated class ranks one step higher.
func TestR6OwnsItsPorts(t *testing.T) {
	h := svcHost(noFirewall(ss("tcp 0.0.0.0:2375 dockerd")), "internet", declare(2375, "localhost"))
	res := Judge([]Host{h})[h.Asset]
	if slices.ContainsFunc(res.Judged, func(j finding.Judgment) bool { return j.ID == finding.IDSvcListensBeyond && j.Subject.Key != "" }) {
		t.Errorf("R3 judged R6's port: %+v", res.Judged)
	}
	j := verdictOn(t, filterID(res.Judged, finding.IDSensitiveListens), "2375/tcp")
	if j.Verdict != Fired || !j.Has("unauthenticated_default") || !j.Has("contradiction") || j.Subject.Label != "dockerd" ||
		!strings.Contains(j.Why, "Docker Engine API") || len(j.NotChecked) < 2 {
		t.Errorf("%+v", j)
	}
	// A class with a sign-in by default carries no such step.
	h = sensHost(noFirewall(ss("tcp 0.0.0.0:445 smbd")))
	j = verdictOn(t, filterID(Judge([]Host{h})[h.Asset].Judged, finding.IDSensitiveListens), "445/tcp")
	if j.Has("unauthenticated_default") {
		t.Errorf("smb: %+v", j)
	}
	// Declared internet-facing: still reported, at base, and says why.
	h = sensHost(noFirewall(ss("tcp 0.0.0.0:445 smbd")), declare(445, "internet"))
	j = verdictOn(t, filterID(Judge([]Host{h})[h.Asset].Judged, finding.IDSensitiveListens), "445/tcp")
	if j.Verdict != Fired || j.Has("contradiction") || !strings.HasPrefix(j.Why, whyInternetSensitive) {
		t.Errorf("internet audience: %+v", j)
	}
}

func filterID(js []finding.Judgment, id string) []finding.Judgment {
	var out []finding.Judgment
	for _, j := range js {
		if j.ID == id {
			out = append(out, j)
		}
	}
	return out
}

// A read known to be incomplete proves presence, never absence.
func TestR6AnIncompleteReadNeverDisproves(t *testing.T) {
	r := ruleByID(t, finding.IDSensitiveListens)
	for _, fx := range sensitiveFixtures {
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
	}
}

// Where R6 only doubts the owner, the port stays R3's: an unnamed owner on a
// table port must not turn a declared service's finding into R3's disproof.
func TestR6DoubtLeavesTheDeclaredServiceToR3(t *testing.T) {
	h := svcHost(noFirewall(ss("tcp 0.0.0.0:2375 -")), "internet", declare(2375, "localhost"))
	res := Judge([]Host{h})[h.Asset]
	r3 := verdictOn(t, filterID(res.Judged, finding.IDSvcListensBeyond), "2375/tcp")
	if r3.Verdict != Fired {
		t.Errorf("R3: %+v", r3)
	}
	r6 := verdictOn(t, filterID(res.Judged, finding.IDSensitiveListens), "2375/tcp")
	if r6.Verdict != Abstained {
		t.Errorf("R6: %+v", r6)
	}
}

// A port shared with a program R6 does not read is not R6's: the declared
// service stays R3's, which fires, instead of both rules disproving.
func TestR6AMixedPortStaysR3s(t *testing.T) {
	h := svcHost(withUFW(ss("tcp 0.0.0.0:8888 jupyter-lab", "tcp [::]:8888 nginx"), ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere",
		"8888/tcp (v6) ALLOW IN Anywhere (v6)"), "internet", declare(8888, "localhost"))
	res := Judge([]Host{h})[h.Asset]
	if j := verdictOn(t, filterID(res.Judged, finding.IDSvcListensBeyond), "8888/tcp"); j.Verdict != Fired {
		t.Errorf("R3: %+v", j)
	}
	if j := verdictOn(t, filterID(res.Judged, finding.IDSensitiveListens), "8888/tcp"); j.Verdict == Disproved {
		t.Errorf("R6: %+v", j)
	}
}
