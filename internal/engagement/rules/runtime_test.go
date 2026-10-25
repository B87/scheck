package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// pkgs is a packages record set: "name version" per line.
func pkgs(manager string, lines ...string) finding.Fact {
	recs := check.Records{Kind: check.ParsePackages, Items: []check.Record{}}
	for _, l := range lines {
		f := strings.Fields(l)
		recs.Items = append(recs.Items, check.Record{check.FieldName: f[0], check.FieldVersion: f[1],
			check.FieldStatus: check.PackageInstalled, check.FieldManager: manager})
	}
	return finding.Fact{Parsed: recs}
}

// runtimeHost is a Linux host (os-release as check's parser gives it) with
// the dpkg read as given and no rpm; the listeners are those of ss lines.
func runtimeHost(osID, osVersion string, dpkg finding.Fact, listeners ...string) Host {
	f := noFirewall(ss(listeners...))
	f.facts[checkOSRelease] = finding.Fact{Parsed: map[string]string{"id": osID, "version_id": osVersion}}
	f.facts[checkDpkgRuntimes] = dpkg
	f.why[checkRpmRuntimes] = "check-unavailable:command_missing"
	return Host{Asset: "host:web1:22", Name: "web1", Facts: f,
		Collected: []time.Time{time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 24, 10, 0, 20, 0, time.UTC)}}
}

// rpmHost is the same for the Red Hat family.
func rpmHost(osID, osVersion string, rpm finding.Fact, listeners ...string) Host {
	h := runtimeHost(osID, osVersion, pkgs("dpkg"), listeners...)
	f := h.Facts.(fakeFacts)
	delete(f.facts, checkDpkgRuntimes)
	f.why[checkDpkgRuntimes] = "check-unavailable:command_missing"
	delete(f.why, checkRpmRuntimes)
	f.facts[checkRpmRuntimes] = rpm
	return h
}

const (
	webAll = "tcp 0.0.0.0:443 nginx"
	fpm83  = "php8.3-fpm 8.3.6-0ubuntu0.24.04.9"
)

var phpFixtures = []fixture{
	{"ubuntu fpm below the fix, nginx open", runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), webAll, sshAll), "php8.3-fpm", Fired, ""},
	{"ubuntu fpm below the fix, no listeners read", with2(runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83)), func(f fakeFacts) { f.why[checkListeners] = "check-denied:sudo_refused" }), "php8.3-fpm", Fired, ""},
	{"ubuntu fpm below the fix, nothing serves", runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), sshAll), "php8.3-fpm", Fired, ""},
	{"apache module below the fix", runtimeHost("debian", "12", pkgs("dpkg", "libapache2-mod-php8.2 8.2.20-1~deb12u1"), "tcp 0.0.0.0:80 apache2"), "libapache2-mod-php8.2", Fired, ""},
	{"rhel remi below upstream", rpmHost("rhel", "9", pkgs("rpm", "php-fpm 8.3.20-1.el9.remi")), "php-fpm", Fired, ""},
	{"ubuntu fixed package", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.13")), "php8.3-fpm", Disproved, ""},
	{"debian fixed package", runtimeHost("debian", "12", pkgs("dpkg", "php8.2-fpm 8.2.35-1~deb12u1")), "php8.2-fpm", Disproved, ""},
	{"no PHP package", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 18.19.1+dfsg-6ubuntu5"), sshAll), "", Disproved, ""},
	{"rhel package, table has no fixed one", rpmHost("rhel", "9", pkgs("rpm", "php-fpm 8.2.13-1.el9")), "php-fpm", Abstained, "unavailable:backport_unknown"},
	{"a source scheck does not know", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "php8.3-fpm 8.3.20-1custom")), "php8.3-fpm", Abstained, "unavailable:source_unrecognized"},
	{"sury on a line patched without a number", runtimeHost("debian", "12", pkgs("dpkg", "php8.1-fpm 8.1.31-1+0~20250101.1+debian12~1.gbp1+deb.sury.org")), "php8.1-fpm", Abstained, "unavailable:unnumbered_backport"},
	{"neither package database read", with2(runtimeHost("ubuntu", "24.04", pkgs("dpkg")), func(f fakeFacts) {
		f.why[checkDpkgRuntimes] = "check-unavailable:command_missing"
		delete(f.facts, checkDpkgRuntimes)
	}), "", Abstained, reasonPackages},
	{"php-fpm listens and no package is installed", runtimeHost("ubuntu", "24.04", pkgs("dpkg"), "tcp 127.0.0.1:9000 php-fpm8.3", sshAll), "php-fpm8.3", Abstained, reasonPHPNoPackage},
	{"os-release not read", with2(runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83)), func(f fakeFacts) {
		delete(f.facts, checkOSRelease)
		f.why[checkOSRelease] = "check-not-run"
	}), "php8.3-fpm", Abstained, "unavailable:os_release"},
	{"package read cut short, no PHP shown", runtimeHost("ubuntu", "24.04", partialPkgs(pkgs("dpkg", "nodejs 18.19.1+dfsg-6ubuntu5"))), "", Abstained, reasonPackagesPartial},
	{"package read cut short, a fixed package is not disproved from it", runtimeHost("ubuntu", "24.04", partialPkgs(pkgs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.13"))), "php8.3-fpm", Abstained, reasonPackagesPartial},
	{"opensuse names its packages otherwise", rpmHost("opensuse-leap", "15.5", pkgs("rpm", "rpm 4.18.0-1.1")), "", Abstained, reasonDistribution},
	{"os-release unread and nothing found", with2(runtimeHost("ubuntu", "24.04", pkgs("dpkg")), func(f fakeFacts) {
		delete(f.facts, checkOSRelease)
		f.why[checkOSRelease] = "check-not-run"
	}), "", Abstained, reasonDistribution},
	{"centos 7 names php otherwise", rpmHost("centos", "7", pkgs("rpm", "rpm 4.11.3-1.el7")), "", Abstained, reasonDistribution},
	{"amazon linux names php otherwise", rpmHost("amzn", "2023", pkgs("rpm", "rpm 4.16.1-1.amzn2023")), "", Abstained, reasonDistribution},
	{"debian 8 names php5", runtimeHost("debian", "8", pkgs("dpkg")), "", Abstained, reasonDistribution},
	{"an rpm package database that does not exist on a debian host is not a cut read", with2(runtimeHost("debian", "12", pkgs("dpkg", "php8.2-fpm 8.2.35-1~deb12u1")), func(f fakeFacts) {
		delete(f.why, checkRpmRuntimes)
		f.facts[checkRpmRuntimes] = partialPkgs(pkgs("rpm"))
	}), "php8.2-fpm", Disproved, ""},
	{"a partial read on a distribution the reads do not know still withdraws a disproof", runtimeHost("linuxmint", "22", partialPkgs(pkgs("dpkg", "php8.3-fpm 8.3.36-1+ubuntu24.04.1+deb.sury.org+1"))), "php8.3-fpm", Abstained, "unavailable:packages_partial"},
	{"php-cli on the red hat family may serve through php-cgi", rpmHost("rocky", "9", pkgs("rpm", "rpm 4.16.1-1.el9", "php-cli 8.2.13-1.el9")), "php-cli", Abstained, "unavailable:php_cli"},
	{"a software-collection apache module on rhel is found", rpmHost("rhel", "9", pkgs("rpm", "php83-php 8.3.20-1.el9.remi")), "php83-php", Fired, ""},
	{"a software-collection fpm on rhel is found", rpmHost("rhel", "9", pkgs("rpm", "php83-php-fpm 8.3.20-1.el9.remi")), "php83-php-fpm", Fired, ""},
}

func partialPkgs(f finding.Fact) finding.Fact {
	r := f.Parsed.(check.Records)
	r.Partial = true
	f.Parsed = r
	f.Partial = true
	return f
}

// with2 edits a host's fake facts, a copy of the maps being shared by design.
func with2(h Host, edit func(fakeFacts)) Host {
	edit(h.Facts.(fakeFacts))
	return h
}

var nodeFixFixtures = []fixture{
	{"nodesource below the fix", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.20.0-1nodesource1")), "nodejs", Fired, ""},
	{"debian with an old Brotli library", runtimeHost("debian", "12", pkgs("dpkg", "nodejs 18.20.4+dfsg-1~deb12u1", "libbrotli1 1.0.9-2")), "nodejs", Fired, ""},
	{"nodesource fixed", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.23.4-1nodesource1")), "nodejs", Disproved, ""},
	{"no Node.js", runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83)), "", Disproved, ""},
	{"end of life line has no fix to miss", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 20.11.1-1nodesource1")), "nodejs", Abstained, reasonLineUnsupported},
	{"ubuntu package, table has no row", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 18.19.1+dfsg-6ubuntu5", "libbrotli1 1.1.0-2build2")), "nodejs", Abstained, "unavailable:backport_unknown"},
	{"debian with the fixed library", runtimeHost("debian", "12", pkgs("dpkg", "nodejs 18.20.4+dfsg-1~deb12u1", "libbrotli1 1.0.9-2+deb12u1")), "nodejs", Abstained, "unavailable:distro_node_unfixed"},
	{"databases not read", with2(runtimeHost("ubuntu", "24.04", pkgs("dpkg")), func(f fakeFacts) {
		f.why[checkDpkgRuntimes] = "check-unavailable:command_missing"
		delete(f.facts, checkDpkgRuntimes)
	}), "", Abstained, reasonPackages},
}

var nodeLineFixtures = []fixture{
	{"nodesource 20", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 20.11.1-1nodesource1")), "nodejs", Fired, ""},
	{"nodesource 25", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 25.1.0-1nodesource1")), "nodejs", Fired, ""},
	{"nodesource 22 is still fixed", runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.20.0-1nodesource1")), "nodejs", Disproved, ""},
	{"nodesource 22 after its support ended", at(runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.23.4-1nodesource1")), time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)), "nodejs", Fired, ""},
	{"nodesource 22 as its support ends during the read", at(runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.23.4-1nodesource1")), time.Date(2027, 4, 30, 23, 59, 50, 0, time.UTC)), "nodejs", Abstained, reasonEOLWithin},
	{"nodesource 22 with no read time", func() Host {
		h := runtimeHost("ubuntu", "24.04", pkgs("dpkg", "nodejs 22.23.4-1nodesource1"))
		h.Collected = nil
		return h
	}(), "nodejs", Abstained, "unavailable:collection_time"},
	{"no Node.js", runtimeHost("ubuntu", "24.04", pkgs("dpkg")), "", Disproved, ""},
	{"a distribution's old line is the distribution's", runtimeHost("debian", "12", pkgs("dpkg", "nodejs 18.20.4+dfsg-1~deb12u1", "libbrotli1 1.0.9-2")), "nodejs", Abstained, reasonDistroPackage},
	{"unknown source", runtimeHost("debian", "12", pkgs("dpkg", "nodejs 20.1.0-custom")), "nodejs", Abstained, "unavailable:source_unrecognized"},
}

func judged(t *testing.T, h Host, id string) []finding.Judgment {
	t.Helper()
	return filterID(Judge([]Host{h})[h.Asset].Judged, id)
}

// A fired R7 on a web server that is open to every address carries the
// serves_web attribute, cites the listener, and says what it did not read.
func TestR7ServingWebServerRaises(t *testing.T) {
	j := verdictOn(t, judged(t, phpFixtures[0].host, finding.IDPHPFixMissing), "php8.3-fpm")
	if j.Verdict != Fired || !j.Has("serves_web") {
		t.Fatalf("%+v", j)
	}
	if !strings.Contains(j.Why, "nginx listens on 0.0.0.0:443/tcp") || !strings.Contains(j.Why, "CVE-2026-109618") {
		t.Errorf("why: %s", j.Why)
	}
	cites := map[string]bool{}
	for _, f := range j.Facts {
		cites[f.Check] = true
	}
	for _, id := range []string{checkDpkgRuntimes, checkListeners} {
		if !cites[id] {
			t.Errorf("does not cite %s: %+v", id, j.Facts)
		}
	}
	if len(j.NotChecked) == 0 || !strings.Contains(strings.Join(j.NotChecked, " "), "containers") {
		t.Errorf("not checked: %v", j.NotChecked)
	}
}

// Without a reachable web server, or without the listeners, the finding
// stands at its base and says so; the raise is never taken on a guess.
func TestR7DoesNotRaiseWithoutAReachableWebServer(t *testing.T) {
	for _, i := range []int{1, 2} {
		j := verdictOn(t, judged(t, phpFixtures[i].host, finding.IDPHPFixMissing), "php8.3-fpm")
		if j.Verdict != Fired || j.Has("serves_web") || !strings.Contains(j.Why, "rated at its base") {
			t.Errorf("%s: %+v", phpFixtures[i].name, j)
		}
	}
	// A firewall that filters the port.
	h := runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), webAll, sshAll)
	f := h.Facts.(fakeFacts)
	delete(f.why, checkUFW)
	f.facts[checkUFW] = finding.Fact{Parsed: []string{ufwActive, ufwDeny, "22/tcp ALLOW IN Anywhere"}}
	j := verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php8.3-fpm")
	if j.Verdict != Fired || j.Has("serves_web") {
		t.Errorf("a filtered web port raised: %+v", j)
	}
	// A reverse proxy that may front PHP elsewhere is not a web server here.
	h = runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), "tcp 0.0.0.0:443 haproxy")
	if j := verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php8.3-fpm"); j.Has("serves_web") {
		t.Errorf("haproxy raised: %+v", j)
	}
	// A web server on loopback is not reachable.
	h = runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), "tcp 127.0.0.1:8080 nginx")
	if j := verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php8.3-fpm"); j.Has("serves_web") {
		t.Errorf("loopback raised: %+v", j)
	}
}

// The mod_php wording is added where the PHP project demonstrated its
// exploit, and a package on a pro-only fix says so.
func TestR7Wording(t *testing.T) {
	j := verdictOn(t, judged(t, phpFixtures[3].host, finding.IDPHPFixMissing), "libapache2-mod-php8.2")
	if !strings.Contains(j.Why, "mod_php") {
		t.Errorf("%s", j.Why)
	}
	h := runtimeHost("ubuntu", "20.04", pkgs("dpkg", "php7.4-fpm 7.4.3-4ubuntu2.20"))
	j = verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php7.4-fpm")
	if j.Verdict != Fired || !strings.Contains(j.Why, "Ubuntu Pro") {
		t.Errorf("%+v", j)
	}
}

// The runtime rules never print a claim the evidence does not bear:
// "vulnerable" from a version, or "exploited".
func TestRuntimeRulesNeverOverclaim(t *testing.T) {
	var all []fixture
	all = append(all, phpFixtures...)
	all = append(all, nodeFixFixtures...)
	all = append(all, nodeLineFixtures...)
	for _, fx := range all {
		for _, j := range Judge([]Host{fx.host})[fx.host.Asset].Judged {
			text := strings.ToLower(j.Why + " " + strings.Join(j.NotChecked, " "))
			for _, bad := range []string{"vulnerable", "exploited"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s: %s says %q: %s", fx.name, j.ID, bad, text)
				}
			}
		}
	}
}

// A read known to be incomplete proves presence, never absence.
func TestRuntimeRulesAnIncompleteReadNeverDisproves(t *testing.T) {
	for id, fs := range map[string][]fixture{finding.IDPHPFixMissing: phpFixtures, finding.IDNodeFixMissing: nodeFixFixtures, finding.IDNodeLineUnsupported: nodeLineFixtures} {
		r := ruleByID(t, id)
		for _, fx := range fs {
			f := fx.host.Facts.(fakeFacts)
			f.partial = true
			h := fx.host
			h.Facts = f
			js, _ := run(r, h)
			for _, j := range js {
				if j.Verdict == Disproved {
					t.Errorf("%s/%s: disproved on an incomplete read: %+v", id, fx.name, j)
				}
			}
		}
	}
}

// The runtime groups are never wholly assessed: what lies outside the
// package database is a standing gap.
func TestRuntimeGroupsCarryTheirGap(t *testing.T) {
	h := phpFixtures[5].host
	res := Judge([]Host{h})[h.Asset]
	found := 0
	for _, plan := range res.Coverage {
		for _, g := range plan.Groups {
			if g.Gap != nil && g.Gap.Reason == reasonRuntimeInstalls && g.HostDomain == check.DomainRuntimes {
				found++
			}
		}
	}
	if found != 3 {
		t.Errorf("%d runtime groups with the gap, want 3: %+v", found, res.Coverage)
	}
}

// macOS and Alpine-like hosts are not judged and say so.
func TestRuntimeRulesAreLinuxOnly(t *testing.T) {
	h := runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83))
	f := h.Facts.(fakeFacts)
	f.platform = check.MacOS
	h.Facts = f
	res := Judge([]Host{h})[h.Asset]
	for _, j := range res.Judged {
		if j.ID == finding.IDPHPFixMissing || j.ID == finding.IDNodeFixMissing || j.ID == finding.IDNodeLineUnsupported {
			t.Errorf("judged on macOS: %+v", j)
		}
	}
	unread := 0
	for _, plan := range res.Coverage {
		for _, u := range plan.Unread {
			if strings.Contains(u.Detail, "PHP and Node.js packages on Linux only") {
				unread++
			}
		}
	}
	if unread != 3 {
		t.Errorf("%d unread groups, want 3", unread)
	}
}

// at is a host read at t (twenty seconds long).
func at(h Host, t time.Time) Host {
	h.Collected = []time.Time{t, t.Add(20 * time.Second)}
	return h
}

// A partial read of one database must not withdraw or mark anything beyond
// the runtime rules' own verdicts: other rules' groups stay as their facts
// decide, and the host's population is not flagged incomplete for them.
func TestRuntimePartialReadStaysLocal(t *testing.T) {
	h := runtimeHost("ubuntu", "24.04", partialPkgs(pkgs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.13")), "tcp 127.0.0.1:5432 postgres", sshAll)
	res := Judge([]Host{h})[h.Asset]
	if res.PopulationIncomplete {
		t.Error("a partial package read flagged the host's whole population incomplete")
	}
	if j := verdictOn(t, filterID(res.Judged, finding.IDDBListensUnfiltered), ""); j.Verdict != Disproved {
		t.Errorf("R1 was withdrawn by a package read it does not use: %+v", j)
	}
}

// A verdict that used a table row cites os-release, and a Node.js judged
// through its Brotli library cites the library.
func TestRuntimeVerdictsCiteTheirTableInputs(t *testing.T) {
	j := verdictOn(t, judged(t, nodeFixFixtures[1].host, finding.IDNodeFixMissing), "nodejs")
	checks := map[string]string{}
	for _, f := range j.Facts {
		checks[f.Excerpt] = f.Check
	}
	var sawLib, sawOS bool
	for ex := range checks {
		sawLib = sawLib || strings.Contains(ex, "libbrotli1 1.0.9-2")
		sawOS = sawOS || strings.Contains(ex, "ID=debian VERSION_ID=12")
	}
	if !sawLib || !sawOS {
		t.Errorf("lib %v os %v: %+v", sawLib, sawOS, j.Facts)
	}
	if !strings.Contains(strings.Join(j.NotChecked, " "), "Debian had not published") {
		t.Errorf("not checked: %v", j.NotChecked)
	}
	// Another distribution does not get Debian's sentence.
	h := rpmHost("fedora", "40", pkgs("rpm", "rpm 4.19.1-1.fc40", "nodejs 20.11.0-1.fc40"))
	if j := verdictOn(t, judged(t, h, finding.IDNodeFixMissing), "nodejs"); strings.Contains(strings.Join(j.NotChecked, " "), "Debian") {
		t.Errorf("%v", j.NotChecked)
	}
}

// A container that publishes a port is not a web server scheck saw, and the
// finding says the PHP inside it was not read.
func TestR7ContainerPublishingTheWebPort(t *testing.T) {
	h := runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), "tcp 0.0.0.0:443 docker-proxy")
	j := verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php8.3-fpm")
	if j.Has("serves_web") || !strings.Contains(j.Why, "docker-proxy publishes 0.0.0.0:443/tcp, a container") {
		t.Errorf("%+v", j)
	}
}

// An IPv6 listener is written with brackets.
func TestR7WritesAnIPv6ListenerWithBrackets(t *testing.T) {
	h := runtimeHost("ubuntu", "24.04", pkgs("dpkg", fpm83), "tcp [::]:80 nginx")
	j := verdictOn(t, judged(t, h, finding.IDPHPFixMissing), "php8.3-fpm")
	if !j.Has("serves_web") || !strings.Contains(j.Why, "[::]:80/tcp") {
		t.Errorf("%+v", j)
	}
}
