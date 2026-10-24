package report

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/engagement/rules"
	"github.com/b87/scheck/internal/engagement/severity"
	"github.com/b87/scheck/internal/finding"
)

// hostFacts are a host's facts for the multi-fact rules, each observed as
// the host envelope numbers its checks' first run.
type hostFacts struct {
	facts map[string]finding.Fact
	why   map[string]string
}

func (h hostFacts) Platform() check.Platform { return check.Linux }

func (h hostFacts) Fact(id string) (finding.Fact, string) {
	if why, ok := h.why[id]; ok {
		return finding.Fact{Check: id, Observation: id + "#1"}, why
	}
	f, ok := h.facts[id]
	if !ok {
		return finding.Fact{Check: id}, "check-not-run"
	}
	f.Check, f.Observation = id, id+"#1"
	return f, ""
}

func listenRecs(recs ...check.Record) finding.Fact {
	return finding.Fact{Parsed: check.Records{Kind: check.ParseListeners, Items: recs}}
}

func listen(proto, addr, port, process string) check.Record {
	r := check.Record{check.FieldProtocol: proto, check.FieldState: "LISTEN", check.FieldAddress: addr, check.FieldPort: port}
	if process != "" {
		r[check.FieldProcess] = process
	}
	return r
}

// withHostRules is the Ubuntu host with the multi-fact rules judged over
// the given listeners on a host with no firewall, graded as Analyze grades
// them.
func withHostRules(t *testing.T, listeners finding.Fact, d severity.Declarations, services ...rules.Service) Input {
	t.Helper()
	return withHostFacts(t, map[string]finding.Fact{"net.listeners": listeners}, d, services...)
}

// withHostFacts is withHostRules with any facts set, over a host with no
// firewall.
func withHostFacts(t *testing.T, set map[string]finding.Fact, d severity.Declarations, services ...rules.Service) Input {
	t.Helper()
	in := oneHost(t, "ubuntu")
	// Declared context comes from an engagement file: --host declares none.
	in.FromHost, in.Path, in.Trigger, in.Rerun = false, "engagement.yaml", "routine", "scheck run engagement.yaml"
	a := &in.Assets[0]
	facts := hostFacts{
		facts: map[string]finding.Fact{"fw.nft": {Parsed: ""},
			"fw.iptables_backend": {Parsed: "/usr/sbin/xtables-nft-multi\n"},
			// As check's parser gives os-release (keys in lower case), and a
			// dpkg read that found no PHP or Node.js, like the Ubuntu fixture.
			"os.release": {Parsed: map[string]string{"id": "ubuntu", "version_id": "24.04"}}, "pkg.dpkg_runtimes": pkgFact("dpkg")},
		why: map[string]string{"fw.ufw": "check-unavailable:command_missing", "fw.firewalld": "check-unavailable:command_missing",
			"pkg.rpm_runtimes": "check-unavailable:command_missing"},
	}
	maps.Copy(facts.facts, set)
	exposure := ""
	if _, ok := d.Internet[a.ID]; ok {
		exposure = "internet"
	}
	read := time.Date(2026, 10, 7, 7, 12, 3, 0, time.UTC)
	res := rules.Judge([]rules.Host{{Asset: a.ID, Name: a.Name, Facts: facts, Context: rules.Context{Services: services, Exposure: exposure},
		Collected: []time.Time{read, read.Add(2 * time.Second)}}})[a.ID]
	a.Judged, a.Coverage, a.PopulationIncomplete = res.Judged, res.Coverage, res.PopulationIncomplete
	severity.GradeAll(a.Judged, a.ID, d)
	return in
}

func hostDatabaseFiredReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "5432", "postgres"), listen("tcp", "::", "5432", "postgres")),
		severity.Declarations{Internet: map[string]string{"host:ubuntu:22": "assets.ubuntu.context.exposure"}},
		rules.Service{Port: 5432, Proto: "tcp", Audience: "lan", Key: "assets.ubuntu.context.expected_services[0]"})
}

func hostDatabaseDisprovedReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "127.0.0.1", "5432", "postgres")), severity.Declarations{})
}

func hostDatabaseAbstainedReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "5432", "docker-proxy")), severity.Declarations{})
}

// R1's three outcomes reach the report: a finding on the port with its
// facts as evidence and its chain, or the data row's reason.
func TestHostRulesReachTheReport(t *testing.T) {
	r := build(hostDatabaseFiredReport(t))
	validate(t, schema(t), r)
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == finding.IDDBListensUnfiltered {
			f = &r.Findings[i]
		}
	}
	if f == nil || *f.Key.Subject != "5432/tcp" || f.Severity != "high" || f.Rule.Kind != "multi_fact" || f.AcceptTemplate == nil || !f.AcceptTemplate.BySubject {
		t.Fatalf("finding %+v", f)
	}
	if got := row(t, r, "data"); got.Mark != "partial" || len(got.SubItems) != 1 || got.SubItems[0].Mark != "assessed" {
		t.Errorf("data row %+v", got)
	}
	r = build(hostDatabaseDisprovedReport(t))
	if got := row(t, r, "data"); got.SubItems[0].Mark != "assessed" || len(r.Findings) != 0 {
		t.Errorf("disproved: %+v", got)
	}
	r = build(hostDatabaseAbstainedReport(t))
	if got := row(t, r, "data"); got.Mark != "not_assessed" || !hasReason(got.Reasons, "unavailable:container_port") {
		t.Errorf("abstained: %+v", got)
	}
}

func hasReason(rs []ReasonDetail, reason string) bool {
	for _, r := range rs {
		if r.Reason == reason {
			return true
		}
	}
	return false
}

// sshEmptyPassword is the Ubuntu host with these accounts having no
// password and a login shell, sshd accepting an empty password, and its
// posture rules graded on the same accounts: accounts.empty_password
// fires for every one of them.
func sshEmptyPassword(t *testing.T, accounts ...string) Input {
	t.Helper()
	status := []check.Record{{check.FieldName: "root", check.FieldStatus: "L"}}
	passwd := []check.Record{{check.FieldName: "root", check.FieldUID: "0", check.FieldHome: "/root", check.FieldShell: "/bin/bash"}}
	var excerpts []string
	for _, a := range accounts {
		uid := "1001"
		if a == "root" {
			status, passwd, uid = nil, nil, "0"
		}
		status = append(status, check.Record{check.FieldName: a, check.FieldStatus: "NP"})
		passwd = append(passwd, check.Record{check.FieldName: a, check.FieldUID: uid, check.FieldHome: "/home/" + a, check.FieldShell: "/bin/bash"})
		excerpts = append(excerpts, "name="+a+" status=NP")
	}
	in := withHostFacts(t, map[string]finding.Fact{
		"net.listeners":          listenRecs(listen("tcp", "0.0.0.0", "22", "sshd")),
		"accounts.passwd_status": {Parsed: check.Records{Kind: check.ParsePasswdStatus, Items: status}},
		"accounts.passwd":        {Parsed: check.Records{Kind: check.ParseAccounts, Items: passwd}},
		"sshd.config": {Parsed: map[string]string{"port": "22", "listenaddress": "0.0.0.0:22", "permitemptypasswords": "yes",
			"passwordauthentication": "yes", "kbdinteractiveauthentication": "no", "usepam": "yes", "authenticationmethods": "any",
			"permitrootlogin": "prohibit-password"}},
	}, severity.Declarations{})
	env := &in.Assets[0].Host.Envelope
	for i := range env.Assessments {
		if env.Assessments[i].Finding == finding.IDEmptyPassword {
			env.Assessments[i].Status = finding.Matched
		}
	}
	def, _ := finding.Lookup(finding.IDEmptyPassword)
	env.Findings = append(env.Findings, finding.Finding{ID: def.ID, Title: def.Title, Category: def.Category,
		SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity, Adjustments: []finding.Adjustment{}, Status: finding.StatusOpen,
		Source: finding.SourceRule, Confidence: finding.ConfidenceHigh, Platform: "linux", Impact: def.Impact, Remediation: def.Remediation,
		Evidence: []finding.Evidence{{Observation: "accounts.passwd_status#1", Check: "accounts.passwd_status", Excerpt: strings.Join(excerpts, "; ")}}})
	return in
}

func hostSSHFiredReport(t *testing.T) Input { return sshEmptyPassword(t, "alice") }

// "Fix these first" leaves out the host-local finding only where the
// remote one names every account it does, and is open.
func TestTheLocalEmptyPasswordIsRankedUnlessCovered(t *testing.T) {
	ranked := func(r *Report) bool {
		return slices.ContainsFunc(r.Summary.Items, func(i Item) bool { return slices.Contains(i.IDs, finding.IDEmptyPassword) })
	}
	if r := build(sshEmptyPassword(t, "alice")); ranked(r) {
		t.Error("covered by the remote finding, yet ranked")
	}
	// root logs in with keys only: the remote finding names alice, not root.
	if r := build(sshEmptyPassword(t, "root", "alice")); !ranked(r) {
		t.Error("root's empty password is ranked nowhere")
	}
	in := sshEmptyPassword(t, "alice")
	in.Assets[0].Judged[slices.IndexFunc(in.Assets[0].Judged, func(j Judgment) bool { return j.ID == finding.IDEmptyPasswordRemote })].Verdict = verdictAbstained
	if r := build(in); !ranked(r) {
		t.Error("the remote finding did not fire, yet the local one is not ranked")
	}
}

// R2 reaches the report as one critical finding on the host listing its
// accounts, and the SSH server line says what it judged.
func TestAnEmptyPasswordOverSSHReachesTheReport(t *testing.T) {
	r := build(hostSSHFiredReport(t))
	validate(t, schema(t), r)
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == finding.IDEmptyPasswordRemote {
			f = &r.Findings[i]
		}
	}
	if f == nil || f.Severity != "critical" || f.Key.Subject != nil || f.Affected == nil || f.Affected.Listed[0] != "alice" {
		t.Fatalf("finding %+v", f)
	}
	ssh := subItem(t, row(t, r, "hosts"), "SSH server")
	if !slices.Contains(ssh.Judged, "accounts with no password that SSH lets in") || !slices.Contains(ssh.Rules, finding.IDEmptyPasswordRemote) {
		t.Errorf("SSH server %+v", ssh)
	}
}

// hostServiceBeyondReport is R3 firing: a service declared for this host
// only listens on every address of an internet-facing host with no host
// firewall.
func hostServiceBeyondReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "8080", "node")),
		severity.Declarations{Internet: map[string]string{"host:ubuntu:22": "assets.ubuntu.context.exposure"}},
		rules.Service{Port: 8080, Proto: "tcp", Audience: "localhost", Purpose: "admin dashboard", Key: "assets.ubuntu.context.expected_services[0]"})
}

// R6 on the Docker API, declared for this host only on an internet-facing
// host: the class with no sign-in by default and a contradicted declaration,
// which the ceiling holds at high.
func hostSensitiveDockerReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "2375", "dockerd")),
		severity.Declarations{Internet: map[string]string{"host:ubuntu:22": "assets.ubuntu.context.exposure"}},
		rules.Service{Port: 2375, Proto: "tcp", Audience: "localhost", Purpose: "docker", Key: "assets.ubuntu.context.expected_services[0]"})
}

// R6 on SMB with no declaration: the plain path, at base.
func hostSensitiveSMBReport(t *testing.T) Input {
	return withHostRules(t, listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "445", "smbd")), severity.Declarations{})
}

// R3 reaches the report at high, citing the declaration it contradicts,
// and an area marked not used never hides it.
func TestAServiceBeyondItsAudienceReachesTheReport(t *testing.T) {
	in := hostServiceBeyondReport(t)
	r := build(in)
	validate(t, schema(t), r)
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == finding.IDSvcListensBeyond {
			f = &r.Findings[i]
		}
	}
	if f == nil || f.Severity != "high" || f.Subject == nil || f.Subject.Label != "node" || f.Area != string(finding.AreaExternal) {
		t.Fatalf("%+v", f)
	}
	in.NotUsed = []string{"external"}
	r = build(in)
	for _, row := range r.Coverage {
		if row.Area == string(finding.AreaExternal) && row.Mark == "not_applicable" {
			t.Fatalf("not_used hid a finding: %+v", row)
		}
	}
}

// contextNotesReport is a database host whose operator said they run no
// data stores: the row reports the finding and carries the note, and a C2
// note reaches the readout (docs/spec/engagement.md, "Context notes").
func contextNotesReport(t *testing.T) Input {
	in := hostDatabaseFiredReport(t)
	in.NotUsed = []string{"data"}
	in.ContextNotes = []ContextNote{
		{Area: "data", Kind: NoteContextNotUsed, Source: "not_used[0]", Detail: "You said you run no data stores (`not_used`), but `postgres` listens on 0.0.0.0:5432 on `ubuntu`. If these are yours, remove `data` from `not_used`."},
		{Kind: NoteContextDeploysTo, Source: "assets.shop-repo.deploys_to", Detail: "`shop-repo` (`github:acme/shop`) is declared to deploy production, but GitHub shows it archived. If production now deploys from another repository, declare that one."},
	}
	return in
}

func pkgFact(manager string, lines ...string) finding.Fact {
	recs := check.Records{Kind: check.ParsePackages, Items: []check.Record{}}
	for _, l := range lines {
		f := strings.Fields(l)
		recs.Items = append(recs.Items, check.Record{check.FieldName: f[0], check.FieldVersion: f[1],
			check.FieldStatus: check.PackageInstalled, check.FieldManager: manager})
	}
	return finding.Fact{Parsed: recs}
}

// R7 on an Ubuntu 24.04 PHP-FPM behind nginx on every address, on a host
// declared internet-facing: the package is below Ubuntu's fixed one, a web
// server is open, and the ceiling holds the rating at high.
func hostPHPFiredReport(t *testing.T) Input {
	return withHostFacts(t, map[string]finding.Fact{
		"net.listeners":     listenRecs(listen("tcp", "0.0.0.0", "22", "sshd"), listen("tcp", "0.0.0.0", "443", "nginx")),
		"os.release":        {Parsed: map[string]string{"id": "ubuntu", "version_id": "24.04"}},
		"pkg.dpkg_runtimes": pkgFact("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.9", "nodejs 22.23.4-1nodesource1"),
	}, severity.Declarations{Internet: map[string]string{"host:ubuntu:22": "assets.ubuntu.context.exposure"}})
}

// R8 and R9 on an end-of-life NodeSource build: R8 has no fix to miss, and
// R9 fires.
func hostNodeAbstainedReport(t *testing.T) Input {
	return withHostFacts(t, map[string]finding.Fact{
		"net.listeners":     listenRecs(listen("tcp", "0.0.0.0", "22", "sshd")),
		"os.release":        {Parsed: map[string]string{"id": "debian", "version_id": "12"}},
		"pkg.dpkg_runtimes": pkgFact("dpkg", "nodejs 20.11.1-1nodesource1"),
	}, severity.Declarations{})
}

// R7 reaches the report as a finding on the package with its chain and its
// evidence, and R9's end-of-life line as a finding of its own.
func TestRuntimeFindingsReachTheReport(t *testing.T) {
	r := build(hostPHPFiredReport(t))
	validate(t, schema(t), r)
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == finding.IDPHPFixMissing {
			f = &r.Findings[i]
		}
	}
	if f == nil || *f.Key.Subject != "php8.3-fpm" || f.Severity != "high" || f.Rule.Kind != "multi_fact" || !f.AcceptTemplate.BySubject {
		t.Fatalf("finding %+v", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("findings %+v", r.Findings)
	}
	r = build(hostNodeAbstainedReport(t))
	validate(t, schema(t), r)
	var line *Finding
	for i := range r.Findings {
		if r.Findings[i].ID == finding.IDNodeLineUnsupported {
			line = &r.Findings[i]
		}
	}
	if line == nil || line.Severity != "medium" {
		t.Fatalf("end-of-life finding %+v", r.Findings)
	}
}
