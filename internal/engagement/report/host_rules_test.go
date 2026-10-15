package report

import (
	"testing"

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
	in := oneHost(t, "ubuntu")
	// Declared context comes from an engagement file: --host declares none.
	in.FromHost, in.Path, in.Trigger, in.Rerun = false, "engagement.yaml", "routine", "scheck run engagement.yaml"
	a := &in.Assets[0]
	facts := hostFacts{
		facts: map[string]finding.Fact{"net.listeners": listeners, "fw.nft": {Parsed: ""},
			"fw.iptables_backend": {Parsed: "/usr/sbin/xtables-nft-multi\n"}, "os.release": {Parsed: map[string]string{"ID": "ubuntu"}}},
		why: map[string]string{"fw.ufw": "check-unavailable:command_missing", "fw.firewalld": "check-unavailable:command_missing"},
	}
	res := rules.Judge([]rules.Host{{Asset: a.ID, Name: a.Name, Facts: facts, Context: rules.Context{Services: services}}})[a.ID]
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
