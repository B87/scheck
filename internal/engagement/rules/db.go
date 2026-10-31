package rules

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

const checkListeners = "net.listeners"

// Reasons R1 abstains with, beyond the firewall's.
const (
	reasonListeners     = "unavailable:listeners"
	reasonListenerOwner = "unavailable:listener_owner"
	reasonContainerPort = "unavailable:container_port"
)

// notCheckedDB is what every R1 judgment leaves unread.
const notCheckedDB = "Whether a cloud firewall or security group blocks it was not assessed; who can sign in to the " +
	"database (its users, passwords and access rules, such as pg_hba.conf) was not read"

// whyInternet is R1's sentence when the service is declared for the
// internet: the rating stays at base.
const whyInternet = "You declared it internet-facing; a database open to every address is still reported. Restrict it to the addresses that need it."

func init() {
	registry = append(registry, Rule{
		ID: finding.IDDBListensUnfiltered, Platform: check.Linux,
		Reads: append([]Read{{ReadCheck, checkListeners}, {ReadDeclared, DeclaredServices}}, firewallReads...),
		Judge: dbListensUnfiltered,
		Group: "Databases listening beyond localhost", Unbuilt: "this version of scheck has no rule for databases on this platform",
		HostDomain: check.DomainFirewall, HostJudges: "whether database ports are filtered only; see Data stores",
		Incomplete: finding.CoverageReason{Reason: reasonListenerOwner,
			Detail: "some listeners' owners are not shown to a read without sudo, so a database on another port could not be ruled out"},
	})
}

// dbListensUnfiltered is R1, db.listens_unfiltered: a database bound beyond
// localhost on a port the host firewall leaves open to every source
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2").
func dbListensUnfiltered(v *View) []Outcome {
	l, abstain := readListening(v)
	if abstain != nil {
		return []Outcome{*abstain}
	}
	fr := newFirewallReader(v)
	var out []Outcome
	for _, g := range l.groups {
		if beyond := g.beyond(); len(beyond) > 0 {
			if o, ok := dbSubject(v, g, beyond, fr); ok {
				out = append(out, o)
			}
		}
	}
	switch {
	case !l.complete:
		// A database on a port whose owner is not shown cannot be ruled
		// out: the host is not disproved, whatever its subjects say.
		out = append(out, Outcome{Verdict: Abstained, Reason: reasonListenerOwner, Incomplete: true,
			NotChecked: []string{"some listeners' owners are not shown to a read without sudo, so a database on another port could not be ruled out"}})
	case len(out) == 0:
		out = append(out, Outcome{Verdict: Disproved, Excerpts: []Excerpt{{checkListeners, "no database in scheck's list listens beyond localhost"}}})
	}
	return out
}

// dbSubject is R1's verdict on one port/proto's listeners beyond loopback,
// ok false when nothing on it may be a database.
func dbSubject(v *View, g portGroup, group []listener, fr *firewallReader) (Outcome, bool) {
	table := slices.Contains(tablePorts, g.port)
	var dbs []listener
	var doubt, doubtDetail string
	for _, l := range group {
		reason, detail := ownerDoubt(l)
		switch {
		case isDatabase(l):
			dbs = append(dbs, l)
		case reason != "" && table:
			// A container runtime or port proxy hides a database only on a
			// database's usual port (docs/spec/engagement.md, R1); elsewhere
			// the port is R3's when declared.
			doubt, doubtDetail = reason, detail
		case table && l.process == "":
			doubt, doubtDetail = reasonListenerOwner, "the owner of this port is not shown to a read without sudo, and it is a database's usual port"
		}
	}
	if len(dbs) == 0 && doubt == "" {
		return Outcome{}, false
	}
	subject := finding.Subject{Kind: "service", Key: g.key(), Label: g.key()}
	if len(dbs) > 0 {
		subject.Label = dbs[0].process
	}
	listened := cited(group)
	if len(dbs) == 0 {
		return Outcome{Subject: subject, Verdict: Abstained, Reason: doubt, Excerpts: []Excerpt{listened},
			NotChecked: []string{doubtDetail}}, true
	}
	r := fr.reach(dbs)
	o := Outcome{Subject: subject, Excerpts: []Excerpt{listened}, NotChecked: []string{notCheckedDB}}
	switch {
	case r.open != nil:
		o.Verdict = Fired
		o.Excerpts = append(o.Excerpts, r.open.excerpts...)
		o.NotChecked = append(o.NotChecked, r.open.notChecked)
		o.Attributes, o.Why = declared(v, g.port, g.proto)
	case r.unknown != nil:
		o.Verdict, o.Reason = Abstained, r.unknown.reason
		o.NotChecked = []string{r.unknown.detail, notCheckedDB}
	case doubt != "":
		o.Verdict, o.Reason = Abstained, doubt
		o.NotChecked = []string{doubtDetail, notCheckedDB}
	default:
		o.Verdict = Disproved
		o.Excerpts = append(o.Excerpts, r.filtered...)
		if r.notChecked != "" {
			o.NotChecked = append(o.NotChecked, r.notChecked)
		}
		if line := r.allowedFrom("the ones that need it"); line != "" {
			o.NotChecked = append(o.NotChecked, line)
		}
	}
	if slices.ContainsFunc(dbs, func(l listener) bool { return l.process == "java" }) {
		o.NotChecked = append(o.NotChecked, "A java process on "+g.key()+" is read as Elasticsearch or OpenSearch from its port; "+
			"which program it is was not confirmed")
	}
	return o, true
}

// declared is what the host's expected_services say of the port: a
// contradiction when it was declared for an audience short of the
// internet, or the sentence for one declared internet-facing.
func declared(v *View, port int, proto string) ([]finding.Attribute, string) {
	for _, s := range v.Services() {
		if s.Port != port || !strings.EqualFold(s.Proto, proto) {
			continue
		}
		switch s.Audience {
		case "localhost", "lan", "vpn":
			return []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: s.Key}}}, ""
		case "internet":
			return nil, whyInternet
		}
	}
	return nil, ""
}

func dedupe(ex []Excerpt) []Excerpt {
	var out []Excerpt
	for _, e := range ex {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}
