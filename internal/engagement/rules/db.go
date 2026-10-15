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
	"database (pg_hba.conf, database users and passwords) was not read"

// whyInternet is R1's sentence when the service is declared for the
// internet: the rating stays at base.
const whyInternet = "You declared it internet-facing; a database open to every address is still reported. Restrict it to the addresses that need it."

func init() {
	registry = append(registry, Rule{
		ID: finding.IDDBListensUnfiltered, Platform: check.Linux,
		Reads: append([]Read{{ReadCheck, checkListeners}, {ReadDeclared, DeclaredServices}}, firewallReads...),
		Judge: dbListensUnfiltered,
		Group: "Databases listening beyond localhost", Unbuilt: "this version of scheck has no rule for databases on this platform",
		Incomplete: finding.CoverageReason{Reason: reasonListenerOwner,
			Detail: "some listeners' owners are not shown to a read without sudo, so a database on another port could not be ruled out"},
	})
}

// dbListensUnfiltered is R1, db.listens_unfiltered: a database bound beyond
// localhost on a port the host firewall leaves open to every source
// (docs/spec/engagement.md, "The multi-fact rules of 0.0.2").
func dbListensUnfiltered(v *View) []Outcome {
	f, why := v.Fact(checkListeners)
	recs, typed := f.Parsed.(check.Records)
	if why != "" || !typed {
		return []Outcome{{Verdict: Abstained, Reason: reasonListeners, Incomplete: true,
			NotChecked: []string{"the listening sockets could not be read (" + why + ")"}}}
	}
	ls, portsOK := listeners(recs)
	complete := !f.Partial && portsOK
	byKey := map[string][]listener{}
	var keys []string
	for _, l := range ls {
		if l.loopback {
			continue
		}
		if !l.known || l.process == "" {
			complete = false
		}
		if _, seen := byKey[l.key()]; !seen {
			keys = append(keys, l.key())
		}
		byKey[l.key()] = append(byKey[l.key()], l)
	}
	var out []Outcome
	var fw *firewall
	for _, key := range keys {
		o, ok := dbSubject(v, byKey[key], &fw)
		if ok {
			out = append(out, o)
		}
	}
	switch {
	case !complete:
		// A database on a port whose owner is not shown cannot be ruled
		// out: the host is not disproved, whatever its subjects say.
		out = append(out, Outcome{Verdict: Abstained, Reason: reasonListenerOwner, Incomplete: true,
			NotChecked: []string{"some listeners' owners are not shown to a read without sudo, so a database on another port could not be ruled out"}})
	case len(out) == 0:
		out = append(out, Outcome{Verdict: Disproved, Excerpts: []Excerpt{{checkListeners, "no database in scheck's list listens beyond localhost"}}})
	}
	return out
}

// dbSubject is R1's verdict on one port/proto, ok false when nothing on it
// may be a database.
func dbSubject(v *View, group []listener, fw **firewall) (Outcome, bool) {
	port, proto := group[0].port, group[0].proto
	table := slices.Contains(tablePorts, port)
	var dbs []listener
	var doubt, doubtDetail string
	for _, l := range group {
		switch {
		case isDatabase(l.process, l.port):
			dbs = append(dbs, l)
		case containerOwners[l.process] != "":
			doubt, doubtDetail = reasonContainerPort, containerOwners[l.process]
		case table && slices.Contains(portProxies, l.process):
			doubt, doubtDetail = reasonContainerPort, "a container port proxy owns this port; the service behind it is not known"
		case table && l.process == "":
			doubt, doubtDetail = reasonListenerOwner, "the owner of this port is not shown to a read without sudo, and it is a database's usual port"
		}
	}
	if len(dbs) == 0 && doubt == "" {
		return Outcome{}, false
	}
	key := group[0].key()
	subject := finding.Subject{Kind: "service", Key: key, Label: key}
	if len(dbs) > 0 {
		subject.Label = dbs[0].process
	}
	var lines []string
	for _, l := range group {
		lines = append(lines, l.excerpt())
	}
	listened := Excerpt{checkListeners, strings.Join(lines, "; ")}
	if len(dbs) == 0 {
		return Outcome{Subject: subject, Verdict: Abstained, Reason: doubt, Excerpts: []Excerpt{listened},
			NotChecked: []string{doubtDetail}}, true
	}
	if *fw == nil {
		read := readFirewall(v)
		*fw = &read
	}
	var open, unknown *answer
	filtered := []Excerpt{}
	filteredNotChecked := ""
	for _, v6 := range []bool{false, true} {
		if !slices.ContainsFunc(dbs, func(l listener) bool { return l.known && (v6 && l.v6 || !v6 && l.v4) }) {
			continue
		}
		a := (*fw).open(port, proto, v6)
		switch a.filter {
		case filterOpen:
			if open == nil {
				open = &a
			}
		case filterUnknown:
			if unknown == nil {
				unknown = &a
			}
		default:
			filtered = append(filtered, a.excerpts...)
			filteredNotChecked = a.notChecked
		}
	}
	if slices.ContainsFunc(dbs, func(l listener) bool { return !l.known }) && unknown == nil && open == nil {
		unknown = &answer{reason: reasonListeners, detail: "a database's bind address was not recognized"}
	}
	o := Outcome{Subject: subject, Excerpts: []Excerpt{listened}, NotChecked: []string{notCheckedDB}}
	switch {
	case open != nil:
		o.Verdict = Fired
		o.Excerpts = append(o.Excerpts, open.excerpts...)
		o.NotChecked = append(o.NotChecked, open.notChecked)
		o.Attributes, o.Why = declared(v, port, proto)
	case unknown != nil:
		o.Verdict, o.Reason = Abstained, unknown.reason
		o.NotChecked = []string{unknown.detail, notCheckedDB}
	case doubt != "":
		o.Verdict, o.Reason = Abstained, doubt
		o.NotChecked = []string{doubtDetail, notCheckedDB}
	default:
		o.Verdict = Disproved
		o.Excerpts = append(o.Excerpts, dedupe(filtered)...)
		if filteredNotChecked != "" {
			o.NotChecked = append(o.NotChecked, filteredNotChecked)
		}
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
