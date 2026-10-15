package rules

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// Reasons R3 abstains with, beyond R1's and the firewall's.
const (
	reasonAudience        = "unavailable:audience"
	reasonAudienceNetwork = "unavailable:audience_network"
	reasonBindNetwork     = "unavailable:bind_network"
	reasonNoDeclaration   = "unavailable:no_declaration"
)

// notCheckedSvc is what every R3 judgment leaves unread.
const notCheckedSvc = "Whether a cloud firewall or security group blocks it was not assessed; whether the service asks for a password or key was not read"

func init() {
	registry = append(registry, Rule{
		ID: finding.IDSvcListensBeyond, Platform: check.Linux,
		Reads: append([]Read{{ReadCheck, checkListeners}, {ReadDeclared, DeclaredServices}, {ReadDeclared, DeclaredExposure}}, firewallReads...),
		Judge: listensBeyondDeclared,
		Group: "Declared services listening beyond their audience", Unbuilt: "this version of scheck has no rule for declared services on this platform",
		HostDomain: check.DomainFirewall, HostJudges: "whether declared services listen beyond their audience only; see External surface",
		Incomplete: finding.CoverageReason{Reason: reasonListeners, Detail: "the listening sockets could not be read in full"},
	})
}

// listensBeyondDeclared is R3, svc.listens_beyond_declared: a service the
// operator declared for localhost, a LAN or a VPN that listens beyond that
// audience on a port the host firewall leaves open (docs/spec/engagement.md,
// "The multi-fact rules of 0.0.2"). Its subjects are the declarations; a
// port R1 judges is R1's.
func listensBeyondDeclared(v *View) []Outcome {
	var declared []Service
	for _, s := range v.Services() {
		// An entry with no audience declares none to contradict.
		if s.Audience != "internet" && s.Audience != "" {
			declared = append(declared, s)
		}
	}
	if len(declared) == 0 {
		return []Outcome{{Verdict: Abstained, Reason: reasonNoDeclaration,
			NotChecked: []string{"no service on this host is declared for localhost, lan or vpn (expected_services); scheck judges a service's reach only against what you declared"}}}
	}
	l, unread := readListening(v)
	exposure := v.Exposure()
	fr := newFirewallReader(v)
	var out []Outcome
	for _, s := range declared {
		subject := finding.Subject{Kind: "service", Key: s.subjectKey(), Label: s.subjectKey()}
		if s.Purpose != "" {
			subject.Label = s.Purpose
		}
		if unread != nil {
			o := *unread
			o.Subject = subject
			out = append(out, o)
			continue
		}
		g, seen := l.at(s.Port, s.Proto)
		if !l.portsOK && (!seen || len(g.beyond()) == 0) {
			// A record whose port was unreadable may be this service, on
			// any address: neither absence nor loopback-only is shown.
			out = append(out, Outcome{Subject: subject, Verdict: Abstained, Reason: reasonListeners, Incomplete: true,
				NotChecked: []string{"a listening socket's port could not be read, so whether this service listens could not be established", notCheckedSvc}})
			continue
		}
		if !seen || r1Owns(g) {
			// Not listening is svc.expected_missing's; a database's port is R1's.
			continue
		}
		out = append(out, judgeService(s, subject, g, exposure, fr))
	}
	if len(out) == 0 {
		// Every declared port is a database's, which R1 judges, or has
		// nothing listening, which svc.expected_missing reports.
		out = append(out, Outcome{Verdict: Disproved, Excerpts: []Excerpt{{checkListeners,
			"no service declared for localhost, lan or vpn listens here, other than on database ports R1 judges"}}})
	}
	return out
}

// subjectKey is the service's subject key, port/proto.
func (s Service) subjectKey() string {
	return portGroup{port: s.Port, proto: strings.ToLower(s.Proto)}.key()
}

// r1Owns says R1 gives the port an outcome: a database beyond loopback,
// or an unnamed owner or container proxy on a database's usual port.
func r1Owns(g portGroup) bool {
	table := slices.Contains(tablePorts, g.port)
	return slices.ContainsFunc(g.beyond(), func(l listener) bool {
		reason, _ := ownerDoubt(l)
		return isDatabase(l.process, l.port) || table && (l.process == "" || reason != "")
	})
}

func judgeService(s Service, subject finding.Subject, g portGroup, exposure string, fr *firewallReader) Outcome {
	beyond := g.beyond()
	// The process when shown, else the declared purpose, else port/proto.
	if i := slices.IndexFunc(beyond, func(l listener) bool { return l.process != "" }); i >= 0 {
		subject.Label = beyond[i].process
	}
	o := Outcome{Subject: subject, NotChecked: []string{notCheckedSvc}}
	if s.Audience != "localhost" && s.Audience != "lan" && s.Audience != "vpn" {
		o.Verdict, o.Reason = Abstained, reasonAudience
		o.NotChecked = []string{s.Audience + " is not an audience a service can have", notCheckedSvc}
		return o
	}
	if len(beyond) == 0 {
		o.Verdict = Disproved
		o.Excerpts = []Excerpt{{checkListeners, "listens only on loopback (" + cited(g.all).Text + ")"}}
		return o
	}
	listened := cited(beyond)
	o.Excerpts = []Excerpt{listened}
	for _, l := range beyond {
		if reason, detail := ownerDoubt(l); reason != "" {
			o.Verdict, o.Reason = Abstained, reason
			if runtime, ok := map[string]string{"docker-proxy": "Docker", "conmon": "Podman"}[l.process]; ok {
				detail = runtime + " publishes " + g.key() + " on " + l.address + ", though you declared it for " + s.Audience +
					" only; " + runtime + "'s rules bypass ufw and firewalld, and scheck does not read them in this version. " +
					"If only this host needs it, publish it on 127.0.0.1 (-p 127.0.0.1:" + strconv.Itoa(g.port) + ":" + strconv.Itoa(g.port) + ")."
			}
			o.NotChecked = []string{detail, notCheckedSvc}
			return o
		}
	}
	// A firewall that filters the port disproves whatever the bind.
	r := fr.reach(beyond)
	switch {
	case r.open == nil && r.unknown != nil:
		o.Verdict, o.Reason = Abstained, r.unknown.reason
		o.NotChecked = []string{r.unknown.detail, notCheckedSvc}
		return o
	case r.open == nil:
		o.Verdict = Disproved
		o.Excerpts = append(o.Excerpts, r.filtered...)
		if r.notChecked != "" {
			o.NotChecked = append(o.NotChecked, r.notChecked)
		}
		if line := r.allowedFrom("your " + s.Audience); line != "" {
			o.NotChecked = append(o.NotChecked, line)
		}
		return o
	}
	if s.Audience != "localhost" && exposure != "internet" {
		o.Verdict, o.Reason = Abstained, reasonAudienceNetwork
		o.NotChecked = []string{"you declared it for your " + s.Audience + "; on a host not declared internet-facing, scheck cannot tell which networks its addresses face", notCheckedSvc}
		return o
	}
	// The bind is judged only in the families the firewall left open: the
	// open answer and the address must be the same family's.
	open := r.inOpen(beyond)
	if s.Audience != "localhost" {
		// A LAN or VPN service bound to a private address may be just
		// that; on a cloud VM a public address can forward to it.
		if i := slices.IndexFunc(open, func(l listener) bool { return !l.wildcard() && !l.global() }); i >= 0 &&
			!slices.ContainsFunc(open, func(l listener) bool { return l.wildcard() || l.global() }) {
			o.Verdict, o.Reason = Abstained, reasonBindNetwork
			o.NotChecked = []string{"bound to " + open[i].address + ", a private address; on a cloud VM a public address can forward to it, and scheck did not read the cloud firewall", notCheckedSvc}
			return o
		}
	}
	o.Verdict = Fired
	o.Excerpts = append(o.Excerpts, r.open.excerpts...)
	o.NotChecked = append(o.NotChecked, r.open.notChecked)
	o.Attributes = []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: s.Key}}}
	switch {
	case s.Audience == "localhost" && exposure == "internet":
		o.Why = "You declared it for this host only, and the host is internet-facing: unless a cloud firewall blocks it, anyone can connect to it."
	case s.Audience == "localhost":
		o.Why = "You declared it for this host only; machines on the networks this host is on can connect to it."
	case slices.ContainsFunc(open, listener.wildcard):
		o.Why = "You declared it for your " + s.Audience + " only, but it listens on every address of an internet-facing host and the host firewall lets any address in."
	default:
		o.Why = "You declared it for your " + s.Audience + " only, but it listens on a public address of an internet-facing host and the host firewall lets any address in."
	}
	return o
}

// wildcard says the listener is bound to every address.
func (l listener) wildcard() bool {
	return l.address == "*" || l.address == "0.0.0.0" || l.address == "::"
}

// global says the listener is bound to a specific global-unicast address:
// not loopback, private (RFC 1918, fc00::/7), CGNAT (100.64.0.0/10) or
// link-local.
func (l listener) global() bool {
	addr, _, _ := strings.Cut(l.address, "%")
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}
