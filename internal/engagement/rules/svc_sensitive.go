package rules

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// SensitiveServicesVersion identifies the table of remote-administration
// services below: a change to it changes what R6 reads as one
// (docs/spec/engagement.md, R6).
const SensitiveServicesVersion = "2026-10-24.2"

// sensitive is one class of service whose exposure beyond the host is a
// problem whatever the operator declared: it gives control of the host or
// its data, or a login in clear text. A listener is matched by process, as
// the kernel names it (comm, cut at 15 characters), and by port when the
// class lists them. unauthenticated marks a class that has no sign-in by
// default, which ranks one step higher.
type sensitive struct {
	class           string
	processes       []string
	ports           []int
	proto           string
	unauthenticated bool
	// activators are programs that listen for the service on its port
	// before starting it (inetd and systemd socket activation): matched only
	// on that port.
	activators []string
	// anyPort says the processes count on any port, not only the listed
	// ones (a telnet daemon is one wherever it listens).
	anyPort bool
	fix     string
}

var sensitiveServices = []sensitive{
	{class: "Docker Engine API without TLS", processes: []string{"dockerd"}, activators: []string{"systemd"}, ports: []int{2375}, proto: "tcp", unauthenticated: true,
		fix: "Never expose 2375; reach the engine through an ssh:// Docker context."},
	{class: "Docker Engine API (TLS; whether client certificates are required was not read)", processes: []string{"dockerd"}, activators: []string{"systemd"}, ports: []int{2376}, proto: "tcp",
		fix: "Require client certificates, or reach the engine through an ssh:// Docker context."},
	{class: "etcd client port (no sign-in by default; holds cluster secrets)", processes: []string{"etcd"}, ports: []int{2379}, proto: "tcp", unauthenticated: true,
		fix: "Bind etcd to the private interface and require client certificates."},
	{class: "kubelet", processes: []string{"kubelet", "k3s-server", "kubelite"}, ports: []int{10250}, proto: "tcp",
		fix: "Restrict the kubelet port to the control plane."},
	{class: "kubelet read-only port (no sign-in at all)", processes: []string{"kubelet", "k3s-server", "kubelite"}, ports: []int{10255}, proto: "tcp", unauthenticated: true,
		fix: "Disable the read-only port (readOnlyPort: 0) or restrict it to the control plane."},
	{class: "Telnet (a login in clear text)", processes: []string{"in.telnetd", "telnetd"}, proto: "tcp", activators: []string{"systemd", "inetd", "xinetd"}, ports: []int{23}, anyPort: true,
		fix: "Replace Telnet with SSH."},
	{class: "FTP (a login in clear text)", processes: []string{"vsftpd", "proftpd", "pure-ftpd"}, proto: "tcp", activators: []string{"systemd", "inetd", "xinetd"}, ports: []int{21}, anyPort: true,
		fix: "Replace FTP with SFTP."},
	{class: "SMB file sharing", processes: []string{"smbd"}, ports: []int{445, 139}, proto: "tcp",
		fix: "Allow SMB only from the addresses that need it."},
	{class: "Remote Desktop (RDP)", processes: []string{"xrdp", "gnome-remote-de"}, ports: []int{3389}, proto: "tcp",
		fix: "Reach the desktop through a VPN or an SSH tunnel."},
	{class: "VNC remote desktop", processes: []string{"Xvnc", "Xtigervnc", "x11vnc", "wayvnc", "vncserver-x11-c"}, ports: []int{5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909}, proto: "tcp",
		fix: "Reach the desktop through a VPN or an SSH tunnel."},
	{class: "Jupyter (often started with an empty token)", processes: []string{"jupyter-lab", "jupyter-noteboo", "jupyter-server"}, proto: "tcp",
		fix: "Set a token or password and bind it to localhost."},
	{class: "SNMP", processes: []string{"snmpd"}, ports: []int{161}, proto: "udp",
		fix: "Change the community from public, or use SNMPv3."},
	{class: "RabbitMQ management", processes: []string{"beam.smp"}, ports: []int{15672}, proto: "tcp",
		fix: "Bind the management port to localhost or the private network."},
}

// sensitiveOf is the table row a listener belongs to, if any.
func sensitiveOf(l listener) (sensitive, bool) {
	for _, s := range sensitiveServices {
		if s.proto != "" && s.proto != l.proto {
			continue
		}
		inPorts := s.anyPort || len(s.ports) == 0 || slices.Contains(s.ports, l.port)
		if inPorts && slices.Contains(s.processes, l.process) {
			return s, true
		}
		if slices.Contains(s.activators, l.process) && slices.Contains(s.ports, l.port) {
			return s, true
		}
	}
	return sensitive{}, false
}

// sensitivePort says a row of the table names the port: an owner that is
// not shown there may be one.
func sensitivePort(port int, proto string) bool {
	return slices.ContainsFunc(sensitiveServices, func(s sensitive) bool {
		return s.proto == proto && slices.Contains(s.ports, port)
	})
}

// r6Owns says every listener on the port beyond loopback is a table
// service. R3 leaves such a port to R6; a port where R6 only doubts the owner,
// or where another program listens beside a table service, stays R3's too,
// which has its own words for a container proxy and an unnamed owner.
func r6Owns(g portGroup) bool {
	beyond := g.beyond()
	return len(beyond) > 0 && !slices.ContainsFunc(beyond, func(l listener) bool {
		_, ok := sensitiveOf(l)
		return !ok
	})
}

// notCheckedSensitive is what every R6 judgment leaves unread.
const notCheckedSensitive = "Whether a cloud firewall or security group blocks it was not assessed; whether the service asks " +
	"for a password, a key or a certificate was not read"

// whyInternetSensitive is R6's sentence when the service is declared for the
// internet: the rating stays at base.
const whyInternetSensitive = "You declared it internet-facing; a remote-administration service open to every address is still reported. Restrict it to the addresses that need it."

func init() {
	registry = append(registry, Rule{
		ID: finding.IDSensitiveListens, Platform: check.Linux,
		Reads: append([]Read{{ReadCheck, checkListeners}, {ReadDeclared, DeclaredServices}}, firewallReads...),
		Judge: sensitiveListens,
		Group: "Remote-administration services listening beyond localhost", Unbuilt: "this version of scheck has no rule for remote-administration services on this platform",
		HostDomain: check.DomainFirewall, HostJudges: "whether remote-administration ports are filtered only; see External surface",
		Incomplete: finding.CoverageReason{Reason: reasonListenerOwner,
			Detail: "some listeners' owners are not shown to a read without sudo, so a remote-administration service on another port could not be ruled out"},
	})
}

// sensitiveListens is R6, svc.sensitive_listens_unfiltered: a table service
// bound beyond localhost on a port the host firewall leaves open to every
// source, whatever the operator declared (docs/spec/engagement.md, R6).
func sensitiveListens(v *View) []Outcome {
	l, abstain := readListening(v)
	if abstain != nil {
		return []Outcome{*abstain}
	}
	fr := newFirewallReader(v)
	var out []Outcome
	for _, g := range l.groups {
		if beyond := g.beyond(); len(beyond) > 0 {
			if o, ok := sensitiveSubject(v, g, beyond, fr); ok {
				out = append(out, o)
			}
		}
	}
	switch {
	case !l.complete:
		out = append(out, Outcome{Verdict: Abstained, Reason: reasonListenerOwner, Incomplete: true,
			NotChecked: []string{"some listeners' owners are not shown to a read without sudo, so a remote-administration service on another port could not be ruled out"}})
	case len(out) == 0:
		out = append(out, Outcome{Verdict: Disproved, Excerpts: []Excerpt{{checkListeners, "no remote-administration service in scheck's list listens beyond localhost"}}})
	}
	return out
}

// sensitiveSubject is R6's verdict on one port/proto's listeners beyond
// loopback, ok false when nothing on it may be in the table.
func sensitiveSubject(v *View, g portGroup, group []listener, fr *firewallReader) (Outcome, bool) {
	var hits []listener
	var class sensitive
	var doubt, doubtDetail string
	table := sensitivePort(g.port, g.proto)
	for _, l := range group {
		reason, detail := ownerDoubt(l)
		if s, ok := sensitiveOf(l); ok {
			hits, class = append(hits, l), s
			continue
		}
		switch {
		case reason != "" && table:
			doubt, doubtDetail = reason, detail
		case table && l.process == "":
			doubt, doubtDetail = reasonListenerOwner, "the owner of this port is not shown to a read without sudo, and it is a remote-administration port"
		case table:
			// A program scheck does not recognise holds a remote-administration
			// port: neither a hit nor a disproof.
			doubt, doubtDetail = reasonListenerOwner, l.process+" holds "+g.key()+", a remote-administration port, and is not a program scheck recognises there"
		}
	}
	// Another program beyond loopback beside a table service (the other
	// address family, or a second binding) is not shown to be filtered by
	// anything R6 read about the table service: neither a disproof.
	if len(hits) > 0 && len(hits) < len(group) && doubt == "" {
		for _, l := range group {
			if _, ok := sensitiveOf(l); ok {
				continue
			}
			if reason, detail := ownerDoubt(l); reason != "" {
				doubt, doubtDetail = reason, detail
			} else {
				doubt, doubtDetail = reasonListenerOwner, "another program, "+processOrUnnamed(l.process)+", also listens on "+g.key()+", so the whole port was not shown to be filtered"
			}
			break
		}
	}
	if len(hits) == 0 && doubt == "" {
		return Outcome{}, false
	}
	subject := finding.Subject{Kind: "service", Key: g.key(), Label: g.key()}
	if len(hits) > 0 {
		subject.Label = hits[0].process
	}
	listened := cited(group)
	if len(hits) == 0 {
		return Outcome{Subject: subject, Verdict: Abstained, Reason: doubt, Excerpts: []Excerpt{listened},
			NotChecked: []string{doubtDetail}}, true
	}
	r := fr.reach(hits)
	o := Outcome{Subject: subject, Excerpts: []Excerpt{listened}, NotChecked: []string{notCheckedSensitive}}
	switch {
	case r.open != nil:
		o.Verdict = Fired
		o.Excerpts = append(o.Excerpts, r.open.excerpts...)
		o.NotChecked = append(o.NotChecked, r.open.notChecked)
		var why string
		o.Attributes, why = declared(v, g.port, g.proto)
		o.Why = class.class + ". " + class.fix
		if why != "" {
			o.Why = whyInternetSensitive + " " + class.fix
		}
		// The collector's words win over the severity table's, so the
		// contradiction step is worded here.
		for _, s := range v.Services() {
			if s.Port == g.port && strings.EqualFold(s.Proto, g.proto) && (s.Audience == "localhost" || s.Audience == "lan" || s.Audience == "vpn") {
				o.Why += " You declared it for " + s.Audience + " only, but it listens beyond that and the host firewall lets any address in."
			}
		}
		if class.unauthenticated {
			o.Attributes = append(o.Attributes, finding.Attribute{Name: "unauthenticated_default",
				Ref: finding.Ref{Observation: checkListeners, Excerpt: class.class + " on " + g.key()}})
		}
	case r.unknown != nil:
		o.Verdict, o.Reason = Abstained, r.unknown.reason
		o.NotChecked = []string{r.unknown.detail, notCheckedSensitive}
	case doubt != "":
		o.Verdict, o.Reason = Abstained, doubt
		o.NotChecked = []string{doubtDetail, notCheckedSensitive}
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
	return o, true
}

func processOrUnnamed(process string) string {
	if process == "" {
		return "owner not shown"
	}
	return process
}
