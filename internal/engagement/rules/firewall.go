package rules

import (
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The host firewall as R1 reads it (docs/spec/engagement.md, R1): whether
// it leaves a port open to every source, per address family. One reading
// of every firewall fact, so a later rule over another service asks the
// same question and gets the same answer.

// The checks the firewall reading needs.
const (
	checkUFW       = "fw.ufw"
	checkNFT       = "fw.nft"
	checkFirewalld = "fw.firewalld"
	checkBackend   = "fw.iptables_backend"
	checkOSRelease = "os.release"
)

// firewallReads are the declared reads of the firewall reading.
var firewallReads = []Read{{ReadCheck, checkUFW}, {ReadCheck, checkNFT}, {ReadCheck, checkFirewalld},
	{ReadCheck, checkBackend}, {ReadCheck, checkOSRelease}}

// filter is the firewall's answer for one port, protocol and family.
type filter int

const (
	filterUnknown filter = iota
	filterFiltered
	filterOpen
)

// answer is a filter with what it rests on, and why it is unknown.
type answer struct {
	filter
	excerpts []Excerpt
	// reason and detail say why the answer is unknown.
	reason, detail string
	// notChecked is what the branch that decided leaves unread.
	notChecked string
	// sources are the sources of the ALLOW rules for the port that were
	// passed over because they name a source: a filtered answer lets them in.
	sources []string
}

// firewall is the host firewall read once per rule run.
type firewall struct {
	// ufw is set when ufw is active and its rules were read; it decides.
	ufw *ufwState
	// none says no host firewall filters anything: ufw inactive or absent,
	// firewalld not running or absent, an empty nftables ruleset and the
	// nf_tables iptables backend or none.
	none     bool
	excerpts []Excerpt
	unknown  answer
}

const (
	notCheckedUFW  = "Only ufw's own rule listing was read: rules added outside ufw (by scripts, Docker, kube-proxy or a network plugin, in iptables or other nftables tables) and custom lines in /etc/ufw/before.rules were not, and they can open or close this port whatever ufw shows"
	notCheckedNone = "Filters outside nftables (eBPF programs such as Cilium's) were not read"
)

// readFirewall reads the firewall facts.
func readFirewall(v *View) firewall {
	ufw, why := v.Fact(checkUFW)
	var ex []Excerpt
	switch {
	case why == "check-unavailable:command_missing":
		ex = append(ex, Excerpt{checkUFW, "not installed (command not found)"})
	case why != "":
		return unknownFirewall(reasonUFW, "ufw's status could not be read ("+why+")")
	default:
		lines, _ := ufw.Parsed.([]string)
		st, ok := parseUFW(lines)
		if !ok {
			return unknownFirewall(reasonUFW, "ufw's status output was not recognized")
		}
		st.partial = ufw.Partial
		if st.active {
			return firewall{ufw: &st}
		}
		ex = append(ex, Excerpt{checkUFW, "Status: inactive"})
	}
	fd, why := v.Fact(checkFirewalld)
	switch state := strings.TrimSpace(asText(fd.Parsed)); {
	case why == "check-unavailable:command_missing":
		ex = append(ex, Excerpt{checkFirewalld, "not installed (command not found)"})
	case why != "":
		return unknownFirewall("unavailable:firewall_firewalld", "firewalld's state could not be read ("+why+")")
	case state == "not running":
		ex = append(ex, Excerpt{checkFirewalld, "not running"})
	case state == "running":
		return unknownFirewall("unavailable:firewall_firewalld", "firewalld is running and scheck does not read its zones in this version")
	default:
		return unknownFirewall("unavailable:firewall_firewalld", "firewalld's state was not recognized")
	}
	nft, why := v.Fact(checkNFT)
	switch {
	case why == "check-unavailable:command_missing":
		return unknownFirewall("unavailable:firewall_nft", "nft is not installed, so the kernel's packet filter rules could not be listed")
	case why != "" || nft.Partial:
		return unknownFirewall("unavailable:firewall_nft", "the nftables ruleset could not be read")
	case !emptyRuleset(asText(nft.Parsed)):
		return unknownFirewall("unavailable:firewall_nft", "nftables holds rules and ufw is inactive; scheck does not read nftables rules in this version")
	}
	ex = append(ex, Excerpt{checkNFT, "empty ruleset (no tables)"})
	backend, why := v.Fact(checkBackend)
	if why != "" {
		return unknownFirewall("unavailable:firewall_backend", "which iptables backend the host uses could not be read ("+why+")")
	}
	target := strings.TrimSpace(asText(backend.Parsed))
	switch base := path.Base(target); {
	case target == "" && alpine(v):
		// Alpine keeps iptables in /sbin, which this read does not look at.
		return unknownFirewall("unavailable:firewall_backend", "/usr/sbin/iptables is not where this distribution keeps iptables")
	case target == "":
		ex = append(ex, Excerpt{checkBackend, "not installed (no /usr/sbin/iptables)"})
	case base == "xtables-nft-multi":
		ex = append(ex, Excerpt{checkBackend, target})
	case base == "xtables-legacy-multi" || base == "xtables-multi":
		return unknownFirewall("unavailable:firewall_backend", "iptables uses the legacy backend, whose rules nftables does not show and scheck does not read")
	default:
		return unknownFirewall("unavailable:firewall_backend", "/usr/sbin/iptables resolves to "+target+", which scheck does not recognize")
	}
	return firewall{none: true, excerpts: ex}
}

func unknownFirewall(reason, detail string) firewall {
	return firewall{unknown: answer{reason: reason, detail: detail}}
}

// alpine says the host's os-release names Alpine.
func alpine(v *View) bool {
	f, why := v.Fact(checkOSRelease)
	kv, _ := f.Parsed.(map[string]string)
	return why == "" && strings.EqualFold(strings.Trim(kv["ID"], `"`), "alpine")
}

func asText(parsed any) string {
	s, _ := parsed.(string)
	return s
}

// emptyRuleset says nft listed no table: nothing but blank and comment
// lines (nft 1.0 prints warnings about tables iptables-nft manages as
// comments).
func emptyRuleset(out string) bool {
	for l := range strings.SplitSeq(out, "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

// open answers whether the firewall leaves port/proto open to every source
// for one address family.
func (fw firewall) open(port int, proto string, v6 bool) answer {
	switch {
	case fw.ufw != nil:
		a := fw.ufw.walk(port, proto, v6)
		a.notChecked = notCheckedUFW
		return a
	case fw.none:
		return answer{filter: filterOpen, excerpts: fw.excerpts, notChecked: notCheckedNone}
	}
	return fw.unknown
}

// ufwState is `ufw status verbose` read.
type ufwState struct {
	active   bool
	status   string
	defaults string
	// incoming is the default for incoming traffic: deny, reject or allow.
	incoming string
	rules    []ufwRule
	// v6 says ufw lists IPv6 rules, so it manages ip6tables: with IPV6=no
	// it still prints its default, which then filters nothing over IPv6.
	v6 bool
	// partial says the read is known to be incomplete: a rule after the
	// cut may be the first match, so its default decides nothing.
	partial bool
}

type ufwRule struct {
	line   string
	action string // ALLOW | DENY | REJECT | LIMIT
	v6     bool
	iface  bool
	open   bool // from every source
	from   string
	// srcPort is the source port spec of a rule whose From names ports and
	// no address: the source is still every address, and a sender
	// chooses its own source port.
	srcPort string
	all     bool // every port
	spec    portSpec
	// to is a specific destination address, "" for any.
	to netip.Prefix
}

type portSpec struct {
	ports [][2]int // inclusive ranges
	proto string   // "" for both
}

func (p portSpec) covers(port int, proto string) bool {
	if p.proto != "" && p.proto != proto {
		return false
	}
	return slices.ContainsFunc(p.ports, func(r [2]int) bool { return port >= r[0] && port <= r[1] })
}

var (
	ufwRuleLine = regexp.MustCompile(`^(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+)$`)
	ufwDefault  = regexp.MustCompile(`(\w+) \(incoming\)`)
	ufwPorts    = regexp.MustCompile(`^(\d+(?::\d+)?(?:,\d+(?::\d+)?)*)(?:/(tcp|udp))?$`)
	// ufwAttrib is the log and direction attribute ufw prints after the
	// source: (log), (log-all), (out), or several joined by ", ".
	ufwAttrib = regexp.MustCompile(`\s+\((?:log|log-all|out)(?:, (?:log|log-all|out))*\)$`)
	// ufwIface is the interface a rule is bound to, printed last.
	ufwIface = regexp.MustCompile(` on [^\s()]+$`)
	// ufwProto is a protocol ufw prints after an address or Anywhere.
	ufwProto = regexp.MustCompile(`^(?:tcp|udp|gre|esp|ah|igmp|ipv6|vrrp)$`)
)

// parseUFW reads `ufw status verbose`; ok is false when a line is not
// recognized, since an unread rule may be the first match.
func parseUFW(lines []string) (ufwState, bool) {
	var st ufwState
	seenStatus := false
	for _, raw := range lines {
		l := strings.TrimSpace(raw)
		switch {
		case l == "" || strings.HasPrefix(l, "Logging:") || strings.HasPrefix(l, "New profiles:") || strings.Trim(l, "- ") == "":
			continue
		case l == "Status: active":
			st.active, st.status, seenStatus = true, l, true
		case l == "Status: inactive":
			st.status, seenStatus = l, true
		case strings.HasPrefix(l, "Status:"):
			return st, false
		case strings.HasPrefix(l, "Default:"):
			st.defaults = l
			m := ufwDefault.FindStringSubmatch(l)
			if m == nil {
				return st, false
			}
			st.incoming = m[1]
		case strings.HasPrefix(l, "To ") && strings.Contains(l, "Action") && strings.Contains(l, "From"):
			continue
		default:
			r, ok := parseUFWRule(l)
			if !ok {
				return st, false
			}
			if r != nil {
				st.v6 = st.v6 || r.v6
				st.rules = append(st.rules, *r)
			}
		}
	}
	if !seenStatus || st.active && !slices.Contains([]string{"deny", "reject", "allow"}, st.incoming) {
		return st, false
	}
	return st, true
}

// parseUFWRule reads one rule line as `ufw status verbose` prints it (its
// get_status): To, action and direction, From, then an attribute and a
// comment. nil for a rule that is not incoming; ok is false for a line
// whose To or From is not recognized.
func parseUFWRule(l string) (*ufwRule, bool) {
	m := ufwRuleLine.FindStringSubmatch(l)
	if m == nil {
		return nil, false
	}
	if m[3] != "IN" {
		return nil, true
	}
	r := &ufwRule{line: strings.Join(strings.Fields(l), " "), action: m[2]}
	to, from := strings.TrimSpace(m[1]), strings.TrimSpace(m[4])
	// A comment is the last thing printed; neither column holds a "#".
	if f, _, ok := strings.Cut(from, " # "); ok {
		from = strings.TrimSpace(f)
	}
	from = ufwAttrib.ReplaceAllString(from, "")
	var ok bool
	if to, ok = r.location(to); !ok {
		return nil, false
	}
	if from, ok = r.location(from); !ok {
		return nil, false
	}
	r.from = from
	switch {
	case from == "Anywhere" || anywhereProto(from):
		r.open = true
	case ufwPorts.MatchString(from):
		r.open, r.srcPort = true, from
	case !recognized(from):
		return nil, false
	}
	// A rule from an IPv6 source is an IPv6 rule: ufw prints (v6) only
	// when both ends are ::/0.
	if f := strings.Fields(from); len(f) > 0 && isAddress(f[0]) && prefix(f[0]).Addr().Is6() {
		r.v6 = true
	}
	switch fields := strings.Fields(to); {
	case to == "Anywhere":
		r.all = true
	case anywhereProto(to):
		r.all, r.spec.proto = true, strings.TrimPrefix(to, "Anywhere/")
	case ufwPorts.MatchString(to):
		r.spec = ports(to)
	case len(fields) == 2 && isAddress(fields[0]) && ufwPorts.MatchString(fields[1]):
		r.to, r.spec = prefix(fields[0]), ports(fields[1])
	case len(fields) == 1 && isAddress(to):
		r.to, r.all = prefix(to), true
	case len(fields) == 1 && addressProto(to):
		i := strings.LastIndex(to, "/")
		r.to, r.all, r.spec.proto = prefix(to[:i]), true, to[i+1:]
	default:
		return nil, false
	}
	// With To Anywhere, ufw prints the protocol in From only: it is the
	// rule's.
	if r.all && r.spec.proto == "" && r.srcPort != "" {
		r.spec.proto = ports(r.srcPort).proto
	}
	// A rule to an IPv6 destination is an IPv6 rule, (v6) or not.
	if r.to.IsValid() && r.to.Addr().Is6() {
		r.v6 = true
	}
	return r, true
}

// location strips what a To or From column prints after its address and
// ports, in get_status's order: the application profile (which may hold
// spaces and " on "), (v6), then the interface, whose name holds neither.
func (r *ufwRule) location(s string) (string, bool) {
	if m := ufwIface.FindStringSubmatchIndex(s); m != nil {
		s, r.iface = s[:m[0]], true
	}
	if t, ok := strings.CutSuffix(s, " (v6)"); ok {
		s, r.v6 = t, true
	}
	// An address or a port spec never holds " (": what follows is the
	// application profile verbose output prints after the ports.
	if i := strings.Index(s, " ("); i >= 0 {
		app := s[i:]
		if !strings.HasSuffix(app, ")") {
			return "", false
		}
		if strings.HasSuffix(app, "(v6))") {
			r.v6 = true
		}
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}

// recognized says a source column is a shape ufw prints: an address or
// network, with ports or a protocol, or ports alone.
func recognized(from string) bool {
	fields := strings.Fields(from)
	switch {
	case len(fields) == 1:
		return isAddress(fields[0]) || addressProto(fields[0]) || ufwPorts.MatchString(fields[0])
	case len(fields) == 2:
		return isAddress(fields[0]) && ufwPorts.MatchString(fields[1])
	}
	return false
}

// addressProto is "10.0.0.5/tcp" or "10.0.0.0/8/tcp": an address or
// network with a protocol and no port.
func addressProto(s string) bool {
	i := strings.LastIndex(s, "/")
	return i > 0 && ufwProto.MatchString(s[i+1:]) && isAddress(s[:i])
}

// anywhereProto is "Anywhere/gre": every address, one protocol.
func anywhereProto(s string) bool {
	proto, ok := strings.CutPrefix(s, "Anywhere/")
	return ok && ufwProto.MatchString(proto)
}

func isAddress(s string) bool {
	_, err := netip.ParsePrefix(cidr(s))
	return err == nil
}

func prefix(s string) netip.Prefix {
	p, _ := netip.ParsePrefix(cidr(s))
	return p
}

// cidr makes an address a one-address prefix.
func cidr(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}

func ports(s string) portSpec {
	m := ufwPorts.FindStringSubmatch(s)
	spec := portSpec{proto: m[2]}
	for part := range strings.SplitSeq(m[1], ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, _ := strconv.Atoi(lo)
		b := a
		if isRange {
			b, _ = strconv.Atoi(hi)
		}
		spec.ports = append(spec.ports, [2]int{a, b})
	}
	return spec
}

const reasonUFW = "unavailable:firewall_ufw"

// walk is ufw's first match for incoming traffic to port/proto from any
// source in one family, then its default.
func (st ufwState) walk(port int, proto string, v6 bool) answer {
	if v6 && !st.v6 {
		return answer{reason: reasonUFW, detail: "ufw lists no IPv6 rule, so its output does not show whether it filters IPv6"}
	}
	head := []Excerpt{{checkUFW, st.status + "; " + st.defaults}}
	var sources []string
	for _, r := range st.rules {
		if r.v6 != v6 {
			continue
		}
		if !r.all && !r.spec.covers(port, proto) || r.all && r.spec.proto != "" && r.spec.proto != proto {
			continue
		}
		switch {
		case r.iface:
			return answer{reason: reasonUFW, detail: "a ufw rule for this port applies to one network interface, and scheck cannot tell which networks that interface faces"}
		case !r.open:
			// Traffic from other sources does not match it; a filtered
			// answer says whom it lets in.
			if (r.action == "ALLOW" || r.action == "LIMIT") && !slices.Contains(sources, r.from) {
				sources = append(sources, r.from)
			}
			continue
		case r.srcPort != "" && (r.action == "DENY" || r.action == "REJECT"):
			// Traffic from other source ports does not match it.
			continue
		case r.to.IsValid() && (r.action == "DENY" || r.action == "REJECT"):
			// Traffic to the host's other addresses does not match it.
			continue
		case r.to.IsValid() && r.to.Addr().IsLoopback():
			continue
		case r.to.IsValid():
			return answer{reason: reasonUFW, detail: "a ufw rule opens this port to one of the host's addresses, and scheck does not compare it with the address the database listens on"}
		case r.srcPort != "":
			return answer{filter: filterOpen, excerpts: append(head, Excerpt{checkUFW, r.line + ": ufw allows this port from any address whose source port is " +
				r.srcPort + "; a sender chooses its own source port, so the rule does not restrict who can connect"})}
		case r.action == "ALLOW" || r.action == "LIMIT":
			return answer{filter: filterOpen, excerpts: append(head, Excerpt{checkUFW, r.line})}
		default:
			return answer{filter: filterFiltered, excerpts: append(head, Excerpt{checkUFW, r.line}), sources: sources}
		}
	}
	if st.partial {
		return answer{reason: reasonUFW, detail: "ufw's status output was cut short, so a later rule may decide this port"}
	}
	if st.incoming == "allow" {
		return answer{filter: filterOpen, excerpts: head}
	}
	return answer{filter: filterFiltered, excerpts: head, sources: sources}
}

// firewallReader reads the firewall on first use: a rule that never asks
// touches no firewall fact, so a partial one cannot withdraw its
// disproval.
type firewallReader struct {
	v  *View
	fw *firewall
}

func newFirewallReader(v *View) *firewallReader { return &firewallReader{v: v} }

// reach is the firewall's answer for the families some listeners of one
// port reach: the first open answer, the first unknown one, or what
// filters every family.
type reach struct {
	open, unknown *answer
	// openV4 and openV6 are the families left open: a rule judging the
	// bind reads only the listeners in them.
	openV4, openV6 bool
	filtered       []Excerpt
	// notChecked is the deciding branch's sentence when filtered.
	notChecked string
	// sources are what source-restricted ALLOW rules let in, when filtered.
	sources []string
}

// reach answers for listeners of one port/proto beyond loopback. A bind
// address that was not recognized is unknown.
func (r *firewallReader) reach(ls []listener) reach {
	if r.fw == nil {
		read := readFirewall(r.v)
		r.fw = &read
	}
	var out reach
	port, proto := ls[0].port, ls[0].proto
	for _, v6 := range []bool{false, true} {
		if !slices.ContainsFunc(ls, func(l listener) bool { return l.known && (v6 && l.v6 || !v6 && l.v4) }) {
			continue
		}
		a := r.fw.open(port, proto, v6)
		switch a.filter {
		case filterOpen:
			if out.open == nil {
				out.open = &a
			}
			if v6 {
				out.openV6 = true
			} else {
				out.openV4 = true
			}
		case filterUnknown:
			if out.unknown == nil {
				out.unknown = &a
			}
		default:
			out.filtered = append(out.filtered, a.excerpts...)
			out.notChecked = a.notChecked
			for _, src := range a.sources {
				if !slices.Contains(out.sources, src) {
					out.sources = append(out.sources, src)
				}
			}
		}
	}
	if slices.ContainsFunc(ls, func(l listener) bool { return !l.known }) && out.unknown == nil && out.open == nil {
		out.unknown = &answer{reason: reasonListeners, detail: "a listener's bind address was not recognized"}
	}
	out.filtered = dedupe(out.filtered)
	return out
}

// allowedFrom is the Not checked line of a filtered answer that passed
// over source-restricted ALLOW rules, "" when none: whom they let in was
// not compared with whom should be (docs/spec/engagement.md, R1, R3).
func (r reach) allowedFrom(whom string) string {
	if len(r.sources) == 0 {
		return ""
	}
	return "ufw allows this port from " + strings.Join(r.sources, ", ") + "; whether those addresses are only " + whom + " was not judged"
}

// inOpen are the listeners in a family the firewall left open.
func (r reach) inOpen(ls []listener) []listener {
	var out []listener
	for _, l := range ls {
		if l.known && (l.v4 && r.openV4 || l.v6 && r.openV6) {
			out = append(out, l)
		}
	}
	return out
}
