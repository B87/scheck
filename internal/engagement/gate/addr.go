package gate

import (
	"net/netip"
	"slices"
)

var (
	cgnat    = netip.MustParsePrefix("100.64.0.0/10")
	thisNet  = netip.MustParsePrefix("0.0.0.0/8")
	reserved = netip.MustParsePrefix("240.0.0.0/4")
	ietf     = netip.MustParsePrefix("192.0.0.0/24")
	bench    = netip.MustParsePrefix("198.18.0.0/15")
	nat64    = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4   = netip.MustParsePrefix("2002::/16")
	mapped   = netip.MustParsePrefix("::ffff:0:0/96")
	// NAT64Local is RFC 8215's local-use prefix: a site's own translator,
	// whose embedding scheme scheck does not read, so nothing behind it is
	// contacted and validation refuses an address inside it.
	NAT64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	// metadata are cloud metadata services outside the link-local range:
	// AWS over IPv6, and Alibaba Cloud inside the CGNAT range a network
	// root may cover.
	metadata = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}
)

// addrClass is what an address is to the gate.
type addrClass int

const (
	public addrClass = iota
	// notPublic is admitted only inside a declared network root.
	notPublic
	// never is admitted whatever the roots: loopback, link-local and cloud
	// metadata. A taken-over name pointed at 169.254.169.254 would put the
	// CI runner's own credentials into evidence (docs/spec/scope.md,
	// "Addresses").
	never
)

// classify places an address, looking through IPv4-mapped, NAT64 and 6to4
// forms at the IPv4 address they carry: each is at least not public, and
// never when what it carries is.
func classify(a netip.Addr) addrClass {
	if NAT64Local.Contains(a) {
		return never
	}
	if f := Forms(a); len(f) > 1 {
		return max(notPublic, classify(f[1]))
	}
	if slices.Contains(metadata, a) {
		return never
	}
	switch {
	// Dialling an unspecified address reaches this machine.
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsUnspecified():
		return never
	case a.IsPrivate(), a.IsMulticast(), a.IsInterfaceLocalMulticast(),
		cgnat.Contains(a), thisNet.Contains(a), reserved.Contains(a), ietf.Contains(a), bench.Contains(a):
		return notPublic
	}
	return public
}

// Carried is the IPv4 network an IPv6 network carries: inside IPv4-mapped
// (::ffff:0:0/96) or NAT64 (64:ff9b::/96), the IPv4 address in the last 32
// bits; inside 6to4 (2002::/16), the one in bits 16–47. A network holding
// the whole of any of them carries every IPv4 address, so excluding more
// never excludes less. False for any other network. It is the one place
// scheck reads these embeddings: the gate, the engagement's excludes and
// the SSH transport's check all compare through it (docs/spec/scope.md,
// "Addresses").
func Carried(p netip.Prefix) (netip.Prefix, bool) {
	a, b := p.Addr(), p.Addr().As16()
	switch {
	case !a.Is6():
		return netip.Prefix{}, false
	case p.Bits() < mapped.Bits() && p.Contains(mapped.Addr()), p.Bits() < nat64.Bits() && p.Contains(nat64.Addr()),
		p.Bits() < sixTo4.Bits() && p.Contains(sixTo4.Addr()):
		return netip.MustParsePrefix("0.0.0.0/0"), true
	case mapped.Contains(a), nat64.Contains(a):
		return netip.PrefixFrom(netip.AddrFrom4([4]byte(b[12:16])), max(p.Bits(), 96)-96).Masked(), true
	case sixTo4.Contains(a):
		return netip.PrefixFrom(netip.AddrFrom4([4]byte(b[2:6])), min(p.Bits(), 48)-16).Masked(), true
	}
	return netip.Prefix{}, false
}

// Forms are an address without its IPv6 zone and, for one that carries an
// IPv4 address (Carried), that address: the same machine, reached either
// way. The carried form is last. A zone names the interface, not the
// machine, and a prefix never contains a zoned address, so it is dropped:
// an /etc/hosts entry or a link-local answer cannot escape an exclude by
// carrying one.
func Forms(a netip.Addr) []netip.Addr {
	a = a.WithZone("")
	out := []netip.Addr{a}
	if c, ok := Carried(netip.PrefixFrom(a, a.BitLen())); ok {
		out = append(out, c.Addr())
	}
	return out
}
