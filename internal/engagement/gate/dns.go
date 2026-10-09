package gate

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The gate's own DNS client (docs/spec/scope.md, "Third-party sources", "The
// resolver"): one question per query, to the first nameserver in the
// system's resolv.conf, over UDP with TCP on a truncated answer. It reads
// what the system's lookup functions hide: the rcode, which tells NXDOMAIN
// from NODATA from SERVFAIL, and the CNAME chain, which is what a dangling
// record is.

type dnsType uint16

const (
	typeA     dnsType = 1
	typeNS    dnsType = 2
	typeCNAME dnsType = 5
	typeMX    dnsType = 15
	typeTXT   dnsType = 16
	typeAAAA  dnsType = 28
)

var typeNames = map[dnsType]string{typeA: "A", typeNS: "NS", typeCNAME: "CNAME", typeMX: "MX", typeTXT: "TXT", typeAAAA: "AAAA"}

func (t dnsType) String() string { return typeNames[t] }

const (
	rcodeOK       = 0
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeRefused  = 5
)

// maxChain is how many CNAME hops a name may take (docs/spec/scope.md,
// "Discovery").
const maxChain = 8

// dnsTimeout bounds each query.
const dnsTimeout = 5 * time.Second

// Outcome is what resolving one name came to.
type Outcome string

const (
	OutcomeAddresses Outcome = "addresses"
	// OutcomeRecords is a record lookup that found records of its type.
	OutcomeRecords  Outcome = "records"
	OutcomeNXDomain Outcome = "nxdomain"
	// OutcomeNoData is a final name that exists with no address.
	OutcomeNoData   Outcome = "nodata"
	OutcomeServFail Outcome = "servfail"
	OutcomeRefused  Outcome = "refused"
	OutcomeTimeout  Outcome = "timeout"
	// OutcomeLoop is a chain that loops or passes maxChain.
	OutcomeLoop Outcome = "loop"
	// OutcomeExcluded is a chain that enters a name an exclude covers,
	// which is never queried.
	OutcomeExcluded Outcome = "excluded"
	// OutcomeError is an answer scheck cannot read, a name in it that is
	// not one, or an address redact_extra matches.
	OutcomeError Outcome = "error"
	// OutcomeNoResolver is a question never sent: no nameserver to ask.
	OutcomeNoResolver  Outcome = "no_resolver"
	OutcomeDeadline    Outcome = "deadline"
	OutcomeCanceled    Outcome = "canceled"
	OutcomeAuditFailed Outcome = "audit_failed"
)

// Lookup is what resolving one name found.
type Lookup struct {
	Name string
	// Chain is the CNAME targets in order, the last one the name the
	// addresses (or the failure) belong to.
	Chain []string
	Addrs []netip.Addr
	// Outside is the chain's first name outside every root, "" when none:
	// the service a name points at.
	Outside string
	// FinalInRoot says the name the chain ends at is under a root: a
	// dangling chain there is a stale record, not a takeover candidate.
	FinalInRoot bool
	Outcome     Outcome
	// ExcludedBy is the exclude a chain entered.
	ExcludedBy string
	// Queries counts the queries sent for it.
	Queries int
	// target is Target as answered, before redaction: what PointsAt
	// compares, so a verdict out of the gate is the gate's own.
	target string
}

// PointsAt reports whether the name points where a first_party
// confirmation's target says (canonical, as validation reads it): the
// comparison the gate makes before it sends a path the confirmation
// admits, made on the names as answered.
func (l Lookup) PointsAt(target string) bool {
	return target != "" && l.target == target
}

// Final is the name the chain ends at.
func (l Lookup) Final() string {
	if len(l.Chain) == 0 {
		return l.Name
	}
	return l.Chain[len(l.Chain)-1]
}

// Insufficient reports a lookup that says nothing about the name: never
// dangling, never resolved, retried on resume.
func (l Lookup) Insufficient() bool {
	switch l.Outcome {
	case OutcomeAddresses, OutcomeNXDomain, OutcomeNoData:
		return false
	}
	return true
}

// Target is where the name points, as a first_party confirmation records
// it and the gate checks it (docs/spec/scope.md, "First-party evidence"):
// the chain's first name outside every root, else its addresses
// (JoinAddrs); "" when it has neither.
func (l Lookup) Target() string {
	if l.Outside != "" {
		return l.Outside
	}
	return JoinAddrs(l.Addrs)
}

// JoinAddrs is a set of addresses as a confirmation's target holds them:
// IPv4 first, each family in order, once each, joined with commas. It is
// also the order the gate dials them in.
func JoinAddrs(addrs []netip.Addr) string {
	out := make([]string, 0, len(addrs))
	for _, a := range sortAddrs(addrs) {
		out = append(out, a.String())
	}
	return strings.Join(out, ",")
}

func sortAddrs(addrs []netip.Addr) []netip.Addr {
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, func(x, y netip.Addr) int {
		return cmp.Or(cmp.Compare(x.BitLen(), y.BitLen()), x.Compare(y))
	})
	return slices.Compact(addrs)
}

// dnsQuery encodes a recursive query for name, a fully qualified name
// without its trailing dot.
func dnsQuery(id uint16, name string, t dnsType) ([]byte, error) {
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01                          // RD
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	if len(name) > 253 {
		return nil, errors.New("name longer than 253 characters")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("%q is not a DNS name", name)
		}
		b = append(b, byte(len(label))) //nolint:gosec // at most 63, checked above
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(t))
	return binary.BigEndian.AppendUint16(b, 1), nil // class IN
}

type dnsRR struct {
	name   string
	typ    dnsType
	target string     // CNAME, MX, NS
	addr   netip.Addr // A, AAAA
	pref   uint16     // MX
	// txt is a TXT record's character-strings, kept apart: a rule joins
	// them (RFC 7208 §3.3).
	txt []string
}

type dnsMsg struct {
	id        uint16
	rcode     int
	truncated bool
	qname     string
	qtype     dnsType
	answers   []dnsRR
}

var errShort = errors.New("short DNS message")

// readName decodes a possibly compressed name at off; it returns the name
// lowercased, without its trailing dot, and the offset after it in place.
// A pointer must point backwards, so a message cannot make it loop.
func readName(b []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(b) {
			return "", 0, errShort
		}
		n := int(b[off])
		switch {
		case n == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), end, nil
		case n&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, errShort
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if ptr >= off || jumps > 64 {
				return "", 0, errors.New("bad DNS name pointer")
			}
			if end < 0 {
				end = off + 2
			}
			off, jumps = ptr, jumps+1
		case n&0xc0 != 0:
			return "", 0, errors.New("bad DNS label")
		default:
			if off+1+n > len(b) {
				return "", 0, errShort
			}
			if bytes.IndexByte(b[off+1:off+1+n], '.') >= 0 {
				// Joined with dots, it would read as another name.
				return "", 0, errors.New("a DNS label holding a dot")
			}
			labels = append(labels, string(b[off+1:off+1+n]))
			off += 1 + n
		}
	}
}

// parseDNS decodes a response: its header, its one question and the A,
// AAAA, CNAME, MX, NS and TXT records of its answer section; other records
// are skipped. A record of a known type whose data does not decode fails
// the whole message.
func parseDNS(b []byte) (dnsMsg, error) {
	if len(b) < 12 {
		return dnsMsg{}, errShort
	}
	m := dnsMsg{id: binary.BigEndian.Uint16(b), rcode: int(b[3] & 0x0f), truncated: b[2]&0x02 != 0}
	if b[2]&0x80 == 0 {
		return dnsMsg{}, errors.New("not a DNS response")
	}
	qd, an := binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:])
	if qd != 1 {
		return dnsMsg{}, errors.New("a DNS response with other than one question")
	}
	name, off, err := readName(b, 12)
	if err != nil {
		return dnsMsg{}, err
	}
	if off+4 > len(b) {
		return dnsMsg{}, errShort
	}
	m.qname, m.qtype = name, dnsType(binary.BigEndian.Uint16(b[off:]))
	off += 4
	for range an {
		rr := dnsRR{}
		if rr.name, off, err = readName(b, off); err != nil {
			return dnsMsg{}, err
		}
		if off+10 > len(b) {
			return dnsMsg{}, errShort
		}
		rr.typ = dnsType(binary.BigEndian.Uint16(b[off:]))
		class := binary.BigEndian.Uint16(b[off+2:])
		size := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+size > len(b) {
			return dnsMsg{}, errShort
		}
		data := b[off : off+size]
		switch {
		case class != 1:
		case rr.typ == typeA && size == 4:
			rr.addr = netip.AddrFrom4([4]byte(data))
			m.answers = append(m.answers, rr)
		case rr.typ == typeAAAA && size == 16:
			rr.addr = netip.AddrFrom16([16]byte(data))
			m.answers = append(m.answers, rr)
		case rr.typ == typeCNAME || rr.typ == typeNS:
			if rr.target, err = rdataName(b, off, off+size); err != nil {
				return dnsMsg{}, err
			}
			m.answers = append(m.answers, rr)
		case rr.typ == typeMX:
			if size < 3 {
				return dnsMsg{}, errShort
			}
			rr.pref = binary.BigEndian.Uint16(data)
			if rr.target, err = rdataName(b, off+2, off+size); err != nil {
				return dnsMsg{}, err
			}
			m.answers = append(m.answers, rr)
		case rr.typ == typeTXT:
			if rr.txt, err = txtStrings(data); err != nil {
				return dnsMsg{}, err
			}
			m.answers = append(m.answers, rr)
		}
		off += size
	}
	return m, nil
}

// rdataName reads a name in a record's data, which must end inside it.
func rdataName(b []byte, off, end int) (string, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return "", err
	}
	if next > end {
		return "", errors.New("a DNS name runs past its record")
	}
	return name, nil
}

// txtStrings splits a TXT record's data into its character-strings, each a
// length byte and that many bytes (RFC 1035 §3.3.14).
func txtStrings(data []byte) ([]string, error) {
	out := []string{}
	for i := 0; i < len(data); {
		n := int(data[i])
		if i+1+n > len(data) {
			return nil, errShort
		}
		out = append(out, string(data[i+1:i+1+n]))
		i += 1 + n
	}
	if len(out) == 0 {
		return nil, errors.New("a TXT record with no string")
	}
	return out, nil
}

// nameserver is the first nameserver in resolv.conf, or the zero address.
func nameserver(conf []byte) netip.Addr {
	for line := range strings.SplitSeq(string(conf), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				return a
			}
		}
	}
	return netip.Addr{}
}

func systemNameserver() netip.Addr {
	conf, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return netip.Addr{}
	}
	return nameserver(conf)
}

// exchange sends one query to server over UDP or TCP. The resolver is the
// system's, not a target: the address rules are for what a request reaches.
func exchange(ctx context.Context, server string, query []byte, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if !tcp {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	if len(query) > 512 {
		return nil, errors.New("a DNS query over 512 bytes")
	}
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil { //nolint:gosec // at most 512, checked above
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// query sends one question, audited as a dns line before and a dns_answer
// line after (redacted as record and auditAnswer do), paced by the DNS ceiling and bounded by
// dnsTimeout and the run's deadline. It returns the decoded answer, or the
// outcome that ended it.
func (g *Gate) query(ctx context.Context, e Entry, name string, t dnsType) (dnsMsg, Outcome) {
	ctx, cancel := g.withDeadline(ctx, dnsTimeout)
	defer cancel()
	if !g.nameserver.IsValid() {
		return dnsMsg{}, OutcomeNoResolver
	}
	release, err := g.dns.acquire(ctx, g.now, g.sleep)
	switch {
	case err != nil && g.pastDeadline(g.now()):
		return dnsMsg{}, OutcomeDeadline
	case errors.Is(err, context.Canceled):
		return dnsMsg{}, OutcomeCanceled
	case err != nil:
		return dnsMsg{}, OutcomeTimeout
	}
	defer release()
	d := Entry{Event: "dns", RequestID: e.RequestID, Stage: e.Stage, Asset: e.Asset, Op: "dns", Source: "dns",
		Params: map[string]string{"name": name, "type": t.String()}, DestIP: g.nameserver.String(), Decision: DecisionSent}
	if err := g.record(d); err != nil {
		return dnsMsg{}, OutcomeAuditFailed
	}
	g.countDNS()
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dnsQuery(id, name, t)
	if err != nil {
		return dnsMsg{}, OutcomeError
	}
	server := netip.AddrPortFrom(g.nameserver, 53).String()
	start := g.now()
	var m dnsMsg
	var out Outcome
	for _, tcp := range []bool{false, true} {
		raw, err := g.exchange(ctx, server, q, tcp)
		if err != nil {
			out = OutcomeError
			switch {
			case g.pastDeadline(g.now()):
				out = OutcomeDeadline
			case errors.Is(err, context.Canceled):
				out = OutcomeCanceled
			case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
				out = OutcomeTimeout
			}
			break
		}
		if m, err = parseDNS(raw); err != nil || m.id != id || m.qname != name || m.qtype != t {
			out = OutcomeError
			break
		}
		if !m.truncated {
			break
		}
	}
	d.Event, d.Time, d.DurationMS = "dns_answer", time.Time{}, g.now().Sub(start).Milliseconds()
	switch {
	case out != "":
	case m.rcode == rcodeOK:
	case m.rcode == rcodeNXDomain:
		d.Decision = "unavailable:nxdomain"
	case m.rcode == rcodeServFail:
		out = OutcomeServFail
	case m.rcode == rcodeRefused:
		out = OutcomeRefused
	default:
		out = OutcomeError
	}
	if out != "" {
		d.Decision = "unavailable:" + string(out)
	}
	// Each name and address redacted on its own, as the gate judges them,
	// so an anchored pattern matches here as it does there, and only
	// once: record leaves answers as they are.
	for _, rr := range m.answers {
		d.Answers = append(d.Answers, g.auditAnswer(rr))
	}
	_ = g.record(d)
	return m, out
}

// auditAnswer is one answer record as the audit line holds it, each name,
// address and string redacted on its own.
func (g *Gate) auditAnswer(rr dnsRR) string {
	name := g.redact(rr.name)
	switch rr.typ {
	case typeCNAME, typeNS:
		return name + " " + rr.typ.String() + " " + g.redact(rr.target)
	case typeMX:
		return name + " MX " + strconv.Itoa(int(rr.pref)) + " " + g.redact(rr.target)
	case typeTXT:
		return name + " TXT " + strconv.Quote(g.joinTXT(rr.txt))
	}
	return name + " " + g.redact(rr.addr.String())
}

// joinTXT is a TXT record as rules read it, its strings joined (RFC 7208
// §3.3), redacted once as joined: a value split across two strings, as
// providers split a long record wherever 255 bytes fall, is redacted whole,
// and no marker is redacted again.
func (g *Gate) joinTXT(strs []string) string {
	return g.redact(strings.Join(strs, ""))
}

func (g *Gate) redact(v string) string {
	v, _ = g.redactor.RedactString(v)
	return v
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// lookup resolves name's A and AAAA records, following its CNAME chain at
// most maxChain hops (docs/spec/scope.md, "Discovery"), and places the
// chain against the roots (Lookup.Outside).
func (g *Gate) lookup(ctx context.Context, e Entry, name string) Lookup {
	l, records := g.chase(ctx, e, name, OutcomeAddresses, typeA, typeAAAA)
	for _, rr := range records {
		l.Addrs = append(l.Addrs, rr.addr)
	}
	if g.redactsAddr(l.Addrs) {
		// An address redact_extra matches can be neither dialled nor
		// recorded: the audit line's dest_ip would hold it.
		l.Addrs, l.Outcome = nil, OutcomeError
	}
	for _, hop := range l.Chain {
		if d, err := answerName(hop); err != nil || d != hop {
			break // the hop chase stopped at, which is not a name
		}
		if g.scope.Subject(e.Asset, "domain:"+hop).Root == "" {
			l.Outside = hop
			break
		}
	}
	l.FinalInRoot = g.scope.Subject(e.Asset, "domain:"+l.Final()).Root != ""
	l.target = l.Target()
	return l
}

// redactsAddr reports whether redact_extra matches any of the addresses.
func (g *Gate) redactsAddr(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if s := a.String(); g.redact(s) != s {
			return true
		}
	}
	return false
}

// chase follows the chain. A resolver normally answers with the whole
// chain; when it stops at a CNAME, the gate asks for the chain's end
// itself. NXDOMAIN and NODATA belong to the chain's end. A chain that
// enters a name an exclude covers (Scope.Name) stops there: the resolver
// may have followed it, but the gate sends no query for it
// (docs/spec/scope.md, "Discovery"), and a request through it is refused.
//
// When neither address query finds an address or a CNAME at the chain's
// end, the gate asks for its CNAME: a DNS host may answer an address query
// for an in-zone CNAME whose target does not exist with NXDOMAIN and no
// CNAME, and only a CNAME query shows the dangling record
// (docs/spec/scope.md, "The resolver").
func (g *Gate) chase(ctx context.Context, e Entry, name string, found Outcome, types ...dnsType) (Lookup, []dnsRR) {
	l := Lookup{Name: name}
	seen, asked, cnameAsked := map[string]bool{name: true}, map[string]bool{}, map[string]bool{}
	cur := name
	for {
		asked[cur] = true
		var records []dnsRR
		nx := false
		for _, t := range types {
			m, out := g.query(ctx, e, cur, t)
			l.Queries++
			if out != "" {
				l.Outcome = out
				return l, nil
			}
			if g.extend(&l, m, seen) {
				return l, nil
			}
			for _, rr := range m.answers {
				if rr.typ == t && rr.name == l.Final() {
					records = append(records, rr)
				}
			}
			if m.rcode == rcodeNXDomain {
				nx = true
				break
			}
		}
		// The chain's end, once per name: where the queries stopped
		// (NODATA moves on to ask a new end itself), or a new end the
		// resolver answered NXDOMAIN for.
		if end := l.Final(); len(records) == 0 && !cnameAsked[end] && (end == cur || nx) {
			cnameAsked[end] = true
			m, out := g.query(ctx, e, end, typeCNAME)
			l.Queries++
			if out != "" {
				l.Outcome = out
				return l, nil
			}
			if g.extend(&l, m, seen) {
				return l, nil
			}
			if l.Final() != end {
				cur = l.Final()
				continue
			}
		}
		switch {
		case len(records) > 0:
			l.Outcome = found
			return l, records
		case nx:
			l.Outcome = OutcomeNXDomain
			return l, nil
		case asked[l.Final()]:
			l.Outcome = OutcomeNoData
			return l, nil
		}
		cur = l.Final()
	}
}

// extend follows the CNAME records in m from the chain's end. It reports
// true when the chain ends there, its outcome set: a loop or a chain past
// maxChain, a target that is not a name, or one an exclude covers.
func (g *Gate) extend(l *Lookup, m dnsMsg, seen map[string]bool) bool {
	for next := cname(m, l.Final()); next != ""; next = cname(m, l.Final()) {
		if seen[next] || len(l.Chain) >= maxChain {
			l.Outcome = OutcomeLoop
			return true
		}
		seen[next] = true
		l.Chain = append(l.Chain, next)
		if d, err := answerName(next); err != nil || d != next {
			// Not a name scheck would query or print as one.
			l.Outcome = OutcomeError
			return true
		}
		if x := g.scope.Name(next); x != "" {
			l.Outcome, l.ExcludedBy = OutcomeExcluded, x
			return true
		}
	}
	return false
}

// cname is the target of name's CNAME record in m, or "".
func cname(m dnsMsg, name string) string {
	for _, rr := range m.answers {
		if rr.typ == typeCNAME && rr.name == name {
			return rr.target
		}
	}
	return ""
}

// Resolve is one discovery lookup.
type Resolve struct {
	Asset, Name, Stage string
	// Control marks a control lookup: a random label under a root, or
	// under invalid., whose answer says how the resolver treats names that
	// do not exist. The report counts them apart.
	Control bool
}

// DecisionSent is the decision of a request or lookup the gate sent.
const DecisionSent = "sent"

// Resolved is a lookup's admission and what it found.
type Resolved struct {
	RequestID string
	// Decision is sent or refused:<rule>, as the audit line has it.
	Decision string
	Detail   string
	// ExcludedBy is the exclude that refused the name, or that its chain
	// entered.
	ExcludedBy string
	Lookup     Lookup
}

// Resolve admits and sends one discovery lookup (docs/spec/scope.md,
// "Discovery"): a name under the asset's root and no exclude, its A and
// AAAA records with the CNAME chain. A control name under `invalid.` (RFC
// 6761), which names no one's asset, is the one lookup outside every root
// the gate sends. A name an exclude covers (Scope.Name) is refused before
// any query: a query reaches its authoritative servers, which may be the
// excluded party's.
func (g *Gate) Resolve(ctx context.Context, r Resolve) Resolved {
	e := Entry{RequestID: g.nextID(), Stage: r.Stage, Asset: r.Asset, Op: "dns.lookup", Source: "dns",
		Params: map[string]string{"name": r.Name}}
	refuse := func(rule, detail string) Resolved {
		e.Event, e.Decision, e.Detail = "refused", "refused:"+rule, detail
		_ = g.record(e)
		out := Resolved{RequestID: e.RequestID, Decision: e.Decision, Detail: detail}
		if rule == "excluded" {
			out.ExcludedBy = detail
		}
		return out
	}
	name := strings.TrimSuffix(r.Name, ".")
	if d, err := dnsName(name); err != nil || d != name {
		return refuse("bind", "not a lowercase DNS name")
	}
	invalid := strings.HasSuffix(name, ".invalid")
	if !invalid {
		rule, detail := g.placeSubject(r.Asset, "domain:"+name)
		if rule == "" {
			if x := g.scope.Name(name); x != "" {
				rule, detail = "excluded", x
			}
		}
		if rule != "" {
			return refuse(rule, detail)
		}
	}
	if g.pastDeadline(g.now()) {
		return refuse("deadline", "limits.timeout passed")
	}
	if !g.nameserver.IsValid() {
		// Nothing to ask: not sent, so neither counted nor a control.
		e.Event, e.Decision, e.Detail = "refused", "unavailable:no_resolver", "no nameserver in /etc/resolv.conf"
		_ = g.record(e)
		return Resolved{RequestID: e.RequestID, Decision: e.Decision, Detail: e.Detail}
	}
	if r.Control {
		g.countControl(invalid)
	}
	l := g.redactLookup(g.lookup(ctx, e, name))
	return Resolved{RequestID: e.RequestID, Decision: DecisionSent, ExcludedBy: l.ExcludedBy, Lookup: l}
}

// redactLookup is a lookup as it leaves the gate: redact_extra may name an
// internal host a CNAME points at, which scope.json and the report would
// otherwise print. Every verdict on the names (Outside, FinalInRoot,
// PointsAt, an exclude in the chain) was made on them as answered, before
// this; an address redact_extra matches already ended the lookup.
func (g *Gate) redactLookup(l Lookup) Lookup {
	if l.Chain != nil {
		chain := make([]string, len(l.Chain))
		for i, hop := range l.Chain {
			chain[i] = g.redact(hop)
		}
		l.Chain = chain
	}
	l.Outside = g.redact(l.Outside)
	return l
}

// Records is one read of the records of a name the engagement file gives
// (docs/spec/web-collector.md, "Reads"): TXT at a domain, at `_dmarc.<d>`
// or at `<selector>._domainkey.<d>`, MX or NS at a domain.
type Records struct {
	Asset, Name, Stage string
	// Type is TXT, MX or NS.
	Type string
}

// MX is one mail exchanger: its preference and target, "" for a null MX
// (RFC 7505).
type MX struct {
	Pref   uint16
	Target string
}

// RecordSet is a records read's admission and what it found. Names in it,
// the chain and MX and NS targets, are redacted as a lookup's are, and each
// TXT record is redacted as rules read it (joinTXT).
type RecordSet struct {
	RequestID string
	// Decision is sent or refused:<rule>, unavailable:no_resolver when
	// there is no nameserver to ask.
	Decision   string
	Detail     string
	ExcludedBy string
	// Chain is the CNAME targets followed, the last the name the records
	// (or the failure) belong to.
	Chain   []string
	Outcome Outcome
	// TXT holds each TXT record, its strings joined.
	TXT []string
	MX  []MX
	NS  []string
}

// Insufficient reports a read that says nothing about the name's records.
func (r RecordSet) Insufficient() bool {
	switch r.Outcome {
	case OutcomeRecords, OutcomeNXDomain, OutcomeNoData:
		return false
	}
	return true
}

var recordTypes = map[string]dnsType{"TXT": typeTXT, "MX": typeMX, "NS": typeNS}

// ReadRecords admits and sends one records read: a name scheck builds
// from the engagement file (recordName), under the asset's root and no
// exclude, its records of one type, with the CNAME chain followed as an
// address lookup follows it.
func (g *Gate) ReadRecords(ctx context.Context, r Records) RecordSet {
	e := Entry{RequestID: g.nextID(), Stage: r.Stage, Asset: r.Asset, Op: "dns.records", Source: "dns",
		Params: map[string]string{"name": r.Name, "type": r.Type}}
	refuse := func(decision, detail string) RecordSet {
		e.Event, e.Decision, e.Detail = "refused", decision, detail
		_ = g.record(e)
		out := RecordSet{RequestID: e.RequestID, Decision: e.Decision, Detail: detail}
		if decision == "refused:excluded" {
			out.ExcludedBy = detail
		}
		return out
	}
	t, ok := recordTypes[r.Type]
	if !ok {
		return refuse("refused:bind", "not TXT, MX or NS")
	}
	name := strings.TrimSuffix(r.Name, ".")
	if d, err := recordName(name); err != nil || d != name {
		return refuse("refused:bind", "not a lowercase DNS name scheck reads records at")
	}
	rule, detail := g.placeSubject(r.Asset, "domain:"+name)
	if rule == "" {
		if x := g.scope.Name(name); x != "" {
			rule, detail = "excluded", x
		}
	}
	switch {
	case rule != "":
		return refuse("refused:"+rule, detail)
	case g.pastDeadline(g.now()):
		return refuse("refused:deadline", "limits.timeout passed")
	case !g.nameserver.IsValid():
		return refuse("unavailable:no_resolver", "no nameserver in /etc/resolv.conf")
	}
	l, records := g.chase(ctx, e, name, OutcomeRecords, t)
	out := RecordSet{RequestID: e.RequestID, Decision: DecisionSent, ExcludedBy: l.ExcludedBy, Outcome: l.Outcome}
	for _, rr := range records {
		switch rr.typ {
		case typeTXT:
			out.TXT = append(out.TXT, g.joinTXT(rr.txt))
		case typeMX, typeNS:
			// A target is a name the collector may look up next: one that
			// is not a name ends the read, as a chain's hop does. A null
			// MX's target is the root, "".
			if d, err := answerName(rr.target); (err != nil || d != rr.target) && (rr.typ != typeMX || rr.target != "") {
				return RecordSet{RequestID: e.RequestID, Decision: DecisionSent, Outcome: OutcomeError, Chain: g.redactLookup(l).Chain}
			}
			if rr.typ == typeMX {
				out.MX = append(out.MX, MX{Pref: rr.pref, Target: g.redact(rr.target)})
			} else {
				out.NS = append(out.NS, g.redact(rr.target))
			}
		}
	}
	out.Chain = g.redactLookup(l).Chain
	return out
}
