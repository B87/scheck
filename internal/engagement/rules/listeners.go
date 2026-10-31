package rules

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// DatabasesVersion identifies the database table: a change to it changes
// what R1 reads as a database (docs/spec/engagement.md, R1).
const DatabasesVersion = "2026-10-31"

// database is one database program as the kernel names its process
// (comm, cut at 15 characters), and the ports it counts on: nil for any.
type database struct {
	process string
	ports   []int
}

// databases are matched by process first, then by port.
var databases = []database{
	{"postgres", nil}, {"mysqld", nil}, {"mariadbd", nil}, {"redis-server", nil}, {"valkey-server", nil},
	{"mongod", nil}, {"memcached", nil}, {"clickhouse-serv", nil}, {"clickhouse", nil}, {"influxd", nil},
	{"couchdb", nil}, {"beam.smp", []int{5984}},
	// Elasticsearch and OpenSearch run their bundled JVM, so the kernel names
	// the process java; only its two ports make it a data store.
	{"java", []int{9200, 9300}},
}

// tablePorts are the ports of the table's databases: an owner that is not
// shown there may be one.
var tablePorts = []int{5432, 3306, 33060, 6379, 27017, 11211, 8123, 9000, 8086, 5984, 9200, 9300}

// containerOwners publish a container's port: their rules bypass the host
// firewall, and the service behind them is not known.
var containerOwners = map[string]string{
	"docker-proxy": "Docker publishes this port; its rules bypass ufw and firewalld, and scheck does not read them in this version",
	"conmon":       "Podman publishes this port; its rules bypass ufw and firewalld, and scheck does not read them in this version",
}

// portProxies forward a container's port without saying what is behind it.
var portProxies = []string{"rootlessport", "pasta", "pasta.avx2", "slirp4netns"}

// tcpOnly are the table's processes that count on tcp alone: Elasticsearch
// and OpenSearch listen on no udp port.
var tcpOnly = []string{"java"}

func isDatabase(l listener) bool {
	for _, d := range databases {
		if d.process == l.process && (d.ports == nil || slices.Contains(d.ports, l.port)) &&
			(l.proto == "tcp" || !slices.Contains(tcpOnly, d.process)) {
			return true
		}
	}
	return false
}

// listener is one listening socket as R1 reads it.
type listener struct {
	proto, address, process string
	port                    int
	// loopback, v4 and v6 are what the bind address reaches; known is
	// false when the address was not recognized.
	loopback, v4, v6, known bool
}

// key is the listener's subject, port/proto.
func (l listener) key() string { return strconv.Itoa(l.port) + "/" + l.proto }

// excerpt is the listener as the report cites it.
func (l listener) excerpt() string {
	addr := l.address
	if strings.Contains(addr, ":") {
		addr = "[" + addr + "]"
	}
	owner := l.process
	if owner == "" {
		owner = "owner not shown"
	}
	return l.proto + " " + addr + ":" + strconv.Itoa(l.port) + " (" + owner + ")"
}

// listeners reads the net.listeners records: tcp sockets listening and
// udp sockets bound; ok is false for a record whose port is unreadable.
func listeners(recs check.Records) ([]listener, bool) {
	var out []listener
	ok := true
	for _, r := range recs.Items {
		proto, state := strings.ToLower(r[check.FieldProtocol]), strings.ToUpper(r[check.FieldState])
		listening := proto == "tcp" && state == "LISTEN" || proto == "udp" && state == "UNCONN"
		if !listening {
			continue
		}
		port, err := strconv.Atoi(r[check.FieldPort])
		if err != nil || port <= 0 || port > 65535 {
			ok = false
			continue
		}
		l := listener{proto: proto, address: r[check.FieldAddress], process: r[check.FieldProcess], port: port}
		l.classify()
		out = append(out, l)
	}
	// "::" alone takes IPv4 too, unless an IPv4 wildcard holds the same
	// port, which only a v6-only socket allows.
	for i, l := range out {
		if l.address != "::" {
			continue
		}
		if slices.ContainsFunc(out, func(o listener) bool { return o.address == "0.0.0.0" && o.key() == l.key() }) {
			out[i].v4 = false
		}
	}
	return out, ok
}

// classify reads the bind address: loopback, or the families beyond it.
func (l *listener) classify() {
	addr, zone, _ := strings.Cut(l.address, "%")
	l.known = true
	switch addr {
	case "*":
		l.v4, l.v6 = true, true
	case "0.0.0.0":
		l.v4 = true
	case "::":
		l.v4, l.v6 = true, true
	default:
		a, err := netip.ParseAddr(addr)
		if err != nil {
			l.known = false
			return
		}
		a = a.Unmap()
		l.loopback = a.IsLoopback()
		l.v4, l.v6 = a.Is4(), a.Is6()
	}
	if zone == "lo" {
		l.loopback = true
	}
	if l.loopback {
		l.v4, l.v6 = false, false
	}
}

// portGroup is every listener of one port/proto, loopback included.
type portGroup struct {
	port  int
	proto string
	all   []listener
}

func (g portGroup) key() string { return strconv.Itoa(g.port) + "/" + g.proto }

// beyond are the listeners beyond loopback.
func (g portGroup) beyond() []listener {
	var out []listener
	for _, l := range g.all {
		if !l.loopback {
			out = append(out, l)
		}
	}
	return out
}

// cited is the listeners as a judgment cites them.
func cited(ls []listener) Excerpt {
	var lines []string
	for _, l := range ls {
		lines = append(lines, l.excerpt())
	}
	return Excerpt{checkListeners, strings.Join(lines, "; ")}
}

// listening is the listener read grouped by port, in read order, and
// whether it is complete: not partial, every port parsed and every
// listener beyond loopback recognized and named.
type listening struct {
	groups   []portGroup
	complete bool
	// portsOK is false when a record's port was unreadable: any port may
	// be the one it hides.
	portsOK bool
}

// readListening reads net.listeners, or the abstention when it cannot.
func readListening(v *View) (listening, *Outcome) {
	f, why := v.Fact(checkListeners)
	recs, typed := f.Parsed.(check.Records)
	if why != "" || !typed {
		return listening{}, &Outcome{Verdict: Abstained, Reason: reasonListeners, Incomplete: true,
			NotChecked: []string{"the listening sockets could not be read (" + why + ")"}}
	}
	ls, portsOK := listeners(recs)
	out := listening{complete: !f.Partial && portsOK, portsOK: portsOK}
	for _, l := range ls {
		if !l.loopback && (!l.known || l.process == "") {
			out.complete = false
		}
		i := slices.IndexFunc(out.groups, func(g portGroup) bool { return g.port == l.port && g.proto == l.proto })
		if i < 0 {
			out.groups = append(out.groups, portGroup{port: l.port, proto: l.proto})
			i = len(out.groups) - 1
		}
		out.groups[i].all = append(out.groups[i].all, l)
	}
	return out, nil
}

// at is the group of port/proto.
func (l listening) at(port int, proto string) (portGroup, bool) {
	i := slices.IndexFunc(l.groups, func(g portGroup) bool { return g.port == port && strings.EqualFold(g.proto, proto) })
	if i < 0 {
		return portGroup{}, false
	}
	return l.groups[i], true
}

// ownerDoubt is why a listener's owner leaves the service behind it
// unknown: a container runtime or port proxy publishes it.
func ownerDoubt(l listener) (reason, detail string) {
	switch {
	case containerOwners[l.process] != "":
		return reasonContainerPort, containerOwners[l.process]
	case slices.Contains(portProxies, l.process):
		return reasonContainerPort, "a container port proxy owns this port; the service behind it is not known"
	}
	return "", ""
}

// Database is a database process listening on the host, on any address,
// loopback included.
type Database struct {
	Process, Address, Proto string
	Port                    int
	// ByPort: the process is read as a data store from its port alone
	// (java on Elasticsearch's ports), not from its name.
	ByPort bool
}

// Databases are the listeners in the database table on any address, in
// read order: a local postgres is still a data store (docs/spec/engagement.md,
// "Context notes", C3). Nothing when the listeners were not read.
func Databases(f Facts) []Database {
	fact, why := f.Fact(checkListeners)
	recs, typed := fact.Parsed.(check.Records)
	if why != "" || !typed {
		return nil
	}
	ls, _ := listeners(recs)
	var out []Database
	for _, l := range ls {
		if isDatabase(l) {
			out = append(out, Database{Process: l.process, Address: l.address, Proto: l.proto, Port: l.port, ByPort: l.process == "java"})
		}
	}
	return out
}
