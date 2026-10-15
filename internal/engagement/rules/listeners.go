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
const DatabasesVersion = "2026-10-15"

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
}

// tablePorts are the ports of the table's databases: an owner that is not
// shown there may be one.
var tablePorts = []int{5432, 3306, 33060, 6379, 27017, 11211, 8123, 9000, 8086, 5984}

// containerOwners publish a container's port: their rules bypass the host
// firewall, and the service behind them is not known.
var containerOwners = map[string]string{
	"docker-proxy": "Docker publishes this port; its rules bypass ufw and firewalld, and scheck does not read them in this version",
	"conmon":       "Podman publishes this port; its rules bypass ufw and firewalld, and scheck does not read them in this version",
}

// portProxies forward a container's port without saying what is behind it.
var portProxies = []string{"rootlessport", "pasta", "pasta.avx2", "slirp4netns"}

func isDatabase(process string, port int) bool {
	for _, d := range databases {
		if d.process == process && (d.ports == nil || slices.Contains(d.ports, port)) {
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
