package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/b87/scheck/internal/target"
)

// server is an in-process sshd: it accepts any key, records the channel
// types it was asked to open, and either forwards direct-tcpip channels
// (a hop) or accepts sessions (a target).
type server struct {
	addr     string
	signer   xssh.Signer
	accepted atomic.Int32
	mu       sync.Mutex
	channels []string
}

func newServer(t *testing.T, forward bool) *server {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{signer: signer}
	cfg := &xssh.ServerConfig{PublicKeyCallback: func(xssh.ConnMetadata, xssh.PublicKey) (*xssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go s.serve(c, cfg, forward)
		}
	}()
	return s
}

func (s *server) serve(c net.Conn, cfg *xssh.ServerConfig, forward bool) {
	_, chans, reqs, err := xssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go xssh.DiscardRequests(reqs)
	for nc := range chans {
		s.mu.Lock()
		s.channels = append(s.channels, nc.ChannelType())
		s.mu.Unlock()
		switch {
		case forward && nc.ChannelType() == "direct-tcpip":
			// RFC 4254 §7.2: host string, port uint32, originator, port.
			p := nc.ExtraData()
			n := binary.BigEndian.Uint32(p[:4])
			host := string(p[4 : 4+n])
			port := binary.BigEndian.Uint32(p[4+n : 8+n])
			up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if err != nil {
				_ = nc.Reject(xssh.ConnectionFailed, err.Error())
				continue
			}
			ch, creqs, _ := nc.Accept()
			go xssh.DiscardRequests(creqs)
			go func() { _, _ = io.Copy(ch, up); _ = ch.Close() }()
			go func() { _, _ = io.Copy(up, ch); _ = up.Close() }()
		case !forward && nc.ChannelType() == "session":
			ch, creqs, _ := nc.Accept()
			go xssh.DiscardRequests(creqs)
			_ = ch
		default:
			_ = nc.Reject(xssh.Prohibited, "not here")
		}
	}
}

func (s *server) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.channels...)
}

// world writes a client identity and a known_hosts file naming the given
// servers.
func world(t *testing.T, known ...*server) (identity, khPath string) {
	t.Helper()
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := xssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	identity = filepath.Join(dir, "id")
	if err := os.WriteFile(identity, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []byte
	for _, s := range known {
		lines = append(lines, knownhosts.Line([]string{knownhosts.Normalize(s.addr)}, s.signer.PublicKey())+"\n"...)
	}
	khPath = filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, lines, 0o600); err != nil {
		t.Fatal(err)
	}
	return identity, khPath
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

// A jump host forwards one TCP connection and nothing else: no session or
// command is opened on it, and the target's host key is still verified
// (docs/ROADMAP.md, E1c).
func TestJumpHostOnlyForwards(t *testing.T) {
	hop, dst := newServer(t, true), newServer(t, false)
	identity, kh := world(t, hop, dst)
	hh, hp := hostPort(t, hop.addr)
	th, tp := hostPort(t, dst.addr)
	var p Progress
	st, err := Dial(context.Background(), Options{Host: th, Port: tp, User: "ops", Identity: identity, KnownHosts: kh,
		MaxOutput: 1024, Jump: &Hop{Host: hh, Port: hp, User: "ops"}, Progress: &p})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if p.Resolved != nil || !reflect.DeepEqual(p, Progress{Dialled: true, Connected: true, JumpDialled: true, JumpConnected: true}) {
		t.Errorf("progress %+v", p)
	}
	sess, err := st.client.NewSession()
	if err != nil {
		t.Fatalf("a session on the target through the hop: %v", err)
	}
	_ = sess.Close()
	if got := hop.seen(); len(got) != 1 || got[0] != "direct-tcpip" {
		t.Errorf("the hop was asked for %v; it must only forward", got)
	}
	if got := dst.seen(); len(got) != 1 || got[0] != "session" {
		t.Errorf("the target saw %v", got)
	}
}

// A hop whose key is unknown is refused before the target is contacted:
// exit 3, as for the target's own key.
func TestUnknownJumpHostKeyRefusesBeforeTheTarget(t *testing.T) {
	hop, dst := newServer(t, true), newServer(t, false)
	identity, kh := world(t, dst) // the hop's key is not known
	hh, hp := hostPort(t, hop.addr)
	th, tp := hostPort(t, dst.addr)
	var p Progress
	_, err := Dial(context.Background(), Options{Host: th, Port: tp, User: "ops", Identity: identity, KnownHosts: kh,
		MaxOutput: 1024, Jump: &Hop{Host: hh, Port: hp, User: "ops"}, Progress: &p})
	if !errors.Is(err, target.ErrAccess) || !errors.Is(err, target.ErrHostKeyUnknown) || !errors.Is(err, target.ErrJumpHost) {
		t.Fatalf("err %v, want an access refusal for an unknown host key", err)
	}
	// The jump host was reached; the host behind it was not tried.
	if p.Resolved != nil || !reflect.DeepEqual(p, Progress{JumpDialled: true, JumpConnected: true}) {
		t.Errorf("progress %+v", p)
	}
	time.Sleep(50 * time.Millisecond)
	if n := dst.accepted.Load(); n != 0 {
		t.Errorf("the target was contacted %d times", n)
	}
	if len(hop.seen()) != 0 {
		t.Errorf("a channel was opened on an unverified hop: %v", hop.seen())
	}
}

// A hop that cannot reach the target is a transport failure (exit 2).
func TestJumpHostThatCannotReachTheTarget(t *testing.T) {
	hop := newServer(t, true)
	identity, kh := world(t, hop)
	hh, hp := hostPort(t, hop.addr)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closedPort := hostPort(t, ln.Addr().String())
	_ = ln.Close()
	var p Progress
	_, err := Dial(context.Background(), Options{Host: "127.0.0.1", Port: closedPort, User: "ops", Identity: identity,
		KnownHosts: kh, MaxOutput: 1024, Timeout: 2 * time.Second, Jump: &Hop{Host: hh, Port: hp, User: "ops"}, Progress: &p})
	if !errors.Is(err, target.ErrUnreachable) || errors.Is(err, target.ErrAccess) {
		t.Fatalf("err %v, want unreachable", err)
	}
	// Tried through the jump host, which never got through.
	if p.Resolved != nil || !reflect.DeepEqual(p, Progress{Dialled: true, JumpDialled: true, JumpConnected: true}) {
		t.Errorf("progress %+v", p)
	}
}
