package ssh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/b87/scheck/internal/target"
)

// An address the engagement excludes is refused before a connection opens,
// whether written as an address or reached through a name; any other is
// dialled (docs/spec/scope.md, "The scope gate").
func TestDialRefusesAnExcludedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// Every loopback address: localhost resolves to 127.0.0.1, ::1 or both,
	// depending on the machine's hosts file.
	deny := func(a netip.Addr) error {
		if a.IsLoopback() {
			return errors.New("excluded")
		}
		return nil
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		var p Progress
		_, err := dialTCP(context.Background(), host, net.JoinHostPort(host, port), time.Second, "", deny, &p.Dialled, &p.Connected, &p)
		if !errors.Is(err, target.ErrExcluded) || !errors.Is(err, target.ErrAccess) {
			t.Errorf("%s: %v", host, err)
		}
		// A name is resolved here even when its address is refused.
		if p.Dialled || p.Connected || (host == "localhost") != (len(p.Resolved) == 1) {
			t.Errorf("%s: progress %+v", host, p)
		}
	}
	select {
	case <-accepted:
		t.Fatal("an excluded address was connected to")
	case <-time.After(50 * time.Millisecond):
	}
	var p Progress
	conn, err := dialTCP(context.Background(), "127.0.0.1", ln.Addr().String(), time.Second, "", func(netip.Addr) error { return nil }, &p.Dialled, &p.Connected, &p)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !p.Dialled || !p.Connected || len(p.Resolved) != 0 {
		t.Errorf("progress %+v", p)
	}
}
