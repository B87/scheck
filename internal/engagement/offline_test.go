package engagement

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Every gate a test of this package builds has a dialer and a resolver that
// fail at once: no test reaches crt.sh, a website or a DNS server
// (AGENTS.md, "Testing rules").
func init() {
	offline := errors.New("no network in tests")
	defaultGate = func(cfg gate.Config) (*gate.Gate, error) {
		cfg.Net = &gate.Net{
			Dial:       func(context.Context, string, string) (net.Conn, error) { return nil, offline },
			Nameserver: netip.MustParseAddr("192.0.2.53"),
			Exchange:   func(context.Context, string, []byte, bool) ([]byte, error) { return nil, offline },
		}
		return gate.New(cfg)
	}
}
