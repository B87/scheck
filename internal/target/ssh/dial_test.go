package ssh

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/b87/scheck/internal/target"
)

// Exit 3 is a positive list: a host key scheck cannot verify and failed
// authentication. Every other handshake failure is a transport failure
// (docs/spec/engagement.md, "Exit codes").
func TestHandshakeErrorsAreClassified(t *testing.T) {
	o := Options{Host: "203.0.113.5", KnownHosts: "/kh"}
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"unknown host key", &knownhosts.KeyError{}, target.ErrAccess},
		{"unknown host key, kind", &knownhosts.KeyError{}, target.ErrHostKeyUnknown},
		{"changed host key", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}, target.ErrAccess},
		{"changed host key, kind", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}, target.ErrHostKeyChanged},
		{"authentication", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"), target.ErrAccess},
		{"reset", errors.New("read tcp: connection reset by peer"), target.ErrUnreachable},
		{"eof", io.EOF, target.ErrUnreachable},
		{"deadline", errors.New("read tcp: i/o timeout"), target.ErrUnreachable},
	}
	for _, tc := range cases {
		got := handshakeErr(tc.err, "203.0.113.5:22", o, "")
		if !errors.Is(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
