//go:build integration

package integ

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/check/common"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/ssh"
	"github.com/b87/scheck/test/containers"
)

// Acceptance criterion 11: the canary aborts against fish and a restricted
// shell before any other command is sent, and passes on POSIX shells.
func TestCanaryMatrix(t *testing.T) {
	c := containers.Start(t, "shell-matrix")
	canary, _ := check.Lookup("sys.canary", check.Any)
	cases := map[string]bool{"u_sh": true, "u_bash": true, "u_zsh": true, "u_fish": false, "u_rbash": false}
	for user, wantOK := range cases {
		t.Run(user, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, err := ssh.Dial(ctx, ssh.Options{Host: c.Host, Port: c.Port, User: user, Identity: c.Identity,
				KnownHosts: c.KnownHosts, MaxOutput: 64 << 10})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			err = st.Verify(ctx, canary.Argv, common.CanaryString)
			if wantOK {
				if err != nil {
					t.Fatalf("canary failed on %s: %v (echo %q)", user, err, st.CanaryOutput)
				}
				res, err := st.Exec(ctx, []string{"uname", "-s"})
				if err != nil || strings.TrimSpace(string(res.Stdout)) != "Linux" {
					t.Fatalf("exec after canary: %+v %v", res, err)
				}
				return
			}
			if !errors.Is(err, target.ErrCanary) {
				t.Fatalf("%s: want ErrCanary, got %v (echo %q)", user, err, st.CanaryOutput)
			}
			if _, err := st.Exec(ctx, []string{"uname", "-s"}); !errors.Is(err, target.ErrCanary) {
				t.Fatalf("%s: a command was accepted after a failed canary: %v", user, err)
			}
		})
	}
}

// The CLI path, through the 0.0.2 alias: exit 3 on a failed canary with the
// echo kept out of the text, a run on a POSIX shell, and exit 3 on an
// unknown host key.
func TestSSHCommandExitCodes(t *testing.T) {
	c := containers.Start(t, "shell-matrix")
	bin := containers.BuildScheck(t)
	common := []string{"--identity", c.Identity, "--known-hosts", c.KnownHosts, "--no-persist"}

	out, errOut, code := containers.Run(t, bin, append([]string{"ssh", "u_fish@" + c.Addr()}, common...)...)
	if code != 3 || !strings.Contains(errOut, "canary") || !strings.Contains(out, "REFUSED:") ||
		!strings.Contains(out, "login shell changed what it sent back") || !strings.Contains(out, "does not by itself mean") {
		t.Fatalf("fish: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = containers.Run(t, bin, append([]string{"ssh", "u_bash@" + c.Addr(), "--format", "json"}, common...)...)
	if code > 1 || !strings.Contains(out, `"canary": "ok"`) {
		t.Fatalf("bash: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	// An unreadable known_hosts file: refused before any contact, exit 3.
	out, errOut, code = containers.Run(t, bin, "ssh", "u_bash@"+c.Addr(), "--identity", c.Identity, "--known-hosts", c.KnownHosts+".missing", "--no-persist")
	if code != 3 || !strings.Contains(out, "scheck could not use the access it was given") {
		t.Fatalf("missing known_hosts: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	// Unknown host key: refused before any auth, exit 3, and said as such.
	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = containers.Run(t, bin, "ssh", "u_bash@"+c.Addr(), "--identity", c.Identity, "--known-hosts", empty, "--no-persist")
	if code != 3 || !strings.Contains(out, "its host key is not in your known_hosts file") {
		t.Fatalf("unknown host: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}
