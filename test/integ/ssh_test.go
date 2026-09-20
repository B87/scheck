//go:build integration

package integ

import (
	"context"
	"errors"
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

// The CLI path: exit 3 on a failed canary, a real plan on a POSIX shell.
func TestSSHCommandExitCodes(t *testing.T) {
	c := containers.Start(t, "shell-matrix")
	bin := containers.BuildScheck(t)
	common := []string{"--identity", c.Identity, "--known-hosts", c.KnownHosts, "--stop-after", "plan"}

	out, errOut, code := containers.Run(t, bin, append([]string{"ssh", "u_fish@" + c.Addr()}, common...)...)
	if code != 3 || !strings.Contains(errOut, "canary") {
		t.Fatalf("fish: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	out, errOut, code = containers.Run(t, bin, append([]string{"ssh", "u_bash@" + c.Addr()}, common...)...)
	if code != 0 || !strings.Contains(out, "checks on linux") {
		t.Fatalf("bash: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	// Unknown host key: refused before any auth, exit 3.
	_, errOut, code = containers.Run(t, bin, "ssh", "u_bash@"+c.Addr(), "--identity", c.Identity, "--known-hosts", c.KnownHosts+".missing", "--stop-after", "plan")
	if code != 3 {
		t.Fatalf("unknown host: code=%d stderr=%q", code, errOut)
	}
}
