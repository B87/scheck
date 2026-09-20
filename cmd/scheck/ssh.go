package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/check/common"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/ssh"
)

func newSSHCmd(opts *globalOpts) *cobra.Command {
	var (
		port       int
		identity   string
		knownHosts string
	)
	cmd := &cobra.Command{
		Use:   "ssh [user@]host[:port] | ssh NAME",
		Short: "Audit a remote host over SSH (NAME resolves a `targets:` entry from config)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.notInPhase1(cmd); err != nil {
				return err
			}
			var st *ssh.Target
			sess, err := opts.newSession(func(b policy.Budgets) (target.Target, error) {
				return nil, nil // placeholder; the target needs config, built below
			})
			if err != nil {
				return err
			}
			defer sess.close()

			so, err := resolveSSHTarget(sess, args[0], port, identity, knownHosts)
			if err != nil {
				return err
			}
			so.MaxOutput = sess.budgets.CaptureLimit()
			opts.logf(1, "ssh: connecting to %s@%s:%d", so.User, so.Host, so.Port)
			st, err = ssh.Dial(cmd.Context(), so)
			if err != nil {
				return usageErr("%v", err)
			}
			defer func() { _ = st.Close() }()
			sess.runner.Target = st
			if err := verifyCanary(cmd.Context(), sess, st); err != nil {
				return err
			}
			if err := detectPlatform(cmd.Context(), sess, st); err != nil {
				return err
			}
			return runStopAfter(cmd, sess)
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (default 22)")
	cmd.Flags().StringVar(&identity, "identity", "", "private key file (otherwise ssh-agent)")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	return cmd
}

// resolveSSHTarget turns the positional argument plus flags into options,
// consulting config `targets:` when the argument is a bare name.
func resolveSSHTarget(sess *session, arg string, port int, identity, knownHosts string) (ssh.Options, error) {
	so := ssh.Options{Port: port, Identity: identity, KnownHosts: knownHosts}
	if t, ok := sess.cfg.Targets[arg]; ok && !strings.ContainsAny(arg, "@:") {
		so.Host, so.User = t.Host, t.User
		if so.Port == 0 {
			so.Port = t.Port
		}
		if so.Identity == "" {
			so.Identity = t.Identity
		}
	} else {
		rest := arg
		if i := strings.LastIndex(rest, "@"); i >= 0 {
			so.User, rest = rest[:i], rest[i+1:]
		}
		if h, p, err := net.SplitHostPort(rest); err == nil {
			rest = h
			if n, err := strconv.Atoi(p); err == nil && so.Port == 0 {
				so.Port = n
			}
		}
		so.Host = rest
	}
	if so.Host == "" {
		return so, usageErr("ssh: no host in %q", arg)
	}
	if so.User == "" {
		return so, usageErr("ssh: user is required (user@host or targets.%s.user)", arg)
	}
	if strings.HasPrefix(so.Identity, "~/") {
		if home, err := homeDir(); err == nil {
			so.Identity = home + so.Identity[1:]
		}
	}
	return so, nil
}

// verifyCanary is the first thing sent on the connection. Its outcome is
// audited like any check; failure is a policy error (exit 3).
func verifyCanary(ctx context.Context, sess *session, st *ssh.Target) error {
	c, ok := check.Lookup("sys.canary", check.Any)
	if !ok {
		return usageErr("catalog has no canary check")
	}
	err := st.Verify(ctx, c.Argv, common.CanaryString)
	entry := policy.AuditEntry{CheckID: c.ID, Argv: c.Argv, Decision: "run"}
	if err != nil {
		entry.Decision = "denied:canary"
	}
	if aerr := sess.audit.Log(entry); aerr != nil {
		sess.opts.logf(0, "audit log: %v", aerr)
	}
	if err != nil {
		if errors.Is(err, target.ErrCanary) {
			return usageErr("%v", err)
		}
		return incompleteErr("%v", err)
	}
	sess.opts.logf(1, "ssh: canary ok")
	return nil
}

func detectPlatform(ctx context.Context, sess *session, st *ssh.Target) error {
	res := sess.runner.Run(ctx, "sys.platform", nil)
	if res.Status != runner.StatusOK {
		return incompleteErr("ssh: cannot detect platform: %s", res.Reason)
	}
	p := target.PlatformFromUname(strings.TrimSpace(res.Raw))
	if p == target.Unknown {
		return incompleteErr("ssh: unsupported platform %q", strings.TrimSpace(res.Raw))
	}
	st.SetPlatform(p)
	sess.opts.logf(1, "ssh: platform %s", p)
	return nil
}
