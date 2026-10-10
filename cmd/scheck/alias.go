package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// The 0.0.1 commands are aliases of `scheck run --host` for 0.0.2 only and
// are removed in 0.0.3 (docs/spec/host-collector.md §8, "The aliases").
// Each 0.0.1 flag maps to its run equivalent or exits 3
// naming the replacement; nothing is accepted and silently ignored.

func newLocalCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Deprecated: scheck run --host local",
		Long: "Deprecated alias of `scheck run --host local`, removed in 0.0.3. It runs the one-host\n" +
			"engagement and prints the engagement report; with --format json a host's own envelope is\n" +
			"assets[0].envelope.",
		Example: "  scheck run --host local\n  scheck run --host local --format json --no-persist",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlias(cmd, opts, &hostOpts{host: "local"})
		},
	}
}

func newSSHCmd(opts *globalOpts) *cobra.Command {
	var (
		port int
		ho   hostOpts
	)
	cmd := &cobra.Command{
		Use:   "ssh user@host[:port]",
		Short: "Deprecated: scheck run --host user@host",
		Long: "Deprecated alias of `scheck run --host user@host`, removed in 0.0.3. It runs the one-host\n" +
			"engagement and prints the engagement report; with --format json a host's own envelope is\n" +
			"assets[0].envelope.",
		Example: "  scheck run --host deploy@203.0.113.5 --identity ~/.ssh/deploy --sudo",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			locator, err := sshLocator(args[0], port)
			if err != nil {
				return err
			}
			ho.host = locator
			return runAlias(cmd, opts, &ho)
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (default 22); prefer user@host:port")
	cmd.Flags().StringVar(&ho.identity, "identity", "", "private key file (otherwise ssh-agent)")
	cmd.Flags().StringVar(&ho.knownHosts, "known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	return cmd
}

// sshLocator is the 0.0.1 argument as a --host locator: the user and port
// go into the locator, and --port wins over a port in the argument, as it
// did in 0.0.1.
func sshLocator(arg string, port int) (string, error) {
	user, rest := "", arg
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		user, rest = rest[:i+1], rest[i+1:]
	}
	host := rest
	if h, p, err := net.SplitHostPort(rest); err == nil {
		host = h
		if port == 0 {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		return "", usageErr("ssh: no host in %q", arg)
	}
	if host == "local" {
		// `local` is the machine running scheck as a --host locator; on
		// ssh it would silently read this machine instead of a remote one.
		return "", usageErr("ssh: %q is not a remote host; `scheck run --host local` reads this machine", arg)
	}
	if port == 0 {
		if strings.Contains(host, ":") {
			return user + "[" + host + "]", nil
		}
		return user + host, nil
	}
	return user + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// aliasRefusals are the 0.0.1 flags with no meaning on a run, each with
// where its meaning went.
var aliasRefusals = map[string]string{
	"context":        "context is assets.<name>.context in an engagement file; `scheck run --host … --write-engagement FILE` writes one to start from",
	"ignore-context": "a one-host check reads no context; an engagement's context is in its file",
	"audit-log":      "every run writes audit.jsonl in its run directory, and the JSON report carries the command trace under --no-persist",
}

// runAlias runs the one-host engagement the 0.0.1 command named, after a
// deprecation line on stderr that names where run.assessment went
// (docs/spec/report.md, "JSON consumers").
func runAlias(cmd *cobra.Command, opts *globalOpts, ho *hostOpts) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "scheck %s is deprecated and is removed in 0.0.3: this is `scheck run --host %s`; "+
		"with --format json, run.assessment is now assets[0].envelope.run.assessment\n", cmd.Name(), ho.host)
	if err := opts.rejectUnimplemented(cmd); err != nil {
		return err
	}
	for name, home := range aliasRefusals {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return usageErr("--%s is not available on scheck %s: %s", name, cmd.Name(), home)
		}
	}
	switch opts.StopAfter {
	case "", "facts":
		// facts collected and assessed the host: that is the run.
		opts.StopAfter = ""
	case "context":
		opts.StopAfter = "intake"
	case "plan":
		return usageErr("--stop-after plan is not available on scheck %s: `scheck catalog --platform linux|macos --profile baseline|hardened` lists the checks without contacting the host", cmd.Name())
	default:
		return usageErr("--stop-after on scheck %s must be context, plan or facts (as in 0.0.1); scheck run takes intake|scope|recon|plan|check|analyze|report", cmd.Name())
	}
	return executeEngagement(cmd, opts, ho, nil)
}
