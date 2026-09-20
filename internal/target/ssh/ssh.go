// Package ssh runs catalog argv on a remote host over SSH.
//
// SSH hands a string to the remote login shell, so the argv contract is
// honoured by Quote plus a runtime canary (SPEC.md §4.3): the first command
// on any session must round-trip a string full of metacharacters byte for
// byte, or the session aborts before anything else is sent.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/b87/scheck/internal/target"
)

// Options configures a connection.
type Options struct {
	Host       string
	Port       int
	User       string
	Identity   string // private key file; empty means agent only
	KnownHosts string // defaults to ~/.ssh/known_hosts
	MaxOutput  int    // per-stream capture cap, required
	Timeout    time.Duration
}

// Target is one authenticated SSH connection. Exec refuses to run anything
// until Verify has passed the canary.
type Target struct {
	client   *xssh.Client
	opts     Options
	mu       sync.Mutex
	verified bool
	platform target.Platform
	// CanaryOutput is what the remote shell echoed, kept for the report.
	CanaryOutput string
}

// Dial connects and authenticates. The host key must already be in
// known_hosts; scheck never trusts a key on first use.
func Dial(ctx context.Context, opts Options) (*Target, error) {
	if opts.MaxOutput <= 0 {
		return nil, errors.New("ssh: MaxOutput must be > 0")
	}
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.KnownHosts == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		opts.KnownHosts = home + "/.ssh/known_hosts"
	}
	hostKey, err := knownhosts.New(opts.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("ssh: known_hosts %s: %w", opts.KnownHosts, err)
	}
	auth, err := authMethods(opts.Identity)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	cfg := &xssh.ClientConfig{
		User:              opts.User,
		Auth:              auth,
		HostKeyCallback:   hostKey,
		HostKeyAlgorithms: hostKeyAlgorithms(opts.KnownHosts, addr),
		Timeout:           opts.Timeout,
	}
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	c, chans, reqs, err := xssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			return nil, fmt.Errorf("ssh: %s is not in %s; verify its key out of band, then: ssh-keyscan -H %s >> %s", opts.Host, opts.KnownHosts, opts.Host, opts.KnownHosts)
		}
		return nil, fmt.Errorf("ssh: %s: %w", addr, err)
	}
	return &Target{client: xssh.NewClient(c, chans, reqs), opts: opts, platform: target.Unknown}, nil
}

func authMethods(identity string) ([]xssh.AuthMethod, error) {
	var methods []xssh.AuthMethod
	if identity != "" {
		raw, err := os.ReadFile(identity)
		if err != nil {
			return nil, fmt.Errorf("ssh: identity: %w", err)
		}
		signer, err := xssh.ParsePrivateKey(raw)
		if err != nil {
			var pass *xssh.PassphraseMissingError
			if errors.As(err, &pass) {
				return nil, fmt.Errorf("ssh: identity %s is passphrase-protected; load it into ssh-agent instead", identity)
			}
			return nil, fmt.Errorf("ssh: identity %s: %w", identity, err)
		}
		methods = append(methods, xssh.PublicKeys(signer))
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			methods = append(methods, xssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if len(methods) == 0 {
		return nil, errors.New("ssh: no authentication available: pass --identity or run an ssh-agent (password auth is never used)")
	}
	return methods, nil
}

// Verify runs the canary argv as the first command and compares the echo to
// want. On mismatch the connection is closed and target.ErrCanary returned;
// nothing else can be executed on this Target afterwards.
func (t *Target) Verify(ctx context.Context, argv []string, want string) error {
	t.mu.Lock()
	t.verified = true // allow exactly this call
	t.mu.Unlock()
	res, err := t.Exec(ctx, argv)
	t.CanaryOutput = string(res.Stdout)
	if err == nil && res.Code == 0 && bytes.Equal(res.Stdout, []byte(want)) {
		return nil
	}
	t.mu.Lock()
	t.verified = false
	t.mu.Unlock()
	_ = t.Close()
	if err != nil {
		return fmt.Errorf("%w: %v", target.ErrCanary, err)
	}
	return fmt.Errorf("%w: remote shell returned %q (exit %d); login shell is not POSIX sh compatible", target.ErrCanary, res.Stdout, res.Code)
}

// SetPlatform records the platform once `uname -s` has been observed.
func (t *Target) SetPlatform(p target.Platform) { t.platform = p }

// Platform implements target.Target.
func (t *Target) Platform() target.Platform { return t.platform }

// Transport implements target.Target.
func (t *Target) Transport() target.Transport { return target.TransportSSH }

// Close ends the connection.
func (t *Target) Close() error {
	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	return err
}

// Exec implements target.Target: one session per call, Quote(argv) as the
// command line, both streams capped.
func (t *Target) Exec(ctx context.Context, argv []string) (target.Result, error) {
	t.mu.Lock()
	ok := t.verified && t.client != nil
	t.mu.Unlock()
	if !ok {
		return target.Result{}, fmt.Errorf("%w: session not verified", target.ErrCanary)
	}
	if len(argv) == 0 {
		return target.Result{}, errors.New("empty argv")
	}
	start := time.Now()
	sess, err := t.client.NewSession()
	if err != nil {
		return target.Result{}, fmt.Errorf("ssh: session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	stdout := &target.CapWriter{Max: t.opts.MaxOutput}
	stderr := &target.CapWriter{Max: t.opts.MaxOutput}
	sess.Stdout, sess.Stderr = stdout, stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(Quote(argv)) }()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		_ = sess.Close()
		<-done
		return target.Result{Code: -1, Stdout: stdout.Buf, Stderr: stderr.Buf, Duration: time.Since(start)},
			fmt.Errorf("%w after %s", target.ErrTimeout, time.Since(start).Round(time.Millisecond))
	}
	res := target.Result{Stdout: stdout.Buf, Stderr: stderr.Buf, StdoutTruncated: stdout.Truncated,
		StderrTruncated: stderr.Truncated, Duration: time.Since(start)}
	var exitErr *xssh.ExitError
	switch {
	case runErr == nil:
		res.Code = 0
	case errors.As(runErr, &exitErr):
		res.Code = exitErr.ExitStatus()
		if res.Code == target.CodeNotFound {
			return res, fmt.Errorf("%w: %s", target.ErrNotFound, argv[0])
		}
	default:
		res.Code = -1
		return res, fmt.Errorf("ssh: %s: %w", argv[0], runErr)
	}
	return res, nil
}
