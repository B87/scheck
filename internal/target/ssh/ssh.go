// Package ssh runs catalog argv on a remote host over SSH.
//
// SSH hands a string to the remote login shell, so the argv contract is
// honoured by Quote plus a runtime canary (docs/spec/host-collector.md §4.3): the first command
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
	"strings"
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
	// Jump, when set, is a ProxyJump hop: the connection to the target is
	// opened through it, its host key verified against the same known_hosts
	// and the same credentials offered. Nothing runs on the hop; it only
	// forwards one TCP connection (docs/ROADMAP.md, E1c).
	Jump *Hop
}

// Hop is a jump host.
type Hop struct {
	Host string
	Port int
	User string
}

// Target is one authenticated SSH connection. Exec refuses to run anything
// until Verify has passed the canary.
type Target struct {
	client   *xssh.Client
	hop      *xssh.Client // the jump host's connection, closed with the target's
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
		return nil, fmt.Errorf("ssh: known_hosts %s: %w (%w)", opts.KnownHosts, err, target.ErrAccess)
	}
	auth, err := authMethods(opts.Identity)
	if err != nil {
		return nil, fmt.Errorf("%w (%w)", err, target.ErrAccess)
	}
	config := func(user, addr string) *xssh.ClientConfig {
		return &xssh.ClientConfig{
			User:              user,
			Auth:              auth,
			HostKeyCallback:   hostKey,
			HostKeyAlgorithms: hostKeyAlgorithms(opts.KnownHosts, addr),
			Timeout:           opts.Timeout,
		}
	}
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	var hop *xssh.Client
	var conn net.Conn
	if j := opts.Jump; j != nil {
		port := j.Port
		if port == 0 {
			port = 22
		}
		hopAddr := net.JoinHostPort(j.Host, strconv.Itoa(port))
		hc, err := dialTCP(ctx, hopAddr, opts.Timeout, "jump host ")
		if err != nil {
			return nil, fmt.Errorf("%w (%w)", err, target.ErrJumpHost)
		}
		if hop, err = handshake(ctx, hc, hopAddr, config(j.User, hopAddr), opts, Options{Host: j.Host, KnownHosts: opts.KnownHosts}, "jump host "); err != nil {
			return nil, fmt.Errorf("%w (%w)", err, target.ErrJumpHost)
		}
		// The hop forwards one TCP connection to the target (direct-tcpip,
		// as ssh -J); no session or command is opened on it.
		// The hop answers the channel open, or not, within the same
		// timeout as a handshake.
		openCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		conn, err = hop.DialContext(openCtx, "tcp", addr)
		cancel()
		if err != nil {
			_ = hop.Close()
			return nil, fmt.Errorf("ssh: jump host %s could not reach %s: %w (%w)", hopAddr, addr, err, target.ErrUnreachable)
		}
	} else {
		var err error
		if conn, err = dialTCP(ctx, addr, opts.Timeout, ""); err != nil {
			return nil, err
		}
	}
	client, err := handshake(ctx, conn, addr, config(opts.User, addr), opts, opts, "")
	if err != nil {
		if hop != nil {
			_ = hop.Close()
		}
		return nil, err
	}
	return &Target{client: client, hop: hop, opts: opts, platform: target.Unknown}, nil
}

func dialTCP(ctx context.Context, addr string, timeout time.Duration, role string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s%s: %w (%w)", role, addr, err, target.ErrUnreachable)
	}
	return conn, nil
}

// handshake runs the SSH handshake on conn under a deadline: the earlier of
// the timeout and ctx's. ClientConfig.Timeout bounds only xssh.Dial, so a
// peer that accepts TCP and never speaks SSH would otherwise hold the
// handshake forever; a forwarded channel has no deadline of its own, so the
// connection is closed when the deadline passes.
func handshake(ctx context.Context, conn net.Conn, addr string, cfg *xssh.ClientConfig, opts, who Options, role string) (*xssh.Client, error) {
	wait := opts.Timeout
	if d, ok := ctx.Deadline(); ok && time.Until(d) < wait {
		wait = time.Until(d)
	}
	timer := time.AfterFunc(wait, func() { _ = conn.Close() })
	c, chans, reqs, err := xssh.NewClientConn(conn, addr, cfg)
	timer.Stop()
	if err != nil {
		_ = conn.Close()
		return nil, handshakeErr(err, addr, who, role)
	}
	return xssh.NewClient(c, chans, reqs), nil
}

// handshakeErr names why the handshake failed. A host key scheck cannot
// verify and failed authentication are ErrAccess, on the jump host as on
// the target; anything else (a reset, an EOF, the deadline) is
// ErrUnreachable. role names the jump host in the message.
func handshakeErr(err error, addr string, opts Options, role string) error {
	var keyErr *knownhosts.KeyError
	switch {
	case errors.As(err, &keyErr) && len(keyErr.Want) == 0:
		return fmt.Errorf("ssh: %s%s is not in %s; verify its key out of band, then: ssh-keyscan -H %s >> %s (%w, %w)", role, opts.Host, opts.KnownHosts, opts.Host, opts.KnownHosts, target.ErrAccess, target.ErrHostKeyUnknown)
	case errors.As(err, &keyErr):
		return fmt.Errorf("ssh: %s%s: the host key does not match %s: %w (%w, %w)", role, addr, opts.KnownHosts, err, target.ErrAccess, target.ErrHostKeyChanged)
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("ssh: %s%s: %w (%w)", role, addr, err, target.ErrAccess)
	}
	return fmt.Errorf("ssh: %s%s: %w (%w)", role, addr, err, target.ErrUnreachable)
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
			if _, ok := errors.AsType[*xssh.PassphraseMissingError](err); ok {
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
		// A session lost while the canary ran is a transport failure, not
		// a shell that altered output: both stay matchable.
		return fmt.Errorf("%w: %w", target.ErrCanary, err)
	}
	// The echo is target output that no redactor has seen, so it is kept
	// on the target for the caller to redact and is never in the error.
	return fmt.Errorf("%w: the remote shell returned %d bytes, not the canary (exit %d); login shell is not POSIX sh compatible", target.ErrCanary, len(res.Stdout), res.Code)
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
	if t.hop != nil {
		_ = t.hop.Close()
		t.hop = nil
	}
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
		return target.Result{}, fmt.Errorf("ssh: session: %w (%w)", err, target.ErrTransport)
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
		// No exit status came back: the session, not the command, failed.
		res.Code = -1
		return res, fmt.Errorf("ssh: %s: %w (%w)", argv[0], runErr, target.ErrTransport)
	}
	return res, nil
}
