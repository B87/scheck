// Package containers starts the sshd-equipped images under test/containers
// for integration tests. It needs a working `docker` (or `podman`) CLI; tests
// skip when neither is available.
package containers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// Container is a running sshd reachable on 127.0.0.1.
type Container struct {
	ID         string
	Host       string
	Port       int
	Identity   string // private key path authorised for every user in the image
	KnownHosts string // file holding the container's host key
}

// Addr is host:port.
func (c *Container) Addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

// Runtime returns the container CLI to use, or "" when none works.
func Runtime() string {
	for _, bin := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		if err := exec.Command(bin, "info").Run(); err == nil {
			return bin
		}
	}
	return ""
}

// Start builds test/containers/<name> and runs it, cleaning up when the test
// ends. It skips the test when no runtime is available.
func Start(t testing.TB, name string) *Container {
	t.Helper()
	rt := Runtime()
	if rt == "" {
		t.Skip("no container runtime available")
	}
	dir := t.TempDir()
	identity, pub := genKey(t, dir)
	image := "scheck-test-" + name
	run(t, rt, "build", "-q", "-t", image, "--build-arg", "PUBKEY="+pub, filepath.Join(root(t), "test", "containers", name))
	id := strings.TrimSpace(run(t, rt, "run", "-d", "--rm", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command(rt, "rm", "-f", id).Run() })
	port := mappedPort(t, rt, id)
	c := &Container{ID: id, Host: "127.0.0.1", Port: port, Identity: identity, KnownHosts: filepath.Join(dir, "known_hosts")}
	waitSSH(t, c)
	return c
}

// Exec runs a command inside the container (for setup, e.g. installing a
// sudoers fragment) and returns combined output.
func (c *Container) Exec(t testing.TB, args ...string) string {
	t.Helper()
	return run(t, Runtime(), append([]string{"exec", c.ID}, args...)...)
}

// ExecInput runs a command inside the container with stdin supplied.
func (c *Container) ExecInput(t testing.TB, input string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(Runtime(), append([]string{"exec", "-i", c.ID}, args...)...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Diff returns `docker diff` output: every filesystem change since start.
func (c *Container) Diff(t testing.TB) string {
	t.Helper()
	return run(t, Runtime(), "diff", c.ID)
}

func genKey(t testing.TB, dir string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := xssh.MarshalPrivateKey(priv, "scheck-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := xssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.TrimSpace(string(xssh.MarshalAuthorizedKey(sshPub)))
}

func mappedPort(t testing.TB, rt, id string) int {
	t.Helper()
	out := run(t, rt, "port", id, "22")
	// "127.0.0.1:55000" (possibly one line per address family)
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(line)); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				return n
			}
		}
	}
	t.Fatalf("cannot parse mapped port from %q", out)
	return 0
}

// waitSSH polls until sshd answers and its host key is captured.
func waitSSH(t testing.TB, c *Container) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, "ssh-keyscan", "-p", strconv.Itoa(c.Port), "-t", "ed25519", c.Host).Output()
		cancel()
		if err == nil && bytes.Contains(out, []byte("ssh-ed25519")) {
			if err := os.WriteFile(c.KnownHosts, out, 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sshd in %s did not come up", c.ID)
}

func run(t testing.TB, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}

func root(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}

// BuildScheck compiles the CLI into a temp dir and returns its path.
func BuildScheck(t testing.TB) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "scheck")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/scheck")
	cmd.Dir = root(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// Run executes scheck with args and returns stdout, stderr and the exit code.
func Run(t testing.TB, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errorsAs(err, &ee) {
			t.Fatalf("run %s: %v", strings.Join(args, " "), err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// Sprintf is fmt.Sprintf re-exported so test files need one import fewer.
func Sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }
