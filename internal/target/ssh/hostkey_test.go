package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestHostKeyAlgorithms(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edKey, _ := xssh.NewPublicKey(edPub)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey, _ := xssh.NewPublicKey(&rsaPriv.PublicKey)

	// A hashed entry for 127.0.0.1:2222 and a plain one for example.com.
	plain := "[127.0.0.1]:2222"
	body := "# comment\n" +
		knownhosts.HashHostname(plain) + " " + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(edKey))) + "\n" +
		"example.com " + strings.TrimSpace(string(xssh.MarshalAuthorizedKey(rsaKey))) + "\n"
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hostKeyAlgorithms(p, plain); len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Errorf("hashed lookup: %v", got)
	}
	if got := hostKeyAlgorithms(p, "example.com:22"); len(got) != 3 || got[0] != "ssh-rsa" {
		t.Errorf("plain lookup: %v", got)
	}
	if got := hostKeyAlgorithms(p, "nowhere:22"); got != nil {
		t.Errorf("unknown host: %v", got)
	}
}
