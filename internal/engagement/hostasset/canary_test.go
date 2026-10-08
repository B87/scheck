package hostasset

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// A login shell that never answers the canary is a host that could not be
// read (exit 2), never a refusal (exit 3): nothing was shown to be altered
// (docs/spec/engagement.md, "Exit codes").
func TestASilentCanaryIsATransportFailure(t *testing.T) {
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := xssh.NewSignerFromKey(hostPriv)
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := xssh.MarshalPrivateKey(cliPriv, "")
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id")
	_ = os.WriteFile(idPath, pem.EncodeToMemory(blk), 0o600)

	cfg := &xssh.ServerConfig{PublicKeyCallback: func(xssh.ConnMetadata, xssh.PublicKey) (*xssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hostSigner)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := xssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go xssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							_ = r.Reply(true, nil) // accept exec, then never answer
						}
						_ = ch
					}()
				}
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	kh := filepath.Join(dir, "known_hosts")
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{knownhosts.Normalize("127.0.0.1:" + strconv.Itoa(port))}, hostSigner.PublicKey())+"\n"), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Collect(ctx, Options{Host: "127.0.0.1", Port: port, User: "u", Identity: idPath, KnownHosts: kh})
	he, ok := errors.AsType[*Error](err)
	if !ok || he.Usage || he.Kind != "" {
		t.Fatalf("a canary that never answered: %v (usage %v, kind %q), want a transport failure", err, ok && he.Usage, func() string {
			if ok {
				return he.Kind
			}
			return ""
		}())
	}
}
