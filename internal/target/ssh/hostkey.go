package ssh

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // known_hosts hashing is defined as HMAC-SHA1 by OpenSSH
	"encoding/base64"
	"os"
	"strings"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyAlgorithms lists the algorithms of the keys known_hosts already holds
// for addr, so the handshake prefers a key type we can verify. This mirrors
// OpenSSH: without it a server offering ecdsa first would be rejected with
// "key mismatch" even though its ed25519 key is on file. Returns nil when
// nothing is known (the handshake then fails with a clear "not in file").
func hostKeyAlgorithms(path, addr string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	want := knownhosts.Normalize(addr)
	var algos []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		_, hosts, key, _, _, err := xssh.ParseKnownHosts(line)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			if hostMatches(h, want) {
				if a := key.Type(); !seen[a] {
					seen[a] = true
					algos = append(algos, a)
					// RSA keys are usable under the SHA-2 signature algorithms too.
					if a == xssh.KeyAlgoRSA {
						algos = append(algos, xssh.KeyAlgoRSASHA512, xssh.KeyAlgoRSASHA256)
					}
				}
				break
			}
		}
	}
	return algos
}

// hostMatches compares one known_hosts host field (plain or |1| hashed)
// against a normalized address.
func hostMatches(field, want string) bool {
	if !strings.HasPrefix(field, "|1|") {
		return field == want
	}
	parts := strings.Split(field, "|") // "", "1", salt, hash
	if len(parts) != 4 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(want))
	return hmac.Equal(mac.Sum(nil), sum)
}
