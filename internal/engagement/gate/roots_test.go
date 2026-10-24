package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Verification never fetches a missing intermediate from the URL a
// certificate names, on any platform: the roots the gate builds are read by
// Go's own verifier, never handed to the operating system's, which on macOS
// would send that request outside the gate (docs/spec/scope.md,
// "Connections").
func TestRootsNeverFetchTheIssuerURL(t *testing.T) {
	var hits atomic.Int32
	aia := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer aia.Close()
	w := newWorld(t)
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	itmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Unpublished Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ider, _ := x509.CreateCertificate(rand.Reader, itmpl, w.ca, &ikey.PublicKey, w.caKey)
	inter, _ := x509.ParseCertificate(ider)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{aia.URL + "/int.cer"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, inter, &key.PublicKey, ikey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.ca.Raw})
	machine, note := systemRoots()
	if note != "" {
		t.Fatal(note)
	}
	bundle, _ := bundleRoots(caPEM, nil)
	// A gate built without the test seam verifies with these roots.
	plain := newWorld(t)
	plain.systemRoots = true
	g := plain.gate()
	if g.roots == nil || g.noRoots {
		t.Fatalf("New left the roots to the platform: %v", g.roots)
	}
	for name, pool := range map[string]*x509.CertPool{"this machine's roots": machine, "a bundle read as macOS's": bundle, "the gate's": g.roots} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.example.com"}); err == nil {
			t.Errorf("%s: a chain missing its intermediate verified", name)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the issuer's URL was fetched %d times", n)
	}
	if _, note := bundleRoots(nil, errors.New("absent")); note != rootsNote {
		t.Errorf("no bundle: %q", note)
	}
}

// With no root to verify against, every chain fails alike, so none is
// classed: the certificate rules abstain rather than call every site's
// issuer untrusted.
func TestNoRootsClassesNothing(t *testing.T) {
	w := newWorld(t)
	c := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.53", 443, &c, ok200("hi"))
	g := w.gate()
	g.roots, g.noRoots = x509.NewCertPool(), true
	res := g.Send(t.Context(), web("https", "www.example.com", "/"))
	if res.Decision != "unavailable:tls_invalid" || res.Response.TLS.Class != ClassUnclassified {
		t.Fatalf("%+v %+v", res, res.Response.TLS)
	}
}
