package gate

import (
	"crypto/x509"
	"os"
	"runtime"
)

// darwinRoots is the root bundle macOS ships for the TLS libraries outside
// its own frameworks.
const darwinRoots = "/etc/ssl/cert.pem"

// rootsNote is printed when no root could be read: every certificate then
// fails to verify, which is reported, never bypassed.
const rootsNote = "scheck could not read the system's root certificates, so no certificate verified and none was judged"

// systemRoots is the pool TLS verifies against (docs/spec/scope.md,
// "Connections"), always one Go's own verifier reads. On macOS, a nil or
// system pool hands verification to the operating system, which fetches a
// missing intermediate from the URL the certificate names: a request no
// admission, exclude or audit line would see. There the bundled roots are
// read from their file instead. Elsewhere the system pool is read from
// files and verified by Go. With none, the pool is empty and the note says
// so.
func systemRoots() (*x509.CertPool, string) {
	if runtime.GOOS == "darwin" {
		return bundleRoots(os.ReadFile(darwinRoots))
	}
	// Go returns an empty pool, and no error, when no bundle exists.
	if p, err := x509.SystemCertPool(); err == nil && !p.Equal(x509.NewCertPool()) {
		return p, ""
	}
	return x509.NewCertPool(), rootsNote
}

// bundleRoots is a pool of the certificates in a PEM bundle.
func bundleRoots(pem []byte, err error) (*x509.CertPool, string) {
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		return x509.NewCertPool(), rootsNote
	}
	return pool, ""
}
