package workspace

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/policy"
)

func TestFoundationSurface(t *testing.T) {
	if _, err := gate.NewRegistry(Ops...); err != nil {
		t.Fatal(err)
	}
	if len(Ops) != 4 {
		t.Fatal("unexpected step 1 read surface")
	}
	for _, op := range Ops {
		if op.Method != gate.GET || op.Auth != gate.WorkspaceADC {
			t.Fatal("collector holds non-read operation")
		}
	}
}

type bindingScope struct{}

func (bindingScope) Subject(asset, id string) gate.Standing {
	admitted := asset == "saas:google-workspace:example.com" && id == asset
	if !admitted {
		return gate.Standing{}
	}
	return gate.Standing{UnderAsset: true, Root: asset}
}
func (bindingScope) Name(string) string                                 { return "" }
func (bindingScope) Address(netip.Addr) (string, bool)                  { return "", false }
func (bindingScope) Admits(string, string, *gate.Lookup) gate.Admission { return gate.Admission{} }
func (bindingScope) Throttle(string) (float64, int)                     { return 0, 0 }
func (bindingScope) OrgUnits(string) []gate.OrgUnit                     { return nil }

func TestBindUsesGateSelectedCustomerAndExposesOnlyBinding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"admin.googleapis.com", "oauth2.googleapis.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var paths []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Host == "oauth2.googleapis.com" {
			if r.Method != "POST" || r.URL.Path != "/token" {
				t.Error("unexpected exchange")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if len(r.Form) != 4 || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "test-refresh" || r.Form.Get("client_secret") != "test-secret" || r.Form.Get("client_id") != "test-client" {
				t.Error("refresh form changed")
			}
			_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("unexpected target request")
		}
		switch r.URL.Path {
		case "/admin/directory/v1/customers/my_customer":
			_, _ = w.Write([]byte(`{"id":"C123","postalAddress":"PRIVATE_CONTACT"}`))
		case "/admin/directory/v1/customer/C123/domains":
			_, _ = w.Write([]byte(`{"domains":[{"domainName":"example.com","verified":true},{"domainName":"private.invalid","verified":true}]}`))
		case "/admin/directory/v1/customer/C123/domainaliases":
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("unexpected bootstrap path")
			w.WriteHeader(404)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	path := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(path, []byte(`{"type":"authorized_user","client_id":"test-client","client_secret":"test-secret","refresh_token":"test-refresh"}`), 0600); err != nil {
		t.Fatal(err)
	}
	reg, err := gate.NewRegistry(Ops...)
	if err != nil {
		t.Fatal(err)
	}
	var audit strings.Builder
	g, err := gate.New(gate.Config{Registry: reg, Scope: bindingScope{}, Audit: policy.NewAudit(&audit), Version: "test",
		Getenv: func(k string) string {
			if k == "GOOGLE_APPLICATION_CREDENTIALS" {
				return path
			}
			return ""
		},
		Net: &gate.Net{RootCAs: roots, Nameserver: netip.MustParseAddr("192.0.2.53"), Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server.Listener.Addr().String())
		}, Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }, Exchange: func(_ context.Context, _ string, q []byte, _ bool) ([]byte, error) {
			out := append([]byte(nil), q...)
			binary.BigEndian.PutUint16(out[2:4], 0x8180)
			if binary.BigEndian.Uint16(q[len(q)-4:len(q)-2]) == 1 {
				binary.BigEndian.PutUint16(out[6:8], 1)
				out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 12)
			}
			return out, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := Bind(context.Background(), g, "saas:google-workspace:example.com")
	if result.CustomerID != "C123" || result.Domain != "example.com" || result.Profile != "directory" || result.ScopesKnown || len(result.Reads) != 3 || len(paths) != 4 {
		t.Fatalf("binding failed: %+v paths=%v", result, paths)
	}
	encoded, _ := json.Marshal(result)
	for _, s := range []string{"test-token", "test-refresh", "test-secret", "PRIVATE_CONTACT", "private.invalid"} {
		if strings.Contains(string(encoded)+audit.String(), s) {
			t.Fatal("binding leaked private material")
		}
	}
}
