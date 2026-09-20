package policy

import (
	"strings"
	"testing"
)

const seededKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBSEEDEDSEEDED\n-----END OPENSSH PRIVATE KEY-----"

func TestRedactSeededSecrets(t *testing.T) {
	r, err := NewRedactor([]string{`internal\.example\.com`})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		input  string
		secret string // must not survive
		rule   string
	}{
		{"private key", "key:\n" + seededKey + "\nend", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "private-key"},
		{"truncated private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAseededseeded", "MIIEowIBAAKCAQEAseededseeded", "private-key"},
		{"aws access key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
		{"aws secret via kv", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "kv-secret"},
		{"bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.SEEDEDPAYLOAD.SEEDEDSIG", "SEEDEDPAYLOAD", "bearer"},
		{"password=", "DB_PASSWORD=hunter2seeded\nother=1", "hunter2seeded", "kv-secret"},
		{"password: quoted", `password: "s3cr3t seeded"`, "s3cr3t", "kv-secret"},
		{"token=", "token=abcdef123456seeded", "abcdef123456seeded", "kv-secret"},
		{"github token", "url = https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github-token"},
		{"extra rule", "host = db.internal.example.com", "internal.example.com", "extra:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits := r.RedactString(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:"+tc.rule+":") {
				t.Fatalf("no marker for %s in %q (hits %v)", tc.rule, out, hits)
			}
			if len(hits) == 0 || out == "" {
				t.Fatalf("redaction must leave a marker, got %q", out)
			}
		})
	}
}

func TestRedactLeavesLegitimateContentAlone(t *testing.T) {
	r, _ := NewRedactor(nil)
	keep := []string{
		// Certificates and plist payloads are needed by the model; the v0.1
		// "long base64" rule was dropped for exactly this reason.
		"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEbGludXgwDQYJKoZIhvcNAQELBQAw\n-----END CERTIFICATE-----",
		"<data>\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n</data>",
		// sshd -T output: settings, not secrets.
		"passwordauthentication yes\npermitrootlogin no\nkbdinteractiveauthentication no",
		"PasswordAuthentication=no",
		"token_required: false",
		"# password: none",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxpbnV4bGludXhsaW51eGxpbnV4bGludXhsaW4 ops@bastion",
	}
	for _, in := range keep {
		out, hits := r.RedactString(in)
		if out != in {
			t.Errorf("legitimate content altered:\n in: %q\nout: %q\nhits: %v", in, out, hits)
		}
	}
}

func TestRedactMarkerCountsBytes(t *testing.T) {
	r, _ := NewRedactor(nil)
	out, hits := r.RedactString("x=AKIAIOSFODNN7EXAMPLE")
	if out != "x="+Marker("aws-access-key", 20) || hits[0].Bytes != 20 {
		t.Errorf("out=%q hits=%v", out, hits)
	}
}

func TestRedactBadExtraPattern(t *testing.T) {
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Fatal("want compile error")
	}
}
