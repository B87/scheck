package policy

import (
	"math/rand/v2"
	"testing"
)

func TestDetectCredentialByShape(t *testing.T) {
	cases := []struct{ in, detector string }{
		{"-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"},
		{"key: AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github-token"},
		{"xoxb-123456789012-abcdefghij", "slack-token"},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"},
		{"Bearer abcdefgh12345678", "bearer"},
		{"https://deploy:hunter2@git.example.com/repo", "url-credentials"},
		{"secret: Zq3xT9vB2mK8pL4nR7wY1cD6hJ5fG0sA", "high-entropy"},
		{"aws: Kf8/Zq3xT9vB2mK8pL4nR7wY1cD6hJ5fG0sA+Wd", "high-entropy"},
		{"note: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "high-entropy"},
	}
	for _, tc := range cases {
		got, ok := DetectCredential(tc.in)
		if !ok || got != tc.detector {
			t.Errorf("DetectCredential(%q) = %q, %v; want %q", tc.in, got, ok, tc.detector)
		}
	}
}

// Values an engagement file legitimately holds must not trip the detector,
// or the operator learns to ignore it.
func TestDetectCredentialLeavesDeclarationsAlone(t *testing.T) {
	for _, s := range []string{
		"example-ltd-2026-q4",
		"alice@example.com",
		"https://shop.example.com/checkout/",
		"deploy@203.0.113.5",
		"gcp:example-prod-123456",
		"google-workspace:example.com",
		"github:example-org/client-nda",
		"123e4567-e89b-12d3-a456-426614174000",
		"customer-orders-and-invoices-for-europe",
		"Annual self-assessment; contact on-call before any scan.",
		"break-glass path; MFA at the bastion",
		"~/.ssh/deploy",
		"/srv/backups/postgres/nightly",
		`project-tangerine`,
		`[A-Za-z0-9]{32}`,
		"password: not a value, a description of the password policy",
		"API uses bearer authentication only",
		"/Volumes/Backup2024/TimeMachineData",
		"/home/deploy/ExampleCorpBackups2026",
		"ProductionDatabaseBackup2026Q4",
		"https://docs.example.com/Guides/SetupWithSSO2024",
		"CustomerOrdersAndInvoicesEU2026",
		"arn:aws:iam::123456789012:role/ReadOnlySecurityAudit2026",
		"2026-10-07T09:00:00+02:00",
	} {
		if d, ok := DetectCredential(s); ok {
			t.Errorf("DetectCredential(%q) matched %s", s, d)
		}
	}
}

// Narrowing the detector for prose must not cost it random keys: generated
// tokens of key length, in the alphabets keys are written in, are caught.
func TestDetectCredentialCatchesRandomKeys(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, alpha := range []string{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		"0123456789abcdef",
	} {
		const n, tries = 32, 1000
		hit := 0
		for range tries {
			b := make([]byte, n)
			for i := range b {
				b[i] = alpha[r.IntN(len(alpha))]
			}
			if _, ok := DetectCredential(string(b)); ok {
				hit++
			}
		}
		if hit < tries*95/100 {
			t.Errorf("alphabet of %d: %d of %d random %d-character keys detected, want 95%%", len(alpha), hit, tries, n)
		}
	}
}
