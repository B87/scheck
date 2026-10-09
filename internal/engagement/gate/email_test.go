package gate_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestEmailRulesThroughRun(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	h.DNS(map[string]string{"example.com": "nodata", "news.example.com": "nodata"})
	h.TXT("example.com", "v=spf1 include:SENDGRID.NET. -all")
	h.TXT("news.example.com", "v=spf1 -all")
	seed := "EMAIL_SECRET_" + "SEEDED"
	h.TXT("sendgrid.net", "v=spf1 ip4:192.0.2.1 -all", "site-verification="+seed)
	h.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=25; rua=mailto:reports@example.com")
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	n.Add(n, big.NewInt(31))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	h.TXT("google._domainkey.example.com", "v=DKIM1; p="+base64.StdEncoding.EncodeToString(der))
	file := `schema: 1
engagement: {name: mail-review, timezone: Europe/Madrid, trigger: routine}
roots: [{domain: news.example.com}, {domain: example.com}]
people: {alice: {kind: employee}}
mail:
 senders:
  - {domain: example.com, service: Google Workspace, dkim_selectors: [Google]}
  - {domain: news.example.com, service: sendgrid}
 no_mail: [unused.example.com]
redact_extra: [EMAIL_SECRET_[A-Z]+]
intent:
 accepted_risks:
  - {id: email.dmarc_partial, asset: domain:example.com, subject: example.com, reason: rollout, accepted_by: alice}
  - {id: email.spf_undeclared_sender, asset: domain:example.com, subject: 'example.com/include:sendgrid.net', reason: verifying owner, accepted_by: alice}
`
	// YAML flow collections quote a regex containing brackets.
	file = strings.Replace(file, "[EMAIL_SECRET_[A-Z]+]", "['EMAIL_SECRET_[A-Z]+']", 1)
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false }, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir := runDir(t)
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	if out.Report.Exit.Code != 1 {
		t.Fatal(out.Report.Exit)
	}
	found := map[string]bool{}
	for _, f := range out.Report.Findings {
		if !strings.HasPrefix(f.ID, "email.") {
			continue
		}
		found[f.ID+" "+f.Subject.Key] = true
		if f.ID == finding.IDEmailDKIMKeyBreakable && (f.Subject.Key != "google._domainkey.example.com" || f.Key.Asset != "domain:example.com") {
			t.Fatal(f)
		}
		if f.ID == finding.IDEmailDMARCPartial && f.Subject.Key == "news.example.com" {
			if f.Key.Asset != "domain:news.example.com" || len(f.Rule.Reads) < 2 {
				t.Fatalf("inherited attribution: %+v", f)
			}
		}
	}
	for _, key := range []string{"email.dkim_key_breakable google._domainkey.example.com", "email.spf_undeclared_sender example.com/include:sendgrid.net", "email.dmarc_partial example.com", "email.dmarc_partial news.example.com", "email.no_mail_spoofable unused.example.com"} {
		if !found[key] {
			t.Errorf("missing %s: %+v", key, found)
		}
	}
	if len(out.Report.Acceptances) != 2 || out.Report.Acceptances[0].Outcome != "applied" || out.Report.Acceptances[1].Outcome != "applied" {
		t.Fatal(out.Report.Acceptances)
	}
	for _, q := range h.Queries() {
		if strings.Contains(q, "._domainkey.news.example.com") {
			t.Fatalf("invented selector queried: %s", q)
		}
	}
	noted := false
	for _, n := range out.Report.Notes {
		noted = noted || strings.Contains(n.Detail, "no selector given")
	}
	if !noted {
		t.Fatal("missing selector coverage note")
	}
	raw, _ := json.Marshal(out.Report)
	if strings.Contains(string(raw), seed) || strings.Contains(string(raw), "reports@example.com") {
		t.Fatal("raw mail secret or rua address leaked to report")
	}
	marked := false
	err = filepath.WalkDir(dir.Path, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), seed) {
			t.Errorf("secret leaked to %s", path)
		}
		marked = marked || strings.Contains(string(b), "[REDACTED:extra:")
		return nil
	})
	if err != nil || !marked {
		t.Fatalf("redaction marker %v err %v", marked, err)
	}
}
