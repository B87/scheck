package web

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// dkimBits recognizes a published public key, not whether any current message
// uses it (RFC 8301, RFC 8463; docs/spec/web-collector.md, "Email").
// Zero bits is a recognized Ed25519 key. Revoked keys are handled separately.
func dkimBits(k DKIMKey) (int, bool) {
	if k.Malformed || markedTags(k.Tags) {
		return 0, false
	}
	raw := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(k.Tags["p"])
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(der) == 0 {
		return 0, false
	}
	switch k.Tags["k"] {
	case "ed25519":
		return 0, len(der) == 32
	case "", "rsa":
		if key, e := x509.ParsePKIXPublicKey(der); e == nil {
			if rsaKey, ok := key.(*rsa.PublicKey); ok && rsaKey.N.Sign() > 0 && rsaKey.E >= 3 && rsaKey.E%2 == 1 {
				return rsaKey.N.BitLen(), true
			}
		}
		if key, e := x509.ParsePKCS1PublicKey(der); e == nil && key.N.Sign() > 0 && key.E >= 3 && key.E%2 == 1 {
			return key.N.BitLen(), true
		}
	}
	return 0, false
}

func (j *judging) dkim(m MailEvidence, u mailUse, base Judgment) {
	ids := []string{finding.IDEmailDKIMMissing, finding.IDEmailDKIMKeyBreakable, finding.IDEmailDKIMKey1024}
	emit := func(id, verdict, reason string) { x := base; x.ID, x.Verdict, x.Reason = id, verdict, reason; j.add(x) }
	var expected []string
	for _, sender := range u.senders {
		expected = append(expected, sender.Selectors...)
		if len(sender.Selectors) == 0 {
			base.Subject = Subject{Kind: "dkim_selector", Key: m.Domain + "/no-selector", Label: "DKIM for " + sender.Service + " on " + m.Domain + ": no selector given; find s= in a recent message's DKIM-Signature"}
			base.Reads = []string{}
			for _, id := range ids {
				emit(id, Abstained, "unavailable:dkim_selector")
			}
		}
	}
	if len(u.senders) == 0 && len(m.DKIM) == 0 {
		base.Subject = Subject{Kind: "dkim_selector", Key: m.Domain + "/no-selector", Label: "DKIM on " + m.Domain + ": no selector given; DNS cannot list selectors"}
		base.Reads = []string{}
		for _, id := range ids {
			emit(id, Abstained, "unavailable:dkim_selector")
		}
	}
	reads := append([]SelectorRead{}, m.DKIM...)
	for _, sel := range expected {
		found := false
		for _, r := range reads {
			found = found || r.Selector == sel
		}
		if !found {
			reads = append(reads, SelectorRead{Selector: sel})
		}
	}
	for _, sel := range reads {
		name := sel.Selector + "._domainkey." + m.Domain
		var services []string
		for _, sender := range u.senders {
			if slices.Contains(sender.Selectors, sel.Selector) {
				services = append(services, sender.Service)
			}
		}
		label := "selector " + sel.Selector
		if len(services) > 0 {
			label += " (" + strings.Join(services, ", ") + ")"
		}
		base.Subject = Subject{Kind: "dkim_selector", Key: name, Label: label + " on " + m.Domain}
		base.Reads = nonEmpty(sel.Read.RequestID)
		base.Excerpt = "DKIM at " + name
		reason := ""
		switch {
		case sel.Read.Insufficient():
			reason = readReason(sel.Read)
		case sel.Marked > 0:
			reason = "unavailable:redacted"
		case len(sel.Keys) > 1:
			reason = "unavailable:dkim_multiple_keys"
		case len(sel.Keys) == 1 && markedTags(sel.Keys[0].Tags):
			reason = "unavailable:redacted"
		}
		if reason != "" {
			for _, id := range ids {
				emit(id, Abstained, reason)
			}
			continue
		}
		if len(sel.Keys) == 0 || !sel.Keys[0].Malformed && sel.Keys[0].Tags["p"] == "" {
			base.Excerpt += "; no key or revoked empty p="
			emit(finding.IDEmailDKIMMissing, Fired, "")
			emit(finding.IDEmailDKIMKeyBreakable, Abstained, "unavailable:dkim_key")
			emit(finding.IDEmailDKIMKey1024, Abstained, "unavailable:dkim_key")
			continue
		}
		bits, ok := dkimBits(sel.Keys[0])
		if !ok {
			for _, id := range ids {
				emit(id, Abstained, "unavailable:dkim_key")
			}
			continue
		}
		if bits == 0 {
			base.Excerpt += "; Ed25519 public key"
		} else {
			base.Excerpt += fmt.Sprintf("; RSA modulus %d bits", bits)
		}
		base.NotChecked = []string{"Whether this selector signs current mail and whether that mail aligns were not assessed"}
		emit(finding.IDEmailDKIMMissing, Disproved, "")
		if bits > 0 && bits < 1024 {
			emit(finding.IDEmailDKIMKeyBreakable, Fired, "")
		} else {
			emit(finding.IDEmailDKIMKeyBreakable, Disproved, "")
		}
		if bits == 1024 {
			emit(finding.IDEmailDKIMKey1024, Fired, "")
		} else {
			emit(finding.IDEmailDKIMKey1024, Disproved, "")
		}
	}
}
