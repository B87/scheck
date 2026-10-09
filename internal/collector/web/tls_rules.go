package web

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func inspection(t *gate.TLSInfo) bool {
	if t == nil {
		return false
	}
	for _, c := range t.Chain {
		for _, id := range inspectionIssuers {
			s := strings.ToLower(c.Issuer)
			at := strings.Index(s, id)
			if at >= 0 {
				left := at == 0 || !asciiLetter(s[at-1])
				end := at + len(id)
				right := end == len(s) || !asciiLetter(s[end])
				if left && right {
					return true
				}
			}
		}
	}
	return false
}
func asciiLetter(b byte) bool { return b >= 'a' && b <= 'z' }
func (j *judging) tls(s Site, ps []Page) {
	var p Page
	for _, q := range ps {
		u, _ := url.Parse(q.URL)
		if u.Scheme == "https" && (u.Port() == "" || u.Port() == "443") {
			p = q
			break
		}
	}
	name := s.Name
	if u, e := url.Parse("https://" + name); e == nil {
		name = u.Hostname()
	}
	reason := ""
	if blocked(p) != "" {
		reason = "unavailable:blocked"
	}
	t := p.TLS
	if t == nil {
		reason = "unavailable:tls_handshake"
	} else if inspection(t) {
		reason = "unavailable:tls_interception"
	}
	takeoverSubject := name
	if j.in.Wildcard != nil && j.in.Wildcard.Name == name {
		takeoverSubject = "*." + j.in.Root
	}
	for _, x := range j.out {
		if x.ID == finding.IDDNSTakeoverCandidate && x.Verdict == Fired && x.Subject.Key == takeoverSubject {
			reason = "unavailable:takeover"
		}
	}
	for _, id := range []string{finding.IDTLSCertificateInvalid, finding.IDTLSCertificateExpiring, finding.IDTLSLegacyOnly} {
		x := Judgment{ID: id, Asset: j.assetOf(name), Subject: Subject{Kind: SubjectDNSName, Key: name, Label: name}, Verdict: Abstained, Reason: reason, Reads: []string{p.RequestID}, NotChecked: []string{"One TLS connection only; other versions, ciphers and revocation were not tested"}}
		if reason != "" {
			j.add(x)
			continue
		}
		switch id {
		case finding.IDTLSLegacyOnly:
			if t.Version == "TLS 1.2" || t.Version == "TLS 1.3" {
				x.Verdict, x.Excerpt = Disproved, "One connection negotiated "+t.Version
			} else if t.Alert == "protocol_version" && len(t.Chain) == 0 {
				x.Verdict, x.Excerpt = Fired, "The TLS 1.2-or-later attempt received a protocol_version alert; no older version was tried"
			} else {
				x.Reason = "unavailable:tls_handshake"
			}
		case finding.IDTLSCertificateInvalid:
			if len(t.Chain) == 0 {
				x.Reason = "unavailable:tls_handshake"
			} else if t.Verified {
				x.Verdict, x.Excerpt = Disproved, "The gate verified the certificate chain"
			} else {
				switch t.Class {
				case gate.ClassExpired, gate.ClassHostnameMismatch, gate.ClassUntrustedIssuer, gate.ClassMissingIntermediate:
					x.Verdict = Fired
					x.Excerpt = "Certificate verification failed: " + t.Class
					if t.Class == gate.ClassMissingIntermediate {
						x.Excerpt += "; browsers may recover, but clients that do not fetch intermediates may fail"
					}
				default:
					x.Reason = "unavailable:certificate_unclassified"
				}
			}
		case finding.IDTLSCertificateExpiring:
			if !t.Verified || len(t.Chain) == 0 || t.Chain[0].NotAfter.IsZero() || j.in.Now.IsZero() {
				x.Reason = "unavailable:certificate"
			} else {
				at := p.CollectedAt
				if at.IsZero() {
					at = j.in.Now
				}
				left := t.Chain[0].NotAfter.Sub(at)
				x.Verdict = Disproved
				if left >= 0 && left <= 14*24*time.Hour {
					x.Verdict = Fired
				}
				x.Excerpt = fmt.Sprintf("Certificate expires at %s (%.1f days from collection); confirm renewal is working", t.Chain[0].NotAfter.Format(time.RFC3339), left.Hours()/24)
				x.Details = map[string]any{"days_remaining": left.Hours() / 24}
			}
		}
		j.add(x)
	}
}
