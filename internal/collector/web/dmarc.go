package web

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

type dmarcPolicy struct {
	tags                   map[string]string
	reads                  []string
	reason, detail, policy string
	pct                    int
	testing, usable, rua   bool
}

// dmarcPolicy uses only collected records. An absent subdomain record cannot
// establish missing DMARC without its organizational policy; no extra reads
// are sent (docs/spec/web-collector.md, "Email").
func (in Input) dmarcPolicy(m MailEvidence) dmarcPolicy {
	d := parseDMARC(m)
	if d.reason != "" || len(m.DMARCRecords) > 0 {
		return d
	}
	org := organizationalDomain(m.Domain)
	if org == m.Domain {
		return d
	}
	d.reason = "unavailable:dmarc_parent"
	d.detail = "The organizational-domain policy was not read; inherited DMARC is unknown"
	if org == "" {
		return d
	}
	for _, parent := range slices.Concat(in.Evidence.Mail, in.MailPolicies) {
		if parent.Domain != org {
			continue
		}
		p := parseDMARC(parent)
		p.reads = append(d.reads, p.reads...)
		p.detail = "Inherited from " + org + ": " + p.detail
		if p.usable {
			inherited := p.policy
			if sp, ok := p.tags["sp"]; ok {
				inherited = strings.ToLower(sp)
				if !policyValue(sp) {
					p.reason = "unavailable:dmarc_policy"
					p.usable = false
				}
			}
			if np, ok := p.tags["np"]; ok {
				p.reads = append(p.reads, nonEmpty(m.TXT.RequestID)...)
				p.reads = append(p.reads, nonEmpty(m.MX.RequestID)...)
				if !policyValue(np) {
					p.reason = "unavailable:dmarc_policy"
					p.usable = false
				} else {
					exists := !m.TXT.Insufficient() && (m.TXT.Outcome == "records" || m.TXT.Outcome == "nodata") || !m.MX.Insufficient() && (m.MX.Outcome == "records" || m.MX.Outcome == "nodata")
					absent := !m.TXT.Insufficient() && m.TXT.Outcome == "nxdomain" && !m.MX.Insufficient() && m.MX.Outcome == "nxdomain"
					switch {
					case absent:
						inherited = strings.ToLower(np)
					case !exists && !strings.EqualFold(np, inherited):
						p.reason = "unavailable:dmarc_existence"
						p.usable = false
					}
				}
			}
			p.policy = inherited
			p.detail += "; effective inherited policy=" + inherited
		}
		return p
	}
	return d
}

func markedTags(tags map[string]string) bool {
	for _, v := range tags {
		if marked(v) {
			return true
		}
	}
	return false
}

func marked(v string) bool {
	return strings.Contains(v, "[REDACTED:") || strings.Contains(v, "[TRUNCATED:")
}

func parseDMARC(m MailEvidence) dmarcPolicy {
	d := dmarcPolicy{reads: nonEmpty(m.DMARC.RequestID), pct: 100}
	switch {
	case m.DMARC.Insufficient():
		d.reason = readReason(m.DMARC)
	case m.DMARCMarked > 0:
		d.reason = "unavailable:redacted"
	case len(m.DMARCRecords) == 0:
		d.detail = "No DMARC record"
	case len(m.DMARCRecords) > 1:
		d.detail = "Multiple DMARC records"
	default:
		r := m.DMARCRecords[0]
		d.tags, d.rua = r.Tags, r.RUA
		if markedTags(r.Tags) {
			d.reason = "unavailable:redacted"
			break
		}
		if r.Malformed {
			d.detail = "Malformed DMARC record"
			break
		}
		d.policy = strings.ToLower(r.Tags["p"])
		if !policyValue(d.policy) {
			d.detail = "DMARC p is missing or invalid"
			break
		}
		d.usable = true
		if pct, ok := r.Tags["pct"]; ok {
			n, err := strconv.Atoi(pct)
			if err != nil || n < 0 || n > 100 || len(pct) > 3 || !decimal(pct) {
				d.reason = "unavailable:dmarc_policy"
				break
			}
			d.pct = n
		}
		if t, ok := r.Tags["t"]; ok {
			switch strings.ToLower(t) {
			case "y":
				d.testing = true
			case "n":
			default:
				d.reason = "unavailable:dmarc_policy"
			}
		}
		d.detail = fmt.Sprintf("DMARC p=%s; legacy pct=%d; test mode=%t", d.policy, d.pct, d.testing)
		if d.policy == "reject" && (d.testing || d.pct == 0) {
			d.detail += "; reduced enforcement can still request quarantine"
		}
	}
	return d
}

func decimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func policyValue(p string) bool {
	switch strings.ToLower(p) {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}
func (d dmarcPolicy) enforces() bool {
	return d.usable && d.policy != "none" && d.pct > 0 && !d.testing
}

func (j *judging) dmarc(m MailEvidence, u mailUse, base Judgment) {
	d := j.in.dmarcPolicy(m)
	base.Reads = append(d.reads, u.reads...)
	base.Excerpt = d.detail
	base.NotChecked = []string{"Actual receiver enforcement, current DMARC DNS tree walking and message alignment were not assessed"}
	emit := func(id, verdict, reason string) { x := base; x.ID, x.Verdict, x.Reason = id, verdict, reason; j.add(x) }
	if u.mode == "none" {
		sp := inspectSPF(m)
		base.Reads = append(base.Reads, nonEmpty(m.TXT.RequestID)...)
		base.Excerpt += "; SPF: " + strings.Join(m.TXT.TXT, " | ")
		badSPF := sp.known && !sp.denyAll
		badDMARC := d.reason == "" && (!d.enforces() || d.policy != "reject" || d.pct != 100)
		switch {
		case badSPF || badDMARC:
			reason := d.reason
			if !sp.known && reason == "" {
				reason = sp.reason
			}
			emit(finding.IDEmailNoMailSpoofable, Fired, reason)
		case sp.known && d.reason == "":
			emit(finding.IDEmailNoMailSpoofable, Disproved, "")
		default:
			reason := d.reason
			if reason == "" {
				reason = sp.reason
			}
			if reason == "" {
				reason = "unavailable:spf_incomplete"
			}
			emit(finding.IDEmailNoMailSpoofable, Abstained, reason)
		}
		return
	}
	if u.mode == "" {
		for _, id := range []string{finding.IDEmailDMARCNotEnforced, finding.IDEmailDMARCPartial, finding.IDEmailDMARCSubdomainsOpen, finding.IDEmailNoMailSpoofable} {
			emit(id, Abstained, "unavailable:mail_use")
		}
		return
	}
	if d.reason != "" {
		for _, id := range []string{finding.IDEmailDMARCNotEnforced, finding.IDEmailDMARCPartial, finding.IDEmailDMARCSubdomainsOpen} {
			emit(id, Abstained, d.reason)
		}
		return
	}
	if !d.enforces() {
		emit(finding.IDEmailDMARCNotEnforced, Fired, "")
		return
	}
	emit(finding.IDEmailDMARCNotEnforced, Disproved, "")
	if d.pct < 100 {
		emit(finding.IDEmailDMARCPartial, Fired, "")
	} else {
		emit(finding.IDEmailDMARCPartial, Disproved, "")
	}
	if organizationalDomain(m.Domain) != m.Domain {
		emit(finding.IDEmailDMARCSubdomainsOpen, Abstained, "unavailable:dmarc_descendants")
		return
	}
	open := false
	for _, tag := range []string{"sp", "np"} {
		if v, ok := d.tags[tag]; ok {
			base.Excerpt += "; " + tag + "=" + v
			if !policyValue(v) {
				emit(finding.IDEmailDMARCSubdomainsOpen, Abstained, "unavailable:dmarc_policy")
				return
			}
			open = open || strings.EqualFold(v, "none")
		}
	}
	if open {
		emit(finding.IDEmailDMARCSubdomainsOpen, Fired, "")
	} else {
		emit(finding.IDEmailDMARCSubdomainsOpen, Disproved, "")
	}
}
