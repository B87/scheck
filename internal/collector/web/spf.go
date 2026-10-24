package web

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// SenderTableVersion pins exact provider includes and explicit service aliases.
// Sources, reviewed 2026-10-09:
// https://support.google.com/a/answer/33786
// https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure
// https://www.twilio.com/docs/sendgrid/ui/sending-email/verify-sender-with-spf
// https://docs.aws.amazon.com/ses/latest/dg/mail-from.html
const SenderTableVersion = "2026-10-09.1"

var senderIncludes = map[string]string{
	"_spf.google.com":                   "google-workspace",
	"spf.protection.outlook.com":        "microsoft-365",
	"spf.protection.office365.us":       "microsoft-365",
	"spf.protection.partner.outlook.cn": "microsoft-365",
	"sendgrid.net":                      "sendgrid",
	"amazonses.com":                     "amazon-ses",
}

func senderService(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "google workspace", "g suite", "gsuite", "google-workspace":
		return "google-workspace"
	case "microsoft 365", "office 365", "office365", "microsoft-365":
		return "microsoft-365"
	case "twilio sendgrid", "sendgrid":
		return "sendgrid"
	case "amazon ses", "aws ses", "amazon-ses":
		return "amazon-ses"
	}
	return s
}

type spfTerm struct {
	name, arg, raw  string
	positive, broad bool
}
type spfRecord struct {
	terms            []spfTerm
	invalid, unknown bool
	denyAll          bool
}

var modifierName = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
var spfDomain = regexp.MustCompile(`^([a-z0-9_][a-z0-9_-]*\.)+[a-z0-9_-]+\.?$`)

// parseSPF retains order and qualifiers, stops mechanisms at all, and ignores
// redirect when all exists (RFC 7208 §§4–6; docs/spec/web-collector.md, "Email").
// Macros remain unknown: this DNS-only review has no sender to expand them.
func parseSPF(record string) spfRecord {
	p := spfRecord{}
	if marked(record) {
		p.unknown = true
		return p
	}
	for _, c := range record {
		if c < 32 || c > 126 {
			p.invalid = true
		}
	}
	fields := strings.Fields(record)
	if !isSPF(record) {
		p.invalid = true
		return p
	}
	var redirect *spfTerm
	modifiers := map[string]bool{}
	all := false
	for _, raw := range fields[1:] {
		s := strings.ToLower(raw)
		if k, v, ok := strings.Cut(s, "="); ok && !strings.Contains(k, ":") && !strings.Contains(k, "%") {
			if !modifierName.MatchString(k) {
				p.invalid = true
				continue
			}
			if k == "redirect" || k == "exp" {
				if modifiers[k] {
					p.invalid = true
				}
				modifiers[k] = true
				if !validSPFDomain(v) {
					p.invalid = true
				}
				if k == "redirect" {
					t := spfTerm{name: k, arg: v, raw: raw, positive: true}
					redirect = &t
				}
			}
			continue
		}
		reachable := !all
		t := spfTerm{raw: raw, positive: true}
		if strings.ContainsAny(s[:1], "+-~?") {
			t.positive = s[0] == '+'
			s = s[1:]
		}
		if s == "" {
			p.invalid = true
			continue
		}
		var explicitArg bool
		t.name, t.arg, explicitArg = strings.Cut(s, ":")
		if explicitArg && t.arg == "" {
			p.invalid = true
		}
		if i := strings.Index(t.name, "/"); i >= 0 {
			t.arg = t.name[i:]
			t.name = t.name[:i]
		}
		switch t.name {
		case "all":
			if t.arg != "" {
				p.invalid = true
			}
			all = true
		case "include", "exists":
			if !validSPFDomain(t.arg) {
				p.invalid = true
			}
			p.unknown = p.unknown || strings.Contains(t.arg, "%")
		case "a", "mx":
			domain, cidr, _ := strings.Cut(t.arg, "/")
			if domain != "" && !validSPFDomain(domain) {
				p.invalid = true
			}
			if strings.Contains(t.arg, "/") && !dualCIDR(cidr) {
				p.invalid = true
			}
			p.unknown = p.unknown || strings.Contains(domain, "%")
		case "ptr":
			if t.arg != "" && !validSPFDomain(t.arg) {
				p.invalid = true
			}
			p.unknown = p.unknown || strings.Contains(t.arg, "%")
		case "ip4", "ip6":
			prefix := t.arg
			if !strings.Contains(prefix, "/") {
				if t.name == "ip4" {
					prefix += "/32"
				} else {
					prefix += "/128"
				}
			}
			ip, err := netip.ParsePrefix(prefix)
			if err != nil || t.name == "ip4" && !ip.Addr().Is4() || t.name == "ip6" && !ip.Addr().Is6() {
				p.invalid = true
			} else {
				t.broad = t.positive && (t.name == "ip4" && ip.Bits() <= 8 || t.name == "ip6" && ip.Bits() <= 16)
			}
		default:
			p.invalid = true
		}
		if reachable {
			p.terms = append(p.terms, t)
		}
	}
	if !all && redirect != nil {
		if !validSPFDomain(redirect.arg) {
			p.invalid = true
		}
		p.unknown = p.unknown || strings.Contains(redirect.arg, "%")
		p.terms = append(p.terms, *redirect)
	}
	p.denyAll = !p.invalid && !p.unknown && len(fields) == 2 && strings.EqualFold(fields[1], "-all")
	return p
}
func validSPFDomain(s string) bool {
	return s != "" && (strings.Contains(s, "%") || len(s) <= 254 && spfDomain.MatchString(s))
}
func dualCIDR(s string) bool {
	v4, v6, has6 := strings.Cut(s, "//")
	if after, ok := strings.CutPrefix(s, "/"); ok {
		v4, v6, has6 = "", after, true
	}
	valid := func(s string, max int) bool { n, e := strconv.Atoi(s); return e == nil && decimal(s) && n <= max }
	return (v4 == "" && has6 || valid(v4, 32)) && (!has6 || valid(v6, 128))
}

type spfInclude struct{ name, service string }
type spfInspection struct {
	known, denyAll, authorizes, complete, broad, pathUnknown bool
	reason                                                   string
	errors, grants, unmapped, reads                          []string
	includes                                                 []spfInclude
	count, voids                                             int
}

// inspectSPF is a static review of reachable published terms, never an SMTP
// evaluation. Definite defects survive an incomplete tree; absence does not
// (docs/spec/web-collector.md, "Email", "Reads").
func inspectSPF(m MailEvidence) spfInspection {
	s := spfInspection{reads: nonEmpty(m.TXT.RequestID), complete: true}
	if m.TXT.Insufficient() {
		s.reason = readReason(m.TXT)
		s.complete = false
		return s
	}
	if m.TXT.SPFMarked || markedOther(m.TXT.TXT) || slices.ContainsFunc(m.TXT.TXT, marked) {
		s.reason = "unavailable:redacted"
		s.complete = false
		return s
	}
	s.known = true
	records := spfOnly(m.TXT.TXT)
	if len(records) > 1 {
		s.errors = append(s.errors, "Multiple SPF records")
		return s
	}
	if len(records) == 0 {
		return s
	}
	s.denyAll = parseSPF(records[0]).denyAll
	// canPass is a recognized possible grant; universal means every sender
	// passes, which makes even a negative include terminal. valid is false
	// when an unknown or error prevents conclusions on the remaining path.
	type path struct{ canPass, universal, valid bool }
	var walk func(RecordRead, string, bool, bool, int) path
	walk = func(r RecordRead, owner string, allows, compare bool, depth int) path {
		result := path{valid: true}
		if depth > MaxLookups {
			s.complete = false
			return path{}
		}
		recs := spfOnly(r.TXT)
		if r.Insufficient() {
			s.complete = false
			s.reason = readReason(r)
			return path{}
		}
		if r.SPFMarked || slices.ContainsFunc(recs, marked) {
			s.complete = false
			s.reason = "unavailable:redacted"
			return path{}
		}
		if len(recs) != 1 {
			s.errors = append(s.errors, owner+": include or redirect returns no single SPF record")
			return path{}
		}
		p := parseSPF(recs[0])
		if p.invalid {
			s.errors = append(s.errors, owner+": invalid SPF syntax")
			return path{}
		}
		remaining, onlyPositive := true, true
		used := map[int]bool{}
		for _, t := range p.terms {
			positive := allows && remaining && t.positive
			if !remaining && t.positive {
				if allows {
					s.pathUnknown = true
				}
				result.valid = false
			}
			switch t.name {
			case "include", "a", "mx", "ptr", "exists", "redirect":
				s.count++
			}
			if s.count > MaxLookups {
				remaining = false
				positive = false
				result.valid = false
			}
			// A message-dependent macro cannot establish a later path's reachability.
			if strings.Contains(t.arg, "%") {
				s.complete = false
				s.reason = "unavailable:spf_macro"
				remaining = false
				result.valid = false
				continue
			}
			if t.name != "include" && t.name != "redirect" {
				if remaining && t.positive {
					result.canPass = true
				}
				if positive && (t.name == "all" || t.broad) {
					s.broad = true
					s.grants = append(s.grants, owner+": "+t.raw)
				}
				if compare && allows && t.positive && (t.name == "ip4" || t.name == "ip6") {
					s.unmapped = append(s.unmapped, t.raw)
				}
				if t.name == "all" {
					result.universal = remaining && t.positive && onlyPositive
					break
				}
				if !t.positive {
					remaining = false
					onlyPositive = false
				}
				continue
			}
			service := senderIncludes[strings.TrimSuffix(t.arg, ".")]
			found := false
			childPath := path{}
			for i, child := range m.SPF {
				if used[i] || child.From != r.RequestID || child.Via != t.name || !strings.EqualFold(strings.TrimSuffix(child.Name, "."), strings.TrimSuffix(t.arg, ".")) {
					continue
				}
				used[i] = true
				found = true
				s.reads = append(s.reads, nonEmpty(child.RequestID)...)
				if !child.Insufficient() && (child.Outcome == "nxdomain" || child.Outcome == "nodata") {
					s.voids++
				}
				childPath = walk(child.RecordRead, child.Name, positive, compare && service == "", depth+1)
				break
			}
			if !found {
				s.complete = false
				s.reason = "unavailable:spf_incomplete"
			}
			if remaining && t.positive && childPath.canPass {
				result.canPass = true
			}
			if t.name == "include" && positive && compare && childPath.canPass {
				s.includes = append(s.includes, spfInclude{strings.TrimSuffix(t.arg, "."), service})
				if service == "" {
					s.unmapped = append(s.unmapped, "include:"+t.arg)
				}
			} else if t.name == "include" && positive && compare && service == "" {
				s.unmapped = append(s.unmapped, "include:"+t.arg)
			}
			if childPath.universal {
				result.universal = remaining && t.positive && onlyPositive
				break
			}
			if !childPath.valid {
				remaining = false
				result.valid = false
			}
			if !t.positive && childPath.canPass {
				remaining = false
				onlyPositive = false
			}
		}
		return result
	}
	root := walk(m.TXT, m.Domain, true, true, 0)
	s.authorizes = root.canPass
	if s.count > MaxLookups {
		s.errors = append(s.errors, fmt.Sprintf("SPF can exceed its lookup limit: %s%d DNS-querying terms in the static tree", atLeast(!s.complete), s.count))
	}
	if s.voids > 2 {
		s.errors = append(s.errors, fmt.Sprintf("SPF can exceed its void-lookup limit: %s%d void lookups", atLeast(!s.complete), s.voids))
	}
	return s
}
func atLeast(b bool) string {
	if b {
		return "at least "
	}
	return ""
}

func (j *judging) spfRules(m MailEvidence, u mailUse, base Judgment) {
	s := inspectSPF(m)
	base.Reads = append(s.reads, u.reads...)
	base.Excerpt = "SPF of " + m.Domain + ": " + strings.Join(m.TXT.TXT, " | ")
	reason := s.reason
	if reason == "" && s.pathUnknown {
		reason = "unavailable:spf_path"
	}
	if reason == "" {
		reason = "unavailable:spf_incomplete"
	}
	emit := func(id, verdict, why string) { x := base; x.ID, x.Verdict, x.Reason = id, verdict, why; j.add(x) }
	switch u.mode {
	case "sending":
		switch {
		case !s.known:
			emit(finding.IDEmailSPFMissing, Abstained, reason)
		case len(m.TXT.TXT) == 0:
			emit(finding.IDEmailSPFMissing, Fired, "")
		default:
			emit(finding.IDEmailSPFMissing, Disproved, "")
		}
	case "":
		emit(finding.IDEmailSPFMissing, Abstained, "unavailable:mail_use")
	}
	if !s.known {
		emit(finding.IDEmailSPFInvalid, Abstained, reason)
		emit(finding.IDEmailSPFPermitsAnyone, Abstained, reason)
	} else if len(m.TXT.TXT) > 0 {
		switch {
		case len(s.errors) > 0:
			base.Excerpt += "; " + strings.Join(s.errors, "; ")
			incomplete := ""
			if !s.complete {
				incomplete = reason
			}
			emit(finding.IDEmailSPFInvalid, Fired, incomplete)
		case !s.complete:
			emit(finding.IDEmailSPFInvalid, Abstained, reason)
		default:
			emit(finding.IDEmailSPFInvalid, Disproved, "")
		}
		switch {
		case s.broad:
			base.Excerpt += "; broad authorization: " + strings.Join(s.grants, ", ")
			emit(finding.IDEmailSPFPermitsAnyone, Fired, "")
		case !s.complete || s.pathUnknown || len(s.errors) > 0:
			emit(finding.IDEmailSPFPermitsAnyone, Abstained, reason)
		default:
			emit(finding.IDEmailSPFPermitsAnyone, Disproved, "")
		}
	}
	// Compare only positive includes with declared services. A known provider's
	// internal include tree is not another business service declaration.
	base.Subject = Subject{Kind: "spf_mechanism", Key: m.Domain + "/SPF", Label: "SPF sender comparison for " + m.Domain}
	if len(u.senders) == 0 {
		emit(finding.IDEmailSPFUndeclaredSender, Abstained, "unavailable:mail_senders")
		return
	}
	if !s.known || !s.complete || s.pathUnknown || len(s.errors) > 0 {
		emit(finding.IDEmailSPFUndeclaredSender, Abstained, reason)
	}
	declared := map[string]bool{}
	for _, sender := range u.senders {
		declared[senderService(sender.Service)] = true
	}
	for _, inc := range s.includes {
		base.Subject = Subject{Kind: "spf_mechanism", Key: m.Domain + "/include:" + inc.name, Label: "SPF include:" + inc.name + " on " + m.Domain}
		base.Excerpt = "SPF includes senders through include:" + inc.name + " on " + m.Domain
		switch {
		case inc.service == "":
			emit(finding.IDEmailSPFUndeclaredSender, Abstained, "no_rule")
		case declared[inc.service]:
			emit(finding.IDEmailSPFUndeclaredSender, Disproved, "")
		default:
			base.Excerpt += " maps to " + inc.service + ", absent from declared senders"
			emit(finding.IDEmailSPFUndeclaredSender, Fired, "")
		}
	}
	if len(s.unmapped) > 0 {
		base.Subject = Subject{Kind: "spf_mechanism", Key: m.Domain + "/unmapped", Label: "SPF terms not mapped to a sending service: " + strings.Join(s.unmapped, ", ")}
		emit(finding.IDEmailSPFUndeclaredSender, Abstained, "no_rule")
	}
	if s.known && s.complete && !s.pathUnknown && len(s.errors) == 0 && len(s.includes) == 0 && len(s.unmapped) == 0 {
		emit(finding.IDEmailSPFUndeclaredSender, Disproved, "")
	}
}
