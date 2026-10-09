package web

import (
	"fmt"
	"strings"
)

// MailContext carries declarations only, never inferred sending activity.
// Email findings belong to the root and carry their own mail subjects
// (docs/spec/web-collector.md, "Subjects").
type MailContext struct {
	Domain  string
	NoMail  bool
	Senders []MailSender
}

type MailSender struct {
	Service   string
	Selectors []string
}

// MailNote is DNS context for the readout, including what DNS cannot prove.
type MailNote struct{ Domain, Detail string }

type mailUse struct {
	mode, label, detail string
	senders             []MailSender
	reads               []string
}

func (in Input) mailUse(m MailEvidence) mailUse {
	u := mailUse{label: m.Domain + " (not declared)"}
	for _, c := range in.MailContext {
		if c.Domain != m.Domain {
			continue
		}
		u.senders = c.Senders
		if c.NoMail {
			u.mode, u.label = "none", m.Domain+" (declared no mail)"
			u.detail = "You declared that " + m.Domain + " sends no mail."
			return u
		}
		if len(c.Senders) > 0 {
			var names []string
			for _, s := range c.Senders {
				names = append(names, s.Service)
			}
			u.mode, u.label = "sending", m.Domain+" (declared sending: "+strings.Join(names, ", ")+")"
			u.detail = "You listed " + strings.Join(names, ", ") + " as sending for " + m.Domain + ". DNS does not show whether they send current mail."
			return u
		}
	}
	u.reads = append(inspectSPF(m).reads, nonEmpty(m.MX.RequestID)...)
	sp := inspectSPF(m)
	mx := false
	for _, r := range m.MX.MX {
		mx = mx || r.Target != "." && r.Target != ""
	}
	switch {
	case !m.MX.Insufficient() && mx, sp.authorizes:
		u.mode = "sending"
		signs := "SPF authorization"
		if mx && !m.MX.Insufficient() {
			signs = "a non-null MX"
		}
		u.detail = "You did not say whether " + m.Domain + " sends mail. It shows signs of mail use (" + signs + "), so it was judged as a sending domain. This does not prove it sends mail."
	case !m.MX.Insufficient() && sp.known && sp.complete && !sp.pathUnknown && len(sp.errors) == 0 && !sp.authorizes:
		u.mode = "none"
		u.detail = "You did not say whether " + m.Domain + " sends mail. It shows no signs of mail use in the records read, so it was judged as a domain that sends no mail."
	default:
		u.detail = "You did not say whether " + m.Domain + " sends mail, and the DNS evidence could not establish its mail use."
	}
	return u
}

func (j *judging) email(m MailEvidence) {
	u := j.in.mailUse(m)
	base := Judgment{Asset: j.in.Asset, Subject: Subject{Kind: "mail_domain", Key: m.Domain, Label: u.label}, Context: u.detail, Reads: []string{}}
	j.dmarc(m, u, base)
	j.spfRules(m, u, base)
	j.dkim(m, u, base)
}

// MailNotes describes mail use, alignment and comparison limitations even when
// no finding fires. It reads only the same redacted evidence as Judge.
func MailNotes(in Input) []MailNote {
	var notes []MailNote
	for _, m := range in.Evidence.Mail {
		u := in.mailUse(m)
		if in.Doubt != "" {
			u.detail = "Mail DNS could not be judged: " + in.Doubt
		}
		notes = append(notes, MailNote{m.Domain, u.detail})
		if in.Doubt != "" {
			continue
		}
		d := in.dmarcPolicy(m)
		if d.reason == "" && len(d.tags) > 0 {
			var alignment []string
			for _, tag := range []string{"adkim", "aspf"} {
				v, ok := d.tags[tag]
				if !ok {
					v = "r (default relaxed)"
				}
				alignment = append(alignment, tag+"="+v)
			}
			notes = append(notes, MailNote{m.Domain, strings.Join(alignment, ", ") + "; whether your senders' mail actually aligns is not visible in DNS. Aggregate-report destination present: " + fmt.Sprint(d.rua)})
		}
		notes = append(notes, MailNote{m.Domain, "DMARC coverage is limited to the DNS records read, including legacy pct percentages. Receivers may discover or apply policies differently; actual mail handling was not tested"})
		if len(u.senders) == 0 {
			notes = append(notes, MailNote{m.Domain, "SPF was not compared with your senders: none were listed for this domain"})
		}
		if len(u.senders) == 0 {
			notes = append(notes, MailNote{m.Domain, "DKIM was not checked: no selector given, and DNS cannot list selectors. Find s= in the DKIM-Signature header of a recent message"})
		}
		for _, sender := range u.senders {
			if len(sender.Selectors) == 0 {
				notes = append(notes, MailNote{m.Domain, "DKIM for " + sender.Service + " was not checked: no selector given. Find s= in the DKIM-Signature header of a recent message from this service"})
			}
		}
		notes = append(notes, MailNote{m.Domain, "SPF a, mx, ptr and exists terms were counted without evaluating their address results; actual sender authentication was not assessed"})
		sp := inspectSPF(m)
		for _, item := range sp.unmapped {
			notes = append(notes, MailNote{m.Domain, "SPF term read, not compared with declared senders: " + item})
		}
		if u.mode == "none" {
			signs := sp.authorizes
			for _, mx := range m.MX.MX {
				signs = signs || !m.MX.Insufficient() && mx.Target != "." && mx.Target != ""
			}
			for _, sel := range m.DKIM {
				signs = signs || !sel.Read.Insufficient() && len(sel.Keys) > 0
			}
			if signs {
				notes = append(notes, MailNote{m.Domain, "Declared no mail, but DNS shows mail-related records. Confirm whether this domain still sends or receives mail before changing its policy"})
			}
		}
	}
	return notes
}
