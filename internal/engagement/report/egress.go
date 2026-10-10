package report

import (
	"fmt"
	"slices"
	"strings"
	"time"

	hostreport "github.com/b87/scheck/internal/report"
)

// hostSideEffects are the host checks that may make a host contact its own
// package repositories (docs/spec/host-collector.md §1).
var hostSideEffects = []string{"pkg.dnf_check_update"}

// EgressInput is what left this machine, as the run counted it
// (docs/spec/report.md, "What left this machine").
type EgressInput struct {
	// Sources are the third-party sources the gate sent to, DNS first.
	Sources []SourceInput
	// Sites are the web requests by name, with whether one was admitted on
	// first-party evidence.
	Sites []SiteInput
	// UserAgent is what every web request carried, as the gate sets it.
	UserAgent string
	// SSHResolved are the names of the hosts and jump hosts SSH dialled,
	// written as names, which this machine's system resolver resolved;
	// SSHResolvedByJump are the host names a jump host resolved. The
	// gate's resolver saw neither.
	SSHResolved       []string
	SSHResolvedByJump []string
	// Tenants are the SaaS tenants whose people data was read.
	Tenants []string
	// Unrecorded are the starts of a resumed run's earlier sessions that
	// ended before recording all they sent: the counts are at least these.
	Unrecorded []time.Time
	// Contacts are the hosts a resumed run's earlier sessions reached;
	// this session's are its assets that were not kept.
	Contacts []HostContact
}

// HostContact is how far one session got in reaching one host asset, and
// the checks it ran there that may have made the host contact its own
// package repositories.
type HostContact struct {
	ID, Status, Contact, JumpContact, Via string
	SideEffects                           []string
}

// SideEffects are the checks of obs that may have made a host contact its
// own package repositories: a check that ran the binary, since one the host
// does not have contacted nothing.
func SideEffects(obs map[string]hostreport.Observation) []string {
	var out []string
	for _, o := range obs {
		if o.Attempted && o.ReasonCode != "command_missing" && slices.Contains(hostSideEffects, o.Check) && !slices.Contains(out, o.Check) {
			out = append(out, o.Check)
		}
	}
	slices.Sort(out)
	return out
}

// SourceInput is one third-party source.
type SourceInput struct {
	Source      string
	Operator    string
	Host        string
	Sent        []string
	Requests    int
	Credentials []string
	// For DNS, the gate's control lookups and whether it read only the
	// main resolver of a Mac.
	RootControls           int
	InvalidQueries         int
	InvalidControl         bool
	ScopedResolversIgnored bool
}

// SiteInput is one web name and the requests sent to it.
type SiteInput struct {
	Name       string
	FirstParty bool
	Requests   int
}

// Egress is the report's "What left this machine".
type Egress struct {
	Sources         []EgressSource `json:"sources"`
	Assets          []EgressAsset  `json:"assets"`
	Unconfirmed     EgressNames    `json:"unconfirmed"`
	HostSideEffects []string       `json:"host_side_effects"`
	Model           string         `json:"model"`
	Telemetry       string         `json:"telemetry"`
	UserAgent       string         `json:"user_agent"`
	// Stored is the run directory, nil when nothing was stored.
	Stored *string `json:"stored"`
	// Tenants are the tenants whose people data the run directory holds.
	Tenants []string `json:"tenants_read"`
	// SSHResolved are the host and jump host names this machine's system
	// resolver was asked for, to reach them over SSH; not counted.
	SSHResolved []string `json:"ssh_resolved"`
	// SSHResolvedByJump are the host names a jump host resolved.
	SSHResolvedByJump []string `json:"ssh_resolved_by_jump"`
	// Unrecorded are the starts of earlier sessions that ended before
	// recording all they sent; audit.jsonl holds every request they made.
	Unrecorded []time.Time `json:"unrecorded_sessions,omitempty"`
}

// EgressSource is one third-party source and what it was sent.
type EgressSource struct {
	Source   string `json:"source"`
	Operator string `json:"operator,omitempty"`
	Host     string `json:"host"`
	// Sent is what the source learned: the names, organizations or
	// repositories asked about. The DNS resolver's is described, not
	// listed.
	Sent        []string `json:"sent"`
	Requests    int      `json:"requests"`
	Credentials []string `json:"credentials,omitempty"`
	// ControlLookups counts the DNS lookups for random names under the
	// domain roots, and ControlInvalid says one was under invalid., both
	// among Requests: they test whether the resolver answers names that
	// do not exist.
	ControlLookups int  `json:"control_lookups,omitempty"`
	ControlInvalid bool `json:"control_invalid,omitempty"`
	InvalidQueries int  `json:"invalid_queries,omitempty"`
	// ScopedResolversIgnored says only a Mac's main resolver was asked,
	// not its per-interface (VPN) resolvers.
	ScopedResolversIgnored bool `json:"scoped_resolvers_ignored,omitempty"`
}

// EgressAsset is one kind of the operator's own systems.
type EgressAsset struct {
	Kind     string `json:"kind"`
	Requests int    `json:"requests,omitempty"`
	Sessions int    `json:"sessions,omitempty"`
	// Unreached counts the servers a connection was attempted to that
	// never answered.
	Unreached int `json:"unreached,omitempty"`
	// JumpHosts counts the jump hosts connected to, and JumpUnreached
	// those a connection was attempted to that never answered; each
	// distinct jump host once.
	JumpHosts     int `json:"jump_hosts,omitempty"`
	JumpUnreached int `json:"jump_unreached,omitempty"`
	Runs          int `json:"runs,omitempty"`
	Sites         int `json:"sites,omitempty"`
}

// EgressNames are the names under a root without first-party evidence
// that were sent requests.
type EgressNames struct {
	Names    []string `json:"names"`
	Requests int      `json:"requests"`
}

// egress builds the block from the run's counts and the assets.
func (b *builder) egress() Egress {
	in := b.in.Egress
	if in == nil {
		in = &EgressInput{}
	}
	e := Egress{Sources: []EgressSource{}, Assets: []EgressAsset{}, Unconfirmed: EgressNames{Names: []string{}},
		HostSideEffects: []string{}, Model: "none", Telemetry: "none", UserAgent: in.UserAgent,
		Tenants: orEmpty(in.Tenants), SSHResolved: orEmpty(in.SSHResolved), SSHResolvedByJump: orEmpty(in.SSHResolvedByJump)}
	for _, u := range in.Unrecorded {
		e.Unrecorded = append(e.Unrecorded, u.UTC())
	}
	if b.r.Run.Directory != nil {
		dir := *b.r.Run.Directory
		e.Stored = &dir
	}
	for _, s := range in.Sources {
		sent := make([]string, 0, len(s.Sent))
		for _, v := range s.Sent {
			_, v, _ = strings.Cut(v, ":")
			sent = append(sent, strings.TrimPrefix(v, "github:"))
		}
		if s.Source == "dns" {
			sent = []string{}
		}
		e.Sources = append(e.Sources, EgressSource{Source: s.Source, Operator: s.Operator, Host: s.Host, Sent: sent,
			Requests: s.Requests, Credentials: slices.Clone(s.Credentials), ControlLookups: s.RootControls,
			InvalidQueries: s.InvalidQueries, ControlInvalid: s.InvalidControl, ScopedResolversIgnored: s.ScopedResolversIgnored})
	}
	var web EgressAsset
	for _, s := range in.Sites {
		if s.FirstParty {
			web.Requests += s.Requests
			web.Sites++
			continue
		}
		e.Unconfirmed.Names = append(e.Unconfirmed.Names, s.Name)
		e.Unconfirmed.Requests += s.Requests
	}
	if web.Sites > 0 {
		web.Kind = "websites"
		e.Assets = append(e.Assets, web)
	}
	hosts := EgressAsset{Kind: "hosts"}
	jumps := map[string]string{} // jump host:port → connected, or unreached when never
	// This session's contacts, then a resumed run's earlier sessions': a
	// kept host was reached by the session that collected it.
	contacts := slices.Clone(in.Contacts)
	for _, a := range b.in.Assets {
		if a.Kind == "host" && !a.Kept {
			contacts = append(contacts, HostContact{ID: a.ID, Status: a.Status, Contact: a.Contact, JumpContact: a.JumpContact, Via: a.Via})
		}
	}
	for _, a := range contacts {
		// As far as the transport got, whatever became of the collection.
		switch {
		case a.ID == "host:local":
			if a.Status != "not_collected" {
				hosts.Runs++
			}
		case a.Contact == "connected":
			hosts.Sessions++
		case a.Contact == "unreached":
			hosts.Unreached++
		}
		// One server, whoever logs in to it: Via is user@host:port.
		if _, server, _ := strings.Cut(a.Via, "@"); server != "" && a.JumpContact != "" && jumps[server] != "connected" {
			jumps[server] = a.JumpContact
		}
	}
	// What the hosts were made to contact: in this report's envelopes, and
	// in what each earlier session recorded, since a host collected again
	// without the check may no longer show it.
	effects := slices.Clone(in.Contacts)
	for _, a := range b.in.Assets {
		if a.Kind == "host" && a.Host != nil {
			effects = append(effects, HostContact{SideEffects: SideEffects(a.Host.Envelope.Observations)})
		}
	}
	for _, c := range effects {
		for _, id := range c.SideEffects {
			if !slices.Contains(e.HostSideEffects, id) {
				e.HostSideEffects = append(e.HostSideEffects, id)
			}
		}
	}
	for _, c := range jumps {
		if c == "connected" {
			hosts.JumpHosts++
		} else {
			hosts.JumpUnreached++
		}
	}
	if hosts.Runs+hosts.Sessions+hosts.Unreached+hosts.JumpHosts+hosts.JumpUnreached > 0 {
		e.Assets = append(e.Assets, hosts)
	}
	slices.Sort(e.HostSideEffects)
	return e
}

// egress prints "What left this machine" (docs/spec/report.md), in
// plain words: a data protection officer reads it to answer a customer.
func (t *text) egress() {
	e := t.r.Egress
	t.line(t.bold("WHAT LEFT THIS MACHINE"))
	if len(e.Unrecorded) > 0 {
		starts := make([]string, len(e.Unrecorded))
		for i, u := range e.Unrecorded {
			starts[i] = u.In(t.zone).Format("2006-01-02 15:04")
		}
		sessions := "the session started " + joinAnd(starts) + " ended before it recorded all it sent"
		if len(starts) > 1 {
			sessions = "the sessions started " + joinAnd(starts) + " ended before they recorded all they sent"
		}
		t.hang("  ", "  ", "At least what follows: "+sessions+". audit.jsonl in the run directory lists every request this run made.")
	}
	t.line("  Third-party services:")
	if len(e.Sources) == 0 && len(e.SSHResolved) == 0 {
		t.line("    none")
	}
	for _, s := range e.Sources {
		t.hang("    ", "      ", clean(sourceLine(s)))
	}
	if len(e.SSHResolved) > 0 {
		t.hang("    ", "      ", clean("Your DNS resolver, asked through this machine's system resolver for the servers reached "+
			"over SSH that are written as names: "+joinAnd(e.SSHResolved)+"; not counted."))
	}
	if n := e.SSHResolvedByJump; len(n) > 0 {
		verb := "were"
		if len(n) == 1 {
			verb = "was"
		}
		t.hang("    ", "      ", clean(joinAnd(n)+", reached through a jump host, "+verb+" resolved by the jump host, not by this machine."))
	}
	t.line("  Your own systems:")
	if len(e.Assets) == 0 {
		t.line("    none")
	}
	for _, a := range e.Assets {
		switch a.Kind {
		case "websites":
			t.line(fmt.Sprintf("    websites shown to be yours: %d %s, %d %s.", a.Sites, plural(a.Sites, "site"), a.Requests, plural(a.Requests, "request")))
		case "hosts":
			var parts []string
			if a.Sessions > 0 {
				parts = append(parts, fmt.Sprintf("%d SSH %s", a.Sessions, plural(a.Sessions, "session")))
			}
			if a.Unreached > 0 {
				parts = append(parts, fmt.Sprintf("%d %s not reached (a connection was attempted)", a.Unreached,
					plural(a.Unreached, "server")))
			}
			if a.JumpHosts > 0 {
				parts = append(parts, fmt.Sprintf("%d jump %s connected to", a.JumpHosts, plural(a.JumpHosts, "host")))
			}
			if a.JumpUnreached > 0 {
				parts = append(parts, fmt.Sprintf("%d jump %s not reached (a connection was attempted)", a.JumpUnreached,
					plural(a.JumpUnreached, "host")))
			}
			if a.Runs > 0 {
				parts = append(parts, "this machine, read in place")
			}
			t.line("    servers: " + strings.Join(parts, "; ") + ".")
		}
	}
	for _, id := range e.HostSideEffects {
		t.hang("    ", "      ", "One server check may make the server download its package list from its own update servers ("+id+").")
	}
	t.line("  Names under your domains not shown to be yours:")
	if len(e.Unconfirmed.Names) == 0 {
		t.line("    none")
	} else {
		names := e.Unconfirmed.Names
		list := strings.Join(names, ", ")
		if len(names) > 10 {
			list = strings.Join(names[:10], ", ") + fmt.Sprintf(" and %d more", len(names)-10)
		}
		t.hang("    ", "      ", clean(fmt.Sprintf("%s: %d %s, what a browser sends when it opens the page (the certificate, and the "+
			"home page over https and http). These servers may be a provider's or someone else's.", list, e.Unconfirmed.Requests,
			plural(e.Unconfirmed.Requests, "request"))))
	}
	t.line("  AI models:")
	t.line("    Nothing was sent to an AI model provider.")
	t.line("  Nothing was sent to the makers of scheck: no telemetry, no update check.")
	if len(e.Assets) > 0 && e.Assets[0].Kind == "websites" || len(e.Unconfirmed.Names) > 0 {
		t.line(`  Every web request identified itself as "` + e.UserAgent + `".`)
	}
	switch {
	case e.Stored == nil:
		t.line("  What scheck read is stored nowhere; the report is on stdout.")
	case len(e.Tenants) > 0:
		t.hang("  ", "    ", clean("What scheck read, including people's names and email addresses from "+strings.Join(e.Tenants, ", ")+
			", is stored only on this machine, in "+*e.Stored+"; deleting that directory removes it."))
	default:
		t.hang("  ", "    ", clean("What scheck read is stored only on this machine, in "+*e.Stored+"; deleting that directory removes it."))
	}
	t.blank()
}

// sourceLine is one third-party source in words.
func sourceLine(s EgressSource) string {
	n := fmt.Sprintf("%d %s", s.Requests, plural(s.Requests, "request"))
	switch s.Source {
	case "dns":
		who := "Your DNS resolver at " + s.Host
		switch s.Host {
		case "127.0.0.53":
			who = "Your system's resolver (systemd-resolved)"
		case "":
			who = "Your DNS resolver"
		}
		line := who + ", and whatever it forwards to, as for any web browsing on this network: names under your domains, " +
			"the names they point to (including third-party mail and DNS providers), and the services above; " + fmt.Sprintf("%d %s", s.Requests, plural(s.Requests, "lookup"))
		switch c := s.ControlLookups; {
		case s.InvalidQueries > 0:
			line += fmt.Sprintf(", including %d random test %s under your domains and %d %s for random names under invalid", c, plural(c, "name"), s.InvalidQueries, func() string {
				if s.InvalidQueries == 1 {
					return "query"
				}
				return "queries"
			}())
		case c > 0 && s.ControlInvalid:
			line += fmt.Sprintf(", including %d random test %s under your domains and one under invalid", c, plural(c, "name"))
		case c > 0:
			line += fmt.Sprintf(", including %d random test %s", c, plural(c, "name"))
		case s.ControlInvalid:
			line += ", including one random test name under invalid"
		}
		line += "."
		if s.ScopedResolversIgnored {
			line += " On this Mac only the main resolver was asked: per-interface (VPN) resolvers were not used."
		}
		return line
	case "crt.sh":
		return fmt.Sprintf("crt.sh, a public certificate log run by %s: asked which certificates exist for %s; %s. "+
			"crt.sh sees this machine's internet address and those names, and may keep logs.", or(s.Operator, "a third party"),
			joinAnd(s.Sent), n)
	}
	var line strings.Builder
	line.WriteString(s.Host)
	line.WriteString(": ")
	line.WriteString(joinAnd(s.Sent))
	for _, c := range s.Credentials {
		line.WriteString(", using the credential in ")
		line.WriteString(c)
		line.WriteString(" (the variable's name; its value appears nowhere)")
	}
	return line.String() + "; " + n + "."
}

// orEmpty is a copy of xs, empty rather than nil, for a JSON list.
func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return slices.Clone(xs)
}

func joinAnd(xs []string) string {
	switch len(xs) {
	case 0:
		return "nothing"
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
