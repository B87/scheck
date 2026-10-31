package web

import (
	"context"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// Probe is one entry of the reviewed probe list (docs/spec/scope.md,
// "Probes"; docs/spec/web-collector.md, "Probes"): a single GET of a
// well-known sensitive path of a first-party site. The path and the
// signature are compiled in; nothing a site says, and nothing an operator
// writes, adds one. A probe asks one question: does this path serve a file
// of this shape. It never reads past the first ProbeMaxBytes and keeps none
// of them.
type Probe struct {
	// ID names the probe and its op, web.probe.<ID>.
	ID string
	// Path is the whole request path.
	Path string
	// Tag is the framework the probe applies to, "" for every site.
	Tag string
	// Finding is the finding id a match raises.
	Finding string
	// Shape says what a match is, for the preview and the report.
	Shape string
	// Signature is the content test the gate applies.
	Signature gate.Signature
}

// ProbesVersion versions the list: a changed path or signature changes it.
const ProbesVersion = "2026-10-31"

var textFile = []string{"text/plain", "application/octet-stream"}

// Probes is the reviewed list, in the order it is sent.
var Probes = []Probe{
	{ID: "git_head", Path: "/.git/HEAD", Finding: finding.IDWebVCSMetadataExposed, Shape: "a git HEAD file",
		Signature: gate.Signature{Pattern: `\A(ref: refs/[A-Za-z0-9._/-]+|[0-9a-f]{40})\s*\z`, Types: textFile}},
	{ID: "git_config", Path: "/.git/config", Finding: finding.IDWebVCSMetadataExposed, Shape: "a git config file",
		Signature: gate.Signature{Pattern: `(?m)^\[core\]\s*$`, Types: textFile}},
	{ID: "env", Path: "/.env", Finding: finding.IDWebConfigFileExposed, Shape: "an environment file (KEY=value lines)",
		Signature: gate.Signature{Pattern: `(?m)^(export\s+)?[A-Z][A-Z0-9_]{2,}\s*=`, Types: textFile}},
	{ID: "htpasswd", Path: "/.htpasswd", Finding: finding.IDWebConfigFileExposed, Shape: "a password file (user:hash lines)",
		Signature: gate.Signature{Pattern: `(?m)^[A-Za-z0-9._@-]+:(\$apr1\$|\$2[abxy]\$|\{SHA\}|\$[56]\$)`, Types: textFile}},
	{ID: "server_status", Path: "/server-status", Finding: finding.IDWebDebugInterfaceExposed, Shape: "Apache's server status page",
		Signature: gate.Signature{Pattern: `Apache Server Status for`, Types: []string{"text/html"}}},
	{ID: "npmrc", Path: "/.npmrc", Tag: "node", Finding: finding.IDWebConfigFileExposed, Shape: "an npm configuration file",
		Signature: gate.Signature{Pattern: `(?m)^(//[^\s=]+:_authToken\s*=|_auth\s*=|registry\s*=)`, Types: textFile}},
	{ID: "wp_config_bak", Path: "/wp-config.php.bak", Tag: "wordpress", Finding: finding.IDWebConfigFileExposed, Shape: "a WordPress configuration backup",
		Signature: gate.Signature{Pattern: `define\(\s*['"]DB_(NAME|USER|PASSWORD)['"]`, Types: textFile}},
	{ID: "wp_debug_log", Path: "/wp-content/debug.log", Tag: "wordpress", Finding: finding.IDWebConfigFileExposed, Shape: "a WordPress debug log",
		Signature: gate.Signature{Pattern: `(?m)^\[\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2} UTC\] `, Types: textFile}},
	{ID: "phpinfo", Path: "/phpinfo.php", Tag: "php", Finding: finding.IDWebDebugInterfaceExposed, Shape: "a phpinfo() page",
		Signature: gate.Signature{Pattern: `PHP Version [0-9]`, Types: []string{"text/html"}}},
	{ID: "symfony_profiler", Path: "/_profiler/", Tag: "php", Finding: finding.IDWebDebugInterfaceExposed, Shape: "the Symfony profiler",
		Signature: gate.Signature{Pattern: `Symfony Profiler`, Types: []string{"text/html"}}},
	{ID: "laravel_ignition", Path: "/_ignition/health-check", Tag: "laravel", Finding: finding.IDWebDebugInterfaceExposed, Shape: "Laravel's Ignition health check",
		Signature: gate.Signature{Pattern: `"can_execute_commands"`, Types: []string{"application/json"}}},
	{ID: "spring_env", Path: "/actuator/env", Tag: "spring", Finding: finding.IDWebDebugInterfaceExposed, Shape: "Spring Boot's environment endpoint",
		Signature: gate.Signature{Pattern: `"propertySources"`, Types: []string{"application/json", "application/vnd.spring-boot.actuator.v3+json", "application/vnd.spring-boot.actuator.v2+json", "application/vnd.spring-boot.actuator+json"}}},
	{ID: "rails_info", Path: "/rails/info/properties", Tag: "rails", Finding: finding.IDWebDebugInterfaceExposed, Shape: "Rails' info page",
		Signature: gate.Signature{Pattern: `Rails version`, Types: []string{"text/html"}}},
}

// impliedTags are the tags a declared framework also selects: PHP frameworks
// run the PHP probes. django has no probe of its own: its debug page answers only to a
// missing path, which no fixed list can ask for.
var impliedTags = map[string][]string{"laravel": {"php"}, "wordpress": {"php"}}

// OpProbe is a probe's op id.
func OpProbe(p Probe) string { return "web.probe." + p.ID }

// ProbeOps are the probes' declared requests: one op per probe, its path
// literal.
func ProbeOps() []gate.Op {
	ops := make([]gate.Op, 0, len(Probes))
	for _, p := range Probes {
		sig := p.Signature
		ops = append(ops, gate.Op{ID: OpProbe(p), Provider: "web", Method: gate.GET, URL: "{scheme}://{host}" + p.Path,
			Params: []gate.Param{{Name: "scheme", Type: gate.Scheme}, {Name: "host", Type: gate.Host}},
			Level:  gate.Probe, Accept: []string{"*/*"}, MaxBytes: gate.ProbeMaxBytes, Signature: &sig})
	}
	return ops
}

// SelectProbes splits the list by the frameworks a site was declared built
// with: the probes that apply, and those whose framework was not declared.
// A site declared none, or with no declaration, gets only the probes that
// apply to every site; guessing a framework from the site's own answers
// would be path discovery (docs/spec/scope.md, "Impact levels").
func SelectProbes(frameworks []string) (apply, skipped []Probe) {
	for _, p := range Probes {
		if p.Tag == "" || slices.ContainsFunc(frameworks, func(f string) bool {
			return f == p.Tag || slices.Contains(impliedTags[f], p.Tag)
		}) {
			apply = append(apply, p)
		} else {
			skipped = append(skipped, p)
		}
	}
	return apply, skipped
}

// ProbeSkip is a probe that is listed but not sent, and why.
type ProbeSkip struct {
	Probe Probe
	Why   string
}

// ProbeTarget is one site to probe: the probes to send, and those that
// were chosen but are not sent. Engagement decides both; the collector
// sends exactly Send, in order, one request each.
type ProbeTarget struct {
	Name   string
	Scheme string
	Mode   string
	// Evidence is the first-party evidence the probes rest on, as the
	// report words it.
	Evidence string
	Send     []Probe
	Skip     []ProbeSkip
}

// ProbeEvidence is what the probes of one domain root read.
type ProbeEvidence struct {
	Sites []ProbeSite `json:"sites"`
}

// ProbeSite is one site's probes.
type ProbeSite struct {
	Name     string      `json:"name"`
	Scheme   string      `json:"scheme"`
	Mode     string      `json:"mode"`
	Evidence string      `json:"evidence"`
	Reads    []ProbeRead `json:"reads"`
}

// ProbeRead is one probe's outcome: what the response was, never its body.
type ProbeRead struct {
	Probe   string `json:"probe"`
	URL     string `json:"url"`
	Finding string `json:"finding"`
	// NotRun is why nothing was sent for it, as a coverage code without its
	// "unavailable:" prefix; empty when it was sent or the gate refused it.
	NotRun      string    `json:"not_run,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	Status      int       `json:"status,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Matched     bool      `json:"matched,omitempty"`
	Redacted    []string  `json:"redacted,omitempty"`
	Vantage     string    `json:"vantage,omitempty"`
	CollectedAt time.Time `json:"collected_at,omitzero"`
}

// Not-run codes of a probe, after "unavailable:".
const (
	NotRunMode      = "probe_mode"
	NotRunDeclined  = "probe_declined"
	NotRunNoTTY     = "probe_no_terminal"
	NotRunNoAnswer  = "probe_site_unreachable"
	NotRunWindow    = "probe_window"
	NotRunEvidence  = "probe_evidence"
	NotRunCancelled = "probe_not_reached"
)

// CollectProbes sends each target's probes through the gate, one GET apiece.
// A refusal the gate makes for the site as a whole (outside the window, no
// first-party evidence, an address that moved) ends that site's list: the
// rest are recorded as not run for the same reason, not asked again.
func CollectProbes(ctx context.Context, g Gate, asset string, targets []ProbeTarget) ProbeEvidence {
	var ev ProbeEvidence
	for _, t := range targets {
		s := ProbeSite{Name: t.Name, Scheme: t.Scheme, Mode: t.Mode, Evidence: t.Evidence}
		for _, sk := range t.Skip {
			s.Reads = append(s.Reads, ProbeRead{Probe: sk.Probe.ID, URL: probeURL(t, sk.Probe), Finding: sk.Probe.Finding, NotRun: sk.Why})
		}
		halted := ""
		for _, p := range t.Send {
			r := ProbeRead{Probe: p.ID, URL: probeURL(t, p), Finding: p.Finding}
			switch {
			case halted != "":
				r.NotRun = halted
			case ctx.Err() != nil:
				r.NotRun = NotRunCancelled
			default:
				res := g.Send(ctx, gate.Request{Op: OpProbe(p), Asset: asset, Stage: "check",
					Params: map[string]string{"scheme": t.Scheme, "host": t.Name}})
				r = probeRead(r, res)
				halted = siteHalt(res.Decision)
			}
			s.Reads = append(s.Reads, r)
		}
		ev.Sites = append(ev.Sites, s)
	}
	return ev
}

func probeURL(t ProbeTarget, p Probe) string { return t.Scheme + "://" + t.Name + p.Path }

// siteHalt is the not-run code of a refusal that holds for every probe of
// the site.
func siteHalt(decision string) string {
	switch decision {
	case "refused:window":
		return NotRunWindow
	case "refused:first_party", "refused:address_moved":
		return NotRunEvidence
	case "refused:level":
		return NotRunMode
	}
	return ""
}

func probeRead(r ProbeRead, res gate.Result) ProbeRead {
	r.RequestID, r.Decision, r.Detail = res.RequestID, res.Decision, res.Detail
	resp := res.Response
	if resp == nil {
		return r
	}
	r.Status, r.Matched, r.Vantage, r.CollectedAt = resp.Status, resp.Matched, resp.Vantage, resp.CollectedAt
	if media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		r.ContentType = strings.ToLower(media)
	}
	for _, h := range resp.Redactions {
		r.Redacted = append(r.Redacted, fmt.Sprintf("%s:%d", h.Rule, h.Bytes))
	}
	return r
}

// probes judges what the probes read (docs/spec/web-collector.md,
// "Probes"): fired when the path served a file of the shape, disproved when
// it plainly did not, abstained on anything that leaves it open. A 200 that
// does not match is disproved only when nothing in it was redacted: a
// marker could be what hid the shape.
func (j *judging) probes() {
	if j.in.Probes == nil {
		return
	}
	for _, s := range j.in.Probes.Sites {
		for _, r := range s.Reads {
			x := j.webVerdict(r.Finding, r.URL, "url", "", "", nil)
			x.Reads = []string{r.RequestID}
			x.Details = map[string]any{"probe": r.Probe, "evidence": s.Evidence, "mode": s.Mode}
			switch {
			case r.NotRun != "":
				x.Reason = "unavailable:" + r.NotRun
			case r.Decision != gate.DecisionSent && r.Decision != "reused":
				x.Reason = probeRefusal(r)
			case r.Status == 200 && r.Matched:
				x.Verdict = Fired
				x.Excerpt = fmt.Sprintf("served (status 200, %s) and matched %s; only its first lines were read and none were kept; probed on first-party evidence: %s", r.ContentType, probeShape(r.Probe), s.Evidence)
				x.Details["status"], x.Details["content_type"] = r.Status, r.ContentType
				if len(r.Redacted) > 0 {
					x.Details["redacted"] = r.Redacted
				}
			case r.Status == 401 || r.Status == 403 || r.Status == 429 || r.Status >= 500:
				x.Reason = "unavailable:http_status"
			case r.Status >= 300 && r.Status < 400:
				x.Reason = "unavailable:redirected"
			case r.Status == 200 && len(r.Redacted) > 0:
				x.Reason = "unavailable:redacted"
			default:
				x.Verdict = Disproved
				x.Excerpt = "not served at this path from this vantage; probed on first-party evidence: " + s.Evidence
				x.Details["status"] = r.Status
			}
			j.add(x)
		}
	}
}

// probeRefusal is the coverage reason of a probe the gate did not send.
func probeRefusal(r ProbeRead) string {
	if c := siteHalt(r.Decision); c != "" {
		return "unavailable:" + c
	}
	if reason := gate.ReasonOf(r.Decision); reason != "" {
		return reason
	}
	return "unavailable:not_read"
}

func probeShape(id string) string {
	for _, p := range Probes {
		if p.ID == id {
			return p.Shape
		}
	}
	return id
}
