package rules

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/advisory"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// R7 php.fix_missing, R8 node.fix_missing and R9 node.line_unsupported
// (docs/spec/engagement.md, R7 to R9; G8): the PHP and Node.js packages a host
// has installed, judged against the dated advisory table of internal/advisory.
// They read package metadata only, never the runtimes, and the table decides
// what a version means: no rule here compares a version.

// WebServersVersion identifies the list of programs below: a change to it
// changes what R7 reads as a web server in front of PHP.
const WebServersVersion = "2026-10-24"

// webServers are the programs, as the kernel names them (comm, cut at 15
// characters), whose listening beyond localhost means PHP behind them is
// reachable. A reverse proxy that may front PHP on another machine
// (haproxy, traefik, envoy, varnishd) is not counted, and nor is PHP's
// built-in development server (php), which the advisory does not address.
var webServers = []string{"nginx", "apache2", "httpd", "caddy", "lighttpd", "litespeed", "lshttpd", "openlitespeed",
	"frankenphp", "unitd", "angie"}

// isWebServer says a listener's program serves web requests: a table entry,
// or PHP's own FastCGI and CGI daemons listening themselves.
func isWebServer(process string) bool {
	return slices.Contains(webServers, process) || strings.HasPrefix(process, "php-fpm") || strings.HasPrefix(process, "php-cgi")
}

// The checks R7 to R9 read.
const (
	checkDpkgRuntimes = "pkg.dpkg_runtimes"
	checkRpmRuntimes  = "pkg.rpm_runtimes"
)

// Reasons the runtime rules abstain with, beyond the table's own
// (advisory.Reason*), which are prefixed "unavailable:".
const (
	reasonPackages        = "unavailable:packages"
	reasonPackagesPartial = "unavailable:packages_partial"
	reasonDistribution    = "unavailable:distribution"
	reasonLineUnsupported = "unavailable:line_unsupported"
	reasonDistroPackage   = "unavailable:distro_package"
	reasonPHPNoPackage    = "unavailable:php_without_package"
	reasonEOLWithin       = "unavailable:eol_within_collection"
	reasonRuntimeInstalls = "unavailable:runtime_installs"
)

// notCheckedRuntimes is what every R7 to R9 judgment leaves unread.
const notCheckedRuntimes = "Read: PHP and Node.js packages from dpkg and rpm. Not read: containers and their images; Homebrew and installs " +
	"from source; nvm, volta, asdf and fnm installs in home directories; control-panel PHP (cPanel, Plesk, CloudLinux); Node.js inside " +
	"applications; other programs that bundle Brotli; whether running processes were restarted after an update. Advisories published " +
	"after " + advisory.TableVersion + ", the date of this build's table, are not known to it"

// runtimeGap is the coverage gap of the runtime groups: what no read can
// reach, so a group is at most partial.
var runtimeGap = &finding.CoverageReason{Reason: reasonRuntimeInstalls,
	Detail: "PHP and Node.js installed outside the package database (containers, Homebrew, source builds, version managers, control panels) are not read"}

// whyModPHP is added to a fired R7 on the Apache module.
const whyModPHP = "Apache with mod_php is the setup the PHP project demonstrated a full exploit against."

func init() {
	pkgReads := []Read{{ReadCheck, checkDpkgRuntimes}, {ReadCheck, checkRpmRuntimes}, {ReadCheck, checkOSRelease}}
	incomplete := finding.CoverageReason{Reason: reasonPackages,
		Detail: "neither package database could be read, so PHP and Node.js could not be judged"}
	unbuilt := "this version of scheck reads PHP and Node.js packages on Linux only"
	registry = append(registry,
		Rule{
			ID: finding.IDPHPFixMissing, Platform: check.Linux,
			Reads: append(slices.Clone(pkgReads), append([]Read{{ReadCheck, checkListeners}},
				slices.DeleteFunc(slices.Clone(firewallReads), func(r Read) bool { return r.Name == checkOSRelease })...)...),
			Judge: phpFixMissing, OwnPartial: true,
			Group: "PHP security fix (October 2026)", Unbuilt: unbuilt, Incomplete: incomplete, Gap: runtimeGap,
			HostDomain: check.DomainRuntimes, HostJudges: "PHP web packages against the October 2026 fix",
		},
		Rule{
			ID: finding.IDNodeFixMissing, Platform: check.Linux, Reads: slices.Clone(pkgReads), Judge: nodeFixMissing, OwnPartial: true,
			Group: "Node.js security fixes (October 2026)", Unbuilt: unbuilt, Incomplete: incomplete, Gap: runtimeGap,
			HostDomain: check.DomainRuntimes, HostJudges: "Node.js packages against the October 2026 fixes",
		},
		Rule{
			ID: finding.IDNodeLineUnsupported, Platform: check.Linux, Reads: slices.Clone(pkgReads), Judge: nodeLineUnsupported, OwnPartial: true,
			Group: "Node.js release line support", Unbuilt: unbuilt, Incomplete: incomplete, Gap: runtimeGap,
			HostDomain: check.DomainRuntimes, HostJudges: "whether the Node.js release line is still fixed by its project",
		})
}

// runtimeRead is what the package reads gave: the table's assessment, the
// os-release it was made with, and which reads were usable and whole.
type runtimeRead struct {
	a       advisory.Assessment
	osr     map[string]string
	read    []string
	partial []string
}

// readRuntimes reads the two package databases and os-release and judges
// them with the advisory table. The abstention is the whole rule's when
// neither database could be read; a host has one of them, so the other being
// unavailable is expected.
func readRuntimes(v *View) (runtimeRead, *Outcome) {
	var rr runtimeRead
	var reads []check.Records
	var whys []string
	if f, why := v.Fact(checkOSRelease); why == "" {
		rr.osr, _ = f.Parsed.(map[string]string)
	}
	for _, id := range []string{checkDpkgRuntimes, checkRpmRuntimes} {
		f, why := v.Fact(id)
		recs, typed := f.Parsed.(check.Records)
		if why != "" || !typed {
			whys = append(whys, id+": "+why)
			continue
		}
		reads, rr.read = append(reads, recs), append(rr.read, id)
		// A partial read counts unless the distribution is one the other
		// manager covers: an rpm database that does not exist on a Debian
		// host is not "cut short". On a distribution the reads do not know,
		// or with os-release unread, every partial read counts.
		other := "rpm"
		if id == checkRpmRuntimes {
			other = "dpkg"
		}
		if (f.Partial || recs.Partial) && !advisory.Covers(rr.osr, other) {
			rr.partial = append(rr.partial, id)
		}
	}
	if len(reads) == 0 {
		return rr, &Outcome{Verdict: Abstained, Reason: reasonPackages,
			NotChecked: []string{"the package databases could not be read (" + strings.Join(whys, "; ") + ")"}}
	}
	rr.a = advisory.Assess(rr.osr, reads...)
	return rr, nil
}

// citeOf is the package check a runtime was read from.
func citeOf(r advisory.Runtime) string {
	if r.Manager == "rpm" {
		return checkRpmRuntimes
	}
	return checkDpkgRuntimes
}

func runtimeSubject(r advisory.Runtime) finding.Subject {
	return finding.Subject{Kind: "package", Key: r.Package, Label: r.Package}
}

// evidence is what a verdict on one package rests on: the package record,
// the Brotli library it was judged through, and the os-release that chose
// the distribution's row.
func (rr runtimeRead) evidence(r advisory.Runtime) []Excerpt {
	out := []Excerpt{{citeOf(r), r.Excerpt}}
	if r.Via != "" {
		out = append(out, Excerpt{citeOf(r), r.Via})
	}
	if id := rr.osr["id"]; id != "" {
		out = append(out, Excerpt{checkOSRelease, "ID=" + id + " VERSION_ID=" + rr.osr["version_id"]})
	}
	return out
}

// partialNote says which reads were not whole.
func (rr runtimeRead) partialNote() string {
	return "the read of " + strings.Join(rr.partial, " and ") + " was cut short, held a package that was not fully installed, or had " +
		"lines scheck did not recognize, so it is not read as showing a package absent or fixed"
}

// settle is a disproof only a whole read can carry: with any partial read it
// becomes an abstention that says so. Every verdict but a disproof stands.
func (rr runtimeRead) settle(o Outcome) Outcome {
	if o.Verdict != Disproved || len(rr.partial) == 0 {
		return o
	}
	o.Verdict, o.Reason = Abstained, reasonPackagesPartial
	o.NotChecked = append([]string{rr.partialNote()}, o.NotChecked...)
	return o
}

// unknownOutcome is the abstention of a package the table cannot judge.
func (rr runtimeRead) unknownOutcome(r advisory.Runtime) Outcome {
	return Outcome{Subject: runtimeSubject(r), Verdict: Abstained, Reason: "unavailable:" + r.Reason,
		Excerpts: rr.evidence(r), NotChecked: []string{r.Detail, notCheckedRuntimes}}
}

// none is the host-level outcome when no package of the product is installed:
// a disproof only of that narrow claim, never of "no vulnerable PHP on this
// host", and only on a distribution whose package names the reads cover and
// from reads that were whole.
func (rr runtimeRead) none(what string) Outcome {
	from := rr.read[0]
	covered := false
	for _, c := range rr.read {
		manager := "dpkg"
		if c == checkRpmRuntimes {
			manager = "rpm"
		}
		if advisory.Covers(rr.osr, manager) {
			covered, from = true, c
			break
		}
	}
	cited := Excerpt{from, "no " + what + " is installed according to the package database"}
	if !covered {
		distro := "not identified (os-release was not read)"
		if id := rr.osr["id"]; id != "" {
			distro = id
		}
		return Outcome{Verdict: Abstained, Reason: reasonDistribution, Excerpts: []Excerpt{cited},
			NotChecked: []string{"scheck reads the package names of Debian, Ubuntu, the Red Hat family and Fedora; this host is " + distro +
				", so a package under another name would not have been seen", notCheckedRuntimes}}
	}
	return rr.settle(Outcome{Verdict: Disproved, Excerpts: []Excerpt{cited}, NotChecked: []string{notCheckedRuntimes}})
}

// phpFixMissing is R7, php.fix_missing: an installed PHP web package that is
// below the fix of the source it came from (docs/spec/engagement.md, R7).
func phpFixMissing(v *View) []Outcome {
	rr, abstain := readRuntimes(v)
	if abstain != nil {
		return []Outcome{*abstain}
	}
	var out []Outcome
	var web *webServing
	for _, r := range rr.a.Runtimes {
		if r.Product != advisory.PHP {
			continue
		}
		o := Outcome{Subject: runtimeSubject(r), Excerpts: rr.evidence(r), NotChecked: []string{notCheckedRuntimes}}
		switch r.Status {
		case advisory.Affected:
			if web == nil {
				w := servesWeb(v)
				web = &w
			}
			o.Verdict, o.Why = Fired, r.Detail
			if r.Component == advisory.ApacheModule {
				o.Why += " " + whyModPHP
			}
			o.Why += " " + web.why
			o.Excerpts = append(o.Excerpts, web.excerpts...)
			o.NotChecked = append(o.NotChecked, web.notChecked...)
			if web.serves {
				o.Attributes = []finding.Attribute{{Name: "serves_web", Ref: finding.Ref{Observation: checkListeners, Excerpt: web.cite}}}
			}
		case advisory.Fixed:
			o.Verdict, o.Why = Disproved, r.Detail
			o = rr.settle(o)
		default:
			o = rr.unknownOutcome(r)
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		if o, found := phpWithoutPackage(v); found {
			return []Outcome{o}
		}
		o := rr.none("PHP web package (FPM, CGI or the Apache module)")
		o.NotChecked = append(o.NotChecked, "a PHP that runs from outside the package databases is looked for only among the listening sockets, and only when they are read with sudo")
		out = append(out, o)
	}
	return out
}

// phpWithoutPackage is the abstention when a PHP program listens on a host
// whose package databases show no PHP: it is installed some way scheck does
// not read, so its version was not read.
func phpWithoutPackage(v *View) (Outcome, bool) {
	l, abstain := readListening(v)
	if abstain != nil {
		return Outcome{}, false
	}
	for _, g := range l.groups {
		for _, li := range g.all {
			if strings.HasPrefix(li.process, "php-fpm") || strings.HasPrefix(li.process, "php-cgi") || li.process == "frankenphp" {
				return Outcome{Verdict: Abstained, Reason: reasonPHPNoPackage,
					Subject:    finding.Subject{Kind: "package", Key: li.process, Label: li.process},
					Excerpts:   []Excerpt{cited([]listener{li})},
					NotChecked: []string{li.process + " listens on this host, but no package of PHP was found, so its version was not read", notCheckedRuntimes}}, true
			}
		}
	}
	return Outcome{}, false
}

// webServing is what R7 learned of a web server in front of PHP.
type webServing struct {
	serves     bool
	why        string
	cite       string
	excerpts   []Excerpt
	notChecked []string
}

// hostPort is a listener's address and port as a person writes them.
func hostPort(l listener) string {
	addr := l.address
	if strings.Contains(addr, ":") {
		addr = "[" + addr + "]"
	}
	return addr + ":" + strconv.Itoa(l.port) + "/" + l.proto
}

// servesWeb reads the listeners and the host firewall for a web server
// reachable beyond localhost: the raise of attribute serves_web. When
// either cannot be read, the finding stands at its base and says so.
func servesWeb(v *View) webServing {
	l, abstain := readListening(v)
	if abstain != nil {
		return webServing{why: "Whether a web server on this host is reachable was not established (the listening sockets could not be read), so this is rated at its base.",
			notChecked: abstain.NotChecked}
	}
	fr := newFirewallReader(v)
	var w webServing
	var doubt []string
	container := ""
	for _, g := range l.groups {
		var hits []listener
		for _, li := range g.beyond() {
			if isWebServer(li.process) {
				hits = append(hits, li)
			} else if reason, _ := ownerDoubt(li); reason != "" && container == "" {
				container = li.process + " publishes " + hostPort(li)
			}
		}
		if len(hits) == 0 {
			continue
		}
		r := fr.reach(hits)
		switch {
		case r.open != nil:
			if !w.serves {
				open := r.inOpen(hits)
				if len(open) == 0 {
					open = hits
				}
				w.serves = true
				w.cite = cited(open).Text
				w.why = open[0].process + " listens on " + hostPort(open[0]) + " and the host firewall lets any address in, " +
					"so PHP on this host is reachable by whoever reaches that web server, if it passes requests to PHP."
				w.excerpts = append(w.excerpts, cited(open))
				w.excerpts = append(w.excerpts, r.open.excerpts...)
				w.notChecked = append(w.notChecked, r.open.notChecked)
			}
		case r.unknown != nil:
			doubt = append(doubt, r.unknown.detail)
		}
	}
	if w.serves {
		return w
	}
	w.why = "scheck did not see a web server on this host reachable beyond localhost, so this is rated at its base."
	if len(doubt) > 0 {
		w.why = "Whether the host firewall lets a web server on this host be reached was not established, so this is rated at its base."
		w.notChecked = append(w.notChecked, doubt[0])
	}
	if container != "" {
		w.why = container + ", a container: what it serves, and any PHP or Node.js inside it, was not read. " + w.why
	}
	if !l.complete {
		w.notChecked = append(w.notChecked, "some listeners' owners are not shown to a read without sudo, so a web server on another port could not be ruled out")
	}
	return w
}

// nodeRuntimes are the Node.js packages of the assessment.
func nodeRuntimes(a advisory.Assessment) []advisory.Runtime {
	var out []advisory.Runtime
	for _, r := range a.Runtimes {
		if r.Product == advisory.Node {
			out = append(out, r)
		}
	}
	return out
}

// nodeNotChecked is a Node.js judgment's own not-checked lines.
func nodeNotChecked(r advisory.Runtime) []string {
	out := []string{notCheckedRuntimes}
	if (r.ViaBrotli || r.Reason == advisory.ReasonDistroNode) && strings.HasPrefix(r.Source, "Debian") {
		out = append(out, "Debian had not published fixes for the other nine flaws of this release as of "+advisory.TableVersion)
	}
	return out
}

// nodeFixMissing is R8, node.fix_missing.
func nodeFixMissing(v *View) []Outcome {
	rr, abstain := readRuntimes(v)
	if abstain != nil {
		return []Outcome{*abstain}
	}
	var out []Outcome
	for _, r := range nodeRuntimes(rr.a) {
		o := Outcome{Subject: runtimeSubject(r), Excerpts: rr.evidence(r), NotChecked: nodeNotChecked(r)}
		switch r.Status {
		case advisory.Affected:
			o.Verdict, o.Why = Fired, r.Detail
		case advisory.Fixed:
			o.Verdict, o.Why = Disproved, r.Detail
			o = rr.settle(o)
		case advisory.EOL:
			o.Verdict, o.Reason = Abstained, reasonLineUnsupported
			o.NotChecked = append([]string{"the Node.js project publishes no fix for the " + r.Line + " line, so there is no fix to be missing; see node.line_unsupported"}, o.NotChecked...)
		default:
			o = rr.unknownOutcome(r)
			o.NotChecked = append([]string{r.Detail}, nodeNotChecked(r)...)
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		out = append(out, rr.none("Node.js package (nodejs)"))
	}
	return out
}

// nodeLineUnsupported is R9, node.line_unsupported: a Node.js build that
// tracks its project, on a line the project no longer fixes. A line the
// table holds a fix for is supported until its date, which is compared with
// the time the packages were read, never the time of the report.
func nodeLineUnsupported(v *View) []Outcome {
	rr, abstain := readRuntimes(v)
	if abstain != nil {
		return []Outcome{*abstain}
	}
	var out []Outcome
	for _, r := range nodeRuntimes(rr.a) {
		o := Outcome{Subject: runtimeSubject(r), Excerpts: rr.evidence(r), NotChecked: nodeNotChecked(r)}
		switch {
		case r.Status == advisory.EOL:
			o.Verdict, o.Why = Fired, r.Detail
		case r.Distro:
			o.Verdict, o.Reason = Abstained, reasonDistroPackage
			o.NotChecked = append([]string{r.Package + " " + r.Version + " is a " + r.Source + " package: its fixes come from the distribution, and scheck does not know whether the distribution still supports this line"}, o.NotChecked...)
		case r.Status == advisory.Affected || r.Status == advisory.Fixed:
			o = rr.settle(lineSupport(v, r, o))
		default:
			o = rr.unknownOutcome(r)
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		out = append(out, rr.none("Node.js package (nodejs)"))
	}
	return out
}

// lineSupport judges a line the table holds a fix for against the date its
// support ends, at the time the host was read.
func lineSupport(v *View, r advisory.Runtime, o Outcome) Outcome {
	supported := "Node.js " + r.Version + " is on the " + r.Line + " line, which the Node.js project still fixes"
	if r.EOLDate == "" {
		o.Verdict, o.Why = Disproved, supported+"."
		return o
	}
	times := v.Collected()
	if len(times) == 0 || slices.ContainsFunc(times, time.Time.IsZero) {
		o.Verdict, o.Reason = Abstained, finding.ReasonNoCollectionTime
		o.NotChecked = append([]string{"the line's support ends on " + r.EOLDate + ", and the time the packages were read was not recorded"}, o.NotChecked...)
		return o
	}
	switch finding.LeftAt(r.EOLDate, time.UTC, times) {
	case finding.LeftNotPassed:
		o.Verdict, o.Why = Disproved, supported+" until "+r.EOLDate+"."
	case finding.LeftPassed:
		o.Verdict = Fired
		o.Why = "Node.js " + r.Version + " is on the " + r.Line + " line, whose support from the Node.js project ended on " + r.EOLDate +
			". Its releases no longer receive security fixes, and the project says end-of-life versions are always affected by later flaws."
	default:
		o.Verdict, o.Reason = Abstained, reasonEOLWithin
		o.NotChecked = append([]string{"the line's support ends on " + r.EOLDate + ", between the first and the last read of this host"}, o.NotChecked...)
	}
	return o
}
