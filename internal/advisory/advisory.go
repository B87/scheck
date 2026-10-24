// Package advisory is the dated table of named runtime disclosures the host
// collector judges PHP and Node.js packages against, and the one place that
// decides what an installed package version means (docs/spec/host-collector.md
// §1 and §11, G8). It reads package records that were already collected and
// runs nothing; callers get a status per installed runtime package and the
// sentence that says why, and know nothing of version orderings, package
// sources or backports.
//
// The table is not a vulnerability database. It holds the October 2026 PHP
// and Node.js releases, with, for each distribution, either a verified fixed
// package or no row at all; a version below a number that a distribution
// backports is never judged by that number.
package advisory

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// Product is the runtime a package belongs to.
type Product string

// The products.
const (
	PHP  Product = "php"
	Node Product = "node"
)

// Component is what a PHP package is: the part that serves requests.
type Component string

// The components. PHPPackage is an RPM named php, which may carry the Apache
// module or only a command line binary depending on the distribution.
const (
	FPM          Component = "fpm"
	CGI          Component = "cgi"
	ApacheModule Component = "apache_module"
	PHPPackage   Component = "php_package"
	NodeRuntime  Component = "node"
)

// Status is what an installed package's version means against the table.
type Status string

// The statuses. Affected and EOL are findings; Fixed is a disproof of that
// package alone; Unknown is neither safe nor unsafe.
const (
	// Affected: below the fix of the source it came from.
	Affected Status = "affected"
	// Fixed: at or above the fix of the same source.
	Fixed Status = "fixed"
	// EOL: a line its project no longer fixes, from a source that tracks the
	// project (Node.js 20 from NodeSource, for one).
	EOL Status = "eol"
	// Unknown: the table cannot say, for the Reason.
	Unknown Status = "unknown"
)

// The reasons a status is Unknown (the rules prefix them "unavailable:").
const (
	// ReasonBackport: the distribution is recognized but the table has no
	// fixed package of it; a version below a number proves nothing.
	ReasonBackport = "backport_unknown"
	// ReasonSource: the package came from a source scheck does not recognize.
	ReasonSource = "source_unrecognized"
	// ReasonUnnumbered: a line whose fix was published without a new version.
	ReasonUnnumbered = "unnumbered_backport"
	// ReasonBrotli: a distribution Node.js whose Brotli library was not read.
	ReasonBrotli = "brotli_unread"
	// ReasonDistroNode: the Brotli library is fixed, and the distribution has
	// published nothing for the other flaws of the Node.js release.
	ReasonDistroNode = "distro_node_unfixed"
	// ReasonOS: os-release was not read, so the distribution is not known.
	ReasonOS = "os_release"
)

// Runtime is one installed PHP or Node.js package and what the table says
// of it.
type Runtime struct {
	Product   Product
	Component Component
	// Package and Version are as the package manager printed them; Manager is
	// "dpkg" or "rpm".
	Package, Version, Manager string
	// Line is the release line, "8.3" or "22".
	Line   string
	Status Status
	Reason string
	// Source is where the package came from, as the report names it
	// ("Ubuntu 24.04", "deb.sury.org", "NodeSource"); "" when unrecognized.
	Source string
	// Distro says the source is a distribution that backports fixes, whose
	// own support decides what a line is.
	Distro bool
	// FixedIn is the version the package is compared with (a package version
	// for a distribution, an upstream version otherwise); Ref the
	// distribution's advisory; Pro that the fix is only published through a
	// paid subscription.
	FixedIn, Ref string
	Pro          bool
	// ViaBrotli says the judgment rests on the Brotli library package a
	// Node.js links, not on Node.js itself.
	ViaBrotli bool
	// EOLDate is the end-of-life date of the line, when the table has it.
	EOLDate string
	// Detail is the sentence that says what the status means for this
	// package; Excerpt the package as the report cites it.
	Detail, Excerpt string
}

// Assessment is every PHP and Node.js package found in the reads.
type Assessment struct {
	Runtimes []Runtime
	// Partial says a read was cut short or had a line it did not understand:
	// it can show a package, never that none is installed.
	Partial bool
}

// The os-release keys, as check's key-value parser lowercases them.
const (
	osID        = "id"
	osVersionID = "version_id"
)

type pkg struct{ name, version, manager string }

// Assess reads the package records of the dpkg and rpm checks, with
// os-release (nil when it was not read), and judges every PHP web package
// and Node.js runtime installed. Only packages in the installed state count (a held
// package is installed; a half-configured one makes its read partial).
func Assess(osRelease map[string]string, reads ...check.Records) Assessment {
	var a Assessment
	var pkgs []pkg
	for _, r := range reads {
		a.Partial = a.Partial || r.Partial
		for _, rec := range r.Items {
			if rec[check.FieldStatus] != check.PackageInstalled {
				continue
			}
			pkgs = append(pkgs, pkg{rec[check.FieldName], rec[check.FieldVersion], rec[check.FieldManager]})
		}
	}
	for _, p := range pkgs {
		if comp, line, ok := phpPackage(p); ok {
			a.Runtimes = append(a.Runtimes, assessPHP(p, comp, line, osRelease))
		} else if p.name == "nodejs" {
			a.Runtimes = append(a.Runtimes, assessNode(p, pkgs, osRelease))
		}
	}
	return a
}

// phpPackage recognizes a PHP package that serves requests, by name: the
// dpkg names carry the line, an RPM's line is its version's.
func phpPackage(p pkg) (Component, string, bool) {
	if p.manager == "rpm" {
		var c Component
		switch p.name {
		case "php":
			c = PHPPackage
		case "php-fpm":
			c = FPM
		case "php-cgi":
			c = CGI
		default:
			return "", "", false
		}
		core, ok := upstreamCore(p.version)
		if !ok || len(core) < 2 {
			return "", "", false
		}
		return c, fmt.Sprintf("%d.%d", core[0], core[1]), true
	}
	for _, line := range check.PHPLines {
		switch p.name {
		case "php" + line + "-fpm":
			return FPM, line, true
		case "php" + line + "-cgi":
			return CGI, line, true
		case "libapache2-mod-php" + line:
			return ApacheModule, line, true
		}
	}
	return "", "", false
}

// source is where a package came from.
type source int

const (
	srcOther source = iota
	srcSury
	srcRemi
	srcNodeSource
	srcDebian
	srcUbuntu
	srcRPMDist
)

var (
	// A Debian package of the distribution: upstream, revision, and at most
	// the security suffix. Anything else in the version is a third party's.
	debianVersion = regexp.MustCompile(`^(\d+:)?\d+(\.\d+)*([+~]dfsg\d*)?-\d+(\.\d+)?([+~]deb\d+u\d+)?(\+b\d+)?$`)
	// An Ubuntu package of the distribution: upstream, an ubuntu revision,
	// and at most the extended-security suffix. A PPA build or a vendor
	// repository's package that merely mentions ubuntu does not match.
	ubuntuVersion = regexp.MustCompile(`^(\d+:)?\d+(\.\d+)*([+~]dfsg\d*)?-\d+((ubuntu|build|maysync)[\d.]+)+(\+esm\d+)?$`)
	rpmDistro     = regexp.MustCompile(`[.+](el\d+|fc\d+|amzn\d*)`)
)

func sourceOf(p pkg, osr map[string]string) (source, string) {
	lv := strings.ToLower(p.version)
	switch {
	case strings.Contains(lv, "sury"), strings.Contains(lv, ".gbp") && (strings.Contains(lv, "+debian") || strings.Contains(lv, "+ubuntu")):
		return srcSury, "deb.sury.org"
	case strings.Contains(lv, "nodesource"), strings.Contains(lv, "nsolid"):
		return srcNodeSource, "NodeSource"
	case strings.Contains(lv, ".remi"):
		return srcRemi, "Remi's repository"
	case p.manager == "rpm":
		if name, ok := rpmDistros[osr[osID]]; ok && rpmDistro.MatchString(lv) {
			return srcRPMDist, name
		}
	case osr[osID] == "ubuntu" && ubuntuVersion.MatchString(p.version):
		return srcUbuntu, strings.TrimSpace("Ubuntu " + osr[osVersionID])
	case osr[osID] == "debian" && debianVersion.MatchString(p.version):
		return srcDebian, strings.TrimSpace("Debian " + osr[osVersionID])
	}
	return srcOther, ""
}

func excerpt(p pkg) string { return p.name + " " + p.version + " (" + p.manager + ")" }

func newRuntime(p pkg, prod Product, comp Component, line string) Runtime {
	return Runtime{Product: prod, Component: comp, Package: p.name, Version: p.version, Manager: p.manager,
		Line: line, Excerpt: excerpt(p)}
}

// unnumberedLines are the PHP lines whose fix the project published without
// a new version number.
var unnumberedLines = []string{"7.4", "8.0", "8.1"}

func findRow(rows []distroRow, osr map[string]string, line string) (distroRow, bool) {
	for _, r := range rows {
		if r.os == osr[osID] && r.version == osr[osVersionID] && r.line == line {
			return r, true
		}
	}
	return distroRow{}, false
}

func assessPHP(p pkg, comp Component, line string, osr map[string]string) Runtime {
	r := newRuntime(p, PHP, comp, line)
	src, label := sourceOf(p, osr)
	r.Source = label
	unknown := func(reason, detail string) Runtime {
		r.Status, r.Reason, r.Detail = Unknown, reason, detail
		return r
	}
	switch src {
	case srcSury, srcRemi:
		fixed, ok := phpFixed[line]
		if !ok {
			if !slices.Contains(unnumberedLines, line) {
				return unknown(ReasonBackport, fmt.Sprintf("%s %s is on PHP %s, a line the PHP project stopped fixing long before this release; scheck's table has no fixed version for it, so it cannot be judged by its number.", p.name, p.version, line))
			}
			if src == srcSury {
				return unknown(ReasonUnnumbered, fmt.Sprintf("%s comes from deb.sury.org, which patched PHP 7.4 to 8.1 without new version numbers, so the version cannot say whether the fix is in. Check its changelog for an entry on or after 21 October 2026: zless /usr/share/doc/%s/changelog.Debian.gz",
					p.name, p.name))
			}
			return unknown(ReasonUnnumbered, fmt.Sprintf("%s %s is on a line the PHP project fixed without a new version number, so the version cannot say whether the fix is in.", p.name, p.version))
		}
		core, _ := upstreamCore(p.version)
		want, _ := upstreamCore(fixed)
		r.FixedIn = fixed
		if compareCore(core, want) < 0 {
			r.Status = Affected
			r.Detail = fmt.Sprintf("%s %s from %s is below %s, the first PHP %s release that fixes %s.", p.name, p.version, label, fixed, line, PHPAdvisory)
		} else {
			r.Status = Fixed
			r.Detail = fmt.Sprintf("%s %s from %s is at or above %s, the first PHP %s release that fixes %s.", p.name, p.version, label, fixed, line, PHPAdvisory)
		}
		return r
	case srcDebian, srcUbuntu:
		row, ok := findRow(phpRows, osr, line)
		if !ok {
			return unknown(ReasonBackport, fmt.Sprintf("%s %s is a %s package, and scheck's table (%s) has no %s package of PHP %s that fixes these CVEs, so its version cannot be judged. Check the distribution's page for CVE-2026-109618.",
				p.name, p.version, label, TableVersion, label, line))
		}
		r.FixedIn, r.Ref, r.Pro = row.fixed, row.ref, row.pro
		if compareDpkg(p.version, row.fixed) < 0 {
			r.Status = Affected
			r.Detail = fmt.Sprintf("%s %s is below %s, the first %s package that fixes %s.", p.name, p.version, row.fixed, row.name, PHPAdvisory)
			if row.pro {
				r.Detail += " This fix is published only through Ubuntu Pro."
			}
		} else {
			r.Status = Fixed
			r.Detail = fmt.Sprintf("%s %s is at or above %s, the first %s package that fixes %s.", p.name, p.version, row.fixed, row.name, PHPAdvisory)
		}
		return r
	case srcRPMDist:
		r.Distro = true
		return unknown(ReasonBackport, fmt.Sprintf("%s backports fixes without changing PHP's version number, so comparing %s with the upstream fix would be wrong, and scheck's table (%s) has no %s package that fixes these CVEs. Check the vendor's page for CVE-2026-109618.",
			label, p.version, TableVersion, label))
	}
	if osr[osID] == "" {
		return unknown(ReasonOS, fmt.Sprintf("%s %s: the operating system was not identified (os-release was not read), so the source of the package cannot be told.", p.name, p.version))
	}
	return unknown(ReasonSource, fmt.Sprintf("%s %s came from a source scheck does not recognize, so whether it carries the fix cannot be told from its version.", p.name, p.version))
}

func assessNode(p pkg, all []pkg, osr map[string]string) Runtime {
	r := newRuntime(p, Node, NodeRuntime, "")
	core, haveCore := upstreamCore(p.version)
	if haveCore {
		r.Line = fmt.Sprint(core[0])
	}
	src, label := sourceOf(p, osr)
	r.Source = label
	unknown := func(reason, detail string) Runtime {
		r.Status, r.Reason, r.Detail = Unknown, reason, detail
		return r
	}
	switch src {
	case srcNodeSource:
		if !haveCore {
			return unknown(ReasonSource, fmt.Sprintf("nodejs %s has a version scheck cannot read.", p.version))
		}
		if core[0] > nodeNewest {
			return unknown(ReasonSource, fmt.Sprintf("Node.js %s is newer than the table (%s) knows, so it was not judged.", p.version, TableVersion))
		}
		if fixed, ok := nodeFixed[r.Line]; ok {
			want, _ := upstreamCore(fixed)
			r.FixedIn = fixed
			if compareCore(core, want) < 0 {
				r.Status = Affected
				r.Detail = fmt.Sprintf("Node.js %s (%s) is below %s, which fixes 10 flaws published on 21 October 2026. The worst, %s, corrupts memory in the Brotli decoder: an application that decompresses Brotli data an attacker supplies (an HTTP client decompressing a response, or a server accepting compressed request bodies) can be crashed or made to run the attacker's code. Others weaken TLS hostname checks and DNS lookups.",
					p.version, label, fixed, NodeBrotliAdvisory)
			} else {
				r.Status = Fixed
				r.Detail = fmt.Sprintf("Node.js %s (%s) is at or above %s, the release of its line that fixes the 10 flaws published on 21 October 2026.", p.version, label, fixed)
			}
			return r
		}
		r.Status = EOL
		r.EOLDate, _ = EOLDate("node", r.Line)
		when := ""
		if r.EOLDate != "" {
			when = " on " + r.EOLDate
		}
		r.Detail = fmt.Sprintf("Node.js %s (%s) is on the %s line, which reached end of life%s. The Node.js project publishes no fix for it: its 21 October 2026 release fixes 22, 24 and 26 only and says end-of-life versions are always affected. Its Brotli decoder flaw is %s.",
			p.version, label, r.Line, when, NodeBrotliAdvisory)
		return r
	case srcDebian, srcUbuntu, srcRPMDist:
		r.Distro = true
		lib, found := brotliOf(all)
		if src != srcDebian {
			if src == srcRPMDist {
				return unknown(ReasonBackport, fmt.Sprintf("%s's nodejs %s: scheck's table (%s) has no %s package that fixes the Node.js flaws or the Brotli library, so its version cannot be judged. Check the vendor's page for CVE-2026-111497.",
					label, p.version, TableVersion, label))
			}
			return unknown(ReasonBackport, fmt.Sprintf("%s's nodejs %s: scheck's table (%s) has no %s package that fixes the Node.js flaws or the Brotli library, so its version cannot be judged. Check the distribution's page for CVE-2026-111497.",
				label, p.version, TableVersion, label))
		}
		if !found {
			return unknown(ReasonBrotli, fmt.Sprintf("nodejs %s decompresses Brotli through the system library, and the library's package was not found, so it cannot be judged.", p.version))
		}
		row, ok := findRow(brotliRows, osr, "")
		if !ok {
			return unknown(ReasonBackport, fmt.Sprintf("nodejs %s decompresses Brotli through the system library, and scheck's table (%s) has no %s package of it that fixes %s.",
				p.version, TableVersion, label, NodeBrotliAdvisory))
		}
		r.FixedIn, r.Ref = row.fixed, row.ref
		if compareDpkg(lib.version, row.fixed) < 0 {
			r.Status = Affected
			r.ViaBrotli = true
			r.Detail = fmt.Sprintf("nodejs %s decompresses Brotli through the system library, and libbrotli1 %s is below %s, %s's fix for %s. Updating nodejs does not fix this; updating the Brotli library and restarting your Node processes does.",
				p.version, lib.version, row.fixed, row.name, NodeBrotliAdvisory)
			return r
		}
		return unknown(ReasonDistroNode, fmt.Sprintf("nodejs %s decompresses Brotli through the system library, and libbrotli1 %s is at or above %s, %s's fix for %s; %s had published no fix for the other nine flaws of this release as of %s, so the package is not shown fixed.",
			p.version, lib.version, row.fixed, row.name, NodeBrotliAdvisory, label, TableVersion))
	}
	if osr[osID] == "" {
		return unknown(ReasonOS, fmt.Sprintf("nodejs %s: the operating system was not identified (os-release was not read), so the source of the package cannot be told.", p.version))
	}
	return unknown(ReasonSource, fmt.Sprintf("nodejs %s came from a source scheck does not recognize, so whether it carries the fixes cannot be told from its version.", p.version))
}

// brotliOf is the Brotli library package a distribution's Node.js links.
func brotliOf(all []pkg) (pkg, bool) {
	for _, p := range all {
		if p.manager == "dpkg" && p.name == "libbrotli1" {
			return p, true
		}
	}
	return pkg{}, false
}

// Recognizes says whether the table knows what a package name is: a PHP web
// package, Node.js, or the Brotli library it links. The catalog test uses it
// to keep the reads and the table the same list.
func Recognizes(name string) bool {
	switch name {
	case "nodejs", "libbrotli1", "brotli", "libbrotli", "rpm":
		return true
	}
	if _, _, ok := phpPackage(pkg{name, "8.2.0", "dpkg"}); ok {
		return true
	}
	_, _, ok := phpPackage(pkg{name, "8.2.0-1", "rpm"})
	return ok
}
