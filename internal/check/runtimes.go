package check

import (
	"slices"
	"strings"
)

// PHPLines are the PHP release lines whose web packages the runtime reads
// look for, by exact name (docs/spec/host-collector.md §3, G8): the catalog
// admits no glob, so each package is its own argv token. 5.6 to 8.5 covers
// every line a distribution or a third-party repository has packaged.
var PHPLines = []string{"5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"}

// DpkgRuntimeArgv is dpkg-query -s over the PHP web packages of every line
// (FPM, CGI, the Apache module) and the Node.js runtime with the Brotli
// library it links. -s prints one field per line (Package, Status, Version),
// which no terminal width cuts, unlike the columns of -l. The command is a
// query on the package database: it never runs the runtime itself.
func DpkgRuntimeArgv() []string {
	argv := []string{"dpkg-query", "-s"}
	for _, l := range PHPLines {
		argv = append(argv, "php"+l+"-fpm", "php"+l+"-cgi", "libapache2-mod-php"+l)
	}
	return append(argv, "nodejs", "libbrotli1")
}

// RpmRuntimeArgv is rpm -q over the same families by their RPM names. A
// package that is not installed answers "package X is not installed". The
// first name is rpm itself, which every host with an rpm database has: when
// the database cannot be opened rpm prints the same sentence for every name
// and exits like a host with none of them, so the read counts only when rpm
// finds itself (parsePackages).
func RpmRuntimeArgv() []string {
	return []string{"rpm", "-q", "rpm", "php", "php-fpm", "php-cgi", "nodejs", "brotli", "libbrotli"}
}

// RuntimePackageNames are every package name the two reads ask about, for the
// test that pins the advisory table's name parsing to the catalog.
func RuntimePackageNames() []string {
	var out []string
	out = append(out, DpkgRuntimeArgv()[2:]...)
	out = append(out, RpmRuntimeArgv()[2:]...)
	return out
}

// The states of a packages record (the third word of dpkg's Status field;
// an rpm record is always installed). Only PackageInstalled counts as a
// package that is there; the half-installed states make the read partial,
// since such a package may be a vulnerable one that is held or interrupted.
const (
	PackageInstalled   = "installed"
	packageConfigFiles = "config-files"
	packageNotInst     = "not-installed"
)

// parsePackages reads `dpkg-query -s` (stanzas of Package, Status and
// Version fields) or `rpm -q` (name-version-release.arch) into package
// records. A package that is not installed answers on stderr or with a
// sentence and has no record; that is not an unparsed line. A field that
// holds a redaction or truncation marker makes its record unparsed, since
// part of a version proves nothing; when the output was cut, the last record
// is dropped and counted unparsed, since the cut may have fallen inside it.
func parsePackages(bin string, lines []string, cut bool) ([]Record, int) {
	out, bad := []Record{}, 0
	if bin == "rpm" {
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "package ") && strings.HasSuffix(l, " is not installed") {
				continue
			}
			// name-version-release.arch: the last two dashes split it.
			i := strings.LastIndex(l, "-")
			if i <= 0 || strings.ContainsAny(l, " \t") || hasMarker(l) {
				bad++
				continue
			}
			j := strings.LastIndex(l[:i], "-")
			if j <= 0 {
				bad++
				continue
			}
			rel := l[i+1:]
			if k := strings.LastIndex(rel, "."); k > 0 {
				rel = rel[:k]
			}
			out = append(out, Record{FieldName: l[:j], FieldVersion: l[j+1:i] + "-" + rel, FieldStatus: PackageInstalled, FieldManager: "rpm"})
		}
		if cut && len(out) > 0 {
			out, bad = out[:len(out)-1], bad+1
		}
		// rpm finds itself in any database it could open.
		if !slices.ContainsFunc(out, func(r Record) bool { return r[FieldName] == "rpm" }) {
			bad++
		}
		return out, bad
	}
	// dpkg-query -s: a stanza per package, fields "Name: value"; a line that
	// starts with a space continues the previous field and is ignored.
	var name, status, version string
	flush := func() {
		defer func() { name, status, version = "", "", "" }()
		if name == "" && status == "" && version == "" {
			return
		}
		st := dpkgState(status)
		// A package that is gone leaves a stanza with no version: not there.
		if st == packageConfigFiles || st == packageNotInst {
			return
		}
		if name == "" || version == "" || st == "" || hasMarker(name) || hasMarker(version) || hasMarker(status) {
			bad++
			return
		}
		if st != PackageInstalled {
			bad++ // half-installed, half-configured, unpacked, triggers: present, not settled
		}
		out = append(out, Record{FieldName: name, FieldVersion: version, FieldStatus: st, FieldManager: "dpkg"})
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		key, val, ok := strings.Cut(l, ": ")
		if !ok {
			if strings.HasPrefix(l, "dpkg-query:") {
				continue // stderr: no information is available for a package
			}
			key, val, ok = strings.Cut(l, ":")
			if !ok {
				bad++
				continue
			}
		}
		switch key {
		case "Package":
			flush()
			name = strings.TrimSpace(val)
		case "Status":
			status = strings.TrimSpace(val)
		case "Version":
			version = strings.TrimSpace(val)
		}
	}
	if cut {
		// The cut may have fallen inside the stanza still open (or inside
		// the last record): that one is not a record.
		switch {
		case name != "" || status != "" || version != "":
			name, status, version = "", "", ""
		case len(out) > 0:
			out = out[:len(out)-1]
		}
		bad++
	}
	flush()
	return out, bad
}

// dpkgState is the state word of a Status field ("install ok installed"
// is installed; "hold ok installed" too), or "" for a field of another
// shape.
func dpkgState(status string) string {
	f := strings.Fields(status)
	if len(f) != 3 {
		return ""
	}
	return f[2]
}
