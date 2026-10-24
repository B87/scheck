package check

import (
	"strings"
	"testing"
)

func pkgCheck(bin string) Check {
	return Check{ID: "pkg.test", Parser: ParsePackages, Argv: []string{bin, "-s"}}
}

func TestParsePackagesDpkg(t *testing.T) {
	raw := `Package: php8.3-fpm
Status: install ok installed
Priority: optional
Section: php
Installed-Size: 5000
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: arm64
Version: 8.3.6-0ubuntu0.24.04.13
Depends: libc6
Description: server-side, HTML-embedded scripting language (FPM-CGI binary)
 Package: not-a-record
 Version: 9.9.9
Conffiles:
 /etc/php/8.3/fpm/php-fpm.conf abc

Package: php8.1-fpm
Status: deinstall ok config-files
Version: 8.1.2-1ubuntu2.14
Architecture: amd64

Package: nodejs
Status: hold ok installed
Version: 18.19.1+dfsg-6ubuntu5
Architecture: amd64
`
	recs, err := Parse(pkgCheck("dpkg-query"), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	r := recs.(Records)
	if r.Partial || len(r.Items) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Items[0][FieldName] != "php8.3-fpm" || r.Items[0][FieldVersion] != "8.3.6-0ubuntu0.24.04.13" || r.Items[0][FieldStatus] != PackageInstalled || r.Items[0][FieldManager] != "dpkg" {
		t.Errorf("%+v", r.Items[0])
	}
	// A held package is installed.
	if r.Items[1][FieldName] != "nodejs" || r.Items[1][FieldStatus] != PackageInstalled {
		t.Errorf("%+v", r.Items)
	}
	if s := Summary(pkgCheck("dpkg-query"), r); s != "2 installed packages" {
		t.Errorf("summary %q", s)
	}
}

// A package that is half installed, or interrupted, is there: it is kept and
// the read is partial, so nothing is disproved from it.
func TestParsePackagesHalfInstalledIsPartial(t *testing.T) {
	for _, st := range []string{"install ok half-configured", "install ok unpacked", "install ok half-installed", "install ok triggers-pending"} {
		recs, _ := Parse(pkgCheck("dpkg-query"), []byte("Package: php8.3-fpm\nStatus: "+st+"\nVersion: 8.3.6-0ubuntu0.24.04.9\n"))
		if r := recs.(Records); !r.Partial || len(r.Items) != 1 || r.Items[0][FieldStatus] == PackageInstalled {
			t.Errorf("%s: %+v", st, r)
		}
	}
}

func TestParsePackagesMarkerInAFieldIsUnparsed(t *testing.T) {
	recs, _ := Parse(pkgCheck("dpkg-query"), []byte("Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.12-1+ubuntu24.04.1+deb.[REDACTED:extra:4 bytes].org+1\n"))
	if r := recs.(Records); !r.Partial || len(r.Items) != 0 {
		t.Errorf("dpkg: %+v", r)
	}
	recs, _ = Parse(pkgCheck("rpm"), []byte("php-fpm-8.2.[REDACTED:extra:4 bytes]-1.el9.x86_64\n"))
	if r := recs.(Records); !r.Partial || len(r.Items) != 0 {
		t.Errorf("rpm: %+v", r)
	}
}

func TestParsePackagesRpm(t *testing.T) {
	raw := "php-8.2.13-1.el9.x86_64\nphp-fpm-8.2.13-1.el9.x86_64\npackage php-cgi is not installed\nnodejs-20.11.1-1nodesource.x86_64\n"
	recs, err := Parse(pkgCheck("rpm"), []byte("rpm-4.19.1-1.el9.x86_64\n"+raw))
	if err != nil {
		t.Fatal(err)
	}
	r := recs.(Records)
	r.Items = r.Items[1:]
	if r.Partial || len(r.Items) != 3 {
		t.Fatalf("%+v", r)
	}
	if r.Items[1][FieldName] != "php-fpm" || r.Items[1][FieldVersion] != "8.2.13-1.el9" || r.Items[1][FieldManager] != "rpm" {
		t.Errorf("%+v", r.Items[1])
	}
	if r.Items[2][FieldName] != "nodejs" || r.Items[2][FieldVersion] != "20.11.1-1nodesource" {
		t.Errorf("%+v", r.Items[2])
	}
}

func TestParsePackagesUnrecognisedLineIsPartial(t *testing.T) {
	recs, err := Parse(pkgCheck("rpm"), []byte("garbage\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := recs.(Records); !r.Partial || len(r.Items) != 0 {
		t.Errorf("%+v", r)
	}
	recs, _ = Parse(pkgCheck("dpkg-query"), []byte("Package: php8.3-fpm\nStatus: install ok installed\n"))
	if r := recs.(Records); !r.Partial {
		t.Errorf("dpkg stanza without a version: %+v", r)
	}
}

// The argv carries exact names only: no glob, no format string.
func TestRuntimeArgvIsExactNames(t *testing.T) {
	for _, argv := range [][]string{DpkgRuntimeArgv(), RpmRuntimeArgv()} {
		for _, tok := range argv {
			if strings.ContainsAny(tok, "*?[]${}") {
				t.Errorf("%q", tok)
			}
		}
	}
	if len(RuntimePackageNames()) == 0 {
		t.Error("no names")
	}
}

// A purged package leaves a stanza with no version: it is not there, and the
// read is whole.
func TestParsePackagesPurgedIsNotPartial(t *testing.T) {
	recs, _ := Parse(pkgCheck("dpkg-query"), []byte("Package: php8.1-fpm\nStatus: purge ok not-installed\nArchitecture: amd64\n\nPackage: nodejs\nStatus: install ok installed\nVersion: 18.19.1+dfsg-6ubuntu5\n"))
	if r := recs.(Records); r.Partial || len(r.Items) != 1 || r.Items[0][FieldName] != "nodejs" {
		t.Errorf("%+v", r)
	}
}

// A cut inside the last stanza must not leave a record with a shortened
// version.
func TestParsePackagesCutDropsTheOpenStanza(t *testing.T) {
	raw := "Package: nodejs\nStatus: install ok installed\nVersion: 18.19.1+dfsg-6ubuntu5\n\nPackage: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.6-0ubuntu0.24.04.1\n[TRUNCATED:1000 bytes]\n"
	recs, _ := Parse(pkgCheck("dpkg-query"), []byte(raw))
	r := recs.(Records)
	if !r.Partial || len(r.Items) != 1 || r.Items[0][FieldName] != "nodejs" {
		t.Errorf("%+v", r)
	}
	recs, _ = Parse(pkgCheck("rpm"), []byte("rpm-4.19.1-1.fc40.x86_64\nphp-fpm-8.2.1\n[TRUNCATED:10 bytes]\n"))
	if r := recs.(Records); !r.Partial || len(r.Items) != 1 {
		t.Errorf("rpm: %+v", r)
	}
}

// rpm prints "is not installed" for every name when its database cannot be
// opened, exactly like a host with none of them: only a read that finds rpm
// itself counts as whole.
func TestParsePackagesRpmDatabaseFailureIsPartial(t *testing.T) {
	recs, _ := Parse(pkgCheck("rpm"), []byte("package rpm is not installed\npackage php is not installed\n"))
	if r := recs.(Records); !r.Partial {
		t.Errorf("%+v", r)
	}
	recs, _ = Parse(pkgCheck("rpm"), []byte("rpm-4.19.1-1.fc40.x86_64\npackage php is not installed\n"))
	if r := recs.(Records); r.Partial {
		t.Errorf("%+v", r)
	}
}
