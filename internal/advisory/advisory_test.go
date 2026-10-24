package advisory

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
)

func recs(manager string, lines ...string) check.Records {
	r := check.Records{Kind: check.ParsePackages, Items: []check.Record{}}
	for _, l := range lines {
		f := strings.Fields(l)
		r.Items = append(r.Items, check.Record{check.FieldName: f[0], check.FieldVersion: f[1], check.FieldStatus: check.PackageInstalled, check.FieldManager: manager})
	}
	return r
}

func os(id, version string) map[string]string {
	return map[string]string{"id": id, "version_id": version}
}

func one(t *testing.T, a Assessment) Runtime {
	t.Helper()
	if len(a.Runtimes) != 1 {
		t.Fatalf("%d runtimes: %+v", len(a.Runtimes), a.Runtimes)
	}
	return a.Runtimes[0]
}

func TestPHPStatuses(t *testing.T) {
	cases := []struct {
		name   string
		os     map[string]string
		dpkg   string
		rpm    string
		status Status
		reason string
	}{
		// Ubuntu's fixed package carries upstream 8.3.6: the number is far
		// below 8.3.36 and the package is fixed.
		{"ubuntu 24.04 fixed package", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-0ubuntu0.24.04.13", "", Fixed, ""},
		{"ubuntu 24.04 older package", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-0ubuntu0.24.04.9", "", Affected, ""},
		{"ubuntu 24.04 later package", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-0ubuntu0.24.04.14", "", Fixed, ""},
		{"ubuntu 22.04", os("ubuntu", "22.04"), "php8.1-fpm 8.1.2-1ubuntu2.14", "", Affected, ""},
		{"ubuntu with a line the row does not carry", os("ubuntu", "24.04"), "php8.4-fpm 8.4.1-1ubuntu1", "", Unknown, ReasonBackport},
		{"ubuntu 20.04 needs pro", os("ubuntu", "20.04"), "php7.4-fpm 7.4.3-4ubuntu2.20", "", Affected, ""},
		{"debian 12 below", os("debian", "12"), "php8.2-fpm 8.2.28-1~deb12u1", "", Affected, ""},
		{"debian 12 at the fix", os("debian", "12"), "php8.2-fpm 8.2.35-1~deb12u1", "", Fixed, ""},
		{"debian 12 stock before any update", os("debian", "12"), "php8.2-fpm 8.2.7-1", "", Affected, ""},
		{"debian 11 has no row", os("debian", "11"), "php7.4-fpm 7.4.33-1+deb11u5", "", Unknown, ReasonBackport},
		{"sury 8.3 below upstream", os("ubuntu", "24.04"), "php8.3-fpm 8.3.30-1+ubuntu24.04.1+deb.sury.org+1", "", Affected, ""},
		{"sury 8.3 at upstream", os("debian", "12"), "php8.3-fpm 8.3.36-1+0~20261021.1+debian12~1.gbp1", "", Fixed, ""},
		{"sury 8.1 patched without a number", os("debian", "12"), "php8.1-fpm 8.1.31-1+0~20250101.1+debian12~1.gbp1+deb.sury.org", "", Unknown, ReasonUnnumbered},
		{"debian host with an unrecognized version", os("debian", "12"), "php8.2-fpm 8.2.1-custom1", "", Unknown, ReasonSource},
		{"ubuntu release pocket rebuild", os("ubuntu", "22.04"), "php8.1-fpm 8.1.2-1build1", "", Affected, ""},
		{"ubuntu mid-sync version", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-0maysync1", "", Affected, ""},
		{"debian binNMU", os("debian", "13"), "php8.4-fpm 8.4.11-1+b1", "", Affected, ""},
		{"rhel module build", os("rhel", "9"), "", "php-fpm 8.2.13-1.module+el9.4.0+123+abcd", Unknown, ReasonBackport},
		{"sury on a line the project stopped long ago", os("debian", "12"), "php7.3-fpm 7.3.33-1+0~20250101.1+debian12~1.gbp1+deb.sury.org", "", Unknown, ReasonBackport},
		{"remi on a line the project stopped long ago", os("rhel", "9"), "", "php-fpm 7.0.33-1.el9.remi", Unknown, ReasonBackport},
		{"debian-synced version on ubuntu is not ubuntu's", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-1", "", Unknown, ReasonSource},
		{"no os-release", nil, "php8.2-fpm 8.2.1-1", "", Unknown, ReasonOS},
		{"a PPA build is not Ubuntu's package", os("ubuntu", "24.04"), "php8.3-fpm 8.3.6-1ubuntu1~ppa1", "", Unknown, ReasonSource},
		{"a version cut by a narrow terminal is not Ubuntu's package", os("ubuntu", "24.04"), "php8.3-fpm 8.3.12-1+ubuntu24", "", Unknown, ReasonSource},
		{"a snapshot build is not deb.sury.org", os("debian", "12"), "php8.2-fpm 8.2.20-1~deb12u1~1.gbp123abc", "", Unknown, ReasonSource},
		{"debian testing has no version id", os("debian", ""), "php8.4-fpm 8.4.8-1", "", Unknown, ReasonBackport},
		{"rhel backports", os("rhel", "9"), "", "php-fpm 8.2.13-1.el9", Unknown, ReasonBackport},
		{"fedora backports", os("fedora", "40"), "", "php 8.3.10-1.fc40", Unknown, ReasonBackport},
		{"remi below upstream", os("rhel", "9"), "", "php-fpm 8.3.20-1.el9.remi", Affected, ""},
		{"remi at upstream", os("rhel", "9"), "", "php-fpm 8.4.27-1.el9.remi", Fixed, ""},
		{"rpm of a family not in the list", os("opensuse-leap", "15.5"), "", "php-fpm 8.2.13-1.1", Unknown, ReasonSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reads []check.Records
			if tc.dpkg != "" {
				reads = append(reads, recs("dpkg", tc.dpkg))
			}
			if tc.rpm != "" {
				reads = append(reads, recs("rpm", tc.rpm))
			}
			r := one(t, Assess(tc.os, reads...))
			if r.Status != tc.status || r.Reason != tc.reason {
				t.Errorf("%s %s: %+v", r.Package, r.Version, r)
			}
			if r.Detail == "" || r.Excerpt == "" {
				t.Errorf("no words: %+v", r)
			}
			if r.Status == Affected && r.FixedIn == "" {
				t.Errorf("affected without the fix named: %+v", r)
			}
			if strings.Contains(strings.ToLower(r.Detail), "vulnerable") || strings.Contains(strings.ToLower(r.Detail), "exploited") {
				t.Errorf("claims too much: %s", r.Detail)
			}
		})
	}
}

func TestUbuntuProFixIsSaid(t *testing.T) {
	r := one(t, Assess(os("ubuntu", "20.04"), recs("dpkg", "php7.4-fpm 7.4.3-4ubuntu2.20")))
	if !r.Pro || !strings.Contains(r.Detail, "Ubuntu Pro") {
		t.Errorf("%+v", r)
	}
}

func TestNodeStatuses(t *testing.T) {
	cases := []struct {
		name   string
		os     map[string]string
		dpkg   []string
		rpm    []string
		status Status
		reason string
		brotli bool
	}{
		{"nodesource below", os("ubuntu", "24.04"), []string{"nodejs 22.20.0-1nodesource1"}, nil, Affected, "", false},
		{"nodesource fixed", os("ubuntu", "24.04"), []string{"nodejs 22.23.4-1nodesource1"}, nil, Fixed, "", false},
		{"nodesource 24 below", os("debian", "12"), []string{"nodejs 24.22.0-1nodesource1"}, nil, Affected, "", false},
		{"nodesource 20 is end of life", os("ubuntu", "22.04"), []string{"nodejs 20.11.1-1nodesource1"}, nil, EOL, "", false},
		{"nodesource 25 is end of life", os("ubuntu", "22.04"), []string{"nodejs 25.1.0-1nodesource1"}, nil, EOL, "", false},
		{"nodesource newer than the table", os("ubuntu", "22.04"), []string{"nodejs 28.0.0-1nodesource1"}, nil, Unknown, ReasonSource, false},
		{"debian 12 with an old library", os("debian", "12"), []string{"nodejs 18.20.4+dfsg-1~deb12u1", "libbrotli1 1.0.9-2"}, nil, Affected, "", true},
		{"debian 12 with the fixed library", os("debian", "12"), []string{"nodejs 18.20.4+dfsg-1~deb12u1", "libbrotli1 1.0.9-2+deb12u1"}, nil, Unknown, ReasonDistroNode, false},
		{"debian 13 with an old library", os("debian", "13"), []string{"nodejs 20.19.2+dfsg-1", "libbrotli1 1.1.0-2"}, nil, Affected, "", true},
		{"debian without the library read", os("debian", "12"), []string{"nodejs 18.20.4+dfsg-1~deb12u1"}, nil, Unknown, ReasonBrotli, false},
		{"debian 11 has no brotli row", os("debian", "11"), []string{"nodejs 12.22.12~dfsg-1~deb11u4", "libbrotli1 1.0.9-2"}, nil, Unknown, ReasonBackport, false},
		{"ubuntu has no row", os("ubuntu", "24.04"), []string{"nodejs 18.19.1+dfsg-6ubuntu5", "libbrotli1 1.1.0-2build2"}, nil, Unknown, ReasonBackport, false},
		{"rpm distribution", os("fedora", "40"), nil, []string{"nodejs 20.11.0-1.fc40"}, Unknown, ReasonBackport, false},
		{"unknown source", os("debian", "12"), []string{"nodejs 20.1.0-custom"}, nil, Unknown, ReasonSource, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reads []check.Records
			if len(tc.dpkg) > 0 {
				reads = append(reads, recs("dpkg", tc.dpkg...))
			}
			if len(tc.rpm) > 0 {
				reads = append(reads, recs("rpm", tc.rpm...))
			}
			a := Assess(tc.os, reads...)
			if len(a.Runtimes) != 1 {
				t.Fatalf("%+v", a.Runtimes)
			}
			r := a.Runtimes[0]
			if r.Status != tc.status || r.Reason != tc.reason || r.ViaBrotli != tc.brotli {
				t.Errorf("%+v", r)
			}
			if r.Detail == "" {
				t.Errorf("no words: %+v", r)
			}
		})
	}
}

func TestOnlyInstalledPackagesCount(t *testing.T) {
	r := recs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.9")
	r.Items[0][check.FieldStatus] = "config-files"
	if a := Assess(os("ubuntu", "24.04"), r); len(a.Runtimes) != 0 {
		t.Errorf("a removed package with configuration left counted: %+v", a.Runtimes)
	}
}

func TestPartialReadIsCarried(t *testing.T) {
	r := recs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.9")
	r.Partial = true
	if a := Assess(os("ubuntu", "24.04"), r); !a.Partial || len(a.Runtimes) != 1 {
		t.Errorf("%+v", a)
	}
}

func TestOnlyACLIPackageIsNoSubject(t *testing.T) {
	if a := Assess(os("ubuntu", "24.04"), recs("dpkg", "php8.3-cli 8.3.6-0ubuntu0.24.04.9")); len(a.Runtimes) != 0 {
		t.Errorf("%+v", a.Runtimes)
	}
}

// The reads and the table are one list: every package the catalog asks about
// is one the table recognizes.
func TestEveryQueriedNameIsRecognized(t *testing.T) {
	for _, n := range check.RuntimePackageNames() {
		if !Recognizes(n) {
			t.Errorf("the catalog queries %s, which the table does not recognize", n)
		}
	}
	if Recognizes("php8.3-cli") || Recognizes("openssl") {
		t.Error("recognizes a name it does not judge")
	}
}

func TestDpkgOrdering(t *testing.T) {
	less := [][2]string{
		{"8.3.6-0ubuntu0.24.04.9", "8.3.6-0ubuntu0.24.04.13"},
		{"1.0.9-2", "1.0.9-2+deb12u1"},
		{"1.0.9-2~deb12u1", "1.0.9-2"},
		{"8.2.7-1", "8.2.35-1~deb12u1"},
		{"1:1.0-1", "2:0.1-1"},
		{"7.4.3-4ubuntu2.29", "7.4.3-4ubuntu2.29+esm5"},
		{"1.0", "1.0+b1"},
		{"1.0~rc1", "1.0"},
	}
	for _, p := range less {
		if compareDpkg(p[0], p[1]) >= 0 || compareDpkg(p[1], p[0]) <= 0 {
			t.Errorf("%s should sort before %s", p[0], p[1])
		}
	}
	if compareDpkg("1.0-1", "1.0-1") != 0 {
		t.Error("equal versions")
	}
}

func TestEOLDates(t *testing.T) {
	if d, ok := EOLDate("node", "20"); !ok || d != "2026-04-30" {
		t.Errorf("%q %v", d, ok)
	}
	if _, ok := EOLDate("node", "18"); ok {
		t.Error("a date the table does not hold")
	}
}

// The real parser lowercases os-release keys: Assess must read what check
// gives it, not what a test builds.
func TestAssessReadsTheParsedOSRelease(t *testing.T) {
	parsed, err := check.Parse(check.Check{ID: "os.release", Parser: check.ParseKV, Argv: []string{"cat", "/etc/os-release"}},
		[]byte("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	osr := parsed.(map[string]string)
	r := one(t, Assess(osr, recs("dpkg", "php8.3-fpm 8.3.6-0ubuntu0.24.04.9")))
	if r.Status != Affected {
		t.Errorf("%+v", r)
	}
}
