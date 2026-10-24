package advisory

// TableVersion identifies the advisory table below: a change to any row
// changes what a host's PHP or Node.js is judged against, so the constant is
// bumped with it (docs/spec/host-collector.md §3, G8). The table is a dated
// constant, not a feed: nothing here is fetched at run time, and an
// advisory published after this date is not known to it.
const TableVersion = "2026-10-24"

// The disclosures the table holds.
const (
	// PHPAdvisory is the PHP security release of 21 October 2026.
	PHPAdvisory = "CVE-2026-109618 and CVE-2026-109619 (PHP security release of 21 October 2026)"
	// NodeBrotliAdvisory is the Brotli decoder flaw of the Node.js security
	// release of 21 October 2026, which fixed ten flaws.
	NodeBrotliAdvisory = "CVE-2026-111497"
)

// phpFixed is the first upstream PHP version that fixes the PHP flaws, by
// release line. Lines 8.1 and older have no release: the PHP project
// published source patches for 7.4, 8.0 and 8.1 without a new version
// number, so no version of those lines is shown fixed by its number.
var phpFixed = map[string]string{"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}

// nodeFixed is the first Node.js project version that fixes the October
// 2026 release, by major version. Any other major is end of life or newer
// than this table.
var nodeFixed = map[string]string{"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}

// nodeNewest is the newest Node.js major the table knows; a newer major is
// not judged.
const nodeNewest = 26

// distroRow is one distribution's fixed package of a product. An absent row
// is an explicitly empty field: the distribution is recognized, and scheck
// does not know a package that fixes the flaw, so a version below any number
// proves nothing (it may carry the fix under its old number).
type distroRow struct {
	os      string // os-release ID
	version string // os-release VERSION_ID
	name    string // as the report names it
	// line is the PHP release line the package carries ("" for Brotli).
	line  string
	fixed string // the first package version that fixes it
	ref   string // the distribution's advisory
	// pro says the fix is published only through a paid extended-support
	// subscription.
	pro bool
}

// phpRows are the verified distribution packages that fix the PHP flaws.
// Red Hat family, Fedora and Alpine have no row: Red Hat's page carries no
// product data, and an Alpine tracker answer could not be read.
var phpRows = []distroRow{
	{os: "debian", version: "12", name: "Debian 12", line: "8.2", fixed: "8.2.35-1~deb12u1", ref: "DLA-4848-1"},
	{os: "debian", version: "13", name: "Debian 13", line: "8.4", fixed: "8.4.27-1~deb13u1", ref: "DSA-6574-1"},
	{os: "ubuntu", version: "22.04", name: "Ubuntu 22.04", line: "8.1", fixed: "8.1.2-1ubuntu2.28", ref: "USN-8948-1"},
	{os: "ubuntu", version: "24.04", name: "Ubuntu 24.04", line: "8.3", fixed: "8.3.6-0ubuntu0.24.04.13", ref: "USN-8948-1"},
	{os: "ubuntu", version: "26.04", name: "Ubuntu 26.04", line: "8.5", fixed: "8.5.4-0ubuntu1.5", ref: "USN-8948-1"},
	{os: "ubuntu", version: "26.10", name: "Ubuntu 26.10", line: "8.5", fixed: "8.5.9-0ubuntu2.1", ref: "USN-8948-1"},
	{os: "ubuntu", version: "20.04", name: "Ubuntu 20.04", line: "7.4", fixed: "7.4.3-4ubuntu2.29+esm5", ref: "Ubuntu Pro", pro: true},
	{os: "ubuntu", version: "18.04", name: "Ubuntu 18.04", line: "7.2", fixed: "7.2.24-0ubuntu0.18.04.17+esm14", ref: "Ubuntu Pro", pro: true},
}

// brotliRows are the distribution packages of the Brotli library that fix
// CVE-2026-111497. Debian's and Homebrew's Node.js decompress Brotli through
// the system library, so the library's package decides. Ubuntu has no row:
// its tracker says "needs evaluation".
var brotliRows = []distroRow{
	{os: "debian", version: "12", name: "Debian 12", fixed: "1.0.9-2+deb12u1", ref: "DLA-4855-1"},
	{os: "debian", version: "13", name: "Debian 13", fixed: "1.1.0-2+deb13u1", ref: "DSA-6582-1"},
}

// eol is the end-of-life date of a release line, as the project that
// publishes it states it. A line absent here has no date in the table.
// Every date was read on 2026-10-24 from php.net/supported-versions (PHP 8.2 to
// 8.5) and the Node.js release schedule (20, 22, 24, 25, 26).
var eol = map[string]string{
	"php 8.2": "2026-12-31", "php 8.3": "2027-12-31", "php 8.4": "2028-12-31", "php 8.5": "2029-12-31",
	"node 20": "2026-04-30", "node 25": "2026-06-01", "node 26": "2029-04-30", "node 22": "2027-04-30", "node 24": "2028-04-30",
}

// EOLDate is the end-of-life date of a release line ("php 8.2", "node 20"),
// and whether the table knows it.
func EOLDate(product, line string) (string, bool) {
	d, ok := eol[product+" "+line]
	return d, ok
}

// rpmDistros are the os-release IDs of the Red Hat family and Fedora: their
// packages backport fixes without changing the PHP version number.
var rpmDistros = map[string]string{
	"rhel": "Red Hat Enterprise Linux", "centos": "CentOS", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
	"ol": "Oracle Linux", "fedora": "Fedora", "amzn": "Amazon Linux",
}
