package finding

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/check"
)

// CredFileTablesVersion identifies the name and group tables below: a change
// to any of them changes what the credential-file rules read as a credential
// or as a broad group (docs/spec/host-collector.md §6.5, G5).
const CredFileTablesVersion = "2026-10-24"

// The kinds of file a CredFiles predicate judges.
const (
	CredEnv      = "env"
	CredSSHKey   = "ssh_key"
	CredCloud    = "cloud"
	CredContSock = "container_socket"
)

// envNames are the .env files read, by exact name: the catalog's argv cannot
// carry a glob. Templates (.env.example and the like) are absent on purpose.
var envNames = []string{".env", ".env.local", ".env.production", ".env.production.local", ".env.prod",
	".env.staging", ".env.development", ".env.development.local"}

var sshKeyNames = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ed25519_sk", "id_ecdsa_sk"}

// cloudSuffixes are matched on the path's ending, never the basename alone.
var cloudSuffixes = []string{"/.aws/credentials", "/.config/gcloud/credentials.db",
	"/.config/gcloud/application_default_credentials.json", "/.config/gcloud/access_tokens.db"}

var sockNames = []string{"docker.sock", "podman.sock", "containerd.sock"}

// ownSocketGroups are the groups a container engine's socket is meant to
// belong to; any other group that can write to it is a grant.
var ownSocketGroups = []string{"docker", "podman", "root", "wheel"}

// broadGroups are groups every ordinary account belongs to ("staff" is every
// user on macOS); any other group is a deliberate share and is not judged.
var broadGroups = []string{"users", "staff", "everyone"}

// CredFiles reads a find_ls fact of credential files and the folders above
// them that stop others getting in. A file is exposed when the world, or a
// group everyone is in, can read it (write, for .env files and the container
// socket) and every listed folder above it lets them through: the mode of a
// file inside a private home says nothing about who can reach it. It fires
// on a recognised exposed file even from a partial listing, because folders
// are listed before their contents; it never decides that nothing is
// exposed from a depth-capped listing that showed no file (the read is a
// sample), and judges only mode bits, never access lists.
type CredFiles struct {
	Kind string
	// FireOnly says the listing never disproves: BSD find prints a newline in
	// a name raw, so any local user can plant records that look like a
	// folder blocking a key. Such a listing may still prove an exposure.
	FireOnly bool
}

// inHome says a path is under a home directory.
func inHome(p string) bool {
	for _, h := range []string{"/home/", "/root/", "/Users/", "/var/root/"} {
		if strings.HasPrefix(p, h) {
			return true
		}
	}
	return false
}

func (p CredFiles) Accepts(k check.ParserKind) bool { return k == check.ParseFindLS }
func (p CredFiles) String() string                  { return "an exposed " + p.Kind + " file" }

// permission characters of the symbolic mode, by index.
const (
	gR, gW, gX = 4, 5, 6
	oR, oW, oX = 7, 8, 9
)

func isX(c byte) bool { return c == 'x' || c == 's' || c == 't' }

// passes says a folder lets in the world, or the group g.
func passes(d check.Record, g string, world bool) bool {
	m := d[check.FieldSymbolic]
	if len(m) != 10 {
		return false
	}
	if isX(m[oX]) {
		return true
	}
	return !world && isX(m[gX]) && d[check.FieldGroup] == g
}

// exposure is who can reach a file and how: "" when nobody beyond its
// owner can by mode bits and the folders above.
func (p CredFiles) exposure(f check.Record, dirs []check.Record) string {
	m := f[check.FieldSymbolic]
	if len(m) != 10 {
		return ""
	}
	write := p.Kind == CredEnv || p.Kind == CredContSock
	read := p.Kind != CredContSock
	reach := func(world bool) bool {
		if p.Kind == CredContSock {
			return true // /run is traversable by everyone
		}
		for _, d := range dirs {
			if strings.HasPrefix(f[check.FieldPath], strings.TrimSuffix(d[check.FieldPath], "/")+"/") &&
				!passes(d, f[check.FieldGroup], world) {
				return false
			}
		}
		return true
	}
	if p.Kind == CredContSock {
		switch {
		case m[oW] == 'w':
			return "writable by every account"
		case m[gW] == 'w' && !slices.Contains(ownSocketGroups, f[check.FieldGroup]):
			return "writable by group " + f[check.FieldGroup]
		}
		return ""
	}
	worldHit := (read && m[oR] == 'r') || (write && m[oW] == 'w')
	if worldHit && reach(true) {
		if write && m[oW] == 'w' {
			return "writable by every account"
		}
		return "readable by every account"
	}
	groupHit := slices.Contains(broadGroups, f[check.FieldGroup]) && ((read && m[gR] == 'r') || (write && m[gW] == 'w'))
	if groupHit && reach(false) {
		if write && m[gW] == 'w' {
			return "writable by group " + f[check.FieldGroup]
		}
		return "readable by group " + f[check.FieldGroup]
	}
	return ""
}

// target says whether a listed entry is one this kind of rule judges.
func (p CredFiles) target(r check.Record) bool {
	pth, base := r[check.FieldPath], path.Base(r[check.FieldPath])
	switch p.Kind {
	case CredEnv:
		return slices.Contains(envNames, base)
	case CredSSHKey:
		return slices.Contains(sshKeyNames, base)
	case CredCloud:
		return slices.ContainsFunc(cloudSuffixes, func(s string) bool { return strings.HasSuffix(pth, s) })
	case CredContSock:
		return slices.Contains(sockNames, base)
	}
	return false
}

func (p CredFiles) Eval(parsed any) Verdict {
	recs, ok := parsed.(check.Records)
	if !ok {
		return notAssessed("unexpected-parsed-shape")
	}
	var dirs, files []check.Record
	for _, r := range recs.Items {
		switch r[check.FieldType] {
		case "d":
			dirs = append(dirs, r)
		default:
			if p.target(r) {
				files = append(files, r)
			}
		}
	}
	var exposed []string
	judged, links, unjudged := 0, 0, 0
	for _, f := range files {
		wantType := "-"
		if p.Kind == CredContSock {
			wantType = "s"
		}
		if f[check.FieldType] != wantType {
			links++ // a link's own mode says nothing; its target is judged if listed
			continue
		}
		// The folders above a declared application folder are not read, so a
		// .env inside a home (which others usually cannot enter) is not
		// judged.
		if p.Kind == CredEnv && inHome(f[check.FieldPath]) {
			unjudged++
			continue
		}
		judged++
		if e := p.exposure(f, dirs); e != "" {
			exposed = append(exposed, fmt.Sprintf("%s %s %s:%s %s", f[check.FieldPath], f[check.FieldSymbolic], f[check.FieldUser], f[check.FieldGroup], e))
		}
	}
	if len(exposed) > 0 {
		excerpt := exposed[0]
		if len(exposed) > 1 {
			excerpt += fmt.Sprintf(" (+%d more)", len(exposed)-1)
		}
		return matched("recognized-exposed-file", excerpt+"; mode bits only")
	}
	if recs.Partial {
		return notAssessed("partial-output")
	}
	if judged > 0 && p.FireOnly {
		return notAssessed("listing_not_trusted")
	}
	if judged > 0 {
		return notMatched("recognized-unexposed-files", fmt.Sprintf("%d listed, none reachable by others by mode bits", judged))
	}
	if unjudged > 0 {
		return notAssessed("home_ancestors_not_read")
	}
	if links > 0 {
		return notAssessed("symlink_not_followed")
	}
	// A depth-capped listing that showed no file says nothing: a home on its
	// own filesystem, a link or a folder the account could not enter all
	// leave a walk short without a trace.
	return notAssessed("no-file-listed")
}
