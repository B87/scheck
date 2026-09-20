package policy

import (
	"path"
	"strings"
)

// PathDecision is the outcome of a path policy check.
type PathDecision int

// Decisions. MetadataOnly means "stat it, never read it".
const (
	PathDeny PathDecision = iota
	PathAllow
	PathMetadataOnly
)

func (d PathDecision) String() string {
	switch d {
	case PathAllow:
		return "allow"
	case PathMetadataOnly:
		return "metadata-only"
	default:
		return "deny"
	}
}

// PathVerdict is a decision plus the rule that produced it, for the audit log
// and for the error returned to the model.
type PathVerdict struct {
	Decision PathDecision
	Rule     string
}

// Rule names.
const (
	RuleConfigDeny     = "path.config_deny"
	RuleNotAllowed     = "path.not_allowed"
	RuleHomeMetadata   = "path.home_metadata"
	RuleLogMetadata    = "path.log_metadata"
	RuleSensitivePrefx = "path.sensitive:"
)

// allowedPrefixes are the only trees the model may read content from.
// Segments may use path.Match syntax (`/opt/*/etc`).
var allowedPrefixes = []string{
	"/etc",
	"/usr/local/etc",
	"/opt/*/etc",
	"/usr/lib/systemd",
	"/lib/systemd",
	"/run/systemd",
	"/proc/sys",
	"/Library/LaunchDaemons",
	"/Library/LaunchAgents",
	"/Library/Preferences",
	"/System/Library/LaunchDaemons",
	"/System/Library/LaunchAgents",
}

// metadataPrefixes are reachable for stat, never for content.
var metadataPrefixes = map[string]string{
	"/var/log":  RuleLogMetadata,
	"/home":     RuleHomeMetadata,
	"/root":     RuleHomeMetadata,
	"/Users":    RuleHomeMetadata,
	"/var/root": RuleHomeMetadata,
}

// sensitiveRule downgrades an otherwise allowed path to metadata-only.
type sensitiveRule struct {
	name    string
	kind    sensitiveKind
	pattern string
}

type sensitiveKind int

const (
	matchFull      sensitiveKind = iota // path.Match against the whole path
	matchBase                           // path.Match against the basename
	matchComponent                      // any directory component equals pattern
)

var sensitiveRules = []sensitiveRule{
	{"shadow", matchFull, "/etc/shadow"},
	{"shadow", matchFull, "/etc/shadow-"},
	{"shadow", matchFull, "/etc/gshadow"},
	{"shadow", matchFull, "/etc/gshadow-"},
	{"master_passwd", matchFull, "/etc/master.passwd"},
	{"ssh_host_key", matchFull, "/etc/ssh/ssh_host_*_key"},
	{"ssh_identity", matchBase, "id_*"},
	{"key_file", matchBase, "*.key"},
	{"pem_file", matchBase, "*.pem"},
	{"p12_file", matchBase, "*.p12"},
	{"pfx_file", matchBase, "*.pfx"},
	{"keytab", matchBase, "*.keytab"},
	{"netrc", matchBase, ".netrc"},
	{"git_credentials", matchBase, ".git-credentials"},
	{"ssh_dir", matchComponent, ".ssh"},
	{"aws_dir", matchComponent, ".aws"},
	{"gnupg_dir", matchComponent, ".gnupg"},
	{"wireguard", matchFull, "/etc/wireguard/*"},
	{"sssd_secrets", matchFull, "/var/lib/sss/secrets/*"},
}

// PathPolicy decides whether a resolved absolute path may be read.
type PathPolicy struct {
	extraDeny []string
}

// NewPathPolicy builds the compiled-in policy plus config `deny_paths`
// prefixes. Config can only add denials, never remove one.
func NewPathPolicy(denyPaths []string) *PathPolicy {
	p := &PathPolicy{}
	for _, d := range denyPaths {
		if d = path.Clean(d); d != "/" && strings.HasPrefix(d, "/") {
			p.extraDeny = append(p.extraDeny, d)
		}
	}
	return p
}

// Decide classifies p, which must already be absolute and symlink-resolved on
// the target (the runner does that with the fs.realpath check). Traversal is
// rejected earlier at the charset level, so Decide only cleans.
func (pp *PathPolicy) Decide(p string) PathVerdict {
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		return PathVerdict{PathDeny, RuleNotAllowed}
	}
	for _, d := range pp.extraDeny {
		if underPrefix(p, d) {
			return PathVerdict{PathDeny, RuleConfigDeny}
		}
	}
	if name, hit := sensitive(p); hit {
		// Sensitive files are metadata-only wherever they are, provided the
		// tree is reachable at all.
		if allowedContent(p) || metadataPrefix(p) != "" {
			return PathVerdict{PathMetadataOnly, RuleSensitivePrefx + name}
		}
		return PathVerdict{PathDeny, RuleNotAllowed}
	}
	if allowedContent(p) {
		return PathVerdict{PathAllow, ""}
	}
	if rule := metadataPrefix(p); rule != "" {
		return PathVerdict{PathMetadataOnly, rule}
	}
	return PathVerdict{PathDeny, RuleNotAllowed}
}

func allowedContent(p string) bool {
	for _, a := range allowedPrefixes {
		if underGlobPrefix(p, a) {
			return true
		}
	}
	return false
}

func metadataPrefix(p string) string {
	for prefix, rule := range metadataPrefixes {
		if underPrefix(p, prefix) {
			return rule
		}
	}
	return ""
}

func sensitive(p string) (string, bool) {
	base := path.Base(p)
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for _, r := range sensitiveRules {
		switch r.kind {
		case matchFull:
			if ok, _ := path.Match(r.pattern, p); ok {
				return r.name, true
			}
		case matchBase:
			if ok, _ := path.Match(r.pattern, base); ok {
				// Public halves of key pairs are not secrets.
				if r.name == "ssh_identity" && strings.HasSuffix(base, ".pub") {
					continue
				}
				return r.name, true
			}
		case matchComponent:
			for _, c := range comps[:max(len(comps)-1, 0)] {
				if c == r.pattern {
					return r.name, true
				}
			}
		}
	}
	return "", false
}

func underPrefix(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// underGlobPrefix matches p's leading segments against a pattern whose
// segments may contain path.Match wildcards.
func underGlobPrefix(p, pattern string) bool {
	ps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	gs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	if len(ps) < len(gs) {
		return false
	}
	for i, g := range gs {
		if ok, _ := path.Match(g, ps[i]); !ok {
			return false
		}
	}
	return true
}
