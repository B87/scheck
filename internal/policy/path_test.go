package policy

import "testing"

// The hostile-path corpus (docs/SPEC.md §11). Every row is a path as it would
// arrive after charset validation and symlink resolution.
func TestPathPolicyCorpus(t *testing.T) {
	pp := NewPathPolicy([]string{"/etc/corp-secrets", "relative/ignored"})
	cases := []struct {
		path string
		want PathDecision
		rule string
	}{
		{"/etc/ssh/sshd_config", PathAllow, ""},
		{"/etc/os-release", PathAllow, ""},
		{"/etc/sudoers.d/90-cloud-init", PathAllow, ""},
		{"/etc", PathAllow, ""},
		{"/opt/nginx/etc/nginx.conf", PathAllow, ""},
		{"/usr/lib/systemd/system/sshd.service", PathAllow, ""},
		{"/Library/LaunchDaemons/com.x.plist", PathAllow, ""},
		{"/etc/ssh/ssh_host_ed25519_key.pub", PathAllow, ""},

		{"/etc/shadow", PathMetadataOnly, "path.sensitive:shadow"},
		{"/etc/gshadow-", PathMetadataOnly, "path.sensitive:shadow"},
		{"/etc/ssh/ssh_host_ed25519_key", PathMetadataOnly, "path.sensitive:ssh_host_key"},
		{"/etc/ssl/private/server.key", PathMetadataOnly, "path.sensitive:key_file"},
		{"/etc/ssl/certs/ca.pem", PathMetadataOnly, "path.sensitive:pem_file"},
		{"/etc/wireguard/wg0.conf", PathMetadataOnly, "path.sensitive:wireguard"},
		{"/var/log/auth.log", PathMetadataOnly, RuleLogMetadata},
		{"/home/ops/.ssh/authorized_keys", PathMetadataOnly, "path.sensitive:ssh_dir"},
		{"/home/ops/.ssh/id_ed25519", PathMetadataOnly, "path.sensitive:ssh_identity"},
		{"/root/.aws/credentials", PathMetadataOnly, "path.sensitive:aws_dir"},
		{"/Users/x/.bash_history", PathMetadataOnly, RuleHomeMetadata},
		{"/Users/x/Documents/notes.txt", PathMetadataOnly, RuleHomeMetadata},

		{"/etc/corp-secrets/db.yaml", PathDeny, RuleConfigDeny},
		{"/etc/corp-secrets", PathDeny, RuleConfigDeny},
		{"/usr/bin/id", PathDeny, RuleNotAllowed},
		{"/proc/1/environ", PathDeny, RuleNotAllowed},
		{"/tmp/x.key", PathDeny, RuleNotAllowed},
		{"/opt/etc/x", PathDeny, RuleNotAllowed}, // /opt/*/etc needs a vendor segment
		{"/etcetera/x", PathDeny, RuleNotAllowed},
		{"/var/logs/x", PathDeny, RuleNotAllowed},
		{"etc/passwd", PathDeny, RuleNotAllowed},
		// A symlink from an allowed prefix that resolved elsewhere arrives
		// here as its resolved path and is judged as such.
		{"/usr/share/doc/x", PathDeny, RuleNotAllowed},
	}
	for _, tc := range cases {
		got := pp.Decide(tc.path)
		if got.Decision != tc.want || got.Rule != tc.rule {
			t.Errorf("%s: got %s/%q, want %s/%q", tc.path, got.Decision, got.Rule, tc.want, tc.rule)
		}
	}
}

func TestPathPolicyCleansButDoesNotResolve(t *testing.T) {
	pp := NewPathPolicy(nil)
	// Clean collapses a benign "/etc//ssh/./sshd_config".
	if v := pp.Decide("/etc//ssh/./sshd_config"); v.Decision != PathAllow {
		t.Errorf("clean path denied: %+v", v)
	}
	// Traversal is refused upstream by the charset; if it ever got here,
	// Clean must not turn it into an allowed path outside /etc.
	if v := pp.Decide("/etc/../usr/bin/id"); v.Decision != PathDeny {
		t.Errorf("traversal escaped: %+v", v)
	}
}

// macOS spells /etc as /private/etc once resolved; the policy must judge the
// canonical name, so an allowed prefix still allows and a sensitive file is
// still metadata-only (docs/SPEC.md §4.1).
func TestCanonicalMacOSPrivate(t *testing.T) {
	pp := NewPathPolicy(nil)
	cases := map[string]PathDecision{
		"/private/etc/ssh/sshd_config":          PathAllow,
		"/private/etc/master.passwd":            PathMetadataOnly,
		"/private/etc/ssh/ssh_host_ed25519_key": PathMetadataOnly,
		"/private/var/log/system.log":           PathMetadataOnly,
		"/private/var/root/.ssh/id_rsa":         PathMetadataOnly,
		"/private/tmp/x":                        PathDeny,
		"/privateer/etc/passwd":                 PathDeny,
	}
	for p, want := range cases {
		if got := pp.Decide(Canonical(p, true)).Decision; got != want {
			t.Errorf("macos %s: %s, want %s", p, got, want)
		}
		if got := pp.Decide(Canonical(p, false)).Decision; got != PathDeny {
			t.Errorf("linux %s: %s, want deny (no /private on Linux)", p, got)
		}
	}
}
