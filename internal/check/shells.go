package check

import (
	"path"
	"strings"
)

// noLoginShells refuse a login or run one fixed command, matched by full
// path so a script named `nologin` elsewhere clears nothing
// (docs/spec/host-collector.md §6.5, the accounts.empty_password row).
var noLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/bin/true": true, "/usr/bin/true": true,
	"/dev/null": true,
	"/bin/sync": true, "/usr/bin/sync": true, "/sbin/shutdown": true, "/usr/sbin/shutdown": true,
	"/sbin/halt": true, "/usr/sbin/halt": true,
}

// RefusesLogin reports whether an /etc/passwd shell refuses a login or runs
// one fixed command. An empty shell field does not: login(1) runs /bin/sh.
func RefusesLogin(shell string) bool { return noLoginShells[strings.TrimSpace(shell)] }

// interactiveShells are matched by name.
var interactiveShells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "fish": true,
	"tcsh": true, "csh": true, "ash": true, "busybox": true, "rbash": true, "git-shell": true,
}

// InteractiveShell reports whether a shell is a recognized interactive one,
// an empty field included. A shell that is neither this nor RefusesLogin is
// unrecognized, and a rule reading it is not assessed rather than passed.
func InteractiveShell(shell string) bool {
	s := strings.TrimSpace(shell)
	return s == "" || interactiveShells[path.Base(s)]
}
