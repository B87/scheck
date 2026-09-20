package ssh

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/check/common"
)

// The quoter's input domain: every literal token in the catalog, samples
// across each parameter charset, and the canary. Each must survive a trip
// through a real POSIX shell byte for byte, on every POSIX shell present.
func quoterDomain() [][]string {
	var argvs [][]string
	for _, c := range check.All() {
		params := map[string]string{}
		for _, p := range c.Params {
			switch p.Kind {
			case check.KindPath:
				params[p.Name] = "/etc/ssh/sshd_config.d/50-cloud_init.conf"
			case check.KindIdent:
				params[p.Name] = "ssh.service"
			case check.KindInt:
				params[p.Name] = "20"
			case check.KindEnum:
				params[p.Name] = p.Enum[0]
			}
		}
		argv, err := c.Bind(params)
		if err != nil {
			panic(err)
		}
		argvs = append(argvs, argv)
	}
	argvs = append(argvs,
		[]string{"x", ""},
		[]string{"x", "A-Za-z0-9._/-", "A-Za-z0-9._-", "=", "%a:%U", ",", "+", "@"},
		[]string{"x", common.CanaryString},
		[]string{"x", "it's", "''", "'", `'\''`, "a b", "$(id)", "`id`", "$HOME", ";", "|", "&&", ">", "*", "?", "[a]", "~", "#", "\\", "\\\\", "\n", "\t"},
	)
	return argvs
}

func TestQuoteRoundTripsThroughPOSIXShells(t *testing.T) {
	shells := []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ksh"}
	tested := 0
	for _, sh := range shells {
		if _, err := os.Stat(sh); err != nil {
			continue
		}
		tested++
		for _, argv := range quoterDomain() {
			// Replace argv[0] with a printer so we observe exactly what the
			// shell handed to the program, one token per line.
			probe := append([]string{"printf", "%s\n"}, argv[1:]...)
			want := strings.Join(argv[1:], "\n") + "\n"
			cmd := exec.CommandContext(context.Background(), sh, "-c", Quote(probe))
			out, err := cmd.Output()
			if err != nil {
				t.Errorf("%s: %q: %v", sh, argv, err)
				continue
			}
			if string(out) != want {
				t.Errorf("%s: argv %q\n got %q\nwant %q", sh, argv, out, want)
			}
		}
	}
	if tested == 0 {
		t.Skip("no POSIX shell found")
	}
}

func TestQuoteShape(t *testing.T) {
	if got := Quote([]string{"printf", "%s", "it's"}); got != `LC_ALL=C 'printf' '%s' 'it'\''s'` {
		t.Errorf("got %s", got)
	}
}
