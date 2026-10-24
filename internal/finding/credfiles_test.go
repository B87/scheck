package finding

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
)

func findLS(t *testing.T, lines ...string) check.Records {
	t.Helper()
	v, err := check.Parse(check.Check{ID: "x", Parser: check.ParseFindLS, Argv: []string{"find"}}, []byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return v.(check.Records)
}

// A file is exposed when its mode and every listed folder above it let
// others in; the mode of a file inside a private folder says nothing about
// who can reach it (docs/spec/host-collector.md §6.5, G5).
func TestCredFilesReachability(t *testing.T) {
	const (
		home0 = "1 4 drwxr-x--- 5 ana ana 4096 Oct  3 10:11 /home/ana"
		file0 = "1 4 -rw-r--r-- 1 ana ana 411 Oct  3 10:11 /home/ana/.ssh/id_ed25519"
	)
	const (
		file   = "1 4 -rw-r--r-- 1 ana ana 411 Oct  3 10:11 /home/ana/.ssh/id_ed25519"
		fileG  = "1 4 -rw-rw---- 1 ana %s 411 Oct  3 10:11 /home/ana/.ssh/id_ed25519"
		home   = "1 4 drwxr-x--- 5 ana ana 4096 Oct  3 10:11 /home/ana"
		homeG  = "1 4 drwxrwx--- 5 ana %s 4096 Oct  3 10:11 /home/ana"
		sshDir = "1 4 drwx------ 2 ana ana 4096 Oct  3 10:11 /home/ana/.ssh"
		link   = "1 0 lrwxrwxrwx 1 ana ana 11 Oct  3 10:11 /home/ana/.ssh/id_rsa -> /tmp/other"
	)
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"world readable, nothing blocks", []string{file}, Matched},
		{"a private home blocks it", []string{home, file}, NotMatched},
		{"a private .ssh blocks it", []string{sshDir, file}, NotMatched},
		{"group users can read, nothing blocks", []string{strings.Replace(fileG, "%s", "users", 1)}, Matched},
		{"a named group is a deliberate share", []string{strings.Replace(fileG, "%s", "deploy", 1)}, NotMatched},
		{"group users, folder open to that group only", []string{strings.Replace(homeG, "%s", "users", 1), strings.Replace(fileG, "%s", "users", 1)}, Matched},
		{"group users, folder open to another group", []string{strings.Replace(homeG, "%s", "deploy", 1), strings.Replace(fileG, "%s", "users", 1)}, NotMatched},
		{"a link's own mode says nothing", []string{link}, NotAssessed},
		{"nothing listed says nothing", nil, NotAssessed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := CredFiles{Kind: CredSSHKey}
			if got := p.Eval(findLS(t, tc.lines...)); got.Status != tc.want {
				t.Fatalf("%s (%s), want %s", got.Status, got.Reason, tc.want)
			}
		})
	}
	// A listing any local user could forge never disproves (macOS).
	safe := findLS(t, home0, file0)
	if got := (CredFiles{Kind: CredSSHKey, FireOnly: true}).Eval(safe); got.Status != NotAssessed || got.Reason != "listing_not_trusted" {
		t.Errorf("fire-only listing: %s %s", got.Status, got.Reason)
	}
	if got := (CredFiles{Kind: CredSSHKey, FireOnly: true}).Eval(findLS(t, file0)); got.Status != Matched {
		t.Errorf("fire-only still proves an exposure: %s", got.Status)
	}
	// Only the key names and path endings of the table are judged.
	other := "1 4 -rw-rw-rw- 1 ana ana 4 Oct  3 10:11 /home/ana/notes/credentials"
	if got := (CredFiles{Kind: CredCloud}).Eval(findLS(t, other)); got.Status != NotAssessed || got.Reason != "no-file-listed" {
		t.Errorf("a file called credentials elsewhere: %s %s", got.Status, got.Reason)
	}
	aws := "1 4 -rw-r--r-- 1 ana ana 4 Oct  3 10:11 /home/ana/.aws/credentials"
	if got := (CredFiles{Kind: CredCloud}).Eval(findLS(t, aws)); got.Status != Matched {
		t.Errorf("aws credentials: %s", got.Status)
	}
}

// An .env file is exposed when it can be read or changed by everyone, and
// the container socket by its write bit alone.
func TestCredFilesEnvAndSocket(t *testing.T) {
	env := func(mode, group, dirs string) check.Records {
		lines := []string{"1 4 " + mode + " 1 www " + group + " 90 Oct  3 10:11 /srv/shop/.env"}
		if dirs != "" {
			lines = append([]string{dirs}, lines...)
		}
		return findLS(t, lines...)
	}
	e := CredFiles{Kind: CredEnv}
	for mode, want := range map[string]string{
		"-rw-r--r--": Matched, "-rw-rw-rw-": Matched, "-rw-r-----": NotMatched, "-rw-------": NotMatched, "-rw----rw-": Matched,
	} {
		if got := e.Eval(env(mode, "www", "")); got.Status != want {
			t.Errorf("env %s: %s", mode, got.Status)
		}
	}
	if got := e.Eval(env("-rw-rw----", "staff", "")); got.Status != Matched {
		t.Errorf("env writable by group staff: %s", got.Status)
	}
	// A template is not in the name table.
	tpl := findLS(t, "1 4 -rw-r--r-- 1 www www 9 Oct  3 10:11 /srv/shop/.env.example")
	if got := e.Eval(tpl); got.Status == Matched {
		t.Errorf("a template matched: %+v", got)
	}
	sock := func(mode, group string) check.Records {
		return findLS(t, "5 0 "+mode+" 1 root "+group+" 0 Oct  3 10:11 /run/docker.sock")
	}
	s := CredFiles{Kind: CredContSock}
	for _, tc := range []struct{ mode, group, want string }{
		{"srw-rw----", "docker", NotMatched}, {"srw-rw----", "root", NotMatched}, {"srw-rw-rw-", "root", Matched},
		{"srw-rw----", "ops", Matched}, {"srw-r--r--", "root", NotMatched},
	} {
		if got := s.Eval(sock(tc.mode, tc.group)); got.Status != tc.want {
			t.Errorf("socket %s %s: %s", tc.mode, tc.group, got.Status)
		}
	}
	if got := s.Eval(findLS(t)); got.Status != NotAssessed {
		t.Errorf("no socket listed: %s", got.Status)
	}
	// A .env inside a home is not judged: the folders above the declared
	// folder are not read.
	home := findLS(t, "1 4 -rw-r--r-- 1 alice alice 9 Oct  3 10:11 /home/alice/shop/.env")
	if got := e.Eval(home); got.Status != NotAssessed || got.Reason != "home_ancestors_not_read" {
		t.Errorf("env in a home: %s %s", got.Status, got.Reason)
	}
}
