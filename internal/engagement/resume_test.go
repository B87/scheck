package engagement

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// resumeVersion is a release build's version: a resume keeps nothing a dev
// or dirty build read.
const resumeVersion = "v0.0.2"

var resumeStart = time.Date(2026, 10, 7, 7, 12, 3, 0, time.UTC)

// startRun writes file where a resume reads it again and runs it once.
func startRun(t *testing.T, file string, collect func(context.Context, hostasset.Options) (*hostasset.Collection, error)) (string, string, *Outcome) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Parse(path, []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), res.Engagement.Name, resumeStart)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := Run(context.Background(), res, RunOptions{Raw: []byte(file), Dir: dir, Started: resumeStart, Version: resumeVersion, Collect: collect})
	if err != nil {
		t.Fatal(err)
	}
	return path, dir.Path, out
}

// resume runs the run directory again, as `scheck run DIR` does.
func resume(t *testing.T, dir, version string, collect func(context.Context, hostasset.Options) (*hostasset.Collection, error)) *Outcome {
	t.Helper()
	out, err := resumeErr(t, dir, version, collect)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// resumeErr is resume for a session that may end on an error.
func resumeErr(t *testing.T, dir, version string, collect func(context.Context, hostasset.Options) (*hostasset.Collection, error)) (*Outcome, error) {
	t.Helper()
	d, err := OpenRun(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := LoadPrior(d)
	if err != nil {
		t.Fatal(err)
	}
	res, raw, err := p.LoadEngagement(testOpts)
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), res, RunOptions{Raw: raw, Dir: d, Resume: p, Started: p.Manifest.Started,
		Session: resumeStart.Add(time.Hour), Version: version, Collect: collect})
}

// collectFirstFails refuses 203.0.113.5 while fail is set and collects
// everything else from the ubuntu fixture, counting by address.
func collectFirstFails(t *testing.T, fail *bool, calls map[string]int) func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
	return collectFirstFailsFrom(t, "ubuntu", fail, calls)
}

func collectFirstFailsFrom(t *testing.T, name string, fail *bool, calls map[string]int) func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
	n := 0
	fromFixture := fixtureCollect(t, name, &n)
	return func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		calls[o.Host]++
		if o.Host == "203.0.113.5" && *fail {
			return nil, &hostasset.Error{Err: errors.New("ssh: dial tcp 203.0.113.5:22: connection refused")}
		}
		return fromFixture(ctx, o)
	}
}

// A host is resumed as a unit: one an earlier session collected completely
// is kept with its trace and never contacted, one that failed is collected
// again on a new session; the report says the run was resumed, and the
// audit log keeps both sessions in order (E4 test 20).
func TestResumeKeepsACompletedHost(t *testing.T) {
	fail, calls := true, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	path, dir, first := startRun(t, twoHosts, collect)
	if first.ExitCode() != 2 || calls["203.0.113.5"] != 1 || calls["203.0.113.6"] != 1 {
		t.Fatalf("first session: exit %d, calls %v", first.ExitCode(), calls)
	}
	auditBefore, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	keptTrace := first.Report.Assets[1].Trace

	fail = false
	out := resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.5"] != 2 || calls["203.0.113.6"] != 1 {
		t.Errorf("collections %v: the failed host is collected again, the completed one kept", calls)
	}
	if !out.Report.Run.Resumed || out.ExitCode() == 2 || len(out.Report.Engagement.EditedByHand) != 0 {
		t.Errorf("resumed %v, exit %d, edited %v", out.Report.Run.Resumed, out.ExitCode(), out.Report.Engagement.EditedByHand)
	}
	if !out.Report.Run.Started.Equal(resumeStart) || out.Report.Engagement.Source.Path == nil || *out.Report.Engagement.Source.Path != path {
		t.Errorf("run %+v, source %+v", out.Report.Run, out.Report.Engagement.Source)
	}
	if got := out.Report.Assets[1].Trace; len(got) == 0 || len(got) != len(keptTrace) || got[0].Check != keptTrace[0].Check {
		t.Errorf("the kept host's trace: %d entries, %d before", len(got), len(keptTrace))
	}
	audit, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !strings.HasPrefix(string(audit), string(auditBefore)) || len(audit) == len(auditBefore) {
		t.Error("the resumed session's commands are not appended to the audit log")
	}
	var m Manifest
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil || len(m.Sessions) != 2 || !m.Started.Equal(resumeStart) {
		t.Errorf("run.json: %+v, %v", m, err)
	}

	// A third session keeps both, and contacts nothing.
	out = resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.5"] != 2 || calls["203.0.113.6"] != 1 || out.ExitCode() == 2 {
		t.Errorf("a resume of a complete run: collections %v, exit %d", calls, out.ExitCode())
	}
}

// A host is kept only under the inputs it was collected with, and only by a
// build that names one commit: a changed asset, an accepted risk that names
// it, a redact_extra or a dev build collects it again.
func TestResumeCollectsAgainWhatChanged(t *testing.T) {
	base := twoHosts + "assets:\n  ops:\n    host: 203.0.113.6\n"
	risk := "intent:\n  accepted_risks:\n    - {id: sshd.password_auth_enabled, asset: ops, reason: lab, accepted_by: alice, expires: 2026-10-06}\npeople:\n  alice: {kind: employee}\n"
	for name, tc := range map[string]struct {
		start   string // the first session's file; base when empty
		edit    func(string) string
		version string
		want    int
	}{
		"nothing":   {edit: func(f string) string { return f }, want: 1},
		"elevation": {edit: func(f string) string { return f + "    elevate: sudo\n" }, want: 2},
		"accepted risk": {edit: func(f string) string {
			return f + "intent:\n  accepted_risks:\n    - {id: sshd.password_auth_enabled, asset: ops, reason: lab, accepted_by: alice}\npeople:\n  alice: {kind: employee}\n"
		}, want: 2},
		"redact_extra": {edit: func(f string) string { return f + "redact_extra: ['tangerine']\n" }, want: 2},
		"an exclude":   {edit: func(f string) string { return f + "exclude:\n  - network: 198.51.100.0/24\n" }, want: 2},
		// An acceptance's expiry is graded in the engagement's timezone.
		"the timezone": {start: base + risk, edit: func(f string) string {
			return strings.Replace(f, "timezone: Europe/Madrid", "timezone: Pacific/Pago_Pago", 1)
		}, want: 2},
		"a dev build":   {edit: func(f string) string { return f }, version: "dev", want: 2},
		"a dirty build": {edit: func(f string) string { return f }, version: "v0.0.2-3-gabcdef0-dirty", want: 2},
	} {
		t.Run(name, func(t *testing.T) {
			fail, calls := false, map[string]int{}
			collect := collectFirstFails(t, &fail, calls)
			start := cmp.Or(tc.start, base)
			path, dir, _ := startRun(t, start, collect)
			if err := os.WriteFile(path, []byte(tc.edit(start)), 0o600); err != nil {
				t.Fatal(err)
			}
			v := tc.version
			if v == "" {
				v = resumeVersion
			}
			resume(t, dir, v, collect)
			if calls["203.0.113.6"] != tc.want {
				t.Errorf("collections %v, want %d of 203.0.113.6", calls, tc.want)
			}
		})
	}
}

// A change only analysis reads contacts nothing, and a file the resume
// used although it changed since is named in the report. A host's envelope
// is never used as written: one changed since collects the host again.
func TestResumeAnalysisOnlyAndHandEdits(t *testing.T) {
	fail, calls := false, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	path, dir, first := startRun(t, twoHosts, collect)
	appendNewline := func(name string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edited := "evidence/" + fileName(first.Report.Assets[1].Name) + ".collection.json"
	appendNewline(edited)
	if err := os.WriteFile(path, []byte(twoHosts+"people:\n  alice: {kind: employee}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.5"] != 1 || calls["203.0.113.6"] != 1 {
		t.Errorf("collections %v: nothing a host reads changed", calls)
	}
	if !slices.Equal(out.Report.Engagement.EditedByHand, []string{edited}) {
		t.Errorf("edited by hand: %v, want %s", out.Report.Engagement.EditedByHand, edited)
	}

	appendNewline("evidence/" + fileName(first.Report.Assets[0].Name) + ".json")
	out = resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.5"] != 2 || calls["203.0.113.6"] != 1 {
		t.Errorf("collections %v: a host whose envelope changed is collected again", calls)
	}
	if !slices.Equal(out.Report.Engagement.EditedByHand, []string{edited}) {
		t.Errorf("edited by hand: %v, want only the record still in use, %s", out.Report.Engagement.EditedByHand, edited)
	}
}

// A resume refuses a directory it cannot resume: one another run holds,
// one with no run.json, and a file that now names another engagement.
func TestResumeRefusals(t *testing.T) {
	fail, calls := false, map[string]int{}
	path, dir, _ := startRun(t, twoHosts, collectFirstFails(t, &fail, calls))
	held, err := LockRunDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRun(dir); !errors.Is(err, ErrLocked) {
		t.Errorf("a locked directory: %v", err)
	}
	held.Close()
	if _, err := OpenRun(t.TempDir()); err == nil || !strings.Contains(err.Error(), manifestFile) {
		t.Errorf("no run.json: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(twoHosts, "name: acme", "name: other", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := OpenRun(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := LoadPrior(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.LoadEngagement(testOpts); err == nil || !strings.Contains(err.Error(), "start a new run") {
		t.Errorf("a renamed engagement: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.LoadEngagement(testOpts); err == nil {
		t.Error("a missing engagement file")
	}
}

// A --host run resumes from the directory's own copy of the engagement it
// built.
func TestResumeHostRun(t *testing.T) {
	res, raw, err := ForHost("deploy@203.0.113.6", HostFlags{}, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), res.Engagement.Name, resumeStart)
	if err != nil {
		t.Fatal(err)
	}
	fail, calls := false, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	if _, err := Run(context.Background(), res, RunOptions{Raw: raw, Dir: dir, Started: resumeStart, Version: resumeVersion, Collect: collect}); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	out := resume(t, dir.Path, resumeVersion, collect)
	if calls["203.0.113.6"] != 1 || !out.Report.Run.Resumed || out.Report.Engagement.BuiltFrom != "host" {
		t.Errorf("collections %v, run %+v, built from %s", calls, out.Report.Run, out.Report.Engagement.BuiltFrom)
	}
}

// A resume reads the engagement file where the first session found it,
// whatever directory each later session is started from.
func TestResumeFromAnotherDirectory(t *testing.T) {
	fail, calls := false, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	first := t.TempDir()
	t.Chdir(first)
	if err := os.WriteFile("engagement.yaml", []byte(twoHosts), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Parse("engagement.yaml", []byte(twoHosts), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), "acme", resumeStart)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), res, RunOptions{Raw: []byte(twoHosts), Dir: dir, Started: resumeStart, Version: resumeVersion, Collect: collect}); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	t.Chdir(t.TempDir())
	resume(t, dir.Path, resumeVersion, collect)
	resume(t, dir.Path, resumeVersion, collect)
	// The file typed by a relative path is the same file read from its
	// absolute one: every completed host is kept from the first resume.
	for host, n := range calls {
		if n != 1 {
			t.Errorf("%s collected %d times", host, n)
		}
	}
	var m Manifest
	if err := readJSON(filepath.Join(dir.Path, manifestFile), &m); err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(filepath.Join(first, "engagement.yaml")); m.File != filepath.Join(first, "engagement.yaml") && m.File != want {
		t.Errorf("run.json file %q, want the first session's %s", m.File, filepath.Join(first, "engagement.yaml"))
	}
}

// A host is kept only from one session: an envelope written after the
// record that names it, as by a session cut between the two, keeps nothing.
func TestResumeKeepsNoHostMixedFromTwoSessions(t *testing.T) {
	fail, calls := false, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	_, dir, first := startRun(t, twoHosts, collect)
	env := "evidence/" + fileName(first.Report.Assets[1].Name) + ".json"
	var m Manifest
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil {
		t.Fatal(err)
	}
	m.Files[env] = sha([]byte("an envelope a later session wrote"))
	d, err := LockRunDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteJSON(manifestFile, m); err != nil {
		t.Fatal(err)
	}
	d.Close()
	resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.6"] != 2 || calls["203.0.113.5"] != 1 {
		t.Errorf("collections %v: only the host whose record and envelope agree is kept", calls)
	}
}

// An acceptance is read at the time its host was graded: one that expired
// between the session that failed to reach the host and the one that
// collected it says expired, as the finding it no longer covers is open.
func TestResumeGradesAcceptancesWhenTheHostWasCollected(t *testing.T) {
	file := twoHosts + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n" +
		"    - {id: fw.app_firewall_disabled, asset: deploy@203.0.113.5, reason: lab, accepted_by: alice, expires: 2026-10-08}\n"
	fail, calls := true, map[string]int{}
	collect := collectFirstFailsFrom(t, "macos", &fail, calls)
	_, dir, _ := startRun(t, file, collect)
	fail = false
	d, err := OpenRun(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPrior(d)
	if err != nil {
		t.Fatal(err)
	}
	res, raw, err := p.LoadEngagement(testOpts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Run(context.Background(), res, RunOptions{Raw: raw, Dir: d, Resume: p, Started: p.Manifest.Started,
		Session: resumeStart.Add(72 * time.Hour), Version: resumeVersion, Collect: collect})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Report.Acceptances) != 1 || out.Report.Acceptances[0].Outcome != "expired" {
		t.Errorf("acceptances %+v", out.Report.Acceptances)
	}
	found := false
	for _, f := range out.Report.Findings {
		if f.Key.ID == "fw.app_firewall_disabled" {
			found = true
			if f.Status != "open" {
				t.Errorf("the finding an expired acceptance covered is %s", f.Status)
			}
		}
	}
	if !found {
		t.Error("the macos fixture opens no fw.app_firewall_disabled")
	}
}

// A resume refuses a directory with a link in it, which a write would
// follow out of it, and one others may write to.
func TestResumeRefusesAnUnsafeDirectory(t *testing.T) {
	fail, calls := false, map[string]int{}
	_, dir, _ := startRun(t, twoHosts, collectFirstFails(t, &fail, calls))
	outside := filepath.Join(t.TempDir(), "bashrc")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.Rename(audit, audit+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, audit); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRun(dir); err == nil || !strings.Contains(err.Error(), "holds a link") {
		t.Errorf("a planted link: %v", err)
	}
	if err := os.Remove(audit); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(audit+".real", audit); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "evidence"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRun(dir); err == nil || !strings.Contains(err.Error(), "written by others") {
		t.Errorf("a world-writable directory: %v", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "x" {
		t.Error("the file a link pointed at was written")
	}
	if err := os.Chmod(filepath.Join(dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	// run.json names the file a resume reads: another user who may write
	// it could point the resume at an engagement of their own.
	for _, mode := range []os.FileMode{0o666, 0o620} {
		if err := os.Chmod(filepath.Join(dir, manifestFile), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRun(dir); err == nil || !strings.Contains(err.Error(), "written by others") {
			t.Errorf("run.json at %o: %v", mode, err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, manifestFile), 0o600); err != nil {
		t.Fatal(err)
	}

	// A hard link: the audit log's other name is outside the directory.
	if err := os.Remove(audit); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, audit); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRun(dir); err == nil || !strings.Contains(err.Error(), "another link") {
		t.Errorf("a hard link: %v", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "x" {
		t.Error("the file a hard link names was written")
	}
}

// A --host run's own engagement, edited since --host built it, is not
// resumed: it would read what --host never built.
func TestResumeRefusesAnEditedHostEngagement(t *testing.T) {
	res, raw, err := ForHost("deploy@203.0.113.6", HostFlags{}, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := CreateRunDir(t.TempDir(), res.Engagement.Name, resumeStart)
	if err != nil {
		t.Fatal(err)
	}
	fail, calls := false, map[string]int{}
	if _, err := Run(context.Background(), res, RunOptions{Raw: raw, Dir: dir, Started: resumeStart, Version: resumeVersion,
		Collect: collectFirstFails(t, &fail, calls)}); err != nil {
		t.Fatal(err)
	}
	widened := strings.Replace(string(raw), "roots:\n", "roots:\n  - host: root@203.0.113.9\n", 1)
	if widened == string(raw) {
		t.Fatalf("no roots: in\n%s", raw)
	}
	if err := dir.Write("engagement.yaml", []byte(widened)); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	d, err := OpenRun(dir.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, err := LoadPrior(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.LoadEngagement(testOpts); err == nil || !strings.Contains(err.Error(), "edited since") {
		t.Errorf("an edited --host engagement: %v", err)
	}
}

// A session that ended before recording what it sent makes the resumed
// report's egress counts "at least", naming when it started.
func TestResumeMarksAnUnrecordedSession(t *testing.T) {
	fail, calls := true, map[string]int{}
	collect := collectFirstFails(t, &fail, calls)
	_, dir, _ := startRun(t, twoHosts, collect)
	var m Manifest
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil {
		t.Fatal(err)
	}
	m.Sessions[0].Ended = false
	d, err := LockRunDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteJSON(manifestFile, m); err != nil {
		t.Fatal(err)
	}
	d.Close()
	fail = false
	out := resume(t, dir, resumeVersion, collect)
	if u := out.Report.Egress.Unrecorded; len(u) != 1 || !u[0].Equal(resumeStart) {
		t.Errorf("unrecorded sessions %v", u)
	}
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil || len(m.Sessions) != 2 || !m.Sessions[1].Ended {
		t.Errorf("run.json sessions %+v: %v", m.Sessions, err)
	}
}

// Only the gate records the run wrote are handed to the gate: one placed in
// evidence/requests by hand is not a success scheck had.
func TestResumeLoadsOnlyRecordedRequests(t *testing.T) {
	fail, calls := false, map[string]int{}
	_, dir, _ := startRun(t, twoHosts, collectFirstFails(t, &fail, calls))
	d, err := LockRunDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{o: RunOptions{Dir: d}}
	var m Manifest
	if err := readJSON(filepath.Join(dir, manifestFile), &m); err != nil {
		t.Fatal(err)
	}
	r.manifest = &m
	body := []byte(`{"Status":200,"Body":"PGh0bWw+"}`)
	if err := r.write(requestsDir+"aaaa.json", json.RawMessage(body)); err != nil {
		t.Fatal(err)
	}
	if err := d.Write(requestsDir+"bbbb.json", body); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPrior(d)
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Requests) != 1 || p.Requests["aaaa"] == nil || string(p.Requests["aaaa"].Body) != "<html>" {
		t.Errorf("requests %v", p.Requests)
	}
}

// Merging sessions' egress sums each source per host, so two resolvers stay
// two, keeps DNS first, and carries every session's host contacts.
func TestMergeEgress(t *testing.T) {
	into := &ereport.EgressInput{Sources: []ereport.SourceInput{
		{Source: "crt.sh", Host: "crt.sh", Sent: []string{"domain:b.example"}, Requests: 1},
	}}
	mergeEgress(into, &ereport.EgressInput{
		Sources: []ereport.SourceInput{
			{Source: "dns", Host: "192.168.1.1", Requests: 5},
			{Source: "crt.sh", Host: "crt.sh", Sent: []string{"domain:a.example"}, Requests: 2},
		},
		Contacts:    []ereport.HostContact{{ID: "host:203.0.113.5:22", Status: "failed", Contact: "connected"}},
		SSHResolved: []string{"build.example.com"},
	})
	mergeEgress(into, &ereport.EgressInput{Sources: []ereport.SourceInput{{Source: "dns", Host: "10.0.0.1", Requests: 3}}})
	var got []string
	for _, s := range into.Sources {
		got = append(got, fmt.Sprintf("%s@%s:%d:%v", s.Source, s.Host, s.Requests, s.Sent))
	}
	want := []string{"dns@192.168.1.1:5:[]", "dns@10.0.0.1:3:[]", "crt.sh@crt.sh:3:[domain:a.example domain:b.example]"}
	if !slices.Equal(got, want) {
		t.Errorf("sources %v, want %v", got, want)
	}
	if len(into.Contacts) != 1 || !slices.Equal(into.SSHResolved, []string{"build.example.com"}) {
		t.Errorf("contacts %v, ssh %v", into.Contacts, into.SSHResolved)
	}
}

// A host an earlier session reached and this one collected again counts
// both SSH sessions in what left this machine.
func TestResumeCountsEverySessionsContact(t *testing.T) {
	fail, calls := true, map[string]int{}
	inner := collectFirstFails(t, &fail, calls)
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		if o.Reach != nil {
			o.Reach.Dialled, o.Reach.Connected = true, true
		}
		return inner(ctx, o)
	}
	_, dir, first := startRun(t, twoHosts, collect)
	fail = false
	out := resume(t, dir, resumeVersion, collect)
	sessions := func(o *Outcome) int {
		for _, a := range o.Report.Egress.Assets {
			if a.Kind == "hosts" {
				return a.Sessions
			}
		}
		return 0
	}
	if sessions(first) != 2 || sessions(out) != 3 {
		t.Errorf("SSH sessions: %d first, %d after the resume, want 2 and 3", sessions(first), sessions(out))
	}
}

// A session that ends on an error after it reached a host still counts that
// contact: it ended, so its count is exact, and the next report has it.
func TestResumeCountsTheContactOfASessionThatFailed(t *testing.T) {
	fail, calls := true, map[string]int{}
	inner := collectFirstFails(t, &fail, calls)
	broken := false
	collect := func(ctx context.Context, o hostasset.Options) (*hostasset.Collection, error) {
		if o.Reach != nil {
			o.Reach.Dialled, o.Reach.Connected = true, true
		}
		if broken {
			return nil, errors.New("a stage error after the host was reached")
		}
		return inner(ctx, o)
	}
	_, dir, _ := startRun(t, twoHosts, collect) // 2 sessions; .5 is refused, .6 collected
	fail, broken = false, true
	if _, err := resumeErr(t, dir, resumeVersion, collect); err == nil {
		t.Fatal("the session did not fail")
	}
	broken = false
	out := resume(t, dir, resumeVersion, collect)
	for _, a := range out.Report.Egress.Assets {
		if a.Kind == "hosts" && a.Sessions != 4 {
			t.Errorf("SSH sessions %d, want 4: two, the failed session's one, and this one's", a.Sessions)
		}
	}
	if len(out.Report.Egress.Unrecorded) != 0 {
		t.Errorf("unrecorded %v: every session ended", out.Report.Egress.Unrecorded)
	}
}

// What a host was made to contact stays in the report after the host is
// collected again without the check: the earlier session ran it.
func TestResumeKeepsAnEarlierSessionsHostSideEffects(t *testing.T) {
	fail, calls := true, map[string]int{} // 203.0.113.5 never collected: ops is the only host that ran dnf
	collect := collectFirstFailsFrom(t, "fedora", &fail, calls)
	base := twoHosts + "assets:\n  ops:\n    host: 203.0.113.6\n"
	path, dir, first := startRun(t, base, collect)
	if !slices.Contains(first.Report.Egress.HostSideEffects, "pkg.dnf_check_update") {
		t.Fatalf("the first session's side effects %v", first.Report.Egress.HostSideEffects)
	}
	if err := os.WriteFile(path, []byte(base+"    disable_checks: [pkg.dnf_check_update]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := resume(t, dir, resumeVersion, collect)
	if calls["203.0.113.6"] != 2 {
		t.Fatalf("collections %v: the host was not collected again", calls)
	}
	if !slices.Contains(out.Report.Egress.HostSideEffects, "pkg.dnf_check_update") {
		t.Errorf("after the resume %v: the first session's dnf contact is gone", out.Report.Egress.HostSideEffects)
	}
}

func TestSessionSitesPreserveFirstPartyAdmission(t *testing.T) {
	sites := []gate.Site{
		{Asset: "domain:example.com", Name: "app.example.com", Requests: 2},
		{Asset: "domain:example.com", Name: "app.example.com", Requests: 3, FirstParty: true},
		{Asset: "url:https://app.example.com/", Name: "app.example.com", Requests: 1},
	}
	want := []ereport.SiteInput{{Name: "app.example.com", Requests: 3}, {Name: "app.example.com", Requests: 3, FirstParty: true}}
	for range 3 {
		got := sessionSites(sites)
		if !slices.Equal(got, want) {
			t.Fatal(got)
		}
		slices.Reverse(sites)
	}
	into := &ereport.EgressInput{Sites: sessionSites(sites)}
	mergeEgress(into, &ereport.EgressInput{Sites: []ereport.SiteInput{{Name: "app.example.com", Requests: 2}}})
	if len(into.Sites) != 2 || into.Sites[0].FirstParty || into.Sites[0].Requests != 5 || !into.Sites[1].FirstParty || into.Sites[1].Requests != 3 {
		t.Fatal(into.Sites)
	}
}
