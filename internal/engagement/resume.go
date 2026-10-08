package engagement

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
)

// manifestFile is the run's own record of itself: what a resume reads
// first (docs/spec/engagement.md, "Stop and resume").
const manifestFile = "run.json"

// requestsDir holds the gate's successes a resume may reuse, one file per
// request identity.
const requestsDir = "evidence/requests/"

// Manifest is run.json: where the engagement file is, its hash, each
// session of the run, and the hash of every file a stage wrote, so a resume
// can tell a file edited by hand.
type Manifest struct {
	Started time.Time `json:"started"`
	Source  Source    `json:"source"`
	// File is the engagement file's absolute path, which a resume reads
	// again; Host marks a run --host built instead, whose file is the
	// directory's engagement.yaml.
	File     string    `json:"file,omitempty"`
	Host     bool      `json:"host,omitempty"`
	Sessions []Session `json:"sessions"`
	// Files maps each file a stage wrote, relative to the directory, to the
	// sha256 of the bytes written.
	Files map[string]string `json:"files"`
	// ScopeInputs fingerprints what Scope read; its document is kept on a
	// resume only while they match.
	ScopeInputs string `json:"scope_inputs,omitempty"`
}

// Session is one invocation of the run: its start, the build, and what
// left this machine during it, once it ended.
type Session struct {
	Started time.Time `json:"started"`
	Version string    `json:"version"`
	// Egress is what the session sent, recorded after each stage and when
	// it ended; Ended says it lived to record the last of it.
	Egress *ereport.EgressInput `json:"egress,omitempty"`
	Ended  bool                 `json:"ended"`
}

// Prior is what earlier sessions of a run left that a resume may keep.
type Prior struct {
	Manifest Manifest
	Scope    *ScopeDoc
	// Requests are the gate's earlier successes, by identity.
	Requests map[string]*gate.Response
	// dir is the run directory, read as each file is used.
	dir *RunDir
}

// hostRecord is evidence/<asset>.collection.json: one session's host
// collection as Recon recorded it, beyond its envelope, with the
// fingerprint of what it read from the file and the hash of the envelope
// that session wrote. A host is kept only from one record, so nothing in it
// mixes two sessions.
type hostRecord struct {
	Inputs   string              `json:"inputs"`
	Graded   time.Time           `json:"graded"`
	Envelope string              `json:"envelope_sha256"`
	Recon    ReconAsset          `json:"recon"`
	Planned  []string            `json:"planned"`
	Trace    []policy.AuditEntry `json:"trace"`
}

// OpenRun locks a run directory to resume it, or says why it cannot be.
func OpenRun(path string) (*RunDir, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a run directory", path)
	}
	// The path typed may reach the directory through a link; what is
	// checked and written is the directory itself.
	abs, err := filepath.EvalSymlinks(path)
	if err == nil {
		abs, err = filepath.Abs(abs)
	}
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, manifestFile)); err != nil {
		return nil, fmt.Errorf("%s has no %s: it is not a run directory, or an earlier build wrote it and it cannot be resumed", path, manifestFile)
	}
	if err := checkRunDir(abs); err != nil {
		return nil, err
	}
	return LockRunDir(abs)
}

// checkRunDir refuses a directory scheck did not leave as it writes one:
// a link inside it, which a write would follow out of it, anything but
// directories and regular files, or a file or directory others may write
// to: run.json names the file a resume reads and contacts the hosts of. A
// directory received from someone else is the case it is for.
func checkRunDir(root string) error {
	// The directory it sits in too: another user who may write there
	// could swap the run directory itself.
	parent := filepath.Dir(root)
	if info, err := os.Lstat(parent); err != nil {
		return err
	} else if err := owned(parent, info); err != nil {
		return fmt.Errorf("cannot resume %s: %w", root, err)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		t := d.Type()
		switch {
		case t&fs.ModeSymlink != 0:
			return fmt.Errorf("%s holds a link, %s: scheck writes no links into a run directory and will not follow one", root, rel)
		case !d.IsDir() && !t.IsRegular():
			return fmt.Errorf("%s holds %s, which is not a regular file", root, rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if err := owned(rel, info); err != nil {
			return fmt.Errorf("cannot resume %s: %w", root, err)
		}
		return nil
	})
}

// LoadPrior reads what a locked run directory's earlier sessions left. A
// file missing or unreadable is not kept, and what depends on it is read
// again; only the manifest is required.
func LoadPrior(dir *RunDir) (*Prior, error) {
	var m Manifest
	if err := readJSON(dir.File(manifestFile), &m); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestFile, err)
	}
	if m.Files == nil {
		m.Files = map[string]string{}
	}
	p := &Prior{Manifest: m, Requests: map[string]*gate.Response{}, dir: dir}
	var scope ScopeDoc
	if readJSON(dir.File("scope.json"), &scope) == nil {
		p.Scope = &scope
	}
	// Only the records the run wrote: one placed there by hand is not
	// a success scheck had.
	for name := range m.Files {
		id, ok := strings.CutPrefix(name, requestsDir)
		if !ok {
			continue
		}
		id, ok = strings.CutSuffix(id, ".json")
		var resp gate.Response
		if ok && !strings.ContainsAny(id, `/\.`) && readJSON(dir.File(name), &resp) == nil {
			p.Requests[id] = &resp
		}
	}
	return p, nil
}

// Dir is the locked run directory.
func (p *Prior) Dir() *RunDir { return p.dir }

// LoadEngagement reads the engagement a run directory was started from:
// the file at its recorded path, or for --host the directory's own copy,
// which --host writes unmasked since it sets no redact_extra. The file may
// have changed since; the resume compares what each stage read.
func (p *Prior) LoadEngagement(opts Options) (*Resolved, []byte, error) {
	m := p.Manifest
	// Read from where the first session found the file, under the name it
	// gave it: every source an input cites (a host's context, an accepted
	// risk) then reads as it did, and a completed host is kept.
	path, name := m.File, m.Source.Path
	if name == "" {
		name = m.File
	}
	if m.Host {
		// --host built this file, and only it: one edited since would
		// change what the run reads under a header that says --host built
		// it.
		if p.edited("engagement.yaml") {
			return nil, nil, errors.New("the engagement --host built for this run was edited since: start a new run with scheck run --host")
		}
		path, name = p.dir.File("engagement.yaml"), hostSource
	}
	if !filepath.IsAbs(path) {
		return nil, nil, fmt.Errorf("%s names no engagement file by its absolute path", manifestFile)
	}
	// A regular file only: a device or a pipe would never end the read.
	if st, err := os.Stat(path); err != nil {
		return nil, nil, fmt.Errorf("the engagement file this run was started from: %w", err)
	} else if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("the engagement file this run was started from, %s, is not a regular file", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("the engagement file this run was started from: %w", err)
	}
	res, err := Parse(name, raw, opts)
	if err != nil {
		return nil, nil, err
	}
	res.fromHost = m.Host
	// The directory sits under the engagement's name: another name is
	// another engagement, not this run resumed.
	if want := filepath.Base(filepath.Dir(p.dir.Path)); res.Engagement.Name != want {
		return nil, nil, fmt.Errorf("the engagement file now names %q, not %q: start a new run", res.Engagement.Name, want)
	}
	return res, raw, nil
}

// edited says whether a file the resume uses differs from what the run
// wrote: changed, or never written by it.
func (p *Prior) edited(name string) bool {
	b, err := os.ReadFile(p.dir.File(name))
	if err != nil {
		return false
	}
	return p.Manifest.Files[name] != sha(b)
}

// scopeInputs fingerprints what the Scope stage reads from the file, with
// the build, and each asset's first-party evidence at the session's time,
// so a confirmation that expired since runs Scope again. An unknown build
// has none, so its Scope is always run again.
func scopeInputs(res *Resolved, version string, at time.Time) string {
	if !gate.KnownBuild(version) {
		return ""
	}
	var evidence []any
	for _, a := range res.Assets {
		evidence = append(evidence, res.firstParty(a, at))
	}
	return fingerprint(struct {
		Version       string
		Roots         []Ref
		Exclude       []Ref
		Defaults      EffectiveDefaults
		Assets        []ResolvedAsset
		RedactExtra   []string
		Mail          Mail
		Intent        Intent
		Authorization *Authorization
		FirstParty    []any
	}{version, res.Roots, res.Exclude, res.Defaults, res.Assets, res.RedactExtra(), res.Mail, res.Intent, res.Authorization, evidence})
}

// complete says Scope found no gap a resume should try to close: every
// certificate transparency answer read, every name checked.
func (d *ScopeDoc) complete() bool {
	for _, dom := range d.Domains {
		if dom.CT != "ok" {
			return false
		}
		for _, n := range dom.Names {
			if n.Status == NameInsufficient || n.Status == NameNotChecked {
				return false
			}
		}
	}
	return true
}

func fingerprint(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return sha(b)
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// mergeEgress adds what one session sent to what the others did: a
// resumed run's "What left this machine" covers every earlier session, as
// far as each recorded it.
func mergeEgress(into, from *ereport.EgressInput) {
	if from == nil {
		return
	}
	// One entry per source and host: a session on another network asked
	// another DNS resolver.
	for _, s := range from.Sources {
		i := slices.IndexFunc(into.Sources, func(x ereport.SourceInput) bool { return x.Source == s.Source && x.Host == s.Host })
		if i < 0 {
			s.Sent, s.Credentials = slices.Clone(s.Sent), slices.Clone(s.Credentials)
			into.Sources = append(into.Sources, s)
			continue
		}
		t := &into.Sources[i]
		t.Sent = union(t.Sent, s.Sent)
		t.Credentials = union(t.Credentials, s.Credentials)
		t.Requests += s.Requests
		t.RootControls += s.RootControls
		t.InvalidControl = t.InvalidControl || s.InvalidControl
		t.ScopedResolversIgnored = t.ScopedResolversIgnored || s.ScopedResolversIgnored
	}
	// DNS first, as the gate lists it.
	slices.SortStableFunc(into.Sources, func(a, b ereport.SourceInput) int {
		return cmp.Compare(boolInt(a.Source != "dns"), boolInt(b.Source != "dns"))
	})
	into.Contacts = append(into.Contacts, from.Contacts...)
	for _, s := range from.Sites {
		i := slices.IndexFunc(into.Sites, func(x ereport.SiteInput) bool { return x.Name == s.Name })
		if i < 0 {
			into.Sites = append(into.Sites, s)
			continue
		}
		into.Sites[i].Requests += s.Requests
		into.Sites[i].FirstParty = into.Sites[i].FirstParty || s.FirstParty
	}
	into.SSHResolved = union(into.SSHResolved, from.SSHResolved)
	into.SSHResolvedByJump = union(into.SSHResolvedByJump, from.SSHResolvedByJump)
	into.Tenants = union(into.Tenants, from.Tenants)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func union(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// openManifest starts this session in run.json: a new run's first, or the
// next of a resumed one.
func (r *run) openManifest() error {
	if p := r.o.Resume; p != nil {
		m := p.Manifest
		m.Files = maps.Clone(m.Files)
		m.Sessions = slices.Clone(m.Sessions)
		r.manifest = &m
	} else {
		r.manifest = &Manifest{Started: r.o.Started.UTC(), Files: map[string]string{}}
	}
	r.manifest.Source = r.res.Source
	// A resume reads the file where the first session found it: its
	// path as typed is relative to that session's directory, not this one's.
	r.manifest.Host = r.res.fromHost
	if r.o.Resume == nil && !r.res.fromHost {
		abs, err := filepath.Abs(r.res.Source.Path)
		if err != nil {
			return fmt.Errorf("run directory: %w", err)
		}
		r.manifest.File = abs
	}
	r.manifest.Sessions = append(r.manifest.Sessions, Session{Started: r.session.UTC(), Version: r.o.Version})
	return r.saveManifest()
}

func (r *run) saveManifest() error {
	b, err := json.MarshalIndent(r.manifest, "", "  ")
	if err != nil {
		return err
	}
	return r.o.Dir.Write(manifestFile, append(b, '\n'))
}

// closeSession records what this session sent, for the reports of the
// sessions after it.
func (r *run) closeSession() {
	s := &r.manifest.Sessions[len(r.manifest.Sessions)-1]
	s.Egress, s.Ended = r.sessionEgress(), true
	if err := r.saveManifest(); err != nil {
		r.o.Log("run directory: %s: %v", manifestFile, err)
	}
}

// keepRequests writes the gate's successes a later resume may reuse, and
// what this session has sent so far: a session cut later still leaves it.
func (r *run) keepRequests() error {
	if r.o.Dir == nil {
		return nil
	}
	r.manifest.Sessions[len(r.manifest.Sessions)-1].Egress = r.sessionEgress()
	if err := r.saveManifest(); err != nil {
		return fmt.Errorf("run directory: %s: %w", manifestFile, err)
	}
	if r.gate == nil {
		return nil
	}
	for _, id := range r.gate.Reused() {
		r.used(requestsDir + id + ".json")
	}
	// Successes holds only what this session sent and kept, never what it
	// reused, so a record that could not be reused is replaced.
	for id, resp := range r.gate.Successes() {
		name := requestsDir + id + ".json"
		if err := r.write(name, resp); err != nil {
			return err
		}
	}
	return nil
}

// used notes that the resume used a file an earlier session wrote; one
// edited since is named in the report.
func (r *run) used(name string) {
	if p := r.o.Resume; p != nil && p.edited(name) && !slices.Contains(r.edited, name) {
		r.edited = append(r.edited, name)
	}
}

// hostInputs fingerprints what a host collection reads from the file and
// the build: reach, profile, elevation, narrowing, redaction and context,
// accepted risks included, and the excludes its dial is checked against. A
// completed host is kept on resume only while they match, since nothing
// regrades a kept envelope; an unknown build has none, so it keeps no
// host.
func hostInputs(o hostasset.Options, exclude []Ref, version string) string {
	if !gate.KnownBuild(version) {
		return ""
	}
	var risks []any
	if o.Context != nil {
		// The zone too: an acceptance's expiry is graded in
		// engagement.timezone, and a Location marshals as {}.
		for _, k := range o.Context.AcceptedRisks {
			risks = append(risks, []string{k.ID, k.Reason, k.Expires, k.Source, k.Zone.String()})
		}
	}
	return fingerprint(struct {
		Version                                            string
		Local                                              bool
		Host, User, Identity, KnownHosts, Elevate, Profile string
		Port                                               int
		Jump                                               *hostasset.Hop
		DisableChecks, DenyPaths, RedactExtra              []string
		RunTimeout                                         time.Duration
		Context                                            *operator.Structured
		Risks                                              []any
		ContextSource                                      string
		Exclude                                            []Ref
	}{version, o.Local, o.Host, o.User, o.Identity, o.KnownHosts, o.Elevate, o.Profile, o.Port, o.Jump,
		o.DisableChecks, o.DenyPaths, o.RedactExtra, o.RunTimeout, o.Context, risks, o.ContextSource, exclude})
}

// keptHost is a host an earlier session collected completely, under the
// same inputs: kept as a unit, never contacted again. Its record and
// envelope must be one session's: the envelope scheck last wrote is the one
// the record names, so a session cut between the two writes keeps nothing.
func (r *run) keptHost(a ResolvedAsset, inputs string) (ReconAsset, bool) {
	p := r.o.Resume
	if p == nil || inputs == "" {
		return ReconAsset{}, false
	}
	name := fileName(a.Name)
	envFile, recFile := "evidence/"+name+".json", "evidence/"+name+".collection.json"
	var rec hostRecord
	var env report.Envelope
	raw, err := os.ReadFile(p.dir.File(envFile))
	if err != nil || readJSON(p.dir.File(recFile), &rec) != nil || json.Unmarshal(raw, &env) != nil {
		return ReconAsset{}, false
	}
	// The envelope on disk must be the one this record's session wrote and
	// run.json last recorded: a host's envelope is never used as written,
	// since one edited, or written by a session cut before it recorded
	// it, would pair with another session's facts and trace. A host costs
	// seconds to collect again.
	if rec.Inputs != inputs || rec.Recon.Status != StatusCollected || rec.Recon.Name != a.Name || rec.Recon.ID != a.ID ||
		rec.Envelope == "" || rec.Envelope != p.Manifest.Files[envFile] || rec.Envelope != sha(raw) {
		return ReconAsset{}, false
	}
	// The report embeds the envelope as a fresh collection's: without
	// the path it was written to.
	env.Run.Persisted = nil
	c, err := hostasset.Restore(env, rec.Planned)
	if err != nil {
		return ReconAsset{}, false
	}
	r.o.Log("recon: %s kept from an earlier session", a.Name)
	r.used(recFile)
	r.hosts[a.Name], r.traces[a.Name], r.graded[a.Name], r.kept[a.Name] = c, rec.Trace, rec.Graded, true
	return rec.Recon, true
}

// recordHost writes what a resume needs to keep a host: its envelope and
// its record.
func (r *run) recordHost(a ResolvedAsset, c *hostasset.Collection, inputs string, ra ReconAsset) error {
	if r.o.Dir == nil {
		return nil
	}
	name := fileName(a.Name)
	env := c.Envelope()
	path := r.o.Dir.File("evidence/" + name + ".json")
	env.Run.Persisted = &path
	if err := r.write("evidence/"+name+".json", env); err != nil {
		return err
	}
	return r.write("evidence/"+name+".collection.json", hostRecord{Inputs: inputs, Graded: r.session.UTC(), Envelope: r.manifest.Files["evidence/"+name+".json"],
		Recon: ra, Planned: c.Planned(), Trace: r.traces[a.Name]})
}
