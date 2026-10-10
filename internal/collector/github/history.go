package github

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

const HistoryVersion = "github-history:2026-10-10"
const OpHistoryHeads = "github.history_heads"
const OpHistoryPull = "github.history_pull_refs"
const OpMirror = "github.mirror_history"

func historyOps() []gate.Op {
	ops := []gate.Op{}
	for _, v := range []struct{ id, prefix string }{{OpHistoryHeads, "heads"}, {OpHistoryPull, "pull"}} {
		ops = append(ops, gate.Op{ID: v.id, Provider: "github", Method: gate.GET, Subject: "repo:github:{owner}/{repo}", Params: []gate.Param{{Name: "owner", Type: gate.Login}, {Name: "repo", Type: gate.RepoName}}, URL: "https://api.github.com/repos/{owner}/{repo}/git/matching-refs/" + v.prefix + "/", Level: gate.Observe, Auth: gate.GitHubToken, APIVersion: "2026-03-10", Accept: []string{"application/json", "application/vnd.github+json"}, MaxBytes: 1 << 20, Keep: []string{"ref", "object.type", "object.sha"}, List: &gate.List{Items: "$", Kind: gate.KindOther}})
	}
	return ops
}

type HistoryLocation struct {
	Commit   string `json:"commit"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Detector string `json:"detector"`
	Marker   string `json:"marker"`
}
type RepositoryHistory struct {
	Asset          string                  `json:"asset"`
	Read           Read                    `json:"read"`
	References     []Read                  `json:"references,omitempty"`
	RepositoryRead Read                    `json:"repository_read"`
	Visibility     *string                 `json:"visibility,omitempty"`
	Complete       bool                    `json:"complete"`
	RemoteKnown    bool                    `json:"remote_known"`
	RemoteMatches  []policy.SecretLocation `json:"remote_matches,omitempty"`
	Locations      []HistoryLocation       `json:"locations,omitempty"`
	Gaps           []string                `json:"gaps,omitempty"`
	Objects        int                     `json:"objects"`
	Commits        int                     `json:"commits"`
	Blobs          int                     `json:"blobs"`
	Redactions     []policy.Hit            `json:"redactions,omitempty"`
}
type mirrorSecurity interface {
	DetectMirrorCredentials([]byte) ([]policy.SecretLocation, bool)
	RedactMirrorName(string) (string, []policy.Hit)
	MirrorExtraRedactions([]byte) []policy.Hit
}
type mirrorScan struct {
	ctx                                        context.Context
	files                                      *gate.MirrorFiles
	result                                     *RepositoryHistory
	detect                                     func([]byte) ([]policy.SecretLocation, bool)
	redact                                     func(string) (string, []policy.Hit)
	extra                                      func([]byte) []policy.Hit
	packFiles                                  []mirrorPack
	indexReleases                              []func()
	entries, indexed, objects, commits, visits int
	expanded, resident                         int64
	pending                                    []string
	seenCommits                                map[string]bool
}

func (s *mirrorScan) check() error {
	if s.ctx.Err() != nil {
		return gate.ErrMirrorLimit
	}
	return nil
}
func (s *mirrorScan) gap(gap string) {
	s.result.Complete = false
	if !slices.Contains(s.result.Gaps, gap) {
		s.result.Gaps = append(s.result.Gaps, gap)
	}
}
func safeMirrorReason(err error) string {
	switch {
	case errors.Is(err, gate.ErrMirrorLimit):
		return "limit_reached"
	case errors.Is(err, errMirrorMismatch):
		return "mirror_remote_mismatch"
	case errors.Is(err, gate.ErrMirrorPath):
		return "unsafe_mirror_path"
	case errors.Is(err, errMirrorCorrupt):
		return "corrupt_mirror"
	case errors.Is(err, errMirrorChanged):
		return "mirror_changed"
	default:
		return "unsupported_or_unreadable_mirror"
	}
}

// CollectHistory never transports Git objects. Only advertised ref metadata goes
// through the API gate (docs/spec/github-collector.md, "Fresh reference comparison and resume").
func CollectHistory(ctx context.Context, g Sender, e Evidence, checkouts map[string]string) Evidence {
	for _, a := range e.RepositoriesAccess {
		r := RepositoryHistory{Asset: a.Asset, RepositoryRead: a.RepositoryRead, Complete: true}
		if a.Repository != nil {
			r.Visibility = a.Repository.Visibility
		}
		checkout := checkouts[a.Asset]
		if checkout == "" {
			r.Complete = false
			r.Gaps = []string{"mirror_not_declared"}
			e.RepositoriesHistory = append(e.RepositoriesHistory, r)
			continue
		}
		if a.Repository == nil || !usableRead(a.RepositoryRead) {
			r.Complete = false
			r.Gaps = []string{"repository_identity_unknown"}
			e.RepositoriesHistory = append(e.RepositoriesHistory, r)
			continue
		}
		refs := map[string]string{}
		fresh := true
		for _, op := range []string{OpHistoryHeads, OpHistoryPull} {
			result := g.Send(ctx, gate.Request{Op: op, Asset: a.Asset, Stage: "recon", Exists: true, Params: map[string]string{"owner": a.Repository.Owner.Login, "repo": a.Repository.Name}})
			read := readOf(op, result)
			r.References = append(r.References, read)
			var items []struct {
				Ref    string `json:"ref"`
				Object struct {
					Type string `json:"type"`
					SHA  string `json:"sha"`
				} `json:"object"`
			}
			if !usableRead(read) || result.Response.Population == nil || result.Response.Population.More || len(result.Response.Population.Incomplete) > 0 || string(result.Response.Body) == "null" || json.Unmarshal(result.Response.Body, &items) != nil {
				fresh = false
				continue
			}
			prefix := "refs/heads/"
			if op == OpHistoryPull {
				prefix = "refs/pull/"
			}
			if len(items) > 10000 {
				fresh = false
				r.Gaps = append(r.Gaps, "limit_reached")
				continue
			}
			for _, item := range items {
				if !refOK(item.Ref) || !strings.HasPrefix(item.Ref, prefix) || item.Object.Type != "commit" || !fullSHA.MatchString(item.Object.SHA) {
					fresh = false
					continue
				}
				if _, duplicate := refs[item.Ref]; duplicate {
					fresh = false
				}
				refs[item.Ref] = strings.ToLower(item.Object.SHA)
			}
		}
		if !fresh {
			r.Complete = false
			r.Gaps = append(r.Gaps, "advertised_refs_unavailable")
		}
		r = readMirror(ctx, g, r, checkout, refs)
		e.RepositoriesHistory = append(e.RepositoriesHistory, r)
	}
	return e
}
func readMirror(ctx context.Context, g Sender, r RepositoryHistory, checkout string, advertised map[string]string) RepositoryHistory {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	r.Read = Read{Op: OpMirror, RequestID: OpMirror + ":" + r.Asset, Decision: "sent", Status: 200, ObservedAt: time.Now().UTC()}
	files, err := gate.OpenMirror(checkout)
	if err != nil {
		r.Complete = false
		r.Gaps = append(r.Gaps, safeMirrorReason(err))
		r.Read.Gap = safeMirrorReason(err)
		r.Read.Detail = safeMirrorReason(err)
		r.Read.Reason = "refused"
		r.Read.Kind = "mirror"
		r.Read.Decision = "refused:mirror"
		return r
	}
	defer func() { _ = files.Close() }()
	redactor, _ := policy.NewRedactor(nil)
	s := mirrorScan{ctx: ctx, files: files, result: &r, detect: func(b []byte) ([]policy.SecretLocation, bool) { return policy.SecretLocations(b, "") }, redact: redactor.RedactString, seenCommits: map[string]bool{}}
	if security, ok := g.(mirrorSecurity); ok {
		s.detect = security.DetectMirrorCredentials
		s.redact = security.RedactMirrorName
		s.extra = security.MirrorExtraRedactions
	}
	finish := func(err error) RepositoryHistory {
		r.Objects = s.objects
		r.Commits = s.commits
		if err != nil {
			s.gap(safeMirrorReason(err))
			r.Read.Gap = safeMirrorReason(err)
			r.Read.Detail = safeMirrorReason(err)
			r.Read.Decision = "unavailable:mirror"
			r.Read.Reason = "failed"
			if errors.Is(err, errMirrorMismatch) || errors.Is(err, gate.ErrMirrorPath) {
				r.Read.Decision = "refused:mirror"
				r.Read.Reason = "refused"
				r.Read.Kind = "mirror"
			}
			if errors.Is(err, gate.ErrMirrorLimit) {
				r.Read.Reason = "limit_reached"
			}
		}
		r.Read.Redactions = append(r.Read.Redactions, r.Redactions...)
		return r
	}
	defer func() {
		for _, release := range s.indexReleases {
			release()
		}
	}()
	config, err := s.files.Read("config", 64<<10)
	if err != nil {
		return finish(err)
	}
	hits, err := parseMirrorConfig(config, r.Asset, s.detect)
	if err != nil {
		return finish(err)
	}
	r.RemoteKnown = true
	r.RemoteMatches = hits
	for _, hit := range hits {
		r.Redactions = append(r.Redactions, policy.Hit{Rule: hit.Rule, Bytes: hit.Bytes})
	}
	before, err := s.metadata()
	if err != nil {
		return finish(err)
	}
	defer before.release()
	if !bytes.Equal(config, before.config) {
		return finish(errMirrorChanged)
	}
	for name, sha := range advertised {
		if before.refs[name] != sha {
			s.gap("mirror_refs_differ")
		}
	}
	if err = s.packs(); err != nil {
		return finish(err)
	}
	names := slices.Sorted(maps.Values(before.refs))
	names = slices.Compact(names)
	// Reserve the bounded worklist and visited-commit bookkeeping up front.
	releaseWork, err := s.reserve(200000*128 + 20000*128)
	if err != nil {
		return finish(err)
	}
	defer releaseWork()
	s.pending = names
	for len(s.pending) > 0 {
		id := s.pending[len(s.pending)-1]
		s.pending = s.pending[:len(s.pending)-1]
		if err = s.visitCommit(id, 0, map[string]bool{}); err != nil {
			s.gap(safeMirrorReason(err))
			if errors.Is(err, gate.ErrMirrorLimit) {
				return finish(err)
			}
		}
		if len(s.pending) > 200000 {
			return finish(gate.ErrMirrorLimit)
		}
	}
	after, err := s.metadata()
	if err != nil {
		return finish(err)
	}
	defer after.release()
	if !sameMetadata(before, after) {
		return finish(errMirrorChanged)
	}
	return finish(nil)
}
func (s *mirrorScan) visitCommit(id string, tagDepth int, tagActive map[string]bool) error {
	id = strings.ToLower(id)
	if s.seenCommits[id] {
		return nil
	}
	if tagDepth > 16 {
		return gate.ErrMirrorLimit
	}
	if tagActive[id] {
		return errMirrorCorrupt
	}
	o, err := s.object(id, 0, map[string]bool{})
	if err != nil {
		return err
	}
	defer func() { o.release() }()
	if o.kind == "tag" {
		tagActive[id] = true
		defer delete(tagActive, id)
		header, _, _ := bytes.Cut(o.data, []byte("\n\n"))
		target := ""
		typ := ""
		for line := range strings.SplitSeq(string(header), "\n") {
			if strings.HasPrefix(line, "object ") {
				if target != "" {
					return errMirrorCorrupt
				}
				target = line[7:]
			}
			if strings.HasPrefix(line, "type ") {
				typ = line[5:]
			}
		}
		if !fullSHA.MatchString(target) || !slices.Contains([]string{"commit", "tag"}, typ) {
			return errMirrorFormat
		}
		return s.visitCommit(target, tagDepth+1, tagActive)
	}
	if o.kind != "commit" {
		return errMirrorFormat
	}
	s.commits++
	if s.commits > 20000 {
		return gate.ErrMirrorLimit
	}
	s.seenCommits[id] = true
	header, _, has := bytes.Cut(o.data, []byte("\n\n"))
	if !has {
		return errMirrorCorrupt
	}
	tree := ""
	parents := []string{}
	for line := range strings.SplitSeq(string(header), "\n") {
		if strings.HasPrefix(line, "tree ") {
			if tree != "" {
				return errMirrorCorrupt
			}
			tree = line[5:]
		}
		if strings.HasPrefix(line, "parent ") {
			if !fullSHA.MatchString(line[7:]) {
				return errMirrorCorrupt
			}
			// The worklist must not retain an entire commit header via a substring.
			parents = append(parents, strings.Clone(line[7:]))
		}
	}
	if !fullSHA.MatchString(tree) {
		return errMirrorCorrupt
	}
	if err = s.visitTree(tree, id, "", 0, map[string]bool{}); err != nil {
		return err
	}
	// Release commit bytes before walking parents, keeping history depth bounded
	// independently of the number of ancestors.
	dataRelease := o.release
	o.release = func() {}
	dataRelease()
	// Iterative parent queue is driven by the top-level worklist (below).
	s.pending = append(s.pending, parents...)
	return nil
}
func (s *mirrorScan) visitTree(id, commit, prefix string, depth int, active map[string]bool) error {
	if depth > 128 {
		return gate.ErrMirrorLimit
	}
	if active[id] {
		return errMirrorCorrupt
	}
	active[id] = true
	defer delete(active, id)
	o, err := s.object(id, 0, map[string]bool{})
	if err != nil {
		return err
	}
	defer func() { o.release() }()
	if o.kind != "tree" {
		return errMirrorCorrupt
	}
	data := o.data
	seen := map[string]bool{}
	var seenBytes int64
	defer func() { s.resident -= seenBytes }()
	for len(data) > 0 {
		if err = s.check(); err != nil {
			return err
		}
		s.visits++
		if s.visits > 250000 {
			return gate.ErrMirrorLimit
		}
		header, tail, ok := bytes.Cut(data, []byte{0})
		if !ok || len(tail) < 20 {
			return errMirrorCorrupt
		}
		mode, name, ok := strings.Cut(string(header), " ")
		if !ok || name == "" || name == "." || name == ".." || strings.Contains(name, "/") || !utf8.ValidString(name) || strings.ContainsAny(name, "\\") || strings.ContainsFunc(name, unicode.IsControl) || seen[name] {
			return errMirrorFormat
		}
		// Bound the full path before allocating it (fixed reader budgets).
		if len(prefix)+len(name)+1 > 4096 {
			return gate.ErrMirrorLimit
		}
		charge := int64(len(name) + 128)
		if _, err = s.reserve(charge); err != nil {
			return err
		}
		seenBytes += charge
		seen[name] = true
		fullPath := path.Join(prefix, name)
		object := hex.EncodeToString(tail[:20])
		data = tail[20:]
		switch mode {
		case "40000", "040000":
			if err = s.visitTree(object, commit, fullPath, depth+1, active); err != nil {
				return err
			}
		case "160000":
			s.gap("submodule_content_unassessed")
		case "100644", "100755", "120000":
			if err = s.visitBlob(object, commit, fullPath); err != nil {
				return err
			}
		default:
			return errMirrorFormat
		}
	}
	return nil
}
func (s *mirrorScan) visitBlob(id, commit, name string) error {
	o, err := s.object(id, 0, map[string]bool{})
	if err != nil {
		return err
	}
	defer func() { o.release() }()
	if o.kind != "blob" {
		return errMirrorCorrupt
	}
	s.result.Blobs++
	if bytes.HasPrefix(o.data, []byte("version https://git-lfs.github.com/spec/v1\n")) {
		s.gap("lfs_payload_unassessed")
	}
	// Bounded regex candidate arrays and safe detector results are transient.
	detectorRelease, err := s.reserve(32 << 20)
	if err != nil {
		return err
	}
	defer detectorRelease()
	hits, detectorComplete := s.detect(o.data)
	if s.extra != nil {
		extra := s.extra(o.data)
		if _, err = s.reserve(int64(len(extra)) * 128); err != nil {
			return err
		}
		s.result.Redactions = append(s.result.Redactions, extra...)
		if len(extra) > 10000 {
			return gate.ErrMirrorLimit
		}
	}
	safeName, redactions := s.redact(name)
	if _, err = s.reserve(int64(len(redactions)) * 128); err != nil {
		return err
	}
	s.result.Redactions = append(s.result.Redactions, redactions...)
	if len(hits) > 0 && (len(redactions) > 0 || safeName != name) {
		s.gap("history_path_redacted")
		return nil
	}
	for _, hit := range hits {
		if len(s.result.Locations) >= 10000 {
			return gate.ErrMirrorLimit
		}
		if _, err = s.reserve(int64(len(name) + len(hit.Marker) + len(hit.Rule) + 512)); err != nil {
			return err
		}
		s.result.Locations = append(s.result.Locations, HistoryLocation{commit, name, hit.Line, hit.Rule, hit.Marker})
		s.result.Redactions = append(s.result.Redactions, policy.Hit{Rule: hit.Rule, Bytes: hit.Bytes})
	}
	if !detectorComplete {
		return gate.ErrMirrorLimit
	}
	return nil
}
func JudgeHistory(e Evidence) []Judgment {
	out := []Judgment{}
	for _, r := range e.RepositoriesHistory {
		reads := []string{}
		if r.Read.Op != "" {
			reads = append(reads, r.Read.RequestID)
		}
		for _, read := range r.References {
			reads = append(reads, read.RequestID)
		}
		base := func(id string, subject *Subject) Judgment {
			j := judgment(id, r.Asset, subject, reads)
			j.NotChecked = []string{"Unadvertised or deleted refs, GitHub objects served only by SHA, unreachable objects, reflogs, submodule and LFS payloads remain unassessed", "Credential usability, revocation and detector misses were not tested"}
			return j
		}
		remote := base(finding.IDGitHubRemoteCredential, &Subject{Kind: "secret_location", Key: "remote:origin", Label: "mirror origin configuration"})
		if r.Read.Op != "" {
			remote.Reads = []string{r.Read.RequestID}
		}
		markers := []string{}
		for _, m := range r.RemoteMatches {
			markers = append(markers, m.Marker)
		}
		remote.Details = map[string]any{"markers": strings.Join(markers, " ")}
		remoteExcerpt := "Supported matching mirror origin contains no recognized credential"
		if len(markers) > 0 {
			remoteExcerpt = "Recognized credential-bearing mirror origin userinfo or pattern; no URL retained. " + strings.Join(markers, " ")
		}
		if !r.RemoteKnown {
			remoteExcerpt = "Mirror origin admission is unavailable; no absence claim"
		}
		settle(&remote, len(markers) > 0, r.RemoteKnown, remoteExcerpt)
		out = append(out, remote)
		for _, loc := range r.Locations {
			key := fmt.Sprintf("history:%s:%s:%d:%s", loc.Commit, url.PathEscape(loc.Path), loc.Line, loc.Detector)
			j := base(finding.IDGitHubHistoryCredential, &Subject{Kind: "secret_location", Key: key, Label: fmt.Sprintf("%s:%d at %s", loc.Path, loc.Line, loc.Commit)})
			settle(&j, true, true, fmt.Sprintf("%s:%d at commit %s: %s", loc.Path, loc.Line, loc.Commit, loc.Marker))
			j.Details = map[string]any{"commit": loc.Commit, "path": loc.Path, "line": loc.Line, "detector": loc.Detector, "marker": loc.Marker}
			if usableRead(r.RepositoryRead) && r.Visibility != nil && *r.Visibility == "public" {
				j.Attributes = []string{"observed_public"}
				j.Details["repository_read"] = r.RepositoryRead.RequestID
				j.Details["repository_visibility"] = "public"
				j.Excerpt += " Observed repository visibility: public."
			}
			out = append(out, j)
		}
		if len(r.Locations) == 0 || !r.Complete {
			j := base(finding.IDGitHubHistoryCredential, nil)
			settle(&j, false, r.Complete, "No recognized credential pattern found in the supported mirror history read")
			if !r.Complete {
				j.Excerpt = "Mirror history remains partially read or unavailable; no absence claim."
				j.NotChecked = append(j.NotChecked, "Mirror gaps: "+HistoryGapText(r.Gaps))
			}
			out = append(out, j)
		}
	}
	return out
}

// HistoryGapText exposes only compiled, actionable explanations.
func HistoryGapText(gaps []string) string {
	descriptions := map[string]string{
		"mirror_not_declared":              "No mirror checkout was declared; provide an authorized bare mirror to read history",
		"repository_identity_unknown":      "Repository identity could not be verified; obtain the authorized repository read access and resume",
		"advertised_refs_unavailable":      "Advertised branch/pull refs could not be read; authorize repository Contents read and resume",
		"mirror_refs_differ":               "Mirror refs differ from the observed GitHub refs; update your authorized mirror and resume",
		"unsafe_mirror_path":               "Mirror file access was refused because a path or file was unsafe; use a regular, confined bare mirror",
		"mirror_remote_mismatch":           "Mirror origin does not match this repository; provide the matching authorized mirror",
		"unsupported_or_unreadable_mirror": "Mirror format is unsupported or its files could not be read; provide a supported SHA-1 bare mirror",
		"corrupt_mirror":                   "A mirror object or reference could not be validated; recreate your authorized mirror and resume",
		"mirror_changed":                   "Mirror configuration or refs changed during reading; stop concurrent mirror updates and resume",
		"limit_reached":                    "A compiled history-read limit stopped collection; retained findings remain valid and unread history remains unassessed",
		"unsupported_mirror_layout":        "Shallow, alternate or other unsupported mirror metadata prevents complete coverage",
		"replacement_refs_unassessed":      "Replacement references were ignored; affected history remains unassessed",
		"promisor_objects_unassessed":      "Partial-clone objects were not fetched; unread history remains unassessed",
		"submodule_content_unassessed":     "Submodule repositories were not followed or read",
		"lfs_payload_unassessed":           "Git LFS payloads were not followed or read",
		"history_path_redacted":            "A matched credential's path was redacted, so no stable safe finding location could be retained",
	}
	if len(gaps) == 0 {
		return "none in the supported traversal"
	}
	out := []string{}
	for _, gap := range gaps {
		if text := descriptions[gap]; text != "" {
			out = append(out, text)
		} else {
			out = append(out, "Some mirror evidence could not be interpreted; unread history remains unassessed")
		}
	}
	return strings.Join(out, "; ")
}
