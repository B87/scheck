package github

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

const historyAsset = "repo:github:acme/shop"

type historySender struct {
	head            string
	refCount        int
	changed, denied bool
	calls           []string
	literal         string
	extra           []string
}

func (h *historySender) Send(_ context.Context, r gate.Request) gate.Result {
	h.calls = append(h.calls, r.Op)
	if h.denied {
		return gate.Result{Decision: "unavailable:permission", Reason: "failed"}
	}
	items := []any{}
	if r.Op == OpHistoryHeads {
		sha := h.head
		if h.changed {
			sha = strings.Repeat("f", 40)
		}
		if sha != "" {
			items = append(items, map[string]any{"ref": "refs/heads/main", "object": map[string]any{"type": "commit", "sha": sha}})
		}
	}
	if r.Op == OpHistoryHeads && h.refCount > 0 {
		items = nil
		for i := range h.refCount {
			items = append(items, map[string]any{"ref": "refs/heads/" + strconv.FormatInt(int64(i), 36), "object": map[string]any{"type": "commit", "sha": h.head}})
		}
	}
	b, _ := json.Marshal(items)
	return gate.Result{RequestID: r.Op, Decision: "sent", Response: &gate.Response{Status: 200, Body: b, CollectedAt: time.Now(), Population: &gate.Population{}}}
}
func (h *historySender) DetectMirrorCredentials(b []byte) ([]policy.SecretLocation, bool) {
	return policy.SecretLocations(b, h.literal)
}
func (h *historySender) RedactMirrorName(name string) (string, []policy.Hit) {
	r, _ := policy.NewRedactor(h.extra)
	return r.WithLiteral("credential", h.literal).RedactString(name)
}
func (h *historySender) MirrorExtraRedactions(b []byte) []policy.Hit {
	r, _ := policy.NewRedactor(h.extra)
	return r.ExtraRedactionCounts(b)
}
func historyEvidence() Evidence {
	visibility := "private"
	return Evidence{RepositoriesAccess: []RepositoryAccess{{Asset: historyAsset, RepositoryRead: Read{Op: OpRepository, RequestID: "repo-read", Decision: "sent", Status: 200}, Repository: &Repository{Name: "shop", FullName: "acme/shop", Owner: Account{ID: 1, Login: "acme", Type: "Organization"}, Visibility: &visibility}}}}
}

type fixtureObject struct {
	kind string
	data []byte
}

func fixtureWrite(t *testing.T, root, name string, b []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func compressed(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	if _, e := w.Write(b); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func looseFixture(t *testing.T, root string, o fixtureObject) string {
	t.Helper()
	id := objectID(o.data, o.kind)
	header := []byte(o.kind + " " + itoa(len(o.data)) + "\x00")
	fixtureWrite(t, root, "objects/"+id[:2]+"/"+id[2:], compressed(t, append(header, o.data...)))
	return id
}
func itoa(n int) string { return strconv.Itoa(n) }
func historyFixture(t *testing.T, content string) (string, string, []fixtureObject) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, root, "config", []byte("[core]\n bare = true\n repositoryformatversion = 0\n[remote \"origin\"]\n url = https://github.com/acme/shop.git\n mirror = true\n fetch = +refs/*:refs/*\n"))
	blob := fixtureObject{"blob", []byte(content)}
	blobID := looseFixture(t, root, blob)
	rawID, _ := hex.DecodeString(blobID)
	tree := fixtureObject{"tree", append([]byte("100644 settings.txt\x00"), rawID...)}
	treeID := looseFixture(t, root, tree)
	commit := fixtureObject{"commit", []byte("tree " + treeID + "\nauthor Test <test@example.test> 1 +0000\ncommitter Test <test@example.test> 1 +0000\n\nfixture\n")}
	sha := looseFixture(t, root, commit)
	fixtureWrite(t, root, "HEAD", []byte("ref: refs/heads/main\n"))
	fixtureWrite(t, root, "refs/heads/main", []byte(sha+"\n"))
	return root, sha, []fixtureObject{blob, tree, commit}
}
func collectHistoryFixture(t *testing.T, root, head string, h *historySender) Evidence {
	t.Helper()
	h.head = head
	return CollectHistory(context.Background(), h, historyEvidence(), map[string]string{historyAsset: root})
}
func hasHistoryVerdict(js []Judgment, id string, v string) bool {
	for _, j := range js {
		if j.ID == id && j.Verdict == v {
			return true
		}
	}
	return false
}
func TestHistoryRulesFireDisproveAbstain(t *testing.T) {
	for _, v := range []struct {
		name, body, origin string
		verdict            string
	}{{"fire", "password=opaque-fixture-value", "https://user:opaque-origin-password@github.com/acme/shop.git", Fired}, {"disprove", "ordinary text and 0123456789abcdef0123456789abcdef", "", Disproved}, {"abstain", "ordinary text", "", Abstained}} {
		t.Run(v.name, func(t *testing.T) {
			root, sha, _ := historyFixture(t, v.body)
			if v.origin != "" {
				b, _ := os.ReadFile(filepath.Join(root, "config"))
				fixtureWrite(t, root, "config", bytes.ReplaceAll(b, []byte("https://github.com/acme/shop.git"), []byte(v.origin)))
			}
			if v.verdict == Abstained {
				fixtureWrite(t, root, "config", []byte("invalid config"))
			}
			h := &historySender{}
			e := collectHistoryFixture(t, root, sha, h)
			js := JudgeHistory(e)
			for _, id := range finding.GitHubHistoryIDs() {
				if !hasHistoryVerdict(js, id, v.verdict) {
					t.Fatalf("%s: %v; evidence %+v", id, js, e.RepositoriesHistory)
				}
			}
			raw, _ := json.Marshal(e)
			for _, secret := range []string{"opaque-fixture-value", "opaque-origin-password"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("seeded secret persisted")
				}
			}
			if v.verdict == Fired && !bytes.Contains(raw, []byte("[REDACTED:")) {
				t.Fatal("missing marker")
			}
			if !slices.Equal(h.calls, []string{OpHistoryHeads, OpHistoryPull}) {
				t.Fatal(h.calls)
			}
		})
	}
}
func TestHistoryPartialRetainsPositive(t *testing.T) {
	root, sha, _ := historyFixture(t, "password=positive-value")
	for _, h := range []*historySender{{changed: true}, {denied: true}} {
		e := collectHistoryFixture(t, root, sha, h)
		js := JudgeHistory(e)
		if !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Fired) || !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Abstained) || hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Disproved) {
			t.Fatal(js)
		}
	}
}
func TestHistoryMissingMirrorAndNoIdentity(t *testing.T) {
	h := &historySender{}
	e := CollectHistory(context.Background(), h, historyEvidence(), nil)
	if len(h.calls) != 0 || !hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Abstained) {
		t.Fatal(e)
	}
	e = historyEvidence()
	e.RepositoriesAccess[0].Repository = nil
	CollectHistory(context.Background(), h, e, map[string]string{historyAsset: "/never-open"})
	if len(h.calls) != 0 {
		t.Fatal(h.calls)
	}
}
func TestHistoryLiteralExtraAndMarkerControls(t *testing.T) {
	literal := "opaque-account-credential-12345"
	for _, v := range []struct {
		body string
		h    historySender
		fire bool
	}{{literal, historySender{literal: literal}, true}, {"customer-person", historySender{extra: []string{"customer-person"}}, false}, {"[REDACTED:credential:30 bytes]", historySender{}, false}} {
		root, sha, _ := historyFixture(t, v.body)
		e := collectHistoryFixture(t, root, sha, &v.h)
		if hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Fired) != v.fire {
			t.Fatal(e.RepositoriesHistory)
		}
		if len(v.h.extra) > 0 && len(e.RepositoriesHistory[0].Redactions) == 0 {
			t.Fatal("extra match not counted")
		}
	}
}
func TestHistoryRescanChanges(t *testing.T) {
	root, sha, _ := historyFixture(t, "ordinary")
	h := &historySender{}
	first := collectHistoryFixture(t, root, sha, h)
	if !first.RepositoriesHistory[0].Complete {
		t.Fatal(first.RepositoriesHistory)
	}
	_, newSHA, objects := historyFixture(t, "password=now-present")
	for _, o := range objects {
		looseFixture(t, root, o)
	}
	fixtureWrite(t, root, "refs/heads/main", []byte(newSHA+"\n"))
	second := collectHistoryFixture(t, root, newSHA, h)
	if !hasHistoryVerdict(JudgeHistory(second), finding.IDGitHubHistoryCredential, Fired) || len(h.calls) != 4 {
		t.Fatal(second.RepositoriesHistory, h.calls)
	}
}
func TestMirrorCorruptionAndCaps(t *testing.T) {
	for _, name := range []string{"corrupt", "oversize", "alternates", "duplicate", "escape"} {
		t.Run(name, func(t *testing.T) {
			root, sha, objects := historyFixture(t, "ordinary")
			switch name {
			case "corrupt":
				id := objectID(objects[0].data, "blob")
				fixtureWrite(t, root, "objects/"+id[:2]+"/"+id[2:], []byte("bad-zlib"))
			case "oversize":
				fixtureWrite(t, root, "config", bytes.Repeat([]byte("x"), 65537))
			case "alternates":
				fixtureWrite(t, root, "objects/info/alternates", []byte("/outside"))
			case "duplicate":
				b, _ := os.ReadFile(filepath.Join(root, "config"))
				fixtureWrite(t, root, "config", append(b, []byte(" url=https://github.com/acme/shop.git\n")...))
			case "escape":
				id := objectID(objects[0].data, "blob")
				p := filepath.Join(root, "objects", id[:2], id[2:])
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("/outside", p); e != nil {
					t.Fatal(e)
				}
			}
			e := collectHistoryFixture(t, root, sha, &historySender{})
			if e.RepositoriesHistory[0].Complete || hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Disproved) {
				t.Fatal(e.RepositoriesHistory)
			}
		})
	}
}

// PACK and index fixtures are constructed in-process, with no Git invocation.
type packFixtureEntry struct {
	object  fixtureObject
	kind    int
	base    int
	refBase string
	payload []byte
}

func fixturePack(t *testing.T, root string, entries []packFixtureEntry) {
	t.Helper()
	raw := []byte("PACK\x00\x00\x00\x02")
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(entries)))
	offsets := []int64{}
	crcs := []uint32{}
	ids := []string{}
	for _, entry := range entries {
		start := len(raw)
		offsets = append(offsets, int64(start))
		payload := entry.object.data
		if entry.payload != nil {
			payload = entry.payload
		}
		size := len(payload)
		first := byte((entry.kind << 4) | (size & 15))
		size >>= 4
		if size > 0 {
			first |= 128
		}
		raw = append(raw, first)
		for size > 0 {
			b := byte(size & 127)
			size >>= 7
			if size > 0 {
				b |= 128
			}
			raw = append(raw, b)
		}
		if entry.kind == 6 {
			n := int64(start) - offsets[entry.base]
			b := []byte{byte(n & 127)}
			for n>>7 > 0 {
				n = (n >> 7) - 1
				b = append(b, byte(128|(n&127)))
			}
			slices.Reverse(b)
			raw = append(raw, b...)
		}
		if entry.kind == 7 {
			b, e := hex.DecodeString(entry.refBase)
			if e != nil {
				t.Fatal(e)
			}
			raw = append(raw, b...)
		}
		raw = append(raw, compressed(t, payload)...)
		crcs = append(crcs, crc32.ChecksumIEEE(raw[start:]))
		ids = append(ids, objectID(entry.object.data, entry.object.kind))
	}
	checksum := structuralHash(raw)
	raw = append(raw, checksum...)
	name := "pack-" + hex.EncodeToString(checksum)
	fixtureWrite(t, root, "objects/pack/"+name+".pack", raw)
	order := make([]int, len(entries))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return strings.Compare(ids[a], ids[b]) })
	idx := []byte{255, 't', 'O', 'c', 0, 0, 0, 2}
	for i := range 256 {
		n := 0
		for _, id := range ids {
			b, _ := hex.DecodeString(id[:2])
			if int(b[0]) <= i {
				n++
			}
		}
		idx = binary.BigEndian.AppendUint32(idx, uint32(n))
	}
	for _, i := range order {
		b, _ := hex.DecodeString(ids[i])
		idx = append(idx, b...)
	}
	for _, i := range order {
		idx = binary.BigEndian.AppendUint32(idx, crcs[i])
	}
	for _, i := range order {
		idx = binary.BigEndian.AppendUint32(idx, uint32(offsets[i]))
	}
	idx = append(idx, checksum...)
	idx = append(idx, structuralHash(idx)...)
	fixtureWrite(t, root, "objects/pack/"+name+".idx", idx)
}
func deltaLiteral(base, result []byte) []byte {
	b := []byte{}
	for _, n := range []int{len(base), len(result)} {
		for {
			c := byte(n & 127)
			n >>= 7
			if n > 0 {
				c |= 128
			}
			b = append(b, c)
			if n == 0 {
				break
			}
		}
	}
	for len(result) > 0 {
		n := min(len(result), 127)
		b = append(b, byte(n))
		b = append(b, result[:n]...)
		result = result[n:]
	}
	return b
}
func TestHistoryPackedDeltas(t *testing.T) {
	for _, kind := range []int{3, 6, 7} {
		t.Run(itoa(kind), func(t *testing.T) {
			root, sha, objects := historyFixture(t, "password=packed-secret")
			blob := objects[0]
			id := objectID(blob.data, "blob")
			if e := os.Remove(filepath.Join(root, "objects", id[:2], id[2:])); e != nil {
				t.Fatal(e)
			}
			base := fixtureObject{"blob", []byte("ordinary base")}
			entries := []packFixtureEntry{}
			entry := packFixtureEntry{object: blob, kind: kind}
			if kind == 6 {
				entries = append(entries, packFixtureEntry{object: base, kind: 3})
				entry.base = 0
				entry.payload = deltaLiteral(base.data, blob.data)
			}
			if kind == 7 {
				entry.refBase = looseFixture(t, root, base)
				entry.payload = deltaLiteral(base.data, blob.data)
			}
			entries = append(entries, entry)
			fixturePack(t, root, entries)
			e := collectHistoryFixture(t, root, sha, &historySender{})
			if !e.RepositoriesHistory[0].Complete || !hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Fired) {
				t.Fatalf("%+v", e.RepositoriesHistory)
			}
		})
	}
}
func TestMirrorConfigConservativeAdmission(t *testing.T) {
	root, _, _ := historyFixture(t, "ordinary")
	base, e := os.ReadFile(filepath.Join(root, "config"))
	if e != nil {
		t.Fatal(e)
	}
	detect := func(b []byte) ([]policy.SecretLocation, bool) { return policy.SecretLocations(b, "") }
	for _, url := range []string{"ssh://git@github.com/acme/shop.git", "git@github.com:acme/shop.git", "https://github.com/acme/shop"} {
		raw := bytes.ReplaceAll(base, []byte("https://github.com/acme/shop.git"), []byte("\""+url+"\" # comment"))
		if hits, e := parseMirrorConfig(raw, historyAsset, detect); e != nil || len(hits) != 0 {
			t.Fatal(url, e, hits)
		}
	}
	for _, suffix := range []string{"[include]\npath=/outside\n", "[extensions]\nobjectformat=sha256\n", "[url \"https://outside/\"]\ninsteadOf=https://github.com/\n", "[remote \"origin\"]\nurl=https://github.com/acme/shop\n", "[remote \"origin\"]\npromisor=true\n"} {
		if _, e := parseMirrorConfig(append(slices.Clone(base), []byte(suffix)...), historyAsset, detect); e == nil {
			t.Fatal(suffix)
		}
	}
	for _, url := range []string{"https://github.com/acme/other.git", "https://github.com:443/acme/shop.git", "https://github.com/acme/shop?x=1", "https://github.com/acme/%73hop.git"} {
		if _, e := parseMirrorConfig(bytes.ReplaceAll(base, []byte("https://github.com/acme/shop.git"), []byte(url)), historyAsset, detect); e == nil {
			t.Fatal(url)
		}
	}
}
func TestHistoryPublicSourceAndPathRedaction(t *testing.T) {
	root, sha, _ := historyFixture(t, "password=present")
	e := collectHistoryFixture(t, root, sha, &historySender{extra: []string{"settings"}})
	if hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Fired) || e.RepositoriesHistory[0].Complete {
		t.Fatal(e)
	}
	e = collectHistoryFixture(t, root, sha, &historySender{})
	public := "public"
	e.RepositoriesHistory[0].Visibility = &public
	js := JudgeHistory(e)
	for _, j := range js {
		if j.ID == finding.IDGitHubHistoryCredential && j.Verdict == Fired {
			if !slices.Contains(j.Attributes, "observed_public") || j.Details["repository_read"] != "repo-read" {
				t.Fatal(j)
			}
		}
		if j.ID == finding.IDGitHubRemoteCredential && len(j.Attributes) > 0 {
			t.Fatal("public adjusted remote")
		}
	}
}
func TestHistoryDeltaFailures(t *testing.T) {
	s := mirrorScan{}
	base := []byte("abc")
	for _, b := range [][]byte{{3, 3, 0}, {3, 3, 128}, {4, 3, 3, 'a', 'b', 'c'}, {3, 3, 4, 'a', 'b', 'c', 'd'}, {3, 3, 255}} {
		if _, release, e := s.delta(base, b); e == nil {
			release()
			t.Fatal(b)
		}
	}
	b := append([]byte{3}, bytes.Repeat([]byte{255}, 12)...)
	if _, _, e := s.delta(base, b); e == nil {
		t.Fatal("overflow accepted")
	}
}
func TestHistoryCrossPackDeltaAndPackIntegrity(t *testing.T) {
	root, sha, objects := historyFixture(t, "password=cross-pack")
	blob := objects[0]
	id := objectID(blob.data, "blob")
	if e := os.Remove(filepath.Join(root, "objects", id[:2], id[2:])); e != nil {
		t.Fatal(e)
	}
	base := fixtureObject{"blob", []byte("base")}
	fixturePack(t, root, []packFixtureEntry{{object: base, kind: 3}})
	fixturePack(t, root, []packFixtureEntry{{object: blob, kind: 7, refBase: objectID(base.data, "blob"), payload: deltaLiteral(base.data, blob.data)}})
	e := collectHistoryFixture(t, root, sha, &historySender{})
	if !e.RepositoriesHistory[0].Complete || !hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Fired) {
		t.Fatal(e.RepositoriesHistory)
	}
	packs, _ := filepath.Glob(filepath.Join(root, "objects/pack/*.idx"))
	raw, err := os.ReadFile(packs[0])
	if err != nil {
		t.Fatal(err)
	}
	raw[1032] ^= 1
	if err = os.WriteFile(packs[0], raw, 0600); err != nil {
		t.Fatal(err)
	}
	e = collectHistoryFixture(t, root, sha, &historySender{})
	if e.RepositoriesHistory[0].Complete || hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Disproved) {
		t.Fatal(e.RepositoriesHistory)
	}
}

type changingHistorySender struct {
	historySender
	root    string
	changed bool
}

func (h *changingHistorySender) DetectMirrorCredentials(b []byte) ([]policy.SecretLocation, bool) {
	hits, complete := h.historySender.DetectMirrorCredentials(b)
	if bytes.Contains(b, []byte("password=before-change")) && !h.changed {
		h.changed = true
		config, _ := os.ReadFile(filepath.Join(h.root, "config"))
		_ = os.WriteFile(filepath.Join(h.root, "config"), append(config, []byte("# concurrent update\n")...), 0600)
	}
	return hits, complete
}
func TestHistoryMutationPreservesPositiveAndNoAbsence(t *testing.T) {
	root, sha, _ := historyFixture(t, "password=before-change")
	h := &changingHistorySender{head: sha, root: root}
	e := CollectHistory(context.Background(), h, historyEvidence(), map[string]string{historyAsset: root})
	js := JudgeHistory(e)
	if e.RepositoriesHistory[0].Complete || !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Fired) || !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Abstained) {
		t.Fatal(e.RepositoriesHistory)
	}
}
func TestHistoryPackHeaderAndDeltaBoundaries(t *testing.T) {
	root, _, _ := historyFixture(t, "ordinary")
	f, err := gate.OpenMirror(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := RepositoryHistory{}
	s := mirrorScan{ctx: ctx, files: f, result: &r}
	if _, e := s.object(strings.Repeat("a", 40), 0, map[string]bool{}); e != gate.ErrMirrorLimit {
		t.Fatal(e)
	}
	s.ctx = context.Background()
	if _, e := s.object(strings.Repeat("a", 40), 65, map[string]bool{}); e != gate.ErrMirrorLimit {
		t.Fatal(e)
	}
	s.objects = 200000
	if _, e := s.object(strings.Repeat("a", 40), 0, map[string]bool{}); e != gate.ErrMirrorLimit {
		t.Fatal(e)
	}
	s.resident = 128 << 20
	if _, e := s.reserve(1); e != gate.ErrMirrorLimit {
		t.Fatal(e)
	}
}
func TestMirrorLooseTrailingDataNeverDisproves(t *testing.T) {
	root, sha, objects := historyFixture(t, "ordinary")
	id := objectID(objects[0].data, "blob")
	name := filepath.Join(root, "objects", id[:2], id[2:])
	b, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(name, append(b, []byte("trailing-data")...), 0600); e != nil {
		t.Fatal(e)
	}
	ev := collectHistoryFixture(t, root, sha, &historySender{})
	if ev.RepositoriesHistory[0].Complete || hasHistoryVerdict(JudgeHistory(ev), finding.IDGitHubHistoryCredential, Disproved) {
		t.Fatal(ev.RepositoriesHistory)
	}
}

func TestHistoryFullPathBudgetNeverDisproves(t *testing.T) {
	root, _, objects := historyFixture(t, "password=path-budget-seed")
	blobID, _ := hex.DecodeString(objectID(objects[0].data, "blob"))
	treeID := looseFixture(t, root, fixtureObject{"tree", append([]byte("100644 "+strings.Repeat("x", 4097)+"\x00"), blobID...)})
	sha := looseFixture(t, root, fixtureObject{"commit", []byte("tree " + treeID + "\n\nfixture\n")})
	fixtureWrite(t, root, "refs/heads/main", []byte(sha+"\n"))
	ev := collectHistoryFixture(t, root, sha, &historySender{})
	r := ev.RepositoriesHistory[0]
	if r.Complete || !slices.Contains(r.Gaps, "limit_reached") || hasHistoryVerdict(JudgeHistory(ev), finding.IDGitHubHistoryCredential, Disproved) {
		t.Fatal(r)
	}
}

func TestHistoryDetectorExhaustionNeverDisproves(t *testing.T) {
	root, sha, _ := historyFixture(t, strings.Repeat("password=no\n", 10001)+"password=actually-sensitive\n")
	e := collectHistoryFixture(t, root, sha, &historySender{})
	r := e.RepositoriesHistory[0]
	if r.Complete || !slices.Contains(r.Gaps, "limit_reached") || hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Disproved) {
		t.Fatal(r)
	}
}

func TestMirrorDirectoryListsReserveBeforeAllocation(t *testing.T) {
	root, _, _ := historyFixture(t, "ordinary")
	for _, name := range []string{"a", "b"} {
		fixtureWrite(t, root, "wide/"+name, []byte("ordinary"))
	}
	files, err := gate.OpenMirror(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	s := mirrorScan{ctx: context.Background(), files: files, resident: (128 << 20) - 2048}
	if _, _, err = s.list("wide"); err != gate.ErrMirrorLimit {
		t.Fatal(err)
	}
	if s.resident != (128<<20)-2048 {
		t.Fatal("failed list leaked reservation")
	}
	s.resident = 0
	entries, release, err := s.list("wide")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || s.resident != 2048 {
		t.Fatal("retained directory entries were not charged")
	}
	release()
	if s.resident != 0 {
		t.Fatal("list lifetime leaked reservation")
	}
}

func TestMirrorConfigSubsectionsCannotSupplyOrdinarySettings(t *testing.T) {
	for _, section := range []string{"[core \"other\"]", "[core \"\"]", "[extensions \"other\"]", "[extensions \"\"]"} {
		root, sha, _ := historyFixture(t, "ordinary")
		config, err := os.ReadFile(filepath.Join(root, "config"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(section, "[core") {
			config = bytes.Replace(config, []byte("[core]"), []byte(section), 1)
		} else {
			config = append(config, []byte(section+"\n objectformat=sha1\n")...)
		}
		fixtureWrite(t, root, "config", config)
		ev := collectHistoryFixture(t, root, sha, &historySender{})
		if ev.RepositoriesHistory[0].Complete || hasHistoryVerdict(JudgeHistory(ev), finding.IDGitHubHistoryCredential, Disproved) || hasHistoryVerdict(JudgeHistory(ev), finding.IDGitHubRemoteCredential, Disproved) {
			t.Fatal(section, ev.RepositoriesHistory)
		}
	}
}

func TestHistoryLooseExpandedCapIsLimit(t *testing.T) {
	for _, extra := range []int{1, 1024} {
		t.Run(itoa(extra), func(t *testing.T) {
			root, sha, _ := historyFixture(t, strings.Repeat("a", mirrorObjectMax+extra))
			e := collectHistoryFixture(t, root, sha, &historySender{})
			h := e.RepositoriesHistory[0]
			if h.Read.Reason != "limit_reached" || h.Complete || hasHistoryVerdict(JudgeHistory(e), finding.IDGitHubHistoryCredential, Disproved) {
				t.Fatalf("expanded cap: reason=%s gap=%s complete=%v", h.Read.Reason, h.Read.Gap, h.Complete)
			}
		})
	}
}

func TestHistoryAdvertisedRefCapIsIncomplete(t *testing.T) {
	root, sha, _ := historyFixture(t, "password=opaque-fixture-value")
	e := collectHistoryFixture(t, root, sha, &historySender{refCount: 10001})
	h := e.RepositoriesHistory[0]
	if h.Complete || h.References[0].Reason != "limit_reached" || h.References[0].Gap != "limit_reached" {
		t.Fatalf("advertised cap: %+v", h)
	}
	js := JudgeHistory(e)
	if !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Fired) || !hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Abstained) || hasHistoryVerdict(js, finding.IDGitHubHistoryCredential, Disproved) {
		t.Fatal(js)
	}
}
