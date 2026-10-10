package gate_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func writeMirrorObject(t *testing.T, root, kind string, data []byte) string {
	t.Helper()
	raw := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(data))), data...)
	sum := sha1.Sum(raw)
	id := hex.EncodeToString(sum[:])
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "objects", id[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id[2:]), compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return id
}
func writeMirrorCommit(t *testing.T, root, body string) string {
	t.Helper()
	blob := writeMirrorObject(t, root, "blob", []byte(body))
	id, _ := hex.DecodeString(blob)
	tree := writeMirrorObject(t, root, "tree", append([]byte("100644 config.env\x00"), id...))
	commit := writeMirrorObject(t, root, "commit", []byte("tree "+tree+"\nauthor Test <test@example.test> 1 +0000\ncommitter Test <test@example.test> 1 +0000\n\nfixture\n"))
	if err := os.MkdirAll(filepath.Join(root, "refs/heads"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "refs/heads/main"), []byte(commit+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return commit
}
func TestGitHubHistoryRunRedactionAuditAndFreshResume(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	originSecret := "opaque-origin-userinfo-secret"
	literal := "opaque-session-credential-12345"
	known := "ghp_" + strings.Repeat("s", 36)
	config := []byte("[core]\n bare = true\n repositoryformatversion = 0\n[remote \"origin\"]\n url = https://user:" + originSecret + "@github.com/acme/shop.git\n mirror = true\n fetch = +refs/*:refs/*\n")
	if err = os.WriteFile(filepath.Join(root, "config"), config, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "HEAD"), []byte("ref: refs/heads/main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	head := writeMirrorCommit(t, root, "ordinary control text")
	raw := []byte(fmt.Sprintf("schema: 1\nengagement: {name: history, operator: alice, timezone: UTC, trigger: routine}\nroots: [{repo: 'github:acme/shop'}]\nassets:\n  shop: {repo: 'github:acme/shop', public: true, checkout: %q}\npeople:\n  alice: {kind: employee, github: [alice]}\n", root))
	opts := inventoryOptions()
	opts.KnownFinding = finding.Known
	opts.FindingSubject = func(id string) string { return string(finding.SubjectOf(id)) }
	sourcePath := filepath.Join(t.TempDir(), "history.yaml")
	if err = os.WriteFile(sourcePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	res, err := engagement.Parse(sourcePath, raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", literal)
	heads, pulls := 0, 0
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("non-GET")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/repos/acme/shop":
			fmt.Fprint(w, `{"id":10,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"public"}`)
		case "/repos/acme/shop/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"read"}`)
		case "/repos/acme/shop/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		case "/repos/acme/shop/collaborators", "/repos/acme/shop/keys", "/repos/acme/shop/dependabot/alerts", "/repos/acme/shop/secret-scanning/alerts":
			fmt.Fprint(w, `[]`)
		case "/repos/acme/shop/git/matching-refs/heads/":
			heads++
			if r.URL.RawQuery != "" {
				t.Error("invented pagination")
			}
			fmt.Fprintf(w, `[{"ref":"refs/heads/main","object":{"type":"commit","sha":%q},"url":"https://outside.test/never"}]`, head)
		case "/repos/acme/shop/git/matching-refs/pull/":
			pulls++
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected read %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	dir, err := engagement.CreateRunDir(t.TempDir(), "history", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, NewGate: h.Build, Version: "v0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	foundHistory := false
	foundRemote := false
	for _, a := range out.Report.Assessments {
		if a.ID == finding.IDGitHubHistoryCredential && a.Status == "not_matched" && a.Complete {
			foundHistory = true
		}
	}
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDGitHubRemoteCredential {
			foundRemote = true
			if f.Severity != "medium" {
				t.Fatal(f)
			}
		}
	}
	if !foundHistory || !foundRemote {
		t.Fatalf("first outcomes history=%v remote=%v", foundHistory, foundRemote)
	}
	dirPath := dir.Path
	dir.Close()
	head = writeMirrorCommit(t, root, literal+"\n"+known+"\n")
	d, err := engagement.OpenRun(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	prior, err := engagement.LoadPrior(d)
	if err != nil {
		t.Fatal(err)
	}
	resolved, source, err := prior.LoadEngagement(opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err = engagement.Run(context.Background(), resolved, engagement.RunOptions{Dir: d, Raw: source, Resume: prior, Started: prior.Manifest.Started, Session: time.Now(), Version: "v0.0.2", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	findings := 0
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDGitHubHistoryCredential {
			findings++
			if f.Severity != "critical" || f.Subject == nil || !strings.Contains(f.Subject.Key, head) {
				t.Fatal(f)
			}
		}
	}
	if findings != 2 || heads != 2 || pulls != 2 {
		t.Fatalf("findings=%d heads=%d pulls=%d", findings, heads, pulls)
	}
	marker := false
	err = filepath.WalkDir(dirPath, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, secret := range []string{originSecret, literal, known, "https://outside.test/never"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("secret in persisted %s", p)
			}
		}
		marker = marker || bytes.Contains(b, []byte("[REDACTED:"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !marker {
		t.Fatal("no marker")
	}
	audit, err := os.ReadFile(d.File("audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	for line := range bytes.SplitSeq(audit, []byte{'\n'}) {
		var e map[string]any
		if json.Unmarshal(line, &e) == nil && e["event"] == "mirror" {
			attempts++
			if e["counts"] == nil || e["output_sha256"] != nil || e["url"] != nil {
				t.Fatal(e)
			}
		}
	}
	if attempts != 2 {
		t.Fatal(attempts)
	}
	actual, err := os.ReadFile(filepath.Join(root, "config"))
	if err != nil || !bytes.Equal(config, actual) {
		t.Fatal("mirror modified")
	}
}
