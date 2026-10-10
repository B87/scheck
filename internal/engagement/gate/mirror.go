package gate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/b87/scheck/internal/policy"
)

var ErrMirrorPath = errors.New("unsupported mirror path")
var ErrMirrorLimit = errors.New("mirror limit reached")

// MirrorFiles is the single local read boundary. os.Root prevents a concurrent
// symlink change escaping confinement; final opens also refuse links, devices and
// shared hard links. No method writes (docs/spec/scope.md, "Repositories").
type MirrorFiles struct{ root *os.Root }

func OpenMirror(path string) (*MirrorFiles, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrMirrorPath
	}
	// Acquire each directory relative to the previous bound descriptor. A nofollow
	// descriptor identifies the admitted child; OpenRoot must bind that same inode
	// before any contents are read. Only the filesystem root is opened by path.
	r, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, ErrMirrorPath
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		admitted, e := r.Lstat(component)
		if e != nil || !admitted.IsDir() || admitted.Mode()&os.ModeSymlink != 0 {
			_ = r.Close()
			return nil, ErrMirrorPath
		}
		f, e := r.OpenFile(component, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			_ = r.Close()
			return nil, ErrMirrorPath
		}
		opened, e := f.Stat()
		if e != nil || !os.SameFile(admitted, opened) {
			_ = f.Close()
			_ = r.Close()
			return nil, ErrMirrorPath
		}
		next, e := bindMirrorChild(r, component, f)
		_ = f.Close()
		_ = r.Close()
		if e != nil {
			return nil, ErrMirrorPath
		}
		r = next
	}

	return &MirrorFiles{r}, nil
}

// bindMirrorChild verifies identity after acquisition, closing a swapped root.
func bindMirrorChild(parent *os.Root, component string, admitted *os.File) (*os.Root, error) {
	before, err := admitted.Stat()
	if err != nil || !before.IsDir() {
		return nil, ErrMirrorPath
	}
	next, err := parent.OpenRoot(component)
	if err != nil {
		return nil, ErrMirrorPath
	}
	after, err := next.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = next.Close()
		return nil, ErrMirrorPath
	}
	return next, nil
}
func (m *MirrorFiles) Close() error { return m.root.Close() }
func (m *MirrorFiles) check(name string) error {
	if !filepath.IsLocal(name) {
		return ErrMirrorPath
	}
	parts := strings.Split(filepath.Clean(name), string(filepath.Separator))
	p := ""
	for _, part := range parts {
		p = filepath.Join(p, part)
		st, err := m.root.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return ErrMirrorPath
		}
	}
	return nil
}
func (m *MirrorFiles) Open(name string, maxBytes int64) (*os.File, error) {
	if err := m.check(name); err != nil {
		return nil, err
	}
	f, err := m.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrMirrorPath
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrMirrorPath
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink != 1 {
		_ = f.Close()
		return nil, ErrMirrorPath
	}
	if st.Size() > maxBytes {
		_ = f.Close()
		return nil, ErrMirrorLimit
	}
	return f, nil
}
func (m *MirrorFiles) Read(name string, maxBytes int64) ([]byte, error) {
	f, err := m.Open(name, maxBytes)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, ErrMirrorPath
	}
	if int64(len(b)) > maxBytes {
		return nil, ErrMirrorLimit
	}
	return b, nil
}
func (m *MirrorFiles) List(name string, remaining int) ([]os.DirEntry, error) {
	if err := m.check(name); err != nil {
		return nil, err
	}
	f, err := m.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, ErrMirrorPath
	}
	defer func() { _ = f.Close() }()
	items, err := f.ReadDir(remaining + 1)
	if err != nil && err != io.EOF {
		return nil, ErrMirrorPath
	}
	if len(items) > remaining {
		return nil, ErrMirrorLimit
	}
	return items, nil
}

// DetectMirrorCredentials keeps the exact environment credential inside the gate.
func (g *Gate) DetectMirrorCredentials(b []byte) ([]policy.SecretLocation, bool) {
	credential := ""
	if c, _ := g.credential(GitHubToken); c != nil {
		credential = c.secret
	}
	return policy.SecretLocations(b, credential)
}
func (g *Gate) RedactMirrorName(name string) (string, []policy.Hit) {
	redactor := g.redactor
	if c, _ := g.credential(GitHubToken); c != nil {
		redactor = redactor.WithLiteral("credential", c.secret)
	}
	return redactor.RedactString(name)
}

func (g *Gate) MirrorExtraRedactions(b []byte) []policy.Hit {
	return g.redactor.ExtraRedactionCounts(b)
}

// RecordMirrorAttempt emits numeric accounting only; no local contents or paths.
func (g *Gate) RecordMirrorAttempt(asset, request, decision, reason string, objects, commits, blobs int, at time.Time) error {
	return g.record(Entry{Event: "mirror", Asset: asset, RequestID: request, Op: "github.mirror_history", Stage: "recon", Time: at, Level: "passive", Decision: decision, Detail: reason, Counts: map[string]int{"objects": objects, "commits": commits, "blobs": blobs}})
}
