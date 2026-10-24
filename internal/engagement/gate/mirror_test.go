package gate

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func physicalDir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestMirrorFilesRejectLinksAndLimits(t *testing.T) {
	root := physicalDir(t)
	outside := physicalDir(t)
	secret := []byte("outside-content-never-read")
	if e := os.WriteFile(filepath.Join(outside, "secret"), secret, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "regular"), []byte("safe"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "symbolic")); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(filepath.Join(outside, "secret"), filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	m, e := OpenMirror(root)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = m.Close() }()
	for _, p := range []string{"symbolic", "hard", "../secret"} {
		if b, e := m.Read(p, 100); e == nil || bytes.Contains(b, secret) {
			t.Fatalf("%s escaped", p)
		}
	}
	if _, e = m.Read("regular", 3); e != ErrMirrorLimit {
		t.Fatal(e)
	}
	if b, e := m.Read("regular", 4); e != nil || string(b) != "safe" {
		t.Fatal(e)
	}
}
func TestMirrorFilesParentSymlinkRaceCannotEscape(t *testing.T) {
	root := physicalDir(t)
	outside := physicalDir(t)
	if e := os.WriteFile(filepath.Join(outside, "value"), []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "directory"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "directory/value"), []byte("inside"), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := OpenMirror(root)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = m.Close() }()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			_ = os.Rename(filepath.Join(root, "directory"), filepath.Join(root, "parked"))
			_ = os.Symlink(outside, filepath.Join(root, "directory"))
			_ = os.Remove(filepath.Join(root, "directory"))
			_ = os.Rename(filepath.Join(root, "parked"), filepath.Join(root, "directory"))
		}
	})
	for range 1000 {
		b, e := m.Read("directory/value", 100)
		if e == nil && string(b) != "inside" {
			t.Errorf("escaped: %q", b)
		}
	}
	wg.Wait()
}

func TestMirrorRootAdmissionSwapRefused(t *testing.T) {
	parentPath := physicalDir(t)
	for _, name := range []string{"selected", "outside"} {
		if err := os.Mkdir(filepath.Join(parentPath, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	admitted, err := parent.OpenFile("selected", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admitted.Close() }()
	if err = os.Rename(filepath.Join(parentPath, "selected"), filepath.Join(parentPath, "parked")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("outside", filepath.Join(parentPath, "selected")); err != nil {
		t.Fatal(err)
	}
	swapped, err := bindMirrorChild(parent, "selected", admitted)
	if err == nil {
		_ = swapped.Close()
		t.Fatal("admitted a different root after swap")
	}
	if err != ErrMirrorPath {
		t.Fatal(err)
	}
	if _, err = OpenMirror(filepath.Join(parentPath, "selected")); err != ErrMirrorPath {
		t.Fatal(err)
	}
}
