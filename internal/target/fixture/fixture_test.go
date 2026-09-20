package fixture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/b87/scheck/internal/target"
)

func TestReplayAndMiss(t *testing.T) {
	f := New(target.Linux, Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux x\n"})
	res, err := f.Exec(context.Background(), []string{"uname", "-a"})
	if err != nil || string(res.Stdout) != "Linux x\n" || res.Code != 0 {
		t.Fatalf("replay: %+v %v", res, err)
	}
	res, err = f.Exec(context.Background(), []string{"uname", "-r"})
	if !errors.Is(err, target.ErrNotFound) || res.Code != target.CodeNotFound {
		t.Fatalf("miss: %+v %v", res, err)
	}
	if len(f.Calls) != 2 {
		t.Errorf("calls = %d", len(f.Calls))
	}
}

func TestSleepHonoursContext(t *testing.T) {
	f := New(target.Linux, Exec{Argv: []string{"slow"}, Sleep: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := f.Exec(ctx, []string{"slow"}); !errors.Is(err, target.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "manifest.yaml"), `
platform: macos
execs:
  - argv: [sw_vers]
    stdout_file: sw_vers.out
  - argv: [false]
    code: 1
`)
	mustWrite(t, filepath.Join(dir, "sw_vers.out"), "ProductName: macOS\n")
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.Platform() != target.MacOS {
		t.Errorf("platform = %s", f.Platform())
	}
	res, err := f.Exec(context.Background(), []string{"sw_vers"})
	if err != nil || string(res.Stdout) != "ProductName: macOS\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, _ = f.Exec(context.Background(), []string{"false"})
	if res.Code != 1 {
		t.Errorf("code = %d", res.Code)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A manifest may inherit another directory's recordings, override an argv
// and mask one as absent, so an evaluation case is a recorded host plus a
// few facts.
func TestLoadWithBase(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base")
	kase := filepath.Join(dir, "case")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(kase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "uname.stdout"), []byte("Linux base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "manifest.yaml"), []byte("platform: linux\nexecs:\n  - argv: [uname, -a]\n    stdout_file: uname.stdout\n  - argv: [id, -u]\n    stdout: \"0\\n\"\n  - argv: [sestatus]\n    stdout: \"SELinux status: enabled\\n\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kase, "manifest.yaml"), []byte("base: ../base\nexecs:\n  - argv: [id, -u]\n    stdout: \"1000\\n\"\n  - argv: [sestatus]\n    absent: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx, err := Load(kase)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Platform() != "linux" {
		t.Errorf("platform not inherited: %s", fx.Platform())
	}
	ctx := context.Background()
	if r, err := fx.Exec(ctx, []string{"uname", "-a"}); err != nil || string(r.Stdout) != "Linux base\n" {
		t.Errorf("inherited file recording: %q %v", r.Stdout, err)
	}
	if r, _ := fx.Exec(ctx, []string{"id", "-u"}); string(r.Stdout) != "1000\n" {
		t.Errorf("override lost: %q", r.Stdout)
	}
	if _, err := fx.Exec(ctx, []string{"sestatus"}); err == nil {
		t.Error("absent recording still replays")
	}
}
