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
