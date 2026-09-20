package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/report"
)

func env(started time.Time) *report.Envelope {
	return &report.Envelope{SchemaVersion: report.SchemaVersion,
		Host: report.Host{ID: strings.Repeat("ab", 32)}, Run: report.Run{Started: started, Warnings: []string{}},
		Facts: map[string]report.Fact{}, Findings: []finding.Finding{}}
}

func TestWriteTwiceSameHostDir(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	p1, err := Write(dir, env(t0))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Write(dir, env(t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p1) != filepath.Dir(p2) || !strings.HasSuffix(p1, "2026-09-20T12:00:00Z.json") {
		t.Errorf("paths: %s %s", p1, p2)
	}
	files, _ := List(dir, strings.Repeat("ab", 32))
	if len(files) != 2 {
		t.Errorf("list = %v", files)
	}
	info, _ := os.Stat(p1)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(p1)
	var back report.Envelope
	if err := json.Unmarshal(raw, &back); err != nil || back.Run.Persisted == nil || *back.Run.Persisted != p1 {
		t.Errorf("persisted path not recorded inside the file: %v %+v", err, back.Run.Persisted)
	}
	if strings.Contains(string(raw), ".run-") {
		t.Error("temp name leaked")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p1), ".run-*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestWriteDegradesOnUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, env(time.Now())); err == nil {
		t.Fatal("expected an error, not a panic or silent success")
	}
	if _, err := Write(t.TempDir(), &report.Envelope{}); err == nil {
		t.Fatal("empty host id accepted")
	}
}

func TestDirPrecedence(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg")
	if d, _ := Dir(""); d != "/tmp/xdg/scheck" {
		t.Errorf("xdg: %s", d)
	}
	if d, _ := Dir("/explicit"); d != "/explicit" {
		t.Errorf("explicit: %s", d)
	}
	t.Setenv("XDG_STATE_HOME", "")
	if d, _ := Dir(""); !strings.HasSuffix(d, "/.local/state/scheck") {
		t.Errorf("default: %s", d)
	}
}
