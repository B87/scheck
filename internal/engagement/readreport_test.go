package engagement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const tinyReport = `{"schema_version":"1.0","scheck_version":"0.0.3"}`

// runDirWith writes a run directory the way a finished run leaves one: 0700,
// run.json recording the hash of report.json.
func runDirWith(t *testing.T, report string, recorded string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "engagements", "acme")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "2026-10-01T09:00:00Z")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Files: map[string]string{}}
	if recorded != "" {
		m.Files[reportFile] = recorded
	}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifestFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if report != "" {
		if err := os.WriteFile(filepath.Join(dir, reportFile), []byte(report), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestReadReportFromARunDirectory(t *testing.T) {
	dir := runDirWith(t, tinyReport, hashOf(tinyReport))
	got, err := ReadReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RunRecordChecked || got.SHA256 != hashOf(tinyReport) || got.Report.ScheckVersion != "0.0.3" {
		t.Errorf("got %+v", got)
	}
}

func TestReadReportRefusesWhatRestsOnAnEdit(t *testing.T) {
	edited := runDirWith(t, tinyReport, hashOf("something else"))
	if _, err := ReadReport(edited); err == nil || !strings.Contains(err.Error(), "changed since scheck wrote it") {
		t.Errorf("an edited report: %v", err)
	}
	unrecorded := runDirWith(t, tinyReport, "")
	if _, err := ReadReport(unrecorded); err == nil || !strings.Contains(err.Error(), "does not record") {
		t.Errorf("an unrecorded report: %v", err)
	}
	stopped := runDirWith(t, "", "")
	if _, err := ReadReport(stopped); err == nil || !strings.Contains(err.Error(), "stopped before its Report stage") {
		t.Errorf("a run with no report: %v", err)
	}
}

func TestReadReportRefusesARunInProgress(t *testing.T) {
	dir := runDirWith(t, tinyReport, hashOf(tinyReport))
	held, err := LockRunDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := ReadReport(dir); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("got %v", err)
	}
}

func TestReadReportFromAFileIsNotChecked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, []byte(tinyReport), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadReport(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.RunRecordChecked || got.Directory != "" {
		t.Errorf("got %+v", got)
	}
}

func TestReadReportRefusesALinkedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(tinyReport), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(link); err == nil {
		t.Error("a linked report file was read")
	}
}

func TestReadReportDoesNotWaitOnAPipe(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if _, err := ReadReport(p); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("got %v", err)
	}
}
