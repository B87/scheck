package engagement

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	ereport "github.com/b87/scheck/internal/engagement/report"
)

// reportFile is the stage 7 document of a run directory.
const reportFile = "report.json"

// ReadRunReport is a report read for comparison (docs/spec/runs.md,
// "Comparing two runs").
type ReadRunReport struct {
	Report *ereport.Report
	// SHA256 is the digest of the report's bytes as read.
	SHA256 string
	// Directory is the run directory the report was read from, empty for a
	// report file given on its own.
	Directory string
	// RunRecordChecked is true when the report is a run
	// directory's and its bytes are the ones run.json recorded when the
	// Report stage wrote them. A report file given on its own cannot say
	// it was not edited, so a comparison trusts it less.
	RunRecordChecked bool
}

// ReadReport reads the report of a finished run for a comparison. path is a
// run directory or a report.json file. It only reads: a run directory is
// checked as a resume checks it (no link, nobody else's file, nothing
// others may write) and locked for the instant of the read, so a run in
// progress is refused, not read half-written; a report whose bytes differ
// from the hash run.json recorded is refused, since a comparison must never
// call something fixed on text an editor wrote.
func ReadReport(path string) (*ReadRunReport, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		raw, err := readRegular(path)
		if err != nil {
			return nil, err
		}
		return decodeReport(raw, "", false)
	}
	d, err := OpenRun(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var m Manifest
	mraw, err := readRegular(d.File(manifestFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return nil, fmt.Errorf("%s: %s is not valid: %w", path, manifestFile, err)
	}
	raw, err := readRegular(d.File(reportFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s has no %s: the run stopped before its Report stage; resume it with scheck run %s", path, reportFile, path)
	}
	if err != nil {
		return nil, err
	}
	want, recorded := m.Files[reportFile]
	sum := sha256.Sum256(raw)
	switch {
	case !recorded:
		return nil, fmt.Errorf("%s: %s does not record %s, so the report is not one this run finished writing; resume the run", path, manifestFile, reportFile)
	case want != hex.EncodeToString(sum[:]):
		return nil, fmt.Errorf("%s: %s was changed since scheck wrote it (it differs from the hash in %s); a comparison never rests on an edited report", path, reportFile, manifestFile)
	}
	return decodeReport(raw, d.Path, true)
}

func decodeReport(raw []byte, dir string, verified bool) (*ReadRunReport, error) {
	rep, err := ereport.ReadJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &ReadRunReport{Report: rep, SHA256: hex.EncodeToString(sum[:]), Directory: dir, RunRecordChecked: verified}, nil
}

// maxFileBytes bounds what ReadReport reads of any one file: a report or a
// run manifest is JSON scheck wrote, and one past this size is not.
const maxFileBytes = 256 << 20

// readRegular reads a regular file without following a link and without
// waiting on a pipe, up to maxFileBytes.
func readRegular(path string) ([]byte, error) {
	path = filepath.Clean(path)
	if info, err := os.Lstat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("%s is too large to be one scheck wrote", path)
	}
	return raw, nil
}
