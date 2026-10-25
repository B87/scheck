package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// maxReportBytes bounds what ReadJSON reads: a report is JSON scheck wrote,
// and one past this size is not.
const maxReportBytes = 256 << 20

// ReadJSON reads a report scheck wrote (docs/spec/report.md, "Text and
// JSON"), strictly: a report of another schema MAJOR, or of a MINOR newer
// than this build writes, is refused by name before any field is read, and
// an unknown field is an error, not something to skip, so a comparison of
// two reports never reads a field it does not understand as an empty one.
//
// A host asset's embedded collector envelope is dropped. It is the host
// collector's evidence, with its own schema version and, under
// --include-evidence, captures this reader has no place for; the engagement's
// findings and assessments are authoritative over it (docs/spec/report.md,
// "One severity"), and a reader that needs the envelope rebuilds it from the
// run directory's evidence.
func ReadJSON(r io.Reader) (*Report, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReportBytes {
		return nil, errors.New("report is too large to be one scheck wrote")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("not a scheck engagement report: %w", err)
	}
	var version string
	if v, ok := top["schema_version"]; !ok || json.Unmarshal(v, &version) != nil {
		return nil, errors.New("not a scheck engagement report: it has no schema_version")
	}
	if err := checkSchemaVersion(version); err != nil {
		return nil, err
	}
	if err := checkKeys(raw, reflect.TypeFor[Report]()); err != nil {
		return nil, fmt.Errorf("report does not match schema %s: %w", SchemaVersion, err)
	}
	if a, ok := top["assets"]; ok {
		var assets []map[string]json.RawMessage
		if err := json.Unmarshal(a, &assets); err != nil {
			return nil, fmt.Errorf("report assets: %w", err)
		}
		for _, asset := range assets {
			delete(asset, "envelope")
		}
		stripped, err := json.Marshal(assets)
		if err != nil {
			return nil, err
		}
		top["assets"] = stripped
	}
	body, err := json.Marshal(top)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var rep Report
	if err := dec.Decode(&rep); err != nil {
		return nil, fmt.Errorf("report does not match schema %s: %w", SchemaVersion, err)
	}
	return &rep, nil
}

// checkSchemaVersion refuses a MAJOR other than this build's, and a MINOR
// newer than it.
func checkSchemaVersion(v string) error {
	major, minor, ok := splitVersion(v)
	wantMajor, wantMinor, _ := splitVersion(SchemaVersion)
	switch {
	case !ok:
		return fmt.Errorf("report schema_version %q is not MAJOR.MINOR", v)
	case major != wantMajor:
		return fmt.Errorf("report schema_version %s: this build reads %d.x only, and a changed MAJOR changes what fields mean", v, wantMajor)
	case minor > wantMinor:
		return fmt.Errorf("report schema_version %s is newer than this build reads (%s): use the scheck that wrote it, or a newer one", v, SchemaVersion)
	}
	return nil
}

func splitVersion(v string) (major, minor int, ok bool) {
	a, b, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(a)
	minor, err2 := strconv.Atoi(b)
	return major, minor, err1 == nil && err2 == nil && major >= 0 && minor >= 0
}
