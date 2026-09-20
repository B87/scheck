package check

import (
	"fmt"
	"regexp"
	"strings"
)

// Typed parser shapes (docs/SPEC.md §3). A shape exists when something
// downstream needs fields rather than text: the summary line (§7.6), a
// posture rule (§7.5) or, later, `scheck diff` (§7.4).
const (
	ParseListeners    ParserKind = "listeners"
	ParseAccounts     ParserKind = "accounts"
	ParsePasswdStatus ParserKind = "passwd_status"
	ParseUnits        ParserKind = "units"
	ParseUpdates      ParserKind = "updates"
	ParseLaunchd      ParserKind = "launchd"
	ParseFileMode     ParserKind = "file_mode"
)

// Field names of the typed shapes. A rule predicate names one of these
// (docs/SPEC.md §7.5), so they are constants rather than literals.
const (
	FieldProtocol = "protocol"
	FieldAddress  = "address"
	FieldPort     = "port"
	FieldPID      = "pid"
	FieldProcess  = "process"
	FieldName     = "name"
	FieldUID      = "uid"
	FieldShell    = "shell"
	FieldHome     = "home"
	FieldStatus   = "status"
	FieldState    = "state"
	FieldVersion  = "version"
	FieldLabel    = "label"
	FieldMode     = "mode"
	FieldSymbolic = "symbolic"
	FieldUser     = "user"
	FieldGroup    = "group"
	FieldSize     = "size"
)

// Record is one row of a typed shape: named fields, so a posture rule reads a
// value instead of a substring and `scheck diff` compares records instead of
// lines.
type Record map[string]string

// Records is what a typed parser produces. Partial says the record set is
// known to be incomplete — the output was truncated, carried a redaction, or
// held a line the format's parser did not recognise. A posture rule may prove
// an existential condition from a partial set but never a negative one
// (docs/SPEC.md §7.5), so completeness travels with the records.
type Records struct {
	Kind    ParserKind `json:"kind"`
	Items   []Record   `json:"items"`
	Partial bool       `json:"partial"`
	Note    string     `json:"note,omitempty"`
}

// Len is the number of parsed records.
func (r Records) Len() int { return len(r.Items) }

// IsTyped reports whether kind is one of the typed shapes.
func IsTyped(kind ParserKind) bool {
	switch kind {
	case ParseListeners, ParseAccounts, ParsePasswdStatus, ParseUnits, ParseUpdates, ParseLaunchd, ParseFileMode:
		return true
	}
	return false
}

// parseRecords dispatches on the shape. The check is passed in because two
// hosts answer the same question with different tools: `ss` and `lsof` both
// produce listeners, `apt`, `dnf`, `zypper` and `softwareupdate` all produce
// updates. Keying the format off the catalog's own argv[0] keeps the choice
// deterministic instead of sniffing the target's output.
func parseRecords(c Check, raw []byte) (Records, error) {
	lines := parseLines(raw)
	recs := Records{Kind: c.Parser, Items: []Record{}}
	body := make([]string, 0, len(lines))
	markers := 0
	for _, l := range lines {
		if isMarkerLine(l) {
			markers++
			recs.Partial = true
			recs.Note = "output was truncated or redacted"
			continue
		}
		body = append(body, l)
	}
	var (
		items    []Record
		unparsed int
		err      error
	)
	switch c.Parser {
	case ParseListeners:
		items, unparsed = parseListeners(baseName(c.Argv[0]), body)
	case ParseAccounts:
		items, unparsed = parseAccounts(body)
	case ParsePasswdStatus:
		items, unparsed = parsePasswdStatus(body)
	case ParseUnits:
		items, unparsed = parseUnits(body)
	case ParseUpdates:
		items, unparsed = parseUpdates(baseName(c.Argv[0]), body)
	case ParseLaunchd:
		items, unparsed = parseLaunchd(body)
	case ParseFileMode:
		items, err = parseFileMode(body)
	default:
		return recs, fmt.Errorf("unknown typed shape %q", c.Parser)
	}
	if err != nil {
		return recs, err
	}
	recs.Items = items
	if unparsed > 0 {
		recs.Partial = true
		recs.Note = fmt.Sprintf("%d line(s) not recognised", unparsed)
		if markers > 0 {
			recs.Note += "; output was truncated or redacted"
		}
	}
	return recs, nil
}

func isMarkerLine(l string) bool {
	t := strings.TrimSpace(l)
	return strings.HasPrefix(t, "[TRUNCATED:") || strings.HasPrefix(t, "[REDACTED:")
}

// hasMarker reports whether a value carries a redaction or truncation marker,
// which makes any claim about its exact content unsafe.
func hasMarker(s string) bool {
	return strings.Contains(s, "[REDACTED:") || strings.Contains(s, "[TRUNCATED:")
}

// parseListeners reads `ss -tulpnH` or `lsof -nP -iTCP -sTCP:LISTEN`.
func parseListeners(bin string, lines []string) ([]Record, int) {
	if bin == "lsof" {
		return parseLsof(lines)
	}
	return parseSS(lines)
}

var ssProcess = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

func parseSS(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			bad++
			continue
		}
		addr, port := splitHostPort(f[4])
		rec := Record{FieldProtocol: f[0], FieldState: f[1], FieldAddress: addr, FieldPort: port}
		if len(f) > 6 {
			if m := ssProcess.FindStringSubmatch(strings.Join(f[6:], " ")); m != nil {
				rec[FieldProcess], rec[FieldPID] = m[1], m[2]
			}
		}
		out = append(out, rec)
	}
	return out, bad
}

func parseLsof(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && f[0] == "COMMAND" {
			continue // header
		}
		if !strings.Contains(l, "(LISTEN)") {
			continue // lsof prints established sockets too when asked broadly
		}
		if len(f) < 9 {
			bad++
			continue
		}
		addr, port := splitHostPort(f[8])
		out = append(out, Record{
			FieldProtocol: strings.ToLower(f[7]), FieldState: "LISTEN",
			FieldAddress: addr, FieldPort: port, FieldPID: f[1], FieldProcess: f[0],
		})
	}
	return out, bad
}

// splitHostPort splits "0.0.0.0:22", "[::]:22" or "*:631" into address and
// port without pretending to understand every future ss format.
func splitHostPort(s string) (string, string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	host := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	return host, s[i+1:]
}

// parseAccounts reads /etc/passwd rows or `dscl . -list /Users UniqueID`.
func parseAccounts(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if f := strings.Split(l, ":"); len(f) >= 7 {
			out = append(out, Record{FieldName: f[0], FieldUID: f[2], FieldHome: f[5], FieldShell: f[6]})
			continue
		}
		f := strings.Fields(l)
		if len(f) != 2 {
			bad++
			continue
		}
		out = append(out, Record{FieldName: f[0], FieldUID: f[1]})
	}
	return out, bad
}

// parsePasswdStatus reads `passwd -S -a`: "root L 2026-09-11 0 99999 7 -1".
func parsePasswdStatus(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			bad++
			continue
		}
		out = append(out, Record{FieldName: f[0], FieldStatus: f[1]})
	}
	return out, bad
}

var unitsListed = regexp.MustCompile(`^\d+ unit files? listed`)

// parseUnits reads `systemctl list-unit-files --state=enabled --plain`.
func parseUnits(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		if unitsListed.MatchString(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "UNIT" && f[1] == "FILE" {
			continue // header
		}
		if len(f) < 2 {
			bad++
			continue
		}
		out = append(out, Record{FieldName: f[0], FieldState: f[1]})
	}
	return out, bad
}

var (
	suLabel   = regexp.MustCompile(`^\*\s*Label:\s*(.+)$`)
	suVersion = regexp.MustCompile(`Version:\s*([^,]+)`)
	aptLine   = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s`)
)

// parseUpdates reads the pending-update list of whichever package manager the
// catalog entry named.
func parseUpdates(bin string, lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	switch bin {
	case "softwareupdate":
		for i, l := range lines {
			m := suLabel.FindStringSubmatch(strings.TrimSpace(l))
			if m == nil {
				continue // banner, scan diagnostics and Title: rows
			}
			rec := Record{FieldName: strings.TrimSpace(m[1])}
			if i+1 < len(lines) {
				if v := suVersion.FindStringSubmatch(lines[i+1]); v != nil {
					rec[FieldVersion] = strings.TrimSpace(v[1])
				}
			}
			out = append(out, rec)
		}
	case "apt":
		for _, l := range lines {
			if strings.HasPrefix(l, "Listing") || strings.HasPrefix(l, "WARNING") || strings.HasPrefix(l, "N: ") {
				continue
			}
			m := aptLine.FindStringSubmatch(l)
			if m == nil {
				bad++
				continue
			}
			out = append(out, Record{FieldName: m[1], FieldVersion: m[3]})
		}
	case "zypper":
		for _, l := range lines {
			f := strings.Split(l, "|")
			if len(f) < 4 || strings.HasPrefix(strings.TrimSpace(l), "-") {
				continue // frame, header and "No updates found."
			}
			name := strings.TrimSpace(f[1])
			if name == "" || strings.EqualFold(name, "Name") {
				continue
			}
			out = append(out, Record{FieldName: name, FieldVersion: strings.TrimSpace(f[2])})
		}
	default: // dnf / yum check-update
		for _, l := range lines {
			if strings.HasPrefix(l, "Last metadata") || strings.HasPrefix(l, "Obsoleting") {
				continue
			}
			f := strings.Fields(l)
			if len(f) < 3 {
				bad++
				continue
			}
			out = append(out, Record{FieldName: f[0], FieldVersion: f[1]})
		}
	}
	return out, bad
}

// parseLaunchd reads `launchctl list`: PID, last exit status, label.
func parseLaunchd(lines []string) ([]Record, int) {
	out, bad := []Record{}, 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "PID" && f[2] == "Label" {
			continue // header
		}
		if len(f) < 3 {
			bad++
			continue
		}
		out = append(out, Record{FieldPID: f[0], FieldStatus: f[1], FieldLabel: f[2]})
	}
	return out, bad
}

// parseFileMode reads a stat format: symbolic:octal:user:group:size[:type:name].
// It yields one record, so a rule can read the mode as a value instead of
// matching a substring of a line.
func parseFileMode(lines []string) ([]Record, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("file_mode: no output")
	}
	f := strings.Split(strings.TrimSpace(lines[0]), ":")
	if len(f) < 5 {
		return nil, fmt.Errorf("file_mode: want symbolic:octal:user:group:size, got %q", lines[0])
	}
	rec := Record{FieldSymbolic: f[0], FieldMode: f[1], FieldUser: f[2], FieldGroup: f[3], FieldSize: f[4]}
	if len(f) >= 7 {
		rec[FieldName] = f[6]
	}
	return []Record{rec}, nil
}

// IsMarkerLine reports whether a line is *only* a redaction or truncation
// marker — a record of removed bytes rather than a line of output.
func IsMarkerLine(s string) bool { return isMarkerLine(s) }

// HasMarker reports whether a value carries a redaction or truncation marker
// (docs/SPEC.md §4.2). A consumer that would otherwise draw a conclusion from
// the value's exact content has to treat it as incomplete evidence.
func HasMarker(s string) bool { return hasMarker(s) }
