package report

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/b87/scheck/internal/finding"
)

// DefaultWidth is the wrap column when the caller does not know the terminal
// width (docs/SPEC.md §7.6).
const DefaultWidth = 100

// minWidth keeps the layout usable in a very narrow terminal; below it the
// columns cost more than they align.
const minWidth = 40

// Options control the text report. The caller owns the terminal questions:
// report never inspects a file descriptor or the environment.
type Options struct {
	// Verbose is 0 (default), 1 (-v: check descriptions and run detail) or
	// 2 (-vv: the redacted output of every check that ran).
	Verbose int
	// Width is the wrap column; 0 means DefaultWidth.
	Width int
	// Color enables styling. The caller sets it only for a terminal that is
	// not under NO_COLOR (docs/SPEC.md §7.6).
	Color bool
}

func (o Options) normalize() Options {
	if o.Width <= 0 {
		o.Width = DefaultWidth
	}
	if o.Width < minWidth {
		o.Width = minWidth
	}
	if o.Verbose < 0 {
		o.Verbose = 0
	}
	return o
}

// style renders emphasis: bold headings, dim evidence, and the severity
// colours, which are the only colours in the contract (docs/SPEC.md §7.6).
// Everything here is a no-op when Color is false.
type style struct{ on bool }

func (s style) bold(t string) string { return s.wrap(t, "\x1b[1m") }
func (s style) dim(t string) string  { return s.wrap(t, "\x1b[2m") }

// severity is the one colour in the report that carries meaning
// (docs/SPEC.md §7.6). info is left unstyled: it is information, not alarm.
func (s style) severity(sev finding.Severity, t string) string {
	switch sev {
	case finding.SevCritical:
		return s.wrap(t, "\x1b[1;31m")
	case finding.SevHigh:
		return s.wrap(t, "\x1b[31m")
	case finding.SevMedium:
		return s.wrap(t, "\x1b[33m")
	case finding.SevLow:
		return s.wrap(t, "\x1b[36m")
	default:
		return t
	}
}

func (s style) wrap(t, seq string) string {
	if !s.on || t == "" {
		return t
	}
	return seq + t + "\x1b[0m"
}

// sanitize makes target-derived text safe to print on a terminal: control
// characters from a target's output must never be able to move the cursor,
// repaint the screen or forge a line of this report. Newlines survive (the
// caller splits on them) and tabs are expanded by expandTabs first.
func sanitize(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isControl(r rune) bool {
	return r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r))
}

// Sanitize is sanitize for callers outside the package that print text of
// uncertain origin (`scheck config show`, `scheck explain`).
func Sanitize(s string) string { return sanitize(s) }

// inline prevents target-derived fields from forging report structure (§7.6).
func inline(s string) string { return strings.Join(strings.Fields(sanitize(s)), " ") }

// expandTabs replaces tabs with spaces to the next eight-column stop, so a
// command's own column alignment survives being re-indented.
func expandTabs(s string) string {
	if !strings.ContainsRune(s, '\t') {
		return s
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		if r == '\t' {
			n := 8 - col%8
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		if r == '\n' {
			col = 0
		} else {
			col++
		}
	}
	return b.String()
}

// Wrap is wrap, for callers outside the package that render alongside a
// report (`scheck explain`) and must break lines the same way.
func Wrap(s string, width int) []string { return wrap(s, width) }

// wrap breaks s into lines of at most width runes, preferring a break at a
// space and falling back to a hard cut, so no byte of evidence is silently
// dropped (docs/SPEC.md §7.6). Lines carry no trailing padding.
func wrap(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for para := range strings.SplitSeq(s, "\n") {
		out = append(out, wrapOne(strings.TrimRight(para, " "), width)...)
	}
	return out
}

func wrapOne(s string, width int) []string {
	r := []rune(s)
	if len(r) <= width {
		return []string{s}
	}
	var out []string
	for len(r) > 0 {
		var line string
		line, r = chunk(r, width)
		out = append(out, line)
	}
	return out
}

// chunk takes the longest prefix of r that fits in width, preferring a break
// at a space and falling back to a hard cut so no evidence is dropped.
func chunk(r []rune, width int) (string, []rune) {
	if len(r) <= width {
		return strings.TrimRight(string(r), " "), nil
	}
	cut := width
	// Prefer the last space in the line, but not one so early that the line
	// is mostly empty.
	for i := width; i > width/2; i-- {
		if r[i] == ' ' {
			cut = i
			break
		}
	}
	cut = avoidMarkerSplit(r, cut)
	line := strings.TrimRight(string(r[:cut]), " ")
	for cut < len(r) && r[cut] == ' ' {
		cut++
	}
	return line, r[cut:]
}

// markerPrefixes are the two markers the policy layer writes into output.
var markerPrefixes = []string{"[REDACTED:", "[TRUNCATED:"}

// avoidMarkerSplit pulls cut back to the start of a redaction or truncation
// marker it would otherwise break. The marker is the only record that bytes
// were removed (docs/SPEC.md §4.2); a reader has to be able to see it whole.
// A marker wider than the column is still cut, because dropping it would be
// worse than splitting it.
func avoidMarkerSplit(r []rune, cut int) int {
	for start := range cut {
		if r[start] != '[' {
			continue
		}
		if !hasPrefixAt(r, start, markerPrefixes) {
			continue
		}
		end := start
		for end < len(r) && r[end] != ']' {
			end++
		}
		if end >= len(r) || end < cut {
			continue // closed before the break, or never closed
		}
		if start > 0 {
			return start
		}
	}
	return cut
}

func hasPrefixAt(r []rune, i int, prefixes []string) bool {
	for _, p := range prefixes {
		if len(r)-i < len(p) {
			continue
		}
		if string(r[i:i+len(p)]) == p {
			return true
		}
	}
	return false
}

// wrapHanging lays s out so the first line fits after the prefix first and
// every continuation after indent, both inside width. Newlines in s are
// folded to spaces: a hanging block is one logical sentence.
func wrapHanging(first, indent, s string, width int) []string {
	firstAvail := max(width-len([]rune(first)), 16)
	restAvail := max(width-len([]rune(indent)), 16)
	r := []rune(strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " "))
	if len(r) == 0 {
		return []string{first}
	}
	var out []string
	line, rest := chunk(r, firstAvail)
	out = append(out, first+line)
	for len(rest) > 0 {
		line, rest = chunk(rest, restAvail)
		out = append(out, indent+line)
	}
	return out
}

// pad right-pads s to n runes. It is only ever used between columns, never at
// the end of a line (docs/SPEC.md §7.6: no trailing padding).
func pad(s string, n int) string {
	if d := n - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}
