package ssh

import "strings"

// commandPrefix pins the locale so parsers see stable output. It is a plain
// POSIX assignment prefix, part of the enumerable quoter domain.
const commandPrefix = "LC_ALL=C "

// Quote renders argv as one POSIX sh command line. Every token is wrapped in
// single quotes, with embedded single quotes spelled '\”. Because catalog
// literals and parameter charsets exclude everything the shell treats
// specially, the only character this function ever has to escape is the
// single quote itself (present only in the canary), which keeps the input
// domain small enough to enumerate in tests (SPEC.md §4.3).
func Quote(argv []string) string {
	var b strings.Builder
	b.WriteString(commandPrefix)
	for i, tok := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('\'')
		b.WriteString(strings.ReplaceAll(tok, "'", `'\''`))
		b.WriteByte('\'')
	}
	return b.String()
}
