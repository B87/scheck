package advisory

import (
	"strconv"
	"strings"
)

// compareDpkg orders two Debian package versions as dpkg does
// ([epoch:]upstream[-revision]; "~" sorts before everything, even the end).
// It is the only comparison a distribution package may be judged by: a
// distribution's fixed package is a package version, never a PHP or Node.js
// version.
func compareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := dpkgPart(ua, ub); c != 0 {
		return c
	}
	return dpkgPart(ra, rb)
}

func splitDpkg(v string) (epoch int, upstream, revision string) {
	if i := strings.Index(v, ":"); i > 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			epoch, v = e, v[i+1:]
		}
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// dpkgPart compares one part by dpkg's rule: alternating non-digit and digit
// runs, letters before other characters, "~" before the end.
func dpkgPart(a, b string) int {
	for a != "" || b != "" {
		// Non-digit prefix.
		na, nb := leadNonDigits(a), leadNonDigits(b)
		a, b = a[len(na):], b[len(nb):]
		if c := dpkgLexical(na, nb); c != 0 {
			return c
		}
		da, db := leadDigits(a), leadDigits(b)
		a, b = a[len(da):], b[len(db):]
		ia, ib := atoi(da), atoi(db)
		if ia != ib {
			if ia < ib {
				return -1
			}
			return 1
		}
	}
	return 0
}

func leadNonDigits(s string) string {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return s[:i]
}

func leadDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func dpkgOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c == '~':
		return -1
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func dpkgLexical(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var ca, cb byte
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		oa, ob := dpkgOrder(ca, i >= len(a)), dpkgOrder(cb, i >= len(b))
		if oa != ob {
			if oa < ob {
				return -1
			}
			return 1
		}
	}
	return 0
}

// upstreamCore is the leading dotted number of a version after any epoch
// ("8.2.35-1.remi" is [8 2 35]); ok is false when there is none.
func upstreamCore(v string) (parts []int, ok bool) {
	if i := strings.Index(v, ":"); i > 0 {
		if _, err := strconv.Atoi(v[:i]); err == nil {
			v = v[i+1:]
		}
	}
	v = strings.TrimPrefix(v, "v")
	end := 0
	for end < len(v) && (v[end] == '.' || v[end] >= '0' && v[end] <= '9') {
		end++
	}
	for f := range strings.SplitSeq(strings.TrimRight(v[:end], "."), ".") {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, len(parts) > 0
}

// compareCore compares two dotted numbers, a missing component being zero.
func compareCore(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
