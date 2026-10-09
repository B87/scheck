package web

import (
	"embed"
	"strings"
)

// PublicSuffixVersion pins the embedded ICANN and private PSL rules used only
// for the bounded legacy DMARC fallback (docs/spec/web-collector.md, "Email").
const PublicSuffixVersion = "3929462652695bad04f0a27afb600974014a3c8b"

//go:embed data/public_suffix_list.dat
var suffixData embed.FS

var suffixRules = func() map[string]bool {
	data, _ := suffixData.ReadFile("data/public_suffix_list.dat")
	rules := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, "//") {
			rules[line] = true
		}
	}
	return rules
}()

// organizationalDomain applies the PSL's longest rule, wildcard and exception
// algorithm. An unknown suffix is insufficient evidence; the default '*' rule
// must not let a stale snapshot establish that no parent policy can apply.
func organizationalDomain(name string) string {
	labels := strings.Split(name, ".")
	suffix := 0
	for i := range labels {
		part := strings.Join(labels[i:], ".")
		if suffixRules["!"+part] {
			suffix = len(labels) - i - 1
			break
		}
		if suffixRules[part] && len(labels)-i > suffix {
			suffix = len(labels) - i
		}
		if i > 0 && suffixRules["*."+part] && len(labels)-i+1 > suffix {
			suffix = len(labels) - i + 1
		}
	}
	if suffix == 0 || len(labels) <= suffix {
		return ""
	}
	return strings.Join(labels[len(labels)-suffix-1:], ".")
}
