package web

import (
	_ "embed"
	"strings"
)

// BrowserDataVersion versions session names, inspection issuers and block
// markers (docs/spec/web-collector.md, "Data in the tree").
const BrowserDataVersion = "2026-10-09.1"
const PreloadVersion = "2026-10-09.1:d5e6fd51b430fec89732a3976e666011ecffa0a2"

//go:embed data/preloaded_tlds.txt
var preloadData string

func preloaded(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	tld := labels[len(labels)-1]
	for v := range strings.SplitSeq(preloadData, "\n") {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "#") {
			continue
		}
		if v == tld {
			return tld
		}
	}
	return ""
}

var inspectionIssuers = []string{"zscaler", "netskope", "fortigate", "fortinet", "palo alto networks", "cisco umbrella", "sophos", "kaspersky", "eset", "avast", "bitdefender"}
