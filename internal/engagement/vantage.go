package engagement

import (
	"runtime"
	"slices"
	"strings"
)

// ValidVantage validates the operator declaration, never detecting its value
// (docs/spec/engagement.md, "Reachability and vantage").
func ValidVantage(v string) bool { return v == "" || v == "internet" || v == "vpn" || v == "lan" }

func VantageWarnings(res *Resolved, v string) []string {
	var out []string
	if len(res.Intent.NotExposed) > 0 {
		switch v {
		case "":
			out = append(out, "Pages you said are restricted were not checked for reachability: the run's vantage was not given (--vantage internet). internet means outside every permitted source, including office allowlists and VPN.")
		case "vpn", "lan":
			out = append(out, "Pages you said are restricted were not checked for outside reachability: you declared this run came from inside your network.")
		}
	}
	if v == "vpn" && runtime.GOOS == "darwin" {
		out = append(out, "DNS uses /etc/resolv.conf; per-interface VPN resolvers on macOS are not used.")
	}
	return out
}

// mailInputs ties reuse to declarations by canonical domain, independent of
// list order (docs/spec/scope.md, "Resume"). All dependent reads inherit it.
func mailInputs(res *Resolved) map[string]string {
	byDomain := map[string][]string{}
	for _, s := range res.Mail.Senders {
		d := strings.TrimSuffix(strings.ToLower(s.Domain), ".")
		sels := slices.Clone(s.DKIMSelectors)
		for i := range sels {
			sels[i] = strings.ToLower(sels[i])
		}
		slices.Sort(sels)
		byDomain[d] = append(byDomain[d], fingerprint(struct {
			Service   string
			Selectors []string
		}{s.Service, sels}))
	}
	for _, d := range res.Mail.NoMail {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		byDomain[d] = append(byDomain[d], "no_mail")
	}
	out := map[string]string{}
	for d, entries := range byDomain {
		slices.Sort(entries)
		out[d] = fingerprint(entries)
	}
	return out
}
func intentInputs(res *Resolved) map[string]string {
	out := map[string]string{}
	for _, list := range []struct {
		role    string
		entries []Exposure
	}{{"exposed", res.Intent.ExposedOnPurpose}, {"restricted", res.Intent.NotExposed}} {
		for _, e := range list.entries {
			ref, _ := parseURL(e.URL)
			// Only consumed reachability context refreshes the request. Reasons and
			// acceptance changes are regraded against the retained observation.
			out[strings.TrimPrefix(ref.ID, "url:")] = fingerprint(struct{ Role, Audience string }{list.role, e.Audience})
		}
	}
	return out
}
