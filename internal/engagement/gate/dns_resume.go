package gate

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
)

// requestVantage keeps third-party API evidence independent of where web and
// DNS observations came from (docs/spec/scope.md, "Resume").
func (g *Gate) requestVantage(op *compiled) string {
	if op.Provider == "web" || op.Provider == "crt.sh" {
		return g.vantage
	}
	return ""
}

func (g *Gate) dnsInput(name string) string {
	best, value := "", ""
	for domain, input := range g.dnsInputs {
		if (name == domain || strings.HasSuffix(name, "."+domain)) && len(domain) > len(best) {
			best, value = domain, input
		}
	}
	return value
}
func (g *Gate) dnsIdentity(e Entry, name, typ, input string) string {
	if g.rules == "" {
		return ""
	}
	b, _ := json.Marshal([]string{e.Op, e.Asset, name, typ, input, g.rules, g.vantage})
	return hash(b)
}

// dnsReusable refuses uncertain or marked captures and rechecks every chain
// and pointed name against today's excludes. It never authorizes an HTTP dial.
func (g *Gate) dnsReusable(r RecordSet) bool {
	if r.Insufficient() || r.ExcludedBy != "" {
		return false
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "[REDACTED:") || strings.Contains(string(b), "[TRUNCATED:") {
		return false
	}
	for _, n := range r.Chain {
		if _, err := answerName(n); err != nil || g.scope.Name(n) != "" {
			return false
		}
	}
	for _, t := range r.Targets {
		if _, err := answerName(t.Name); err != nil || g.scope.Name(t.Name) != "" {
			return false
		}
	}
	return true
}

func (g *Gate) priorDNS(e Entry, key string) (RecordSet, bool) {
	g.mu.Lock()
	p := g.prior[key]
	g.mu.Unlock()
	if key == "" || p == nil || p.Records == nil || p.Vantage != g.vantage || p.Records.Vantage != g.vantage || !g.dnsReusable(*p.Records) {
		return RecordSet{}, false
	}
	// Decode a fresh copy; no caller can mutate the stored capture.
	b, _ := json.Marshal(p.Records)
	var out RecordSet
	if json.Unmarshal(b, &out) != nil {
		return RecordSet{}, false
	}
	out.RequestID, out.Decision = e.RequestID, DecisionReused
	final := e.Params["name"]
	if len(out.Chain) > 0 {
		final = out.Chain[len(out.Chain)-1]
	}
	out.FinalInRoot = g.scope.Subject(e.Asset, "domain:"+final).Root != ""
	g.observe(e.RequestID, out.CollectedAt, out.Vantage)
	e.Event, e.Decision = DecisionReused, DecisionReused
	if g.record(e) != nil {
		return RecordSet{}, false
	}
	g.mu.Lock()
	g.reused[key] = true
	g.mu.Unlock()
	return out, true
}
func (g *Gate) keepDNS(key string, out RecordSet) {
	if key == "" || !g.dnsReusable(out) {
		return
	}
	b, _ := json.Marshal(out)
	var stored RecordSet
	if json.Unmarshal(b, &stored) != nil {
		return
	}
	g.mu.Lock()
	g.kept[key] = &Response{Vantage: g.vantage, CollectedAt: out.CollectedAt, Records: &stored}
	g.mu.Unlock()
}

// projectTXT retains only the collector's declared fields in the resume
// ledger. The rua sentinel represents presence, never the original address.
// Multiplicity, unknown records and malformed tag order remain recognizable.
func projectTXT(name string, records []string) []string {
	var out []string
	for _, txt := range records {
		if strings.HasPrefix(name, "_dmarc.") || strings.Contains(name, "._domainkey.") {
			dmarc := strings.HasPrefix(name, "_dmarc.")
			allowed := map[string]bool{"v": true, "k": true, "p": true, "t": true}
			if dmarc {
				allowed = map[string]bool{"v": true, "p": true, "sp": true, "np": true, "pct": true, "t": true, "adkim": true, "aspf": true, "rua": true}
			}
			parts := strings.Split(txt, ";")
			// Unknown non-tag records remain unknown, without their text.
			var kept []string
			for i, part := range parts {
				k, v, ok := strings.Cut(part, "=")
				k = strings.TrimSpace(k)
				if dmarc {
					k = strings.ToLower(k)
				}
				if !ok || k == "" {
					if i == 0 || strings.TrimSpace(part) != "" {
						kept = append(kept, "other")
					}
					continue
				}
				if allowed[k] {
					if k == "rua" && strings.TrimSpace(v) != "" {
						v = "present"
					}
					kept = append(kept, k+"="+v)
				} else {
					kept = append(kept, "unknown_"+hash([]byte(k))+"=")
				}
			}
			if len(kept) == 0 {
				kept = []string{"other"}
			}
			out = append(out, strings.Join(kept, ";"))
		} else if isSPFRecord(txt) || strings.Contains(txt, "[REDACTED:") || strings.Contains(txt, "[TRUNCATED:") {
			out = append(out, txt)
		}
	}
	return out
}

// installPoints rebuilds follow-up authority from the admitted projected
// record content, never from a caller's index or a persisted Via field.
func (g *Gate) installPoints(e Entry, out *RecordSet, eval, input string) {
	p := &pointed{asset: e.Asset, eval: eval, input: input, followed: map[int]bool{}}
	point := func(name, via string) { p.names = append(p.names, name); p.via = append(p.via, via) }
	if eval != "" {
		var spf []string
		for _, t := range out.TXT {
			if isSPFRecord(t) {
				spf = append(spf, t)
			}
		}
		if len(spf) == 1 {
			for _, t := range spfTargets(spf[0]) {
				point(t[1], t[0])
			}
		}
	}
	for _, m := range out.MX {
		if m.Target != "" {
			point(m.Target, "mx")
		}
	}
	for _, n := range out.NS {
		point(n, "ns")
	}
	out.Targets = nil
	for i, n := range p.names {
		out.Targets = append(out.Targets, Target{Name: n, Via: p.via[i]})
	}
	if len(p.names) > 0 {
		g.mu.Lock()
		g.pointed[e.RequestID] = p
		g.mu.Unlock()
	}
}

// Observation preserves the collection time and declared vantage of a request.
type Observation struct {
	CollectedAt time.Time
	Vantage     string
}

func (g *Gate) observe(id string, at time.Time, v string) {
	g.mu.Lock()
	g.observations[id] = Observation{at, v}
	g.mu.Unlock()
}
func (g *Gate) Observations() map[string]Observation {
	g.mu.Lock()
	defer g.mu.Unlock()
	return maps.Clone(g.observations)
}

// Entries returns the redacted audit trace, including refused attempts.
func (g *Gate) Entries() []Entry { g.mu.Lock(); defer g.mu.Unlock(); return slices.Clone(g.entries) }
