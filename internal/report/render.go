package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/b87/scheck/internal/check"
)

// WriteJSON renders the envelope as indented JSON.
func WriteJSON(w io.Writer, env Envelope) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// WriteText renders a human-readable fact sheet: header, then one line per
// check grouped by domain.
func WriteText(w io.Writer, env Envelope) error {
	h, r := env.Host, env.Run
	fmt.Fprintf(w, "scheck %s — %s (%s) — %s\n", r.Version, h.Hostname, h.Platform, h.OS)
	fmt.Fprintf(w, "host.id %s  kernel %s  transport %s", short(h.ID), h.Kernel, h.Transport)
	if h.Transport == "ssh" {
		fmt.Fprintf(w, " (shell %s, canary %s)", h.RemoteShell, h.Canary)
	}
	fmt.Fprintf(w, "  elevation %s\n", h.Elevation)
	fmt.Fprintf(w, "run %s  status %s  profile %s  mode %s  %dms\n", r.Started.Format("2006-01-02T15:04:05Z07:00"), r.Status, r.Profile, r.Mode, r.DurationMS)
	for _, wmsg := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", wmsg)
	}
	if r.Persisted != nil {
		fmt.Fprintf(w, "persisted %s\n", *r.Persisted)
	}
	fmt.Fprintln(w)

	byDomain := map[check.Domain][]string{}
	for id := range env.Facts {
		d := check.Domain("other")
		if c, ok := check.Lookup(id, check.Platform(h.Platform)); ok {
			d = c.Domain
		}
		byDomain[d] = append(byDomain[d], id)
	}
	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, string(d))
	}
	sort.Strings(domains)
	ok, unavailable := 0, 0
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, d := range domains {
		ids := byDomain[check.Domain(d)]
		sort.Strings(ids)
		fmt.Fprintf(tw, "[%s]\t\t\n", d)
		for _, id := range ids {
			f := env.Facts[id]
			mark := "-"
			switch f.Status {
			case "ok":
				mark = "+"
				ok++
			case "unavailable":
				unavailable++
			case "denied":
				mark = "!"
			}
			flags := ""
			if f.Truncated {
				flags += " [truncated]"
			}
			if f.Redactions > 0 {
				flags += fmt.Sprintf(" [%d redacted]", f.Redactions)
			}
			if f.Elevated {
				flags += " [elevated]"
			}
			fmt.Fprintf(tw, "  %s %s\t%s%s\t\n", mark, id, summary(f), flags)
		}
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\n%d checks: %d ok, %d unavailable\n", len(env.Facts), ok, unavailable)
	if len(env.Findings) == 0 {
		fmt.Fprintln(w, "findings: none (phase 1 reports facts only)")
	}
	return nil
}

func summary(f Fact) string {
	if f.Status != "ok" {
		return f.Status + ": " + f.Reason
	}
	switch v := f.Parsed.(type) {
	case string:
		return firstLine(v)
	case []string:
		if len(v) == 0 {
			return "0 lines"
		}
		return fmt.Sprintf("%d lines: %s", len(v), firstLine(v[0]))
	case []any:
		return fmt.Sprintf("%d items", len(v))
	case map[string]string:
		return fmt.Sprintf("%d keys", len(v))
	case map[string]any:
		return fmt.Sprintf("%d keys", len(v))
	default:
		return "ok"
	}
}

func firstLine(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\t", " ")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len(s) > 100 {
		s = s[:100] + "…"
	}
	return s
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
