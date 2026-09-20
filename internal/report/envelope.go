package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// SchemaVersion identifies the development envelope. 1.1 adds per-fact
// summaries, the typed `parsed` shapes, rule findings and the assessment
// coverage array (docs/SPEC.md §7.4). Compatibility starts at the first
// GitHub release.
const SchemaVersion = "1.1"

// Envelope is the JSON report (docs/SPEC.md §7.4), shaped so a fleet tool can
// concatenate reports: host identity block, flat findings array.
type Envelope struct {
	SchemaVersion string          `json:"schema_version"`
	Host          Host            `json:"host"`
	Run           Run             `json:"run"`
	Facts         map[string]Fact `json:"facts"`
	// Assessments is one entry per selected posture rule, findings or not:
	// coverage is reported separately from findings, because "no finding"
	// and "not assessed" are different answers (docs/SPEC.md §7.5).
	Assessments []finding.Assessment `json:"assessments"`
	Findings    []finding.Finding    `json:"findings"`
}

// OpenFindings counts the open findings at or above the profile threshold:
// the number that makes the run exit 1 (docs/SPEC.md §8).
func (e Envelope) OpenFindings(p check.Profile) int {
	return finding.OpenAtOrAbove(e.Findings, finding.Threshold(p))
}

// NotAssessed returns the assessments that could not be evaluated, which is
// what an operator reads as missing coverage.
func (e Envelope) NotAssessed() []finding.Assessment {
	var out []finding.Assessment
	for _, a := range e.Assessments {
		if a.Status == finding.NotAssessed {
			out = append(out, a)
		}
	}
	return out
}

// Host identifies the audited machine. ID is stable across runs and
// hostname changes: a hash of /etc/machine-id or IOPlatformUUID.
type Host struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	OS          string `json:"os"`
	Kernel      string `json:"kernel"`
	Transport   string `json:"transport"`
	RemoteShell string `json:"remote_shell,omitempty"`
	Canary      string `json:"canary"`
	Elevation   string `json:"elevation"`
}

// Run describes the invocation. Provider fields are null until phase 2.
type Run struct {
	Started        time.Time       `json:"started"`
	DurationMS     int64           `json:"duration_ms"`
	Status         string          `json:"status"` // complete | incomplete
	Profile        string          `json:"profile"`
	Assessment     string          `json:"assessment"`
	Mode           string          `json:"mode"` // facts | agent | single-pass
	Provider       *string         `json:"provider"`
	Model          *string         `json:"model"`
	Effort         *string         `json:"effort"`
	Native         any             `json:"native"`
	Limits         any             `json:"limits"`
	Usage          Usage           `json:"usage"`
	ContextSources []ContextSource `json:"context_sources"`
	Persisted      *string         `json:"persisted"` // path, or null
	Warnings       []string        `json:"warnings"`
	Version        string          `json:"scheck_version"`
}

// Usage is token accounting; cost is null when the provider has no price.
type Usage struct {
	Input      int      `json:"input"`
	Output     int      `json:"output"`
	CacheRead  int      `json:"cache_read"`
	CacheWrite int      `json:"cache_write"`
	CostUSD    *float64 `json:"cost_usd"`
}

// ContextSource records one operator-context input with its hash.
type ContextSource struct {
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
}

// Meta is what the caller knows that the fact sheet does not.
type Meta struct {
	Started   time.Time
	Transport string
	Canary    string // ok | fail | n/a
	Elevation string
	Profile   string
	Version   string
	// Disabled is config `disable_checks`: a rule whose check was disabled is
	// not assessed, and says so (docs/SPEC.md §7.5).
	Disabled []string
}

// Build assembles the envelope from a fact sheet.
func Build(sheet *baseline.FactSheet, meta Meta) Envelope {
	prof, _ := check.ParseProfile(meta.Profile)
	assessed := finding.Evaluate(finding.Input{Sheet: sheet, Profile: prof, Disabled: meta.Disabled})
	env := Envelope{
		SchemaVersion: SchemaVersion,
		Facts:         FactsFrom(sheet),
		Assessments:   assessed.Assessments,
		Findings:      assessed.Findings,
		Run: Run{
			Started:        meta.Started,
			DurationMS:     time.Since(meta.Started).Milliseconds(),
			Status:         "complete",
			Profile:        meta.Profile,
			Mode:           "facts",
			Assessment:     "rules",
			ContextSources: []ContextSource{},
			Warnings:       []string{},
			Version:        meta.Version,
		},
	}
	if sheet.Incomplete {
		env.Run.Status = "incomplete"
		env.Run.Warnings = append(env.Run.Warnings, "run timed out before every baseline check ran")
	}
	env.Host = hostFrom(sheet, meta)
	if env.Host.ID == "" {
		env.Host.ID = HashID("hostname:" + env.Host.Hostname)
		env.Run.Warnings = append(env.Run.Warnings, "host.id derived from hostname: machine identifier unavailable")
	}
	return env
}

// HashID hashes a raw machine identifier into host.id.
func HashID(raw string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(raw))))
	return hex.EncodeToString(sum[:])
}

func hostFrom(sheet *baseline.FactSheet, meta Meta) Host {
	h := Host{
		Platform:    string(sheet.Platform),
		Hostname:    sheet.Raw("host.hostname"),
		RemoteShell: sheet.Raw("sys.shell"),
		Transport:   meta.Transport,
		Canary:      meta.Canary,
		Elevation:   meta.Elevation,
	}
	if f := strings.Fields(sheet.Raw("sys.uname")); len(f) >= 3 {
		h.Kernel = f[2]
	}
	switch sheet.Platform {
	case check.Linux:
		if raw := sheet.Raw("host.machine_id"); raw != "" {
			h.ID = HashID(raw)
		}
		if r, ok := sheet.Get("os.release"); ok {
			if kv, ok := r.Parsed.(map[string]string); ok {
				h.OS = kv["pretty_name"]
				if h.OS == "" {
					h.OS = strings.TrimSpace(kv["name"] + " " + kv["version_id"])
				}
			}
		}
	case check.MacOS:
		if raw := sheet.Raw("host.platform_uuid"); raw != "" {
			h.ID = HashID(raw)
		}
		if r, ok := sheet.Get("os.release"); ok {
			if kv, ok := r.Parsed.(map[string]string); ok {
				h.OS = strings.TrimSpace(kv["productname"] + " " + kv["productversion"])
				if b := kv["buildversion"]; b != "" {
					h.OS += " (" + b + ")"
				}
			}
		}
	}
	return h
}
