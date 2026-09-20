// Package check defines the check catalog: the entire set of commands scheck
// can execute on a target, in either phase (docs/SPEC.md §3).
//
// A Check is a read-only command template with typed holes. The model (phase
// 2) and the baseline runner (phase 1) both pick a check by id and bind
// parameters; neither ever composes argv. Validate enforces the catalog
// invariants over every registered entry so "denied command" is a rare error,
// not a security boundary.
package check

import (
	"time"

	"github.com/b87/scheck/internal/target"
)

// Platform is the target platform a check applies to; Any applies everywhere.
type Platform = target.Platform

// Any marks a check that runs unchanged on every platform.
const Any Platform = "any"

// Profile gates which checks the model may see (docs/SPEC.md §3, tiers).
type Profile int

// Profiles, ordered: a check is visible when MinProfile <= active profile.
const (
	ProfileBaseline Profile = iota
	ProfileHardened
)

func (p Profile) String() string {
	switch p {
	case ProfileBaseline:
		return "baseline"
	case ProfileHardened:
		return "hardened"
	default:
		return "unknown"
	}
}

// ParseProfile maps the CLI/config spelling to a Profile.
func ParseProfile(s string) (Profile, bool) {
	switch s {
	case "", "baseline":
		return ProfileBaseline, true
	case "hardened":
		return ProfileHardened, true
	default:
		return 0, false
	}
}

// ParamKind is the type of a placeholder.
type ParamKind string

// Parameter kinds. Path and Ident are validated against a strict charset;
// Path additionally passes policy.PathPolicy before binding (in the runner).
const (
	KindPath  ParamKind = "path"
	KindEnum  ParamKind = "enum"
	KindInt   ParamKind = "int"
	KindIdent ParamKind = "ident"
)

// Param is one typed hole in Argv, referenced as "{Name}".
type Param struct {
	Name string
	Kind ParamKind
	Enum []string // Kind == KindEnum
	Min  int      // Kind == KindInt
	Max  int
}

// ParserKind selects how raw stdout is turned into structured facts.
type ParserKind string

// Parser kinds.
const (
	ParseRaw   ParserKind = "raw"
	ParseLines ParserKind = "lines"
	ParseKV    ParserKind = "kv"
	ParseJSON  ParserKind = "json"
)

// PathUse says whether a check with a Path param returns the path's content
// or only metadata about it. Under a metadata-only policy decision the runner
// substitutes the platform's metadata check for a content one.
type PathUse string

// Path uses.
const (
	PathNone     PathUse = ""
	PathContent  PathUse = "content"
	PathMetadata PathUse = "metadata"
)

// Budget holds per-check overrides; zero means "policy default". The runner
// clamps every field to policy.Budgets, so a check can only tighten.
type Budget struct {
	Soft   time.Duration
	Hard   time.Duration
	Output int
}

// Domain groups checks for chunking, --only filtering and report layout.
type Domain string

// Domains used by the baseline catalog.
const (
	DomainSys          Domain = "sys"
	DomainHost         Domain = "host"
	DomainOS           Domain = "os"
	DomainUpdates      Domain = "updates"
	DomainDisk         Domain = "disk"
	DomainIntegrity    Domain = "integrity"
	DomainFirewall     Domain = "firewall"
	DomainNetwork      Domain = "network"
	DomainSSHD         Domain = "sshd"
	DomainAccounts     Domain = "accounts"
	DomainPrivesc      Domain = "privesc"
	DomainRemoteAccess Domain = "remote-access"
	DomainPersistence  Domain = "persistence"
	DomainFS           Domain = "fs"
	DomainLogging      Domain = "logging"
	DomainTime         Domain = "time"
	DomainText         Domain = "text"
)

// Check is one catalog entry. See docs/SPEC.md §3 for field semantics.
type Check struct {
	ID          string
	Description string // one line, rendered into the model's menu
	Platform    Platform
	Domain      Domain
	Argv        []string // literal tokens; a token that is exactly "{name}" binds a Param
	Params      []Param
	Parser      ParserKind
	Baseline    bool    // runs in phase 1
	MinProfile  Profile // model sees this check only at or above this profile
	Elevated    bool    // needs the elevation prefix (docs/SPEC.md §8.1)
	Budget      Budget
	// ExitOK lists exit codes that still count as a successful read. nil means
	// {0}; AnyExit means every code (for `systemctl is-enabled` and friends,
	// whose exit code is the answer).
	ExitOK  []int
	PathUse PathUse
	// Canary marks the single entry whose literal deliberately contains shell
	// metacharacters, used to verify SSH quoting before any other command.
	Canary bool
	// Extract, when set, is a regexp with one capture group; after redaction
	// the runner keeps only that group as the raw output. It minimises what a
	// chatty command (ioreg, dmidecode) hands to the model.
	Extract string
}

// AnyExit is the ExitOK value meaning "any exit code is a valid result".
var AnyExit = []int{anyExitMarker}

const anyExitMarker = -1 << 30

// ExitAllowed reports whether code is a successful outcome for this check.
func (c Check) ExitAllowed(code int) bool {
	if c.ExitOK == nil {
		return code == 0
	}
	for _, ok := range c.ExitOK {
		if ok == anyExitMarker || ok == code {
			return true
		}
	}
	return false
}

// OnDemand reports whether the check is callable by the model rather than
// part of the phase 1 baseline.
func (c Check) OnDemand() bool { return !c.Baseline }

// AppliesTo reports whether the check runs on platform p.
func (c Check) AppliesTo(p Platform) bool {
	return c.Platform == Any || c.Platform == p
}

// HasPathParam reports whether any param is a Path.
func (c Check) HasPathParam() bool {
	for _, p := range c.Params {
		if p.Kind == KindPath {
			return true
		}
	}
	return false
}

// Platform aliases so catalog files read naturally.
const (
	Linux = target.Linux
	MacOS = target.MacOS
)
