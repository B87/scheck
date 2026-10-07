package engagement

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HostFlags are the settings `scheck run --host` takes as flags and writes
// into the asset, so every setting a run used is in the file it keeps
// (docs/spec/engagement.md, "One command, one file").
type HostFlags struct {
	Identity   string
	KnownHosts string
	Timeout    string // the host collector's run timeout, e.g. 10m
	Elevate    string // "", none or sudo
	Profile    string // "", baseline or hardened
}

// hostSource is the source path of an engagement --host built in memory.
const hostSource = "--host"

// ForHost builds the engagement `scheck run --host LOCATOR` runs: one host
// root, one asset carrying the flags, defaults and limits as `scheck init`
// writes them, a name derived from the locator and the machine's time zone,
// and nothing else. It returns the file as YAML, which is what the run
// directory keeps and --write-engagement writes, and the file resolved
// through the same validation as one read from disk.
func ForHost(locator string, h HostFlags, opts Options) (*Resolved, []byte, error) {
	ref, err := parseLocator(KindHost, locator)
	if err != nil {
		// The locator is not quoted: written user:password@host, it holds
		// a secret (parseHost refuses those without quoting them).
		return nil, nil, fmt.Errorf("--host: %w", err)
	}
	name := hostEngagementName(ref)
	f := File{
		Schema:     Schema,
		Engagement: Engagement{Name: name, Timezone: machineTimezone(), Trigger: "routine"},
		Roots:      []Locator{{Host: locator}},
		Defaults: Defaults{Probe: "off", Scan: "off",
			Throttle: &Throttle{Rate: DefaultRate, Concurrency: DefaultConcurrency}, Profile: DefaultProfile},
		Limits: Limits{Timeout: DefaultTimeout.String()},
		Assets: map[string]Asset{name: {Locator: Locator{Host: locator}, Identity: h.Identity,
			KnownHosts: h.KnownHosts, Timeout: h.Timeout, Elevate: h.Elevate, Profile: h.Profile}},
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Built by `scheck run --host` on %s. Add context, accepted risks and\n"+
		"# narrowing here, then run it with `scheck run FILE` (docs/spec/engagement.md).\n",
		time.Now().Format(time.DateOnly))
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	raw := buf.Bytes()
	res, err := Parse(hostSource, raw, opts)
	if err != nil {
		if errs, ok := errors.AsType[Errors](err); ok {
			// Only the flags can be wrong here; name them, not the line.
			msgs := make([]string, len(errs))
			for i, e := range errs {
				msgs[i] = hostFlagFor(e.Key) + ": " + e.Msg
			}
			return nil, nil, errors.New(strings.Join(msgs, "\n"))
		}
		return nil, nil, err
	}
	return res, raw, nil
}

// hostFlagFor names the flag a validation error on the built file came
// from.
func hostFlagFor(key string) string {
	switch {
	case strings.HasSuffix(key, ".identity"):
		return "--identity"
	case strings.HasSuffix(key, ".known_hosts"):
		return "--known-hosts"
	case strings.HasSuffix(key, ".timeout"):
		return "--timeout"
	case strings.HasSuffix(key, ".elevate"):
		return "--elevate"
	case strings.HasSuffix(key, ".profile"):
		return "--profile"
	}
	return "--host"
}

// hostEngagementName derives engagement.name from a host locator: the
// address with separators as dashes, and a non-default port kept, so two
// hosts on one address do not share a run directory.
func hostEngagementName(r Ref) string {
	addr := r.Address()
	name := "host-" + strings.Map(func(c rune) rune {
		if c == '.' || c == ':' {
			return '-'
		}
		return c
	}, addr)
	suffix := ""
	if !r.Local() && r.Port != 22 {
		suffix = "-" + strconv.Itoa(r.Port)
	}
	if limit := 63 - len(suffix); len(name) > limit {
		name = strings.TrimRight(name[:limit], "-")
	}
	return name + suffix
}

// machineTimezone is the IANA name of the zone scheck runs in: $TZ, else
// the zoneinfo path /etc/localtime links to, else UTC.
func machineTimezone() string {
	valid := func(z string) bool {
		_, err := time.LoadLocation(z)
		return z != "" && z != "Local" && err == nil
	}
	if z := strings.TrimPrefix(os.Getenv("TZ"), ":"); valid(z) {
		return z
	}
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if _, z, ok := strings.Cut(filepath.ToSlash(link), "zoneinfo/"); ok && valid(z) {
			return z
		}
	}
	return "UTC"
}
