package check

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
)

// The registry. Per-platform packages register their checks in init(); the
// runner and CLI read through the accessors below. Entries are immutable
// after registration.
var (
	mu      sync.RWMutex
	entries []Check
)

var idRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Register adds checks to the catalog. It panics on a malformed id or on a
// duplicate (id, platform) pair, because that is a programming error in a
// compiled-in table, not a runtime condition.
func Register(cs ...Check) {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range cs {
		if !idRe.MatchString(c.ID) {
			panic(fmt.Sprintf("check: malformed id %q", c.ID))
		}
		if c.Platform == "" {
			panic(fmt.Sprintf("check %s: platform is required", c.ID))
		}
		for _, e := range entries {
			if e.ID != c.ID {
				continue
			}
			if e.Platform == c.Platform || e.Platform == Any || c.Platform == Any {
				panic(fmt.Sprintf("check %s: duplicate registration for platform %s", c.ID, c.Platform))
			}
		}
		entries = append(entries, c)
	}
}

// Reset empties the catalog. Tests only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	entries = nil
}

// All returns every registered check, sorted by (id, platform).
func All() []Check {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Check, len(entries))
	copy(out, entries)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Platform < out[j].Platform
	})
	return out
}

// Lookup returns the check with the given id for platform p: the
// platform-specific entry if one exists, otherwise the Any entry.
func Lookup(id string, p Platform) (Check, bool) {
	mu.RLock()
	defer mu.RUnlock()
	var anyMatch *Check
	for i := range entries {
		e := &entries[i]
		if e.ID != id {
			continue
		}
		if e.Platform == p {
			return *e, true
		}
		if e.Platform == Any {
			anyMatch = e
		}
	}
	if anyMatch != nil {
		return *anyMatch, true
	}
	return Check{}, false
}

// ForPlatform returns every check applicable to p and visible at profile
// prof, sorted by id.
func ForPlatform(p Platform, prof Profile) []Check {
	var out []Check
	for _, c := range All() {
		if c.AppliesTo(p) && c.MinProfile <= prof {
			out = append(out, c)
		}
	}
	return out
}

// Baseline returns the phase 1 set for platform p, sorted by id.
func Baseline(p Platform) []Check {
	var out []Check
	for _, c := range All() {
		if c.Baseline && c.AppliesTo(p) {
			out = append(out, c)
		}
	}
	return out
}
