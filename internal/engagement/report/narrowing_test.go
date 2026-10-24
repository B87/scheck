package report

import (
	"testing"

	"github.com/b87/scheck/internal/check"
	hostreport "github.com/b87/scheck/internal/report"
)

// A read refused for a deny_paths entry is counted under that entry; a walk
// refused because a denied path lies inside its root has no one entry to
// blame and counts under deny_paths as a whole, never dropped
// (docs/spec/report.md, "Excluded, narrowed and not run").
func TestNarrowingCountsADenyInsideRefusalUnderDenyPathsAsAWhole(t *testing.T) {
	v := &hostView{
		platform: check.Linux,
		h:        &HostInput{DenyPaths: []Entry{{Value: "/srv/app/keys", Source: "engagement.yaml assets.web.deny_paths[0]"}}},
		env: hostreport.Envelope{Observations: map[string]hostreport.Observation{
			"text.cat#1":        {ReasonCode: "path_denied", Reason: "path.config_deny: /srv/app/keys/x"},
			"creds.app_env_1#1": {ReasonCode: "path_denied", Reason: "path.deny_inside: /srv/shop"},
		}},
	}
	got := (&builder{}).narrowing(v)
	var perEntry, whole int
	for _, n := range got {
		if n.DeniedReads == nil {
			continue
		}
		if n.Entry == "engagement.yaml assets.web.deny_paths" {
			whole = *n.DeniedReads
		} else {
			perEntry = *n.DeniedReads
		}
	}
	if perEntry != 1 || whole != 1 {
		t.Errorf("per entry %d, as a whole %d: %+v", perEntry, whole, got)
	}
}
