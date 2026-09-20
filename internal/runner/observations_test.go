package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/target/fixture"
)

func TestObservationsRetainRepeatedResults(t *testing.T) {
	h := newHarness(t, ElevateRoot, fixture.Exec{Argv: []string{"cat", "/etc/hosts"}, Stdout: "first"})
	params := map[string]string{"path": "/etc/hosts"}
	first := h.r.Run(context.Background(), "text.cat", params)
	// A second response to the identical request must not alter the first capture.
	h.r.Target = fixture.New(check.Linux, fixture.Exec{Argv: []string{"cat", "/etc/hosts"}, Stdout: "second"})
	second := h.r.Run(context.Background(), "text.cat", params)
	params["path"] = "/etc/changed"
	first.Params["path"] = "/etc/mutated"
	first.Parsed.([]string)[0] = "mutated"
	stored, ok := h.r.Observations().Get(first.Observation)
	if !ok || stored.Raw != "first" || stored.Params["path"] != "/etc/hosts" || stored.Parsed.([]string)[0] != "first" {
		t.Fatalf("mutated observation: %+v", stored)
	}
	if second.Observation == first.Observation || second.Raw != "second" || second.Occurrence <= first.Occurrence {
		t.Fatalf("repeated call: %+v", second)
	}
	stored.Params["path"] = "changed again"
	all := h.r.Observations().All()
	all[0].Argv[0] = "changed"
	again, _ := h.r.Observations().Get(first.Observation)
	if again.Params["path"] != "/etc/hosts" || h.r.Observations().All()[0].Argv[0] == "changed" {
		t.Fatal("Get exposed mutable storage")
	}
	if _, ok := h.r.Observations().Get("text.cat"); ok {
		t.Fatal("check ID resolved as observation")
	}
	if _, ok := h.r.Observations().Get("missing#1"); ok {
		t.Fatal("unknown reference resolved")
	}
}

func TestObservationDenialsAndMetadataAreRedacted(t *testing.T) {
	h := newHarness(t, ElevateNone)
	ctx := context.Background()
	const secret = "AKIAIOSFODNN7EXAMPLE"
	unknown := h.r.Run(ctx, secret, map[string]string{"path": "/etc/" + secret, "password": "sentinel-password-value"})
	invalid := h.r.Run(ctx, "text.cat", map[string]string{"path": "relative/" + secret})
	denied := h.r.Run(ctx, "text.cat", map[string]string{"path": "/tmp/" + secret})
	unavailable := h.r.Run(ctx, "sshd.config", nil)
	if unknown.Attempted || invalid.Attempted || denied.Attempted || unavailable.Attempted {
		t.Fatal("denied/skipped calls claim execution")
	}
	if unknown.RanAs != "" || len(invalid.Argv) != 0 || len(denied.Argv) == 0 {
		t.Fatal("catalog resolution / typed binding attribution incorrect")
	}
	for _, r := range []Result{unknown, invalid, denied, unavailable} {
		got, ok := h.r.Observations().Get(r.Observation)
		if !ok || got.Status != r.Status || got.Observation == "" {
			t.Fatalf("lost outcome %+v", r)
		}
	}
	for _, e := range h.entries(t) {
		if _, ok := h.r.Observations().Get(e.Observation); !ok {
			t.Fatalf("unresolved audit %+v", e)
		}
	}
	raw, _ := json.Marshal(h.r.Observations().All())
	for _, artifact := range []string{string(raw), h.audit.String()} {
		if strings.Contains(artifact, secret) || strings.Contains(artifact, "sentinel-password-value") || !strings.Contains(artifact, "[REDACTED:") {
			t.Fatalf("metadata redaction failed: %s", artifact)
		}
	}
}
