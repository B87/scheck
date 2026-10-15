package report

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/severity"
	"github.com/b87/scheck/internal/finding"
)

// graded gives the input's fired judgments their chains as Analyze does,
// with the declarations the input carries (data.matters_most) and any
// more the test adds (exposures, production repositories). A judgment a
// fixture already graded keeps its chain, so a fixture can carry its own
// declarations into every test that builds it.
func graded(in Input, more ...func(*severity.Declarations)) Input {
	d := severity.Declarations{Production: map[string]severity.Production{}}
	for i, id := range in.DataMattersMost {
		name := id
		for _, a := range in.Assets {
			if a.ID == id {
				name = a.Name
			}
		}
		d.MattersMost = append(d.MattersMost, severity.Matter{Asset: id, Name: name, Key: fmt.Sprintf("data.matters_most[%d]", i)})
	}
	for _, f := range more {
		f(&d)
	}
	in.Assets = slices.Clone(in.Assets)
	for i := range in.Assets {
		in.Assets[i].Judged = slices.Clone(in.Assets[i].Judged)
		for k := range in.Assets[i].Judged {
			j := &in.Assets[i].Judged[k]
			if j.Chain != nil || j.Verdict != verdictFired || j.Details["superseded_by"] != nil {
				continue
			}
			owner := j.Asset
			if owner == "" {
				owner = in.Assets[i].ID
			}
			j.Chain = severity.Grade(*j, owner, d)
		}
	}
	observeReads(&in)
	return in
}

// observeReads records, as the run does from the gate, when each read a
// judgment cites was collected; a fixture that says nothing read it at the
// run's start.
func observeReads(in *Input) {
	in.Observations = maps.Clone(in.Observations)
	if in.Observations == nil {
		in.Observations = map[string]Observation{}
	}
	for _, a := range in.Assets {
		for _, j := range a.Judged {
			for _, r := range j.Reads {
				if _, ok := in.Observations[r]; !ok {
					in.Observations[r] = Observation{CollectedAt: in.Started}
				}
			}
		}
	}
}

// build is Build over a graded input.
func build(in Input, more ...func(*severity.Declarations)) *Report {
	return Build(graded(in, more...))
}

// exposed declares a URL exposed on purpose, as intent.exposed_on_purpose[0].
func exposed(url, reason string) func(*severity.Declarations) {
	return func(d *severity.Declarations) {
		d.Exposed = append(d.Exposed, severity.Exposed{URL: url, Reason: reason, Key: fmt.Sprintf("intent.exposed_on_purpose[%d]", len(d.Exposed))})
	}
}

// production declares a repository asset deploys_to: production.
func production(id, name string) func(*severity.Declarations) {
	return func(d *severity.Declarations) {
		d.Production[id] = severity.Production{Name: name, Key: "assets." + name + ".deploys_to"}
	}
}

// A fired judgment Analyze did not grade is reported at its base, never
// dropped: a missed grade must not turn a finding into a clean exit.
func TestUngradedFiredJudgmentIsStillReported(t *testing.T) {
	in := githubHistoryFiredReport(t)
	for i := range in.Assets {
		for k := range in.Assets[i].Judged {
			in.Assets[i].Judged[k].Chain = nil
		}
	}
	r := Build(in)
	if len(r.Findings) == 0 || r.Exit.Code != 1 {
		t.Fatal(len(r.Findings), r.Exit)
	}
	for _, f := range r.Findings {
		if f.Severity != f.SeverityBase || len(f.Adjustments) != 0 {
			t.Fatal(f)
		}
	}
}

// The ranking's reason is a step that moved the severity, never a cap,
// and an operator's parenthesis survives in it.
func TestRankingReasonIsAMovingStep(t *testing.T) {
	in := githubHistoryFiredReport(t)
	for i := range in.Assets {
		for k := range in.Assets[i].Judged {
			in.Assets[i].Judged[k].Chain = nil
		}
	}
	repo := ""
	for _, a := range in.Assets {
		for _, j := range a.Judged {
			if j.ID == finding.IDGitHubHistoryCredential {
				repo = j.Asset
			}
		}
	}
	r := Build(graded(in, func(d *severity.Declarations) {
		d.MattersMost = append(d.MattersMost, severity.Matter{Asset: repo, Name: "production", What: "orders (EU) and invoices", Key: "data.matters_most[0]"})
	}))
	var buf bytes.Buffer
	if err := WriteText(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "raised: capped at high") || !strings.Contains(buf.String(), "raised: this finding concerns a secret in an observed public") {
		t.Fatal(buf.String())
	}
	in = githubAccessFiredReport(t)
	for i := range in.Assets {
		for k := range in.Assets[i].Judged {
			in.Assets[i].Judged[k].Chain = nil
		}
	}
	r = Build(graded(in, production(githubAccessRepo, "production"), func(d *severity.Declarations) {
		d.MattersMost = append(d.MattersMost, severity.Matter{Asset: githubAccessOrg, Name: "engineering", What: "orders (EU) and invoices", Key: "data.matters_most[0]"})
	}))
	buf.Reset()
	if err := WriteText(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(buf.String()), " "), "raised: you listed engineering under data.matters_most as holding orders (EU) and invoices, so this ranks one step higher") {
		t.Fatal(buf.String())
	}
}
