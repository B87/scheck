package finding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/operator"
)

var now = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

func base(id string) Finding {
	def, ok := Lookup(id)
	if !ok {
		panic(id)
	}
	return Finding{ID: def.ID, Title: def.Title, Category: def.Category, SeverityBase: def.BaseSeverity,
		Severity: def.BaseSeverity, Status: StatusOpen, Source: SourceRule, Confidence: ConfidenceHigh,
		Evidence: []Evidence{{Check: "x", Excerpt: "y"}}, Impact: def.Impact, Remediation: def.Remediation}
}

// The §11 severity table: (finding id, structured context) → severity,
// adjustments and status. Every adjustment is attributed to its source.
func TestSeverityTable(t *testing.T) {
	origins := map[string]string{"exposure": "hosts/gw.yaml", "environment": "scheck.yaml#context", "expected_services": "hosts/gw.yaml", "accepted_risks": "hosts/gw.yaml"}
	svc := &ServiceRef{Port: 5432, Proto: "tcp"}
	cases := []struct {
		name    string
		id      string
		ctx     *operator.Structured
		service *ServiceRef
		want    Severity
		adjust  []string // rule from source
		status  string
	}{
		{"no context", IDPasswordAuthEnabled, nil, nil, SevMedium, nil, StatusOpen},
		{"lan is neutral", IDPasswordAuthEnabled, &operator.Structured{Exposure: "lan"}, nil, SevMedium, nil, StatusOpen},
		{"internet escalates remote-access", IDPasswordAuthEnabled, &operator.Structured{Exposure: "internet"}, nil, SevHigh, []string{"exposure:internet from hosts/gw.yaml#context.exposure"}, StatusOpen},
		{"internet escalates network", IDAppFirewallDisabled, &operator.Structured{Exposure: "internet"}, nil, SevHigh, []string{"exposure:internet from hosts/gw.yaml#context.exposure"}, StatusOpen},
		{"internet leaves disk alone", IDFileVaultOff, &operator.Structured{Exposure: "internet"}, nil, SevHigh, nil, StatusOpen},
		{"critical stays critical", IDEmptyPassword, &operator.Structured{Exposure: "internet"}, nil, SevCritical, nil, StatusOpen},
		{"dev de-escalates everything", IDFileVaultOff, &operator.Structured{Environment: "dev"}, nil, SevMedium, []string{"environment:dev from scheck.yaml#context.environment"}, StatusOpen},
		{"airgapped de-escalates remote-access two", IDRootLoginEnabled, &operator.Structured{Exposure: "airgapped"}, nil, SevLow, []string{"exposure:airgapped from hosts/gw.yaml#context.exposure"}, StatusOpen},
		{"airgapped leaves network alone", IDAppFirewallDisabled, &operator.Structured{Exposure: "airgapped"}, nil, SevMedium, nil, StatusOpen},
		{"internet then dev", IDPasswordAuthEnabled, &operator.Structured{Exposure: "internet", Environment: "dev"}, nil, SevMedium,
			[]string{"exposure:internet from hosts/gw.yaml#context.exposure", "environment:dev from scheck.yaml#context.environment"}, StatusOpen},
		{"info cannot go lower", IDRemoteLoginEnabled, &operator.Structured{Environment: "dev"}, nil, SevInfo, nil, StatusOpen},
		{"expected service is info", IDUnexpectedListener, &operator.Structured{ExpectedServices: []operator.Service{{Port: 5432, Proto: "tcp", Purpose: "postgres", Source: "hosts/gw.yaml"}}}, svc,
			SevInfo, []string{"expected_service:5432/tcp from hosts/gw.yaml#context.expected_services"}, StatusOpen},
		{"undeclared service escalates", IDUnexpectedListener, &operator.Structured{ExpectedServices: []operator.Service{{Port: 443, Proto: "tcp", Source: "hosts/gw.yaml"}}}, svc,
			SevHigh, []string{"unexpected_service:5432/tcp from hosts/gw.yaml#context.expected_services"}, StatusOpen},
		{"no declared services means no judgement", IDUnexpectedListener, &operator.Structured{Exposure: "lan"}, svc, SevMedium, nil, StatusOpen},
		{"accepted", IDPasswordAuthEnabled, &operator.Structured{AcceptedRisks: []operator.Risk{{ID: IDPasswordAuthEnabled, Reason: "MFA at bastion", Expires: "2026-12-31", Source: "hosts/gw.yaml"}}}, nil, SevMedium, nil, StatusAccepted},
		{"accepted and escalated", IDPasswordAuthEnabled, &operator.Structured{Exposure: "internet", AcceptedRisks: []operator.Risk{{ID: IDPasswordAuthEnabled, Reason: "r", Source: "s"}}}, nil, SevHigh, []string{"exposure:internet from hosts/gw.yaml#context.exposure"}, StatusAccepted},
		{"expired acceptance does not suppress", IDPasswordAuthEnabled, &operator.Structured{AcceptedRisks: []operator.Risk{{ID: IDPasswordAuthEnabled, Reason: "old", Expires: "2026-01-01", Source: "s"}}}, nil, SevMedium, nil, StatusOpen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := Grader{Context: tc.ctx, Origins: origins, Now: now}
			f := base(tc.id)
			f.Service = tc.service
			got, steps := g.Grade(f)
			if got.Severity != tc.want || got.Status != tc.status {
				t.Errorf("severity %s status %s, want %s %s; steps %+v", got.Severity, got.Status, tc.want, tc.status, steps)
			}
			var adj []string
			for _, a := range got.Adjustments {
				adj = append(adj, a.Rule+" from "+a.Source)
			}
			if strings.Join(adj, ";") != strings.Join(tc.adjust, ";") {
				t.Errorf("adjustments %v, want %v", adj, tc.adjust)
			}
			if got.SeverityBase != base(tc.id).SeverityBase {
				t.Error("base severity must be preserved")
			}
			if steps[0].Stage != "base" || steps[len(steps)-1].Stage != "final" || steps[len(steps)-1].To != string(got.Severity) {
				t.Errorf("chain %+v", steps)
			}
		})
	}
}

// The delta strings in the report are signed and the accepted reason is
// carried; JSON shows base and final side by side (§6.4).
func TestAdjustmentAttributionInJSON(t *testing.T) {
	g := Grader{Context: &operator.Structured{Exposure: "internet", AcceptedRisks: []operator.Risk{{ID: IDRootLoginEnabled, Reason: "jump host only", Source: "gw.yaml"}}},
		Origins: map[string]string{"exposure": "scheck.yaml#context"}, Now: now}
	got, _ := g.Grade(base(IDRootLoginEnabled))
	raw, _ := json.Marshal(got)
	for _, want := range []string{`"severity_base":"high"`, `"severity":"critical"`, `"delta":"+1"`, `"source":"scheck.yaml#context.exposure"`, `"status":"accepted"`, `"accepted_reason":"jump host only"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %s in %s", want, raw)
		}
	}
	if got.Open() {
		t.Error("an accepted finding counts towards the exit code")
	}
}

// --ignore-context is a nil Context: grading reproduces the base severity
// exactly, with no adjustments and no acceptance (§6.4).
func TestNilContextIsUnadjusted(t *testing.T) {
	g := Grader{Now: now}
	for _, d := range Defs() {
		got, steps := g.Grade(base(d.ID))
		if got.Severity != d.BaseSeverity || len(got.Adjustments) != 0 || got.Status != StatusOpen || len(steps) != 2 {
			t.Errorf("%s: %+v %+v", d.ID, got, steps)
		}
	}
}

// Custom findings are capped at medium and never escalated (§7.1).
func TestCustomFindingCaps(t *testing.T) {
	f := Finding{ID: "custom:vendor-agent", Custom: true, Category: CategoryNetwork, SeverityBase: SevMedium, Severity: SevMedium,
		Source: SourceModel, Confidence: ConfidenceHigh, Status: StatusOpen}
	g := Grader{Context: &operator.Structured{Exposure: "internet"}, Now: now}
	got, steps := g.Grade(f)
	if got.Severity != SevMedium || len(got.Adjustments) != 0 {
		t.Errorf("custom finding escalated: %+v", got)
	}
	found := false
	for _, s := range steps {
		if strings.Contains(s.Reason, "never escalated") {
			found = true
		}
	}
	if !found {
		t.Errorf("the refusal is not in the chain: %+v", steps)
	}
	g = Grader{Context: &operator.Structured{Environment: "dev"}, Now: now}
	if got, _ := g.Grade(f); got.Severity != SevLow {
		t.Errorf("custom finding may still be de-escalated: %s", got.Severity)
	}
}

// Emulated tool calling caps a model finding's confidence at medium, never
// a rule finding's (§5.3).
func TestConfidenceCap(t *testing.T) {
	g := Grader{EmulatedToolCalling: true, Now: now}
	model := base(IDPasswordAuthEnabled)
	model.Source = SourceModel
	if got, _ := g.Grade(model); got.Confidence != ConfidenceMedium {
		t.Errorf("model confidence %s", got.Confidence)
	}
	if got, _ := g.Grade(base(IDPasswordAuthEnabled)); got.Confidence != ConfidenceHigh {
		t.Errorf("rule confidence %s", got.Confidence)
	}
	if got, _ := (Grader{Now: now}).Grade(model); got.Confidence != ConfidenceHigh {
		t.Errorf("native tool calling capped confidence: %s", got.Confidence)
	}
}

// An expired acceptance is a finding in its own right and does not
// suppress the finding it named (§6.3).
func TestExpiredAcceptanceFinding(t *testing.T) {
	g := Grader{Context: &operator.Structured{AcceptedRisks: []operator.Risk{
		{ID: IDPasswordAuthEnabled, Reason: "old", Expires: "2026-01-01", Source: "gw.yaml"},
		{ID: IDRootLoginEnabled, Reason: "current", Expires: "2027-01-01", Source: "gw.yaml"},
		{ID: "custom:thing", Reason: "never expires", Source: "gw.yaml"},
	}}, Now: now}
	expired := g.ExpiredAcceptances("linux")
	if len(expired) != 1 || expired[0].ID != IDAcceptanceExpired || !strings.Contains(expired[0].Evidence[0].Excerpt, IDPasswordAuthEnabled) {
		t.Fatalf("expired: %+v", expired)
	}
	if got, _ := g.Grade(base(IDPasswordAuthEnabled)); got.Status != StatusOpen {
		t.Error("expired acceptance suppressed its finding")
	}
	if got, _ := g.Grade(base(IDRootLoginEnabled)); got.Status != StatusAccepted {
		t.Error("current acceptance did not apply")
	}
}

// A rule finding and an identical synthetic model finding grade to the
// same severity through the same chain (acceptance criterion 9).
func TestRuleAndModelFindingGradeAlike(t *testing.T) {
	g := Grader{Context: &operator.Structured{Exposure: "internet", Environment: "prod"}, Origins: map[string]string{"exposure": "gw.yaml"}, Now: now}
	rule := base(IDPasswordAuthEnabled)
	model := rule
	model.Source = SourceModel
	gr, _ := g.Grade(rule)
	gm, _ := g.Grade(model)
	if gr.Severity != gm.Severity || len(gr.Adjustments) != len(gm.Adjustments) || gr.Adjustments[0] != gm.Adjustments[0] {
		t.Errorf("rule %+v vs model %+v", gr, gm)
	}
}
