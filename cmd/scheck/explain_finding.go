package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/version"
)

// explainFlags reproduce a grading without a run (docs/SPEC.md §8): the
// §6.2 structured keys as flags, layered over any --context sources.
type explainFlags struct {
	Exposure      string
	Environment   string
	Expected      []string // PORT[/PROTO]
	Service       string   // PORT[/PROTO]: the listener the finding is about
	Accepted      bool
	Expires       string
	EmulatedTools bool
}

func (f *explainFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.Exposure, "exposure", "", "grade as if context.exposure were internet|vpn|lan|airgapped")
	fl.StringVar(&f.Environment, "environment", "", "grade as if context.environment were prod|staging|dev")
	fl.StringArrayVar(&f.Expected, "expected-service", nil, "grade as if PORT[/PROTO] were in context.expected_services (repeatable)")
	fl.StringVar(&f.Service, "service", "", "the listener PORT[/PROTO] the finding is about")
	fl.BoolVar(&f.Accepted, "accepted", false, "grade as if the finding id were in context.accepted_risks")
	fl.StringVar(&f.Expires, "expires", "", "with --accepted: the acceptance's expiry date YYYY-MM-DD")
	fl.BoolVar(&f.EmulatedTools, "emulated-tools", false, "apply the confidence cap for emulated tool calling")
}

// explainFinding prints the severity chain for one finding id: base →
// adjustments → cap → status → final (docs/SPEC.md §7.2, §8).
func (o *globalOpts) explainFinding(cmd *cobra.Command, w io.Writer, def finding.Def, ef explainFlags) error {
	ctx, origins, err := o.explainContext(cmd, ef)
	if err != nil {
		return err
	}
	f := finding.Finding{ID: def.ID, Title: def.Title, Category: def.Category, SeverityBase: def.BaseSeverity,
		Severity: def.BaseSeverity, Status: finding.StatusOpen, Source: finding.SourceModel, Confidence: finding.ConfidenceHigh,
		Adjustments: []finding.Adjustment{}, Impact: def.Impact, Remediation: def.Remediation}
	if ef.Service != "" {
		svc, err := parsePortProto(ef.Service)
		if err != nil {
			return usageErr("--service: %v", err)
		}
		f.Service = &finding.ServiceRef{Port: svc.Port, Proto: svc.Proto}
	}
	g := finding.Grader{Context: ctx, Origins: origins, EmulatedToolCalling: ef.EmulatedTools, Now: time.Now()}
	graded, steps := g.Grade(f)
	if o.Format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			SchemaVersion string               `json:"schema_version"`
			Kind          string               `json:"kind"`
			Version       string               `json:"scheck_version"`
			ID            string               `json:"id"`
			Title         string               `json:"title"`
			Category      string               `json:"category"`
			SeverityBase  finding.Severity     `json:"severity_base"`
			Severity      finding.Severity     `json:"severity"`
			Status        string               `json:"status"`
			Confidence    string               `json:"confidence"`
			Adjustments   []finding.Adjustment `json:"adjustments"`
			Chain         []finding.Step       `json:"chain"`
			Context       *operator.Structured `json:"context"`
			Impact        string               `json:"impact"`
			Remediation   finding.Remediation  `json:"remediation"`
		}{"1.0", "finding", version.Version, def.ID, def.Title, def.Category, graded.SeverityBase, graded.Severity,
			graded.Status, graded.Confidence, graded.Adjustments, steps, ctx, def.Impact, def.Remediation})
	}
	opt := o.textOptions(w)
	fmt.Fprintf(w, "%s — %s\n", def.ID, def.Title)
	fmt.Fprintf(w, "  category   %s\n", def.Category)
	fmt.Fprintf(w, "  severity   %s (base %s), status %s, confidence %s\n", graded.Severity, graded.SeverityBase, graded.Status, graded.Confidence)
	fmt.Fprintln(w, "  chain      severity is graded by code, never by the model (docs/SPEC.md §7.2):")
	for _, st := range steps {
		arrow := st.To
		if st.From != "" && st.From != st.To {
			arrow = st.From + " → " + st.To
		}
		for i, l := range report.Wrap(fmt.Sprintf("%-11s %s  %s", st.Stage, arrow, report.Sanitize(st.Reason)), max(opt.Width-13, 30)) {
			if i == 0 {
				fmt.Fprintf(w, "    %s\n", l)
			} else {
				fmt.Fprintf(w, "                 %s\n", l)
			}
		}
	}
	if ctx == nil {
		fmt.Fprintln(w, "  context    none — pass --exposure, --environment, --expected-service, --accepted or --context to reproduce an adjustment")
	}
	for i, l := range report.Wrap(def.Impact, max(opt.Width-13, 30)) {
		if i == 0 {
			fmt.Fprintf(w, "  impact     %s\n", l)
		} else {
			fmt.Fprintf(w, "             %s\n", l)
		}
	}
	fmt.Fprintf(w, "  fix        %s\n", def.Remediation.Summary)
	return nil
}

// explainContext layers the flags over the local --context sources (no
// target is contacted), so a run's adjustment can be reproduced exactly.
func (o *globalOpts) explainContext(cmd *cobra.Command, ef explainFlags) (*operator.Structured, map[string]string, error) {
	var base operator.Structured
	origins := map[string]string{}
	if len(o.Context) > 0 && !o.IgnoreCtx {
		cfg, err := o.loadConfig(cmd)
		if err != nil {
			return nil, nil, err
		}
		m, err := operator.Load(operator.Options{ConfigContext: cfg.Context, ConfigSource: cfg.ContextSource,
			ImplicitDir: operator.DefaultImplicitDir, Flags: o.Context, Budget: policy.DefaultBudgets().ContextBytes,
			KnownFinding: config.KnownFinding})
		if err != nil {
			return nil, nil, usageErr("%v", err)
		}
		base, origins = m.Structured, m.Origins
	}
	set := false
	if ef.Exposure != "" {
		base.Exposure, origins["exposure"] = ef.Exposure, "flag --exposure"
		set = true
	}
	if ef.Environment != "" {
		base.Environment, origins["environment"] = ef.Environment, "flag --environment"
		set = true
	}
	for _, e := range ef.Expected {
		svc, err := parsePortProto(e)
		if err != nil {
			return nil, nil, usageErr("--expected-service: %v", err)
		}
		svc.Source = "flag --expected-service"
		base.ExpectedServices = append(base.ExpectedServices, svc)
		origins["expected_services"] = "flag --expected-service"
		set = true
	}
	if ef.Accepted {
		base.AcceptedRisks = append(base.AcceptedRisks, operator.Risk{ID: cmd.Flags().Arg(0), Reason: "accepted on the command line", Expires: ef.Expires, Source: "flag --accepted"})
		set = true
	}
	if !set && base.IsZero() {
		return nil, nil, nil
	}
	tmp := &operator.Merged{Structured: base}
	if err := validateStructured(tmp); err != nil {
		return nil, nil, usageErr("%v", err)
	}
	return &base, origins, nil
}

// validateStructured reuses operator's schema validation on a block built
// from flags, by round-tripping it through a YAML source.
func validateStructured(m *operator.Merged) error {
	for _, e := range []struct {
		v    string
		set  []string
		name string
	}{
		{m.Structured.Exposure, operator.Exposures, "exposure"},
		{m.Structured.Environment, operator.Environments, "environment"},
	} {
		if e.v == "" {
			continue
		}
		ok := false
		for _, s := range e.set {
			if s == e.v {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s %q is not one of %s", e.name, e.v, strings.Join(e.set, "|"))
		}
	}
	for _, r := range m.Structured.AcceptedRisks {
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return fmt.Errorf("--expires %q is not YYYY-MM-DD", r.Expires)
			}
		}
	}
	return nil
}

func parsePortProto(s string) (operator.Service, error) {
	portS, proto, _ := strings.Cut(s, "/")
	port, err := strconv.Atoi(portS)
	if err != nil || port < 1 || port > 65535 {
		return operator.Service{}, fmt.Errorf("%q is not PORT[/PROTO] with a port in 1..65535", s)
	}
	proto = strings.ToLower(proto)
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return operator.Service{}, fmt.Errorf("%q: proto must be tcp|udp", s)
	}
	return operator.Service{Port: port, Proto: proto, Purpose: "declared on the command line"}, nil
}
