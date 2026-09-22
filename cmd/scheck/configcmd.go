package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/version"
)

// `scheck config show` and `scheck config validate` (docs/SPEC.md §8, §9)
// inspect local configuration through the same resolver and validation an
// ordinary run uses. Neither contacts a model or a target: a target: context
// source is reported as unresolved, credentials are checked for presence
// only, and every displayed string goes through the redactor and the
// terminal escaper.
func newConfigCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate the effective configuration",
		Long: "config show prints every effective setting with the source that set it — built-in " +
			"default, the user config file (" + config.UserConfigDescription() + "), the project " +
			"scheck.yaml, or an explicit flag — and the merged operator context a run would " +
			"consume. config validate applies the same rules a run applies and exits 0 or 3. " +
			"Neither contacts a model or a target; target: context is reported as unresolved. " +
			"Credentials are never printed.",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Print effective settings with their provenance",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
				if err != nil {
					return err
				}
				defer closeOutput()
				insp, err := opts.inspect(cmd)
				if err != nil {
					return err
				}
				if opts.Format == "json" {
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(insp)
				}
				printInspection(w, insp)
				return nil
			},
		},
		&cobra.Command{
			Use:   "validate",
			Short: "Validate the configuration and local context sources; exit 3 on an error",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
				if err != nil {
					return err
				}
				defer closeOutput()
				insp, err := opts.inspect(cmd)
				if err != nil {
					return err
				}
				if insp.Error != "" {
					return usageErr("%s", insp.Error)
				}
				if opts.Format == "json" {
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(insp)
				}
				fmt.Fprintf(w, "configuration ok: %s\n", insp.summary())
				for _, n := range insp.Notes {
					fmt.Fprintf(w, "note: %s\n", n)
				}
				return nil
			},
		},
	)
	return cmd
}

// inspection is the `config show` document.
type inspection struct {
	SchemaVersion string                      `json:"schema_version"`
	Kind          string                      `json:"kind"`
	Version       string                      `json:"scheck_version"`
	Files         []inspectedFile             `json:"files"`
	Settings      map[string]inspectedSetting `json:"settings"`
	Lists         map[string][]inspectedEntry `json:"lists"`
	Targets       map[string]inspectedTarget  `json:"targets"`
	Context       *inspectedContext           `json:"context"`
	Credentials   map[string]string           `json:"credentials"` // env var -> set | unset
	Notes         []string                    `json:"notes"`
	Error         string                      `json:"error,omitempty"`
	order         []string
}

type inspectedFile struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
}
type inspectedSetting struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}
type inspectedEntry struct {
	Value   string `json:"value"`
	Sources string `json:"sources"`
}
type inspectedTarget struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Port     int    `json:"port,omitempty"`
	Identity string `json:"identity"`
	Source   string `json:"source"`
}
type inspectedContext struct {
	Structured operator.Structured `json:"structured"`
	Origins    map[string]string   `json:"origins"`
	Sources    []operator.Source   `json:"sources"`
	Prose      []inspectedProse    `json:"prose"`
	Budget     int                 `json:"budget"`
	Used       int                 `json:"used"`
	Warnings   []string            `json:"warnings"`
}
type inspectedProse struct {
	Source    string `json:"source"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

func (i *inspection) summary() string {
	n := 0
	for _, f := range i.Files {
		if f.Present {
			n++
		}
	}
	s := fmt.Sprintf("%d config %s", n, plural(n, "file"))
	if i.Context != nil {
		unresolved := 0
		for _, src := range i.Context.Sources {
			if src.Unresolved {
				unresolved++
			}
		}
		s += fmt.Sprintf(", context: %d %s", len(i.Context.Sources), plural(len(i.Context.Sources), "source"))
		if unresolved > 0 {
			s += fmt.Sprintf(" (%d unresolved target: source, read only during a run)", unresolved)
		}
	} else {
		s += ", no operator context"
	}
	return s
}

// inspect resolves the configuration exactly as a run would and describes
// it. Validation errors are carried in the document rather than returned,
// so `show` can display a broken configuration and `validate` can exit 3.
func (o *globalOpts) inspect(cmd *cobra.Command) (*inspection, error) {
	r, err := o.resolveConfig(cmd)
	if err != nil {
		return nil, err
	}
	// Displayed strings pass the redactor built from this configuration,
	// then the terminal escaper: an inline secret in a note or a URL
	// becomes a marker, and a control character becomes \xNN.
	red, rerr := policy.NewRedactor(r.Config.RedactExtra)
	if rerr != nil {
		red, _ = policy.NewRedactor(nil)
	}
	clean := func(s string) string {
		out, _ := red.Redact([]byte(s))
		return report.Sanitize(string(out))
	}
	insp := &inspection{SchemaVersion: "1.0", Kind: "config", Version: version.Version,
		Settings: map[string]inspectedSetting{}, Lists: map[string][]inspectedEntry{},
		Targets: map[string]inspectedTarget{}, Credentials: map[string]string{}, Notes: []string{}}
	for _, l := range r.Layers[1:] {
		insp.Files = append(insp.Files, inspectedFile{clean(l.Source), l.Present})
	}
	for _, key := range config.ScalarKeys {
		src := r.Origin[key]
		if src == "" {
			src = config.SourceDefault
		}
		insp.Settings[key] = inspectedSetting{clean(r.Value(key)), clean(src)}
	}
	insp.order = config.ScalarKeys
	for _, key := range config.ListKeys {
		entries := []inspectedEntry{}
		for _, e := range r.List(key) {
			entries = append(entries, inspectedEntry{clean(e[0]), clean(e[1])})
		}
		insp.Lists[key] = entries
	}
	for name, t := range r.Config.Targets {
		insp.Targets[clean(name)] = inspectedTarget{clean(t.Host), clean(t.User), t.Port, clean(t.Identity), clean(r.Entries["targets"][name])}
	}
	for _, info := range llm.Providers() {
		if info.Credential == "" {
			continue
		}
		state := "unset"
		if _, ok := os.LookupEnv(info.Credential); ok {
			state = "set"
		}
		insp.Credentials[info.Credential] = state
	}
	if err := r.Config.Validate(); err != nil {
		insp.Error = clean(err.Error())
	}
	if insp.Error == "" {
		if err := validateProvider(r.Config); err != nil {
			insp.Notes = append(insp.Notes, clean(err.Error()))
		}
	}
	// Local context only: no reader for target: sources, which are then
	// reported as unresolved rather than as read (ROADMAP M2.2a).
	m, err := operator.Load(operator.Options{
		ConfigContext: r.Config.Context, ConfigSource: r.Config.ContextSource,
		ImplicitDir: operator.DefaultImplicitDir, Flags: o.Context,
		Budget: policy.DefaultBudgets().ContextBytes, KnownFinding: config.KnownFinding,
	})
	if err != nil {
		if insp.Error == "" {
			insp.Error = clean(err.Error())
		}
		return insp, nil
	}
	if o.IgnoreCtx {
		insp.Notes = append(insp.Notes, "--ignore-context: a run would read no operator context")
	} else if !m.IsEmpty() || len(m.Sources) > 0 {
		ic := &inspectedContext{Structured: m.Structured, Origins: map[string]string{}, Budget: m.Budget, Used: m.Used, Warnings: []string{}}
		ic.Structured.Role = clean(ic.Structured.Role)
		ic.Structured.Owner = clean(ic.Structured.Owner)
		ic.Structured.DataClassification = clean(ic.Structured.DataClassification)
		for i := range ic.Structured.ExpectedServices {
			svc := &ic.Structured.ExpectedServices[i]
			svc.Purpose, svc.Audience, svc.Source = clean(svc.Purpose), clean(svc.Audience), clean(svc.Source)
		}
		for i := range ic.Structured.AcceptedRisks {
			rk := &ic.Structured.AcceptedRisks[i]
			rk.Reason, rk.Source = clean(rk.Reason), clean(rk.Source)
		}
		ic.Structured.Extra = nil
		for k, v := range m.Origins {
			ic.Origins[k] = clean(v)
		}
		for _, src := range m.Sources {
			src.Name = clean(src.Name)
			ic.Sources = append(ic.Sources, src)
		}
		for _, p := range m.Prose {
			ic.Prose = append(ic.Prose, inspectedProse{clean(p.Source), len(p.Text), p.Truncated})
		}
		for _, w := range m.Warnings {
			ic.Warnings = append(ic.Warnings, clean(w))
		}
		insp.Context = ic
	}
	return insp, nil
}

// validateProvider checks the provider selection without building it or
// touching a credential: the name must be registered and available in this
// build. Adapter-specific validation (model, limits) is the adapter's, at
// run time (M2.6).
func validateProvider(cfg *config.Config) error {
	info, _, ok := llm.Lookup(cfg.Provider)
	if !ok {
		return fmt.Errorf("provider %q is unknown; `scheck providers` lists the registered ones", cfg.Provider)
	}
	if info.Deferred {
		return fmt.Errorf("provider %q is not available in this build", cfg.Provider)
	}
	if cfg.Model == "" && cfg.Provider != "mock" {
		return fmt.Errorf("model: not set; --model or model: is required to build %s (no host assessment in this build needs one)", cfg.Provider)
	}
	return nil
}

func printInspection(w io.Writer, insp *inspection) {
	fmt.Fprintln(w, "configuration files (lowest precedence first; flags override both)")
	for _, f := range insp.Files {
		state := "absent"
		if f.Present {
			state = "present"
		}
		fmt.Fprintf(w, "  %s  %s\n", f.Path, state)
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SETTING\tVALUE\tSOURCE")
	for _, key := range insp.order {
		s := insp.Settings[key]
		v := s.Value
		if v == "" {
			v = "(unset)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", key, v, s.Source)
	}
	_ = tw.Flush()
	for _, key := range config.ListKeys {
		entries := insp.Lists[key]
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s (accumulated; every source that listed an entry is named)\n", key)
		for _, e := range entries {
			fmt.Fprintf(w, "  %s  <- %s\n", e.Value, e.Sources)
		}
	}
	if len(insp.Targets) > 0 {
		names := make([]string, 0, len(insp.Targets))
		for n := range insp.Targets {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintln(w, "\ntargets")
		for _, n := range names {
			t := insp.Targets[n]
			fmt.Fprintf(w, "  %s  %s@%s port %s identity %s  <- %s\n", n, t.User, t.Host, portOrDash(t.Port), orDash(t.Identity), t.Source)
		}
	}
	fmt.Fprintln(w, "\ncredentials (presence only; values are read from the environment at run time, never from a file)")
	vars := make([]string, 0, len(insp.Credentials))
	for v := range insp.Credentials {
		vars = append(vars, v)
	}
	sort.Strings(vars)
	for _, v := range vars {
		fmt.Fprintf(w, "  %s  %s\n", v, insp.Credentials[v])
	}
	if ic := insp.Context; ic != nil {
		fmt.Fprintf(w, "\noperator context (%d %s, %d of %d bytes)\n", len(ic.Sources), plural(len(ic.Sources), "source"), ic.Used, ic.Budget)
		for _, src := range ic.Sources {
			state := ""
			switch {
			case src.Unresolved:
				state = "  unresolved: read from the target only during a run"
			case src.Truncated:
				state = "  truncated"
			}
			fmt.Fprintf(w, "  %s  %s  %d bytes%s\n", src.Name, src.Kind, src.Bytes, state)
		}
		keys := make([]string, 0, len(ic.Origins))
		for k := range ic.Origins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s  <- %s\n", k, ic.Origins[k])
		}
		for _, svc := range ic.Structured.ExpectedServices {
			fmt.Fprintf(w, "    expected_services %d/%s %s  <- %s\n", svc.Port, svc.Proto, svc.Purpose, svc.Source)
		}
		for _, rk := range ic.Structured.AcceptedRisks {
			exp := ""
			if rk.Expires != "" {
				exp = " expires " + rk.Expires
			}
			fmt.Fprintf(w, "    accepted_risks %s%s  <- %s\n", rk.ID, exp, rk.Source)
		}
		for _, wmsg := range ic.Warnings {
			fmt.Fprintf(w, "  warning: %s\n", wmsg)
		}
	} else {
		fmt.Fprintln(w, "\noperator context: none (pass --context, add a context: block, or files under .scheck/context/)")
	}
	for _, n := range insp.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	if insp.Error != "" {
		fmt.Fprintf(w, "\nerror: %s\n", insp.Error)
	}
}

// portOrDash renders an unset port as "-" rather than 0: no port was
// configured, so the transport's default applies, and printing a port number
// nobody wrote would read as configuration that exists.
func portOrDash(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// plural is shared with the report package's spelling.
func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}
