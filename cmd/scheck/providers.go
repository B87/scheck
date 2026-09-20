package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/llm"
	_ "github.com/b87/scheck/internal/llm/all" // every provider adapter
	"github.com/b87/scheck/internal/version"
)

// providerStatus is one row of `scheck providers` (docs/SPEC.md §5.2, §8):
// what is registered, whether this environment can use it, and what it
// declares. Nothing here contacts a provider or reads a credential's value.
type providerStatus struct {
	Name       string      `json:"name"`
	Summary    string      `json:"summary"`
	Status     string      `json:"status"` // ready | unconfigured | unavailable
	Detail     string      `json:"detail,omitempty"`
	Credential string      `json:"credential,omitempty"`
	Limits     *llm.Limits `json:"limits"`
	Native     *llm.Native `json:"native"`
}

func newProvidersCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List inference providers with their limits and native features",
		Long: "providers lists every registered inference provider: whether this environment " +
			"can use it (a credential is checked for presence only, never printed), the context " +
			"limit it declares for the selected --model, and which features the adapter maps " +
			"natively. No provider is contacted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeOutput()
			cfg, err := opts.loadConfig(cmd)
			if err != nil {
				return err
			}
			rows := providerRows(opts.providerConfig(cfg))
			if opts.Format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					SchemaVersion string           `json:"schema_version"`
					Kind          string           `json:"kind"`
					Version       string           `json:"scheck_version"`
					Default       string           `json:"default"`
					Providers     []providerStatus `json:"providers"`
				}{"1.0", "providers", version.Version, defaultProvider, rows})
			}
			printProviders(w, rows)
			return nil
		},
	}
}

// providerRows builds one status per registered provider by constructing
// it from the current configuration. Construction never performs I/O beyond
// reading a mock transcript, so this is safe to run anywhere.
func providerRows(cfg llm.Config) []providerStatus {
	var rows []providerStatus
	for _, info := range llm.Providers() {
		row := providerStatus{Name: info.Name, Summary: info.Summary, Credential: info.Credential}
		if info.Deferred {
			row.Status, row.Detail = "unavailable", "not available in this build"
			rows = append(rows, row)
			continue
		}
		p, err := llm.Build(info.Name, cfg)
		if err != nil {
			row.Status, row.Detail = "unconfigured", err.Error()
			rows = append(rows, row)
			continue
		}
		l, n := p.Limits(), p.Native()
		row.Status, row.Limits, row.Native = "ready", &l, &n
		rows = append(rows, row)
	}
	return rows
}

func printProviders(w io.Writer, rows []providerStatus) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROVIDER\tSTATUS\tMAX CONTEXT\tLOCAL\tNATIVE\tDETAIL")
	for _, r := range rows {
		maxCtx, local, native := "-", "-", "-"
		if r.Limits != nil {
			maxCtx = fmt.Sprint(r.Limits.MaxContext)
			local = fmt.Sprint(r.Limits.Local)
		}
		if r.Native != nil {
			native = nativeString(*r.Native)
		}
		detail := r.Detail
		if detail == "" {
			detail = r.Summary
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Status, maxCtx, local, native, detail)
	}
	_ = tw.Flush()
}

func nativeString(n llm.Native) string {
	var parts []string
	for _, f := range []struct {
		name string
		on   bool
	}{{"tools", n.ToolCalling}, {"parallel", n.ParallelToolCalls}, {"caching", n.PromptCaching}, {"reasoning", n.Reasoning}} {
		if f.on {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	var out strings.Builder
	out.WriteString(parts[0])
	for _, p := range parts[1:] {
		out.WriteString("," + p)
	}
	return out.String()
}
