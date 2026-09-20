package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/check"
)

func newCatalogCmd(opts *globalOpts) *cobra.Command {
	var platform string
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "List every check the model could run under the active profile",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			prof, ok := check.ParseProfile(opts.Profile)
			if !ok {
				return usageErr("--profile must be baseline|hardened")
			}
			var cs []check.Check
			switch platform {
			case "all":
				for _, c := range check.All() {
					if c.MinProfile <= prof {
						cs = append(cs, c)
					}
				}
			case "linux", "macos":
				cs = check.ForPlatform(check.Platform(platform), prof)
			default:
				return usageErr("--platform must be linux|macos|all")
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tPLATFORM\tDOMAIN\tPHASE\tELEVATED\tPARAMS\tDESCRIPTION")
			for _, c := range cs {
				phase := "on-demand"
				if c.Baseline {
					phase = "baseline"
				}
				el := "-"
				if c.Elevated {
					el = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Platform, c.Domain, phase, el, paramSpec(c), c.Description)
			}
			_ = tw.Flush()
			fmt.Fprintf(os.Stdout, "\n%d checks (profile %s, platform %s)\n", len(cs), prof, platform)
			return nil
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "all", "linux|macos|all")
	return cmd
}

func paramSpec(c check.Check) string {
	if len(c.Params) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(c.Params))
	for _, p := range c.Params {
		s := p.Name + ":" + string(p.Kind)
		switch p.Kind {
		case check.KindEnum:
			s += "(" + strings.Join(p.Enum, "|") + ")"
		case check.KindInt:
			s += fmt.Sprintf("[%d..%d]", p.Min, p.Max)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}
