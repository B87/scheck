package main

import "github.com/spf13/cobra"

// Subcommand constructors are replaced slice by slice; until then each one
// exists so the CLI surface matches SPEC.md §8.

func newSudoersCmd(_ *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "sudoers",
		Short: "Print a least-privilege NOPASSWD sudoers fragment for elevated checks",
		RunE: func(*cobra.Command, []string) error {
			return usageErr("sudoers: not implemented yet")
		},
	}
}
