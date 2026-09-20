package main

import "github.com/spf13/cobra"

// Subcommand constructors are replaced slice by slice; until then each one
// exists so the CLI surface matches SPEC.md §8.

func newLocalCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Audit this machine",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.notInPhase1(cmd); err != nil {
				return err
			}
			return usageErr("local: not implemented yet")
		},
	}
}

func newSSHCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "ssh user@host",
		Short: "Audit a remote host over SSH",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.notInPhase1(cmd); err != nil {
				return err
			}
			return usageErr("ssh: not implemented yet")
		},
	}
}

func newCatalogCmd(_ *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "List every check the model could run under the active profile",
		RunE: func(*cobra.Command, []string) error {
			return usageErr("catalog: not implemented yet")
		},
	}
}

func newSudoersCmd(_ *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "sudoers",
		Short: "Print a least-privilege NOPASSWD sudoers fragment for elevated checks",
		RunE: func(*cobra.Command, []string) error {
			return usageErr("sudoers: not implemented yet")
		},
	}
}
