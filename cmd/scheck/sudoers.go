package main

import (
	"os"
	"os/user"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/sudoers"
	"github.com/b87/scheck/internal/target/local"
)

func newSudoersCmd(_ *globalOpts) *cobra.Command {
	var platform, userName string
	cmd := &cobra.Command{
		Use:   "sudoers",
		Short: "Print a least-privilege NOPASSWD sudoers fragment for elevated checks",
		Long: `Prints a sudoers fragment granting the given user NOPASSWD for exactly the
argv of every elevated catalog check on the platform. scheck never installs it.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p := check.Platform(platform)
			if platform == "" {
				p = local.New(1).Platform()
			}
			if userName == "" {
				if u, err := user.Current(); err == nil {
					userName = u.Username
				} else {
					userName = "USER"
				}
			}
			out, err := sudoers.Generate(p, userName)
			if err != nil {
				return usageErr("%v", err)
			}
			_, err = os.Stdout.WriteString(out)
			return err
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "", "linux|macos (default: this machine's)")
	cmd.Flags().StringVar(&userName, "user", "", "user to grant (default: current user)")
	return cmd
}
