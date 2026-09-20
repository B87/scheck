package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/eval"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/version"
)

// `scheck eval` is the M2.7 harness (docs/eval/phase2-criteria.md): a
// developer command, hidden from help, that compares the three arms over
// the labeled suite and the adversarial pairs. With --provider mock it
// validates the harness; with a real provider it produces the record the
// release gate needs. It runs against fixtures only, never a live target.
func newEvalCmd(opts *globalOpts) *cobra.Command {
	var (
		suiteDir string
		repeat   int
		corpus   string
		advCase  string
		noPairs  bool
	)
	cmd := &cobra.Command{
		Use:    "eval",
		Short:  "Run the phase 2 evaluation suite (developer tool)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeOutput()
			suite, err := eval.Load(suiteDir)
			if err != nil {
				return usageErr("%v", err)
			}
			if missing := suite.Validate(); len(missing) > 0 {
				fmt.Fprintf(os.Stderr, "warning: suite below the frozen minimums: %v\n", missing)
			}
			cfg, err := opts.loadConfig(cmd)
			if err != nil {
				return err
			}
			name := cfg.Provider
			if name == "" {
				name = defaultProvider
			}
			o := eval.Options{Suite: suite, Repeat: repeat, Model: cfg.Model, Log: func(f string, a ...any) { opts.logf(1, f, a...) }}
			o.Effort, _ = llm.ParseEffort(cfg.Effort)
			o.Profile, _ = check.ParseProfile(cfg.Profile)
			if name == "mock" {
				o.Provider = eval.MockProvider
			} else {
				if opts.LocalOnly || (cfg.AllowEgress != nil && !*cfg.AllowEgress) {
					return usageErr("--local-only and allow_egress: false are not available in this build")
				}
				pcfg := opts.providerConfig(cfg)
				if _, err := llm.Build(name, pcfg); err != nil {
					return usageErr("provider %s: %v", name, err)
				}
				o.Live = true
				o.Provider = func(eval.Case, eval.Arm) (llm.Provider, error) { return llm.Build(name, pcfg) }
			}
			if !noPairs {
				o.Corpus, o.AdversarialCase = corpus, advCase
			}
			res, err := eval.Execute(cmd.Context(), o)
			if err != nil {
				return incompleteErr("%v", err)
			}
			res.Version = version.Version
			if opts.Format == "json" {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			_, err = io.WriteString(w, res.Markdown())
			return err
		},
	}
	cmd.Flags().StringVar(&suiteDir, "suite", "testdata/eval", "suite directory with cases/")
	cmd.Flags().IntVar(&repeat, "repeat", 1, "runs per case per model arm (the criteria require 3 for a live record)")
	cmd.Flags().StringVar(&corpus, "corpus", "testdata/context", "injection corpus directory")
	cmd.Flags().StringVar(&advCase, "adversarial-case", "linux-password-auth-public", "the case the adversarial pairs run on")
	cmd.Flags().BoolVar(&noPairs, "no-pairs", false, "skip the adversarial pairs")
	return cmd
}
