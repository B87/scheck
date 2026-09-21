package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

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
		suiteDir    string
		repeat      int
		corpus      string
		advCase     string
		noPairs     bool
		cases       []string
		armNames    []string
		boundedFrom string
	)
	cmd := &cobra.Command{
		Use:    "eval",
		Short:  "Run the phase 2 evaluation suite (developer tool)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			suite, err := eval.Load(suiteDir)
			if err != nil {
				return usageErr("%v", err)
			}
			if suite, err = suite.Select(cases); err != nil {
				return usageErr("%v", err)
			}
			if missing := suite.Validate(); len(missing) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: suite below the frozen minimums: %v\n", missing)
			}
			arms, err := eval.ParseArms(armNames)
			if err != nil {
				return usageErr("%v", err)
			}
			cfg, err := opts.loadConfig(cmd)
			if err != nil {
				return err
			}
			name := cfg.Provider
			if name == "" {
				name = defaultProvider
			}
			// Progress goes to stderr unconditionally: a live run is minutes
			// long and its record lands in --out or stdout when it is done.
			o := eval.Options{Suite: suite, Repeat: repeat, Arms: arms, Model: cfg.Model, Version: version.Version,
				Log: func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) }}
			if slices.Contains(arms, eval.ArmBounded) {
				// The research arm's answer sources arrive with their own
				// roadmap slices (docs/ROADMAP-RESEARCH.md R2 and R3); the
				// flag is registered now and refuses what does not exist.
				switch boundedFrom {
				case "scripted":
					o.Answers = eval.ScriptedAnswers
				case "openai", "jev":
					return usageErr("--bounded-source %s is not available in this build", boundedFrom)
				default:
					return usageErr("--bounded-source must be scripted, openai or jev")
				}
			}
			o.Effort, _ = llm.ParseEffort(cfg.Effort)
			o.Profile, _ = check.ParseProfile(cfg.Profile)
			modelArms := slices.Contains(arms, eval.ArmSingle) || slices.Contains(arms, eval.ArmAgent)
			switch {
			case !modelArms:
				// rules and bounded need no provider at all.
			case name == "mock":
				o.Provider = eval.MockProvider
			default:
				if opts.LocalOnly || (cfg.AllowEgress != nil && !*cfg.AllowEgress) {
					return usageErr("--local-only and allow_egress: false are not available in this build")
				}
				// The harness is the one caller of phase 2 left in this build,
				// so the provider pre-flight lives here: a missing model, an
				// unavailable adapter or an unknown context limit is a usage
				// error before a single case runs (docs/SPEC.md §5.2, §5.3).
				if err := validateProvider(cfg); err != nil && cfg.Model == "" && name != "mock" {
					return usageErr("%v", err)
				}
				pcfg := opts.providerConfig(cfg)
				p, err := llm.Build(name, pcfg)
				if err != nil {
					return usageErr("provider %s: %v", name, err)
				}
				if p.Limits().MaxContext <= 0 {
					return usageErr("provider %s: the context limit for model %q is unknown; set max_context: or --max-context (docs/SPEC.md §5.3)", name, cfg.Model)
				}
				o.Live = true
				o.Provider = func(eval.Case, eval.Arm) (llm.Provider, error) { return llm.Build(name, pcfg) }
			}
			if !noPairs {
				o.Corpus, o.AdversarialCase = corpus, advCase
			}
			render := func(res *eval.Results) ([]byte, error) {
				if opts.Format == "json" {
					return json.MarshalIndent(res, "", "  ")
				}
				return []byte(res.Markdown()), nil
			}
			if opts.Out != "" {
				// The record is rewritten after every run, so an interrupted
				// live run still leaves what it measured.
				o.Checkpoint = func(res *eval.Results) {
					if raw, err := render(res); err == nil {
						_ = writeFileAtomic(opts.Out, raw)
					}
				}
			}
			res, err := eval.Execute(cmd.Context(), o)
			if err != nil {
				return incompleteErr("%v", err)
			}
			raw, err := render(res)
			if err != nil {
				return err
			}
			if opts.Out != "" {
				if err := writeFileAtomic(opts.Out, raw); err != nil {
					return usageErr("--out: %v", err)
				}
				return nil
			}
			_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
			return err
		},
	}
	cmd.Flags().StringVar(&suiteDir, "suite", "testdata/eval", "suite directory with cases/")
	cmd.Flags().IntVar(&repeat, "repeat", 1, "runs per case per model arm (the criteria require 3 for a live record)")
	cmd.Flags().StringVar(&corpus, "corpus", "testdata/context", "injection corpus directory")
	cmd.Flags().StringVar(&advCase, "adversarial-case", "linux-password-auth-public", "the case the adversarial pairs run on")
	cmd.Flags().BoolVar(&noPairs, "no-pairs", false, "skip the adversarial pairs")
	cmd.Flags().StringSliceVar(&cases, "cases", nil, "run only these cases (comma-separated names); the record is then below the minimums")
	cmd.Flags().StringSliceVar(&armNames, "arms", nil, "arms to run; default rules,single-pass,agent — the research arm is added with bounded")
	cmd.Flags().StringVar(&boundedFrom, "bounded-source", "scripted", "where the bounded arm's answers come from (scripted; openai and jev arrive with R2 and R3)")
	return cmd
}

// writeFileAtomic replaces path in one rename so a reader never sees a
// half-written record.
func writeFileAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
