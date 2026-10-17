package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/engagement"
	"golang.org/x/term"
)

func newInitCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "init [FILE]",
		Short: "Interview the operator and write an engagement file",
		Long: "scheck init asks the intake questions and writes the engagement file.\n" +
			"Given a file, it asks only what that file does not answer. A file from\n" +
			"scheck run --host … --write-engagement is a valid start.\n" +
			"It contacts nothing. Credentials stay in the environment, never in the file.\n" +
			"End each answer with a line containing only a dot.",
		Example: "  scheck init\n  scheck init engagement.yaml",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, opts, args)
		},
	}
}

func runInit(cmd *cobra.Command, opts *globalOpts, args []string) error {
	if err := opts.rejectUnimplemented(cmd); err != nil {
		return err
	}
	if err := rejectInitFlags(cmd); err != nil {
		return err
	}
	path := "engagement.yaml"
	if len(args) == 1 {
		path = args[0]
	}
	f, existed, err := loadInit(path)
	if err != nil {
		return err
	}
	in := bufio.NewReader(cmd.InOrStdin())
	interactive := stdinIsTerminal(cmd.InOrStdin())
	for _, q := range engagement.Questions() {
		if q.Answered(f) {
			continue
		}
		for {
			answer, err := readAnswer(cmd.ErrOrStderr(), in, q.Text(f))
			if err != nil {
				return err
			}
			snap, err := cloneInit(f)
			if err != nil {
				return err
			}
			notes, err := engagement.Answer(f, q.ID, answer)
			if err != nil {
				*f = *snap
				if !interactive {
					return usageErr("%s", err.Error())
				}
				fmt.Fprintln(cmd.ErrOrStderr(), err.Error())
				continue
			}
			for _, n := range notes {
				fmt.Fprintln(cmd.ErrOrStderr(), n)
			}
			break
		}
	}
	for _, text := range engagement.Explanations(f) {
		fmt.Fprintln(cmd.ErrOrStderr(), text)
		fmt.Fprintln(cmd.ErrOrStderr())
	}
	raw, err := engagement.Encode(f)
	if err != nil {
		return usageErr("scheck init: %v", err)
	}
	if _, err := engagement.Parse(path, raw, engagementOptions); err != nil {
		return usageErr("%v", err)
	}
	if err := writeInit(path, raw); err != nil {
		return err
	}
	verb := "wrote"
	if existed {
		verb = "updated"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s %s; nothing contacted. Run it with: scheck run %s\n", verb, path, path)
	return nil
}

func rejectInitFlags(cmd *cobra.Command) error {
	var extra []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		extra = append(extra, "--"+f.Name)
	})
	if len(extra) > 0 {
		return usageErr("scheck init reads no flags (%s): the answers go in the engagement file", strings.Join(extra, ", "))
	}
	return nil
}

func loadInit(path string) (*engagement.File, bool, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &engagement.File{}, false, nil
	}
	if err != nil {
		return nil, false, usageErr("scheck init: %v", err)
	}
	if _, err := engagement.Parse(path, raw, engagementOptions); err != nil {
		return nil, true, usageErr("%v", err)
	}
	var f engagement.File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, true, usageErr("scheck init: %v", err)
	}
	return &f, true, nil
}

func readAnswer(w io.Writer, in *bufio.Reader, prompt string) (string, error) {
	fmt.Fprintln(w, prompt)
	fmt.Fprintln(w, "End with a line containing only a dot.")
	var b strings.Builder
	for {
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", usageErr("scheck init: the answer was cut off")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if err != nil {
			return "", usageErr("scheck init: the answer was cut off")
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func stdinIsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func cloneInit(f *engagement.File) (*engagement.File, error) {
	raw, err := yaml.Marshal(f)
	if err != nil {
		return nil, err
	}
	var g engagement.File
	if err := yaml.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func writeInit(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".scheck-init-*")
	if err != nil {
		return usageErr("scheck init: %v", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return usageErr("scheck init: %v", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return usageErr("scheck init: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return usageErr("scheck init: %v", err)
	}
	if err := os.Rename(name, path); err != nil {
		return usageErr("scheck init: %v", err)
	}
	ok = true
	return nil
}
