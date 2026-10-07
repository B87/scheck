package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
)

// legacyHomes is where each key of 0.0.1's scheck.yaml lives from 0.0.2
// (docs/spec/engagement.md, "No configuration file").
var legacyHomes = map[string]string{
	"context":        "role, exposure, environment and expected_services: assets.<name>.context; accepted_risks: intent.accepted_risks; data_classification: data.matters_most; compliance, owner and other keys are not read",
	"targets":        "assets.<name> (host, identity, jump)",
	"profile":        "defaults.profile or assets.<name>.profile; --profile with --host",
	"elevate":        "assets.<name>.elevate; --sudo with --host",
	"disable_checks": "assets.<name>.disable_checks",
	"deny_paths":     "assets.<name>.deny_paths",
	"redact_extra":   "redact_extra",
	"state_dir":      "--state-dir",
	"provider":       "a flag on the evaluation harness",
	"model":          "a flag on the evaluation harness",
	"base_url":       "a flag on the evaluation harness",
	"effort":         "a flag on the evaluation harness",
	"max_context":    "a flag on the evaluation harness",
}

// legacyPaths are where 0.0.1 read scheck.yaml (docs/spec/host-collector.md
// §8): the user file, then ./scheck.yaml. scheck only looks for them, to
// refuse; it never reads a setting from either.
func legacyPaths() []string {
	var out []string
	if dir, err := os.UserConfigDir(); err == nil {
		out = append(out, filepath.Join(dir, "scheck", "config.yaml"))
	}
	return append(out, "scheck.yaml")
}

// legacyConfig refuses a run while a configuration file sits where 0.0.1
// read one, naming each key it sets and that key's new home, so a narrowing
// a v0.0.1 user relied on is never dropped silently. It prints keys, never
// values: a redact_extra pattern is often the string it hides.
func legacyConfig() error {
	var found []string
	for _, path := range legacyPaths() {
		raw, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return usageErr("%s: %v", path, err)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s:", path)
		var doc yaml.Node
		if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			b.WriteString("\n  (not readable as YAML; its keys go where docs/spec/engagement.md, \"No configuration file\", says)")
		} else {
			m := doc.Content[0]
			for i := 0; i+1 < len(m.Content); i += 2 {
				key := m.Content[i].Value
				if _, cred := policy.DetectCredential(key); cred {
					key = "(a key shaped like a credential)"
				}
				home, ok := legacyHomes[key]
				if !ok {
					home = "not read"
				}
				fmt.Fprintf(&b, "\n  %s -> %s", report.Sanitize(key), home)
			}
		}
		found = append(found, b.String())
	}
	// 0.0.1 also read every file under ./.scheck/context/ as operator
	// context; an alias dropping its accepted risks without a word would
	// change a CI job's exit code with no reason given.
	if fi, err := os.Stat(operator.DefaultImplicitDir); err == nil && fi.IsDir() {
		found = append(found, operator.DefaultImplicitDir+"/:\n  operator context files -> role, exposure, environment and "+
			"expected_services: assets.<name>.context; accepted_risks: intent.accepted_risks")
	}
	if len(found) == 0 {
		return nil
	}
	return usageErr("scheck reads no configuration file from 0.0.2, and found one where 0.0.1 read it:\n%s\n"+
		"Move these keys into the engagement file (or use the flags named), then delete or rename the file "+
		"(docs/spec/engagement.md, \"No configuration file\").", strings.Join(found, "\n"))
}
