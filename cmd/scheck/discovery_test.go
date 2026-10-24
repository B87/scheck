package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/b87/scheck/internal/check"
)

func TestDiscoveryJSON(t *testing.T) {
	for _, args := range [][]string{{"catalog", "--platform", "linux"}, {"explain", "fs.stat"}} {
		t.Run(args[0], func(t *testing.T) {
			root := newRootCmd()
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs(append(args, "--format", "json"))
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Kind   string             `json:"kind"`
				Checks []checkDescription `json:"checks"`
			}
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Kind != args[0] || len(doc.Checks) == 0 {
				t.Fatalf("bad discovery: %+v", doc)
			}
			for _, c := range doc.Checks {
				original, ok := check.Lookup(c.ID, c.Platform)
				if !ok || !reflect.DeepEqual(c.Argv, original.Argv) || c.Params == nil {
					t.Fatalf("lost catalog structure: %+v", c)
				}
			}
		})
	}
}

func TestDiscoveryOutputFile(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	path := filepath.Join(t.TempDir(), "explain.json")
	root.SetArgs([]string{"explain", "sshd.config", "--format", "json", "--out", path})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !json.Valid(b) {
		t.Fatalf("invalid output routing: %s / %s", out.String(), b)
	}
}

func TestInvalidFormatRejectedBeforeOutput(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"explain", "sshd.config", "--format", "sarif"})
	if err := root.Execute(); err == nil || out.Len() != 0 {
		t.Fatal("unsupported format was silently accepted")
	}
}
