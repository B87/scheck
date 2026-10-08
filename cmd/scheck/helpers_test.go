package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// runIn executes the CLI in dir with HOME pointed at a scratch directory so
// only the files the test wrote are read.
func runIn(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Chdir(dir)
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), exitCodeOf(err)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exitCodeOf(err error) int {
	if err == nil {
		return exitOK
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		return ee.Code
	}
	return exitUsage
}
