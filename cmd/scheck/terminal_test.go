package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/b87/scheck/internal/report"
)

// Colour is for a terminal only, and NO_COLOR wins even there. A redirected
// report and a --out file are always plain (docs/SPEC.md §7.6).
func TestTextOptionsColorAndWidth(t *testing.T) {
	o := &globalOpts{Verbose: 2}

	// Not a file at all: no fd, no colour, default width.
	opt := o.textOptions(&bytes.Buffer{})
	if opt.Color || opt.Width != report.DefaultWidth || opt.Verbose != 2 {
		t.Errorf("buffer: %+v", opt)
	}

	// A real file that is not a terminal: still plain.
	f, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if opt := o.textOptions(f); opt.Color {
		t.Errorf("colour written to a file: %+v", opt)
	}
	if opt := o.textOptions(nopCloser{f}); opt.Color {
		t.Errorf("colour written through nopCloser: %+v", opt)
	}

	// nopCloser must expose the descriptor, or the terminal is never found.
	if _, ok := any(nopCloser{os.Stdout}).(interface{ Fd() uintptr }); !ok {
		t.Error("nopCloser hides Fd(), so stdout can never be detected as a terminal")
	}

	// NO_COLOR is honoured whatever the descriptor says.
	t.Setenv("NO_COLOR", "1")
	if opt := o.textOptions(os.Stdout); opt.Color {
		t.Errorf("NO_COLOR ignored: %+v", opt)
	}
}

// A terminal descriptor is what switches colour on; without one nothing is
// styled, whatever NO_COLOR says.
func TestTerminalFd(t *testing.T) {
	if _, ok := terminalFd(&bytes.Buffer{}); ok {
		t.Error("a bytes.Buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, ok := terminalFd(f); ok {
		t.Error("a regular file is not a terminal")
	}
}
