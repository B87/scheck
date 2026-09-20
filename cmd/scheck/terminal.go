package main

import (
	"io"
	"os"

	"golang.org/x/term"

	"github.com/b87/scheck/internal/report"
)

// textOptions answers the terminal questions that internal/report refuses to
// ask itself (docs/SPEC.md §7.6): how wide to wrap, and whether to style.
// Colour is on only when the report goes to a terminal and NO_COLOR is unset;
// a redirected report and a --out file are always plain.
func (o *globalOpts) textOptions(w io.Writer) report.Options {
	opt := report.Options{Verbose: o.Verbose, Width: report.DefaultWidth}
	fd, isTTY := terminalFd(w)
	if !isTTY {
		return opt
	}
	if cols, _, err := term.GetSize(fd); err == nil && cols > 0 {
		opt.Width = cols
	}
	opt.Color = os.Getenv("NO_COLOR") == ""
	return opt
}

// terminalFd reports the file descriptor behind w, when it has one and it is
// a terminal.
func terminalFd(w io.Writer) (int, bool) {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return 0, false
	}
	fd := int(f.Fd())
	return fd, term.IsTerminal(fd)
}
