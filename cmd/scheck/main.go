// Command scheck runs read-only security engagements (docs/spec/engagement.md).
package main

import (
	"errors"
	"fmt"
	"os"

	// The complete check catalog: without it every plan is empty. The
	// command's tests rely on this import, not on one of their own, so a
	// binary that lost it fails them.
	_ "github.com/b87/scheck/internal/check/all"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if ee, ok := errors.AsType[*exitError](err); ok {
			fmt.Fprintln(os.Stderr, "scheck:", ee.Err)
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, "scheck:", err)
		os.Exit(exitUsage)
	}
}
