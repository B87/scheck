// Command scheck performs a read-only security posture check of one host.
package main

import (
	"errors"
	"fmt"
	"os"
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
