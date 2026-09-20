// Package all links every platform catalog into the binary. Import it for
// its side effect wherever the complete catalog is required (the CLI, the
// baseline runner, and the invariants test that proves acceptance
// criterion 2).
package all

import (
	_ "github.com/b87/scheck/internal/check/common" // registers platform-agnostic checks
	_ "github.com/b87/scheck/internal/check/linux"  // registers Linux checks
	_ "github.com/b87/scheck/internal/check/macos"  // registers macOS checks
)
