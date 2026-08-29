// Package component contains the deliberately small shared command contract for
// the first Phase 1 foundation binaries. Domain runtime behavior belongs in its
// owning module and is not introduced by this package.
package component

import (
	"fmt"
	"io"
)

const Version = "0.1.0-dev"

// Run handles the common immutable component identity surface.
func Run(name string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintf(stdout, "%s %s\n", name, Version)
		return 0
	}

	fmt.Fprintf(stderr, "%s: Phase 1 runtime is not configured; use --version\n", name)
	return 2
}
