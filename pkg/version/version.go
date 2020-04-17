// Package version includes the version information.
package version

import "fmt"

var (
	// Raw is the string representation of the version. This will be replaced
	// with the calculated version at build time.
	// set in the Makefile.
	Raw = "was not built with version info"

	// String is the human-friendly representation of the version.
	String = fmt.Sprintf("app-inc/server-operator %s", Raw)

	// Commit is the commit hash from which the software was built.
	// Set via LDFLAGS in Makefile.
	Commit = ""
)
