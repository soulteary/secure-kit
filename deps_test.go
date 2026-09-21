package secure

import (
	"os/exec"
	"strings"
	"testing"
)

// TestRootPackageIsStandardLibraryOnly is the guard for the reason the passwd
// subpackage exists. Argon2 and bcrypt are the only things here that need
// golang.org/x/crypto, and before v2 they sat in the root package -- so every
// service importing secure-kit for RandomHex or ConstantTimeEqual linked
// x/crypto and x/sys, carried two modules it never called in its go.mod and
// nine lines in its go.sum, and answered for them at audit time.
//
// Nothing else notices if that regresses. Adding an x/crypto import back to a
// root-package file compiles, passes every other test, and quietly puts both
// modules back into every importer's dependency graph. This test is what fails
// instead.
//
// Test files are exempt by construction: `go list -deps .` reports the
// package's own import graph, not its tests'.
func TestRootPackageIsStandardLibraryOnly(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; cannot inspect the import graph")
	}

	out, err := exec.Command("go", "list", "-deps",
		"-f", "{{if .Module}}{{.ImportPath}}{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps .: %v\n%s", err, out)
	}

	// Anything with a Module is outside the standard library. The kit's own
	// packages are the only ones allowed to show up.
	const self = "github.com/soulteary/secure-kit/v2"
	var external []string
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == self || strings.HasPrefix(pkg, self+"/") {
			continue
		}
		external = append(external, pkg)
	}

	if len(external) > 0 {
		t.Errorf("the root package links %d package(s) outside the standard library, want none"+
			" -- move whatever needs them into a subpackage, as passwd does for x/crypto:\n\t%s",
			len(external), strings.Join(external, "\n\t"))
	}
}
