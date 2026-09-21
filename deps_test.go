package secure

import (
	"os/exec"
	"strings"
	"testing"
)

// externalPackages returns the packages outside the standard library that the
// given `go list` arguments pull in, ignoring the kit's own packages. Anything
// with a Module is outside the standard library.
func externalPackages(t *testing.T, args ...string) []string {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; cannot inspect the import graph")
	}

	out, err := exec.Command("go", append([]string{"list", "-deps",
		"-f", "{{if .Module}}{{.ImportPath}}{{end}}"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	var external []string
	for _, pkg := range listedPackages(string(out)) {
		if isSelf(pkg) {
			continue
		}
		external = append(external, pkg)
	}
	return external
}

// listedPackages splits `go list` output into import paths. With -test the
// list also holds the generated test packages, whose entries read
// "example.com/pkg [example.com/pkg.test]" -- one package per line, the import
// path first.
func listedPackages(out string) []string {
	var pkgs []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			pkgs = append(pkgs, fields[0])
		}
	}
	return pkgs
}

// isSelf reports whether an import path belongs to this module, including the
// packages the toolchain generates around it: "pkg.test" for the test binary
// and "pkg_test" for an external test package, which is what example_test.go
// compiles to.
func isSelf(pkg string) bool {
	const self = "github.com/soulteary/secure-kit/v2"
	pkg = strings.TrimSuffix(strings.TrimSuffix(pkg, ".test"), "_test")
	return pkg == self || strings.HasPrefix(pkg, self+"/")
}

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
func TestRootPackageIsStandardLibraryOnly(t *testing.T) {
	if external := externalPackages(t, "."); len(external) > 0 {
		t.Errorf("the root package links %d package(s) outside the standard library, want none"+
			" -- move whatever needs them into a subpackage, as passwd does for x/crypto:\n\t%s",
			len(external), strings.Join(external, "\n\t"))
	}
}

// TestRootTestBinaryIsStandardLibraryOnly guards the half of the graph the
// test above cannot see. `go list -deps .` reports the package's own imports,
// so test files used to be exempt by construction -- and that exemption had a
// price nobody was charging for it.
//
// `go mod tidy` in a program that imports this package walks the tests of the
// packages in its import graph. While these tests imported testify, the chain
//
//	yourprogram -> secure-kit/v2 -> secure-kit/v2.test -> testify/assert
//
// held, so github.com/stretchr/testify and go.yaml.in/yaml/v3 appeared in that
// program's module graph and put four lines into its go.sum, for a test binary
// it never builds. The measurement is in the v2.1.0 CHANGELOG entry; the
// assertion helpers that replaced testify are in assert_test.go.
//
// A `go get` of any test-only library puts that back, silently, and only this
// test notices.
func TestRootTestBinaryIsStandardLibraryOnly(t *testing.T) {
	if external := externalPackages(t, "-test", "."); len(external) > 0 {
		t.Errorf("the root package's test binary links %d package(s) outside the standard"+
			" library, want none -- a test dependency here lands in every importer's"+
			" go.sum:\n\t%s", len(external), strings.Join(external, "\n\t"))
	}
}
