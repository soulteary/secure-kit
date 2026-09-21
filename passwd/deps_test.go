package passwd

import (
	"os/exec"
	"strings"
	"testing"
)

// allowedModules are the two module paths this package may draw on: x/crypto
// for argon2 and bcrypt themselves, and x/sys, which x/crypto's blake2b needs
// for CPU feature detection. Both are the price of hashing a password, and a
// caller pays them only by importing this package.
var allowedModules = []string{
	"golang.org/x/crypto/",
	"golang.org/x/sys/",
}

// TestPasswdDependenciesStayBounded fails when this package, or its tests,
// reach for a module outside that pair.
//
// The subpackage split is only worth what it keeps out. Every dependency added
// here is one an importer of passwd cannot decline -- and, if it arrives
// through a test file, one that lands in the go.sum of anyone importing the
// kit at all, since `go mod tidy` walks the tests of the packages it imports.
// That is how testify travelled with the kit until v2.1.0; see the root
// package's deps_test.go.
func TestPasswdDependenciesStayBounded(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; cannot inspect the import graph")
	}

	for _, args := range [][]string{{"."}, {"-test", "."}} {
		out, err := exec.Command("go", append([]string{"list", "-deps",
			"-f", "{{if .Module}}{{.ImportPath}}{{end}}"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", strings.Join(args, " "), err, out)
		}

		var unexpected []string
		for _, pkg := range listedPackages(string(out)) {
			if isSelf(pkg) {
				continue
			}
			allowed := false
			for _, prefix := range allowedModules {
				if strings.HasPrefix(pkg, prefix) {
					allowed = true
					break
				}
			}
			if !allowed {
				unexpected = append(unexpected, pkg)
			}
		}

		if len(unexpected) > 0 {
			t.Errorf("go list -deps %s reports %d package(s) outside %s:\n\t%s",
				strings.Join(args, " "), len(unexpected),
				strings.Join(allowedModules, " and "), strings.Join(unexpected, "\n\t"))
		}
	}
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
