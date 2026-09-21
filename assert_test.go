package secure

import (
	"strings"
	"testing"
)

// These helpers exist so the kit's own tests import nothing outside the
// standard library, which is not the cosmetic point it looks like.
//
// `go mod tidy` in a program that imports this package records the test
// dependencies of the packages it imports: with testify imported here, the
// chain `yourprogram -> secure-kit/v2 -> secure-kit/v2.test -> testify/assert`
// put github.com/stretchr/testify and go.yaml.in/yaml/v3 into that program's
// module graph and four lines into its go.sum, for a program that never ran
// these tests. deps_test.go is the guard that keeps them out.
//
// The set below is only what the tests here actually use. Each helper calls
// t.Helper(), so a failure is reported at the call site, and each takes the
// wanted value before the observed one.

// mustNoError stops the test when err is not nil. Use it where the rest of the
// case cannot run without the value that failed to materialise.
func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// wantError fails the test when err is nil, and lets it continue.
func wantError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("got nil error, want an error")
	}
}

func wantEqual[T comparable](t *testing.T, want, got T) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func wantNotEqual[T comparable](t *testing.T, notWant, got T) {
	t.Helper()
	if got == notWant {
		t.Errorf("got %v, want anything else", got)
	}
}

func wantTrue(t *testing.T, got bool) {
	t.Helper()
	if !got {
		t.Error("got false, want true")
	}
}

func wantFalse(t *testing.T, got bool) {
	t.Helper()
	if got {
		t.Error("got true, want false")
	}
}

// wantLen checks the length of a slice; wantLenString does the same for a
// string, where the unit is bytes, not runes.
func wantLen[T any](t *testing.T, got []T, want int) {
	t.Helper()
	if len(got) != want {
		t.Errorf("got length %d, want %d", len(got), want)
	}
}

func wantLenString(t *testing.T, got string, want int) {
	t.Helper()
	if len(got) != want {
		t.Errorf("got length %d for %q, want %d", len(got), got, want)
	}
}

func wantContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("got %q, want it to contain %q", s, substr)
	}
}

func wantNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("got %q, want it not to contain %q", s, substr)
	}
}

func wantNotEmpty(t *testing.T, s string) {
	t.Helper()
	if s == "" {
		t.Error("got an empty string, want a non-empty one")
	}
}

// wantPanic fails the test when fn returns without panicking.
func wantPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if recover() == nil {
			t.Error("got a normal return, want a panic")
		}
	}()
	fn()
}
