package passwd

import (
	"strings"
	"testing"
)

// Standard-library assertions, for the reason spelled out in the root
// package's assert_test.go: a test dependency here is recorded by `go mod
// tidy` in every program that imports this package, so testify's four go.sum
// lines travelled with the kit into codebases that never ran these tests.
//
// Each helper calls t.Helper(), so a failure is reported at the call site, and
// each takes the wanted value before the observed one.

// mustNoError stops the test when err is not nil; wantError only fails it.
func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("got nil error, want an error")
	}
}

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

func wantContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("got %q, want it to contain %q", s, substr)
	}
}

func wantNotEmpty(t *testing.T, s string) {
	t.Helper()
	if s == "" {
		t.Error("got an empty string, want a non-empty one")
	}
}

// wantPanic fails the test when fn returns without panicking; wantNoPanic
// fails it when fn panics.
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

func wantNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if r := recover(); r != nil {
			t.Errorf("got panic %v, want a normal return", r)
		}
	}()
	fn()
}
