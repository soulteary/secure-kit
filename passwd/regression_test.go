// Regression tests for the two hashers, moved here with them in v2.

package passwd

import (
	"testing"
)

func TestSimpleArgon2FormatIsParameterSensitive(t *testing.T) {
	weak := NewArgon2Hasher(WithArgon2Memory(16 * 1024))
	hash, err := weak.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	if !weak.Verify(hash, "password") {
		t.Fatal("the hasher that produced the hash cannot verify it")
	}

	strong := NewArgon2Hasher(WithArgon2Memory(64 * 1024))
	if strong.Verify(hash, "password") {
		t.Error("simple-format verification unexpectedly survived a parameter change")
	}

	// PHC format carries its parameters, so it survives.
	phc, err := weak.HashWithParams("password")
	if err != nil {
		t.Fatal(err)
	}
	if !strong.Verify(phc, "password") {
		t.Error("PHC-format hash failed to verify after a parameter change; it records its own parameters")
	}
}

// --- Codex review follow-ups (PR #4) ---

// TestArgon2StrictValidatesCombinedParams: each option validates only its own
// value, so memory=8 with threads=2 passed construction while x/crypto/argon2
// requires memory >= 8*threads. HashWithParams then emitted a PHC string that
// parseArgon2PHC rejects -- a hasher that cannot verify its own output.
func TestArgon2StrictValidatesCombinedParams(t *testing.T) {
	if _, err := NewArgon2HasherStrict(WithArgon2Memory(8), WithArgon2Threads(2)); err == nil {
		t.Error("NewArgon2HasherStrict(memory=8, threads=2) returned nil error, want the illegal pair rejected")
	}

	// The panicking constructor must reject it too.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("NewArgon2Hasher(memory=8, threads=2) did not panic")
			}
		}()
		_ = NewArgon2Hasher(WithArgon2Memory(8), WithArgon2Threads(2))
	}()

	// A legal pair still constructs, and the hash it produces verifies.
	h, err := NewArgon2HasherStrict(WithArgon2Memory(64), WithArgon2Threads(2), WithArgon2Time(1))
	if err != nil {
		t.Fatalf("NewArgon2HasherStrict(memory=64, threads=2) error = %v", err)
	}
	hash, err := h.HashWithParams("hunter2")
	if err != nil {
		t.Fatalf("HashWithParams error = %v", err)
	}
	if !h.Verify(hash, "hunter2") {
		t.Error("Verify returned false for the PHC hash the hasher just produced")
	}
}

// TestExtractSignaturesKeepsPaddedBase64: a bare Base64 signature ends in "="
// padding. Treating any "=" as an algorithm prefix made such a value look
// prefixed, so asking for "sha256=" filtered it away and returned nothing.
