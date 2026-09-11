package secure

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestVerifyAnyDoesNotLeakExpectedSignature: returning the expected HMAC on the
// failure path handed the caller a forgeable value for a payload whose
// signature had just been rejected. Anything that logged or echoed the second
// return value published it.
func TestVerifyAnyDoesNotLeakExpectedSignature(t *testing.T) {
	v := NewHMACVerifier(HMACSHA256, "topsecret")
	payload := []byte(`{"amount":1}`)

	ok, got := v.VerifyAny(payload, []string{"deadbeef", "cafebabe"})
	if ok {
		t.Fatal("VerifyAny matched a wrong signature")
	}
	if got != "" {
		t.Errorf("VerifyAny returned %q on failure; that is the correct signature for the payload", got)
	}
	if got == v.Sign(payload) {
		t.Error("the expected signature was handed back after a failed verification")
	}

	// A genuine match still returns the signature.
	ok, got = v.VerifyAny(payload, []string{"nope", v.Sign(payload)})
	if !ok || got != v.Sign(payload) {
		t.Errorf("VerifyAny on a valid signature = (%v, %q), want (true, the signature)", ok, got)
	}
}

// TestRandomStringHandlesNonASCII: the charset is documented as a set of
// characters, but was indexed by byte, splitting multi-byte runes and emitting
// invalid UTF-8.
func TestRandomStringHandlesNonASCII(t *testing.T) {
	const charset = "中文字符集ABC"

	for i := 0; i < 50; i++ {
		got, err := RandomString(8, charset)
		if err != nil {
			t.Fatalf("RandomString() error = %v", err)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("RandomString produced invalid UTF-8: %q", got)
		}
		if n := utf8.RuneCountInString(got); n != 8 {
			t.Fatalf("RandomString(8) produced %d runes: %q", n, got)
		}
		for _, r := range got {
			if !strings.ContainsRune(charset, r) {
				t.Fatalf("RandomString produced %q, which is not in the charset", r)
			}
		}
	}

	// ASCII behaviour is unchanged.
	got, err := RandomString(10, CharsetDigits)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Errorf("RandomString(10, digits) = %q, want 10 characters", got)
	}
}

// TestRandomIntRangeFullInt64Range: computing max-min+1 in int64 overflowed.
func TestRandomIntRangeFullInt64Range(t *testing.T) {
	const maxInt64 = int64(^uint64(0) >> 1)
	const minInt64 = -maxInt64 - 1

	cases := [][2]int64{
		{0, maxInt64},
		{minInt64, maxInt64},
		{minInt64, 0},
		{-5, 5},
		{7, 7},
	}

	for _, c := range cases {
		for i := 0; i < 20; i++ {
			got, err := RandomIntRange(c[0], c[1])
			if err != nil {
				t.Fatalf("RandomIntRange(%d, %d) error = %v", c[0], c[1], err)
			}
			if got < c[0] || got > c[1] {
				t.Fatalf("RandomIntRange(%d, %d) = %d, out of range", c[0], c[1], got)
			}
		}
	}

	if _, err := RandomIntRange(5, 1); err == nil {
		t.Error("RandomIntRange(5, 1) should fail")
	}
}

// TestExtractSignaturesFiltersConsistently: the single-value path used to skip
// prefix filtering entirely, so a sha1 signature came back as a sha256
// candidate while the same value in a list was filtered out.
func TestExtractSignaturesFiltersConsistently(t *testing.T) {
	if got := ExtractSignatures("sha1=xyz", "sha256="); len(got) != 0 {
		t.Errorf("ExtractSignatures(\"sha1=xyz\", \"sha256=\") = %q, want none", got)
	}
	if got := ExtractSignatures("sha1=xyz, sha256=abc", "sha256="); len(got) != 1 || got[0] != "abc" {
		t.Errorf("mixed list = %q, want [abc]", got)
	}
	// Providers sending a bare signature are still supported.
	if got := ExtractSignatures("abc123", "sha256="); len(got) != 1 || got[0] != "abc123" {
		t.Errorf("bare signature = %q, want [abc123]", got)
	}
}

// TestSimpleArgon2FormatIsParameterSensitive documents the trap the Hash doc
// comment now warns about: "salt:hash" records no parameters, so re-deriving
// with a different configuration fails verification indistinguishably from a
// wrong password.
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
func TestExtractSignaturesKeepsPaddedBase64(t *testing.T) {
	for _, sig := range []string{"gpjdW5UE=", "gpjdW5U==", "gpjdW5UE"} {
		got := ExtractSignatures(sig, "sha256=")
		if len(got) != 1 || got[0] != sig {
			t.Errorf("ExtractSignatures(%q, \"sha256=\") = %v, want [%q] (bare signatures stay supported)", sig, got, sig)
		}
	}

	// A real prefix is still recognised and stripped.
	if got := ExtractSignatures("sha256=abc123", "sha256="); len(got) != 1 || got[0] != "abc123" {
		t.Errorf("ExtractSignatures(prefixed) = %v, want [abc123]", got)
	}
	// A prefixed value whose payload is padded Base64 keeps working.
	if got := ExtractSignatures("sha256=Zm9vYmE=", "sha256="); len(got) != 1 || got[0] != "Zm9vYmE=" {
		t.Errorf("ExtractSignatures(prefixed padded) = %v, want [Zm9vYmE=]", got)
	}
	// A different algorithm is still filtered out.
	if got := ExtractSignatures("sha1=abc,sha256=def", "sha256="); len(got) != 1 || got[0] != "def" {
		t.Errorf("ExtractSignatures(mixed) = %v, want [def]", got)
	}
}
