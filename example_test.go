package secure_test

import (
	"bytes"
	"fmt"

	secure "github.com/soulteary/secure-kit/v2"
)

// The common case: check an inbound webhook's signature, then log what
// arrived without writing the sender's address into the log.
func Example() {
	payload := []byte(`{"event":"user.created","email":"alice@example.com"}`)
	secret := "whsec_do_not_log_me"

	// What the sender put in the signature header.
	header := "sha256=" + secure.ComputeHMACSHA256(payload, secret)

	verifier := secure.NewHMACVerifier(secure.HMACSHA256, secret)
	ok, _ := verifier.VerifyAny(payload, secure.ExtractSignatures(header, "sha256="))

	fmt.Println(ok)
	fmt.Println("accepted event for", secure.MaskEmail("alice@example.com"))
	// Output:
	// true
	// accepted event for a****@example.com
}

// A signature header carries more than one value while a secret is being
// rotated, and may carry algorithms this verifier does not use. Passing the
// prefix keeps the ones it does.
func ExampleExtractSignatures() {
	header := "sha1=635f9f14f9f7e4a1, sha256=1a2b3c, sha256=4d5e6f"

	fmt.Println(secure.ExtractSignatures(header, "sha256="))
	// Output: [1a2b3c 4d5e6f]
}

// VerifyAny accepts a payload signed with either the outgoing or the incoming
// secret, and reports which signature matched -- never the expected one, so a
// caller that logs the result cannot publish a forgeable value.
func ExampleHMACVerifier_VerifyAny() {
	payload := []byte("id=42&amount=100")
	verifier := secure.NewHMACVerifier(secure.HMACSHA256, "current-secret")

	signatures := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		verifier.Sign(payload),
	}

	ok, matched := verifier.VerifyAny(payload, signatures)
	fmt.Println(ok, matched == verifier.Sign(payload))

	ok, matched = verifier.VerifyAny(payload, signatures[:1])
	fmt.Printf("%v %q\n", ok, matched)
	// Output:
	// true true
	// false ""
}

// Comparing a secret with == leaks how much of it an attacker got right,
// because the comparison stops at the first differing byte.
func ExampleConstantTimeEqual() {
	const apiKey = "sk_live_9f8e7d6c5b4a"

	fmt.Println(secure.ConstantTimeEqual(apiKey, "sk_live_9f8e7d6c5b4a"))
	fmt.Println(secure.ConstantTimeEqual(apiKey, "sk_live_0000000000000"))
	// Output:
	// true
	// false
}

// The masking helpers are for log lines and support screens: enough of the
// value to recognise it, not enough to use it.
func ExampleMaskEmail() {
	fmt.Println(secure.MaskEmail("alice@example.com"))
	fmt.Println(secure.MaskEmail("bo@example.com"))
	fmt.Println(secure.MaskPhone("+8613800138000"))
	fmt.Println(secure.MaskCreditCard("4111 1111 1111 1111"))
	fmt.Println(secure.MaskAPIKey("sk_live_9f8e7d6c5b4a3210"))
	// Output:
	// a****@example.com
	// b*@example.com
	// +86*******8000
	// ************1111
	// sk_l***3210
}

// MaskIPAddress keeps the first octet of an IPv4 address and the first group
// of an IPv6 one. The masked IPv6 groups are a fixed seven however the address
// was written, so "2001:db8::1" and its fully expanded form mask alike.
func ExampleMaskIPAddress() {
	fmt.Println(secure.MaskIPAddress("192.168.1.42"))
	fmt.Println(secure.MaskIPAddress("2001:db8::1"))
	// Output:
	// 192.*.*.*
	// 2001:****:****:****:****:****:****:****
}

// SetRandReader replaces the entropy source for the whole package, so a test
// can pin it and get a known value. It applies to the passwd subpackage's
// salts too. Production code must never call it.
func ExampleSetRandReader() {
	secure.SetRandReader(bytes.NewReader([]byte{
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	}))
	defer secure.SetRandReader(nil) // restores crypto/rand.Reader

	token, err := secure.RandomHex(8)
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
	// Output: deadbeefdeadbeef
}
