package passwd_test

import (
	"bytes"
	"fmt"

	secure "github.com/soulteary/secure-kit/v2"
	"github.com/soulteary/secure-kit/v2/passwd"
)

// The common case: hash a password when the account is created, check it at
// login. Nothing else in the kit is needed for this, and nothing else in the
// kit pulls in golang.org/x/crypto.
func Example() {
	hasher := passwd.NewBcryptHasher()

	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	fmt.Println(hasher.Verify(hash, "correct horse battery staple"))
	fmt.Println(hasher.Verify(hash, "Tr0ub4dor&3"))
	// Output:
	// true
	// false
}

// HashWithParams writes the PHC string, which carries the parameters the hash
// was derived with. Verify reads them back out of the hash, so raising the
// cost later leaves every stored hash verifiable.
//
// The salt comes from secure.RandReader, which is why pinning the reader makes
// this example's output fixed. Production code never pins it.
func ExampleArgon2Hasher_HashWithParams() {
	secure.SetRandReader(bytes.NewReader([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}))
	defer secure.SetRandReader(nil)

	hash, err := passwd.NewArgon2Hasher().HashWithParams("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	fmt.Println(hash)
	// Output: $argon2id$v=19$m=65536,t=1,p=4$AAECAwQFBgcICQoLDA0ODw$9wlwvEFs1YfRpU4LEOGpEIF/0VLDDjcs7ON+W7ZqSDk
}

// Hash writes the simple salt:hash format instead, which records no
// parameters. Verify re-derives the hash with the hasher's *current* settings,
// so the day the work factor is raised, every stored hash stops matching and
// every login looks like a wrong password. Use HashWithParams unless an
// existing store forces the simple format.
func ExampleArgon2Hasher_Hash() {
	stored, err := passwd.NewArgon2Hasher().Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	// The same settings the hash was written with.
	fmt.Println(passwd.NewArgon2Hasher().Verify(stored, "correct horse battery staple"))

	// The same password, after someone raised the iteration count.
	stronger := passwd.NewArgon2Hasher(passwd.WithArgon2Time(3))
	fmt.Println(stronger.Verify(stored, "correct horse battery staple"))
	// Output:
	// true
	// false
}

// Out-of-range option values are rejected rather than ignored: the
// constructors panic, and the Strict constructors report the error. An option
// that silently left the cost where it was is how a service ends up with
// weaker hashes than its configuration claims.
func ExampleNewBcryptHasherStrict() {
	_, err := passwd.NewBcryptHasherStrict(passwd.WithBcryptCost(42))
	fmt.Println(err)

	hasher, err := passwd.NewBcryptHasherStrict(passwd.WithBcryptCost(12))
	fmt.Println(hasher.Algorithm(), err)
	// Output:
	// WithBcryptCost: 42 out of range (4..31)
	// bcrypt <nil>
}

// Hasher and HashResolver stayed in the root package when the hashers moved
// out, so code that selects an algorithm at runtime still holds one table --
// it just imports two packages to fill it.
func ExampleBcryptResolver() {
	resolvers := map[string]secure.HashResolver{
		"argon2id": passwd.NewArgon2Hasher(),
		"bcrypt":   &passwd.BcryptResolver{},
		"sha256":   secure.NewSHA256Hasher(),
	}

	stored, err := passwd.NewBcryptHasher().Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	fmt.Println(resolvers["bcrypt"].Check(stored, "correct horse battery staple"))
	// Output: true
}
