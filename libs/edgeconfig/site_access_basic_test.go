package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// A basic auth user is a random 16 byte salt and SHA-256(salt || password),
// independent of the site: the same password hashes differently per salt,
// and the node checks it with one sha256.
func TestBasicAuthUserSaltedHash(t *testing.T) {
	a, err := NewBasicAuthUser("alice", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewBasicAuthUser("alice", "correct horse")
	if len(a.Salt) != 32 || len(a.SHA256) != 64 || a.Salt == b.Salt || a.SHA256 == b.SHA256 {
		t.Fatalf("a = %+v b = %+v", a, b)
	}
	salt, _ := hex.DecodeString(a.Salt)
	sum := sha256.Sum256(append(salt, []byte("correct horse")...))
	if a.SHA256 != hex.EncodeToString(sum[:]) || !a.Verify("correct horse") || a.Verify("wrong") {
		t.Fatalf("hash does not check: %+v", a)
	}
	fixed := BasicAuthUserWithSalt("alice", "000102030405060708090a0b0c0d0e0f", "s3cret")
	sum = sha256.Sum256(append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte("s3cret")...))
	if fixed.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("fixed = %+v", fixed)
	}
}

func TestValidateSiteAccessBasicAuthUsers(t *testing.T) {
	ok := BasicAuthUserWithSalt("alice", "000102030405060708090a0b0c0d0e0f", "s3cret")
	valid := func(user BasicAuthUser) error {
		return ValidateSiteAccess(SiteAccess{BasicAuth: &SiteBasicAuth{Realm: "staff", Users: []BasicAuthUser{user}}},
			[]string{"a.example.test"}, true)
	}
	if err := valid(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BasicAuthUser){
		"short salt": func(u *BasicAuthUser) { u.Salt = u.Salt[:30] },
		"upper salt": func(u *BasicAuthUser) { u.Salt = "000102030405060708090A0B0C0D0E0F" },
		"no hash":    func(u *BasicAuthUser) { u.SHA256 = "" },
	} {
		user := ok
		mutate(&user)
		if valid(user) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
