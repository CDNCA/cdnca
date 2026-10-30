package identity

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("Correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == "Correct-horse-battery-staple" {
		t.Fatal("HashPassword() returned plaintext")
	}
	if !VerifyPassword(hash, "Correct-horse-battery-staple") {
		t.Fatal("VerifyPassword() rejected the correct password")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("VerifyPassword() accepted an incorrect password")
	}
	if VerifyPassword("not-an-argon-hash", "Correct-horse-battery-staple") {
		t.Fatal("VerifyPassword() accepted a malformed hash")
	}
}

func TestPasswordRejectsWeakLength(t *testing.T) {
	for _, weak := range []string{"short-1", "12345678", "abcd 1234", "abcd1234密码"} {
		if _, err := HashPassword(weak); err == nil {
			t.Fatalf("HashPassword(%q) accepted a password that breaks the policy", weak)
		}
	}
}

func TestPasswordHashUsesCanonicalArgon2idParameters(t *testing.T) {
	hash, err := HashPassword("canonical-password-value")
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := parsePasswordHash(hash)
	if !ok {
		t.Fatalf("parsePasswordHash() rejected HashPassword output %q", hash)
	}
	if parsed.memory != 65536 || parsed.iterations != 3 || parsed.parallelism != 2 ||
		len(parsed.salt) != 16 || len(parsed.digest) != 32 {
		t.Fatalf("HashPassword parameters = m=%d,t=%d,p=%d,salt=%d,key=%d",
			parsed.memory, parsed.iterations, parsed.parallelism, len(parsed.salt), len(parsed.digest))
	}
	verification := verifyPasswordHash(hash, "canonical-password-value")
	if !verification.matches || verification.needsUpgrade {
		t.Fatalf("canonical verification = %#v", verification)
	}
}

func TestPasswordVerificationAcceptsBoundedWeakHashForUpgrade(t *testing.T) {
	const password = "Legacy-password-value"
	salt := []byte("12345678")
	digest := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 16)
	weak := fmt.Sprintf("$argon2id$v=%d$m=8192,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))

	verification := verifyPasswordHash(weak, password)
	if !verification.matches || !verification.needsUpgrade || !VerifyPassword(weak, password) {
		t.Fatalf("weak verification = %#v", verification)
	}
	if wrong := verifyPasswordHash(weak, "Wrong-password-value"); wrong.matches || wrong.needsUpgrade {
		t.Fatalf("wrong password verification = %#v", wrong)
	}
}

func TestPasswordVerificationRejectsMalformedAndResourceOversizedHashes(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("1234567890123456"))
	digest := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	for name, hash := range map[string]string{
		"wrong algorithm":       "$argon2i$v=19$m=65536,t=3,p=2$" + salt + "$" + digest,
		"wrong version":         "$argon2id$v=18$m=65536,t=3,p=2$" + salt + "$" + digest,
		"parameter suffix":      "$argon2id$v=19$m=65536,t=3,p=2,x=1$" + salt + "$" + digest,
		"memory oversized":      "$argon2id$v=19$m=65537,t=3,p=2$" + salt + "$" + digest,
		"iterations oversized":  "$argon2id$v=19$m=65536,t=4,p=2$" + salt + "$" + digest,
		"parallelism oversized": "$argon2id$v=19$m=65536,t=3,p=3$" + salt + "$" + digest,
		"salt oversized": "$argon2id$v=19$m=65536,t=3,p=2$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, 17)) + "$" + digest,
		"key oversized": "$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, 33)),
		"encoded oversized": strings.Repeat("x", 257),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parsePasswordHash(hash); ok || VerifyPassword(hash, "canonical-password-value") {
				t.Fatalf("accepted hash %q", hash)
			}
		})
	}
}
