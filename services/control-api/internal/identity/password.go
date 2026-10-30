package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16
	argonKeyLength   = 32

	minimumArgonMemory      = 8 * 1024
	minimumArgonIterations  = 1
	minimumArgonParallelism = 1
	minimumArgonSaltLength  = 8
	minimumArgonKeyLength   = 16
	maximumPasswordHashSize = 256
)

type passwordHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	digest      []byte
}

type passwordVerification struct {
	matches      bool
	needsUpgrade bool
	validHash    bool
	weakHash     bool
}

// HashPassword hashes a new password and is the policy gate: a password that
// breaks libs/passwordpolicy is ErrInvalidUserInput wrapping *passwordpolicy.Error.
func HashPassword(password string) (string, error) {
	if err := CheckNewPassword(password); err != nil {
		return "", err
	}
	return hashPasswordUnchecked(password)
}

// CheckNewPassword applies libs/passwordpolicy to a password being set. The
// error is ErrInvalidUserInput and carries *passwordpolicy.Error, which the
// HTTP layer reports as password_policy_unmet.
func CheckNewPassword(password string) error {
	if err := passwordpolicy.Check(password); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidUserInput, err)
	}
	return nil
}

// hashPasswordUnchecked hashes a password that already signed in (parameter
// upgrade, legacy import), so the new-password policy does not apply.
func hashPasswordUnchecked(password string) (string, error) {
	if len(password) == 0 || len(password) > passwordpolicy.MaxLength {
		return "", errors.New("password length out of range")
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	return verifyPasswordHash(encoded, password).matches
}

func verifyPasswordHash(encoded, password string) passwordVerification {
	parsed, ok := parsePasswordHash(encoded)
	if !ok {
		return passwordVerification{}
	}
	actual := argon2.IDKey(
		[]byte(password), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(len(parsed.digest)),
	)
	matches := subtle.ConstantTimeCompare(actual, parsed.digest) == 1
	weak := parsed.memory != argonMemory || parsed.iterations != argonIterations ||
		parsed.parallelism != argonParallelism || len(parsed.salt) != argonSaltLength ||
		len(parsed.digest) != argonKeyLength
	return passwordVerification{
		matches: matches, needsUpgrade: matches && weak, validHash: true, weakHash: weak,
	}
}

func parsePasswordHash(encoded string) (passwordHash, bool) {
	if len(encoded) == 0 || len(encoded) > maximumPasswordHashSize {
		return passwordHash{}, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return passwordHash{}, false
	}
	parameters, ok := parsePasswordHashParameters(parts[3])
	if !ok {
		return passwordHash{}, false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || base64.RawStdEncoding.EncodeToString(salt) != parts[4] ||
		len(salt) < minimumArgonSaltLength || len(salt) > argonSaltLength {
		return passwordHash{}, false
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || base64.RawStdEncoding.EncodeToString(digest) != parts[5] ||
		len(digest) < minimumArgonKeyLength || len(digest) > argonKeyLength {
		return passwordHash{}, false
	}
	return passwordHash{
		memory: parameters.memory, iterations: parameters.iterations,
		parallelism: parameters.parallelism, salt: salt, digest: digest,
	}, true
}

func parsePasswordHashParameters(encoded string) (passwordHash, bool) {
	var result passwordHash
	seen := make(map[string]bool, 3)
	values := strings.Split(encoded, ",")
	if len(values) != 3 {
		return passwordHash{}, false
	}
	for _, value := range values {
		name, raw, found := strings.Cut(value, "=")
		if !found || seen[name] || raw == "" {
			return passwordHash{}, false
		}
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != raw {
			return passwordHash{}, false
		}
		seen[name] = true
		switch name {
		case "m":
			if parsed < minimumArgonMemory || parsed > argonMemory {
				return passwordHash{}, false
			}
			result.memory = uint32(parsed)
		case "t":
			if parsed < minimumArgonIterations || parsed > argonIterations {
				return passwordHash{}, false
			}
			result.iterations = uint32(parsed)
		case "p":
			if parsed < minimumArgonParallelism || parsed > argonParallelism {
				return passwordHash{}, false
			}
			result.parallelism = uint8(parsed)
		default:
			return passwordHash{}, false
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] {
		return passwordHash{}, false
	}
	return result, true
}
