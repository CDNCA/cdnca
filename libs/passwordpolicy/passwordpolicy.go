// Package passwordpolicy is the single account-password rule shared by
// control-api and license-service: 8 to 1024
// bytes, at least two of upper case, lower case, digits and ASCII symbols,
// and nothing else (no space, control or non-ASCII character).
// packages/cdnca-ui/src/passwordPolicy.ts mirrors it for the consoles.
package passwordpolicy

import (
	"errors"
	"strings"
)

const (
	MinLength = 8
	MaxLength = 1024
	// MinClasses is how many of the four character classes must appear.
	MinClasses = 2

	// Symbols is every accepted symbol: printable ASCII punctuation.
	Symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

// Unmet items, reported to clients as error.details.unmet.
const (
	UnmetLength           = "length"
	UnmetCharacterClasses = "character_classes"
	UnmetInvalidCharacter = "invalid_character"
)

// Code is the API error code for a password that breaks the policy.
const Code = "password_policy_unmet"

// Details is the error.details body sent with Code.
type Details struct {
	Unmet []string `json:"unmet"`
}

// DetailsOf returns the error.details body for err, when err carries *Error.
func DetailsOf(err error) (*Details, bool) {
	unmet, ok := UnmetOf(err)
	if !ok {
		return nil, false
	}
	return &Details{Unmet: unmet}, true
}

// Error lists every unmet item of a rejected password.
type Error struct {
	Unmet []string
}

func (err *Error) Error() string {
	return "password policy unmet: " + strings.Join(err.Unmet, ",")
}

// Check returns nil for an acceptable password, otherwise *Error.
func Check(password string) error {
	var upper, lower, digit, symbol, invalid bool
	for i := 0; i < len(password); i++ {
		c := password[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		case strings.IndexByte(Symbols, c) >= 0:
			symbol = true
		default:
			invalid = true
		}
	}
	var unmet []string
	if len(password) < MinLength || len(password) > MaxLength {
		unmet = append(unmet, UnmetLength)
	}
	classes := 0
	for _, present := range []bool{upper, lower, digit, symbol} {
		if present {
			classes++
		}
	}
	if classes < MinClasses {
		unmet = append(unmet, UnmetCharacterClasses)
	}
	if invalid {
		unmet = append(unmet, UnmetInvalidCharacter)
	}
	if unmet != nil {
		return &Error{Unmet: unmet}
	}
	return nil
}

// UnmetOf returns the unmet items of err when it (or a wrapped error) is *Error.
func UnmetOf(err error) ([]string, bool) {
	var policyErr *Error
	if errors.As(err, &policyErr) {
		return policyErr.Unmet, true
	}
	return nil, false
}
