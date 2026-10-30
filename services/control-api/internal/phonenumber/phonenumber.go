// Package phonenumber normalizes account phone numbers so one number written
// in different ways ("13800138000", "+86 138-0013-8000", "008613800138000")
// is stored and compared as a single E.164 value (FX38). Bare national
// numbers are completed with the platform's default calling code.
package phonenumber

import (
	"errors"
	"strings"
)

// ErrInvalid reports a value that is not an acceptable phone number.
var ErrInvalid = errors.New("invalid phone number")

// DefaultCountryCode is used when the platform setting is empty.
const DefaultCountryCode = "86"

// ValidCountryCode accepts "" (the default) or 1-4 digits without a leading 0.
func ValidCountryCode(code string) bool {
	return code == "" || len(code) <= 4 && code[0] != '0' && allDigits(code)
}

// Normalize returns the canonical form of value; defaultCode is the platform
// "default country/region calling code" ("" means DefaultCountryCode):
//   - formatting characters (space, '-', '.', '(', ')') are removed;
//   - an international prefix "00" becomes "+";
//   - "+<8..15 digits>" (no leading 0 after '+') is E.164 and kept;
//   - with code 86, a bare mainland mobile number (11 digits starting with 1,
//     optionally prefixed with 86) becomes "+86…" and any other bare 6..20
//     digit value (e.g. a landline with its area code) is kept as digits;
//   - with another code, a bare national number (an optional trunk 0 is
//     dropped) becomes "+<code><number>" when that is a valid E.164 length.
func Normalize(value, defaultCode string) (string, error) {
	if !ValidCountryCode(defaultCode) {
		return "", ErrInvalid
	}
	if defaultCode == "" {
		defaultCode = DefaultCountryCode
	}
	compact := strings.Map(func(character rune) rune {
		switch character {
		case ' ', '-', '.', '(', ')':
			return -1
		}
		return character
	}, strings.TrimSpace(value))
	if strings.HasPrefix(compact, "00") {
		compact = "+" + compact[2:]
	}
	if digits, international := strings.CutPrefix(compact, "+"); international {
		if len(digits) < 8 || len(digits) > 15 || digits[0] == '0' || !allDigits(digits) {
			return "", ErrInvalid
		}
		return compact, nil
	}
	if !allDigits(compact) {
		return "", ErrInvalid
	}
	if defaultCode != DefaultCountryCode {
		national := strings.TrimPrefix(compact, "0")
		if national == "" || national[0] == '0' || len(defaultCode)+len(national) < 8 || len(defaultCode)+len(national) > 15 {
			return "", ErrInvalid
		}
		return "+" + defaultCode + national, nil
	}
	switch {
	case len(compact) == 11 && compact[0] == '1':
		return "+86" + compact, nil
	case len(compact) == 13 && strings.HasPrefix(compact, "861"):
		return "+" + compact, nil
	case len(compact) >= 6 && len(compact) <= 20:
		return compact, nil
	}
	return "", ErrInvalid
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
