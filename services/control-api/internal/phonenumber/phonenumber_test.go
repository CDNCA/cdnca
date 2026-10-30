package phonenumber

import (
	"errors"
	"testing"
)

// FX38: the same phone written differently must normalize to one E.164
// value so the users.phone unique index rejects the duplicate.
func TestNormalize(t *testing.T) {
	for input, want := range map[string]string{
		"13800138000":          "+8613800138000",
		"+8613800138000":       "+8613800138000",
		"8613800138000":        "+8613800138000",
		"008613800138000":      "+8613800138000",
		"+86 138-0013-8000":    "+8613800138000",
		" (+86) 138 0013 8000": "+8613800138000",
		"+1 (415) 555-0100":    "+14155550100",
		"0014155550100":        "+14155550100",
		"010-12345678":         "01012345678",
		"123456":               "123456",
	} {
		got, err := Normalize(input, "86")
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "abc", "+", "++8613800138000", "+0123456789", "12345", "+8613800138000x",
		"+1234567890123456", "1380013800０"} {
		if _, err := Normalize(input, "86"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%q) error = %v, want ErrInvalid", input, err)
		}
	}
}

// FX38: a bare mobile number is completed with the configured default
// country code; numbers that already carry one are unchanged.
func TestNormalizeUsesConfiguredDefaultCountryCode(t *testing.T) {
	for _, item := range []struct{ input, code, want string }{
		{"4155550100", "1", "+14155550100"},
		{"07911123456", "44", "+447911123456"},
		{"+8613800138000", "1", "+8613800138000"},
		{"13800138000", "", "+8613800138000"},
		{"13800138000", "86", "+8613800138000"},
		{"010-12345678", "86", "01012345678"},
	} {
		got, err := Normalize(item.input, item.code)
		if err != nil || got != item.want {
			t.Errorf("Normalize(%q, %q) = %q, %v; want %q", item.input, item.code, got, err, item.want)
		}
	}
	for _, code := range []string{"0", "12345", "+1", "a"} {
		if _, err := Normalize("4155550100", code); !errors.Is(err, ErrInvalid) {
			t.Errorf("default code %q accepted", code)
		}
	}
	if !ValidCountryCode("") || !ValidCountryCode("852") || ValidCountryCode("0852") {
		t.Fatal("ValidCountryCode")
	}
}
