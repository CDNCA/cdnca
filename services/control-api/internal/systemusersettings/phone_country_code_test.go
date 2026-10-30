package systemusersettings

import (
	"encoding/json"
	"testing"
)

// FX38: the platform default calling code completes bare phone numbers; it
// defaults to 86, old documents without it read as 86, and only 1-4 digits
// without a leading zero are accepted.
func TestDefaultPhoneCountryCodeSetting(t *testing.T) {
	if DefaultSettings().DefaultPhoneCountryCode != "86" {
		t.Fatalf("default = %q", DefaultSettings().DefaultPhoneCountryCode)
	}
	for _, code := range []string{"86", "1", "852", "1264"} {
		value := DefaultSettings()
		value.DefaultPhoneCountryCode = code
		if !validSettings(value) {
			t.Errorf("code %q rejected", code)
		}
	}
	for _, code := range []string{"", "0", "086", "+86", "12345", "8a"} {
		value := DefaultSettings()
		value.DefaultPhoneCountryCode = code
		if validSettings(value) {
			t.Errorf("code %q accepted", code)
		}
	}
	encoded, _ := json.Marshal(DefaultSettings())
	var legacy map[string]any
	_ = json.Unmarshal(encoded, &legacy)
	delete(legacy, "default_phone_country_code")
	raw, _ := json.Marshal(legacy)
	value, err := decodeSettings(raw)
	if err != nil || value.DefaultPhoneCountryCode != "86" {
		t.Fatalf("legacy document = %q, %v", value.DefaultPhoneCountryCode, err)
	}
}
