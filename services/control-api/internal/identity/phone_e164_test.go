package identity

import "testing"

// FX38: admin/user profile saves store the E.164 phone.
func TestNormalizeUserFieldsUsesE164Phone(t *testing.T) {
	fields := UserFields{DisplayName: "Bob", Phone: "008613800138000"}
	if err := normalizeUserFields(&fields, ""); err != nil || fields.Phone != "+8613800138000" {
		t.Fatalf("phone = %q, %v", fields.Phone, err)
	}
}

func TestNormalizeUserFieldsUsesConfiguredCountryCode(t *testing.T) {
	fields := UserFields{DisplayName: "Bob", Phone: "4155550100"}
	if err := normalizeUserFields(&fields, "1"); err != nil || fields.Phone != "+14155550100" {
		t.Fatalf("phone = %q, %v", fields.Phone, err)
	}
}
