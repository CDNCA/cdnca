package artifactsync

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

// cdncaCE: every code a delivery that failed verification is recorded with
// must revoke the community edition's market purchases.
func TestCommunityRejectionsCoverVerificationFailures(t *testing.T) {
	for _, code := range []string{CodeUnknownKey, CodeInvalidSignature, CodeDigestMismatch, CodeTargetMismatch, CodeExpired,
		CodeRevisionOutOfOrder, CodeSupersedes, CodeInvalidEnvelope} {
		if !slices.Contains(entitlementguard.CommunityCatalogRejections, code) {
			t.Errorf("rejection code %q does not revoke community purchases", code)
		}
	}
	for _, code := range []string{CodeResolveFailed, CodeNotYetValid, CodeApplyFailed, CodeEntryOutOfOrder, ""} {
		if slices.Contains(entitlementguard.CommunityCatalogRejections, code) {
			t.Errorf("non-verification code %q revokes community purchases", code)
		}
	}
}

// A 409 from the license service means another installation holds the key.
func TestEncryptionKeyRegistrationConflictIsExplained(t *testing.T) {
	err := EncryptionKeyRegistrationError("x25519-abc", &ServiceError{StatusCode: 409, Code: "conflict"})
	if !errors.Is(err, ErrEncryptionKeyTaken) || !strings.Contains(err.Error(), "generate-installation-encryption-key") ||
		!strings.Contains(err.Error(), "x25519-abc") {
		t.Fatalf("conflict error = %v", err)
	}
	if err := EncryptionKeyRegistrationError("k", &ServiceError{StatusCode: 503}); errors.Is(err, ErrEncryptionKeyTaken) {
		t.Fatalf("unavailable reported as taken: %v", err)
	}
}
