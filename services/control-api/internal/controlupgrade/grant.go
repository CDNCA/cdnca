package controlupgrade

import (
	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

// SignerRevocationChecker reports whether an authentic signer key ID is
// revoked by the last verified signer-revocation checkpoint.
type SignerRevocationChecker interface {
	CheckSignerRevocation(entitlementguard.SignerArtifactClass, string) error
}

func VerifyGrant(encoded []byte, keys *entitlement.KeyRing,
	options entitlement.UpgradeGrantVerifyOptions) (entitlement.UpgradeGrant, error) {
	return VerifyGrantWithRevocation(encoded, keys, options, nil)
}

// VerifyGrantWithRevocation verifies the grant and then rejects it when the
// outer grant signer or the embedded release-manifest signer is revoked for
// release artifacts. Each signer identity is checked independently.
func VerifyGrantWithRevocation(encoded []byte, keys *entitlement.KeyRing,
	options entitlement.UpgradeGrantVerifyOptions, revocation SignerRevocationChecker) (entitlement.UpgradeGrant, error) {
	signed, err := entitlement.DecodeUpgradeGrant(encoded)
	if err != nil {
		return entitlement.UpgradeGrant{}, err
	}
	if err := keys.VerifyUpgradeGrant(signed, options); err != nil {
		return entitlement.UpgradeGrant{}, err
	}
	if err := checkReleaseSigners(revocation, signed.KeyID, signed.Grant.ArtifactSignatureKeyID); err != nil {
		return entitlement.UpgradeGrant{}, err
	}
	return signed.Grant, nil
}

func checkReleaseSigners(revocation SignerRevocationChecker, keyIDs ...string) error {
	if revocation == nil {
		return nil
	}
	for _, keyID := range keyIDs {
		if keyID == "" {
			continue
		}
		if err := revocation.CheckSignerRevocation(entitlementguard.SignerArtifactRelease, keyID); err != nil {
			return err
		}
	}
	return nil
}
