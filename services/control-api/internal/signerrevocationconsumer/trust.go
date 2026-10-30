package signerrevocationconsumer

import (
	"context"
	"crypto/ed25519"
	"sort"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
)

type DeploymentTrust struct {
	pins                  []entitlementguard.VerificationKey
	offlineRootKeyID      string
	offlineRootGeneration uint64
	offlineRootPublicKey  ed25519.PublicKey
}

func NewDeploymentTrust(store *entitlementguard.TrustStore, config Config) (*DeploymentTrust, error) {
	if store == nil || entitlement.ValidateKeyID(config.OfflineRootKeyID) != nil ||
		config.OfflineRootGeneration == 0 ||
		entitlement.ValidateEd25519PublicKey(config.OfflineRootPublicKey) != nil {
		return nil, ErrInvalidConfiguration
	}
	pins := store.PinnedKeys()
	if len(pins) == 0 {
		return nil, ErrInvalidConfiguration
	}
	for index := range pins {
		if entitlement.ValidateKeyID(pins[index].KeyID) != nil ||
			entitlement.ValidateEd25519PublicKey(pins[index].PublicKey) != nil {
			return nil, ErrInvalidConfiguration
		}
		pins[index] = cloneVerificationKey(pins[index])
	}
	sort.Slice(pins, func(left, right int) bool { return pins[left].KeyID < pins[right].KeyID })
	for index := 1; index < len(pins); index++ {
		if pins[index-1].KeyID == pins[index].KeyID {
			return nil, ErrInvalidConfiguration
		}
	}
	return &DeploymentTrust{
		pins:                  pins,
		offlineRootKeyID:      config.OfflineRootKeyID,
		offlineRootGeneration: config.OfflineRootGeneration,
		offlineRootPublicKey:  append(ed25519.PublicKey(nil), config.OfflineRootPublicKey...),
	}, nil
}

func (trust *DeploymentTrust) KeysetPins(ctx context.Context) ([]entitlementguard.VerificationKey, error) {
	if trust == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]entitlementguard.VerificationKey, len(trust.pins))
	for index := range trust.pins {
		result[index] = cloneVerificationKey(trust.pins[index])
	}
	return result, nil
}

func (trust *DeploymentTrust) OfflineRoot(ctx context.Context, ref signercheckpoint.AuthorityRef) (ed25519.PublicKey, error) {
	if trust == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.Kind != signercheckpoint.AuthorityOfflineRoot || ref.KeyID != trust.offlineRootKeyID ||
		ref.Generation != trust.offlineRootGeneration {
		return nil, signercheckpoint.ErrAuthorityUntrusted
	}
	return append(ed25519.PublicKey(nil), trust.offlineRootPublicKey...), nil
}

func cloneVerificationKey(key entitlementguard.VerificationKey) entitlementguard.VerificationKey {
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	if key.SignUntil != nil {
		value := *key.SignUntil
		key.SignUntil = &value
	}
	if key.VerifyUntil != nil {
		value := *key.VerifyUntil
		key.VerifyUntil = &value
	}
	return key
}

var _ signercheckpoint.TrustSource = (*DeploymentTrust)(nil)
