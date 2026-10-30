package signerrevocation

import (
	"reflect"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

func (snapshot Snapshot) Decide(class ArtifactClass, signer SignerIdentity, at time.Time) Decision {
	if class != ArtifactLease && class != ArtifactPolicy && class != ArtifactRelease {
		return Decision{Reason: ReasonArtifactClassUntrusted}
	}
	if snapshot.Revision == 0 || snapshot.Keyset == nil || at.IsZero() {
		return Decision{Reason: ReasonRevocationStateUnavailable}
	}
	if entitlement.ValidateKeyID(signer.KeyID) != nil || signer.Generation == 0 {
		return Decision{Reason: ReasonSignerIdentityUntrusted}
	}
	if _, found := lineageKey(snapshot, signer.KeyID, signer.Generation); !found {
		return Decision{Reason: ReasonSignerIdentityUntrusted}
	}
	for _, revoked := range snapshot.Revocations {
		if revoked.RevokedKeyID != signer.KeyID || revoked.RevokedKeyGeneration != signer.Generation ||
			at.UTC().Truncate(time.Microsecond).Before(revoked.EffectiveNotBefore) {
			continue
		}
		for _, affected := range revoked.ArtifactClasses {
			if affected == class {
				return Decision{Reason: ReasonSignerRevoked}
			}
		}
	}
	return Decision{Allowed: true, Reason: ReasonAllowed}
}

type Runtime struct {
	current atomic.Pointer[Snapshot]
}

func NewRuntime(snapshot Snapshot) (*Runtime, error) {
	runtime := &Runtime{}
	if err := runtime.Replace(snapshot); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (runtime *Runtime) Replace(snapshot Snapshot) error {
	if runtime == nil || snapshot.Revision == 0 || snapshot.Keyset == nil {
		return ErrInvalidStoredState
	}
	cloned := cloneSnapshot(snapshot)
	for {
		current := runtime.current.Load()
		if current != nil {
			switch {
			case cloned.Revision < current.Revision:
				return ErrSnapshotRollback
			case cloned.Revision == current.Revision:
				if reflect.DeepEqual(cloned, *current) {
					return nil
				}
				return ErrSnapshotConflict
			}
		}
		if runtime.current.CompareAndSwap(current, &cloned) {
			return nil
		}
	}
}

func (runtime *Runtime) Snapshot() (Snapshot, bool) {
	if runtime == nil {
		return Snapshot{}, false
	}
	current := runtime.current.Load()
	if current == nil {
		return Snapshot{}, false
	}
	return cloneSnapshot(*current), true
}

func (runtime *Runtime) DecideLease(signer SignerIdentity, at time.Time) Decision {
	return runtime.decide(ArtifactLease, signer, at)
}

func (runtime *Runtime) DecidePolicy(signer SignerIdentity, at time.Time) Decision {
	return runtime.decide(ArtifactPolicy, signer, at)
}

func (runtime *Runtime) DecideRelease(signer SignerIdentity, at time.Time) Decision {
	return runtime.decide(ArtifactRelease, signer, at)
}

// Upgrade grants and their embedded release manifests are both release-class
// artifacts; callers must check each fixed signer identity independently.
func (runtime *Runtime) DecideUpgradeGrant(signer SignerIdentity, at time.Time) Decision {
	return runtime.decide(ArtifactRelease, signer, at)
}

func (runtime *Runtime) decide(class ArtifactClass, signer SignerIdentity, at time.Time) Decision {
	snapshot, ok := runtime.Snapshot()
	if !ok {
		return Decision{Reason: ReasonRevocationStateUnavailable}
	}
	return snapshot.Decide(class, signer, at)
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.KeysetPayload = append([]byte(nil), snapshot.KeysetPayload...)
	if snapshot.Keyset != nil {
		cloned := *snapshot.Keyset
		cloned.Chain = append([]string(nil), snapshot.Keyset.Chain...)
		cloned.Payload = append([]byte(nil), snapshot.Keyset.Payload...)
		cloned.Keys = make([]entitlementguard.VerificationKey, len(snapshot.Keyset.Keys))
		for index, key := range snapshot.Keyset.Keys {
			cloned.Keys[index] = cloneVerificationKey(key)
		}
		snapshot.Keyset = &cloned
	}
	revocations := snapshot.Revocations
	snapshot.Revocations = make([]Revocation, len(revocations))
	for index, revoked := range revocations {
		revoked.ArtifactClasses = append([]ArtifactClass(nil), revoked.ArtifactClasses...)
		revoked.Encoded = append([]byte(nil), revoked.Encoded...)
		snapshot.Revocations[index] = revoked
	}
	return snapshot
}

func cloneVerificationKey(key entitlementguard.VerificationKey) entitlementguard.VerificationKey {
	key.PublicKey = append([]byte(nil), key.PublicKey...)
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

var _ DecisionSource = (*Runtime)(nil)
