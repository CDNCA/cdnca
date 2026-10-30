package entitlementguard

import "errors"

// SignerArtifactClass mirrors the artifact classes of the authorization
// center's signer-revocation manifest (lease, policy, release). It is defined
// here so the trust store can consult revocation state without importing the
// checkpoint consumer, which already depends on this package.
type SignerArtifactClass string

const (
	SignerArtifactLease   SignerArtifactClass = "lease"
	SignerArtifactPolicy  SignerArtifactClass = "policy"
	SignerArtifactRelease SignerArtifactClass = "release"
)

// ErrSignerRevoked is returned when an authentic signature was produced by a
// signing key that the last verified revocation checkpoint marks as revoked
// for the artifact class.
var ErrSignerRevoked = errors.New("signing key is revoked for this artifact class")

type SignerRevokedError struct {
	Class SignerArtifactClass
	KeyID string
}

func (failure *SignerRevokedError) Error() string {
	return "signing key " + failure.KeyID + " is revoked for " + string(failure.Class) + " artifacts"
}

func (failure *SignerRevokedError) Unwrap() error { return ErrSignerRevoked }

// SignerRevocationGate answers only "is this key known to be revoked". It must
// return nil when no verified revocation state is available so that an
// unreachable or older authorization center never blocks the control plane.
type SignerRevocationGate interface {
	CheckSigner(class SignerArtifactClass, keyID string) error
}

type signerRevocationGateHolder struct{ gate SignerRevocationGate }

// SetSignerRevocationGate installs (or, with nil, removes) the gate consulted
// after every successful lease and upgrade-bundle signature verification.
func (store *TrustStore) SetSignerRevocationGate(gate SignerRevocationGate) {
	if store == nil {
		return
	}
	if gate == nil {
		store.revocationGate.Store(nil)
		return
	}
	store.revocationGate.Store(&signerRevocationGateHolder{gate: gate})
}

// CheckSignerRevocation lets callers that verify signatures through other
// key rings apply the same decision to a signer key ID.
func (store *TrustStore) CheckSignerRevocation(class SignerArtifactClass, keyID string) error {
	if store == nil {
		return nil
	}
	holder := store.revocationGate.Load()
	if holder == nil || holder.gate == nil {
		return nil
	}
	return holder.gate.CheckSigner(class, keyID)
}
