package signerrevocation

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

// Gate adapts the last verified checkpoint (LKG) to the trust store's
// SignerRevocationGate. Its policy is deliberately asymmetric:
//
//   - no verified checkpoint (consumer just started, authorization center
//     unreachable, or an older center without the checkpoint route) allows;
//   - a key ID that the verified checkpoint revokes for the artifact class is
//     denied from effective_not_before onwards, measured on the control
//     plane's own clock. Artifact-supplied timestamps are never consulted, so
//     a backdated artifact cannot escape the revocation.
type Gate struct {
	runtime *Runtime
	now     func() time.Time
	logger  *slog.Logger

	denied           atomic.Uint64
	stateUnavailable atomic.Uint64
}

type GateStats struct {
	Denied           uint64
	StateUnavailable uint64
}

func NewGate(runtime *Runtime, now func() time.Time, logger *slog.Logger) *Gate {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Gate{runtime: runtime, now: now, logger: logger}
}

func (gate *Gate) CheckSigner(class entitlementguard.SignerArtifactClass, keyID string) error {
	if gate == nil || gate.runtime == nil {
		return nil
	}
	current := gate.runtime.current.Load()
	if current == nil {
		gate.stateUnavailable.Add(1)
		return nil
	}
	at := gate.now().UTC().Truncate(time.Microsecond)
	for _, revoked := range current.Revocations {
		if revoked.RevokedKeyID != keyID || at.Before(revoked.EffectiveNotBefore) {
			continue
		}
		for _, affected := range revoked.ArtifactClasses {
			if string(affected) != string(class) {
				continue
			}
			gate.denied.Add(1)
			gate.logger.Warn("signing key revoked; artifact rejected",
				"event", "signer_revocation.denied", "reason", ReasonSignerRevoked,
				"artifact_class", string(class), "key_id", keyID,
				"key_generation", revoked.RevokedKeyGeneration,
				"revocation_sequence", revoked.Sequence,
				"effective_not_before", revoked.EffectiveNotBefore.Format(time.RFC3339Nano),
				"checkpoint_revision", current.Revision)
			return &entitlementguard.SignerRevokedError{Class: class, KeyID: keyID}
		}
	}
	return nil
}

func (gate *Gate) Stats() GateStats {
	if gate == nil {
		return GateStats{}
	}
	return GateStats{Denied: gate.denied.Load(), StateUnavailable: gate.stateUnavailable.Load()}
}

var _ entitlementguard.SignerRevocationGate = (*Gate)(nil)
