package accountrecovery

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
)

const (
	recoveryContextDomain      = "cdnca/account-recovery/recovery-context/v1"
	recoveryContextVersion     = byte(1)
	recoveryContextPayloadSize = 1 + 16 + 16 + 16 + 8 + 32
	recoveryContextSize        = recoveryContextPayloadSize + 32
)

// RecoveryScope is the trusted tenant or platform scope carried by a verified recovery link.
type RecoveryScope struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
}

func issueRecoveryContext(digestKey []byte, claim dispatchClaim, token string) (string, error) {
	if len(digestKey) < 32 || claim.ScopeID == uuid.Nil ||
		claim.ChallengeID == uuid.Nil || claim.ExpiresAt.IsZero() || claim.ExpiresAt.UnixMicro() <= 0 {
		return "", ErrDispatchUnavailable
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(rawToken) != tokenBytes || base64.RawURLEncoding.EncodeToString(rawToken) != token {
		return "", ErrDispatchUnavailable
	}

	payload := make([]byte, recoveryContextPayloadSize)
	payload[0] = recoveryContextVersion
	copy(payload[1:17], claim.TenantID[:])
	copy(payload[17:33], claim.ScopeID[:])
	copy(payload[33:49], claim.ChallengeID[:])
	binary.BigEndian.PutUint64(payload[49:57], uint64(claim.ExpiresAt.UTC().UnixMicro()))
	tokenDigest := keyedDigest(digestKey, tokenDigestDomain, token)
	copy(payload[57:89], tokenDigest[:])
	signature := keyedDigestBytes(digestKey, recoveryContextDomain, payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, signature[:]...)), nil
}

// VerifyRecoveryContext authenticates a recovery link and returns only its trusted scope.
func VerifyRecoveryContext(digestKey []byte, token, encoded string, now time.Time) (RecoveryScope, error) {
	if len(digestKey) < 32 || now.IsZero() {
		return RecoveryScope{}, ErrInvalidToken
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(rawToken) != tokenBytes || base64.RawURLEncoding.EncodeToString(rawToken) != token {
		return RecoveryScope{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != recoveryContextSize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return RecoveryScope{}, ErrInvalidToken
	}
	payload, suppliedSignature := raw[:recoveryContextPayloadSize], raw[recoveryContextPayloadSize:]
	expectedSignature := keyedDigestBytes(digestKey, recoveryContextDomain, payload)
	if !hmac.Equal(expectedSignature[:], suppliedSignature) || payload[0] != recoveryContextVersion {
		return RecoveryScope{}, ErrInvalidToken
	}

	var tenantID, scopeID, challengeID uuid.UUID
	copy(tenantID[:], payload[1:17])
	copy(scopeID[:], payload[17:33])
	copy(challengeID[:], payload[33:49])
	expiresMicros := binary.BigEndian.Uint64(payload[49:57])
	if scopeID == uuid.Nil || challengeID == uuid.Nil || expiresMicros > uint64(^uint64(0)>>1) {
		return RecoveryScope{}, ErrInvalidToken
	}
	expiresAt := time.UnixMicro(int64(expiresMicros)).UTC()
	if !now.UTC().Before(expiresAt) {
		return RecoveryScope{}, ErrInvalidToken
	}
	expectedTokenDigest := keyedDigest(digestKey, tokenDigestDomain, token)
	if !hmac.Equal(expectedTokenDigest[:], payload[57:89]) {
		return RecoveryScope{}, ErrInvalidToken
	}
	return RecoveryScope{TenantID: tenantID, ScopeID: scopeID}, nil
}
