package entitlementsync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/google/uuid"
)

func activationProofMessage(request activationRequest) []byte {
	codeHash := sha256.Sum256([]byte(request.ActivationCode))
	fields := []string{
		"cdnca-license-activation-proof/v1",
		request.RequestID,
		request.InstallationID.String(),
		strings.TrimSpace(request.Name),
		base64.RawURLEncoding.EncodeToString(request.PublicKey),
		base64.RawURLEncoding.EncodeToString(codeHash[:]),
	}
	// The optional installation encryption key (PA-14) is a trailing field
	// only when present (same rule as the license service).
	if len(request.EncryptionPublicKey) > 0 {
		fields = append(fields, "encryption_public_key", base64.RawURLEncoding.EncodeToString(request.EncryptionPublicKey))
	}
	return digestFields(fields...)
}

func renewalProofMessage(installationID uuid.UUID, requestID string) []byte {
	return digestFields("cdnca-license-renewal-proof/v1", requestID, installationID.String())
}

func digestFields(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}
