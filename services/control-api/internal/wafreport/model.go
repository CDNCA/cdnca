package wafreport

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const Schema = "cdnca.waf-custom-rule-report/v1"

type Snapshot struct {
	InstallationID uuid.UUID
	Sequence       uint64
	RequestID      string
	ObservedAt     time.Time
	Policies       []json.RawMessage
	PoliciesDigest [32]byte
	Sent           bool
}

func CanonicalPolicies(policies []json.RawMessage) ([]json.RawMessage, [32]byte, error) {
	return canonicalPolicies(policies)
}

func DigestPolicies(policies []json.RawMessage) [32]byte {
	encoded, _ := json.Marshal(policies)
	return sha256.Sum256(encoded)
}
