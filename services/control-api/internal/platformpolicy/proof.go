package platformpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type ResolveInput struct {
	InstallationID            uuid.UUID
	ControlVersion            string
	ControlProtocolVersion    int
	KnownGlobalRevision       int64
	KnownInstallationRevision int64
	ActiveTargetRevisionID    *string
	ActivePolicySHA256        *string
	Cursor                    *string
	KnownETag                 *string
}

type ResolveRequest struct {
	Schema                    string  `json:"schema"`
	RequestID                 string  `json:"request_id"`
	InstallationID            string  `json:"installation_id"`
	RequestedAt               int64   `json:"requested_at"`
	ControlVersion            string  `json:"control_version"`
	ControlProtocolVersion    int     `json:"control_protocol_version"`
	KnownGlobalRevision       int64   `json:"known_global_revision"`
	KnownInstallationRevision int64   `json:"known_installation_revision"`
	ActiveTargetRevisionID    *string `json:"active_target_revision_id"`
	ActivePolicySHA256        *string `json:"active_policy_sha256"`
	Cursor                    *string `json:"cursor"`
	KnownETag                 *string `json:"known_etag"`
	Proof                     string  `json:"proof"`
}

type AckInput struct {
	InstallationID        uuid.UUID
	TargetRevisionID      string
	ScopeKind             string
	ScopeRevision         int64
	CanonicalPolicySHA256 string
	Status                string
	ErrorCode             *string
	ObservedAt            time.Time
}

type AckRequest struct {
	Schema                string  `json:"schema"`
	RequestID             string  `json:"request_id"`
	InstallationID        string  `json:"installation_id"`
	RequestedAt           int64   `json:"requested_at"`
	TargetRevisionID      string  `json:"target_revision_id"`
	ScopeKind             string  `json:"scope_kind"`
	ScopeRevision         int64   `json:"scope_revision"`
	CanonicalPolicySHA256 string  `json:"canonical_policy_sha256"`
	Status                string  `json:"status"`
	ErrorCode             *string `json:"error_code"`
	ObservedAt            int64   `json:"observed_at"`
	Proof                 string  `json:"proof"`
}

func PrepareResolve(input ResolveInput, requestID string, requestedAt time.Time,
	privateKey ed25519.PrivateKey) (ResolveRequest, error) {
	if input.InstallationID == uuid.Nil || !validRequestID(requestID) || requestedAt.IsZero() ||
		!validSemver(input.ControlVersion) || input.ControlProtocolVersion < 1 ||
		input.KnownGlobalRevision < 0 || input.KnownInstallationRevision < 0 ||
		input.KnownGlobalRevision > maxSafeRevision || input.KnownInstallationRevision > maxSafeRevision ||
		(input.ActiveTargetRevisionID == nil) != (input.ActivePolicySHA256 == nil) ||
		(input.ActiveTargetRevisionID != nil && !validUUID(*input.ActiveTargetRevisionID)) ||
		(input.ActivePolicySHA256 != nil && !validDigest(*input.ActivePolicySHA256)) ||
		(input.Cursor != nil && len(*input.Cursor) > 512) || (input.KnownETag != nil && len(*input.KnownETag) > 128) ||
		len(privateKey) != ed25519.PrivateKeySize {
		return ResolveRequest{}, ErrInvalidEnvelope
	}
	request := ResolveRequest{
		Schema: ResolveRequestSchema, RequestID: requestID, InstallationID: input.InstallationID.String(),
		RequestedAt: requestedAt.UTC().Unix(), ControlVersion: input.ControlVersion,
		ControlProtocolVersion: input.ControlProtocolVersion, KnownGlobalRevision: input.KnownGlobalRevision,
		KnownInstallationRevision: input.KnownInstallationRevision,
		ActiveTargetRevisionID:    cloneString(input.ActiveTargetRevisionID), ActivePolicySHA256: cloneStringOrEmpty(input.ActivePolicySHA256),
		Cursor: cloneStringOrEmpty(input.Cursor), KnownETag: cloneStringOrEmpty(input.KnownETag),
	}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ResolveProofMessage(request)))
	return request, nil
}

func PrepareAcknowledgement(input AckInput, requestID string, requestedAt time.Time,
	privateKey ed25519.PrivateKey) (AckRequest, error) {
	if input.InstallationID == uuid.Nil || !validRequestID(requestID) || requestedAt.IsZero() || input.ObservedAt.IsZero() ||
		!validUUID(input.TargetRevisionID) || (input.ScopeKind != ScopeGlobal && input.ScopeKind != ScopeInstallation) ||
		input.ScopeRevision < 1 || input.ScopeRevision > maxSafeRevision || !validDigest(input.CanonicalPolicySHA256) ||
		!validAck(input.Status, input.ErrorCode) || len(privateKey) != ed25519.PrivateKeySize {
		return AckRequest{}, ErrInvalidEnvelope
	}
	request := AckRequest{
		Schema: AckRequestSchema, RequestID: requestID, InstallationID: input.InstallationID.String(),
		RequestedAt: requestedAt.UTC().Unix(), TargetRevisionID: input.TargetRevisionID,
		ScopeKind: input.ScopeKind, ScopeRevision: input.ScopeRevision,
		CanonicalPolicySHA256: input.CanonicalPolicySHA256, Status: input.Status,
		ErrorCode: cloneString(input.ErrorCode), ObservedAt: input.ObservedAt.UTC().Unix(),
	}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, AckProofMessage(request)))
	return request, nil
}

func ResolveProofMessage(request ResolveRequest) []byte {
	return digestFields(
		ResolveProofDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatInt(request.RequestedAt, 10), request.ControlVersion,
		strconv.Itoa(request.ControlProtocolVersion), strconv.FormatInt(request.KnownGlobalRevision, 10),
		strconv.FormatInt(request.KnownInstallationRevision, 10), optionalString(request.ActiveTargetRevisionID),
		optionalString(request.ActivePolicySHA256), optionalString(request.Cursor), optionalString(request.KnownETag),
	)
}

func AckProofMessage(request AckRequest) []byte {
	return digestFields(
		AckProofDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatInt(request.RequestedAt, 10), request.TargetRevisionID, request.ScopeKind,
		strconv.FormatInt(request.ScopeRevision, 10), request.CanonicalPolicySHA256,
		request.Status, optionalString(request.ErrorCode), strconv.FormatInt(request.ObservedAt, 10),
	)
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

func validRequestID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && len(value) == 43
}

func validAck(status string, errorCode *string) bool {
	switch status {
	case AckFetched, AckValidated, AckApplied, AckRolledBack:
		return errorCode == nil
	case AckRejected:
		return errorCode != nil && codePattern.MatchString(*errorCode)
	default:
		return false
	}
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneStringOrEmpty(value *string) *string {
	if value == nil {
		empty := ""
		return &empty
	}
	return cloneString(value)
}
