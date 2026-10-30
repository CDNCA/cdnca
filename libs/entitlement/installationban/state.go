package installationban

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// Installation state fetch (ADR 0014 §4.4): control-api calls StatePath with
// headers signed by its installation key; the license service answers with the
// latest BanNotice and, for active installations, the current ServiceTicket.
const (
	StatePath             = "/installation/v2/installation-state/current"
	StateSchema           = "cdnca.installation-state/v1"
	StateFetchProofDomain = "cdnca-installation-state-fetch-proof/v1"
	StateFetchClockSkew   = 5 * time.Minute

	HeaderRequestID      = "X-Request-ID"
	HeaderInstallationID = "X-Cdnca-Installation-ID"
	HeaderRequestedAt    = "X-Cdnca-Requested-At"
	HeaderProof          = "X-Cdnca-Proof"
)

var (
	ErrInvalidFetchProof = errors.New("invalid installation state fetch proof")
	ErrFetchExpired      = errors.New("installation state fetch proof is outside the clock window")
)

type StateFetchProof struct {
	InstallationID string
	RequestID      string
	RequestedAt    int64
	Signature      string
}

// StateFetchProofMessage is the SHA-256 of the length-prefixed fields the
// installation key signs.
func StateFetchProofMessage(proof StateFetchProof) ([]byte, error) {
	if !validUUID(proof.InstallationID) || !validRequestID(proof.RequestID) || !validTimestamp(proof.RequestedAt) {
		return nil, ErrInvalidFetchProof
	}
	var input bytes.Buffer
	for _, field := range []string{StateFetchProofDomain, "GET", StatePath, proof.RequestID, proof.InstallationID,
		strconv.FormatInt(proof.RequestedAt, 10)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		input.Write(size[:])
		input.WriteString(field)
	}
	digest := sha256.Sum256(input.Bytes())
	return digest[:], nil
}

// SignStateFetchProof fills proof.Signature with the installation key.
func SignStateFetchProof(proof StateFetchProof, installationKey ed25519.PrivateKey) (StateFetchProof, error) {
	message, err := StateFetchProofMessage(proof)
	if err != nil || len(installationKey) != ed25519.PrivateKeySize {
		return StateFetchProof{}, ErrInvalidFetchProof
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(installationKey, message))
	return proof, nil
}

func VerifyStateFetchProof(proof StateFetchProof, installationKey ed25519.PublicKey, now time.Time) error {
	if len(installationKey) != ed25519.PublicKeySize || now.IsZero() {
		return ErrInvalidFetchProof
	}
	message, err := StateFetchProofMessage(proof)
	if err != nil {
		return err
	}
	delta := now.UTC().Unix() - proof.RequestedAt
	if limit := int64(StateFetchClockSkew / time.Second); delta < -limit || delta > limit {
		return ErrFetchExpired
	}
	signature := decodeSignature(proof.Signature)
	if signature == nil || !ed25519.Verify(installationKey, message, signature) {
		return ErrInvalidFetchProof
	}
	return nil
}

// StateResponse is the JSON body of StatePath. Status is informational; only
// the signed documents (base64url of their canonical bytes, empty when absent)
// are authoritative.
type StateResponse struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	Status         string `json:"status"`
	BanNotice      string `json:"ban_notice"`
	ServiceTicket  string `json:"service_ticket"`
}

// DecodeStateResponse strictly decodes the body and returns the raw documents.
func DecodeStateResponse(encoded []byte) (StateResponse, []byte, []byte, error) {
	var response StateResponse
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if len(encoded) == 0 || len(encoded) > 4*MaxDocumentBytes || decoder.Decode(&response) != nil ||
		decoder.More() || response.Schema != StateSchema || !validUUID(response.InstallationID) {
		return StateResponse{}, nil, nil, ErrInvalidDocument
	}
	notice, ok := decodeOptional(response.BanNotice)
	if !ok {
		return StateResponse{}, nil, nil, ErrInvalidDocument
	}
	ticket, ok := decodeOptional(response.ServiceTicket)
	if !ok {
		return StateResponse{}, nil, nil, ErrInvalidDocument
	}
	return response, notice, ticket, nil
}

func decodeOptional(value string) ([]byte, bool) {
	if value == "" {
		return nil, true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return decoded, err == nil && len(decoded) > 0 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
