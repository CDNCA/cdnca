// Package gatewayaddr is the signed "change the node's Gateway address"
// document (cdnca.gateway-address-change/v1, fix-nodegw) shared by
// control-api (builds and signs one per node), agent-gateway (routes the
// carrier, never verifies) and edge-agent (verifies, probes, switches,
// answers).
//
// The node verifies the signature (Ed25519, the edge publication key it
// already trusts, as sitedrop), probes the new address with a full mTLS
// handshake (gateway CA + server name) and an authenticated Connect hello,
// and only then makes it the active endpoint; a failed probe leaves the old
// address in place and answers the reason. Revision grows per node: a node
// never applies an older one than it holds.
package gatewayaddr

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"time"
)

const (
	Schema    = "cdnca.gateway-address-change/v1"
	Domain    = Schema + "\n"
	Algorithm = "ed25519"
	// MaxDocumentBytes bounds the wire document.
	MaxDocumentBytes = 2 << 10
	// MaxLifetime bounds expires_at - issued_at: an unanswered change is
	// republished with a new revision rather than kept alive forever.
	MaxLifetime = 7 * 24 * time.Hour
)

// Receipt states and error codes (ConnectRequest gateway_address_change_receipt).
const (
	StateProbing  = "probing"
	StateSwitched = "switched"
	StateFailed   = "failed"

	ErrorUntrusted    = "untrusted_signature"
	ErrorInvalid      = "invalid_document"
	ErrorWrongNode    = "wrong_node"
	ErrorStale        = "stale_revision"
	ErrorExpired      = "expired"
	ErrorDial         = "dial_failed"                 // TCP/TLS: unreachable, certificate or server name rejected
	ErrorHandshake    = "handshake_failed"            // the Gateway answered but did not accept this node's session
	ErrorPersist      = "persist_failed"              // the new address could not be written; the old one stays
	ErrorBusy         = "port_transition_in_progress" // a gateway port transition is still open on the node
	ErrorNotSupported = "not_supported"               // answered by the Gateway for a node without the capability
)

var (
	ErrInvalid   = errors.New("gateway address change is invalid")
	ErrUntrusted = errors.New("gateway address change signature is not trusted")
	ErrWrongNode = errors.New("gateway address change is for another node")
)

var (
	canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	serverName    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	keyID         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// Change is one signed document. Field order is the canonical encoding.
type Change struct {
	Schema     string `json:"schema"`
	NodeID     string `json:"node_id"`
	ChangeID   string `json:"change_id"`
	Revision   uint64 `json:"revision"`
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	Signature  string `json:"signature,omitempty"`
}

// ValidAddress: HOST:PORT with a non-empty host and a port in 1..65535.
func ValidAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || len(address) > 255 {
		return false
	}
	parsed, err := strconv.Atoi(port)
	return err == nil && parsed >= 1 && parsed <= 65535 && strconv.Itoa(parsed) == port
}

// ValidServerName: a DNS name or IP literal usable as TLS SNI / verification name.
func ValidServerName(name string) bool {
	return serverName.MatchString(name) || net.ParseIP(name) != nil
}

func (change Change) validate() error {
	if change.Schema != Schema || change.Algorithm != Algorithm || !keyID.MatchString(change.KeyID) ||
		!canonicalUUID.MatchString(change.NodeID) || !canonicalUUID.MatchString(change.ChangeID) || change.Revision == 0 ||
		!ValidAddress(change.Address) || !ValidServerName(change.ServerName) || change.IssuedAt <= 0 ||
		change.ExpiresAt <= change.IssuedAt || change.ExpiresAt-change.IssuedAt > int64(MaxLifetime/time.Second) {
		return ErrInvalid
	}
	return nil
}

// Expired: the node no longer acts on it.
func (change Change) Expired(now time.Time) bool { return now.Unix() >= change.ExpiresAt }

// SigningPayload is what the control plane signs.
func SigningPayload(change Change) ([]byte, error) {
	change.Signature = ""
	if err := change.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(change)
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte(Domain), encoded...), nil
}

// Seal attaches the signature and returns the wire bytes.
func Seal(change Change, signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	change.Signature = hex.EncodeToString(signature)
	if err := change.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(change)
	if err != nil || len(encoded) > MaxDocumentBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Sign fills schema/algorithm/key, signs with key and seals (tests;
// production signs through the edge publication signer with SigningPayload + Seal).
func Sign(change Change, keyIDValue string, key ed25519.PrivateKey) ([]byte, error) {
	change.Schema, change.Algorithm, change.KeyID, change.Signature = Schema, Algorithm, keyIDValue, ""
	payload, err := SigningPayload(change)
	if err != nil {
		return nil, err
	}
	return Seal(change, ed25519.Sign(key, payload))
}

// Decode strictly decodes canonical wire bytes (no signature check: the
// gateway routes with it).
func Decode(encoded []byte) (Change, error) {
	if len(encoded) == 0 || len(encoded) > MaxDocumentBytes {
		return Change{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var change Change
	if err := decoder.Decode(&change); err != nil {
		return Change{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Change{}, ErrInvalid
	}
	canonical, err := json.Marshal(change)
	if err != nil || !bytes.Equal(canonical, encoded) || change.validate() != nil || change.Signature == "" {
		return Change{}, ErrInvalid
	}
	return change, nil
}

// TrustedKeyFunc resolves a control plane key the node trusts.
type TrustedKeyFunc func(keyID string) (ed25519.PublicKey, bool)

// Open verifies a document for nodeID.
func Open(encoded []byte, nodeID string, trusted TrustedKeyFunc) (Change, error) {
	if trusted == nil {
		return Change{}, ErrInvalid
	}
	change, err := Decode(encoded)
	if err != nil {
		return Change{}, err
	}
	payload, err := SigningPayload(change)
	if err != nil {
		return Change{}, err
	}
	signature, err := hex.DecodeString(change.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != change.Signature {
		return Change{}, ErrInvalid
	}
	key, ok := trusted(change.KeyID)
	if !ok || !ed25519.Verify(key, payload, signature) {
		return Change{}, ErrUntrusted
	}
	if change.NodeID != nodeID {
		return Change{}, ErrWrongNode
	}
	return change, nil
}

// Digest is the SHA-256 the carrier and the receipt bind to.
func Digest(encoded []byte) []byte {
	digest := sha256.Sum256(encoded)
	return digest[:]
}

// Route reads node and revision without verifying (gateway routing).
func Route(encoded []byte) (nodeID string, revision uint64, err error) {
	change, err := Decode(encoded)
	if err != nil {
		return "", 0, err
	}
	return change.NodeID, change.Revision, nil
}

// NATS names (agent-gateway owns the streams).
const (
	CommandStream        = "GATEWAY_ADDRESS_COMMANDS"
	ReceiptStream        = "GATEWAY_ADDRESS_RECEIPTS"
	CommandSubjectPrefix = "cdnca.agent.gateway-address.commands"
	ReceiptSubjectPrefix = "cdnca.agent.gateway-address.receipts"
	ReceiptConsumer      = "control_api_gateway_address_receipts"

	MaxCarrierBytes = MaxDocumentBytes + 2<<10
)
