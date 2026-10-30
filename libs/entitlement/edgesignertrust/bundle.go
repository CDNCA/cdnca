package edgesignertrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

const (
	BundleSchema       = "cdnca.edge-signer-trust-bundle/v1"
	ReceiptSchema      = "cdnca.edge-signer-trust-receipt/v1"
	BundleDomain       = "cdnca.edge-signer-trust-bundle/v1\n"
	MaxBundleBytes     = MaxDocumentBytes + 16<<10
	ResultApplied      = "applied"
	ResultRejected     = "rejected"
	ReasonStale        = "stale_revision"
	ReasonConflict     = "revision_conflict"
	ReasonUntrusted    = "untrusted_signature"
	ReasonInvalid      = "invalid_bundle"
	ReasonPersistence  = "persistence_failed"
	ReasonWrongNode    = "wrong_node"
	ReasonNotSupported = "not_supported"
)

// Bundle carries the exact offline document bytes to one node. control-api
// signs BundleDomain + the canonical bundle without the signature using its
// edge publication key (artifact_trust_file of the node).
type Bundle struct {
	Schema    string `json:"schema"`
	NodeID    string `json:"node_id"`
	Revision  uint64 `json:"revision"`
	Document  string `json:"document"` // base64url of the offline Signed wire bytes
	IssuedAt  string `json:"issued_at"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature,omitempty"`
}

// Receipt is the node's answer to one bundle.
type Receipt struct {
	Schema       string `json:"schema"`
	NodeID       string `json:"node_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	Revision     uint64 `json:"revision"` // the revision the node enforces after this bundle
	Result       string `json:"result"`
	Reason       string `json:"reason,omitempty"`
	ReportedAt   string `json:"reported_at"`
}

// BundleSigningPayload is what the control plane signs.
func BundleSigningPayload(bundle Bundle) ([]byte, error) {
	bundle.Signature = ""
	if err := validateBundleFields(bundle); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return nil, ErrInvalidDocument
	}
	return append([]byte(BundleDomain), encoded...), nil
}

// NewBundle builds the unsigned bundle for nodeID from verified document bytes.
func NewBundle(nodeID string, document []byte, keyID string, now time.Time) (Bundle, error) {
	signed, err := Decode(document)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Schema: BundleSchema, NodeID: nodeID, Revision: signed.Document.Revision,
		Document: base64.RawURLEncoding.EncodeToString(document), IssuedAt: CanonicalTime(now), Algorithm: Algorithm,
		KeyID: keyID}
	return bundle, validateBundleFields(bundle)
}

func validateBundleFields(bundle Bundle) error {
	if bundle.Schema != BundleSchema || !keyIDPattern.MatchString(bundle.NodeID) || bundle.Revision == 0 ||
		bundle.Document == "" || !canonicalTime(bundle.IssuedAt) || bundle.Algorithm != Algorithm ||
		!keyIDPattern.MatchString(bundle.KeyID) {
		return ErrInvalidDocument
	}
	return nil
}

// TrustedKeyFunc resolves a control plane key the node trusts.
type TrustedKeyFunc func(keyID string) (ed25519.PublicKey, bool)

// OpenBundle verifies a bundle for nodeID and returns it with the decoded
// document (structure and digest checked; the node has no offline-root pin,
// the control plane verified it before forwarding).
func OpenBundle(encoded []byte, nodeID string, trusted TrustedKeyFunc) (Bundle, Signed, []byte, error) {
	if trusted == nil {
		return Bundle{}, Signed{}, nil, ErrInvalidDocument
	}
	bundle, err := DecodeBundle(encoded)
	if err != nil {
		return Bundle{}, Signed{}, nil, err
	}
	payload, err := BundleSigningPayload(bundle)
	if err != nil {
		return Bundle{}, Signed{}, nil, err
	}
	signature, err := hex.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != bundle.Signature {
		return Bundle{}, Signed{}, nil, ErrInvalidDocument
	}
	key, ok := trusted(bundle.KeyID)
	if !ok || !ed25519.Verify(key, payload, signature) {
		return Bundle{}, Signed{}, nil, ErrUntrusted
	}
	if bundle.NodeID != nodeID {
		return Bundle{}, Signed{}, nil, ErrInvalidDocument
	}
	document, err := base64.RawURLEncoding.DecodeString(bundle.Document)
	if err != nil || base64.RawURLEncoding.EncodeToString(document) != bundle.Document {
		return Bundle{}, Signed{}, nil, ErrInvalidDocument
	}
	signed, err := Decode(document)
	if err != nil || signed.Document.Revision != bundle.Revision {
		return Bundle{}, Signed{}, nil, ErrInvalidDocument
	}
	return bundle, signed, document, nil
}

// DecodeBundle strictly decodes the canonical bundle wire bytes and checks the
// routing fields. It does not verify the signature or the document: the
// gateway uses it to bind the carrier, the Agent verifies with OpenBundle.
func DecodeBundle(encoded []byte) (Bundle, error) {
	if len(encoded) == 0 || len(encoded) > MaxBundleBytes {
		return Bundle{}, ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, ErrInvalidDocument
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Bundle{}, ErrInvalidDocument
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, encoded) || validateBundleFields(bundle) != nil {
		return Bundle{}, ErrInvalidDocument
	}
	return bundle, nil
}

// SealBundle attaches the signature and returns the wire bytes.
func SealBundle(bundle Bundle, signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidDocument
	}
	bundle.Signature = hex.EncodeToString(signature)
	if err := validateBundleFields(bundle); err != nil {
		return nil, err
	}
	return json.Marshal(bundle)
}

// Digest is the hex SHA-256 receipts bind to.
func Digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// EncodeReceipt validates and encodes a receipt.
func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if !ValidReceipt(receipt) {
		return nil, ErrInvalidDocument
	}
	return json.Marshal(receipt)
}

// DecodeReceipt strictly decodes a receipt.
func DecodeReceipt(encoded []byte) (Receipt, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return Receipt{}, ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil || !ValidReceipt(receipt) {
		return Receipt{}, ErrInvalidDocument
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Receipt{}, ErrInvalidDocument
	}
	return receipt, nil
}

func ValidReceipt(receipt Receipt) bool {
	return receipt.Schema == ReceiptSchema && keyIDPattern.MatchString(receipt.NodeID) &&
		sha256Pattern.MatchString(receipt.BundleSHA256) && receipt.Revision <= maxRevision &&
		(receipt.Result == ResultApplied && receipt.Reason == "" && receipt.Revision > 0 ||
			receipt.Result == ResultRejected && reasonPattern.MatchString(receipt.Reason)) &&
		canonicalTime(receipt.ReportedAt)
}
