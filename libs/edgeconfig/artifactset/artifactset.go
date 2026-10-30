// Package artifactset is the node artifact set contract between the control
// plane and edge agents (ADR 0007 section 4.3, CAPABILITY_NAME_ARTIFACT_SET
// v1).
//
// A node artifact set is the complete desired set of node-wide artifacts
// (first: the IP intelligence library) for one node. An item missing from a
// newer set is uninstalled. The control plane signs one set per node and
// revision with the edge publication key the agent already trusts for
// deployments, under its own signature domain.
//
// Delivery rides the edge deployment channel in two kinds of platform-scope
// node-side deployments:
//
//   - segment objects: one configuration per segment (MediaTypeSegment, at
//     most MaxSegmentBytes), shared by every node; the agent stores the bytes
//     in its content-addressed object store under the segment SHA-256;
//   - the set: one configuration per node and revision holding only the
//     signed set document (MediaTypeSet), which names items by digest.
//
// The agent applies a set only when every segment of every item is in its
// object store, prechecks every item with the installer of its media type,
// switches the whole set or nothing, and answers with a Receipt.
package artifactset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"time"
)

const (
	SetSchema       = "cdnca.edge.artifact-set/v1"
	ReceiptSchema   = "cdnca.edge.artifact-set-receipt/v1"
	SignatureDomain = "cdnca-edge-artifact-set/v1"

	// MediaTypeSet is the deployment artifact carrying a signed Set.
	MediaTypeSet = "application/vnd.cdnca.edge.artifact-set+json;version=1"
	// MediaTypeSegment is the deployment artifact carrying one segment object.
	MediaTypeSegment = "application/vnd.cdnca.edge.artifact-segment;version=1"
	// MediaTypeIPIntel is an item whose content is an IP intelligence library
	// (libs/entitlement/ipintel format v2 artifact, CDNIPI01).
	MediaTypeIPIntel = "application/vnd.cdnca.ip-intel-artifact;version=2"
	// MediaTypeEngineModule is an item whose content is a signed engine
	// module bundle (libs/entitlement/enginemodule; the node verifies the
	// platform release signature itself, ADR 0007 section 4.2 B3).
	MediaTypeEngineModule = "application/vnd.cdnca.engine-module+tar;version=1"
	// MediaTypeRulePack is an item whose content is a rule pack: the
	// canonical cdnca.rule-pack/v1 document (CRS profile packs, plain packs)
	// or its sealed form cdnca.rule-pack-sealed/v1, whose content key the
	// item carries wrapped to the node (KeyWrap). Same string as the
	// artifact catalog's rule pack media type. A set may hold several.
	MediaTypeRulePack = "application/vnd.cdnca.rule-pack+json;version=1"

	CompressionNone = "none"
	CompressionZstd = "zstd"
	EncryptionNone  = "none"

	MaxItems           = 32
	MaxSegmentsPerItem = 8
	MaxSegmentBytes    = 4 << 20
	MaxItemBytes       = 64 << 20
	MaxSetBytes        = 64 << 10
	MaxReceiptBytes    = 64 << 10
	// maxRevision keeps revisions exact in JSON numbers and PostgreSQL bigint.
	maxRevision = 1<<53 - 1

	ResultApplied  = "applied"
	ResultRejected = "rejected"
	ResultPending  = "pending"
)

// Reason codes (closed set) of a rejected or pending item.
const (
	ReasonObjectMissing        = "object_missing"
	ReasonSegmentMismatch      = "segment_mismatch"
	ReasonContentMismatch      = "content_mismatch"
	ReasonDecompressFailed     = "decompress_failed"
	ReasonUnsupportedMediaType = "unsupported_media_type"
	ReasonInstallRejected      = "install_rejected"
	// ReasonSignatureInvalid: the item's own signature (engine module:
	// platform release signature) is not trusted by the node.
	ReasonSignatureInvalid = "signature_invalid"
	// ReasonPlatformMismatch: the item is built for another node platform.
	ReasonPlatformMismatch = "platform_mismatch"
	ReasonActivationFailed = "activation_failed"
	// ReasonSetRejected: this item was fine; another item of the set failed,
	// so the set was not switched.
	ReasonSetRejected = "set_rejected"
)

var (
	ErrInvalidSet      = errors.New("node artifact set is invalid")
	ErrUntrusted       = errors.New("node artifact set signature is not trusted")
	ErrInvalidReceipt  = errors.New("node artifact set receipt is invalid")
	ErrSegmentMismatch = errors.New("node artifact segments do not match the item")

	artifactIDPattern = regexp.MustCompile(`^[a-z0-9]+([_-][a-z0-9]+)*/[a-z0-9]+([.-][a-z0-9]+)*$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	mediaTypes = map[string]struct{}{MediaTypeIPIntel: {}, MediaTypeEngineModule: {}, MediaTypeRulePack: {}}
	// wrappedKeyPattern: base64url (unpadded) HPKE wrapped content key.
	wrappedKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,512}$`)
	reasons    = map[string]struct{}{
		ReasonObjectMissing: {}, ReasonSegmentMismatch: {}, ReasonContentMismatch: {}, ReasonDecompressFailed: {},
		ReasonUnsupportedMediaType: {}, ReasonInstallRejected: {}, ReasonSignatureInvalid: {}, ReasonPlatformMismatch: {},
		ReasonActivationFailed: {}, ReasonSetRejected: {},
	}
)

// Segment is one content-addressed slice of an item's compressed bytes.
type Segment struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Item is one desired artifact. Version and Revision are those of the
// control plane's catalog entry (artifactsync LocalArtifact; for an IP
// library the build ID and the library revision), checked by the installer
// against the content. SHA256/Size describe the installed content; the
// compressed bytes (CompressedSHA256/Size) are the concatenated segments.
type Item struct {
	ArtifactID       string    `json:"artifact_id"`
	Version          string    `json:"version"`
	Revision         uint64    `json:"revision"`
	MediaType        string    `json:"media_type"`
	SHA256           string    `json:"sha256"`
	Size             int64     `json:"size"`
	Compression      string    `json:"compression"`
	CompressedSHA256 string    `json:"compressed_sha256"`
	CompressedSize   int64     `json:"compressed_size"`
	Segments         []Segment `json:"segments"`
	Encryption       string    `json:"encryption"`
	// KeyWrap is a sealed rule pack's content key wrapped to this node's
	// artifact encryption key (rulepack.WrapKey, purpose node); only rule
	// pack items carry one. The content itself is not decrypted in transit
	// (Encryption stays none: the sealed document is the content).
	KeyWrap *KeyWrap `json:"key_wrap,omitempty"`
}

// KeyWrap names the node key a content key is wrapped to.
type KeyWrap struct {
	RecipientKeyID string `json:"recipient_key_id"`
	WrappedKey     string `json:"wrapped_key"`
}

// Set is the complete desired set for one node, sorted by artifact ID.
type Set struct {
	Schema    string    `json:"schema"`
	NodeID    string    `json:"node_id"`
	Revision  uint64    `json:"revision"`
	Items     []Item    `json:"items"`
	IssuedAt  time.Time `json:"issued_at"`
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature,omitempty"`
}

// ItemResult is the node's outcome for one item of the received set.
type ItemResult struct {
	ArtifactID string `json:"artifact_id"`
	Version    string `json:"version"`
	SHA256     string `json:"sha256"`
	Result     string `json:"result"`
	Reason     string `json:"reason,omitempty"`
}

// Receipt answers one set deployment. Active* name the set the node runs
// after it (the received set when applied, the last known good otherwise;
// zero when the node has none).
type Receipt struct {
	Schema          string       `json:"schema"`
	NodeID          string       `json:"node_id"`
	Revision        uint64       `json:"revision"`
	SetSHA256       string       `json:"set_sha256"`
	Result          string       `json:"result"`
	ActiveRevision  uint64       `json:"active_revision"`
	ActiveSetSHA256 string       `json:"active_set_sha256,omitempty"`
	Items           []ItemResult `json:"items"`
	ReportedAt      time.Time    `json:"reported_at"`
}

// InstallError is an installer's rejection with a reason code of the closed
// set (the executor reports ReasonInstallRejected for any other error).
type InstallError struct {
	Reason string
	Err    error
}

func (err *InstallError) Error() string { return err.Reason + ": " + err.Err.Error() }
func (err *InstallError) Unwrap() error { return err.Err }

// RejectReason is the receipt reason of an installer error.
func RejectReason(err error) string {
	var install *InstallError
	if errors.As(err, &install) {
		if _, known := reasons[install.Reason]; known {
			return install.Reason
		}
	}
	return ReasonInstallRejected
}

// SupportedMediaType reports whether an item media type is in the closed set.
func SupportedMediaType(mediaType string) bool {
	_, found := mediaTypes[mediaType]
	return found
}

// ValidDigest reports a lowercase hex SHA-256.
func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

// Digest is the SHA-256 of exact bytes (a signed set binds receipts by it).
func Digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// ObjectPath is the content-addressed object path under root
// (ADR 0009 section 8.2): <root>/sha256/<2>/<2>/<64>.
func ObjectPath(root, digest string) (string, error) {
	if !filepath.IsAbs(root) || !ValidDigest(digest) {
		return "", fmt.Errorf("invalid object path for %q", digest)
	}
	return filepath.Join(root, "sha256", digest[:2], digest[2:4], digest), nil
}

// SplitSegments cuts data into consecutive slices of at most size bytes.
func SplitSegments(data []byte, size int) [][]byte {
	if size <= 0 || len(data) == 0 {
		return nil
	}
	segments := make([][]byte, 0, (len(data)+size-1)/size)
	for start := 0; start < len(data); start += size {
		segments = append(segments, data[start:min(start+size, len(data))])
	}
	return segments
}

// Join concatenates segments after checking each and the whole against item.
// The caller decompresses and checks the content digest (CheckContent).
func (item Item) Join(segments [][]byte) ([]byte, error) {
	if validateItem(item) != nil || len(segments) != len(item.Segments) {
		return nil, ErrSegmentMismatch
	}
	joined := make([]byte, 0, item.CompressedSize)
	for index, segment := range segments {
		if int64(len(segment)) != item.Segments[index].Size || Digest(segment) != item.Segments[index].SHA256 {
			return nil, ErrSegmentMismatch
		}
		joined = append(joined, segment...)
	}
	if Digest(joined) != item.CompressedSHA256 {
		return nil, ErrSegmentMismatch
	}
	return joined, nil
}

// CheckContent reports whether content is exactly the item's content.
func (item Item) CheckContent(content []byte) bool {
	return int64(len(content)) == item.Size && Digest(content) == item.SHA256
}

// SigningPayload is the exact byte string the signature covers: the domain,
// a newline, and the canonical set without its signature.
func SigningPayload(set Set) ([]byte, error) {
	if err := validateSet(set); err != nil {
		return nil, err
	}
	set.Signature = ""
	canonical, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrInvalidSet)
	}
	return append([]byte(SignatureDomain+"\n"), canonical...), nil
}

// Signer signs a payload with the edge publication key.
type Signer interface {
	KeyID() string
	Sign(payload []byte) ([]byte, error)
}

type ed25519Signer struct {
	keyID   string
	private ed25519.PrivateKey
}

func (signer ed25519Signer) KeyID() string { return signer.keyID }
func (signer ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

// Sign normalizes, validates and signs set with a local key.
func Sign(set Set, keyID string, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key", ErrInvalidSet)
	}
	return SignWith(set, ed25519Signer{keyID: keyID, private: private})
}

// SignWith normalizes, validates and signs set with signer.
func SignWith(set Set, signer Signer) ([]byte, error) {
	set.Schema, set.Algorithm, set.KeyID = SetSchema, "Ed25519", signer.KeyID()
	set.IssuedAt = set.IssuedAt.UTC().Truncate(time.Second)
	payload, err := SigningPayload(set)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(payload)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: sign", ErrInvalidSet)
	}
	set.Signature = hex.EncodeToString(signature)
	encoded, err := json.Marshal(set)
	if err != nil || len(encoded) > MaxSetBytes {
		return nil, fmt.Errorf("%w: size", ErrInvalidSet)
	}
	return encoded, nil
}

// Decode strictly decodes a canonical set without checking the signature.
func Decode(encoded []byte) (Set, error) {
	var set Set
	if err := decodeCanonical(encoded, MaxSetBytes, &set); err != nil {
		return Set{}, fmt.Errorf("%w: %v", ErrInvalidSet, err)
	}
	if err := validateSet(set); err != nil {
		return Set{}, err
	}
	return set, nil
}

// Verify decodes encoded and verifies its signature with the key resolve
// returns for its key ID.
func Verify(encoded []byte, resolve func(keyID string) (ed25519.PublicKey, bool)) (Set, error) {
	set, err := Decode(encoded)
	if err != nil {
		return Set{}, err
	}
	payload, err := SigningPayload(set)
	if err != nil {
		return Set{}, err
	}
	signature, err := hex.DecodeString(set.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Set{}, fmt.Errorf("%w: signature encoding", ErrUntrusted)
	}
	key, found := resolve(set.KeyID)
	if !found || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, signature) {
		return Set{}, ErrUntrusted
	}
	return set, nil
}

func validateSet(set Set) error {
	if set.Schema != SetSchema || !uuidPattern.MatchString(set.NodeID) || set.Revision == 0 ||
		set.IssuedAt.IsZero() || !set.IssuedAt.Equal(set.IssuedAt.UTC().Truncate(time.Second)) ||
		set.IssuedAt.Location() != time.UTC || set.Algorithm != "Ed25519" || !keyIDPattern.MatchString(set.KeyID) ||
		set.Items == nil || len(set.Items) > MaxItems {
		return fmt.Errorf("%w: envelope", ErrInvalidSet)
	}
	for index, item := range set.Items {
		if err := validateItem(item); err != nil {
			return fmt.Errorf("%w: item %d", ErrInvalidSet, index)
		}
		if index > 0 && set.Items[index-1].ArtifactID >= item.ArtifactID {
			return fmt.Errorf("%w: items are not sorted and unique", ErrInvalidSet)
		}
	}
	return nil
}

func validateItem(item Item) error {
	if !artifactIDPattern.MatchString(item.ArtifactID) || len(item.ArtifactID) > 128 ||
		!versionPattern.MatchString(item.Version) || item.Revision == 0 || item.Revision > maxRevision ||
		!SupportedMediaType(item.MediaType) ||
		!ValidDigest(item.SHA256) || item.Size <= 0 || item.Size > MaxItemBytes ||
		item.Compression != CompressionZstd && item.Compression != CompressionNone ||
		!ValidDigest(item.CompressedSHA256) || item.CompressedSize <= 0 ||
		item.Encryption != EncryptionNone || len(item.Segments) == 0 || len(item.Segments) > MaxSegmentsPerItem ||
		item.Compression == CompressionNone && (item.CompressedSHA256 != item.SHA256 || item.CompressedSize != item.Size) {
		return ErrInvalidSet
	}
	if wrap := item.KeyWrap; wrap != nil && (item.MediaType != MediaTypeRulePack ||
		!keyIDPattern.MatchString(wrap.RecipientKeyID) || !wrappedKeyPattern.MatchString(wrap.WrappedKey)) {
		return ErrInvalidSet
	}
	total := int64(0)
	for index, segment := range item.Segments {
		// SplitSegments layout: every segment but the last has the first one's size.
		if !ValidDigest(segment.SHA256) || segment.Size <= 0 || segment.Size > MaxSegmentBytes ||
			index < len(item.Segments)-1 && segment.Size != item.Segments[0].Size ||
			index == len(item.Segments)-1 && segment.Size > item.Segments[0].Size {
			return ErrInvalidSet
		}
		total += segment.Size
	}
	if total != item.CompressedSize {
		return ErrInvalidSet
	}
	return nil
}

// EncodeReceipt validates and canonically encodes a receipt.
func EncodeReceipt(receipt Receipt) ([]byte, error) {
	receipt.Schema = ReceiptSchema
	receipt.ReportedAt = receipt.ReportedAt.UTC().Truncate(time.Second)
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > MaxReceiptBytes {
		return nil, fmt.Errorf("%w: size", ErrInvalidReceipt)
	}
	return encoded, nil
}

// DecodeReceipt strictly decodes a canonical receipt and checks it.
func DecodeReceipt(encoded []byte) (Receipt, error) {
	var receipt Receipt
	if err := decodeCanonical(encoded, MaxReceiptBytes, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrInvalidReceipt, err)
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema || !uuidPattern.MatchString(receipt.NodeID) || receipt.Revision == 0 ||
		!ValidDigest(receipt.SetSHA256) || receipt.ReportedAt.IsZero() || receipt.Items == nil ||
		len(receipt.Items) > MaxItems || receipt.ActiveSetSHA256 != "" && !ValidDigest(receipt.ActiveSetSHA256) ||
		(receipt.ActiveRevision == 0) != (receipt.ActiveSetSHA256 == "") {
		return fmt.Errorf("%w: envelope", ErrInvalidReceipt)
	}
	counts := map[string]int{}
	for index, item := range receipt.Items {
		if !artifactIDPattern.MatchString(item.ArtifactID) || !versionPattern.MatchString(item.Version) ||
			!ValidDigest(item.SHA256) || index > 0 && receipt.Items[index-1].ArtifactID >= item.ArtifactID {
			return fmt.Errorf("%w: item %d", ErrInvalidReceipt, index)
		}
		_, known := reasons[item.Reason]
		switch item.Result {
		case ResultApplied:
			if item.Reason != "" {
				return fmt.Errorf("%w: applied item has a reason", ErrInvalidReceipt)
			}
		case ResultRejected, ResultPending:
			if !known {
				return fmt.Errorf("%w: item %d reason", ErrInvalidReceipt, index)
			}
		default:
			return fmt.Errorf("%w: item %d result", ErrInvalidReceipt, index)
		}
		counts[item.Result]++
	}
	// A node never runs a revision it did not apply, whatever its digest.
	switched := receipt.ActiveRevision == receipt.Revision
	switch receipt.Result {
	case ResultApplied:
		if !switched || receipt.ActiveSetSHA256 != receipt.SetSHA256 || counts[ResultApplied] != len(receipt.Items) {
			return fmt.Errorf("%w: applied receipt", ErrInvalidReceipt)
		}
	case ResultRejected:
		if switched || counts[ResultRejected] == 0 {
			return fmt.Errorf("%w: rejected receipt", ErrInvalidReceipt)
		}
	case ResultPending:
		if switched || counts[ResultRejected] != 0 || counts[ResultPending] == 0 {
			return fmt.Errorf("%w: pending receipt", ErrInvalidReceipt)
		}
	default:
		return fmt.Errorf("%w: result", ErrInvalidReceipt)
	}
	return nil
}

func decodeCanonical(encoded []byte, limit int, target any) error {
	if len(encoded) == 0 || len(encoded) > limit {
		return errors.New("size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("decode")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	if canonical, err := json.Marshal(target); err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("not canonical")
	}
	return nil
}
