package autodefense

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

// SigningPayload is what the control plane signs: Domain followed by the
// canonical JSON of the part without its signature.
func SigningPayload(snapshot Snapshot) ([]byte, error) {
	snapshot.Signature = ""
	if !snapshot.valid() {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > MaxPartBytes {
		return nil, ErrInvalid
	}
	return append([]byte(Domain), encoded...), nil
}

// Seal attaches the signature and returns the wire bytes.
func Seal(snapshot Snapshot, signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	snapshot.Signature = hex.EncodeToString(signature)
	if !snapshot.valid() {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > MaxPartBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Sign canonicalizes, signs with key and seals one part (control plane and
// tests; production signs through the edge publish signer with
// SigningPayload + Seal).
func Sign(snapshot Snapshot, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	snapshot.Algorithm, snapshot.KeyID, snapshot.Signature = Algorithm, keyID, ""
	snapshot.Canonical()
	payload, err := SigningPayload(snapshot)
	if err != nil {
		return nil, err
	}
	return Seal(snapshot, ed25519.Sign(key, payload))
}

// Decode strictly decodes canonical wire bytes (no signature check: the
// gateway routes with it). Unknown fields, trailing data, non-canonical
// order or encoding and a missing signature are rejected.
func Decode(encoded []byte) (Snapshot, error) {
	if len(encoded) == 0 || len(encoded) > MaxPartBytes {
		return Snapshot{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Snapshot{}, ErrInvalid
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(canonical, encoded) || !snapshot.valid() || snapshot.Signature == "" {
		return Snapshot{}, ErrInvalid
	}
	return snapshot, nil
}

// TrustedKeyFunc resolves a control plane key the node trusts.
type TrustedKeyFunc func(keyID string) (ed25519.PublicKey, bool)

// Open verifies one part for nodeID.
func Open(encoded []byte, nodeID string, trusted TrustedKeyFunc) (Snapshot, error) {
	if trusted == nil {
		return Snapshot{}, ErrInvalid
	}
	snapshot, err := Decode(encoded)
	if err != nil {
		return Snapshot{}, err
	}
	payload, err := SigningPayload(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	signature, err := hex.DecodeString(snapshot.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != snapshot.Signature {
		return Snapshot{}, ErrInvalid
	}
	key, ok := trusted(snapshot.KeyID)
	if !ok || !ed25519.Verify(key, payload, signature) {
		return Snapshot{}, ErrUntrusted
	}
	if snapshot.NodeID != nodeID {
		return Snapshot{}, ErrInvalid
	}
	return snapshot, nil
}

// Assemble joins the verified parts of one revision into the node's state
// (Part = Parts = 1, Signature empty). Parts may come in any order; every
// part of the revision must be present exactly once and agree on the
// header, and sites must be disjoint.
func Assemble(parts []Snapshot) (Snapshot, error) {
	if len(parts) == 0 {
		return Snapshot{}, ErrIncomplete
	}
	ordered := make([]*Snapshot, parts[0].Parts)
	if len(parts) != len(ordered) {
		return Snapshot{}, ErrIncomplete
	}
	first := parts[0]
	for index := range parts {
		part := &parts[index]
		if part.NodeID != first.NodeID || part.Revision != first.Revision || part.Parts != first.Parts ||
			part.IssuedAt != first.IssuedAt || part.AutoMitigation != first.AutoMitigation || part.AttackFragments != first.AttackFragments ||
			part.Part == 0 || part.Part > part.Parts {
			return Snapshot{}, ErrInvalid
		}
		if ordered[part.Part-1] != nil {
			return Snapshot{}, ErrInvalid
		}
		ordered[part.Part-1] = part
	}
	whole := Snapshot{
		Schema: Schema, NodeID: first.NodeID, Revision: first.Revision, Part: 1, Parts: 1, IssuedAt: first.IssuedAt,
		AutoMitigation: first.AutoMitigation, AttackFragments: first.AttackFragments, PlatformAllow: ordered[0].PlatformAllow, PortGroups: ordered[0].PortGroups,
		Prior: ordered[0].Prior, WAFBudget: ordered[0].WAFBudget, Limits: ordered[0].Limits, Algorithm: ordered[0].Algorithm, KeyID: ordered[0].KeyID,
	}
	for _, part := range ordered {
		if len(whole.Sites) > 0 && len(part.Sites) > 0 && whole.Sites[len(whole.Sites)-1].SiteID >= part.Sites[0].SiteID {
			return Snapshot{}, ErrInvalid
		}
		whole.Sites = append(whole.Sites, part.Sites...)
	}
	if !whole.valid() {
		return Snapshot{}, ErrInvalid
	}
	return whole, nil
}

// Split cuts a whole canonical snapshot into the fewest parts whose sealed
// size stays under MaxPartBytes (sites in order; part 1 also carries the
// node-level lists). The parts are unsigned; sign each with Sign.
func Split(whole Snapshot, keyID string) ([]Snapshot, error) {
	whole.Algorithm, whole.KeyID, whole.Signature, whole.Part, whole.Parts = Algorithm, keyID, "", 1, 1
	whole.Canonical()
	if !whole.valid() {
		return nil, ErrInvalid
	}
	// A sealed part is its unsigned JSON plus the signature field; sites add
	// `,"sites":[` + the sites joined by commas + `]`.
	const signatureOverhead = len(`,"signature":""`) + 2*ed25519.SignatureSize
	const sitesOverhead = len(`,"sites":[]`)
	headerSize := func(part Snapshot) int {
		part.Sites = nil
		encoded, _ := json.Marshal(part)
		return len(encoded) + signatureOverhead + sitesOverhead
	}
	first := whole
	rest := whole
	rest.PlatformAllow, rest.PortGroups, rest.Prior, rest.WAFBudget, rest.Limits = nil, nil, nil, nil, nil
	limits := [2]int{headerSize(first), headerSize(rest)}
	var parts []Snapshot
	current, used := first, limits[0]
	current.Sites = nil
	for _, site := range whole.Sites {
		encoded, err := json.Marshal(site)
		if err != nil {
			return nil, ErrInvalid
		}
		add := len(encoded)
		if len(current.Sites) > 0 {
			add++ // comma
		}
		if used+add <= MaxPartBytes {
			current.Sites = append(current.Sites, site)
			used += add
			continue
		}
		if len(current.Sites) == 0 || limits[1]+len(encoded) > MaxPartBytes {
			return nil, ErrInvalid // one site does not fit a part
		}
		parts = append(parts, current)
		current, used = rest, limits[1]+len(encoded)
		current.Sites = []Site{site}
	}
	parts = append(parts, current)
	if len(parts) > MaxParts {
		return nil, ErrInvalid
	}
	for index := range parts {
		parts[index].Part, parts[index].Parts = uint32(index+1), uint32(len(parts))
		if !parts[index].valid() {
			return nil, ErrInvalid
		}
	}
	return parts, nil
}

// Digest is the SHA-256 the carrier and the receipt bind to.
func Digest(encoded []byte) []byte {
	sum := sha256.Sum256(encoded)
	return sum[:]
}

// Route reads node_id and revision from part wire bytes (no signature
// check), for the gateway to bind the carrier.
func Route(encoded []byte) (nodeID string, revision uint64, err error) {
	snapshot, err := Decode(encoded)
	if err != nil {
		return "", 0, err
	}
	return snapshot.NodeID, snapshot.Revision, nil
}
