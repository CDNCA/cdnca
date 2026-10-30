// Package sitedrop is the node site drop list (攻击自动升级 D 级, esc-node)
// shared by control-api (builds and signs a node's snapshot), agent-gateway
// (routes the carrier, never verifies) and edge-agent (verifies, applies,
// answers).
//
// A snapshot (cdnca.site-drop/v1) names every site the node must stop
// serving because it is in level D (DNS points at a black hole; this is the
// residual traffic). The node derives what to drop from the sites it runs:
//   - the ports only D level sites use (no other site, no L4 forward): every
//     packet to them is dropped (XDP, else nftables);
//   - on shared TLS ports, ClientHellos whose SNI is a D level site's name
//     (XDP only: a node without XDP reports sni_unavailable);
//   - in OpenResty, any request or TLS handshake whose Host / SNI selects a
//     D level site is closed without a response (444), which covers plain
//     HTTP on shared ports and QUIC.
//
// Revision grows per node; a node applies a snapshot only when it is not
// older than the one it holds; an empty site list lifts every drop. Each
// site carries Until (at most MaxDuration after IssuedAt): the node lifts it
// by itself then, whatever the control plane does. The control plane signs
// Domain + the canonical snapshot without its signature (Ed25519, the edge
// publication key the node trusts, as securityban).
package sitedrop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
)

const (
	Schema = "cdnca.site-drop/v1"
	Domain = Schema + "\n"
	// Algorithm is the only signature algorithm.
	Algorithm = "ed25519"
	// MaxListBytes bounds the wire size of one snapshot: under the 1 MiB
	// gRPC message limit of agent-gateway and edge-agent with room for the
	// SiteDropCommand / ConnectResponse envelope.
	MaxListBytes = 960 << 10
	// MaxSiteBytes is the longest encoding of one site with its separator
	// (two UUIDs, two 19-digit times); MaxEnvelopeBytes the longest encoding
	// of everything else (128-byte key ID, 20-digit revision, signature).
	MaxSiteBytes     = 158
	MaxEnvelopeBytes = 640
	// MaxSites: any list of at most MaxSites sites fits MaxListBytes.
	MaxSites = (MaxListBytes - MaxEnvelopeBytes) / MaxSiteBytes
	// MaxDuration bounds Until - IssuedAt (最长 7 天).
	MaxDuration = 7 * 24 * time.Hour
)

// Receipt error codes (SiteDropReceipt.error_code) and rejection reasons
// (SiteDropRejection.reason).
const (
	ErrorUntrusted    = "untrusted_signature"
	ErrorInvalid      = "invalid_list"
	ErrorWrongNode    = "wrong_node"
	ErrorStale        = "stale_revision"
	ErrorRuntime      = "runtime_unavailable"
	ErrorNotSupported = "not_supported"

	// RejectSNIUnavailable: the site shares a TLS port with other sites and
	// the node has no XDP, so that port is not dropped for it (OpenResty
	// still closes its handshakes and requests).
	RejectSNIUnavailable = "sni_unavailable"
	// RejectNotServed: the node does not run the site (nothing to drop).
	RejectNotServed = "not_served"
)

var (
	ErrInvalid   = errors.New("site drop list is invalid")
	ErrUntrusted = errors.New("site drop list signature is not trusted")
)

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// Site is one level D site: dropped from Since until Until (Unix seconds).
type Site struct {
	SiteID   string `json:"site_id"`
	TenantID string `json:"tenant_id"`
	Since    int64  `json:"since"`
	Until    int64  `json:"until"`
}

// List is the signed snapshot of one node.
type List struct {
	Schema    string `json:"schema"`
	NodeID    string `json:"node_id"`
	Revision  uint64 `json:"revision"`
	IssuedAt  int64  `json:"issued_at"`
	Sites     []Site `json:"sites"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature,omitempty"`
}

// Canonical sorts the sites by ID so equal content is equal bytes.
func (list *List) Canonical() {
	sort.Slice(list.Sites, func(i, j int) bool { return list.Sites[i].SiteID < list.Sites[j].SiteID })
}

func (list List) validate() error {
	if list.Schema != Schema || !uuidPattern.MatchString(list.NodeID) || list.Revision == 0 || list.IssuedAt <= 0 ||
		list.Sites == nil || len(list.Sites) > MaxSites || list.Algorithm != Algorithm || !keyIDPattern.MatchString(list.KeyID) {
		return ErrInvalid
	}
	limit := list.IssuedAt + int64(MaxDuration/time.Second)
	for index, site := range list.Sites {
		if !uuidPattern.MatchString(site.SiteID) || !uuidPattern.MatchString(site.TenantID) || site.Since <= 0 ||
			site.Since > list.IssuedAt || site.Until <= list.IssuedAt || site.Until > limit {
			return ErrInvalid
		}
		if index > 0 && list.Sites[index-1].SiteID >= site.SiteID {
			return ErrInvalid // unsorted or duplicate
		}
	}
	return nil
}

// SigningPayload is what the control plane signs.
func SigningPayload(list List) ([]byte, error) {
	list.Signature = ""
	if err := list.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte(Domain), encoded...), nil
}

// Seal attaches the signature and returns the wire bytes.
func Seal(list List, signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	list.Signature = hex.EncodeToString(signature)
	if err := list.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(list)
	if err != nil || len(encoded) > MaxListBytes {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Sign canonicalizes, signs with key and seals (control plane and tests;
// production signs through the edge publish signer with SigningPayload +
// Seal).
func Sign(list List, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	list.Schema, list.Algorithm, list.KeyID, list.Signature = Schema, Algorithm, keyID, ""
	if list.Sites == nil {
		list.Sites = []Site{}
	}
	list.Canonical()
	payload, err := SigningPayload(list)
	if err != nil {
		return nil, err
	}
	return Seal(list, ed25519.Sign(key, payload))
}

// Decode strictly decodes canonical wire bytes (no signature check: the
// gateway routes with it).
func Decode(encoded []byte) (List, error) {
	if len(encoded) == 0 || len(encoded) > MaxListBytes {
		return List{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var list List
	if err := decoder.Decode(&list); err != nil {
		return List{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return List{}, ErrInvalid
	}
	canonical, err := json.Marshal(list)
	if err != nil || !bytes.Equal(canonical, encoded) || list.validate() != nil || list.Signature == "" {
		return List{}, ErrInvalid
	}
	return list, nil
}

// TrustedKeyFunc resolves a control plane key the node trusts.
type TrustedKeyFunc func(keyID string) (ed25519.PublicKey, bool)

// ErrWrongNode: a valid, trusted snapshot for another node.
var ErrWrongNode = errors.New("site drop list is for another node")

// Open verifies a snapshot for nodeID.
func Open(encoded []byte, nodeID string, trusted TrustedKeyFunc) (List, error) {
	if trusted == nil {
		return List{}, ErrInvalid
	}
	list, err := Decode(encoded)
	if err != nil {
		return List{}, err
	}
	payload, err := SigningPayload(list)
	if err != nil {
		return List{}, err
	}
	signature, err := hex.DecodeString(list.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != list.Signature {
		return List{}, ErrInvalid
	}
	key, ok := trusted(list.KeyID)
	if !ok || !ed25519.Verify(key, payload, signature) {
		return List{}, ErrUntrusted
	}
	if list.NodeID != nodeID {
		return List{}, ErrWrongNode
	}
	return list, nil
}

// Digest is the SHA-256 the carrier and the receipt bind to.
func Digest(encoded []byte) []byte {
	sum := sha256.Sum256(encoded)
	return sum[:]
}

// Active are the sites still dropped at now, by ID.
func (list List) Active(now time.Time) map[string]time.Time {
	active := map[string]time.Time{}
	for _, site := range list.Sites {
		if site.Until > now.Unix() {
			active[site.SiteID] = time.Unix(site.Until, 0)
		}
	}
	return active
}

// Route reads node_id and revision from snapshot wire bytes (no signature
// check), for the gateway to bind the carrier.
func Route(encoded []byte) (nodeID string, revision uint64, err error) {
	list, err := Decode(encoded)
	if err != nil {
		return "", 0, err
	}
	return list.NodeID, list.Revision, nil
}

// JetStream names (as securityban): agent-gateway owns the streams;
// control-api publishes snapshots and consumes receipts. Subjects end with
// the node ID; commands keep only the newest snapshot per node.
const (
	CommandStream         = "SITE_DROP_COMMANDS"
	ReceiptStream         = "SITE_DROP_RECEIPTS"
	CommandSubjectPrefix  = "cdnca.agent.site-drop.commands"
	ReceiptSubjectPrefix  = "cdnca.agent.site-drop.receipts"
	GatewayConsumerPrefix = "site_drop"
	ReceiptConsumer       = "control_api_site_drop_receipts"
	// MaxCarrierBytes bounds one SiteDropCommand / SiteDropReceipt.
	MaxCarrierBytes = MaxListBytes + 4<<10
)
