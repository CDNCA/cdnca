// Package securityban is the node security ban list shared
// by control-api (builds and signs a node's snapshot), agent-gateway (routes
// the carrier, never verifies) and edge-agent (verifies, applies, answers).
//
// A snapshot (cdnca.security-ban-list/v1) is everything one node should hold:
// the active bans of the sites it serves (the ban list library's manual bans
// and every node's automatic WAF / CC bans, so one node's ban applies on all
// of them) and the releases of the last 7 days (a release lifts the nodes'
// own automatic bans of the client that started before it). Revision grows
// per node with every change; a node applies a snapshot only when it is
// newer than the one it holds. The control plane signs
// Domain + the canonical snapshot without its signature (Ed25519, the edge
// publication key the node trusts as artifact trust).
package securityban

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	Schema = "cdnca.security-ban-list/v1"
	Domain = Schema + "\n"
	// Algorithm is the only signature algorithm.
	Algorithm = "ed25519"
	// MaxListBytes bounds the wire size of one snapshot: under the 1 MiB
	// gRPC message limit of agent-gateway and edge-agent with room for the
	// SecurityBanCommand / ConnectResponse envelope (esc-gw 10-23: a 4 MiB
	// list was refused by gRPC and closed the session on every reconnect).
	MaxListBytes = 960 << 10
	// MaxEntryBytes is the longest encoding of one ban (or release) with its
	// separator (UUID, 39-character IPv6 client with a "/127" network suffix,
	// 19-digit time, longest source); MaxEnvelopeBytes the longest encoding
	// of everything else.
	MaxEntryBytes    = 157
	MaxEnvelopeBytes = 640
	// MaxEntries bounds bans + releases: any such list fits MaxListBytes.
	MaxEntries = (MaxListBytes - MaxEnvelopeBytes) / MaxEntryBytes
	// ReleaseWindow: releases older than this are not sent (the longest
	// automatic ban is 7 days, so no ban they lift is still running).
	ReleaseWindow = 7 * 24 * time.Hour
	// MaxBanDuration bounds one ban.
	MaxBanDuration = 30 * 24 * time.Hour
)

// Receipt error codes (SecurityBanStatus.error_code).
const (
	ErrorUntrusted    = "untrusted_signature"
	ErrorInvalid      = "invalid_list"
	ErrorWrongNode    = "wrong_node"
	ErrorStale        = "stale_revision"
	ErrorRuntime      = "runtime_unavailable"
	ErrorNotSupported = "not_supported"
)

var (
	ErrInvalid   = errors.New("security ban list is invalid")
	ErrUntrusted = errors.New("security ban list signature is not trusted")
)

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// Ban is one active ban: the client is refused on the site until Until.
type Ban struct {
	SiteID string `json:"site_id"`
	Client string `json:"client"`
	Until  int64  `json:"until"` // Unix seconds
	// Source: waf | cc | manual | autodefense (shown in node logs only;
	// autodefense: an automatic defense L3/L4 shared across the site's nodes,
	// ADR 0010 section 8.2).
	Source string `json:"source"`
}

// Release lifts the node's own automatic bans of Client on SiteID that
// started at or before ReleasedAt.
type Release struct {
	SiteID     string `json:"site_id"`
	Client     string `json:"client"`
	ReleasedAt int64  `json:"released_at"` // Unix seconds
}

// List is the signed snapshot of one node.
type List struct {
	Schema    string    `json:"schema"`
	NodeID    string    `json:"node_id"`
	Revision  uint64    `json:"revision"`
	IssuedAt  int64     `json:"issued_at"`
	Bans      []Ban     `json:"bans"`
	Releases  []Release `json:"releases"`
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature,omitempty"`
}

// Canonical sorts the entries (site, client) so equal content is equal bytes.
func (list *List) Canonical() {
	sort.Slice(list.Bans, func(i, j int) bool {
		if list.Bans[i].SiteID != list.Bans[j].SiteID {
			return list.Bans[i].SiteID < list.Bans[j].SiteID
		}
		return list.Bans[i].Client < list.Bans[j].Client
	})
	sort.Slice(list.Releases, func(i, j int) bool {
		if list.Releases[i].SiteID != list.Releases[j].SiteID {
			return list.Releases[i].SiteID < list.Releases[j].SiteID
		}
		return list.Releases[i].Client < list.Releases[j].Client
	})
}

// CanonicalClient is the client as lists carry it: an address (IPv4 dotted,
// IPv6 compressed lower case, no zone, IPv4-mapped unmapped) or, since
// BAN_CIDR, a network "<masked address>/<bits>" of IPv4 /8../31
// or IPv6 /32../127; a full-length prefix is the bare address. A network
// overlapping loopback, unspecified, multicast or link-local is refused (the
// kernel firewall refuses those too).
func CanonicalClient(raw string) (string, bool) {
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return "", false
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			return CanonicalClient(prefix.Addr().String())
		}
		minimum := MinIPv4Bits
		if prefix.Addr().Is6() {
			minimum = MinIPv6Bits
		}
		if prefix.Bits() < minimum {
			return "", false
		}
		prefix = prefix.Masked()
		for _, reserved := range reservedNetworks {
			if prefix.Overlaps(reserved) {
				return "", false
			}
		}
		return prefix.String(), true
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() {
		return "", false
	}
	return address.Unmap().String(), true
}

// The widest networks a ban may cover.
const (
	MinIPv4Bits = 8
	MinIPv6Bits = 32
	// CIDRAPIVersion is CAPABILITY_NAME_BAN_CIDR v1: the node matches network
	// bans and releases.
	CIDRAPIVersion uint32 = 1
)

var reservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("fe80::/10"),
}

// IsNetwork reports a canonical client that is a network, not an address.
func IsNetwork(client string) bool { return strings.Contains(client, "/") }

// HasNetworks reports a list with a network ban or release (only nodes
// declaring BAN_CIDR accept it).
func (list List) HasNetworks() bool {
	for _, ban := range list.Bans {
		if IsNetwork(ban.Client) {
			return true
		}
	}
	for _, release := range list.Releases {
		if IsNetwork(release.Client) {
			return true
		}
	}
	return false
}

func (list List) validate() error {
	if list.Schema != Schema || !uuidPattern.MatchString(list.NodeID) || list.Revision == 0 || list.IssuedAt <= 0 ||
		list.Bans == nil || list.Releases == nil || len(list.Bans)+len(list.Releases) > MaxEntries ||
		list.Algorithm != Algorithm || !keyIDPattern.MatchString(list.KeyID) {
		return ErrInvalid
	}
	seen := map[[2]string]bool{}
	for index, ban := range list.Bans {
		client, ok := CanonicalClient(ban.Client)
		if !ok || client != ban.Client || !uuidPattern.MatchString(ban.SiteID) || ban.Until <= 0 ||
			!validSource(ban.Source) || seen[[2]string{ban.SiteID, ban.Client}] {
			return ErrInvalid
		}
		if index > 0 && (list.Bans[index-1].SiteID > ban.SiteID ||
			list.Bans[index-1].SiteID == ban.SiteID && list.Bans[index-1].Client > ban.Client) {
			return ErrInvalid
		}
		seen[[2]string{ban.SiteID, ban.Client}] = true
	}
	released := map[[2]string]bool{}
	for index, release := range list.Releases {
		client, ok := CanonicalClient(release.Client)
		if !ok || client != release.Client || !uuidPattern.MatchString(release.SiteID) || release.ReleasedAt <= 0 ||
			released[[2]string{release.SiteID, release.Client}] {
			return ErrInvalid
		}
		if index > 0 && (list.Releases[index-1].SiteID > release.SiteID ||
			list.Releases[index-1].SiteID == release.SiteID && list.Releases[index-1].Client > release.Client) {
			return ErrInvalid
		}
		released[[2]string{release.SiteID, release.Client}] = true
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
		return List{}, ErrInvalid
	}
	return list, nil
}

// Digest is the SHA-256 the carrier and the receipt bind to.
func Digest(encoded []byte) []byte {
	sum := sha256.Sum256(encoded)
	return sum[:]
}

// RuntimeSnapshot is what the Agent posts to the node runtime
// (cdnca_banlist.apply): bans still running at now and the releases.
type RuntimeSnapshot struct {
	Revision uint64           `json:"revision"`
	Bans     []RuntimeBan     `json:"bans"`
	Releases []RuntimeRelease `json:"releases"`
}

type RuntimeBan struct {
	SiteID string `json:"site_id"`
	Client string `json:"client"`
	Until  int64  `json:"until"`
}

type RuntimeRelease struct {
	SiteID     string `json:"site_id"`
	Client     string `json:"client"`
	ReleasedAt int64  `json:"released_at"`
}

// Runtime is the list's runtime snapshot at now (expired bans dropped).
func (list List) Runtime(now time.Time) RuntimeSnapshot {
	snapshot := RuntimeSnapshot{Revision: list.Revision, Bans: []RuntimeBan{}, Releases: []RuntimeRelease{}}
	for _, ban := range list.Bans {
		if ban.Until > now.Unix() {
			snapshot.Bans = append(snapshot.Bans, RuntimeBan{SiteID: ban.SiteID, Client: ban.Client, Until: ban.Until})
		}
	}
	for _, release := range list.Releases {
		snapshot.Releases = append(snapshot.Releases, RuntimeRelease(release))
	}
	return snapshot
}

// JetStream names: agent-gateway owns the streams; control-api publishes
// snapshots and consumes receipts. Subjects end with the node ID. Commands
// keep only the newest snapshot per node (a snapshot carries everything).
const (
	CommandStream         = "SECURITY_BAN_COMMANDS"
	StatusStream          = "SECURITY_BAN_STATUS"
	CommandSubjectPrefix  = "cdnca.agent.security-ban.commands"
	StatusSubjectPrefix   = "cdnca.agent.security-ban.status"
	GatewayConsumerPrefix = "security_ban"
	ReceiptConsumer       = "control_api_security_ban_receipts"
	// MaxCarrierBytes bounds one SecurityBanCommand / SecurityBanStatus.
	MaxCarrierBytes = MaxListBytes + 4<<10
)

// Route reads node_id and revision from snapshot wire bytes (no signature
// check), for the gateway to bind the carrier.
func Route(encoded []byte) (nodeID string, revision uint64, err error) {
	list, err := Decode(encoded)
	if err != nil {
		return "", 0, err
	}
	return list.NodeID, list.Revision, nil
}

func validSource(source string) bool {
	return source == "waf" || source == "cc" || source == "manual" || source == "autodefense"
}
