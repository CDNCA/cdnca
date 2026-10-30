// Package securityban is the control plane of the security ban list library
// (IP list "record IP" and unban; a CC automatic ban can be
// lifted).
//
// security_ban_entries holds one row per (site, client) ban: manual bans an
// operator or the site owner adds, and every node's automatic WAF / CC bans,
// folded in from ClickHouse security_events temporary_ban (Sync). A release
// is the row's released_at. The Distributor gives each node serving a site
// the site's active bans (one node's automatic ban applies on all of them)
// and the releases of the last securityban.ReleaseWindow as a signed per-node
// snapshot (libs/edgeconfig/securityban), and records the node's receipt.
package securityban

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput   = errors.New("invalid security ban input")
	ErrNotFound       = errors.New("security ban not found")
	ErrSiteNotFound   = errors.New("site not found")
	ErrAlreadyBanned  = errors.New("client is already banned on the site")
	ErrNotActive      = errors.New("security ban is not active")
	ErrLimitExceeded  = errors.New("site security ban list is full")
	ErrIdempotencyKey = errors.New("security ban idempotency conflict")
)

const (
	SourceWAF    = "waf"
	SourceCC     = "cc"
	SourceManual = "manual"

	// DefaultBanSeconds is the duration of a synced automatic ban whose policy
	// version says nothing (decision: security_events gets no
	// duration column).
	DefaultBanSeconds = 3600
	// MaxManualSeconds bounds a manual ban (the table allows 30 days).
	MaxManualSeconds = int(contract.MaxBanDuration / time.Second)
	// MaxActivePerSite bounds the active bans of one site (snapshots carry at
	// most contract.MaxEntries entries over all sites of a node).
	MaxActivePerSite = 5000

	AuditCreate  = "security.ban.create"
	AuditRelease = "security.ban.release"
)

var (
	ruleIDPattern      = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,128}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Actor is the authenticated principal (security_policies.read / manage
// checked by the caller). A tenant actor only reaches its own scope's sites;
// a platform actor reaches every site.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

func (actor Actor) valid() bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

// Entry is one ban of the list.
type Entry struct {
	ID            uuid.UUID  `json:"id"`
	TenantScopeID uuid.UUID  `json:"tenant_scope_id"`
	SiteID        uuid.UUID  `json:"site_id"`
	SiteDomain    string     `json:"site_domain"`
	ClientIP      string     `json:"client_ip"`
	Source        string     `json:"source"`
	RuleID        string     `json:"rule_id"`
	Reason        string     `json:"reason"`
	BannedAt      time.Time  `json:"banned_at"`
	BannedUntil   time.Time  `json:"banned_until"`
	CreatedBy     *uuid.UUID `json:"created_by"`
	ReleasedAt    *time.Time `json:"released_at"`
	ReleasedBy    *uuid.UUID `json:"released_by"`
	// State: active (refused on the nodes), released, expired.
	State string `json:"state"`
}

const (
	StateActive   = "active"
	StateReleased = "released"
	StateExpired  = "expired"
)

func entryState(entry Entry, now time.Time) string {
	switch {
	case entry.ReleasedAt != nil:
		return StateReleased
	case !entry.BannedUntil.After(now):
		return StateExpired
	}
	return StateActive
}

// ListFilter selects bans. SiteID nil: every site the actor reaches.
type ListFilter struct {
	SiteID   *uuid.UUID
	ClientIP string
	State    string // "" all, or active | released | expired
	Page     int
	Limit    int
}

type ListResult struct {
	Items []Entry `json:"items"`
	Total int     `json:"total"`
	Page  int     `json:"page"`
	Limit int     `json:"limit"`
}

// CreateRequest is a manual ban.
type CreateRequest struct {
	SiteID         uuid.UUID
	ClientIP       string
	DurationSecond int
	Reason         string
	IdempotencyKey string
	RequestID      string
	SourceIP       string
}

type ReleaseRequest struct {
	EntryID   uuid.UUID
	RequestID string
	SourceIP  string
}

// canonicalClient is the client as the list stores and nodes match it: an
// address (a full-length prefix) or a network.
func canonicalClient(raw string) (netip.Prefix, bool) {
	value, ok := contract.CanonicalClient(strings.TrimSpace(raw))
	if !ok {
		return netip.Prefix{}, false
	}
	return clientPrefix(value)
}

// clientPrefix is the inet value of a canonical client.
func clientPrefix(client string) (netip.Prefix, bool) {
	if contract.IsNetwork(client) {
		prefix, err := netip.ParsePrefix(client)
		return prefix, err == nil
	}
	address, err := netip.ParseAddr(client)
	return netip.PrefixFrom(address, address.BitLen()), err == nil
}

// clientText is the canonical client of an inet value: the bare address of a
// full-length prefix, else the network.
func clientText(prefix netip.Prefix) string {
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func validReason(reason string) bool {
	return len([]rune(reason)) <= 256 && !strings.ContainsAny(reason, "\x00\r\n")
}
