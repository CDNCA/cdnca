// Package bansync carries a root subscriber's security ban list of one
// market site to the leaf that serves it: the
// subscriber sends the site's whole list, active bans and recent releases,
// as one snapshot (supply.ban_sync); the leaf reconciles its own ban list of
// the leaf site with it, its ban distributor sends that to the nodes, and the
// reply says what the leaf refused and how far its nodes are
// (supply.ban_reply, a siteconf.Reply whose Status is a Status).
//
// A snapshot, not a delta: a lost or replayed message changes nothing, the
// next one converges, and a leaf that lost state (a paused subscription
// resumed) gets it all back. Revision orders snapshots of one site; the leaf
// skips one older than it applied. The leaf decides the refusals: entries
// over its limits, a ban its operator released, a client it cannot ban.
package bansync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	// OpSync is subscriber -> leaf, OpReply leaf -> subscriber. Both are
	// worthless minutes later (the subscriber resends), so the market prunes
	// them like site log queries (relay PruneTransient, market 082).
	OpSync  = "supply.ban_sync"
	OpReply = "supply.ban_reply"

	// MaxBans / MaxReleases bound one snapshot (well under the relay's 4 MiB
	// envelope with the longest reasons). MaxBans is also the leaf's limit of
	// one site's active market bans.
	MaxBans     = 1000
	MaxReleases = 1000
	MaxReason   = 256
	// MaxBanDuration is the ban list's longest ban.
	MaxBanDuration = 30 * 24 * time.Hour
	// ReleaseWindow: releases older than this are not sent (the ban list's
	// own release window).
	ReleaseWindow = 7 * 24 * time.Hour
	maxClient     = 49
)

// Reply error codes (siteconf.Reply.Error) for a snapshot refused as a whole.
const (
	ErrCodeInvalid     = "ban_sync_invalid"
	ErrCodeRateLimited = "ban_sync_rate_limited"
	// ErrCodePaused: the supply is stopped or paused on the leaf; it lifted
	// the subscriber's bans and takes none until it serves again.
	ErrCodePaused = "supply_paused"
	// ErrCodeEnded: the leaf's last grant sync has no active grant of the
	// subscription; its bans were lifted.
	ErrCodeEnded        = "subscription_ended"
	ErrCodeSiteNotFound = "leaf_site_not_found"
	// ErrCodeUnavailable: the leaf has no ban list to write to.
	ErrCodeUnavailable = "ban_list_unavailable"
)

// Refusal codes of one entry (Refusal.Code).
const (
	RefuseSiteLimit = "site_limit"
	// RefuseTenantLimit: the subscription already holds MaxTenantActive bans
	// on the leaf over all its sites.
	RefuseTenantLimit = "tenant_limit"
	// RefuseRateLimited: more new bans in the last minute than the leaf takes;
	// the entry is sent again with the next snapshot.
	RefuseRateLimited = "rate_limited"
	// RefuseReleasedBySupplier: the leaf's operator released this ban; the
	// leaf does not ban the client again for this entry.
	RefuseReleasedBySupplier = "released_by_supplier"
	RefuseInvalidClient      = "invalid_client"
)

// Node delivery states (Nodes.State).
const (
	NodesApplied    = "applied"
	NodesDelivering = "delivering"
	NodesFailed     = "failed"
	// NodesNone: no active node carries the leaf site yet.
	NodesNone = "no_nodes"
	// NodesOff: the leaf does not send ban lists to nodes (no signer or
	// edge bus configured).
	NodesOff = "distribution_off"
)

var ErrInvalid = errors.New("invalid ban snapshot")

// Ban is one active ban of the subscriber's list. Ref is the subscriber's
// own entry id: the leaf keys its copy by it, nothing else identifies it.
type Ban struct {
	Ref    uuid.UUID `json:"ref"`
	Client string    `json:"client"`
	// Until is Unix seconds. Source is the subscriber's (manual, cc, waf,
	// autodefense), shown to the leaf's operator only.
	Until  int64  `json:"until"`
	Source string `json:"source"`
	Reason string `json:"reason,omitempty"`
}

// Release is one entry the subscriber released (within ReleaseWindow).
type Release struct {
	Ref        uuid.UUID `json:"ref"`
	ReleasedAt int64     `json:"released_at"`
}

// Request is the whole ban list of one subscriber site.
type Request struct {
	SiteID     uuid.UUID `json:"site_id"`
	LeafSiteID uuid.UUID `json:"leaf_site_id"`
	// Revision grows with every change of the snapshot (the subscriber uses
	// Unix milliseconds, so it never moves back across rebinds).
	Revision int64     `json:"revision"`
	Bans     []Ban     `json:"bans"`
	Releases []Release `json:"releases"`
}

var sources = map[string]bool{"manual": true, "cc": true, "waf": true, "autodefense": true}

// Normalize checks the shape of r and sorts it by ref, so equal lists give
// equal digests. Clients are checked as text only: the leaf canonicalises
// them with its own ban list rules and refuses a bad one per entry.
func (r *Request) Normalize() error {
	if r.SiteID == uuid.Nil || r.LeafSiteID == uuid.Nil || r.Revision < 1 ||
		len(r.Bans) > MaxBans || len(r.Releases) > MaxReleases {
		return ErrInvalid
	}
	if r.Bans == nil {
		r.Bans = []Ban{}
	}
	if r.Releases == nil {
		r.Releases = []Release{}
	}
	seen := map[uuid.UUID]bool{}
	for i := range r.Bans {
		ban := &r.Bans[i]
		ban.Reason = strings.TrimSpace(ban.Reason)
		if ban.Ref == uuid.Nil || seen[ban.Ref] || ban.Until <= 0 || !sources[ban.Source] ||
			ban.Client == "" || len(ban.Client) > maxClient || strings.IndexFunc(ban.Client, notClientChar) >= 0 ||
			!cleanText(ban.Reason) || utf8.RuneCountInString(ban.Reason) > MaxReason {
			return ErrInvalid
		}
		seen[ban.Ref] = true
	}
	for _, release := range r.Releases {
		if release.Ref == uuid.Nil || seen[release.Ref] || release.ReleasedAt <= 0 {
			return ErrInvalid
		}
		seen[release.Ref] = true
	}
	slices.SortFunc(r.Bans, func(a, b Ban) int { return strings.Compare(a.Ref.String(), b.Ref.String()) })
	slices.SortFunc(r.Releases, func(a, b Release) int { return strings.Compare(a.Ref.String(), b.Ref.String()) })
	return nil
}

// Digest is the content of a normalized snapshot without its revision: the
// subscriber sends a new revision only when it changes.
func (r Request) Digest() string {
	raw, _ := json.Marshal(struct {
		Bans     []Ban     `json:"bans"`
		Releases []Release `json:"releases"`
	}{r.Bans, r.Releases})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Refusal is one entry the leaf did not take.
type Refusal struct {
	Ref  uuid.UUID `json:"ref"`
	Code string    `json:"code"`
}

// Nodes is how far the leaf's nodes serving the site are with the leaf's
// ban list as of this snapshot: Applied of Total answered it, Failed refused
// it (Reason: the first node's error code).
type Nodes struct {
	State   string `json:"state"`
	Total   int    `json:"total"`
	Applied int    `json:"applied"`
	Failed  int    `json:"failed"`
	Reason  string `json:"reason,omitempty"`
}

// Status is the reply's siteconf.Reply.Status: the revision the leaf runs
// for the site (it skipped an older one), what it refused, and its nodes.
type Status struct {
	Revision int64     `json:"revision"`
	Accepted int       `json:"accepted"`
	Refused  []Refusal `json:"refused"`
	Nodes    Nodes     `json:"nodes"`
}

// Unsupported reports a reply error of a leaf that predates this contract
// (its generic "... operation not supported").
func Unsupported(code string) bool {
	return strings.HasSuffix(code, "operation not supported")
}

func notClientChar(c rune) bool {
	return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':' || c == '/')
}

func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
