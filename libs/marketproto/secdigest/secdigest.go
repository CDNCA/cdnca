// Package secdigest is the leaf controller's signed security digest of one
// subscriber site for one 5-minute window (ADR 0012 §19.1): attack summary,
// mitigations and attack log lines, plus the node's latest automatic defence
// adjustments (§19.2 item 5). The leaf seals it in a relay envelope to the
// grant's root subscriber (operation supply.secdigest), so neither the market
// nor resellers on the path can read it; the inner member signature keeps it
// attributable after the envelope is opened.
package secdigest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	SchemaV1      = "cdnca.market.secdigest/v1"
	Domain        = SchemaV1 + "\n"
	Operation     = "supply.secdigest" // relay op, leaf -> subscriber
	WindowSeconds = 300

	MaxActions     = 64
	MaxLogs        = 200
	MaxAdjustments = 64
	MaxPayload     = 256 << 10

	maxLevel  = 5
	maxText   = 512
	maxSlug   = 64
	maxHost   = 253
	maxPath   = 2048
	maxTarget = 128
)

var (
	ErrSignature = errors.New("security digest signature rejected")
	ErrInvalid   = errors.New("invalid security digest")

	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]*$`)
	fieldPattern = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z0-9_]+(:[a-z0-9][a-z0-9._-]*)?$`)
)

// Summary aggregates the window (analyticslog attack summary of the site).
type Summary struct {
	Events      int64  `json:"events"`
	Blocked     int64  `json:"blocked"`
	Challenged  int64  `json:"challenged"`
	Banned      int64  `json:"banned"`
	Clients     int64  `json:"clients"`
	TopDetector string `json:"top_detector"`
	TopClientIP string `json:"top_client_ip"`
	FirstMS     int64  `json:"first_ms"`
	LastMS      int64  `json:"last_ms"`
}

// Action is one mitigation applied to the site in the window.
type Action struct {
	At     int64  `json:"at"`     // unix seconds
	Source string `json:"source"` // autodefense, waf, cc
	Level  int    `json:"level"`  // autodefense contract §3.5, 0..5
	Kind   string `json:"kind"`   // ip, cidr, ja4, site
	Target string `json:"target"`
	Until  int64  `json:"until"` // 0 = no expiry recorded
	Reason string `json:"reason"`
}

// Log is one attack log line. No request body, cookie or header values.
type Log struct {
	AtMS     int64  `json:"at_ms"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Detector string `json:"detector"`
	RuleID   string `json:"rule_id"`
}

// Adjustment is the node's latest automatic overlay value of a site field
// (autodefense contract §5 kind adjust), for read-only display.
type Adjustment struct {
	Module string `json:"module"`
	Field  string `json:"field"`
	Value  int64  `json:"value"`
	At     int64  `json:"at"`
}

type Dropped struct {
	Actions int64 `json:"actions"`
	Logs    int64 `json:"logs"`
}

type Digest struct {
	Schema        string       `json:"schema"`
	LeafMemberID  uuid.UUID    `json:"leaf_member_id"`
	GrantID       uuid.UUID    `json:"grant_id"`
	LeafSiteID    uuid.UUID    `json:"leaf_site_id"`
	WindowStart   int64        `json:"window_start"` // unix seconds, multiple of 300
	WindowSeconds int64        `json:"window_seconds"`
	Summary       Summary      `json:"summary"`
	Actions       []Action     `json:"actions"`
	Logs          []Log        `json:"logs"`
	Adjustments   []Adjustment `json:"adjustments,omitempty"`
	Dropped       Dropped      `json:"dropped"`
}

// Truncate keeps the newest MaxActions actions and MaxLogs logs (sorted
// newest first) and adds the rest to Dropped.
func (d *Digest) Truncate() {
	slices.SortStableFunc(d.Actions, func(a, b Action) int { return compareDesc(a.At, b.At) })
	slices.SortStableFunc(d.Logs, func(a, b Log) int { return compareDesc(a.AtMS, b.AtMS) })
	if n := len(d.Actions) - MaxActions; n > 0 {
		d.Actions, d.Dropped.Actions = d.Actions[:MaxActions], d.Dropped.Actions+int64(n)
	}
	if n := len(d.Logs) - MaxLogs; n > 0 {
		d.Logs, d.Dropped.Logs = d.Logs[:MaxLogs], d.Dropped.Logs+int64(n)
	}
}

func compareDesc(a, b int64) int {
	switch {
	case a > b:
		return -1
	case a < b:
		return 1
	}
	return 0
}

// Empty reports a window without events; the leaf does not send it.
func (d Digest) Empty() bool {
	return d.Summary.Events == 0 && len(d.Actions) == 0 && len(d.Logs) == 0 &&
		d.Dropped.Actions == 0 && d.Dropped.Logs == 0
}

func (d Digest) Validate() error {
	if d.Schema != SchemaV1 || d.LeafMemberID == uuid.Nil || d.GrantID == uuid.Nil || d.LeafSiteID == uuid.Nil ||
		d.WindowStart <= 0 || d.WindowStart%WindowSeconds != 0 || d.WindowSeconds != WindowSeconds || d.Empty() ||
		len(d.Actions) > MaxActions || len(d.Logs) > MaxLogs || len(d.Adjustments) > MaxAdjustments ||
		d.Dropped.Actions < 0 || d.Dropped.Logs < 0 {
		return ErrInvalid
	}
	end := d.WindowStart + WindowSeconds
	s := d.Summary
	if s.Events < 0 || s.Blocked < 0 || s.Challenged < 0 || s.Banned < 0 || s.Clients < 0 ||
		!optionalSlug(s.TopDetector) || !optionalIP(s.TopClientIP) ||
		s.FirstMS < 0 || s.LastMS < s.FirstMS || (s.LastMS > 0 && !inWindowMS(s.FirstMS, d.WindowStart, end)) ||
		(s.LastMS > 0 && !inWindowMS(s.LastMS, d.WindowStart, end)) {
		return ErrInvalid
	}
	for _, a := range d.Actions {
		if a.At < d.WindowStart || a.At >= end ||
			!slices.Contains([]string{"autodefense", "waf", "cc"}, a.Source) || a.Level < 0 || a.Level > maxLevel ||
			!validTarget(a.Kind, a.Target) || (a.Until != 0 && a.Until < a.At) || !line(a.Reason, maxText) {
			return ErrInvalid
		}
	}
	for _, l := range d.Logs {
		if !inWindowMS(l.AtMS, d.WindowStart, end) || !validIP(l.ClientIP) ||
			l.Host == "" || len(l.Host) > maxHost || !line(l.Host, maxHost) ||
			!strings.HasPrefix(l.Path, "/") || !line(l.Path, maxPath) ||
			l.Action == "" || !optionalSlug(l.Action) || !optionalSlug(l.Detector) || !optionalSlug(l.RuleID) {
			return ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(d.Adjustments))
	for _, a := range d.Adjustments {
		if !slices.Contains(spec.AutoDefenseModules, a.Module) || len(a.Field) > maxSlug ||
			!fieldPattern.MatchString(a.Field) || !strings.HasPrefix(a.Field, a.Module+".") ||
			a.At <= 0 || a.At >= end {
			return ErrInvalid
		}
		if _, dup := seen[a.Field]; dup {
			return ErrInvalid
		}
		seen[a.Field] = struct{}{}
	}
	return nil
}

func inWindowMS(ms, start, end int64) bool { return ms >= start*1000 && ms < end*1000 }

func validIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.String() == s
}

func optionalIP(s string) bool { return s == "" || validIP(s) }

func optionalSlug(s string) bool { return s == "" || (len(s) <= maxSlug && slugPattern.MatchString(s)) }

func validTarget(kind, target string) bool {
	switch kind {
	case "ip":
		return validIP(target)
	case "cidr":
		p, err := netip.ParsePrefix(target)
		return err == nil && p.Masked().String() == target
	case "ja4":
		return target != "" && len(target) <= maxTarget && slugPattern.MatchString(strings.ToLower(target))
	case "site":
		return target == "*"
	}
	return false
}

// line is printable single-line UTF-8 of at most n bytes.
func line(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

var keyPattern = regexp.MustCompile(`^secdigest-([1-9][0-9]{0,18})-[0-9a-f]{16}$`)

// IdempotencyKey is the relay idempotency key of one site's digest for one
// window: a resend of the window reuses the relay row. The window is in the
// clear so the market can count it without opening the envelope; the site
// is only a hash, so the market learns no leaf site identity from it.
func IdempotencyKey(leafSite uuid.UUID, windowStart int64) string {
	sum := sha256.Sum256(append([]byte(SchemaV1+"\n"), leafSite[:]...))
	return "secdigest-" + strconv.FormatInt(windowStart, 10) + "-" + hex.EncodeToString(sum[:8])
}

// WindowOfKey returns the window start of an IdempotencyKey.
func WindowOfKey(key string) (int64, bool) {
	m := keyPattern.FindStringSubmatch(key)
	if m == nil {
		return 0, false
	}
	w, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || w%WindowSeconds != 0 {
		return 0, false
	}
	return w, true
}

type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(d Digest, key ed25519.PrivateKey) (Signed, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	if err := d.Validate(); err != nil {
		return Signed{}, err
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return Signed{}, err
	}
	if len(payload) > MaxPayload {
		return Signed{}, ErrInvalid
	}
	return Signed{Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), payload...)))}, nil
}

// Verify checks the digest against the leaf's member signing key and returns
// it with the exact signed bytes. Unknown fields are rejected.
func Verify(public ed25519.PublicKey, s Signed) (Digest, []byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return Digest{}, nil, ErrSignature
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil || len(payload) > MaxPayload {
		return Digest{}, nil, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(Domain), payload...), signature) {
		return Digest{}, nil, ErrSignature
	}
	var d Digest
	if err := spec.DecodeStrict(payload, &d); err != nil {
		return Digest{}, nil, ErrInvalid
	}
	if err := d.Validate(); err != nil {
		return Digest{}, nil, err
	}
	return d, payload, nil
}
