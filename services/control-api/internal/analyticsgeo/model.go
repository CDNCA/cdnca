package analyticsgeo

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
)

const (
	maximumCatalogDocuments = 16
	maximumCatalogBytes     = 8 << 20
	maximumCatalogEntries   = 100_000
)

var (
	ErrInvalidConfiguration = errors.New("invalid analytics geo configuration")
	ErrInvalidInput         = errors.New("invalid analytics geo input")
	ErrPermissionDenied     = errors.New("analytics geo permission denied")
	ErrScopeForbidden       = errors.New("analytics geo scope forbidden")
	ErrEvidenceUnavailable  = errors.New("analytics geo evidence unavailable")
	ErrInvalidResponse      = errors.New("invalid analytics geo response")
	ErrCapacityExceeded     = errors.New("analytics geo capacity exceeded")
	ErrNotFound             = errors.New("analytics geo event not found")
	ErrVersionNotFound      = errors.New("analytics geo database version not found")
)

type Actor = analyticslog.Actor
type Audience = analyticslog.Audience

const (
	AudiencePlatform = analyticslog.AudiencePlatform
	AudienceTenant   = analyticslog.AudienceTenant
)

type Kind string

const (
	KindAccess Kind = "access"
	KindBlock  Kind = "block"
)

type QueryRequest struct {
	Audience        Audience
	TenantID        string
	Kind            Kind
	EventID         string
	From            time.Time
	To              time.Time
	SiteID          string
	NodeID          string
	ClientIP        string
	DatabaseVersion string
}

type SourceEvent struct {
	EventID     string
	OccurredAt  time.Time
	SiteID      string
	NodeID      string
	ClientIP    string
	CountryCode string
	Carrier     string
}

type SourcePage struct {
	Items      []SourceEvent
	NextCursor string
}

type EventSource interface {
	ReadEvents(context.Context, Actor, QueryRequest) (SourcePage, error)
}

type Resolution = string

const (
	ResolutionMatched Resolution = "matched"
	ResolutionUnknown Resolution = "unknown"
)

type LookupReason = string

const (
	LookupReasonPrefixMatch   LookupReason = "prefix_match"
	LookupReasonNoPrefixMatch LookupReason = "no_prefix_match"
)

type Reconciliation = string

const (
	ReconciliationMatch      Reconciliation = "match"
	ReconciliationMismatch   Reconciliation = "mismatch"
	ReconciliationUnverified Reconciliation = "unverified"
)

type Attribution struct {
	CountryCode   string
	Region        string
	City          string
	Carrier       string
	ASN           uint32
	AddressFamily string
	LookupReason  LookupReason
	Resolution    Resolution
	PrefixLength  int
}

type Provenance struct {
	Version     string
	Provider    string
	SHA256      string
	PublishedAt time.Time
	EffectiveAt time.Time
}

type Item struct {
	EventID           string         `json:"event_id"`
	OccurredAt        time.Time      `json:"occurred_at"`
	SiteID            string         `json:"site_id"`
	NodeID            string         `json:"node_id"`
	ClientIP          string         `json:"-"`
	SourceCountryCode string         `json:"source_country_code"`
	SourceCarrier     string         `json:"source_carrier"`
	CountryCode       string         `json:"country_code"`
	Region            string         `json:"region"`
	City              string         `json:"city"`
	Carrier           string         `json:"carrier"`
	ASN               uint32         `json:"asn"`
	AddressFamily     string         `json:"address_family"`
	LookupReason      LookupReason   `json:"lookup_reason"`
	Resolution        Resolution     `json:"resolution"`
	Reconciliation    Reconciliation `json:"reconciliation"`
	PrefixLength      int            `json:"prefix_length"`
	Provenance        Provenance     `json:"-"`
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validIdentity(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validEventID(value string) bool {
	if !validIdentity(value, 128) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func parseCanonicalAddress(value string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(value)
	return address, err == nil && address.Zone() == "" && address.String() == value
}
