package dnspropagation

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

var ErrInvalidInput = errors.New("invalid dns propagation input")

// ErrAuthoritiesUnavailable means too few authoritative name servers answered
// to judge propagation; the caller must treat the attempt as Unknown.
var ErrAuthoritiesUnavailable = errors.New("dns propagation authorities unavailable")

type ReasonCode string

const (
	ReasonConverged                ReasonCode = "authority_and_public_quorum_agree"
	ReasonAuthorityConflict        ReasonCode = "authority_conflict"
	ReasonPublicQuorumPending      ReasonCode = "public_quorum_pending"
	ReasonResolverIdentityConflict ReasonCode = "resolver_identity_conflict"
	ReasonDNSSECUnverified         ReasonCode = "dnssec_unverified"
	ReasonNXDOMAIN                 ReasonCode = "nxdomain"
	ReasonNODATA                   ReasonCode = "nodata"
	ReasonSERVFAIL                 ReasonCode = "servfail"
	ReasonStale                    ReasonCode = "stale_answer"
)

type DNSSECState string

const (
	DNSSECSecure        DNSSECState = "secure"
	DNSSECInsecure      DNSSECState = "insecure"
	DNSSECBogus         DNSSECState = "bogus"
	DNSSECIndeterminate DNSSECState = "indeterminate"
)

type ResponseStatus string

const (
	ResponseAnswer   ResponseStatus = "answer"
	ResponseNXDOMAIN ResponseStatus = "nxdomain"
	ResponseNODATA   ResponseStatus = "nodata"
	ResponseSERVFAIL ResponseStatus = "servfail"
)

type ResolverRole string

const (
	RoleAuthoritative   ResolverRole = "authoritative"
	RolePublicRecursive ResolverRole = "public_recursive"
)

type LKGAction string

const (
	LKGPreserve LKGAction = "preserve"
	LKGPromote  LKGAction = "promote"
)

type CompensationAction string

const CompensationNone CompensationAction = "none"

type Resolver struct {
	ID   string
	Name string
}

type Delegation struct {
	Zone        string
	Signed      bool
	Authorities []Resolver
}

type RRSet struct {
	Type   dnscheck.RecordType
	Values []string
}

type Observation struct {
	OperationID string
	Role        ResolverRole
	ResolverID  string
	Status      ResponseStatus
	DNSSEC      DNSSECState
	Records     []RRSet
	CNAMEChain  []string
	TTL         time.Duration
	NegativeTTL time.Duration
	ObservedAt  time.Time
	Stale       bool
}

type Source interface {
	Discover(context.Context, string, string) (Delegation, error)
	Observe(context.Context, string, Resolver, string, []dnscheck.RecordType) (Observation, error)
}

type Metric struct {
	Reason             ReasonCode
	Success            bool
	AuthoritativeVotes int
	PublicVotes        int
}

type Metrics interface {
	Record(Metric)
}

type Config struct {
	Source         Source
	Public         []Resolver
	PublicQuorum   int
	MinTTL         time.Duration
	MaxTTL         time.Duration
	MinNegativeTTL time.Duration
	MaxNegativeTTL time.Duration
	MaxAge         time.Duration
	Now            func() time.Time
	Metrics        Metrics
	// EndpointTimeout bounds one resolver endpoint's Observe; zero means
	// defaultEndpointTimeout.
	EndpointTimeout time.Duration
	// Logger receives one line per check that skipped endpoints; nil means slog.Default().
	Logger *slog.Logger
}

// SkippedEndpoint is a resolver endpoint left out of a check because it was
// unreachable, refused the connection or timed out.
type SkippedEndpoint struct {
	Role       ResolverRole
	ResolverID string
	Name       string
	Reason     string
}

type Request struct {
	TenantID    uuid.UUID
	ZoneID      uuid.UUID
	OperationID string
	Zone        string
	Name        string
	Expected    []RRSet
}

type Result struct {
	TenantID           uuid.UUID
	ZoneID             uuid.UUID
	OperationID        string
	Reason             ReasonCode
	Success            bool
	AuthoritativeVotes int
	PublicVotes        int
	RequiredPublic     int
	LKG                LKGAction
	Compensation       CompensationAction
	Observations       []Observation
	Skipped            []SkippedEndpoint
}
