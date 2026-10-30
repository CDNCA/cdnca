package dnscheck

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput          = errors.New("invalid dns check input")
	ErrEndpointDenied        = errors.New("dns resolver endpoint denied")
	ErrMalformedResponse     = errors.New("malformed dns response")
	ErrResponseTooLarge      = errors.New("dns response too large")
	ErrResolverNameAbsent    = errors.New("authoritative resolver is not configured")
	ErrDependencyUnavailable = errors.New("dns resolver dependency unavailable")
)

type RecordType uint16

const (
	RecordA     RecordType = 1
	RecordCNAME RecordType = 5
	RecordSOA   RecordType = 6
	RecordAAAA  RecordType = 28
	RecordTXT   RecordType = 16
)

func (t RecordType) String() string {
	switch t {
	case RecordA:
		return "A"
	case RecordAAAA:
		return "AAAA"
	case RecordCNAME:
		return "CNAME"
	case RecordSOA:
		return "SOA"
	case RecordTXT:
		return "TXT"
	default:
		return "UNKNOWN"
	}
}

type Classification string

const (
	ClassificationHealthy                 Classification = "healthy"
	ClassificationMissing                 Classification = "missing_record"
	ClassificationWrongValue              Classification = "wrong_value"
	ClassificationCNAMEChain              Classification = "cname_chain"
	ClassificationCNAMELoop               Classification = "cname_loop"
	ClassificationCNAMEDepthExceeded      Classification = "cname_depth_exceeded"
	ClassificationNXDOMAIN                Classification = "nxdomain"
	ClassificationNODATA                  Classification = "nodata"
	ClassificationSERVFAIL                Classification = "servfail"
	ClassificationTimeout                 Classification = "timeout"
	ClassificationAuthorityInconsistent   Classification = "authority_inconsistent"
	ClassificationPublicPropagating       Classification = "public_propagating"
	ClassificationPublicPropagationFailed Classification = "public_propagation_failed"
	ClassificationResolverFailure         Classification = "resolver_failure"
	ClassificationMalformedResponse       Classification = "malformed_response"
)

type ResolverRole string

const (
	ResolverAuthoritative ResolverRole = "authoritative"
	ResolverPublic        ResolverRole = "public_recursive"
)

type ExpectedRecord struct {
	Type   RecordType
	Values []string
	// Weights optionally gives a per-value record weight (1..100, keyed by the
	// value as given); a value without one uses CheckRequest.Weight. Used by
	// 节点管理 > DNS配置 "开启IP权重" on providers that write weights.
	Weights map[string]uint32 `json:",omitempty"`
}

type ProviderRecord struct {
	RecordID string
	Name     string
	Type     RecordType
	Value    string
	TTL      uint32
	Line     string `json:",omitempty"`
	Weight   uint32 `json:",omitempty"`
}

type ProviderSnapshot struct {
	TenantID uuid.UUID
	SiteID   uuid.UUID
	ZoneID   uuid.UUID
	Revision int64
	Records  []ProviderRecord
}

type CheckRequest struct {
	TenantID             uuid.UUID
	SiteID               uuid.UUID
	Name                 string
	Expected             []ExpectedRecord
	AuthoritativeNS      []string
	TTL                  uint32
	Line                 string `json:",omitempty"`
	Weight               uint32 `json:",omitempty"`
	PropagationStartedAt *time.Time
	PropagationWindow    time.Duration
	Provider             ProviderSnapshot
}

type ProviderAction string

const (
	ProviderCreate ProviderAction = "create"
	ProviderUpdate ProviderAction = "update"
	ProviderDelete ProviderAction = "delete"
)

type ProviderOperation struct {
	Sequence       int
	Action         ProviderAction
	RecordID       string
	Name           string
	Type           RecordType
	Value          string
	TTL            uint32
	Line           string
	Weight         uint32
	PreviousValue  string
	PreviousTTL    uint32
	PreviousLine   string
	PreviousWeight uint32
	Reason         string
}

type RepairPlan struct {
	TenantID             uuid.UUID
	SiteID               uuid.UUID
	ZoneID               uuid.UUID
	PreconditionRevision int64
	Digest               string
	Operations           []ProviderOperation
}

type Observation struct {
	Role       ResolverRole
	Resolver   string
	RecordType RecordType
	Status     Classification
	Values     []string
	CNAMEChain []string
	Attempts   int
	MinimumTTL uint32
	ErrorCode  string
}

type CheckResult struct {
	TenantID     uuid.UUID
	SiteID       uuid.UUID
	Name         string
	Status       Classification
	Compliant    bool
	CheckedAt    time.Time
	Observations []Observation
	RepairPlan   RepairPlan
}

type ResolverEndpoint struct {
	Network string
	Address netip.Addr
	Port    uint16
}

type NamedResolver struct {
	Name     string
	Endpoint ResolverEndpoint
}

type EndpointPolicy struct {
	allowed map[string]struct{}
}

type DNSQuery struct {
	Name string
	Type RecordType
}

type DNSRecord struct {
	Name           string
	Type           RecordType
	TTL            uint32
	Value          string
	NegativeTTL    uint32
	negativeTTLSet bool
}

type DNSResponse struct {
	Authoritative bool
	Truncated     bool
	RCode         uint8
	Answers       []DNSRecord
	Authority     []DNSRecord
}

type Resolver interface {
	Resolve(context.Context, ResolverEndpoint, DNSQuery) (DNSResponse, error)
}

type Config struct {
	Resolver               Resolver
	EndpointPolicy         EndpointPolicy
	AuthoritativeResolvers []NamedResolver
	PublicResolvers        []NamedResolver
	QueryTimeout           time.Duration
	Attempts               int
	MaxCNAMEDepth          int
	Now                    func() time.Time
}
