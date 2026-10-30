package cnameallocationhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest   = errors.New("invalid CNAME allocation query")
	ErrUnauthenticated  = errors.New("CNAME allocation authentication required")
	ErrPermissionDenied = errors.New("CNAME allocation permission denied")
	ErrNotFound         = errors.New("CNAME allocation authority not found")
	ErrUnavailable      = errors.New("CNAME allocation authority unavailable")
)

type AuthenticateFunc func(*http.Request) (identity.Principal, error)

type AllocationView struct {
	ID               uuid.UUID `json:"id"`
	Mode             string    `json:"mode"`
	OwnerID          uuid.UUID `json:"owner_id"`
	ProviderID       uuid.UUID `json:"provider_id"`
	ZoneID           uuid.UUID `json:"zone_id"`
	Domain           string    `json:"domain"`
	Hostname         string    `json:"hostname"`
	ExplicitHostname bool      `json:"explicit_hostname"`
	State            string    `json:"state"`
	FailureCode      string    `json:"failure_code,omitempty"`
	JobID            uuid.UUID `json:"job_id"`
	Generation       int64     `json:"generation"`
	CurrentRevision  int64     `json:"current_revision"`
	LKGRevision      int64     `json:"lkg_revision,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type AllocationPage struct {
	Items      []AllocationView `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type ListQuery struct {
	AfterID *uuid.UUID
	Limit   int
}

type DiagnoseQuery struct {
	SiteID   uuid.UUID
	Domain   string
	Hostname string
}

type DiagnosisView struct {
	SiteID              uuid.UUID  `json:"site_id"`
	Mode                string     `json:"mode,omitempty"`
	OwnerID             uuid.UUID  `json:"owner_id,omitempty"`
	AllocationID        *uuid.UUID `json:"allocation_id,omitempty"`
	BindingAllocationID *uuid.UUID `json:"binding_allocation_id,omitempty"`
	LKGAllocationID     *uuid.UUID `json:"lkg_allocation_id,omitempty"`
	ProviderID          *uuid.UUID `json:"provider_id,omitempty"`
	ZoneID              *uuid.UUID `json:"zone_id,omitempty"`
	Domain              string     `json:"domain,omitempty"`
	Hostname            string     `json:"hostname,omitempty"`
	State               string     `json:"state,omitempty"`
	Ready               bool       `json:"ready"`
	ReasonCodes         []string   `json:"reason_codes"`
}

type Reader interface {
	List(context.Context, uuid.UUID, ListQuery) ([]AllocationView, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (AllocationView, error)
	Diagnose(context.Context, uuid.UUID, DiagnoseQuery) (DiagnosisView, error)
}
