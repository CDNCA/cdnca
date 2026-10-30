package regioncatalog

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	PermissionRead   = "regions.read"
	PermissionManage = "regions.manage"
)

var (
	ErrInvalidInput        = errors.New("region catalog input is invalid")
	ErrUnauthenticated     = errors.New("region catalog authentication is required")
	ErrPermissionDenied    = errors.New("region catalog permission is required")
	ErrNotFound            = errors.New("region catalog entry was not found")
	ErrNameConflict        = errors.New("region catalog name already exists")
	ErrRevisionConflict    = errors.New("region catalog revision conflict")
	ErrIdempotencyConflict = errors.New("region catalog idempotency conflict")
	ErrInUse               = errors.New("region catalog entry is in use")
	ErrUnavailable         = errors.New("region catalog is unavailable")
)

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	Permissions []string
}

type ListRequest struct {
	Limit     int
	Search    string
	Paginated bool
	Page      int
	PageSize  int
}

type Region struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Code is the region's stable lower-case ASCII code (migration 525):
	// what nodes, error page region overrides and origin routes'
	// node_regions match on. Generated, never changes.
	Code string `json:"code"`
	// CountryCode / ProvinceCode (migration 576): the region's standard
	// geography, "" = not set (ValidGeo).
	CountryCode  string    `json:"country_code"`
	ProvinceCode string    `json:"province_code"`
	Description  string    `json:"description"`
	L2CheckPort  int       `json:"l2_check_port"`
	Sort         int       `json:"sort"`
	Revision     int64     `json:"revision"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Page struct {
	Count int64    `json:"count"`
	Data  []Region `json:"data"`
}

type CreateRequest struct {
	Name           string
	CountryCode    string
	ProvinceCode   string
	Description    string
	L2CheckPort    int
	Sort           int
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	ID               string
	ExpectedRevision int64
	Name             string
	CountryCode      string
	ProvinceCode     string
	Description      string
	L2CheckPort      int
	Sort             int
	IdempotencyKey   string
	RequestID        string
}

type DeleteRequest struct {
	ID               string
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}
