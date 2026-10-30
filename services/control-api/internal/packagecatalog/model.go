// Package packagecatalog keeps the package catalog error values the HTTP API
// still maps (community edition: no package catalog; the shared schema and
// commercial-edition data keep the tables).
package packagecatalog

import (
	"errors"
)

var (
	ErrInvalidInput           = errors.New("invalid package catalog input")
	ErrPermissionDenied       = errors.New("package catalog permission denied")
	ErrNotFound               = errors.New("package catalog resource not found")
	ErrNameConflict           = errors.New("package catalog name conflict")
	ErrRevisionConflict       = errors.New("package catalog revision conflict")
	ErrIdempotencyConflict    = errors.New("package catalog idempotency conflict")
	ErrGroupInUse             = errors.New("package group is in use")
	ErrPublicationUnsupported = errors.New("package offer publication policy is unsupported")
	ErrPublicationConflict    = errors.New("package offer publication conflict")
	// ErrCNAMEDomainNotConfigured: the package CNAME domain is not one of the
	// CNAME domains of 节点管理 > DNS配置, so no site of it could allocate.
	ErrCNAMEDomainNotConfigured = errors.New("package CNAME domain is not a configured CNAME domain")
	// ErrLineGroupNotGranted: a reseller picked a line group the platform has
	// not granted to it (ADR 0018 RS-02).
	ErrLineGroupNotGranted = errors.New("package line group is not granted to the reseller")
	// ErrCNAMESyncNotRetryable: the package CNAME sync job is not retryable.
	ErrCNAMESyncNotRetryable = errors.New("package CNAME sync job is not retryable")
)

// BelowWholesaleError: a reseller package price is below the wholesale price
// of its line groups in the reseller's price list (ADR 0018 §5, RS-02).
type BelowWholesaleError struct {
	Period         string `json:"period"`
	PriceMinor     int64  `json:"price_minor"`
	WholesaleMinor int64  `json:"wholesale_minor"`
	PriceList      string `json:"price_list"`
}

func (e *BelowWholesaleError) Error() string {
	return "package " + e.Period + " price is below the reseller wholesale price"
}
