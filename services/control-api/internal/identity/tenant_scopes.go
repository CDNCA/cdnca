package identity

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// TenantScope is the small, read-only projection used by platform operators
// when choosing a tenant-scoped control-plane target. It intentionally does
// not include billing or other tenant data.
type TenantScope struct {
	ScopeID    uuid.UUID `json:"scope_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	Status     string    `json:"status"`
	DisplayID  string    `json:"display_id"`
	// ParentScopeID is the tenant's reseller (ADR 0018); nil = platform customer.
	ParentScopeID *uuid.UUID `json:"parent_scope_id"`
	// IsReseller: the tenant has a reseller profile (active or suspended).
	IsReseller bool `json:"is_reseller"`
}

type ListTenantScopesInput struct {
	Page   int
	Limit  int
	Search string
	// Parent filters by reseller: "" all, "none" platform customers only,
	// else a reseller scope UUID (its customers).
	Parent string
}

type TenantScopeList struct {
	Items []TenantScope `json:"items"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
	Total int64         `json:"total"`
}

// ListTenantScopes returns tenant scope metadata for a platform administrator.
// Authorization is enforced by the HTTP boundary (which has the effective
// permission set); the service still validates the actor shape so callers
// cannot accidentally use this method with a tenant principal.
func (s *Service) ListTenantScopes(ctx context.Context, actor Actor, input ListTenantScopesInput) (TenantScopeList, error) {
	input.Search = strings.TrimSpace(input.Search)
	if !validAdminActor(actor) || input.Page < 1 || input.Page > 1_000_000 ||
		input.Limit < 1 || input.Limit > 100 || utf8.RuneCountInString(input.Search) > 128 || !validParentFilter(input.Parent) {
		return TenantScopeList{}, ErrInvalidUserInput
	}
	if s == nil || s.store == nil {
		return TenantScopeList{}, fmt.Errorf("identity store is unavailable")
	}
	return s.store.ListTenantScopes(ctx, input)
}

func validParentFilter(parent string) bool {
	if parent == "" || parent == "none" {
		return true
	}
	parsed, err := uuid.Parse(parent)
	return err == nil && parsed != uuid.Nil && parsed.String() == parent
}
