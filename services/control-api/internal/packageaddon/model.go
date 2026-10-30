package packageaddon

import (
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrInvalid     = errors.New("package addon invalid input")
	ErrForbidden   = errors.New("package addon permission denied")
	ErrNotFound    = errors.New("package addon not found")
	ErrConflict    = errors.New("package addon revision conflict")
	ErrDuplicate   = errors.New("package addon already assigned")
	ErrWAFInUse    = errors.New("package addon WAF still in use")
	ErrUnavailable = errors.New("package addon unavailable")
)

type Actor struct{ UserID, ScopeID, SessionID uuid.UUID }
type ProductFields struct {
	Name              string      `json:"name"`
	Remark            string      `json:"remark"`
	Kind              string      `json:"kind"`
	Quantity          int64       `json:"quantity"`
	MonthlyPriceMinor int64       `json:"monthly_price_minor"`
	ProductIDs        []uuid.UUID `json:"product_ids"`
	Enabled           bool        `json:"enabled"`
}
type Product struct {
	ID        uuid.UUID `json:"id"`
	DisplayID string    `json:"display_id"`
	ProductFields
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Assignment struct {
	ID               uuid.UUID `json:"id"`
	DisplayID        string    `json:"display_id"`
	AddonID          uuid.UUID `json:"addon_id"`
	TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
	OwnerUserID      uuid.UUID `json:"owner_user_id"`
	OwnerDisplayID   string    `json:"owner_display_id"`
	OwnerName        string    `json:"owner_name"`
	SubscriptionID   uuid.UUID `json:"subscription_id"`
	SubscriptionName string    `json:"subscription_name"`
	Kind             string    `json:"kind"`
	Amount           int64     `json:"amount"`
	Snapshot         Product   `json:"snapshot"`
	ChargedMinor     int64     `json:"charged_minor"`
	Revision         int64     `json:"revision"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}
type Command struct {
	Action           string         `json:"action"`
	ID               uuid.UUID      `json:"id"`
	ExpectedRevision int64          `json:"expected_revision"`
	Product          *ProductFields `json:"product,omitempty"`
	AddonID          uuid.UUID      `json:"addon_id,omitempty"`
	OwnerUserID      uuid.UUID      `json:"owner_user_id,omitempty"`
	SubscriptionID   uuid.UUID      `json:"subscription_id,omitempty"`
	Amount           int64          `json:"amount,omitempty"`
}
type Result struct {
	ID           uuid.UUID `json:"id"`
	Revision     int64     `json:"revision"`
	ChargedMinor int64     `json:"charged_minor"`
}

type Page[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
}

func Valid(command Command) bool {
	if command.Action == "product.create" || command.Action == "product.update" {
		f := command.Product
		if f == nil || f.Name != strings.TrimSpace(f.Name) || len([]rune(f.Name)) < 1 || len([]rune(f.Name)) > 128 || len([]rune(f.Remark)) > 512 || strings.IndexFunc(f.Name, unicode.IsControl) >= 0 || f.Quantity < 1 || f.Quantity > 1000000000 || f.MonthlyPriceMinor < 0 || f.MonthlyPriceMinor > 1000000000000 || len(f.ProductIDs) > 100 {
			return false
		}
		switch f.Kind {
		case "traffic", "domains", "root_domains", "http_ports", "stream_ports", "custom_cc":
		case "waf":
			if f.Quantity != 1 {
				return false
			}
		default:
			return false
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range f.ProductIDs {
			if id == uuid.Nil || seen[id] {
				return false
			}
			seen[id] = true
		}
		return command.Action == "product.create" && command.ID == uuid.Nil && command.ExpectedRevision == 0 || command.Action == "product.update" && command.ID != uuid.Nil && command.ExpectedRevision > 0
	}
	if command.Action == "assignment.create" {
		return command.AddonID != uuid.Nil && command.OwnerUserID != uuid.Nil && command.SubscriptionID != uuid.Nil && command.Amount > 0 && command.Amount <= 1000000
	}
	if command.Action == "assignment.update" {
		return command.ID != uuid.Nil && command.ExpectedRevision > 0 && command.Amount > 0 && command.Amount <= 1000000
	}
	return (command.Action == "product.delete" || command.Action == "assignment.delete") && command.ID != uuid.Nil && command.ExpectedRevision > 0
}
