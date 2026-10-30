package openrestysecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// DefaultBlockPageNotCounted mirrors DefaultGlobalConfig.
func DefaultBlockPageNotCounted() bool { return true }

// QueryRower is a pool or transaction.
type QueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// BlockPageNotCounted reports the platform's global "block pages are not
// counted as traffic" switch (FX60/NF38). It is a billing rule, so only the
// platform scope's global document decides it; tenants cannot opt in.
func BlockPageNotCounted(ctx context.Context, db QueryRower) (bool, error) {
	if db == nil || ctx == nil {
		return DefaultBlockPageNotCounted(), ErrUnavailable
	}
	var raw []byte
	err := db.QueryRow(ctx, `SELECT config.document FROM openresty_security_configs config
		JOIN access_scopes scope ON scope.id=config.tenant_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		WHERE config.scope_type='global' AND config.scope_id='0' AND config.deleted_at IS NULL
		ORDER BY config.tenant_scope_id LIMIT 1`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultBlockPageNotCounted(), nil
	}
	if err != nil {
		return DefaultBlockPageNotCounted(), fmt.Errorf("read block page traffic setting: %w", err)
	}
	return blockPageNotCountedFromDocument(raw), nil
}

func blockPageNotCountedFromDocument(raw []byte) bool {
	var document map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &document) != nil {
		return DefaultBlockPageNotCounted()
	}
	var value bool
	if field, ok := document["block_page_not_counted"]; ok && json.Unmarshal(field, &value) == nil {
		return value
	}
	return DefaultBlockPageNotCounted()
}
