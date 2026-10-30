package entitlementsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNoLocalLease = errors.New("no local entitlement lease")

type LocalStore interface {
	Current(context.Context) (entitlement.SignedLease, error)
	Install(context.Context, entitlementguard.InstallBundle, time.Time) (entitlementguard.Snapshot, error)
}

type PostgresStore struct {
	pool      *pgxpool.Pool
	installer *entitlementguard.Service
}

func NewPostgresStore(pool *pgxpool.Pool, trust *entitlementguard.TrustStore) *PostgresStore {
	return &PostgresStore{pool: pool, installer: entitlementguard.NewService(pool, trust)}
}

func (store *PostgresStore) Current(ctx context.Context) (entitlement.SignedLease, error) {
	if store == nil || store.pool == nil {
		return entitlement.SignedLease{}, ErrInvalidConfiguration
	}
	var encoded []byte
	err := store.pool.QueryRow(ctx, `
		SELECT lease.signed_lease
		FROM control_installation_entitlement installation
		JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true`,
	).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return entitlement.SignedLease{}, ErrNoLocalLease
	}
	if err != nil {
		return entitlement.SignedLease{}, fmt.Errorf("read current local entitlement: %w", err)
	}
	signed, err := entitlement.Decode(encoded)
	if err != nil {
		return entitlement.SignedLease{}, fmt.Errorf("decode current local entitlement: %w", err)
	}
	return signed, nil
}

func (store *PostgresStore) Install(
	ctx context.Context,
	bundle entitlementguard.InstallBundle,
	now time.Time,
) (entitlementguard.Snapshot, error) {
	if store == nil || store.installer == nil {
		return entitlementguard.Snapshot{}, ErrInvalidConfiguration
	}
	return store.installer.Install(ctx, bundle, now)
}
