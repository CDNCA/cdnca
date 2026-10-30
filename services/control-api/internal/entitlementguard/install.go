package entitlementguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxInstallBundleBytes = 1 << 20

type Service struct {
	pool  *pgxpool.Pool
	trust *TrustStore
}

type installBundleJSON struct {
	InstallationID string                  `json:"installation_id"`
	RevokedSerials []uint64                `json:"revoked_serials"`
	SignedLease    entitlement.SignedLease `json:"signed_lease"`
}

func NewService(pool *pgxpool.Pool, trust *TrustStore) *Service {
	return &Service{pool: pool, trust: trust}
}

func DecodeInstallBundle(encoded []byte) (InstallBundle, error) {
	if len(encoded) == 0 || len(encoded) > maxInstallBundleBytes {
		return InstallBundle{}, ErrInvalidBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire installBundleJSON
	if err := decoder.Decode(&wire); err != nil {
		return InstallBundle{}, ErrInvalidBundle
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return InstallBundle{}, ErrInvalidBundle
	}
	bundle := InstallBundle{
		InstallationID: wire.InstallationID,
		RevokedSerials: append([]uint64(nil), wire.RevokedSerials...),
		SignedLease:    wire.SignedLease,
	}
	return bundle, nil
}

func (s *Service) Install(ctx context.Context, bundle InstallBundle, now time.Time) (Snapshot, error) {
	if s == nil || s.pool == nil || now.IsZero() || bundle.InstallationID == "" ||
		bundle.SignedLease.Lease.Serial == 0 || bundle.SignedLease.Lease.Serial > math.MaxInt64 {
		return Snapshot{}, ErrInvalidBundle
	}
	if s.trust == nil {
		return Snapshot{}, ErrTrustUnavailable
	}
	if len(bundle.RevokedSerials) != 0 {
		return Snapshot{}, ErrUntrustedRevocations
	}
	encodedLease, err := bundle.SignedLease.Encode()
	if err != nil {
		return Snapshot{}, err
	}
	if bundle.SignedLease.Lease.InstallationID != bundle.InstallationID {
		return Snapshot{}, entitlement.ErrInstallationMismatch
	}

	var snapshot Snapshot
	install := func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_installation_entitlement (singleton, installation_id)
			VALUES (true, $1)
			ON CONFLICT (singleton) DO NOTHING`, bundle.InstallationID); err != nil {
			return err
		}
		var installationID string
		var currentSerial *int64
		if err := tx.QueryRow(ctx, `
			SELECT installation_id, current_serial
			FROM control_installation_entitlement
			WHERE singleton = true
			FOR UPDATE`,
		).Scan(&installationID, &currentSerial); err != nil {
			return err
		}
		if installationID != bundle.InstallationID {
			return entitlement.ErrInstallationMismatch
		}

		verified, err := s.trust.Verify(bundle.SignedLease, entitlement.VerifyOptions{
			Now:                    now,
			ExpectedAudience:       entitlement.ControlAudience,
			ExpectedInstallationID: bundle.InstallationID,
		})
		if err != nil {
			return err
		}
		revocation, err := loadRevocationTx(ctx, tx, s.trust, now.UTC(), verified.Lease.CustomerID,
			bundle.InstallationID, verified.Lease.LicenseID, false)
		if err != nil {
			return err
		}
		verified, err = s.trust.Verify(bundle.SignedLease, entitlement.VerifyOptions{
			Now: now, ExpectedAudience: entitlement.ControlAudience,
			ExpectedInstallationID: bundle.InstallationID, RevokedSerials: revocation.RevokedSerials,
		})
		if err != nil {
			return err
		}

		serial := int64(verified.Lease.Serial)
		if currentSerial != nil && serial < *currentSerial {
			return ErrStaleLease
		}
		if currentSerial != nil && serial == *currentSerial {
			var existing []byte
			if err := tx.QueryRow(ctx, `SELECT signed_lease FROM entitlement_cached_leases WHERE serial = $1`, serial).Scan(&existing); err != nil {
				return err
			}
			if !bytes.Equal(existing, encodedLease) {
				return ErrLeaseConflict
			}
		}

		if currentSerial == nil || serial != *currentSerial {
			if err := auditModuleChange(ctx, tx, s.pool, currentSerial, verified.Lease); err != nil {
				return err
			}
		}

		publicKey, found := s.trust.PublicKey(bundle.SignedLease.KeyID)
		if !found {
			return ErrTrustUnavailable
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO entitlement_verification_keys (key_id, public_key, first_seen_at, updated_at)
			VALUES ($1, $2, $3, $3)
			ON CONFLICT (key_id) DO UPDATE
			SET public_key = EXCLUDED.public_key, updated_at = EXCLUDED.updated_at`,
			bundle.SignedLease.KeyID, []byte(publicKey), now.UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO entitlement_cached_leases (
				serial, installation_id, customer_id, license_id, key_id, signed_lease,
				status, not_before, expires_at, grace_until, verified_at, installed_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
			ON CONFLICT (serial) DO UPDATE SET
				status = CASE
					WHEN entitlement_cached_leases.status = 'revoked' OR EXCLUDED.status = 'revoked'
					THEN 'revoked' ELSE EXCLUDED.status END,
				verified_at = EXCLUDED.verified_at`,
			serial,
			verified.Lease.InstallationID,
			verified.Lease.CustomerID,
			verified.Lease.LicenseID,
			bundle.SignedLease.KeyID,
			encodedLease,
			string(verified.Status),
			time.Unix(verified.Lease.NotBefore, 0).UTC(),
			time.Unix(verified.Lease.ExpiresAt, 0).UTC(),
			time.Unix(verified.Lease.GraceUntil, 0).UTC(),
			now.UTC(),
		); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE control_installation_entitlement
			SET current_serial = $1, last_status = $2, last_error_code = NULL,
			    last_verified_at = $3, updated_at = $3
			WHERE singleton = true`, serial, string(verified.Status), now.UTC()); err != nil {
			return err
		}
		snapshot = Snapshot{
			InstallationID: installationID,
			Serial:         verified.Lease.Serial,
			KeyID:          bundle.SignedLease.KeyID,
			Status:         verified.Status,
			VerifiedAt:     now.UTC(),
		}
		return nil
	}
	// LIC-REC-03: a failure before COMMIT rolls back, so the lease is not
	// installed; a COMMIT whose answer was lost may have been applied, and only
	// a re-read of control_installation_entitlement tells.
	tx, err := s.pool.Begin(ctx)
	if err == nil {
		defer func() { _ = tx.Rollback(ctx) }()
		if err = install(tx); err == nil {
			err = commitFailure(tx.Commit(ctx))
		}
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("install local entitlement: %w", err)
	}
	return snapshot, nil
}

// commitFailure marks a COMMIT error as ErrInstallOutcomeUnknown unless the
// server answered it (ROLLBACK or an error: not committed) or pgconn proves
// nothing was sent.
func commitFailure(err error) error {
	var pgErr *pgconn.PgError
	if err == nil || errors.Is(err, pgx.ErrTxCommitRollback) || errors.As(err, &pgErr) || pgconn.SafeToRetry(err) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrInstallOutcomeUnknown, err)
}
