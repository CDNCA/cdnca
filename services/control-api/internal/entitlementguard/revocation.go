package entitlementguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRevocationUnavailable = errors.New("entitlement revocation state unavailable")
	ErrRevocationInvalid     = errors.New("entitlement revocation state invalid")
	ErrRevocationExpired     = errors.New("entitlement revocation state expired")
	ErrRevocationRollback    = errors.New("entitlement revocation revision rollback")
	ErrRevocationConflict    = errors.New("entitlement revocation revision conflict")
	ErrRevocationShrink      = errors.New("entitlement revocation set shrink")
)

// RevocationSnapshot is the exact signed last-known-good state stored by the
// control plane. Artifact and ArtifactSHA256 are retained so startup can
// reverify canonical bytes rather than trusting decomposed columns.
type RevocationSnapshot struct {
	InstallationID string
	CustomerID     string
	LicenseID      string
	Revision       uint64
	KeyID          string
	Artifact       []byte
	ArtifactSHA256 [sha256.Size]byte
	ETag           string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AcceptedAt     time.Time
	RevokedSerials []uint64
}

type RevocationService struct {
	pool  *pgxpool.Pool
	trust *TrustStore
}

func NewRevocationService(pool *pgxpool.Pool, trust *TrustStore) *RevocationService {
	return &RevocationService{pool: pool, trust: trust}
}

func (service *RevocationService) Accept(ctx context.Context, artifact []byte, now time.Time) (RevocationSnapshot, error) {
	if service == nil || service.pool == nil || service.trust == nil || now.IsZero() {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	candidate, err := verifyRevocationArtifact(service.trust, artifact, now.UTC(), signed.Body.CustomerID,
		signed.Body.InstallationID, signed.Body.LicenseID)
	if err != nil {
		return RevocationSnapshot{}, err
	}
	candidate.AcceptedAt = now.UTC()
	publicKey, found := service.trust.PublicKey(candidate.KeyID)
	if !found {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}

	var accepted RevocationSnapshot
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_installation_entitlement (singleton, installation_id)
			VALUES (true, $1)
			ON CONFLICT (singleton) DO NOTHING`, candidate.InstallationID); err != nil {
			return err
		}
		var installationID string
		var currentCustomerID, currentLicenseID *string
		if err := tx.QueryRow(ctx, `
			SELECT installation.installation_id, lease.customer_id, lease.license_id
			FROM control_installation_entitlement installation
			LEFT JOIN entitlement_cached_leases lease ON lease.serial=installation.current_serial
			WHERE installation.singleton = true FOR UPDATE OF installation`,
		).Scan(&installationID, &currentCustomerID, &currentLicenseID); err != nil {
			return err
		}
		if installationID != candidate.InstallationID {
			return entitlement.ErrRevocationInstallationMismatch
		}
		if (currentCustomerID != nil && *currentCustomerID != candidate.CustomerID) ||
			(currentLicenseID != nil && *currentLicenseID != candidate.LicenseID) {
			return ErrRevocationInvalid
		}

		current, currentErr := loadRevocationTx(ctx, tx, service.trust, now.UTC(), "", installationID, "", true)
		if currentErr != nil && !errors.Is(currentErr, ErrRevocationUnavailable) {
			return currentErr
		}
		var currentPointer *RevocationSnapshot
		if currentErr == nil {
			currentPointer = &current
		}
		replayed, err := validateRevocationAdvance(currentPointer, candidate)
		if err != nil {
			return err
		}
		if replayed {
			accepted = current
			return nil
		}

		// Serialize with keyset projection replacement before the LKG insert takes
		// its statement snapshot. A first installation has no keyset LKG row yet,
		// so lock the table rather than relying on a row-level FOR SHARE lock.
		if _, err := tx.Exec(ctx, `LOCK TABLE entitlement_signing_keyset_lkg IN SHARE MODE`); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO entitlement_verification_keys (key_id, public_key, first_seen_at, updated_at)
			VALUES ($1,$2,$3,$3)
			ON CONFLICT (key_id) DO UPDATE SET
				public_key=EXCLUDED.public_key, updated_at=EXCLUDED.updated_at`,
			candidate.KeyID, []byte(publicKey), candidate.AcceptedAt); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO control_entitlement_revocation_lkg (
				singleton, installation_id, customer_id, license_id, revision, key_id,
				artifact, artifact_sha256, artifact_etag, issued_at, expires_at, accepted_at
			) VALUES (true,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (singleton) DO UPDATE SET
				customer_id=EXCLUDED.customer_id, license_id=EXCLUDED.license_id,
				revision=EXCLUDED.revision, key_id=EXCLUDED.key_id, artifact=EXCLUDED.artifact,
				artifact_sha256=EXCLUDED.artifact_sha256, artifact_etag=EXCLUDED.artifact_etag,
				issued_at=EXCLUDED.issued_at, expires_at=EXCLUDED.expires_at,
				accepted_at=EXCLUDED.accepted_at
			RETURNING accepted_at`,
			candidate.InstallationID, candidate.CustomerID, candidate.LicenseID, int64(candidate.Revision),
			candidate.KeyID, candidate.Artifact, candidate.ArtifactSHA256[:], candidate.ETag,
			candidate.IssuedAt, candidate.ExpiresAt, candidate.AcceptedAt).Scan(&candidate.AcceptedAt); err != nil {
			return err
		}
		for _, serial := range candidate.RevokedSerials {
			if _, err := tx.Exec(ctx, `
				INSERT INTO control_entitlement_revoked_serials (
					installation_id, license_id, serial, first_revision,
					first_artifact_sha256, recorded_at
				) VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (installation_id, license_id, serial) DO NOTHING`,
				candidate.InstallationID, candidate.LicenseID, int64(serial), int64(candidate.Revision),
				candidate.ArtifactSHA256[:], candidate.AcceptedAt); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE entitlement_cached_leases
			SET status = 'revoked', verified_at = $3
			WHERE installation_id=$1 AND license_id=$2 AND serial = ANY($4::bigint[])`,
			candidate.InstallationID, candidate.LicenseID, candidate.AcceptedAt,
			uint64sToInt64s(candidate.RevokedSerials)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE control_installation_entitlement installation
			SET last_status='revoked', last_error_code=NULL,
				last_verified_at=$2, updated_at=$2
			FROM entitlement_cached_leases lease
			WHERE installation.singleton=true AND lease.serial=installation.current_serial
				AND lease.installation_id=$1 AND lease.status='revoked'`,
			candidate.InstallationID, candidate.AcceptedAt); err != nil {
			return err
		}
		accepted = cloneRevocationSnapshot(candidate)
		return nil
	})
	if err != nil {
		return RevocationSnapshot{}, fmt.Errorf("accept entitlement revocation state: %w", err)
	}
	return accepted, nil
}

func (service *RevocationService) Restore(ctx context.Context, now time.Time) (RevocationSnapshot, error) {
	if service == nil || service.pool == nil || service.trust == nil || now.IsZero() {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	var snapshot RevocationSnapshot
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		var installationID string
		if err := tx.QueryRow(ctx, `
			SELECT installation_id FROM control_installation_entitlement
			WHERE singleton = true FOR UPDATE`,
		).Scan(&installationID); errors.Is(err, pgx.ErrNoRows) {
			return ErrRevocationUnavailable
		} else if err != nil {
			return err
		}
		var err error
		snapshot, err = loadRevocationTx(ctx, tx, service.trust, now.UTC(), "", installationID, "", false)
		return err
	})
	if err != nil {
		return RevocationSnapshot{}, fmt.Errorf("restore entitlement revocation state: %w", err)
	}
	return snapshot, nil
}

func verifyRevocationArtifact(trust *TrustStore, artifact []byte, now time.Time,
	expectedCustomerID, expectedInstallationID, expectedLicenseID string,
) (RevocationSnapshot, error) {
	if trust == nil || now.IsZero() || expectedCustomerID == "" || expectedInstallationID == "" || expectedLicenseID == "" {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	signed, err := entitlement.DecodeRevocationSet(artifact)
	if err != nil {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	trust.mu.RLock()
	key, found := trust.keys[signed.KeyID]
	trust.mu.RUnlock()
	if !found {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	keyWindow := entitlement.RevocationKeyWindow{
		NotBefore: key.NotBefore, SignUntil: key.SignUntil, VerifyUntil: key.VerifyUntil,
	}
	// Deployment trust files contain root pins without a lifecycle window. They
	// are still valid revocation verification anchors; bind the first artifact
	// to its own issued-at timestamp instead of rejecting the initial install as
	// an unavailable revocation state. Rotated keyset entries retain their
	// explicit windows above.
	if keyWindow.NotBefore.IsZero() {
		keyWindow.NotBefore = time.Unix(signed.Body.IssuedAt, 0).UTC()
	}
	body, err := entitlement.VerifyRevocationSet(signed, key.PublicKey, entitlement.RevocationVerifyOptions{
		Now: now.UTC(), ExpectedAudience: entitlement.RevocationSetAudience,
		ExpectedCustomerID: expectedCustomerID, ExpectedInstallationID: expectedInstallationID,
		ExpectedLicenseID: expectedLicenseID, KeyWindow: keyWindow,
	})
	if err != nil {
		if errors.Is(err, entitlement.ErrRevocationNotCurrent) && now.UTC().Unix() >= signed.Body.ExpiresAt {
			return RevocationSnapshot{}, ErrRevocationExpired
		}
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	return RevocationSnapshot{
		InstallationID: body.InstallationID, CustomerID: body.CustomerID, LicenseID: body.LicenseID,
		Revision: body.Revision, KeyID: signed.KeyID, Artifact: append([]byte(nil), artifact...),
		ArtifactSHA256: entitlement.RevocationSetDigest(artifact), ETag: entitlement.RevocationSetETag(artifact),
		IssuedAt: time.Unix(body.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(body.ExpiresAt, 0).UTC(),
		RevokedSerials: append([]uint64(nil), body.RevokedSerials...),
	}, nil
}

func loadRevocationTx(ctx context.Context, tx pgx.Tx, trust *TrustStore, now time.Time,
	expectedCustomerID, expectedInstallationID, expectedLicenseID string, allowExpired bool,
) (RevocationSnapshot, error) {
	var stored RevocationSnapshot
	var revision int64
	var digest []byte
	err := tx.QueryRow(ctx, `
		SELECT installation_id, customer_id, license_id, revision, key_id,
		       artifact, artifact_sha256, artifact_etag, issued_at, expires_at, accepted_at
		FROM control_entitlement_revocation_lkg WHERE singleton=true`,
	).Scan(&stored.InstallationID, &stored.CustomerID, &stored.LicenseID, &revision, &stored.KeyID,
		&stored.Artifact, &digest, &stored.ETag, &stored.IssuedAt, &stored.ExpiresAt, &stored.AcceptedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RevocationSnapshot{}, ErrRevocationUnavailable
	}
	if err != nil {
		return RevocationSnapshot{}, err
	}
	if revision <= 0 || len(digest) != sha256.Size {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	stored.Revision = uint64(revision)
	copy(stored.ArtifactSHA256[:], digest)
	if expectedCustomerID == "" {
		expectedCustomerID = stored.CustomerID
	}
	if expectedInstallationID == "" {
		expectedInstallationID = stored.InstallationID
	}
	if expectedLicenseID == "" {
		expectedLicenseID = stored.LicenseID
	}
	verifyAt := now.UTC()
	if allowExpired && !verifyAt.Before(stored.ExpiresAt) {
		verifyAt = stored.IssuedAt
	}
	verified, err := verifyRevocationArtifact(trust, stored.Artifact, verifyAt,
		expectedCustomerID, expectedInstallationID, expectedLicenseID)
	if err != nil {
		return RevocationSnapshot{}, err
	}
	if verified.Revision != stored.Revision || verified.KeyID != stored.KeyID ||
		verified.ETag != stored.ETag || !verified.IssuedAt.Equal(stored.IssuedAt) ||
		!verified.ExpiresAt.Equal(stored.ExpiresAt) ||
		subtle.ConstantTimeCompare(verified.ArtifactSHA256[:], stored.ArtifactSHA256[:]) != 1 {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	rows, err := tx.Query(ctx, `
		SELECT serial FROM control_entitlement_revoked_serials
		WHERE installation_id=$1 AND license_id=$2 ORDER BY serial`, stored.InstallationID, stored.LicenseID)
	if err != nil {
		return RevocationSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var serial int64
		if err := rows.Scan(&serial); err != nil || serial <= 0 {
			return RevocationSnapshot{}, ErrRevocationInvalid
		}
		stored.RevokedSerials = append(stored.RevokedSerials, uint64(serial))
	}
	if err := rows.Err(); err != nil {
		return RevocationSnapshot{}, err
	}
	if !equalSerials(stored.RevokedSerials, verified.RevokedSerials) {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	if !allowExpired {
		if err := stored.requireCurrent(now); err != nil {
			return RevocationSnapshot{}, err
		}
	}
	return cloneRevocationSnapshot(stored), nil
}

// loadRevocationLKGTx returns the last verified revocation list even after its
// 15-minute window has passed (the control plane
// keeps working while the license service is down; the lease grace window,
// checked by the caller, bounds how long). Signature, audience, customer,
// installation and license binding are verified exactly as for a current list,
// and the signing key must still be inside its verification window now.
func loadRevocationLKGTx(ctx context.Context, tx pgx.Tx, trust *TrustStore, now time.Time,
	expectedCustomerID, expectedInstallationID, expectedLicenseID string,
) (RevocationSnapshot, error) {
	snapshot, err := loadRevocationTx(ctx, tx, trust, now, expectedCustomerID, expectedInstallationID,
		expectedLicenseID, true)
	if err != nil {
		return RevocationSnapshot{}, err
	}
	if err := trust.requireRevocationKeyVerifiable(snapshot.KeyID, now); err != nil {
		return RevocationSnapshot{}, err
	}
	return snapshot, nil
}

func (trust *TrustStore) requireRevocationKeyVerifiable(keyID string, now time.Time) error {
	trust.mu.RLock()
	key, found := trust.keys[keyID]
	trust.mu.RUnlock()
	if !found || now.IsZero() || (key.VerifyUntil != nil && !now.UTC().Before(*key.VerifyUntil)) {
		return ErrRevocationInvalid
	}
	return nil
}

// RestoreLKG is Restore without the 15-minute currency requirement: it is used
// by startup and readiness so a license service outage does not stop the
// control API. Revocation advance (Accept) and the syncer still use Restore.
func (service *RevocationService) RestoreLKG(ctx context.Context, now time.Time) (RevocationSnapshot, error) {
	if service == nil || service.pool == nil || service.trust == nil || now.IsZero() {
		return RevocationSnapshot{}, ErrRevocationInvalid
	}
	var snapshot RevocationSnapshot
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		var installationID string
		if err := tx.QueryRow(ctx, `
			SELECT installation_id FROM control_installation_entitlement
			WHERE singleton = true FOR UPDATE`,
		).Scan(&installationID); errors.Is(err, pgx.ErrNoRows) {
			return ErrRevocationUnavailable
		} else if err != nil {
			return err
		}
		var err error
		snapshot, err = loadRevocationLKGTx(ctx, tx, service.trust, now.UTC(), "", installationID, "")
		return err
	})
	if err != nil {
		return RevocationSnapshot{}, fmt.Errorf("restore entitlement revocation last-known-good state: %w", err)
	}
	return snapshot, nil
}

func validateRevocationAdvance(current *RevocationSnapshot, candidate RevocationSnapshot) (bool, error) {
	if current == nil {
		return false, nil
	}
	if candidate.InstallationID != current.InstallationID || candidate.CustomerID != current.CustomerID ||
		candidate.LicenseID != current.LicenseID {
		return false, ErrRevocationInvalid
	}
	if candidate.Revision < current.Revision {
		return false, ErrRevocationRollback
	}
	if candidate.Revision == current.Revision {
		if candidate.ArtifactSHA256 != current.ArtifactSHA256 || !bytes.Equal(candidate.Artifact, current.Artifact) {
			return false, ErrRevocationConflict
		}
		return true, nil
	}
	if !candidate.IssuedAt.After(current.IssuedAt) || !serialSuperset(candidate.RevokedSerials, current.RevokedSerials) {
		return false, ErrRevocationShrink
	}
	return false, nil
}

func (snapshot RevocationSnapshot) requireCurrent(now time.Time) error {
	if now.IsZero() || snapshot.ExpiresAt.IsZero() || !now.UTC().Before(snapshot.ExpiresAt) {
		return ErrRevocationExpired
	}
	return nil
}

func cloneRevocationSnapshot(snapshot RevocationSnapshot) RevocationSnapshot {
	snapshot.Artifact = append([]byte(nil), snapshot.Artifact...)
	snapshot.RevokedSerials = append([]uint64(nil), snapshot.RevokedSerials...)
	return snapshot
}

func serialSuperset(candidate, current []uint64) bool {
	index := 0
	for _, serial := range candidate {
		if index < len(current) && serial == current[index] {
			index++
		}
	}
	return index == len(current)
}

func equalSerials(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func uint64sToInt64s(values []uint64) []int64 {
	converted := make([]int64, len(values))
	for index, value := range values {
		converted[index] = int64(value)
	}
	return converted
}
