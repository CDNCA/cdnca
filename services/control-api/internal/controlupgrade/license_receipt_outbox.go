package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	parentGrantReceiptRequestSchema  = "upgrade-grant.receipt-request/v2"
	parentGrantReceiptResponseSchema = "upgrade-grant.receipt-response/v1"

	parentGrantReceiptFetched    = "fetched"
	parentGrantReceiptVerified   = "verified"
	parentGrantReceiptApplied    = "applied"
	parentGrantReceiptRejected   = "rejected"
	parentGrantReceiptRolledBack = "rolled_back"
)

var (
	ErrLicenseReceiptRetryable = errors.New("control upgrade License receipt is retryable")
	ErrLicenseReceiptPermanent = errors.New("control upgrade License receipt is permanently rejected")
	ErrLicenseReceiptClaimLost = errors.New("control upgrade License receipt claim is no longer owned")
)

type ParentGrantReceipt struct {
	ID                  string
	PlanID              string
	InstallationID      string
	GrantID             string
	RequestSchema       string
	RequestDigestSchema uint16
	Sequence            uint16
	Status              string
	InstalledVersion    string
	ErrorCode           string
	RequestedAt         time.Time
	ObservedAt          time.Time
	LogicalDigest       string
	PredecessorID       string
}

type ParentGrantReceiptResponse struct {
	Schema         string
	RequestID      string
	ReceiptID      string
	AcceptedStatus string
	ReceivedAt     time.Time
}

type ParentGrantReceiptClaim struct {
	Receipt      ParentGrantReceipt
	ClaimToken   string
	AttemptCount uint64
}

type ParentGrantReceiptDisposition string

const (
	ParentGrantReceiptDelivered ParentGrantReceiptDisposition = "delivered"
	ParentGrantReceiptRetryable ParentGrantReceiptDisposition = "retryable"
	ParentGrantReceiptFailed    ParentGrantReceiptDisposition = "failed"
)

type ParentGrantReceiptSettlement struct {
	ReceiptID     string
	ClaimToken    string
	LogicalDigest string
	Disposition   ParentGrantReceiptDisposition
	Response      ParentGrantReceiptResponse
	AvailableAt   time.Time
	ErrorCode     string
	SettledAt     time.Time
}

type ParentGrantReceiptStore interface {
	ClaimParentGrantReceipts(context.Context, string, time.Time, time.Duration, int) ([]ParentGrantReceiptClaim, error)
	SettleParentGrantReceipt(context.Context, ParentGrantReceiptSettlement) error
	HasFailedParentGrantReceipt(context.Context) (bool, error)
}

type ParentGrantReceiptClient interface {
	RecordParentGrantReceipt(context.Context, ParentGrantReceipt) (ParentGrantReceiptResponse, error)
}

type LicenseReceiptDispatcherConfig struct {
	WorkerID   string
	ClaimLease time.Duration
	ClaimBatch int
	Clock      func() time.Time
}

type LicenseReceiptDispatcher struct {
	store  ParentGrantReceiptStore
	client ParentGrantReceiptClient
	config LicenseReceiptDispatcherConfig
}

func NewLicenseReceiptDispatcher(store ParentGrantReceiptStore, client ParentGrantReceiptClient,
	config LicenseReceiptDispatcherConfig) (*LicenseReceiptDispatcher, error) {
	if store == nil || client == nil || !rolloutSafeIDPattern.MatchString(config.WorkerID) ||
		config.ClaimLease <= 0 || config.ClaimBatch < 1 || config.ClaimBatch > 128 {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &LicenseReceiptDispatcher{store: store, client: client, config: config}, nil
}

func (dispatcher *LicenseReceiptDispatcher) DispatchOnce(ctx context.Context) (int, error) {
	if dispatcher == nil || ctx == nil || ctx.Err() != nil {
		return 0, ErrInvalidInput
	}
	now := dispatcher.config.Clock().UTC()
	claims, err := dispatcher.store.ClaimParentGrantReceipts(ctx, dispatcher.config.WorkerID, now,
		dispatcher.config.ClaimLease, dispatcher.config.ClaimBatch)
	if err != nil {
		return 0, err
	}
	for _, claim := range claims {
		response, deliveryErr := dispatcher.client.RecordParentGrantReceipt(ctx, claim.Receipt)
		settlement := ParentGrantReceiptSettlement{ReceiptID: claim.Receipt.ID,
			ClaimToken: claim.ClaimToken, LogicalDigest: claim.Receipt.LogicalDigest,
			SettledAt: dispatcher.config.Clock().UTC()}
		switch {
		case deliveryErr == nil:
			settlement.Disposition, settlement.Response = ParentGrantReceiptDelivered, response
		case errors.Is(deliveryErr, ErrLicenseReceiptPermanent):
			settlement.Disposition, settlement.ErrorCode = ParentGrantReceiptFailed, "permanent_response"
		default:
			settlement.Disposition, settlement.ErrorCode = ParentGrantReceiptRetryable, "license_unavailable"
			settlement.AvailableAt = settlement.SettledAt.Add(parentGrantReceiptRetryDelay(claim.AttemptCount))
		}
		if err := dispatcher.store.SettleParentGrantReceipt(ctx, settlement); err != nil {
			return 0, err
		}
	}
	return len(claims), nil
}

func (dispatcher *LicenseReceiptDispatcher) HasFailed(ctx context.Context) (bool, error) {
	if dispatcher == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrInvalidInput
	}
	return dispatcher.store.HasFailedParentGrantReceipt(ctx)
}

func parentGrantReceiptRetryDelay(attempt uint64) time.Duration {
	delay := 500 * time.Millisecond
	for remaining := attempt; remaining > 1 && delay < 30*time.Second; remaining-- {
		delay *= 2
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func parentGrantReceiptLogicalDigest(receipt ParentGrantReceipt) (string, error) {
	if !validParentGrantReceiptDigestFields(receipt) {
		return "", ErrInvalidInput
	}
	hash := sha256.New()
	var size [4]byte
	for _, value := range []string{
		"cdnca-upgrade-grant-receipt-idempotency/v2", parentGrantReceiptRequestSchema,
		receipt.ID, receipt.InstallationID, receipt.GrantID, receipt.Status,
		receipt.InstalledVersion, receipt.ErrorCode, fmt.Sprintf("%d", receipt.ObservedAt.UTC().Unix()),
	} {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func terminalParentGrantReceipt(before, after RolloutPlan, hasApplied bool,
	observedAt time.Time) (ParentGrantReceipt, bool, error) {
	if !validRolloutPlan(before) || before.ID != after.ID || before.ParentGrantID != after.ParentGrantID ||
		!validCanonicalVersion(after.CurrentVersion) || !validCanonicalVersion(after.TargetVersion) ||
		after.State != PlanCompleted {
		return ParentGrantReceipt{}, false, nil
	}
	receipt := ParentGrantReceipt{PlanID: after.ID, GrantID: after.ParentGrantID,
		RequestSchema: parentGrantReceiptRequestSchema, RequestDigestSchema: 2,
		ObservedAt: observedAt.UTC().Truncate(time.Second)}
	switch after.Completion {
	case CompletionUpgraded:
		receipt.Sequence, receipt.Status, receipt.InstalledVersion = 3, parentGrantReceiptApplied, after.TargetVersion
	case CompletionRolledBack:
		if hasApplied {
			receipt.Sequence, receipt.Status, receipt.InstalledVersion = 4, parentGrantReceiptRolledBack, after.CurrentVersion
			break
		}
		errorCode, definitive := terminalParentGrantReceiptError(after)
		if !definitive {
			return ParentGrantReceipt{}, false, nil
		}
		receipt.Sequence, receipt.Status, receipt.InstalledVersion = 3, parentGrantReceiptRejected, after.CurrentVersion
		receipt.ErrorCode = errorCode
	default:
		return ParentGrantReceipt{}, false, nil
	}
	return receipt, true, nil
}

func terminalParentGrantReceiptError(plan RolloutPlan) (string, bool) {
	for index := len(plan.HealthReceipts) - 1; index >= 0; index-- {
		normalized := strings.ToUpper(plan.HealthReceipts[index].Health.Code)
		if normalized == "" {
			continue
		}
		switch normalized {
		case "DOWNLOAD_FAILED":
			return "download_failed", true
		case "HEALTH_FAILED":
			return "health_check_failed", true
		case "RUNTIME_PRECHECK_FAILED", "RUNTIME_SWITCH_FAILED", "RUNTIME_RELOAD_FAILED", "RUNTIME_INSTALL_FAILED":
			// The native runtime switch of the release failed; the node
			// put the previous runtime back (node-runtime-upgrade).
			return "atomic_apply_failed", true
		case "RUNTIME_SIGNATURE_INVALID", "RUNTIME_AGENT_MISMATCH", "RUNTIME_NOT_PACKAGED", "RUNTIME_STATUS_UNAVAILABLE":
			return "preflight_failed", true
		case "UPGRADE_FAILED", "INSTALLER_ROLLED_BACK":
			return "atomic_apply_failed", true
		case "ARTIFACT_INTEGRITY_FAILED", "ARTIFACT_TOO_LARGE", "INSUFFICIENT_DISK", "PLAN_EXPIRED":
			return "preflight_failed", true
		case "ROLLBACK_FAILED", "UNKNOWN_OUTCOME", "INSTALLER_OUTCOME_UNKNOWN",
			"INSTALLER_UNCERTAIN", "CONFLICTING_TERMINAL_STATE":
			return "", false
		default:
			return "", false
		}
	}
	return "", false
}

func validParentGrantReceiptFields(receipt ParentGrantReceipt) bool {
	if !validParentGrantReceiptDigestFields(receipt) || !validCanonicalPlanUUID(receipt.PlanID) {
		return false
	}
	switch receipt.Sequence {
	case 1:
		return receipt.Status == parentGrantReceiptFetched && receipt.ErrorCode == ""
	case 2:
		return receipt.Status == parentGrantReceiptVerified && receipt.ErrorCode == ""
	case 3:
		return receipt.Status == parentGrantReceiptApplied && receipt.ErrorCode == "" ||
			receipt.Status == parentGrantReceiptRejected && validParentGrantReceiptError(receipt.ErrorCode)
	case 4:
		return receipt.Status == parentGrantReceiptRolledBack && receipt.ErrorCode == ""
	default:
		return false
	}
}

func validParentGrantReceiptDigestFields(receipt ParentGrantReceipt) bool {
	if !validCanonicalPlanUUID(receipt.ID) || !validCanonicalPlanUUID(receipt.InstallationID) ||
		!validCanonicalPlanUUID(receipt.GrantID) || receipt.RequestSchema != parentGrantReceiptRequestSchema ||
		receipt.RequestDigestSchema != 2 || !validCanonicalVersion(receipt.InstalledVersion) ||
		receipt.ObservedAt.IsZero() || !receipt.ObservedAt.Equal(receipt.ObservedAt.UTC().Truncate(time.Second)) {
		return false
	}
	if receipt.Status == parentGrantReceiptRejected {
		return validParentGrantReceiptError(receipt.ErrorCode)
	}
	return receipt.ErrorCode == "" && (receipt.Status == parentGrantReceiptFetched ||
		receipt.Status == parentGrantReceiptVerified || receipt.Status == parentGrantReceiptApplied ||
		receipt.Status == parentGrantReceiptRolledBack)
}

func validParentGrantReceiptError(value string) bool {
	switch value {
	case "download_failed", "health_check_failed", "atomic_apply_failed", "preflight_failed":
		return true
	default:
		return false
	}
}

func insertInitialParentGrantReceiptsTx(ctx context.Context, tx pgx.Tx, identity RolloutIdentity,
	plan RolloutPlan, observedAt time.Time) error {
	if tx == nil || !validRolloutIdentity(identity) || !validRolloutPlan(plan) {
		return ErrInvalidPlan
	}
	fetchedID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	verifiedID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	fetched := ParentGrantReceipt{ID: fetchedID.String(), PlanID: plan.ID,
		InstallationID: identity.InstallationID, GrantID: plan.ParentGrantID,
		RequestSchema: parentGrantReceiptRequestSchema, RequestDigestSchema: 2,
		Sequence: 1, Status: parentGrantReceiptFetched, InstalledVersion: plan.CurrentVersion,
		ObservedAt: observedAt.UTC().Truncate(time.Second)}
	verified := ParentGrantReceipt{ID: verifiedID.String(), PlanID: plan.ID,
		InstallationID: identity.InstallationID, GrantID: plan.ParentGrantID,
		RequestSchema: parentGrantReceiptRequestSchema, RequestDigestSchema: 2,
		Sequence: 2, Status: parentGrantReceiptVerified, InstalledVersion: plan.CurrentVersion,
		ObservedAt: observedAt.UTC().Truncate(time.Second), PredecessorID: fetched.ID}
	if err := insertParentGrantReceiptTx(ctx, tx, fetched); err != nil {
		return err
	}
	return insertParentGrantReceiptTx(ctx, tx, verified)
}

func insertTerminalParentGrantReceiptTx(ctx context.Context, tx pgx.Tx, before, after RolloutPlan,
	identity RolloutIdentity, observedAt time.Time) error {
	if tx == nil || !validRolloutIdentity(identity) {
		return ErrInvalidPlan
	}
	var appliedID uuid.UUID
	hasApplied := true
	if err := tx.QueryRow(ctx, `SELECT id FROM control_upgrade_license_receipt_outbox_097
		WHERE plan_id=$1 AND status='applied'`, after.ID).Scan(&appliedID); errors.Is(err, pgx.ErrNoRows) {
		hasApplied = false
	} else if err != nil {
		return err
	}
	receipt, ok, err := terminalParentGrantReceipt(before, after, hasApplied, observedAt)
	if err != nil || !ok {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	receipt.ID, receipt.InstallationID = id.String(), identity.InstallationID
	if receipt.Sequence == 4 {
		receipt.PredecessorID = appliedID.String()
	} else {
		if err := tx.QueryRow(ctx, `SELECT id FROM control_upgrade_license_receipt_outbox_097
			WHERE plan_id=$1 AND status='verified'`, after.ID).Scan(&receipt.PredecessorID); err != nil {
			return err
		}
	}
	return insertParentGrantReceiptTx(ctx, tx, receipt)
}

func insertParentGrantReceiptTx(ctx context.Context, tx pgx.Tx, receipt ParentGrantReceipt) error {
	digest, err := parentGrantReceiptLogicalDigest(receipt)
	if err != nil {
		return err
	}
	receipt.LogicalDigest = digest
	_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_license_receipt_outbox_097(
		id,request_id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,logical_digest,
		receipt_sequence,status,installed_version,error_code,observed_at,predecessor_id,
		state,available_at,attempt_count,created_at,updated_at)
		VALUES($1,$1,$2,$3,$4,$5,$6,decode($7,'hex'),$8,$9,$10,NULLIF($11,''),$12,NULLIF($13,'')::uuid,
		'pending',$12,0,$12,$12)`, receipt.ID, receipt.PlanID, receipt.InstallationID, receipt.GrantID,
		receipt.RequestSchema, receipt.RequestDigestSchema, receipt.LogicalDigest, receipt.Sequence,
		receipt.Status, receipt.InstalledVersion, receipt.ErrorCode, receipt.ObservedAt, receipt.PredecessorID)
	return err
}

func (s *Store) ClaimParentGrantReceipts(ctx context.Context, workerID string, now time.Time,
	lease time.Duration, limit int) ([]ParentGrantReceiptClaim, error) {
	if s == nil || s.pool == nil || !rolloutSafeIDPattern.MatchString(workerID) || now.IsZero() ||
		lease < time.Microsecond || limit < 1 || limit > 128 {
		return nil, ErrInvalidInput
	}
	claims := make([]ParentGrantReceiptClaim, 0, limit)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `WITH server_clock AS (SELECT clock_timestamp() AS now)
			UPDATE control_upgrade_license_receipt_outbox_097 receipt
			SET state='pending',available_at=server_clock.now,claimed_by=NULL,claim_token=NULL,
				claimed_at=NULL,claim_expires_at=NULL,last_error_code='claim_expired',updated_at=server_clock.now
			FROM server_clock WHERE receipt.state='claimed' AND receipt.claim_expires_at<=server_clock.now`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH server_clock AS (SELECT clock_timestamp() AS now), candidates AS (
			SELECT candidate.id FROM control_upgrade_license_receipt_outbox_097 candidate
			CROSS JOIN server_clock
			LEFT JOIN control_upgrade_license_receipt_outbox_097 previous ON previous.id=candidate.predecessor_id
				WHERE candidate.state='pending' AND candidate.available_at<=server_clock.now
				  AND (candidate.predecessor_id IS NULL OR previous.state='delivered')
				ORDER BY candidate.plan_id,candidate.receipt_sequence,candidate.id
				LIMIT $3 FOR UPDATE OF candidate SKIP LOCKED
		), claimed AS (
			UPDATE control_upgrade_license_receipt_outbox_097 receipt SET state='claimed',claimed_by=$1,
				claim_token=gen_random_uuid(),claimed_at=server_clock.now,
				claim_expires_at=server_clock.now+($2::bigint*interval '1 microsecond'),
				attempt_count=receipt.attempt_count+1,updated_at=server_clock.now
			FROM candidates,server_clock WHERE receipt.id=candidates.id RETURNING receipt.*
		)
		SELECT id,plan_id,installation_id,grant_id,request_schema,request_digest_schema,
			encode(logical_digest,'hex'),receipt_sequence,status,installed_version,COALESCE(error_code,''),
			observed_at,COALESCE(predecessor_id::text,''),claim_token::text,attempt_count FROM claimed
		ORDER BY plan_id,receipt_sequence,id`, workerID, lease.Microseconds(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var claim ParentGrantReceiptClaim
			if err := rows.Scan(&claim.Receipt.ID, &claim.Receipt.PlanID, &claim.Receipt.InstallationID,
				&claim.Receipt.GrantID, &claim.Receipt.RequestSchema, &claim.Receipt.RequestDigestSchema,
				&claim.Receipt.LogicalDigest, &claim.Receipt.Sequence, &claim.Receipt.Status,
				&claim.Receipt.InstalledVersion, &claim.Receipt.ErrorCode, &claim.Receipt.ObservedAt,
				&claim.Receipt.PredecessorID, &claim.ClaimToken, &claim.AttemptCount); err != nil {
				return err
			}
			claim.Receipt.ObservedAt = claim.Receipt.ObservedAt.UTC().Truncate(time.Second)
			claims = append(claims, claim)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("claim control upgrade License receipts: %w", err)
	}
	return claims, nil
}

func (s *Store) SettleParentGrantReceipt(ctx context.Context, settlement ParentGrantReceiptSettlement) error {
	if s == nil || s.pool == nil || !validCanonicalPlanUUID(settlement.ReceiptID) ||
		!validCanonicalPlanUUID(settlement.ClaimToken) || !validParentGrantReceiptDigest(settlement.LogicalDigest) {
		return ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var status, digest string
		err := tx.QueryRow(ctx, `SELECT status,encode(logical_digest,'hex')
			FROM control_upgrade_license_receipt_outbox_097
			WHERE id=$1 AND state='claimed' AND claim_token=$2 AND claim_expires_at>clock_timestamp() FOR UPDATE`,
			settlement.ReceiptID, settlement.ClaimToken).Scan(&status, &digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLicenseReceiptClaimLost
		}
		if err != nil {
			return err
		}
		if digest != settlement.LogicalDigest {
			return ErrLicenseReceiptClaimLost
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		switch settlement.Disposition {
		case ParentGrantReceiptDelivered:
			response := settlement.Response
			if response.Schema != parentGrantReceiptResponseSchema || response.RequestID != settlement.ReceiptID ||
				!validCanonicalPlanUUID(response.ReceiptID) || response.AcceptedStatus != status ||
				response.ReceivedAt.Unix() <= 0 || !response.ReceivedAt.Equal(response.ReceivedAt.UTC().Truncate(time.Second)) {
				return ErrInvalidInput
			}
			responseBytes, err := json.Marshal(parentGrantReceiptHTTPResponse{Schema: response.Schema,
				RequestID: response.RequestID, ReceiptID: response.ReceiptID,
				AcceptedStatus: response.AcceptedStatus, ReceivedAt: response.ReceivedAt.UTC().Unix()})
			if err != nil {
				return err
			}
			responseBytes = append(responseBytes, '\n')
			if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_license_receipt_deliveries_097(
				request_id,logical_digest,response_schema,receipt_id,accepted_status,received_at,
				response_bytes,response_sha256,created_at)
				VALUES($1,decode($2,'hex'),$3,$4,$5,$6,$7,sha256($7),transaction_timestamp())`, settlement.ReceiptID,
				settlement.LogicalDigest, response.Schema, response.ReceiptID, response.AcceptedStatus,
				response.ReceivedAt.UTC(), responseBytes); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE control_upgrade_license_receipt_outbox_097 SET state='delivered',
				claimed_by=NULL,claim_token=NULL,claimed_at=NULL,claim_expires_at=NULL,updated_at=$3
				WHERE id=$1 AND claim_token=$2`, settlement.ReceiptID, settlement.ClaimToken, now)
			return err
		case ParentGrantReceiptRetryable:
			if !rolloutSafeIDPattern.MatchString(settlement.ErrorCode) {
				return ErrInvalidInput
			}
			_, err = tx.Exec(ctx, `UPDATE control_upgrade_license_receipt_outbox_097 SET state='pending',
				available_at=$4::timestamptz + CASE LEAST(attempt_count,7::bigint)
					WHEN 1 THEN interval '500 milliseconds'
					WHEN 2 THEN interval '1 second'
					WHEN 3 THEN interval '2 seconds'
					WHEN 4 THEN interval '4 seconds'
					WHEN 5 THEN interval '8 seconds'
					WHEN 6 THEN interval '16 seconds'
					ELSE interval '30 seconds' END,
				claimed_by=NULL,claim_token=NULL,claimed_at=NULL,claim_expires_at=NULL,
				last_error_code=$3,updated_at=$4 WHERE id=$1 AND claim_token=$2`, settlement.ReceiptID,
				settlement.ClaimToken, settlement.ErrorCode, now)
			return err
		case ParentGrantReceiptFailed:
			if !rolloutSafeIDPattern.MatchString(settlement.ErrorCode) {
				return ErrInvalidInput
			}
			_, err = tx.Exec(ctx, `UPDATE control_upgrade_license_receipt_outbox_097 SET state='failed',
				claimed_by=NULL,claim_token=NULL,claimed_at=NULL,claim_expires_at=NULL,
				last_error_code=$3,updated_at=$4 WHERE id=$1 AND claim_token=$2`, settlement.ReceiptID,
				settlement.ClaimToken, settlement.ErrorCode, now)
			return err
		default:
			return ErrInvalidInput
		}
	})
	if err != nil {
		return fmt.Errorf("settle control upgrade License receipt: %w", err)
	}
	return nil
}

func validParentGrantReceiptDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func (s *Store) HasFailedParentGrantReceipt(ctx context.Context) (bool, error) {
	if s == nil || s.pool == nil {
		return false, ErrInvalidInput
	}
	var failed bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM control_upgrade_license_receipt_outbox_097 WHERE state='failed')`).Scan(&failed); err != nil {
		return false, err
	}
	return failed, nil
}
