package acmeruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certnotify"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Dispatcher struct {
	pool   *pgxpool.Pool
	issuer Issuer
	keys   *KeyStore
	config Config
	// notices tells a renewal's owner it failed (certnotify); nil sends none.
	notices certnotify.Enqueuer
	// directory picks a new order's ACME directory (the configured issuer,
	// acmecacredentials); nil keeps config.DirectoryURL for every order.
	directory DirectorySelector
	// routed are the directories directory may return besides the default:
	// an order started on one of them stays there.
	routed []string
}

// DirectorySelector is the ACME directory a new order uses: the default
// directory, or the configured issuer's (an error when it cannot be used).
// issuer is the CA frozen on the order (migration 517); nil for orders that
// predate it, which use the platform default issuer.
type DirectorySelector func(ctx context.Context, tx pgx.Tx, issuer *string, defaultDirectory string) (string, error)

// SelectDirectories makes each new order use selector's directory, one of
// routed or the default; an order already started on a routed directory
// stays on it (orders on the default directory keep the CA failover's own
// pinning). Call before the runtime starts.
func (d *Dispatcher) SelectDirectories(selector DirectorySelector, routed []string) {
	d.directory, d.routed = selector, slices.Clone(routed)
}

// EnableRenewalFailureNotices makes a failed renewal order notify its owner
// (certificate.renew_failed). Call before the runtime starts.
func (d *Dispatcher) EnableRenewalFailureNotices(enqueuer certnotify.Enqueuer) { d.notices = enqueuer }

func NewDispatcher(pool *pgxpool.Pool, issuer Issuer, keys *KeyStore, config Config) (*Dispatcher, error) {
	if pool == nil || issuer == nil || keys == nil || keys.pool != pool || !validHTTPSURL(config.DirectoryURL) ||
		!validContacts(config.Contacts) || !config.AcceptTerms || config.LeaseDuration <= 0 ||
		config.LeaseDuration > 24*time.Hour || config.SettleTimeout <= 0 ||
		config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase ||
		config.MaxAttempts < 1 || config.MaxAttempts > 1000 {
		return nil, ErrInvalidInput
	}
	config.Contacts = append([]string(nil), config.Contacts...)
	return &Dispatcher{pool: pool, issuer: issuer, keys: keys, config: config}, nil
}

func (d *Dispatcher) DispatchOne(ctx context.Context) (DispatchResult, error) {
	lease, found, err := d.claim(ctx)
	if err != nil {
		return DispatchResult{}, err
	}
	if !found {
		return DispatchResult{Outcome: OutcomeIdle}, nil
	}
	result := DispatchResult{
		Outcome: OutcomeRetry, OutboxID: lease.OutboxID, OrderID: lease.OrderID, Attempt: lease.Attempt,
	}
	request, err := d.buildRequest(ctx, lease)
	if err == nil {
		var issued acmeworker.IssueResult
		issued, err = d.issuer.Issue(ctx, request)
		if err == nil && !validIssueResult(issued, request) {
			err = codedError("acme_issue_result_invalid", ErrConflict)
		}
	}
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.config.SettleTimeout)
	defer cancel()
	if err == nil {
		if settleErr := d.complete(settleCtx, lease); settleErr != nil {
			return result, settleErr
		}
		result.Outcome = OutcomeCompleted
		return result, nil
	}
	code, retryAfter := classifyFailure(err)
	result.ErrorCode = code
	slog.Warn("ACME order attempt failed",
		"outbox_id", lease.OutboxID, "order_id", lease.OrderID, "attempt", lease.Attempt,
		"error_code", code, "retry_after", retryAfter, "detail", acmeworker.FailureDetail(err))
	terminal := dispatchTerminal(err, code)
	if settleErr := d.settleFailure(settleCtx, lease, code, acmeworker.PublicReason(err), retryAfter, terminal); settleErr != nil {
		return result, settleErr
	}
	if lease.Attempt >= d.config.MaxAttempts || terminal {
		result.Outcome = OutcomeExhausted
	}
	return result, nil
}

func validIssueResult(result acmeworker.IssueResult, request acmeworker.IssueRequest) bool {
	certificate := result.Certificate
	if certificate.RequestDigest == "" || certificate.CertificateKeyRef != request.CertificateKeyRef ||
		len(certificate.ChainDER) == 0 || len(certificate.ChainDER) > 5 ||
		!bytes.Equal(certificate.LeafDER, certificate.ChainDER[0]) ||
		!validHTTPSURL(certificate.CertificateURL) || !certificate.NotAfter.After(certificate.NotBefore) {
		return false
	}

	chain := make([]*x509.Certificate, len(certificate.ChainDER))
	var canonicalPEM bytes.Buffer
	for index, certificateDER := range certificate.ChainDER {
		parsed, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return false
		}
		chain[index] = parsed
		if index > 0 {
			if err := chain[index-1].CheckSignatureFrom(parsed); err != nil {
				return false
			}
		}
		if err := pem.Encode(&canonicalPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}); err != nil {
			return false
		}
	}
	leaf := chain[0]
	if !bytes.Equal(canonicalPEM.Bytes(), certificate.CertificatePEM) ||
		!sameCanonicalDNSNameSet(request.Domains, certificate.DNSNames) ||
		!sameCanonicalDNSNameSet(request.Domains, leaf.DNSNames) {
		return false
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return certificate.LeafFingerprint == "sha256:"+hex.EncodeToString(fingerprint[:]) &&
		certificate.PublicKeySPKISHA256 == "sha256:"+hex.EncodeToString(spki[:]) &&
		certificate.SerialNumber == leaf.SerialNumber.String() &&
		certificate.NotBefore.UTC().Equal(leaf.NotBefore.UTC()) &&
		certificate.NotAfter.UTC().Equal(leaf.NotAfter.UTC())
}

func sameCanonicalDNSNameSet(left, right []string) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	left = slices.Clone(left)
	right = slices.Clone(right)
	for _, names := range [][]string{left, right} {
		for _, name := range names {
			if name == "" || name != strings.TrimSpace(name) || name != strings.ToLower(name) ||
				strings.HasSuffix(name, ".") {
				return false
			}
		}
		slices.Sort(names)
		for index := 1; index < len(names); index++ {
			if names[index] == names[index-1] {
				return false
			}
		}
	}
	return slices.Equal(left, right)
}

func (d *Dispatcher) claim(ctx context.Context) (Lease, bool, error) {
	var lease Lease
	token, err := uuid.NewRandom()
	if err != nil {
		return Lease{}, false, err
	}
	leaseMilliseconds := d.config.LeaseDuration.Milliseconds()
	err = d.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT id FROM dns_acme_outbox
		WHERE attempts < $1 AND (
			(status IN ('pending','failed') AND next_attempt_at <= statement_timestamp())
			OR (status='processing' AND lease_expires_at <= statement_timestamp())
		) AND NOT EXISTS (SELECT 1 FROM certificate_orders settled
			WHERE settled.scope_id=dns_acme_outbox.scope_id AND settled.id=dns_acme_outbox.aggregate_id
			  AND settled.status='failed')
		ORDER BY COALESCE(lease_expires_at,next_attempt_at),created_at,id
		FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE dns_acme_outbox outbox SET
		status='processing',attempts=outbox.attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+($3 * interval '1 millisecond'),
		last_error_code=NULL,last_error_reason=NULL,updated_at=statement_timestamp()
	FROM candidate WHERE outbox.id=candidate.id
	RETURNING outbox.id,outbox.scope_id,outbox.aggregate_id,outbox.lease_token,
		outbox.attempts,outbox.lease_expires_at,outbox.payload`,
		d.config.MaxAttempts, token, leaseMilliseconds).Scan(
		&lease.OutboxID, &lease.ScopeID, &lease.OrderID, &lease.Token,
		&lease.Attempt, &lease.ExpiresAt, &lease.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, err
	}
	return lease, true, nil
}

type outboxPayload struct {
	OrderID       uuid.UUID  `json:"order_id"`
	ChallengeType string     `json:"challenge_type"`
	Domains       []string   `json:"domains"`
	DNSProviderID *uuid.UUID `json:"dns_provider_id"`
}

type issuanceSnapshotExpectation struct {
	TenantID          uuid.UUID
	ScopeID           uuid.UUID
	ActorUserID       uuid.UUID
	OperationID       string
	DirectoryURL      string
	CertificateKeyRef string
	AccountKeyRef     string
	ProviderRef       *string
	Domains           []string
	ChallengeType     *acmeworker.ChallengeType
}

type issuanceRequestSnapshot struct {
	TenantID           uuid.UUID
	ScopeID            uuid.UUID
	OperationID        string
	CertificateOrderID uuid.UUID
	ActorUserID        uuid.UUID
	ProviderRef        string
	DirectoryURL       string
	AccountKeyRef      string
	CertificateKeyRef  string
	Domains            []string
	ChallengeType      acmeworker.ChallengeType
}

func validateIssuanceRequestSnapshot(raw []byte, expected issuanceSnapshotExpectation) (issuanceRequestSnapshot, error) {
	var snapshot issuanceRequestSnapshot
	if len(raw) == 0 || json.Unmarshal(raw, &snapshot) != nil ||
		snapshot.TenantID == uuid.Nil || snapshot.ScopeID == uuid.Nil || snapshot.ActorUserID == uuid.Nil ||
		expected.TenantID == uuid.Nil || expected.ScopeID == uuid.Nil || expected.ActorUserID == uuid.Nil ||
		snapshot.TenantID != expected.TenantID || snapshot.ScopeID != expected.ScopeID ||
		snapshot.ActorUserID != expected.ActorUserID {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.OperationID != "" && snapshot.OperationID != expected.OperationID {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.DirectoryURL != "" && snapshot.DirectoryURL != expected.DirectoryURL {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.CertificateKeyRef != "" && snapshot.CertificateKeyRef != expected.CertificateKeyRef {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.AccountKeyRef != "" && snapshot.AccountKeyRef != expected.AccountKeyRef {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.ProviderRef != nil && snapshot.ProviderRef != *expected.ProviderRef {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.Domains != nil && !slices.Equal(snapshot.Domains, expected.Domains) {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	if expected.ChallengeType != nil && snapshot.ChallengeType != *expected.ChallengeType {
		return issuanceRequestSnapshot{}, codedError("acme_operation_snapshot_invalid", ErrConflict)
	}
	return snapshot, nil
}

func (d *Dispatcher) buildRequest(ctx context.Context, lease Lease) (acmeworker.IssueRequest, error) {
	var payload outboxPayload
	if err := json.Unmarshal(lease.Payload, &payload); err != nil {
		return acmeworker.IssueRequest{}, codedError("acme_outbox_payload_invalid", err)
	}
	var request acmeworker.IssueRequest
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		var challengeType, orderStatus string
		var domains []string
		var providerID, renewalOfOrderID *uuid.UUID
		var tenantID, actorID uuid.UUID
		var requestSnapshot []byte
		var orderIssuer *string
		err := tx.QueryRow(ctx, `SELECT certificate_order.challenge_type,certificate_order.domains,
			certificate_order.dns_provider_id,certificate_order.created_by_user_id,certificate_order.status,
			certificate_order.renewal_of_order_id,tenant.id,operation.request_snapshot,certificate_order.issuer
			FROM certificate_orders certificate_order
			JOIN access_scopes scope ON scope.id=certificate_order.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			JOIN users actor ON actor.id=certificate_order.created_by_user_id
			 AND acme_runtime_actor_is_active_048(certificate_order.scope_id,certificate_order.created_by_user_id)
			LEFT JOIN acme_issuance_operations operation
			 ON operation.tenant_scope_id=certificate_order.scope_id
			AND operation.operation_id=certificate_order.id::text
				WHERE certificate_order.scope_id=$1 AND certificate_order.id=$2
				FOR UPDATE OF certificate_order
				FOR SHARE OF scope,tenant,actor`, lease.ScopeID, lease.OrderID).Scan(
			&challengeType, &domains, &providerID, &actorID, &orderStatus, &renewalOfOrderID, &tenantID, &requestSnapshot,
			&orderIssuer)
		if errors.Is(err, pgx.ErrNoRows) {
			return codedError("acme_order_unavailable", ErrConflict)
		}
		if err != nil {
			return err
		}
		if requestSnapshot != nil {
			if _, err := validateIssuanceRequestSnapshot(requestSnapshot, issuanceSnapshotExpectation{
				TenantID: tenantID, ScopeID: lease.ScopeID, ActorUserID: actorID,
				OperationID: lease.OrderID.String(),
			}); err != nil {
				return err
			}
		}
		if orderStatus != "pending" && orderStatus != "validating" &&
			orderStatus != "issuing" && orderStatus != "issued" {
			return codedError("acme_order_state_invalid", ErrConflict)
		}
		var parentStatus *string
		if renewalOfOrderID != nil {
			var status string
			err := tx.QueryRow(ctx, `SELECT status FROM certificate_orders
				WHERE scope_id=$1 AND id=$2 FOR SHARE`, lease.ScopeID, *renewalOfOrderID).Scan(&status)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				parentStatus = &status
			}
		}
		if !renewalParentAuthorityAllows(renewalOfOrderID, parentStatus) {
			return codedError("acme_order_state_invalid", ErrConflict)
		}
		// CERT-RENEW-QUEUED-INTENT-01: a scheduled renewal that has not
		// started (still pending, no CA order yet) follows the certificate's
		// latest setting; turned off or disabled since it was queued, it is
		// skipped before any CA call. Once started it runs to completion.
		if renewalOfOrderID != nil && orderStatus == "pending" {
			var renews bool
			if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT certificate_asset_auto_renew_537(parent.scope_id,parent.issued_asset_id)
				FROM certificate_orders parent WHERE parent.scope_id=$1 AND parent.id=$2),false)`,
				lease.ScopeID, *renewalOfOrderID).Scan(&renews); err != nil {
				return err
			}
			if !renews {
				return codedError(codeRenewalSkipped, ErrConflict)
			}
		}
		if payload.OrderID != lease.OrderID || payload.ChallengeType != challengeType ||
			!slices.Equal(payload.Domains, domains) || !equalOptionalUUID(payload.DNSProviderID, providerID) {
			return codedError("acme_outbox_payload_conflict", ErrConflict)
		}
		workerChallenge := acmeworker.ChallengeType(challengeType)
		providerRef := ""
		var frozenProviderID, zoneID uuid.UUID
		switch workerChallenge {
		case acmeworker.ChallengeDNS01:
			if providerID == nil || *providerID == uuid.Nil {
				return codedError("acme_dns_provider_invalid", ErrConflict)
			}
			var providerStatus, credentialKeyID string
			var credentialVersion int64
			var credentialRevoked, platformManaged, platformActor bool
			// DNS-SEC-20261027-01: the platform DNS copy (migration 569, or
			// its deterministic id) only serves orders a platform
			// administrator placed; a tenant's order (or its renewal child,
			// created as the source creator) is refused before any
			// credential is decrypted.
			if err := tx.QueryRow(ctx, `SELECT provider.status,provider.credential_key_id,
				provider.credential_version,provider.credential_revoked,
				provider.managed_by='platform' OR provider.id=$3,
				`+tenantaccess.PlatformAdminSQL("$4", "NULL")+`
				FROM dns_providers provider
				WHERE provider.scope_id=$1 AND provider.id=$2 FOR SHARE OF provider`,
				lease.ScopeID, *providerID, dnsacme.PlatformProviderCopyID(lease.ScopeID), actorID,
			).Scan(&providerStatus, &credentialKeyID, &credentialVersion, &credentialRevoked,
				&platformManaged, &platformActor); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return codedError("acme_dns_provider_unavailable", ErrConflict)
				}
				return err
			}
			if platformManaged && !platformActor {
				return codedError(codeDNSProviderPlatformManaged, ErrConflict)
			}
			if providerStatus != "verified" || credentialKeyID == "" || credentialVersion <= 0 || credentialRevoked {
				return codedError("acme_dns_provider_unavailable", ErrConflict)
			}
			var err error
			zoneID, err = frozenManagedZone(ctx, tx, lease.ScopeID, *providerID, domains)
			if err != nil {
				return err
			}
			frozenProviderID = *providerID
			providerRef = frozenProviderID.String()
		case acmeworker.ChallengeHTTP01:
			if providerID != nil {
				return codedError("acme_http_provider_conflict", ErrConflict)
			}
		default:
			return codedError("acme_challenge_type_invalid", ErrConflict)
		}
		directoryURL := d.config.DirectoryURL
		if requestSnapshot != nil {
			// An order the worker started on a routed CA stays there (its
			// account, its external order); the snapshot is checked below.
			var snapshot issuanceRequestSnapshot
			if json.Unmarshal(requestSnapshot, &snapshot) == nil && slices.Contains(d.routed, snapshot.DirectoryURL) {
				directoryURL = snapshot.DirectoryURL
			}
		} else if d.directory != nil {
			selected, err := d.directory(ctx, tx, orderIssuer, d.config.DirectoryURL)
			if err != nil {
				return codedError(string(acmeworker.CodeEABRequired), err)
			}
			directoryURL = selected
		}
		accountKeyRef, err := AccountKeyRef(lease.ScopeID, directoryURL)
		if err != nil {
			return err
		}
		certificateKeyRef, err := CertificateKeyRef(lease.ScopeID, lease.OrderID)
		if err != nil {
			return err
		}
		challenge := workerChallenge
		if requestSnapshot != nil {
			if _, err := validateIssuanceRequestSnapshot(requestSnapshot, issuanceSnapshotExpectation{
				TenantID: tenantID, ScopeID: lease.ScopeID, ActorUserID: actorID,
				OperationID:       lease.OrderID.String(),
				CertificateKeyRef: certificateKeyRef, AccountKeyRef: accountKeyRef,
				ProviderRef: &providerRef, Domains: domains, ChallengeType: &challenge,
			}); err != nil {
				return err
			}
		}
		if err := d.keys.ensureKey(ctx, tx, lease.ScopeID, actorID, purposeAccount, accountKeyRef); err != nil {
			return err
		}
		if err := d.keys.ensureKey(ctx, tx, lease.ScopeID, actorID, purposeCertificate, certificateKeyRef); err != nil {
			return err
		}
		if orderStatus == "pending" {
			result, err := tx.Exec(ctx, `UPDATE certificate_orders SET
					status='validating',revision=revision+1,updated_at=statement_timestamp()
					WHERE scope_id=$1 AND id=$2 AND status='pending'`, lease.ScopeID, lease.OrderID)
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return ErrConflict
			}
			if err := audit.New(d.pool).Append(ctx, tx, audit.Event{
				ScopeID: lease.ScopeID, ActorUserID: &actorID,
				Action: "certificate.order.transition", ResourceType: "certificate_order",
				ResourceID: lease.OrderID.String(),
				RequestID:  "acme-order-dispatch:" + lease.OrderID.String(), Result: "success",
				Payload: map[string]any{
					"from_status": "pending", "to_status": "validating",
					"operation": "begin_validation", "reason": "issuance_outbox_claimed",
				},
			}); err != nil {
				return err
			}
		}
		request = acmeworker.IssueRequest{
			TenantID: tenantID, ScopeID: lease.ScopeID, OperationID: lease.OrderID.String(),
			CertificateOrderID: lease.OrderID, ActorUserID: actorID,
			ProviderID: frozenProviderID, ZoneID: zoneID, ProviderRef: providerRef, DirectoryURL: directoryURL,
			AccountKeyRef: accountKeyRef, CertificateKeyRef: certificateKeyRef,
			Contacts: append([]string(nil), d.config.Contacts...), AcceptTerms: d.config.AcceptTerms,
			Domains: append([]string(nil), domains...), ChallengeType: workerChallenge,
		}
		return nil
	})
	if err != nil {
		return acmeworker.IssueRequest{}, err
	}
	return request, nil
}

func renewalParentAuthorityAllows(renewalOfOrderID *uuid.UUID, parentStatus *string) bool {
	if renewalOfOrderID == nil {
		return true
	}
	return parentStatus != nil && (*parentStatus == "active" || *parentStatus == "renewal_due")
}

type managedZone struct {
	id   uuid.UUID
	name string
}

func frozenManagedZone(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, providerID uuid.UUID,
	domains []string,
) (uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT zone.id,zone.name FROM dns_zones zone
		WHERE zone.scope_id=$1 AND zone.provider_id=$2
		ORDER BY char_length(zone.name) DESC,zone.id FOR SHARE OF zone`, scopeID, providerID)
	if err != nil {
		return uuid.Nil, err
	}
	defer rows.Close()
	var zones []managedZone
	for rows.Next() {
		var zone managedZone
		if err := rows.Scan(&zone.id, &zone.name); err != nil {
			return uuid.Nil, err
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, err
	}
	for _, zone := range zones {
		if zone.id == uuid.Nil || zone.name == "" || zone.name != strings.ToLower(strings.TrimSpace(zone.name)) {
			continue
		}
		covers := true
		for _, domain := range domains {
			name := strings.TrimPrefix(domain, "*.")
			if name != zone.name && !strings.HasSuffix(name, "."+zone.name) {
				covers = false
				break
			}
		}
		if covers {
			return zone.id, nil
		}
	}
	return uuid.Nil, codedError("acme_dns_zone_unavailable", ErrConflict)
}

func (d *Dispatcher) complete(ctx context.Context, lease Lease) error {
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		var token uuid.UUID
		var attempts int
		var expiresAt, databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT lease_token,attempts,lease_expires_at,statement_timestamp()
			FROM dns_acme_outbox WHERE id=$1 AND status='processing' FOR UPDATE`, lease.OutboxID).
			Scan(&token, &attempts, &expiresAt, &databaseNow); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrLeaseLost
			}
			return err
		}
		if token != lease.Token || attempts != lease.Attempt || !expiresAt.After(databaseNow) {
			return ErrLeaseLost
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM certificate_orders
			WHERE scope_id=$1 AND id=$2 FOR SHARE`, lease.ScopeID, lease.OrderID).Scan(&status); err != nil {
			return err
		}
		if status != "issued" {
			return ErrConflict
		}
		command, err := tx.Exec(ctx, `UPDATE dns_acme_outbox SET
			status='completed',last_error_code=NULL,last_error_reason=NULL,completed_at=statement_timestamp(),
			updated_at=statement_timestamp()
			WHERE id=$1 AND status='processing' AND lease_token=$2 AND attempts=$3
			 AND lease_expires_at > statement_timestamp()`, lease.OutboxID, lease.Token, lease.Attempt)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return nil
	})
}

func (d *Dispatcher) fail(ctx context.Context, lease Lease, code string, retryAfter time.Duration) error {
	return d.settleFailure(ctx, lease, code, "", retryAfter, terminalFailure(code))
}

// settleFailure records the failure category and, when the CA explained it,
// the redacted CA reason (acmeworker.PublicReason).
func (d *Dispatcher) settleFailure(ctx context.Context, lease Lease, code, reason string, retryAfter time.Duration, terminal bool) error {
	if !validateErrorCode(code) {
		return ErrInvalidInput
	}
	delay := d.retryDelay(lease.Attempt)
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay > d.config.RetryMaximum {
		delay = d.config.RetryMaximum
	}
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `UPDATE dns_acme_outbox SET
			status='failed',last_error_code=$4,last_error_reason=NULLIF($6,''),
			next_attempt_at=statement_timestamp()+($5 * interval '1 millisecond'),
			updated_at=statement_timestamp()
			WHERE id=$1 AND status='processing' AND lease_token=$2 AND attempts=$3
			 AND lease_expires_at > statement_timestamp()`,
			lease.OutboxID, lease.Token, lease.Attempt, code, delay.Milliseconds(), reason)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		// A terminal failure fails the order now (FX05③); claim skips outbox
		// rows whose order already failed, so it is not retried.
		if lease.Attempt < d.config.MaxAttempts && !terminal {
			return nil
		}
		var status string
		var revision int64
		var actorID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT status,revision,created_by_user_id FROM certificate_orders
			WHERE scope_id=$1 AND id=$2 FOR UPDATE`, lease.ScopeID, lease.OrderID).
			Scan(&status, &revision, &actorID); err != nil {
			return err
		}
		if status == "failed" {
			return nil
		}
		if status != "pending" && status != "validating" && status != "issuing" {
			return ErrConflict
		}
		result, err := tx.Exec(ctx, `UPDATE certificate_orders SET
			status='failed',failure_code=$4,failure_reason=NULLIF($6,''),revision=revision+1,updated_at=statement_timestamp()
			WHERE scope_id=$1 AND id=$2 AND status=$3 AND revision=$5`,
			lease.ScopeID, lease.OrderID, status, code, revision, reason)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		if err := audit.New(d.pool).Append(ctx, tx, audit.Event{
			ScopeID: lease.ScopeID, ActorUserID: &actorID,
			Action: "certificate.order.transition", ResourceType: "certificate_order",
			ResourceID: lease.OrderID.String(),
			RequestID:  "acme-order-failure:" + lease.OrderID.String(), Result: "success",
			Payload: map[string]any{
				"from_status": status, "to_status": "failed",
				"operation": "fail_issuance", "reason": code,
			},
		}); err != nil {
			return err
		}
		if code == codeRenewalSkipped {
			return nil // the user's own choice, not a renewal failure
		}
		return certnotify.RenewFailedTx(ctx, tx, d.notices, lease.ScopeID, lease.OrderID, code)
	})
}

func (d *Dispatcher) retryDelay(attempt int) time.Duration {
	delay := d.config.RetryBase
	for index := 1; index < attempt && delay < d.config.RetryMaximum; index++ {
		if delay > d.config.RetryMaximum/2 {
			return d.config.RetryMaximum
		}
		delay *= 2
	}
	if delay > d.config.RetryMaximum {
		return d.config.RetryMaximum
	}
	return delay
}

// terminalFailure reports ACME outcomes a retry cannot change: the CA
// rejected the authorization or order, or the challenge type is not
// available in this deployment.
// codeDNSProviderPlatformManaged: a tenant's DNS-01 order names the
// platform DNS copy; retrying cannot change that, so it is terminal.
const codeDNSProviderPlatformManaged = "acme_dns_provider_platform_managed"

// codeRenewalSkipped: the user turned auto-renew off (or disabled the
// certificate) after the renewal was queued and before it started. Terminal,
// and not a failure the user is alerted about (settleFailure).
const codeRenewalSkipped = "acme_renewal_skipped_auto_renew_off"

func terminalFailure(code string) bool {
	if code == codeDNSProviderPlatformManaged || code == codeRenewalSkipped {
		return true
	}
	switch acmeworker.ErrorCode(code) {
	case acmeworker.CodeAuthorizationInvalid, acmeworker.CodeOrderRejected, acmeworker.CodeHTTP01NodeAggregateRequired,
		acmeworker.CodeHTTP01NodeUnsupported, acmeworker.CodeHTTP01NoServingNode, acmeworker.CodeEABRequired:
		return true
	}
	return false
}

// dispatchTerminal: the code is terminal by kind, or the worker settled the
// operation failed (later claims could only repeat the code, fix-certstuck).
func dispatchTerminal(err error, code string) bool {
	return terminalFailure(code) || acmeworker.IsTerminal(err)
}

func classifyFailure(err error) (string, time.Duration) {
	var workerErr *acmeworker.Error
	if errors.As(err, &workerErr) && validateErrorCode(string(workerErr.Code)) {
		return string(workerErr.Code), workerErr.RetryAfter
	}
	var runtimeErr *runtimeError
	if errors.As(err, &runtimeErr) {
		return runtimeErr.code, 0
	}
	if errors.Is(err, context.Canceled) {
		return string(acmeworker.CodeCancelled), 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return string(acmeworker.CodeTimeout), 0
	}
	return "acme_runtime_failed", 0
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validateErrorCode(code string) bool {
	if code == "" || len(code) > 128 {
		return false
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
