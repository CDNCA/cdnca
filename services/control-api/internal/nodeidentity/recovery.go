package nodeidentity

// Expired node certificate self-recovery (ADR 0013 section 6.1 b, GW-02).
//
// A node whose certificate expired while it could not reach the control plane
// signs a RecoverCertificate request with its existing Ed25519 private key.
// The request is accepted when the expired certificate is the node's last
// current certificate, issued by an unrevoked CA epoch of this installation,
// not revoked, expired no longer than RecoveryWindow, the CSR carries the same
// public key, the signature verifies, |now - sent_time| <= 5 minutes and the
// nonce is new. The re-issued certificate is an ordinary renewal (a renewal
// request proven with pop_method 'certificate_signature'), so every reader of
// the renewal chain treats it like a renewed certificate.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrRecoveryWindowExceeded: the certificate expired longer than RecoveryWindow ago.
	ErrRecoveryWindowExceeded = errors.New("node certificate recovery window exceeded")
	// ErrRecoveryProofInvalid: signature, key or freshness check failed.
	ErrRecoveryProofInvalid = errors.New("node certificate recovery proof is invalid")
	// ErrRecoveryNotExpired: an unexpired certificate renews over mTLS instead.
	ErrRecoveryNotExpired = errors.New("node certificate has not expired")
	// ErrRecoveryReplay: the nonce was already used.
	ErrRecoveryReplay = errors.New("node certificate recovery nonce was already used")
)

const (
	EventTypeNodeCertificateRecovered = notification.EventTypeNodeCertificateRecovered
	recoveryTemplateID                = "node.certificate.recovered.zh-cn"
	recoveryNotifyPermission          = "nodes.manage"
	recoveryRequestTTL                = 10 * time.Minute
	recoveryNonceBytes                = 32
)

// RecoverRequest is the Agent's signed request plus the transport facts the
// Gateway observed.
type RecoverRequest struct {
	RequestID                    string
	SentTime                     time.Time
	NodeID                       uuid.UUID
	ExpiredCertificateDER        []byte
	CertificateSigningRequestDER []byte
	Nonce                        []byte
	Signature                    []byte
	GatewayWorkloadIdentity      string
	GatewayInstanceID            string
	PeerIP                       string
}

// RecoveryAlertEnqueuer is notification.Store.
type RecoveryAlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// RecoveryMessage is the canonical message the node signs. The edge-agent
// (internal/enrollment/recovery.go) builds the same bytes; both share the test
// vector in recovery_test.go.
func RecoveryMessage(requestID string, sentTime time.Time, nodeID string, certificateDER, csrDER, nonce []byte) []byte {
	certificateDigest, csrDigest := sha256.Sum256(certificateDER), sha256.Sum256(csrDER)
	return []byte(strings.Join([]string{
		RecoveryProofSignatureTag,
		"request_id=" + requestID,
		"sent_time=" + sentTime.UTC().Format(time.RFC3339Nano),
		"node_id=" + nodeID,
		"certificate_sha256=" + hex.EncodeToString(certificateDigest[:]),
		"csr_sha256=" + hex.EncodeToString(csrDigest[:]),
		"nonce=" + hex.EncodeToString(nonce),
	}, "\n"))
}

type normalizedRecover struct {
	normalizedRenew
	expired   *x509.Certificate
	nonce     []byte
	signature []byte
	message   []byte
	peerIP    *netip.Addr
	sentTime  time.Time
}

func normalizeRecover(request RecoverRequest) (normalizedRecover, error) {
	requestID, err := uuid.Parse(request.RequestID)
	if err != nil || requestID.String() != request.RequestID || request.NodeID == uuid.Nil ||
		request.SentTime.IsZero() || len(request.Nonce) != recoveryNonceBytes ||
		len(request.Signature) != ed25519.SignatureSize || len(request.ExpiredCertificateDER) == 0 ||
		len(request.ExpiredCertificateDER) > 64<<10 {
		return normalizedRecover{}, ErrInvalidInput
	}
	var peer *netip.Addr
	if request.PeerIP != "" {
		address, err := netip.ParseAddr(request.PeerIP)
		if err != nil {
			return normalizedRecover{}, ErrInvalidInput
		}
		address = address.Unmap()
		peer = &address
	}
	expired, err := x509.ParseCertificate(request.ExpiredCertificateDER)
	if err != nil || len(expired.URIs) != 1 || expired.URIs[0].String() != NodeSPIFFEPrefix+request.NodeID.String() ||
		expired.SerialNumber == nil || expired.SerialNumber.Sign() <= 0 {
		return normalizedRecover{}, ErrRecoveryProofInvalid
	}
	renew, err := normalizeRenew(RenewRequest{RequestID: request.RequestID, NodeID: request.NodeID,
		CurrentSerialNumber:          strings.ToLower(expired.SerialNumber.Text(16)),
		CurrentCertificateSHA256:     sha256.Sum256(expired.Raw),
		CertificateSigningRequestDER: request.CertificateSigningRequestDER,
		GatewayWorkloadIdentity:      request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
	if err != nil {
		return normalizedRecover{}, err
	}
	// Same key: the CSR, the expired certificate and the signature use one Ed25519 key.
	certificateKey, certificateOK := expired.PublicKey.(ed25519.PublicKey)
	csrKey, csrOK := renew.CSR.PublicKey.(ed25519.PublicKey)
	if !certificateOK || !csrOK || !bytes.Equal(certificateKey, csrKey) {
		return normalizedRecover{}, ErrRecoveryProofInvalid
	}
	message := RecoveryMessage(request.RequestID, request.SentTime, request.NodeID.String(),
		request.ExpiredCertificateDER, renew.CSRDER, request.Nonce)
	if !ed25519.Verify(certificateKey, message, request.Signature) {
		return normalizedRecover{}, ErrRecoveryProofInvalid
	}
	// The request digest binds the nonce too (idempotent replay of the same request only).
	payload, err := json.Marshal(struct {
		Renew [32]byte `json:"renew"`
		Nonce string   `json:"nonce"`
	}{renew.RequestDigest, hex.EncodeToString(request.Nonce)})
	if err != nil {
		return normalizedRecover{}, ErrInvalidInput
	}
	renew.RequestDigest = sha256.Sum256(append([]byte("recovery\x00"), payload...))
	return normalizedRecover{normalizedRenew: renew, expired: expired, nonce: bytes.Clone(request.Nonce),
		signature: bytes.Clone(request.Signature), message: message, peerIP: peer, sentTime: request.SentTime}, nil
}

// EnableRecoveryAlerts announces recoveries in the notification center.
func (s *Service) EnableRecoveryAlerts(enqueuer RecoveryAlertEnqueuer) { s.recoveryAlerts = enqueuer }

// Recover re-issues an expired node certificate for the same key.
func (s *Service) Recover(ctx context.Context, request RecoverRequest) (Certificate, error) {
	now := s.config.Clock().UTC().Truncate(time.Second)
	normalized, err := normalizeRecover(request)
	if err != nil {
		return Certificate{}, err
	}
	claim, expiredFor, err := s.store.prepareRecovery(ctx, normalized, s.config.NewID, now, s.config.RecoveryWindow,
		now.Add(recoveryRequestTTL), now.Add(s.config.SigningLeaseTTL))
	if err != nil {
		return Certificate{}, err
	}
	if claim.Existing != nil {
		return cloneCertificate(*claim.Existing), nil
	}
	resetSigning := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.store.resetRenewalSigning(cleanupCtx, claim.RequestID, claim.LeaseID)
	}
	signed, err := s.sign(ctx, claim.NodeID, claim.CSRDER, "renewal", now)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	persisted, err := s.prepareCertificate(signed, normalized.CSR, claim.NodeID, claim.CSRHash, now)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	certificateID, eventID, err := s.twoIDs()
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	persisted.ID, persisted.Certificate.ID = certificateID, certificateID
	persisted.RenewalRequestID, persisted.ReplacesCertificateID = &claim.RequestID, &claim.CurrentCertificateID
	certificate, err := s.store.finalizeRecovery(ctx, claim, normalized, persisted,
		s.config.Clock().UTC().Truncate(time.Microsecond), eventID, expiredFor, s.recoveryAlerts)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	return certificate, nil
}

// prepareRecovery claims signing for a new recovery, or returns the issued
// certificate of an identical earlier request. Read-only gates run first so a
// refused recovery writes nothing.
func (s *Store) prepareRecovery(ctx context.Context, input normalizedRecover, newID func() (uuid.UUID, error),
	now time.Time, window time.Duration, expiresAt, leaseExpires time.Time) (renewalSigningClaim, time.Duration, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	claim := renewalSigningClaim{RequestID: input.RequestID, NodeID: input.NodeID, CSRDER: input.CSRDER, CSRHash: input.CSRHash}
	var digest []byte
	var status string
	var issuedID *uuid.UUID
	var signingExpires *time.Time
	var requestExpires time.Time
	err = tx.QueryRow(ctx, `SELECT request_digest,status,issued_certificate_id,signing_lease_expires_at,expires_at
		FROM node_certificate_renewal_requests WHERE request_id=$1 FOR UPDATE`, input.RequestID).Scan(
		&digest, &status, &issuedID, &signingExpires, &requestExpires)
	switch {
	case err == nil:
		if !equalDigest(digest, input.RequestDigest[:]) {
			return renewalSigningClaim{}, 0, ErrIdempotencyConflict
		}
		if status == "issued" && issuedID != nil {
			certificate, err := loadCertificateByID(ctx, tx, *issuedID)
			if err != nil {
				return renewalSigningClaim{}, 0, err
			}
			claim.Existing = &certificate
			return claim, 0, tx.Commit(ctx)
		}
		if status == "signing" && signingExpires != nil && now.Before(*signingExpires) {
			return renewalSigningClaim{}, 0, ErrIssuanceInProgress
		}
		// A pending/expired attempt of the same request: start over with a fresh request ID.
		return renewalSigningClaim{}, 0, ErrAuthorizationExpired
	case !errors.Is(err, pgx.ErrNoRows):
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	// Freshness applies to new requests only: an issued request replays (the
	// node lost the response) whenever it is resent unchanged.
	if skew := now.Sub(input.sentTime); skew > RecoveryRequestMaxSkew || skew < -RecoveryRequestMaxSkew {
		return renewalSigningClaim{}, 0, ErrRecoveryProofInvalid
	}
	var used bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_certificate_recoveries WHERE nonce=$1)`, input.nonce).
		Scan(&used); err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	} else if used {
		return renewalSigningClaim{}, 0, ErrRecoveryReplay
	}
	var certificateStatus, rotationStatus, nodeState, epochStatus string
	var notAfter time.Time
	var revoked bool
	var installationID string
	var caPEM []byte
	err = tx.QueryRow(ctx, `
		SELECT cert.id,cert.status,cert.rotation_status,cert.not_after,node.admin_state,epoch.status,
		       epoch.ca_certificate_pem,COALESCE(cert.installation_id,''),
		       EXISTS(SELECT 1 FROM node_certificate_revocations revoked WHERE revoked.certificate_id=cert.id)
		FROM node_certificates cert
		JOIN nodes node ON node.id=cert.node_id
		JOIN control_installation_entitlement installation
		  ON installation.singleton AND installation.installation_id=cert.installation_id
		JOIN node_ca_key_epochs epoch ON epoch.id=cert.ca_epoch_id AND epoch.installation_id=cert.installation_id
		WHERE cert.node_id=$1 AND cert.serial_number=$2 AND cert.leaf_der_sha256=$3
		FOR UPDATE OF cert,node`, input.NodeID, input.CurrentSerial, input.CurrentCertificateSHA256[:]).Scan(
		&claim.CurrentCertificateID, &certificateStatus, &rotationStatus, &notAfter, &nodeState, &epochStatus,
		&caPEM, &installationID, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return renewalSigningClaim{}, 0, ErrCertificateNotFound
	}
	if err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	if revoked || certificateStatus == "revoked" || epochStatus == "revoked" {
		return renewalSigningClaim{}, 0, ErrCertificateRevoked
	}
	// Only the node's last current certificate: an overlap/retired one means a
	// newer certificate exists for this node.
	if certificateStatus != "active" || rotationStatus != "current" || epochStatus != "active" {
		return renewalSigningClaim{}, 0, ErrCertificateNotFound
	}
	if now.Before(notAfter) {
		return renewalSigningClaim{}, 0, ErrRecoveryNotExpired
	}
	expiredFor := now.Sub(notAfter)
	if expiredFor > window {
		return renewalSigningClaim{}, 0, ErrRecoveryWindowExceeded
	}
	if !renewalAllowedForNodeState(nodeState, input.NodeID) {
		return renewalSigningClaim{}, 0, ErrNodeStateDenied
	}
	// The expired leaf must chain to the stored CA epoch (another CA's
	// certificate with the same serial and digest cannot exist, but verify
	// anyway: the request carried the DER).
	authority, err := parseSinglePEMCertificate(caPEM)
	if err != nil || input.expired.CheckSignatureFrom(authority) != nil {
		return renewalSigningClaim{}, 0, ErrRecoveryProofInvalid
	}
	leaseID, err := newID()
	if err != nil || leaseID == uuid.Nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	claim.LeaseID = leaseID
	if _, err := tx.Exec(ctx, `
		UPDATE node_certificate_renewal_requests
		SET status='expired',signing_lease_id=NULL,signing_lease_expires_at=NULL
		WHERE current_certificate_id=$1 AND status IN ('pending','signing')`, claim.CurrentCertificateID); err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO node_certificate_renewal_requests (
			request_id,request_digest,node_id,current_certificate_id,current_serial_number,
			csr_der,csr_sha256,gateway_workload_identity,gateway_instance_id,status,
			created_at,expires_at,signing_attempt,signing_lease_id,signing_lease_expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11,0,NULL,NULL)`, input.RequestID,
		input.RequestDigest[:], input.NodeID, claim.CurrentCertificateID, input.CurrentSerial,
		input.CSRDER, input.CSRHash[:], input.GatewayWorkloadIdentity, input.GatewayInstanceID, now, expiresAt)
	if err != nil {
		if uniqueViolation(err) {
			return renewalSigningClaim{}, 0, ErrRenewalConflict
		}
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	if _, err := tx.Exec(ctx, `UPDATE node_certificate_renewal_requests SET status='signing',
		signing_attempt=signing_attempt+1,signing_lease_id=$2,signing_lease_expires_at=$3 WHERE request_id=$1`,
		input.RequestID, leaseID, leaseExpires); err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	if err := tx.Commit(ctx); err != nil {
		return renewalSigningClaim{}, 0, ErrPersistence
	}
	return claim, expiredFor, nil
}

// finalizeRecovery binds the re-issued certificate as the node's current one
// in one transaction: the expired current certificate is retired, the renewal
// request records the cryptographic proof and the rotation, a 'recovered'
// event and the recovery fact are appended and the authorization revision
// advances. The notification is enqueued under a savepoint: a failed message
// never undoes the recovery.
func (s *Store) finalizeRecovery(ctx context.Context, claim renewalSigningClaim, input normalizedRecover,
	certificate persistedCertificate, now time.Time, eventID uuid.UUID, expiredFor time.Duration,
	alerts RecoveryAlertEnqueuer) (Certificate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var status, nodeState string
	var lease *uuid.UUID
	var ownerScopeID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT request.status,request.signing_lease_id,node.admin_state,node.scope_id
		FROM node_certificate_renewal_requests request JOIN nodes node ON node.id=request.node_id
		WHERE request.request_id=$1 AND request.node_id=$2 FOR UPDATE OF request,node`, claim.RequestID, claim.NodeID).Scan(
		&status, &lease, &nodeState, &ownerScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrCertificateNotFound
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	if status != "signing" || lease == nil || *lease != claim.LeaseID {
		return Certificate{}, ErrIssuanceInProgress
	}
	if !renewalAllowedForNodeState(nodeState, claim.NodeID) {
		return Certificate{}, ErrNodeStateDenied
	}
	var installationID string
	var epochID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT installation.installation_id,epoch.id
		FROM control_installation_entitlement installation
		JOIN node_ca_key_epochs epoch ON epoch.installation_id=installation.installation_id
		WHERE installation.singleton AND epoch.status='active' AND epoch.ca_certificate_sha256=$1
		  AND epoch.not_before<=$2 AND epoch.not_after>=$3
		FOR SHARE OF installation,epoch`, certificate.IssuerCAHash[:], certificate.NotBefore, certificate.NotAfter).Scan(
		&installationID, &epochID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrCertificateInvalid
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	// The expired current certificate leaves the current slot (current ->
	// overlap ending at its expiry -> retired), as re-enrollment does.
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`UPDATE node_certificates SET rotation_status='retired',lifecycle_revision=lifecycle_revision+1
		 WHERE node_id=$1 AND status='active' AND rotation_status='overlap' AND not_after<=$2`, []any{claim.NodeID, now}},
		{`UPDATE node_certificates SET rotation_status='overlap',lifecycle_revision=lifecycle_revision+1,overlap_until=not_after
		 WHERE id=$1 AND status='active' AND rotation_status='current' AND not_after<=$2`, []any{claim.CurrentCertificateID, now}},
		{`UPDATE node_certificates SET rotation_status='retired',lifecycle_revision=lifecycle_revision+1
		 WHERE id=$1 AND status='active' AND rotation_status='overlap'`, []any{claim.CurrentCertificateID}},
	} {
		if _, err := tx.Exec(ctx, step.query, step.args...); err != nil {
			return Certificate{}, ErrPersistence
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_certificates (
			id,node_id,issuance_kind,enrollment_authorization_id,renewal_request_id,replaces_certificate_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at,
			owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,rotation_status,lifecycle_revision,
			lifecycle_request_id,lifecycle_request_digest,lifecycle_bound_at
		) VALUES ($1,$2,'renewal',NULL,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'active',$15,
			$16,$17,$18,$19,'current',1,$3,$20,$15)`,
		certificate.ID, claim.NodeID, claim.RequestID, claim.CurrentCertificateID, certificate.SerialNumber,
		certificate.CSRHash[:], certificate.PublicKeyHash[:], certificate.URISAN, certificate.NotBefore,
		certificate.NotAfter, certificate.RenewalAt, certificate.LeafCertificatePEM, certificate.IssuingChainPEM,
		certificate.LeafHash[:], now, ownerScopeID, installationID, epochID, certificate.LeafDERHash[:],
		input.RequestDigest[:]); err != nil {
		if uniqueViolation(err) {
			return Certificate{}, ErrCertificateInvalid
		}
		return Certificate{}, ErrPersistence
	}
	messageDigest := sha256.Sum256(input.message)
	for _, step := range []struct {
		query string
		args  []any
	}{
		{`UPDATE node_certificate_renewal_requests SET owner_scope_id=$2,installation_id=$3,ca_epoch_id=$4,
			current_leaf_der_sha256=$5,pop_status='cryptographic_proven',pop_revision=1,
			pop_method='certificate_signature',pop_message_sha256=$6,pop_algorithm='ed25519',pop_signature=$7,
			pop_observed_at=$8 WHERE request_id=$1 AND pop_status='legacy_unbound'`,
			[]any{claim.RequestID, ownerScopeID, installationID, epochID, input.CurrentCertificateSHA256[:],
				messageDigest[:], input.signature, now}},
		{`UPDATE node_certificate_renewal_requests SET issued_leaf_der_sha256=$2,issued_ca_epoch_id=$3,
			rotation_bound_at=$4,overlap_until=$4,pop_revision=pop_revision+1 WHERE request_id=$1 AND rotation_bound_at IS NULL`,
			[]any{claim.RequestID, certificate.LeafDERHash[:], epochID, now}},
		{`UPDATE node_certificate_renewal_requests SET status='issued',signing_lease_id=NULL,signing_lease_expires_at=NULL,
			issued_certificate_id=$2,completed_at=$3 WHERE request_id=$1 AND status='signing'`,
			[]any{claim.RequestID, certificate.ID, now}},
	} {
		result, err := tx.Exec(ctx, step.query, step.args...)
		if err != nil || result.RowsAffected() != 1 {
			return Certificate{}, ErrPersistence
		}
	}
	var revision int64
	if err := tx.QueryRow(ctx, `UPDATE node_identity_state SET authorization_revision=authorization_revision+1,updated_at=$2
		WHERE node_id=$1 RETURNING authorization_revision`, claim.NodeID, now).Scan(&revision); err != nil {
		return Certificate{}, ErrPersistence
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_certificate_events
			(id,node_id,certificate_id,event_type,related_certificate_id,authorization_revision,occurred_at)
		VALUES ($1,$2,$3,'recovered',$4,$5,$6)`, eventID, claim.NodeID, certificate.ID,
		claim.CurrentCertificateID, revision, now); err != nil {
		return Certificate{}, ErrPersistence
	}
	var peer any
	if input.peerIP != nil {
		peer = input.peerIP.String()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_certificate_recoveries(request_id,node_id,nonce,expired_certificate_id,
			issued_certificate_id,gateway_instance_id,peer_ip,expired_for,recovered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,make_interval(secs => $8),$9)`, claim.RequestID, claim.NodeID, input.nonce,
		claim.CurrentCertificateID, certificate.ID, input.GatewayInstanceID, peer, expiredFor.Seconds(), now); err != nil {
		if uniqueViolation(err) {
			return Certificate{}, ErrRecoveryReplay
		}
		return Certificate{}, ErrPersistence
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: ownerScopeID, Action: "node_certificate.lifecycle.recover",
		ResourceType: "node_certificate", ResourceID: certificate.ID.String(), RequestID: claim.RequestID.String(),
		Result: "success", Payload: map[string]any{"node_id": claim.NodeID.String(),
			"expired_serial_number": input.CurrentSerial, "new_serial_number": certificate.SerialNumber,
			"expired_for_seconds": int64(expiredFor / time.Second), "gateway_instance_id": input.GatewayInstanceID,
			"authorization_revision": revision}}); err != nil {
		return Certificate{}, ErrPersistence
	}
	if alerts != nil {
		recoveryAlert(ctx, tx, alerts, claim, input, certificate.Certificate, expiredFor, now)
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, ErrPersistence
	}
	return cloneCertificate(certificate.Certificate), nil
}

func recoveryAlert(ctx context.Context, tx pgx.Tx, alerts RecoveryAlertEnqueuer, claim renewalSigningClaim,
	input normalizedRecover, issued Certificate, expiredFor time.Duration, now time.Time) {
	savepoint, err := tx.Begin(ctx)
	if err == nil {
		err = enqueueRecoveryAlert(ctx, savepoint, alerts, claim, input, issued, expiredFor, now)
		if err != nil {
			_ = savepoint.Rollback(ctx)
		} else {
			err = savepoint.Commit(ctx)
		}
	}
	if err != nil {
		slog.Warn("node certificate recovery alert not enqueued", "node_id", claim.NodeID, "error", err)
	}
}

func enqueueRecoveryAlert(ctx context.Context, tx pgx.Tx, alerts RecoveryAlertEnqueuer, claim renewalSigningClaim,
	input normalizedRecover, issued Certificate, expiredFor time.Duration, now time.Time) error {
	var scope uuid.UUID
	var name, address string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT node.scope_id,node.name,COALESCE(host(node.ipv4),host(node.ipv6),''),
			scope.kind='platform' AND scope.tenant_id IS NULL
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id WHERE node.id=$1`, claim.NodeID).
		Scan(&scope, &name, &address, &platform); err != nil {
		return err
	}
	if !platform {
		// Tenant-owned (marketplace seller) nodes are not alerted, like node security events.
		return nil
	}
	if address == "" {
		address = "-"
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, scope, recoveryNotifyPermission)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	sms := notification.TemplateContext{
		"node_name": notification.PublicValue(name), "node_ip": notification.PublicValue(address),
		"expired_for": notification.PublicValue(recoveryDurationText(expiredFor)),
		"not_after":   notification.PublicValue(issued.NotAfter.UTC().Format(time.DateTime)),
	}
	email := notification.TemplateContext{
		"expired_at":   notification.PublicValue(input.expired.NotAfter.UTC().Format(time.DateTime)),
		"recovered_at": notification.PublicValue(now.UTC().Format(time.DateTime)),
	}
	for key, value := range sms {
		email[key] = value
	}
	source := "node-certificate-recovered/" + claim.RequestID.String()
	for _, recipient := range recipients {
		if _, err := alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: scope, RecipientID: recipient,
			SourceEventID: source, EventType: EventTypeNodeCertificateRecovered, Policy: notification.DeliverySystemRequired,
			Templates: map[notification.Channel]notification.TemplateRef{
				notification.ChannelSMS:   {ID: recoveryTemplateID, Version: 1, Channel: notification.ChannelSMS},
				notification.ChannelEmail: {ID: recoveryTemplateID, Version: 1, Channel: notification.ChannelEmail},
			},
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: sms, notification.ChannelEmail: email},
			AuditRequestID: source,
		}); err != nil {
			return err
		}
	}
	return nil
}

// recoveryDurationText renders how long the certificate had been expired ("3天4小时", "25分钟").
func recoveryDurationText(value time.Duration) string {
	days, hours, minutes := int64(value/(24*time.Hour)), int64(value%(24*time.Hour)/time.Hour), int64(value%time.Hour/time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%d天%d小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	default:
		return fmt.Sprintf("%d分钟", minutes)
	}
}
