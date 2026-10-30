package node

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Identity recovery for an interrupted install (fz-x13): the Gateway
// enrollment committed on the controller (certificate issued) but the host
// never wrote its identity directory. Re-registering would be refused (live
// certificate) and a new token cannot replay the pending request, so the
// installer fetches the issued certificate with the same registration
// credential and the Agent assembles the identity from its pending state.

const auditActionRegistrationIdentityFetch = "node.registration.identity_fetch"

// ErrRegisteredIdentityNotFound covers every miss (unknown machine, no
// issued certificate, CSR mismatch) so callers learn nothing about other
// nodes.
var ErrRegisteredIdentityNotFound = errors.New("registered node identity not found")

type RecoverIdentityRequest struct {
	Credential string
	// MachineFingerprint is the installer's registration fingerprint (the
	// same value sent to Register).
	MachineFingerprint string
	// CSRSHA256 is lowercase hex SHA-256 of the CSR DER kept in the Agent's
	// pending enrollment state.
	CSRSHA256 string
	SourceIP  string
	RequestID string
}

// RegisteredIdentity is the enrollment result the Gateway would have
// returned; the Agent validates it against its pending private keys.
type RegisteredIdentity struct {
	NodeID                  uuid.UUID
	SelectedProtocolMajor   uint32
	SelectedProtocolMinor   uint32
	ArtifactEncryptionKeyID string
	Certificate             RegisteredCertificate
}

type RegisteredCertificate struct {
	LeafCertificatePEM []byte
	IssuingChainPEM    [][]byte
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	RenewalAt          time.Time
}

// RecoverRegisteredIdentity returns the live initial certificate of this
// machine's registered node whose enrollment CSR has the given digest.
func (s *Service) RecoverRegisteredIdentity(ctx context.Context, request RecoverIdentityRequest) (RegisteredIdentity, error) {
	if !s.registration.configured() {
		return RegisteredIdentity{}, ErrRegistrationUnavailable
	}
	if !validWriteMetadata(request.RequestID, request.RequestID) ||
		!machineFingerprintPattern.MatchString(request.MachineFingerprint) ||
		!machineFingerprintPattern.MatchString(request.CSRSHA256) {
		return RegisteredIdentity{}, ErrInvalidInput
	}
	// Forged formats fail before any database work, like Register.
	if !registrationCredentialPattern.MatchString(request.Credential) {
		return RegisteredIdentity{}, ErrInvalidRegistrationCredential
	}
	fingerprint, _ := hex.DecodeString(request.MachineFingerprint)
	csrHash, _ := hex.DecodeString(request.CSRSHA256)
	return s.store.recoverRegisteredIdentity(ctx, s.registration, request, fingerprint, csrHash)
}

func (s *Store) recoverRegisteredIdentity(
	ctx context.Context, keys registrationKeys, request RecoverIdentityRequest, fingerprint, csrHash []byte,
) (RegisteredIdentity, error) {
	var result RegisteredIdentity
	found := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := platformScopeID(ctx, tx)
		if err != nil {
			return err
		}
		keyID, err := keys.verifyCredential(scopeID, request.Credential)
		if err != nil {
			return err
		}
		current, err := currentRegistrationKey(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		if err := current.accepts(keyID, request.Credential); err != nil {
			return err
		}
		existing, _, err := findRegisteredNode(ctx, tx, keys, scopeID, fingerprint)
		if err != nil || existing == nil {
			return err
		}
		now := s.now().UTC()
		var major, minor int32
		err = tx.QueryRow(ctx, `
			SELECT cert.leaf_certificate_pem, cert.issuing_chain_pem, cert.serial_number,
			       cert.not_before, cert.not_after, cert.renewal_at,
			       auth.selected_protocol_major, auth.selected_protocol_minor, auth.artifact_key_id
			FROM node_identity_authorizations auth
			JOIN node_certificates cert
			  ON cert.id = auth.issued_certificate_id AND cert.node_id = auth.node_id
			 AND cert.enrollment_authorization_id = auth.id AND cert.issuance_kind = 'initial'
			WHERE auth.node_id = $1 AND auth.status = 'issued' AND auth.csr_sha256 = $2
			  AND cert.status = 'active' AND cert.rotation_status IN ('current','overlap') AND cert.not_after > $3
			ORDER BY auth.completed_at DESC
			LIMIT 1`, existing.ID, csrHash, now).Scan(
			&result.Certificate.LeafCertificatePEM, &result.Certificate.IssuingChainPEM, &result.Certificate.SerialNumber,
			&result.Certificate.NotBefore, &result.Certificate.NotAfter, &result.Certificate.RenewalAt,
			&major, &minor, &result.ArtifactEncryptionKeyID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read registered node certificate: %w", err)
		}
		found = err == nil
		event := audit.Event{
			ScopeID: scopeID, Action: auditActionRegistrationIdentityFetch, ResourceType: "node",
			ResourceID: existing.ID.String(), RequestID: request.RequestID, Result: "success",
			ActorKind: audit.ActorNode, ActorRef: "node:" + existing.ID.String(),
			SourceIP: strings.TrimSpace(request.SourceIP),
			Payload:  map[string]any{"registration_key_id": keyID.String(), "csr_sha256": request.CSRSHA256},
		}
		if found {
			result.NodeID = existing.ID
			result.SelectedProtocolMajor, result.SelectedProtocolMinor = uint32(major), uint32(minor)
			event.Payload["serial_number"] = result.Certificate.SerialNumber
		} else {
			event.Result, event.ReasonCode = "denied", "no_matching_certificate"
		}
		return s.auditor.Append(ctx, tx, event)
	})
	if err != nil {
		return RegisteredIdentity{}, fmt.Errorf("recover registered node identity: %w", err)
	}
	if !found {
		return RegisteredIdentity{}, ErrRegisteredIdentityNotFound
	}
	return result, nil
}
