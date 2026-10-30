//go:build integration

package nodeidentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recoveryNode struct {
	pool    *pgxpool.Pool
	service *Service
	clock   *identityTestClock
	signer  *identityTestCA
	fixture identityFixture
	key     ed25519.PrivateKey
	issued  Certificate
	request AuthorizeRequest
}

type recordingAlerts struct{ requests []notification.EnqueueRequest }

func (alerts *recordingAlerts) EnqueueTx(_ context.Context, _ pgx.Tx, request notification.EnqueueRequest) (notification.EnqueueResult, error) {
	alerts.requests = append(alerts.requests, request)
	return notification.EnqueueResult{}, nil
}

func ed25519CSR(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "edge-agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// enrolledRecoveryNode enrolls an Ed25519 node on a platform scope at now.
func enrolledRecoveryNode(t *testing.T) recoveryNode {
	t.Helper()
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityPlatformNode(t, pool, now, "active", "initial_enrollment")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := validAuthorizeRequest(t, ed25519CSR(t, key))
	request.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(t.Context(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	return recoveryNode{pool: pool, service: service, clock: clock, signer: signer, fixture: fixture, key: key,
		issued: completion.Certificate, request: request}
}

func (node recoveryNode) leafDER(t *testing.T) []byte {
	t.Helper()
	block, _ := pem.Decode(node.issued.LeafCertificatePEM)
	if block == nil {
		t.Fatal("issued certificate PEM")
	}
	return block.Bytes
}

// signedRecovery builds the request the edge-agent sends, signed by signingKey
// with a CSR for csrKey.
func (node recoveryNode) signedRecovery(t *testing.T, certificateDER []byte, csrKey, signingKey ed25519.PrivateKey) RecoverRequest {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	requestID := uuid.Must(uuid.NewV7()).String()
	sent := node.clock.now()
	csr := ed25519CSR(t, csrKey)
	message := RecoveryMessage(requestID, sent, node.fixture.nodeID.String(), certificateDER, csr, nonce)
	return RecoverRequest{RequestID: requestID, SentTime: sent, NodeID: node.fixture.nodeID,
		ExpiredCertificateDER: certificateDER, CertificateSigningRequestDER: csr, Nonce: nonce,
		Signature: ed25519.Sign(signingKey, message), GatewayWorkloadIdentity: node.request.GatewayWorkloadIdentity,
		GatewayInstanceID: node.request.GatewayInstanceID, PeerIP: "198.51.100.7"}
}

// GW-02: an expired certificate is re-issued for the same key, once; the new
// certificate is the node's current one and authorizes a session.
func TestRecoverExpiredCertificateSameKey(t *testing.T) {
	node := enrolledRecoveryNode(t)
	alerts := &recordingAlerts{}
	node.service.EnableRecoveryAlerts(alerts)
	// The platform member holding nodes.manage (platform_owner) is the recipient.
	var roleID uuid.UUID
	if err := node.pool.QueryRow(t.Context(), `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_owner' AND system_role`,
		node.fixture.scopeID).Scan(&roleID); errors.Is(err, pgx.ErrNoRows) {
		roleID = uuid.New()
		if _, err := node.pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`,
			roleID, node.fixture.scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if _, err := node.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage')
		ON CONFLICT DO NOTHING`, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := node.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)
		ON CONFLICT DO NOTHING`, node.fixture.scopeID, node.fixture.userID, roleID); err != nil {
		t.Fatal(err)
	}
	request := node.signedRecovery(t, node.leafDER(t), node.key, node.key)
	if _, err := node.service.Recover(t.Context(), request); !errors.Is(err, ErrRecoveryNotExpired) {
		t.Fatalf("Recover(unexpired) = %v, want ErrRecoveryNotExpired", err)
	}

	node.clock.set(node.issued.NotAfter.Add(40 * 24 * time.Hour))
	request = node.signedRecovery(t, node.leafDER(t), node.key, node.key)
	recovered, err := node.service.Recover(t.Context(), request)
	if err != nil {
		t.Fatalf("Recover(expired 40 days) = %v", err)
	}
	if recovered.NodeID != node.fixture.nodeID || recovered.SerialNumber == node.issued.SerialNumber ||
		recovered.NotAfter.Sub(node.clock.now()) != DefaultCertificateTTL {
		t.Fatalf("recovered certificate = %+v", recovered)
	}
	leaf, err := parseSinglePEMCertificate(recovered.LeafCertificatePEM)
	if err != nil || !leaf.PublicKey.(ed25519.PublicKey).Equal(node.key.Public()) {
		t.Fatalf("recovered key differs: %v", err)
	}
	// Same request again (the node lost the response): the same certificate, even after the freshness window.
	node.clock.set(node.clock.now().Add(time.Hour))
	replayed, err := node.service.Recover(t.Context(), request)
	if err != nil || replayed.SerialNumber != recovered.SerialNumber {
		t.Fatalf("idempotent replay = %+v, %v", replayed, err)
	}
	// The nonce under a new request ID is a replay.
	other := request
	other.RequestID = uuid.Must(uuid.NewV7()).String()
	other.SentTime = node.clock.now()
	other.Signature = ed25519.Sign(node.key, RecoveryMessage(other.RequestID, other.SentTime, node.fixture.nodeID.String(),
		other.ExpiredCertificateDER, other.CertificateSigningRequestDER, other.Nonce))
	if _, err := node.service.Recover(t.Context(), other); !errors.Is(err, ErrCertificateNotFound) && !errors.Is(err, ErrRecoveryReplay) {
		t.Fatalf("nonce replay = %v", err)
	}

	var rotation, event string
	var expiredFor time.Duration
	var peer string
	if err := node.pool.QueryRow(t.Context(), `SELECT
			(SELECT rotation_status FROM node_certificates WHERE serial_number=$2),
			(SELECT event_type FROM node_certificate_events WHERE certificate_id=$3),
			(SELECT expired_for FROM node_certificate_recoveries WHERE node_id=$1),
			(SELECT host(peer_ip) FROM node_certificate_recoveries WHERE node_id=$1)`,
		node.fixture.nodeID, node.issued.SerialNumber, recovered.ID).Scan(&rotation, &event, &expiredFor, &peer); err != nil {
		t.Fatal(err)
	}
	if rotation != "retired" || event != "recovered" || expiredFor != 40*24*time.Hour || peer != "198.51.100.7" {
		t.Fatalf("rotation=%s event=%s expired_for=%s peer=%s", rotation, event, expiredFor, peer)
	}
	var popMethod, popAlgorithm, kind string
	if err := node.pool.QueryRow(t.Context(), `SELECT request.pop_method,request.pop_algorithm,cert.issuance_kind
		FROM node_certificate_renewal_requests request JOIN node_certificates cert ON cert.id=request.issued_certificate_id
		WHERE request.request_id=$1`, request.RequestID).Scan(&popMethod, &popAlgorithm, &kind); err != nil ||
		popMethod != "certificate_signature" || popAlgorithm != "ed25519" || kind != "renewal" {
		t.Fatalf("proof %s/%s kind %s, %v", popMethod, popAlgorithm, kind, err)
	}
	snapshot, err := node.service.GetAuthorization(t.Context(), GetAuthorizationRequest{
		NodeID: node.fixture.nodeID, CertificateSerialNumber: recovered.SerialNumber,
		CertificateSHA256: certificateDERDigest(t, recovered), GatewayWorkloadIdentity: node.request.GatewayWorkloadIdentity,
		GatewayInstanceID: node.request.GatewayInstanceID})
	if err != nil || !snapshot.ConnectionAllowed {
		t.Fatalf("GetAuthorization(recovered) = %+v, %v", snapshot, err)
	}
	var audited int
	if err := node.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='node_certificate.lifecycle.recover'
		AND resource_id=$1`, recovered.ID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("recover audit events = %d, %v", audited, err)
	}
	if len(alerts.requests) == 0 || alerts.requests[0].EventType != EventTypeNodeCertificateRecovered ||
		alerts.requests[0].Contexts[notification.ChannelSMS]["expired_for"] != notification.PublicValue("40天0小时") {
		t.Fatalf("recovery alerts = %+v", alerts.requests)
	}
}

func TestRecoverRejections(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		prepare func(t *testing.T, node recoveryNode) RecoverRequest
		want    error
	}{
		{"other key in CSR", func(t *testing.T, node recoveryNode) RecoverRequest {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			return node.signedRecovery(t, node.leafDER(t), other, other)
		}, ErrRecoveryProofInvalid},
		{"signed by other key", func(t *testing.T, node recoveryNode) RecoverRequest {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			return node.signedRecovery(t, node.leafDER(t), node.key, other)
		}, ErrRecoveryProofInvalid},
		{"beyond recovery window", func(t *testing.T, node recoveryNode) RecoverRequest {
			node.clock.set(node.issued.NotAfter.Add(DefaultRecoveryWindow + time.Second))
			return node.signedRecovery(t, node.leafDER(t), node.key, node.key)
		}, ErrRecoveryWindowExceeded},
		{"revoked", func(t *testing.T, node recoveryNode) RecoverRequest {
			if err := node.service.Revoke(t.Context(), RevokeRequest{RequestID: uuid.NewString(), NodeID: node.fixture.nodeID,
				SerialNumber: node.issued.SerialNumber, Reason: "key compromise"}); err != nil {
				t.Fatal(err)
			}
			return node.signedRecovery(t, node.leafDER(t), node.key, node.key)
		}, ErrCertificateRevoked},
		{"disabled node", func(t *testing.T, node recoveryNode) RecoverRequest {
			if _, err := node.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='disabled',revision=revision+1 WHERE id=$1`,
				node.fixture.nodeID); err != nil {
				t.Fatal(err)
			}
			return node.signedRecovery(t, node.leafDER(t), node.key, node.key)
		}, ErrNodeStateDenied},
		{"stale sent time", func(t *testing.T, node recoveryNode) RecoverRequest {
			request := node.signedRecovery(t, node.leafDER(t), node.key, node.key)
			node.clock.set(node.clock.now().Add(RecoveryRequestMaxSkew + time.Second))
			return request
		}, ErrRecoveryProofInvalid},
		{"certificate of another CA", func(t *testing.T, node recoveryNode) RecoverRequest {
			foreign := newIdentityTestCA(t, node.issued.NotBefore)
			signed, err := foreign.SignNodeCertificate(t.Context(), SignRequest{NodeID: node.fixture.nodeID,
				CertificateSigningRequestDER: ed25519CSR(t, node.key), URISAN: NodeSPIFFEPrefix + node.fixture.nodeID.String(),
				NotBefore: node.issued.NotBefore, NotAfter: node.issued.NotAfter})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(signed.LeafCertificatePEM)
			return node.signedRecovery(t, block.Bytes, node.key, node.key)
		}, ErrCertificateNotFound},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			node := enrolledRecoveryNode(t)
			node.clock.set(node.issued.NotAfter.Add(time.Hour))
			request := testCase.prepare(t, node)
			var before int
			if err := node.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_certificates WHERE node_id=$1`,
				node.fixture.nodeID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := node.service.Recover(t.Context(), request); !errors.Is(err, testCase.want) {
				t.Fatalf("Recover() = %v, want %v", err, testCase.want)
			}
			var after, recoveries int
			if err := node.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM node_certificates WHERE node_id=$1),
				(SELECT count(*) FROM node_certificate_recoveries WHERE node_id=$1)`, node.fixture.nodeID).Scan(&after, &recoveries); err != nil ||
				after != before || recoveries != 0 {
				t.Fatalf("refused recovery wrote certificates %d->%d recoveries %d, %v", before, after, recoveries, err)
			}
		})
	}
}
