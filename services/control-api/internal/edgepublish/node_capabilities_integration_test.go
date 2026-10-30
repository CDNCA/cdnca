//go:build integration

package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodecertlifecycle"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNodePublicationCapabilitiesIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		complete bool
		age      time.Duration
		mutation string
		deny     bool
	}{
		{name: "authorization_without_issuance", age: time.Minute, deny: true},
		{name: "issued_after_authorization_expiry", complete: true, age: 10 * time.Minute},
		{name: "retired_ca_remains_trusted", complete: true, age: 10 * time.Minute, mutation: "retired_ca"},
		{name: "revoked_ca", complete: true, age: 10 * time.Minute, mutation: "revoked_ca", deny: true},
		{name: "revoked_certificate", complete: true, age: 10 * time.Minute, mutation: "revoked_certificate", deny: true},
		{name: "overlap_not_current", complete: true, age: 10 * time.Minute, mutation: "overlap", deny: true},
		{name: "expired_certificate", complete: true, age: 10 * time.Minute, mutation: "expired_certificate", deny: true},
		{name: "future_certificate", complete: true, age: 10 * time.Minute, mutation: "future_certificate", deny: true},
		{name: "revoked_artifact_key", complete: true, age: 10 * time.Minute, mutation: "revoked_key", deny: true},
		{name: "missing_active_key", complete: true, age: 10 * time.Minute, mutation: "missing_key", deny: true},
		{name: "disabled_node", complete: true, age: 10 * time.Minute, mutation: "disabled_node", deny: true},
		{name: "foreign_scope", complete: true, age: 10 * time.Minute, mutation: "foreign_scope", deny: true},
		{name: "incomplete_target_set", complete: true, age: 10 * time.Minute, mutation: "missing_node", deny: true},
		{name: "pending_new_authorization_does_not_replace_capabilities", complete: true, age: 10 * time.Minute, mutation: "pending_authorization"},
		{name: "renewed_certificate", complete: true, age: 10 * time.Minute, mutation: "renewal"},
		{name: "scheduled_revocation_before_effective", complete: true, age: 10 * time.Minute, mutation: "scheduled_before"},
		{name: "scheduled_revocation_at_effective", complete: true, age: 10 * time.Minute, mutation: "scheduled_effective", deny: true},
		{name: "foreign_key_binding_rejected_by_database", complete: true, age: 10 * time.Minute, mutation: "foreign_key"},
		{name: "busy_current_certificate_is_retryable_not_deadlocked", complete: true, age: 10 * time.Minute, mutation: "busy_certificate", deny: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublishFixture(t)
			ownerScope, ownerUser := fixture.scopeID, fixture.userID
			if test.mutation == "scheduled_before" || test.mutation == "scheduled_effective" {
				ownerScope, ownerUser = fixture.platformScopeID, fixture.platformUserID
				fixture.nodeID = uuid.New()
				seedPublishNode(t, fixture.pool, ownerScope, ownerUser, fixture.nodeID)
			}
			identity := capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool,
				ownerScope, ownerUser, fixture.nodeID, &agentv1.AgentCapabilities{
					AgentVersion: "1.0.0", BuildId: "publication-integration", OperatingSystem: "linux",
					Architecture: "amd64", Features: siteRuntimeV2NodeFeatures(),
				}, publishTestClock.Add(-test.age), test.complete)
			if test.complete && !identity.Authorization.ExpiresAt.Before(publishTestClock) {
				t.Fatal("fixture did not expire the one-time enrollment authorization")
			}
			now, scopeID := publishTestClock, fixture.scopeID
			nodeIDs := []uuid.UUID{fixture.nodeID}
			var query string
			var args []any
			switch test.mutation {
			case "retired_ca":
				query, args = `UPDATE node_ca_key_epochs SET status='retired',retired_at=$2 WHERE id=$1`, []any{identity.CAEpochID, now}
			case "revoked_ca":
				query, args = `UPDATE node_ca_key_epochs SET status='revoked',revoked_at=$2,revocation_reason='test' WHERE id=$1`, []any{identity.CAEpochID, now}
			case "revoked_certificate":
				query, args = `UPDATE node_certificates SET status='revoked',revoked_at=$2,revocation_reason='test' WHERE id=$1`, []any{identity.Completion.Certificate.ID, now}
			case "overlap":
				query, args = `UPDATE node_certificates SET rotation_status='overlap',overlap_until=$2,lifecycle_revision=lifecycle_revision+1 WHERE id=$1`, []any{identity.Completion.Certificate.ID, now.Add(time.Minute)}
			case "expired_certificate":
				now = identity.Completion.Certificate.NotAfter
			case "future_certificate":
				now = identity.Completion.Certificate.NotBefore.Add(-time.Second)
			case "revoked_key":
				query, args = `UPDATE node_artifact_encryption_keys SET status='revoked',deactivated_at=$2,deactivation_reason='test' WHERE id=$1`, []any{identity.Completion.ArtifactEncryptionKeyID, now}
			case "missing_key":
				query, args = `UPDATE node_identity_state SET active_artifact_key_id=NULL,authorization_revision=authorization_revision+1,updated_at=$2 WHERE node_id=$1`, []any{fixture.nodeID, now}
			case "disabled_node":
				query, args = `UPDATE nodes SET admin_state='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`, []any{fixture.nodeID, now}
			case "foreign_scope":
				scopeID = fixture.platformScopeID
			case "missing_node":
				nodeIDs = append(nodeIDs, uuid.New())
			case "busy_certificate":
				blocker, err := fixture.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = blocker.Rollback(context.Background()) }()
				if _, err := blocker.Exec(t.Context(), `SELECT 1 FROM node_certificates WHERE id=$1 FOR UPDATE`, identity.Completion.Certificate.ID); err != nil {
					t.Fatal(err)
				}
			case "pending_authorization":
				capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
					fixture.nodeID, &agentv1.AgentCapabilities{AgentVersion: "new", BuildId: "pending",
						OperatingSystem: "linux", Architecture: "amd64"}, now.Add(-time.Minute), false)
			case "foreign_key":
				foreignID := uuid.New()
				seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, foreignID)
				_, err := fixture.pool.Exec(t.Context(), `UPDATE node_identity_state SET active_artifact_key_id=(
					SELECT active_artifact_key_id FROM node_identity_state WHERE node_id=$2),
					authorization_revision=authorization_revision+1,updated_at=$3 WHERE node_id=$1`, fixture.nodeID, foreignID, now)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
					t.Fatalf("cross-node identity key binding not rejected: %v", err)
				}
			case "scheduled_before", "scheduled_effective":
				if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
					SELECT id,'nodes.manage' FROM roles WHERE scope_id=$1 AND name='platform_owner'
					ON CONFLICT DO NOTHING`, fixture.platformScopeID); err != nil {
					t.Fatal(err)
				}
				lifecycle, err := nodecertlifecycle.NewStore(fixture.pool, nodecertlifecycle.Config{
					Clock: func() time.Time { return publishTestClock }, OverlapWindow: time.Minute,
					AuthorizationSnapshotTTL: time.Minute, MaxScheduledRevocation: time.Hour,
				})
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode(identity.Completion.Certificate.LeafCertificatePEM)
				_, err = lifecycle.RevokeCertificate(t.Context(), nodecertlifecycle.Actor{
					ScopeID: fixture.platformScopeID, UserID: fixture.platformUserID, ScopeKind: "platform",
				}, nodecertlifecycle.RevokeCertificateRequest{
					RequestID: uuid.New(), NodeID: fixture.nodeID, SerialNumber: identity.Completion.Certificate.SerialNumber,
					LeafDERSHA256: sha256.Sum256(block.Bytes), Reason: "test scheduled revocation",
					EffectiveAt: now.Add(time.Minute), RequestTraceID: "publication-capability-revocation",
				})
				if err != nil {
					t.Fatalf("real scheduled revocation: %v", err)
				}
				if test.mutation == "scheduled_effective" {
					now = now.Add(time.Minute)
				}
			case "renewal":
				identity.Clock = identity.Completion.Certificate.RenewalAt.Add(time.Second)
				block, _ := pem.Decode(identity.Completion.Certificate.LeafCertificatePEM)
				renewed, err := identity.Service.Renew(t.Context(), nodeidentity.RenewRequest{
					RequestID: uuid.NewString(), NodeID: fixture.nodeID,
					CurrentSerialNumber:      identity.Completion.Certificate.SerialNumber,
					CurrentCertificateSHA256: sha256.Sum256(block.Bytes), CertificateSigningRequestDER: identity.CSRDER,
					GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/capability-test", GatewayInstanceID: "capability-test",
				})
				if err != nil {
					t.Fatalf("real certificate renewal: %v", err)
				}
				var enrollment *uuid.UUID
				if err := fixture.pool.QueryRow(t.Context(), `SELECT enrollment_authorization_id FROM node_certificates WHERE id=$1`, renewed.ID).Scan(&enrollment); err != nil || enrollment != nil {
					t.Fatalf("renewal must not reuse initial enrollment FK: %v", err)
				}
				now = identity.Clock
			}
			if query != "" {
				if _, err := fixture.pool.Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if test.mutation != "disabled_node" {
				if err := claimEligibleNodes(t.Context(), tx, fixture.scopeID, []uuid.UUID{fixture.nodeID}, now); err != nil {
					t.Fatal(err)
				}
			}
			readContext := t.Context()
			if test.mutation == "busy_certificate" {
				var cancel context.CancelFunc
				readContext, cancel = context.WithTimeout(readContext, 2*time.Second)
				defer cancel()
			}
			capabilities, err := loadSiteRuntimeV2TargetCapabilities(readContext, tx, scopeID, nodeIDs, now)
			if readContext.Err() != nil {
				t.Fatalf("capability reader waited on inverse certificate/node lock order: %v", readContext.Err())
			}
			accepted := err == nil && len(capabilities[fixture.nodeID]) != 0
			if accepted == test.deny {
				t.Fatalf("publication capability eligibility=%v want=%v (error=%v)", accepted, !test.deny, err)
			}
			if test.name == "issued_after_authorization_expiry" {
				for _, target := range []struct {
					table, where string
					id           any
				}{
					{"node_certificates", "id", identity.Completion.Certificate.ID},
					{"node_ca_key_epochs", "id", identity.CAEpochID},
					{"node_artifact_encryption_keys", "id", identity.Completion.ArtifactEncryptionKeyID},
					{"node_identity_state", "node_id", fixture.nodeID},
				} {
					contender, err := fixture.pool.Begin(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					_, lockErr := contender.Exec(t.Context(), "SELECT 1 FROM "+target.table+" WHERE "+target.where+"=$1 FOR UPDATE NOWAIT", target.id)
					_ = contender.Rollback(context.Background())
					var pgErr *pgconn.PgError
					if !errors.As(lockErr, &pgErr) || pgErr.Code != "55P03" {
						t.Fatalf("identity fact %s was not locked: %v", target.table, lockErr)
					}
				}
			}
		})
	}
}
