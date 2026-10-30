//go:build integration

package migrations_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pluginWebhook084Now = time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)

type pluginWebhookIdentity084 struct {
	tenantID       uuid.UUID
	tenantScope    uuid.UUID
	foreignTenant  uuid.UUID
	foreignScope   uuid.UUID
	platformScope  uuid.UUID
	ownerUser      uuid.UUID
	adminUser      uuid.UUID
	memberUser     uuid.UUID
	viewerUser     uuid.UUID
	customUser     uuid.UUID
	foreignUser    uuid.UUID
	platformOwner  uuid.UUID
	platformAdmin  uuid.UUID
	platformReader uuid.UUID
	ownerRole      uuid.UUID
	adminRole      uuid.UUID
	memberRole     uuid.UUID
	viewerRole     uuid.UUID
	platformRoles  map[string]uuid.UUID
}

type pluginWebhookResource084 struct {
	subscription uuid.UUID
	secret       uuid.UUID
}

type pluginWebhookCommandFacts084 struct {
	audit bool
	write bool
	rate  bool
}

type pluginWebhookEntitlementSigner084 struct {
	keyID   string
	private ed25519.PrivateKey
}

type pluginWebhookRuntimeAttestation084 struct {
	generation            int64
	keyID                 string
	privateKey            ed25519.PrivateKey
	natsDomain            string
	deliveryStream        string
	deliverySubjectPrefix string
}

func (signer pluginWebhookEntitlementSigner084) KeyID() string { return signer.keyID }

func (signer pluginWebhookEntitlementSigner084) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type pluginWebhookDB084 interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type pluginWebhookCanonicalEvent084 struct {
	SpecVersion     string                    `json:"specversion"`
	ID              uuid.UUID                 `json:"id"`
	Source          string                    `json:"source"`
	Type            string                    `json:"type"`
	Subject         string                    `json:"subject"`
	Time            time.Time                 `json:"time"`
	DataContentType string                    `json:"datacontenttype"`
	DataSchema      string                    `json:"dataschema"`
	TenantID        uuid.UUID                 `json:"tenant_id"`
	RequestID       string                    `json:"request_id"`
	Traceparent     *string                   `json:"traceparent,omitempty"`
	Sequence        uint64                    `json:"sequence"`
	Data            pluginWebhookEventData084 `json:"data"`
}

type pluginWebhookEventData084 struct {
	SubscriptionID uuid.UUID `json:"subscription_id"`
	Test           bool      `json:"test"`
}

func TestPluginWebhookControl084RoundTripAndContracts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	beforeEffective := pluginWebhookFunctionSource084(t, pool, "custom_rbac_effective_permissions(uuid,uuid)")
	beforeGuard := pluginWebhookFunctionSource084(t, pool, "guard_system_role_permission_mutation()")
	assertPluginWebhookTables084(t, pool, false)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatalf("apply 084: %v", err)
	}
	assertPluginWebhookHead084(t, pool, 84)
	assertPackageCommerceRBAC079Ledger(t, pool, 84)
	assertPluginWebhookTables084(t, pool, true)
	assertPluginWebhookColumnContracts084(t, pool)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 84); err != nil {
		t.Fatalf("empty 084 down: %v", err)
	}
	assertPluginWebhookHead084(t, pool, 83)
	assertPluginWebhookTables084(t, pool, false)
	if got := pluginWebhookFunctionSource084(t, pool, "custom_rbac_effective_permissions(uuid,uuid)"); got != beforeEffective {
		t.Fatal("084 down did not restore the exact 083 effective-permission function body")
	}
	if got := pluginWebhookFunctionSource084(t, pool, "guard_system_role_permission_mutation()"); got != beforeGuard {
		t.Fatal("084 down did not restore the exact 083 system-role guard body")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatalf("reapply 084: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 84)
}

func TestPluginWebhookControl084FreshHead(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertPluginWebhookHead084(t, pool, 84)
	assertPackageCommerceRBAC079Ledger(t, pool, 84)
	assertPluginWebhookTables084(t, pool, true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 84); err != nil {
		t.Fatalf("fresh empty 084 down: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatalf("fresh empty 084 reapply: %v", err)
	}
}

func TestPluginWebhookControl084RBACActorReceiptRotationAndRate(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	assertPluginWebhookRoleGrants084(t, pool, identity)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.ownerUser, true, true)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.adminUser, true, true)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.memberUser, true, false)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.viewerUser, true, false)

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
		identity.tenantScope, identity.viewerUser, identity.viewerRole); err != nil {
		t.Fatal(err)
	}
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.viewerUser, false, false)
	_, customGrant := seedPluginWebhookCustomRole084(t, pool, identity)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.customUser, true, true)
	revokePluginWebhookCustomRole084(t, pool, identity, customGrant)
	assertPluginWebhookEffective084(t, pool, identity.tenantScope, identity.customUser, false, false)

	resource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now)
	platformResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.platformScope, identity.platformAdmin, pluginWebhook084Now.Add(time.Second))
	if platformResource.subscription == uuid.Nil {
		t.Fatal("platform actor did not create an explicitly targeted tenant fact")
	}

	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_subscriptions(
		id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,
		event_types,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,
		created_at,updated_at
	) VALUES($1,$2,$3,$4,'invalid actor','https://hooks.example.com/v1','hooks.example.com','/v1',
		ARRAY['io.cdnca.webhook.v1.test'],$5,'active',1,0,0,$6,$6)`,
		uuid.New(), identity.tenantScope, identity.foreignScope, identity.foreignUser,
		uuid.New(), pluginWebhook084Now)
	assertPluginWebhookCode084(t, err, "P8402")

	var requestID uuid.UUID
	var createKey string
	if err := pool.QueryRow(t.Context(), `SELECT id,idempotency_key FROM plugin_webhook_write_requests
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
		resource.subscription).Scan(&requestID, &createKey); err != nil {
		t.Fatalf("find encrypted create receipt: %v", err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,created_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.revoke',$4,$5,$6,$7)`,
		uuid.New(), identity.tenantScope, identity.ownerUser, createKey, bytes084(32, 0x99),
		resource.subscription, pluginWebhook084Now)
	assertPluginWebhookCode084(t, err, "23505")
	_, err = pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=$2,
			receipt_cleared_reason='expired' WHERE id=$1`,
		requestID, pluginWebhook084Now.Add(23*time.Hour))
	assertPluginWebhookCode084(t, err, "P8404")
	receiptExpiresAt := agePluginWebhookReceipt084(t, pool, requestID)
	callerClearedAt := receiptExpiresAt.Add(48 * time.Hour)
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=$2,
			receipt_cleared_reason='expired' WHERE id=$1`,
		requestID, callerClearedAt); err != nil {
		t.Fatalf("clear expired receipt: %v", err)
	}
	var retainedKey bool
	var storedClearedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT receipt_ciphertext IS NULL AND completed_at IS NOT NULL,
		receipt_cleared_at FROM plugin_webhook_write_requests WHERE id=$1`, requestID).
		Scan(&retainedKey, &storedClearedAt); err != nil || !retainedKey {
		t.Fatalf("expired idempotency key retained=%t err=%v", retainedKey, err)
	}
	if storedClearedAt.Equal(callerClearedAt) || storedClearedAt.Before(receiptExpiresAt) {
		t.Fatalf("receipt cleanup marker=%s caller=%s expiry=%s",
			storedClearedAt, callerClearedAt, receiptExpiresAt)
	}

	rotation := rotatePluginWebhookSecret084(t, pool, identity, resource, pluginWebhook084Now.Add(time.Hour))
	var activeSecret uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT active_secret_version_id
		FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2`,
		identity.tenantScope, resource.subscription).Scan(&activeSecret); err != nil || activeSecret != rotation {
		t.Fatalf("active secret=%s want=%s err=%v", activeSecret, rotation, err)
	}

	for attempt := 0; attempt < 5; attempt++ {
		insertPluginWebhookRate084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(2*time.Hour+time.Duration(attempt)*time.Second), true)
	}
	err = insertPluginWebhookRateResult084(t, pool, identity, resource.subscription,
		pluginWebhook084Now.Add(2*time.Hour+10*time.Second), true)
	assertPluginWebhookCode084(t, err, "P8408")

	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, identity.tenantScope, identity.memberUser); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,$3,$2,$4,'plugin_webhook.test_delivery.create','denied','membership_revoked',$5,$6)`,
		uuid.New(), identity.tenantScope, resource.subscription, identity.memberUser,
		uuid.New(), pluginWebhook084Now.Add(3*time.Hour))
	assertPluginWebhookCode084(t, err, "P8402")

	assertPluginWebhookCode084(t, migrateVersionIsolated(t.Context(), pool, "down", 84), "P8401")
	assertPluginWebhookHead084(t, pool, 84)
}

func TestPluginWebhookControl084ClaimRevokeLinearization(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)

	startedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now)
	startedDelivery := seedPluginWebhookDelivery084(t, pool, identity, startedResource,
		pluginWebhook084Now.Add(time.Minute))
	startedClaim := claimPluginWebhookDelivery084(t, pool, identity, startedResource,
		startedDelivery, pluginWebhook084Now.Add(2*time.Minute))
	startPluginWebhookAttempt084(t, pool, startedClaim, pluginWebhook084Now.Add(3*time.Minute))
	revokePluginWebhookSubscription084(t, pool, identity, startedResource.subscription,
		pluginWebhook084Now.Add(4*time.Minute))
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='succeeded',completed_at=$5,http_status=204,response_sha256=$6,
			response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND claim_token=$4`,
		identity.tenantScope, startedResource.subscription, startedDelivery, startedClaim,
		pluginWebhook084Now.Add(5*time.Minute), bytes084(32, 0x32)); err != nil {
		t.Fatalf("finish pre-revoke-started HTTP: %v", err)
	}
	assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
		startedResource.subscription, startedDelivery, "delivered")

	claimedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now.Add(10*time.Minute))
	claimedDelivery := seedPluginWebhookDelivery084(t, pool, identity, claimedResource,
		pluginWebhook084Now.Add(11*time.Minute))
	claimedToken := claimPluginWebhookDelivery084(t, pool, identity, claimedResource,
		claimedDelivery, pluginWebhook084Now.Add(12*time.Minute))
	revokePluginWebhookSubscription084(t, pool, identity, claimedResource.subscription,
		pluginWebhook084Now.Add(13*time.Minute))
	assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
		claimedResource.subscription, claimedDelivery, "revoked")
	var attemptStatus string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_delivery_attempts
			WHERE claim_token=$1`, claimedToken).Scan(&attemptStatus); err != nil || attemptStatus != "revoked" {
		t.Fatalf("pre-start claim status=%q want revoked err=%v", attemptStatus, err)
	}
	var revokedHasEvidence bool
	if err := pool.QueryRow(t.Context(), `SELECT started_at IS NOT NULL OR http_status IS NOT NULL OR
			failure_code IS NOT NULL OR request_sha256 IS NOT NULL OR response_sha256 IS NOT NULL OR
			response_bytes IS NOT NULL OR response_preview IS NOT NULL OR sanitized_headers IS NOT NULL
			FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, claimedToken).Scan(&revokedHasEvidence); err != nil {
		t.Fatal(err)
	}
	if revokedHasEvidence {
		t.Fatal("pre-start revoked attempt retained HTTP evidence")
	}
	_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='started',started_at=$2,request_sha256=$3 WHERE claim_token=$1`,
		claimedToken, pluginWebhook084Now.Add(14*time.Minute), bytes084(32, 0x33))
	assertPluginWebhookCode084(t, err, "P8404")

	var residualCiphertexts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_secret_versions
		WHERE tenant_scope_id=$1 AND subscription_id IN ($2,$3)
		  AND (nonce IS NOT NULL OR ciphertext IS NOT NULL)`,
		identity.tenantScope, startedResource.subscription, claimedResource.subscription).Scan(&residualCiphertexts); err != nil || residualCiphertexts != 0 {
		t.Fatalf("revoked secret plaintext envelopes=%d want 0 err=%v", residualCiphertexts, err)
	}
}

func TestPluginWebhookControl084RejectsUnfencedAttemptRevocation(t *testing.T) {
	t.Run("claimed attempt cannot fabricate revoke evidence", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='revoked',started_at=$2,completed_at=$3,http_status=503,
				failure_code='network_revoked',retry_after_seconds=1,request_sha256=$4,
				response_sha256=$5,response_bytes=6,response_preview='secret'::bytea,
				sanitized_headers='{"Authorization":"Bearer secret"}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(2*time.Minute),
			pluginWebhook084Now.Add(3*time.Minute), bytes084(32, 0x34), bytes084(32, 0x35))
		assertPluginWebhookCode084(t, err, "P8407")
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "claimed")
	})

	t.Run("active subscription cannot forge revoked delivery", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		_ = claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
			SET status='revoked',completed_at=$4
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookCode084(t, err, "P8407")
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "claimed")
	})
}

func TestPluginWebhookControl084LedgerHeadFailClosed(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	if _, err := pool.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=42`); err != nil {
		t.Fatal(err)
	}
	script, err := controlmigrations.FS.ReadFile("084_plugin_webhook_control.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), string(script), pgx.QueryExecModeSimpleProtocol)
	assertPluginWebhookCode084(t, err, "P8400")
	assertPluginWebhookTables084(t, pool, false)
}

func TestPluginWebhookControl084TargetStorageContract(t *testing.T) {
	checks := []struct {
		name       string
		host       string
		path       string
		constraint string
	}{
		{name: "dotted IPv4", host: "127.0.0.1", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "abbreviated IPv4", host: "127.1", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "single integer IPv4", host: "2130706433", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "legacy octal IPv4", host: "0177.0.0.1", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "single hex IPv4", host: "0x7f000001", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "dotted hex IPv4", host: "0x7f.0x0.0x0.0x1", path: "/hook",
			constraint: "plugin_webhook_subscriptions_target_host_check"},
		{name: "query", host: "hooks.example.com", path: "/hook?token=secret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "fragment", host: "hooks.example.com", path: "/hook#secret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded dot segments upper", host: "hooks.example.com", path: "/%2E%2E/admin",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded dot segments lower", host: "hooks.example.com", path: "/%2e%2e/admin",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded control", host: "hooks.example.com", path: "/hook/%00secret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded unreserved", host: "hooks.example.com", path: "/hook/%7Euser",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded fragment", host: "hooks.example.com", path: "/hook/%23secret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded percent", host: "hooks.example.com", path: "/hook/%25secret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "encoded query", host: "hooks.example.com", path: "/hook/%3Fsecret",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "invalid UTF-8 escape", host: "hooks.example.com", path: "/hook/%FF",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "raw space", host: "hooks.example.com", path: "/hook name",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "malformed escape", host: "hooks.example.com", path: "/hook/%A",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
		{name: "lowercase escape", host: "hooks.example.com", path: "/hook/%c3%a9",
			constraint: "plugin_webhook_subscriptions_target_path_check"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 83)
			identity := seedPluginWebhookIdentity084(t, pool)
			if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
				t.Fatal(err)
			}
			if check.constraint == "plugin_webhook_subscriptions_target_host_check" {
				var valid bool
				if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_target_host_valid_084($1)`,
					check.host).Scan(&valid); err != nil || valid {
					t.Fatalf("target host %q valid=%t want false err=%v", check.host, valid, err)
				}
			} else {
				var valid bool
				if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_target_path_valid_084($1)`,
					check.path).Scan(&valid); err != nil || valid {
					t.Fatalf("target path %q valid=%t want false err=%v", check.path, valid, err)
				}
			}
			_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_subscriptions(
				id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,
				event_types,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,
				created_at,updated_at
			) VALUES($1,$2,$2,$3,'forbidden target','https://' || $4::text || $5::text,$4,$5,
				ARRAY['io.cdnca.webhook.v1.test'],$6,'active',1,0,0,$7,$7)`, uuid.New(),
				identity.tenantScope, identity.ownerUser, check.host, check.path, uuid.New(), pluginWebhook084Now)
			assertPluginWebhookConstraint084(t, err, "23514", check.constraint)
		})
	}

	pool, _, _ := setupPluginWebhook084(t)
	for _, host := range []string{"hooks.example.com", "sub1.api.example.co"} {
		var valid bool
		if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_target_host_valid_084($1)`, host).Scan(&valid); err != nil || !valid {
			t.Fatalf("DNS hostname %q valid=%t want true err=%v", host, valid, err)
		}
	}
	for _, path := range []string{"/v1/events", "/hook/~user", "/hooks/%E4%B8%AD"} {
		var valid bool
		if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_target_path_valid_084($1)`, path).Scan(&valid); err != nil || !valid {
			t.Fatalf("canonical target path %q valid=%t want true err=%v", path, valid, err)
		}
	}
}

func TestPluginWebhookControl084RejectsPostRevokeWork(t *testing.T) {
	t.Run("delivery insert", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		var event uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT event_id FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
			identity.tenantScope, resource.subscription, delivery).Scan(&event); err != nil {
			t.Fatal(err)
		}
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(time.Minute))
		_, err := insertPluginWebhookDeliveryRow084(t, pool, identity, resource, event, uuid.Nil,
			pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox insert", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		digest := sha256.Sum256(body)
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(time.Minute))
		err := insertPluginWebhookOutbox084(t, pool, identity, resource, event, delivery, body, digest[:],
			"plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("queue", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='queued',queued_at=$4,nats_stream_created_unix_nano=101,nats_stream_sequence=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("publish", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		lease := uuid.New()
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,
				lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, lease); err != nil {
			t.Fatal(err)
		}
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(2*time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='published',lease_token=NULL,lease_expires_at=NULL,published_at=$4
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(3*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})
}

func TestPluginWebhookControl084RejectsReplayDrift(t *testing.T) {
	t.Run("event binding", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		original := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		completePluginWebhookDelivery084(t, pool, identity, resource, original, pluginWebhook084Now.Add(time.Minute))
		differentEvent, _ := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now.Add(2*time.Minute))
		_, err := insertPluginWebhookDeliveryRow084(t, pool, identity, resource, differentEvent, original,
			pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("revoked subscription", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		original := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		completePluginWebhookDelivery084(t, pool, identity, resource, original, pluginWebhook084Now.Add(time.Minute))
		var event uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT event_id FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
			identity.tenantScope, resource.subscription, original).Scan(&event); err != nil {
			t.Fatal(err)
		}
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(2*time.Minute))
		_, err := insertPluginWebhookDeliveryRow084(t, pool, identity, resource, event, original,
			pluginWebhook084Now.Add(3*time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})
}

func TestPluginWebhookControl084AttemptTerminalContract(t *testing.T) {
	t.Run("succeeded requires 2xx", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(2*time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='succeeded',completed_at=$2,http_status=500,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(3*time.Minute), bytes084(32, 0x62))
		assertPluginWebhookCode084(t, err, "23514")
	})

	t.Run("failure requires code", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(2*time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=$2,http_status=503,retry_after_seconds=1,
				response_sha256=$3,response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(3*time.Minute), bytes084(32, 0x63))
		assertPluginWebhookCode084(t, err, "23514")
	})

	t.Run("failure code is stable", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(2*time.Minute))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=$2,http_status=503,
				failure_code='Temporary failure',retry_after_seconds=1,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(3*time.Minute), bytes084(32, 0x64))
		assertPluginWebhookCode084(t, err, "23514")
	})

	t.Run("fifth temporary failure terminates", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		for attempt := 1; attempt <= 5; attempt++ {
			base := pluginWebhook084Now.Add(time.Duration(attempt) * 10 * time.Minute)
			claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery, base)
			startPluginWebhookAttempt084(t, pool, claim, base.Add(time.Minute))
			if attempt == 5 {
				if err := finishPluginWebhookDeadLetter084(t, pool, claim, "temporary_failure",
					identity.tenantScope, identity.ownerUser, bytes084(32, byte(0x70+attempt))); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
				SET status='temporary_failure',completed_at=$2,http_status=503,failure_code='upstream_timeout',
				retry_after_seconds=0,response_sha256=$3,response_bytes=0,
					response_preview=''::bytea,sanitized_headers='{}'::jsonb
				WHERE claim_token=$1`, claim, base.Add(2*time.Minute), bytes084(32, byte(0x70+attempt))); err != nil {
				t.Fatal(err)
			}
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
		_, err := insertPluginWebhookClaim084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(60*time.Minute))
		assertPluginWebhookCode084(t, err, "P8407")
	})
}

func TestPluginWebhookControl084WriteReceiptSecretContract(t *testing.T) {
	for _, operation := range []string{"plugin_webhook.subscription.create", "plugin_webhook.secret.activate"} {
		t.Run(operation, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			auditID := appendPluginWebhookAudit084(t, pool, identity.tenantScope, identity.tenantScope,
				identity.ownerUser, operation, "success", "accepted", pluginWebhook084Now)
			query := `INSERT INTO plugin_webhook_write_requests(
				id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
				subscription_id,response_status,response_body,audit_event_id,created_at,completed_at`
			args := []any{uuid.New(), identity.tenantScope, identity.ownerUser, operation,
				bytes084(32, 0x81), resource.subscription, auditID, pluginWebhook084Now}
			if operation == "plugin_webhook.subscription.create" {
				query += `,receipt_wrapping_key_id,receipt_aad_sha256,receipt_nonce,receipt_ciphertext,receipt_expires_at)
					VALUES($1,$2,$2,$3,$4,'secret-body',$5,$6,201,'{"secret":"plaintext"}'::jsonb,
					$7,$8,$8,'plugin-webhook-kek-v1',$9,$10,$11,$12)`
				args = append(args, pluginWebhookReceiptAAD084(identity.tenantScope,
					identity.tenantScope, identity.ownerUser, "secret-body", operation, resource.subscription),
					bytes084(12, 0x83), bytes084(48, 0x84),
					pluginWebhook084Now.Add(24*time.Hour))
			} else {
				query = `INSERT INTO plugin_webhook_write_requests(
					id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,
					request_digest,subscription_id,rotation_id,response_status,response_body,
					audit_event_id,created_at,completed_at
				) VALUES($1,$2,$2,$3,$4,'secret-body',$5,$6,$7,200,
					'{"secret":"plaintext"}'::jsonb,$8,$9,$9)`
				args = []any{uuid.New(), identity.tenantScope, identity.ownerUser, operation,
					bytes084(32, 0x81), resource.subscription, resource.secret, auditID,
					pluginWebhook084Now}
			}
			_, err := pool.Exec(t.Context(), query, args...)
			assertPluginWebhookCode084(t, err, "23514")
		})
	}

	t.Run("exact paired rate", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		if _, err := insertPluginWebhookPendingSecretResult084(t, pool, identity, resource,
			pluginWebhook084Now.Add(time.Hour)); err != nil {
			t.Fatalf("exact rotation command/rate bundle: %v", err)
		}
	})

	t.Run("sixth rotation in one hour", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		for index := 0; index < 5; index++ {
			if err := insertPluginWebhookStandaloneRotationRate084(t, pool, identity, resource.subscription,
				pluginWebhook084Now.Add(time.Hour+time.Duration(index)*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		_, err := insertPluginWebhookPendingSecretResult084(t, pool, identity, resource,
			pluginWebhook084Now.Add(time.Hour+10*time.Second))
		assertPluginWebhookCode084(t, err, "P8408")
	})
}

func TestPluginWebhookControl084SecretAADIdentityContract(t *testing.T) {
	t.Run("authoritative vector", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := uuid.New()
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.rotate",
			resource.subscription, pending, pluginWebhook084Now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
			id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
			wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
		) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
			pending, identity.tenantScope, resource.subscription, identity.ownerUser,
			pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 2,
				"plugin-webhook-kek-v1"), bytes084(12, 0x85), bytes084(48, 0x86), bytes084(32, 0x87),
			pluginWebhook084Now.Add(time.Hour), pluginWebhook084Now.Add(25*time.Hour)); err != nil {
			t.Fatalf("insert authoritative secret AAD vector: %v", err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatalf("commit authoritative secret AAD vector: %v", err)
		}
	})

	checks := []struct {
		name string
		aad  func(pluginWebhookIdentity084, pluginWebhookResource084, uuid.UUID) []byte
	}{
		{name: "target scope", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			pending uuid.UUID) []byte {
			return pluginWebhookSecretAAD084(uuid.New(), resource.subscription, pending, 2,
				"plugin-webhook-kek-v1")
		}},
		{name: "subscription", aad: func(identity pluginWebhookIdentity084, _ pluginWebhookResource084,
			pending uuid.UUID) []byte {
			return pluginWebhookSecretAAD084(identity.tenantScope, uuid.New(), pending, 2,
				"plugin-webhook-kek-v1")
		}},
		{name: "secret version id", aad: func(identity pluginWebhookIdentity084,
			resource pluginWebhookResource084, _ uuid.UUID) []byte {
			return pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, uuid.New(), 2,
				"plugin-webhook-kek-v1")
		}},
		{name: "version", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			pending uuid.UUID) []byte {
			return pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 1,
				"plugin-webhook-kek-v1")
		}},
		{name: "wrapping key", aad: func(identity pluginWebhookIdentity084,
			resource pluginWebhookResource084, pending uuid.UUID) []byte {
			return pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 2,
				"plugin-webhook-kek-v2")
		}},
	}
	for _, check := range checks {
		t.Run("rejects "+check.name+" drift", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			pending := uuid.New()
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
				identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.rotate",
				resource.subscription, pending, pluginWebhook084Now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
				id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
				wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
			) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
				pending, identity.tenantScope, resource.subscription, identity.ownerUser,
				check.aad(identity, resource, pending), bytes084(12, 0x88), bytes084(48, 0x89),
				bytes084(32, 0x8a), pluginWebhook084Now.Add(time.Hour),
				pluginWebhook084Now.Add(25*time.Hour))
			assertPluginWebhookCode084(t, err, "23514")
		})
	}
}

func TestPluginWebhookControl084ReceiptAADIdentityContract(t *testing.T) {
	checks := []struct {
		name string
		aad  func(pluginWebhookIdentity084, pluginWebhookResource084, string) []byte
	}{
		{name: "target scope", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			key string) []byte {
			return pluginWebhookReceiptAAD084(uuid.New(), identity.tenantScope, identity.ownerUser, key,
				"plugin_webhook.subscription.create", resource.subscription)
		}},
		{name: "actor scope", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			key string) []byte {
			return pluginWebhookReceiptAAD084(identity.tenantScope, uuid.New(), identity.ownerUser, key,
				"plugin_webhook.subscription.create", resource.subscription)
		}},
		{name: "actor user", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			key string) []byte {
			return pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, uuid.New(), key,
				"plugin_webhook.subscription.create", resource.subscription)
		}},
		{name: "idempotency key", aad: func(identity pluginWebhookIdentity084,
			resource pluginWebhookResource084, _ string) []byte {
			return pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
				"different-key", "plugin_webhook.subscription.create", resource.subscription)
		}},
		{name: "operation", aad: func(identity pluginWebhookIdentity084, resource pluginWebhookResource084,
			key string) []byte {
			return pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
				key, "plugin_webhook.secret.rotate", resource.subscription)
		}},
		{name: "resource", aad: func(identity pluginWebhookIdentity084, _ pluginWebhookResource084,
			key string) []byte {
			return pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
				key, "plugin_webhook.subscription.create", uuid.New())
		}},
	}
	for _, check := range append([]struct {
		name string
		aad  func(pluginWebhookIdentity084, pluginWebhookResource084, string) []byte
	}{{name: "authoritative vector", aad: func(identity pluginWebhookIdentity084,
		resource pluginWebhookResource084, key string) []byte {
		return pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
			key, "plugin_webhook.subscription.create", resource.subscription)
	}}}, checks...) {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			if check.name == "authoritative vector" {
				var key string
				var stored []byte
				if err := pool.QueryRow(t.Context(), `SELECT idempotency_key,receipt_aad_sha256
					FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND subscription_id=$2
					  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
					resource.subscription).Scan(&key, &stored); err != nil {
					t.Fatal(err)
				}
				expected := pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope,
					identity.ownerUser, key, "plugin_webhook.subscription.create", resource.subscription)
				if string(stored) != string(expected) {
					t.Fatalf("stored receipt AAD=%x want=%x", stored, expected)
				}
				return
			}
			key := "receipt-aad-" + strings.ReplaceAll(check.name, " ", "-")
			auditID := appendPluginWebhookAudit084(t, pool, identity.tenantScope, identity.tenantScope,
				identity.ownerUser, "plugin_webhook.subscription.create", "success", "accepted", pluginWebhook084Now)
			_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
				id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
				subscription_id,response_status,response_body,receipt_wrapping_key_id,receipt_aad_sha256,
				receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,created_at,completed_at
			) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.create',$4,$5,$6,201,
				jsonb_build_object('subscription_id',$6::uuid::text),'plugin-webhook-kek-v1',$7,$8,$9,$10,$11,$12,$12)`,
				uuid.New(), identity.tenantScope, identity.ownerUser, key, bytes084(32, 0x8b),
				resource.subscription, check.aad(identity, resource, key), bytes084(12, 0x8c),
				bytes084(48, 0x8d), pluginWebhook084Now.Add(24*time.Hour), auditID, pluginWebhook084Now)
			assertPluginWebhookCode084(t, err, "23514")
		})
	}
}

func TestPluginWebhookControl084DigestIdentityAndDLQContract(t *testing.T) {
	t.Run("event digest", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		err := insertPluginWebhookEvent084(t, pool, identity, resource, event, nil,
			body, bytes084(32, 0x91), pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox chain", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		digest := sha256.Sum256(body)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, body, digest[:],
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		err = insertPluginWebhookOutbox084(t, tx, identity, resource, event, delivery, body,
			bytes084(32, 0x92), "plugin-webhook-v2-"+hexDigest084("wrong"), pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox message identity", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		digest := sha256.Sum256(body)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, body, digest[:],
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		err = insertPluginWebhookOutbox084(t, tx, identity, resource, event, delivery, body, digest[:],
			"plugin-webhook-v2-"+hexDigest084("wrong"), pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox event delivery binding", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		secondEvent, _ := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now.Add(time.Minute))
		var secondBody, secondDigest []byte
		if err := pool.QueryRow(t.Context(), `SELECT canonical_body,body_sha256 FROM plugin_webhook_events
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, secondEvent).Scan(&secondBody, &secondDigest); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET event_id=$4,queue_body=$5,queue_body_sha256=$6
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, secondEvent, secondBody, secondDigest)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("dead letter terminal", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_dead_letters(
			id,tenant_scope_id,subscription_id,delivery_id,event_id,final_attempt_number,
			actor_scope_id,actor_user_id,nats_stream,nats_subject,nats_message_id,payload_sha256,
			publish_state,reason_code,request_sha256,response_bytes,failed_at
		) SELECT $2,attempt.tenant_scope_id,attempt.subscription_id,attempt.delivery_id,delivery.event_id,
			attempt.attempt_number,attempt.actor_scope_id,attempt.actor_user_id,'PLUGIN_WEBHOOK_DLQ',
			'cdnca.plugin-webhook.dead-letter.v1','plugin-webhook-dlq-v1-' || encode(sha256(
				convert_to(attempt.delivery_id::text || ':' || attempt.attempt_number::text,'UTF8')),'hex'),
			plugin_webhook_dead_letter_payload_sha256_084(attempt.tenant_scope_id,
				attempt.subscription_id,attempt.delivery_id,delivery.event_id,attempt.attempt_number,
				'premature',NULL,attempt.request_sha256,NULL,0),'pending','premature',
			attempt.request_sha256,0,clock_timestamp()
		FROM plugin_webhook_delivery_attempts attempt
		JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		WHERE attempt.claim_token=$1`, claim, uuid.New())
		assertPluginWebhookCode084(t, err, "P8404")
	})
}

func TestPluginWebhookControl084AuditPayloadContract(t *testing.T) {
	for _, missing := range []string{"operation", "reason"} {
		t.Run(missing, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			var position int64
			var previous []byte
			err = tx.QueryRow(t.Context(), `SELECT stream_position,event_hash FROM audit_events
				WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, identity.tenantScope).Scan(&position, &previous)
			if errors.Is(err, pgx.ErrNoRows) {
				position, previous, err = 0, nil, nil
			}
			if err != nil {
				t.Fatal(err)
			}
			auditID := uuid.New()
			payload := `jsonb_build_object('actor_scope_id',$8::uuid::text,'target_scope_id',$2::uuid::text,
				'operation',$5::text,'reason','accepted')`
			if missing == "operation" {
				payload = `jsonb_build_object('actor_scope_id',$8::uuid::text,'target_scope_id',$2::uuid::text,
					'reason','accepted')`
			} else {
				payload = `jsonb_build_object('actor_scope_id',$8::uuid::text,'target_scope_id',$2::uuid::text,
					'operation',$5::text)`
			}
			hash := sha256.Sum256([]byte(auditID.String()))
			if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
				id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
				request_id,result,payload,previous_hash,event_hash,occurred_at
			) VALUES($1,$2,$3,$4,$5,'plugin_webhook',$6,$7,'success',`+payload+`,$9,$10,$11)`,
				auditID, identity.tenantScope, position+1, identity.ownerUser,
				"plugin_webhook.subscription.revoke", auditID.String(), "audit-"+auditID.String(),
				identity.tenantScope, previous, hash[:], pluginWebhook084Now); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
				id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
				subscription_id,response_status,response_body,audit_event_id,created_at,completed_at
			) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.revoke',$4,$5,$6,200,
				jsonb_build_object('subscription_id',$6::uuid::text),$7,$8,$8)`, uuid.New(),
				identity.tenantScope, identity.ownerUser, "audit-"+missing, bytes084(32, 0xa1),
				resource.subscription, auditID, pluginWebhook084Now); err != nil {
				t.Fatal(err)
			}
			assertPluginWebhookCode084(t, tx.Commit(t.Context()), "P8405")
		})
	}
	for name, payload := range map[string]string{
		"mixed case secret": `jsonb_build_object('actor_scope_id',$8::uuid::text,
			'target_scope_id',$2::uuid::text,'operation',$5::text,'reason','accepted',
			'SeCrEt','one-time-secret')`,
		"nested authorization": `jsonb_build_object('actor_scope_id',$8::uuid::text,
			'target_scope_id',$2::uuid::text,'operation',$5::text,'reason','accepted',
			'metadata',jsonb_build_object('Authorization','Bearer secret'))`,
		"signature extra": `jsonb_build_object('actor_scope_id',$8::uuid::text,
			'target_scope_id',$2::uuid::text,'operation',$5::text,'reason','accepted',
			'webhook_signature','v2=secret')`,
	} {
		t.Run(name, func(t *testing.T) {
			assertPluginWebhookAuditPayloadRejected084(t, payload)
		})
	}
}

func TestPluginWebhookControl084SanitizedHeadersContract(t *testing.T) {
	t.Run("safe flat headers", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(2*time.Minute))
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='succeeded',completed_at=$2,http_status=204,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,
				sanitized_headers='{"content-type":"application/json","x-request-id":"safe-084"}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(3*time.Minute), bytes084(32, 0xa2)); err != nil {
			t.Fatalf("persist safe sanitized headers: %v", err)
		}
	})

	for name, headers := range map[string]string{
		"signature header":       `{"X-CDNCA-Webhook-Signature":"opaque"}`,
		"signature suffix":       `{"SiGnAtUrE256":"opaque"}`,
		"x signature suffix":     `{"x-signature256":"opaque"}`,
		"compact api key":        `{"apikey":"opaque"}`,
		"x compact api key":      `{"X-ApiKey":"opaque"}`,
		"private key":            `{"PrivateKey":"opaque"}`,
		"credential":             `{"x-credential-id":"opaque"}`,
		"authorization":          `{"AuThOrIzAtIoN":"opaque"}`,
		"cookie header":          `{"SeT-CoOkIe":"opaque"}`,
		"secret header":          `{"x_secret":"opaque"}`,
		"token header":           `{"token":"opaque"}`,
		"password header":        `{"PASSWORD":"opaque"}`,
		"nested compact api key": `{"x-debug":{"X-ApiKey":"opaque"}}`,
		"sensitive value":        `{"x-debug":"token=one-time-secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
			claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
				pluginWebhook084Now.Add(time.Minute))
			startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(2*time.Minute))
			_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
				SET status='succeeded',completed_at=$2,http_status=204,response_sha256=$3,
					response_bytes=0,response_preview=''::bytea,sanitized_headers=$4::jsonb
				WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(3*time.Minute),
				bytes084(32, 0xa3), headers)
			assertPluginWebhookCode084(t, err, "23514")
		})
	}
}

func TestPluginWebhookControl084FunctionACLContract(t *testing.T) {
	pool, _, _ := setupPluginWebhook084(t)
	for _, signature := range []string{
		"plugin_webhook_mod_084(numeric,numeric)",
		"plugin_webhook_le_numeric_084(bytea)",
		"plugin_webhook_mod_pow_084(numeric,numeric,numeric)",
		"plugin_webhook_ed25519_decode_084(bytea)",
		"plugin_webhook_ed25519_add_084(numeric[],numeric[])",
		"plugin_webhook_ed25519_double_084(numeric[])",
		"plugin_webhook_ed25519_scalarmult_084(numeric[],numeric)",
		"plugin_webhook_ed25519_prime_order_point_084(numeric[])",
		"plugin_webhook_ed25519_verify_084(bytea,bytea,bytea)",
		"plugin_webhook_u32be_084(integer)",
		"plugin_webhook_attestation_frame_084(bytea[])",
		"plugin_webhook_outbox_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,numeric,text,numeric,text,numeric,text,bytea,numeric)",
		"plugin_webhook_dead_letter_attestation_sha256_084(numeric,text,text,uuid,uuid,uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,text,numeric,text,numeric,text,bytea,bytea,numeric)",
		"guard_plugin_webhook_runtime_attestation_key_084()",
		"guard_plugin_webhook_runtime_attestation_head_084()",
		"validate_plugin_webhook_runtime_attestation_head_084()",
		"prevent_plugin_webhook_runtime_attestation_truncate_084()",
		"plugin_webhook_canonical_body_084(uuid,uuid,text,text,timestamp with time zone,text,text,numeric,jsonb)",
		"validate_plugin_webhook_event_body_084()",
		"validate_plugin_webhook_delivery_outbox_084()",
		"validate_plugin_webhook_command_facts_084()",
		"validate_plugin_webhook_event_command_084()",
		"validate_plugin_webhook_secret_command_084()",
		"validate_plugin_webhook_write_request_result_084()",
		"apply_plugin_webhook_secret_expiry_fence_084()",
		"validate_plugin_webhook_physical_cleanup_084()",
		"plugin_webhook_retry_delay_seconds_084(uuid,numeric,timestamp with time zone,integer)",
		"plugin_webhook_dead_letter_payload_sha256_084(uuid,uuid,uuid,uuid,numeric,text,integer,bytea,bytea,integer)",
		"guard_plugin_webhook_dead_letter_084()",
		"validate_plugin_webhook_dead_letter_084()",
		"project_plugin_webhook_dead_letter_ack_084()",
		"stamp_plugin_webhook_xact_id_084()",
		"guard_control_entitlement_revocation_lkg_084()",
		"guard_control_entitlement_revocation_serial_084()",
		"prevent_control_entitlement_revocation_truncate_084()",
		"guard_control_entitlement_cached_lease_084()",
		"record_plugin_webhook_entitlement_decision_084()",
		"prevent_plugin_webhook_entitlement_decision_mutation_084()",
		"prevent_plugin_webhook_entitlement_decision_truncate_084()",
		"validate_plugin_webhook_entitlement_decision_084()",
		"publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)",
		"transition_plugin_webhook_dead_letter_reconcile_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,uuid,text,numeric,numeric,numeric,numeric)",
		"acknowledge_plugin_webhook_dead_letter_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,text,text,numeric,text,numeric,text,bytea,bytea,numeric,numeric,text,bytea)",
	} {
		t.Run(signature, func(t *testing.T) {
			assertPluginWebhookPublicExecute084(t, pool, signature, false)
		})
	}
	for signature, want := range map[string]string{
		"guard_control_entitlement_revocation_lkg_084()":                                                                              "62b96f378d1ba4c4c74fbfcafe2c3d3a5a23146de8bab2f470c7df0e14adbe0a",
		"guard_control_entitlement_revocation_serial_084()":                                                                           "4b82624273ba085015a5e1e33d1815827e01bb8af8203ae6d5b857daa840549c",
		"prevent_control_entitlement_revocation_truncate_084()":                                                                       "d0c73d7c6fffb08947b6eee278bbea177aa20e4ab3d2352b74ae1145d2745f18",
		"guard_control_entitlement_cached_lease_084()":                                                                                "42a19037b108ce795df19ddab7c8100cd0ac5a6e236a57597fe847a75ed2ce33",
		"record_plugin_webhook_entitlement_decision_084()":                                                                            "71e15fe5b179db6bacc14686d54ebc5a01130f6c1312699935f42949ddb097e3",
		"prevent_plugin_webhook_entitlement_decision_mutation_084()":                                                                  "7ba9df94386050cb00ae5fa8cdc0e1a291493f772c1511f3bfb6112ac4da3800",
		"prevent_plugin_webhook_entitlement_decision_truncate_084()":                                                                  "4bb8f628c250d2c444f8a98d1fa7ff8d99fdbe901a2b9878ec12ac42b08451b6",
		"validate_plugin_webhook_entitlement_decision_084()":                                                                          "d3e6bc50123d382fa11270cc3c185fef4422a52cb679a1cd69d8b61c911db4fa",
		"validate_plugin_webhook_write_request_result_084()":                                                                          "4ca31728d285d96637ef07d010c7227a9aa41b64c01099fd9e4e6061ac8e98be",
		"publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)": "58256cb5ecd595099333bcd6d23267761a4852c00689a52fd2ac2be49f4239d8",
		"transition_plugin_webhook_dead_letter_reconcile_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,uuid,text,numeric,numeric,numeric,numeric)":                         "c49ac6357a617189d17d4077fd32df5f71721f08afaaaa3825c391ae9be0be2d",
		"acknowledge_plugin_webhook_dead_letter_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,text,text,numeric,text,numeric,text,bytea,bytea,numeric,numeric,text,bytea)": "11a7d70297c29d2329d4bdfd4522bb5fe37988be3d4e8524a25de1bb0f7c3b83",
	} {
		t.Run("body "+signature, func(t *testing.T) {
			var got string
			if err := pool.QueryRow(t.Context(), `SELECT encode(sha256(convert_to(
				replace(prosrc,current_schema(),'@schema'),'UTF8')),'hex')
				FROM pg_proc WHERE oid=to_regprocedure($1)`, signature).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("function %s body SHA=%s want=%s", signature, got, want)
			}
		})
	}
}

func TestPluginWebhookControl084EventIdentityContract(t *testing.T) {
	checks := []struct {
		name        string
		event       func() uuid.UUID
		traceparent *string
	}{
		{name: "uuidv4", event: uuid.New},
		{name: "zero trace", event: func() uuid.UUID { return uuid.Must(uuid.NewV7()) },
			traceparent: string084("00-00000000000000000000000000000000-0000000000000000-01")},
		{name: "invalid flags", event: func() uuid.UUID { return uuid.Must(uuid.NewV7()) },
			traceparent: string084("00-11111111111111111111111111111111-2222222222222222-ff")},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			err := insertPluginWebhookEvent084(t, pool, identity, resource, check.event(), check.traceparent,
				nil, nil, pluginWebhook084Now)
			assertPluginWebhookCode084(t, err, "23514")
		})
	}
}

func TestPluginWebhookControl084InitialStateAndAtomicOutboxContract(t *testing.T) {
	t.Run("delivery insert is pending only", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		event := uuid.Must(uuid.NewV7())
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, nil, nil,
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery := uuid.New()
		_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_deliveries(
			id,tenant_scope_id,subscription_id,event_id,actor_scope_id,actor_user_id,
			delivery_idempotency_key,target_url,target_host,target_path,status,subscription_revision,
			attempt_count,created_at,completed_at
		) VALUES($1,$2,$3,$4,$2,$5,$6,'https://hooks.example.com/v1/events',
			'hooks.example.com','/v1/events','delivered',1,0,$7,$7)`, delivery,
			identity.tenantScope, resource.subscription, event, identity.ownerUser,
			"plugin-webhook-v2-"+hexDigest084(delivery.String()), pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox insert is pending only", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		digest := sha256.Sum256(body)
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, body, digest[:],
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='queued',queued_at=$4,nats_stream_created_unix_nano=101,nats_stream_sequence=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_outbox(
			id,tenant_scope_id,subscription_id,event_id,delivery_id,actor_scope_id,actor_user_id,
			queue_schema,queue_body,queue_body_sha256,message_id,status,publish_attempt,
			available_at,leased_at,published_at,created_at
		) VALUES($1,$2,$3,$4,$5,$2,$6,'cdnca.plugin-webhook.queue/v2',$7,$8,$9,
			'published',1,$10,$10,$10,$10)`, uuid.New(), identity.tenantScope,
			resource.subscription, event, delivery, identity.ownerUser, body, digest[:],
			"plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("pending bundle leases before queue", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		digest := sha256.Sum256(body)
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, body, digest[:],
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertPluginWebhookOutbox084(t, tx, identity, resource, event, delivery, body, digest[:],
			"plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.test_delivery.create",
			resource.subscription, delivery, pluginWebhook084Now,
			pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,
				lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, uuid.New()); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookDeliveryOutboxStatuses084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "pending", "leased")
	})

	t.Run("queued without outbox cannot commit", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		event := uuid.Must(uuid.NewV7())
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, nil, nil,
			pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='queued',queued_at=$4,nats_stream_created_unix_nano=101,nats_stream_sequence=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.test_delivery.create",
			resource.subscription, delivery, pluginWebhook084Now,
			pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookCode084(t, tx.Commit(t.Context()), "P8404")
	})

	t.Run("queued delivery rejects revoked outbox", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='queued',queued_at=$4,nats_stream_created_unix_nano=101,nats_stream_sequence=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='revoked' WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookCode084(t, tx.Commit(t.Context()), "P8404")
	})

	for _, outboxStatus := range []string{"pending", "leased"} {
		t.Run("revoked delivery rejects "+outboxStatus+" outbox", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
			if outboxStatus == "leased" {
				if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
					SET status='leased',lease_token=$4,
						lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
					WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
					resource.subscription, delivery, uuid.New()); err != nil {
					t.Fatal(err)
				}
			}
			_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='revoked',completed_at=$4
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
				resource.subscription, delivery, pluginWebhook084Now.Add(3*time.Minute))
			assertPluginWebhookCode084(t, err, "P8407")
		})
	}

	t.Run("queued delivery rejects leased outbox", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,
				lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, uuid.New()); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET status='queued',queued_at=$4,nats_stream_created_unix_nano=101,nats_stream_sequence=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookCode084(t, tx.Commit(t.Context()), "P8404")
	})

	t.Run("queued delivery requires stream sequence", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
			SET status='queued',queued_at=$4,nats_stream_sequence=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookCode084(t, err, "23514")
	})

	t.Run("pending delivery rejects published outbox", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='published',published_at=clock_timestamp()
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("inactive subscription rejects outbox lease", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET status='revoked',revision=revision+1,revoke_sequence=1,
				revoked_at=statement_timestamp(),updated_at=statement_timestamp()
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,
				lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			resource.subscription, delivery, uuid.New())
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("subscription revoke preserves pending pair", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookDeliveryOutboxStatuses084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "revoked", "revoked")
	})

	t.Run("published history survives revoke", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		publishPluginWebhookOutbox084(t, pool, identity.tenantScope, resource.subscription, delivery,
			pluginWebhook084Now.Add(time.Minute))
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(2*time.Minute))
		assertPluginWebhookDeliveryOutboxStatuses084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "revoked", "published")
	})
}

func TestPluginWebhookControl084DeliveryAttemptFactBinding(t *testing.T) {
	t.Run("direct queued to claimed has no attempt", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
			SET status='claimed',attempt_count=1,claimed_at=$4
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery, pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	for _, status := range []string{"delivered", "retry_scheduled", "dead_lettered"} {
		t.Run("direct claimed to "+status+" has no terminal attempt", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
			_ = claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
				pluginWebhook084Now.Add(time.Minute))
			var statement string
			if status == "retry_scheduled" {
				statement = `UPDATE plugin_webhook_deliveries SET status='retry_scheduled',next_attempt_at=$4
					WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`
			} else {
				statement = `UPDATE plugin_webhook_deliveries SET status='` + status + `',completed_at=$4
					WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`
			}
			_, err := pool.Exec(t.Context(), statement, identity.tenantScope, resource.subscription,
				delivery, pluginWebhook084Now.Add(2*time.Minute))
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}

	t.Run("paired claim outcome and revoke facts", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		completePluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "delivered")

		revokedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, pluginWebhook084Now.Add(10*time.Minute))
		revokedDelivery := seedPluginWebhookDelivery084(t, pool, identity, revokedResource,
			pluginWebhook084Now.Add(11*time.Minute))
		_ = claimPluginWebhookDelivery084(t, pool, identity, revokedResource, revokedDelivery,
			pluginWebhook084Now.Add(12*time.Minute))
		revokePluginWebhookSubscription084(t, pool, identity, revokedResource.subscription,
			pluginWebhook084Now.Add(13*time.Minute))
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			revokedResource.subscription, revokedDelivery, "revoked")
	})
}

func TestPluginWebhookControl084SequenceFactBinding(t *testing.T) {
	for _, sequence := range []string{"event_sequence", "lifecycle_sequence"} {
		t.Run("direct "+sequence+" increment has no fact", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions SET `+sequence+`=`+
				sequence+`+1,updated_at=$3 WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
				resource.subscription, pluginWebhook084Now.Add(time.Minute))
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}

	t.Run("event and claim advance their sequences", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now)
		if event == uuid.Nil {
			t.Fatal("event fact was not created")
		}
		publishPluginWebhookOutbox084(t, pool, identity.tenantScope, resource.subscription,
			delivery, pluginWebhook084Now.Add(time.Minute))
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(2*time.Minute))
		var eventSequence, lifecycleSequence, claimSequence string
		if err := pool.QueryRow(t.Context(), `SELECT subscription.event_sequence::text,
			subscription.lifecycle_sequence::text,attempt.claim_sequence::text
			FROM plugin_webhook_subscriptions subscription
			JOIN plugin_webhook_delivery_attempts attempt
			  ON attempt.tenant_scope_id=subscription.tenant_scope_id
			 AND attempt.subscription_id=subscription.id AND attempt.claim_token=$3
			WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`, identity.tenantScope,
			resource.subscription, claim).Scan(&eventSequence, &lifecycleSequence, &claimSequence); err != nil {
			t.Fatal(err)
		}
		if eventSequence != "1" || lifecycleSequence != claimSequence {
			t.Fatalf("event/lifecycle/claim sequence=%s/%s/%s", eventSequence, lifecycleSequence, claimSequence)
		}
	})
}

func TestPluginWebhookControl084CommandFactBinding(t *testing.T) {
	operations := []string{
		"plugin_webhook.subscription.create",
		"plugin_webhook.test_delivery.create",
		"plugin_webhook.delivery.replay",
	}
	missing := []struct {
		name  string
		facts pluginWebhookCommandFacts084
	}{
		{name: "audit", facts: pluginWebhookCommandFacts084{}},
		{name: "write request", facts: pluginWebhookCommandFacts084{audit: true, rate: true}},
		{name: "rate event", facts: pluginWebhookCommandFacts084{audit: true, write: true}},
	}
	for _, operation := range operations {
		for _, check := range missing {
			t.Run(operation+" missing "+check.name, func(t *testing.T) {
				err := insertPluginWebhookCommandResult084(t, operation, check.facts)
				assertPluginWebhookCode084(t, err, "P8405")
			})
		}
		t.Run(operation+" fully paired", func(t *testing.T) {
			if err := insertPluginWebhookCommandResult084(t, operation, pluginWebhookCommandFacts084{
				audit: true, write: true, rate: true,
			}); err != nil {
				t.Fatalf("fully paired %s: %v", operation, err)
			}
		})
	}
}

func TestPluginWebhookControl084InitialSubscriptionSequenceContract(t *testing.T) {
	checks := []struct {
		name                        string
		revision, events, lifecycle uint64
		status                      string
	}{
		{name: "revision gap", revision: 2, status: "active"},
		{name: "event sequence gap", revision: 1, events: 1, status: "active"},
		{name: "lifecycle sequence gap", revision: 1, lifecycle: 1, status: "active"},
		{name: "revoked initial state", revision: 2, lifecycle: 1, status: "revoked"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := insertPluginWebhookInitialSubscriptionResult084(t, check.revision, check.events,
				check.lifecycle, check.status)
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}

	pool, _, resource := setupPluginWebhook084(t)
	var revision, events, lifecycle string
	if err := pool.QueryRow(t.Context(), `SELECT revision::text,event_sequence::text,
		lifecycle_sequence::text FROM plugin_webhook_subscriptions WHERE id=$1`,
		resource.subscription).Scan(&revision, &events, &lifecycle); err != nil {
		t.Fatal(err)
	}
	if revision != "1" || events != "0" || lifecycle != "0" {
		t.Fatalf("initial revision/event/lifecycle=%s/%s/%s want=1/0/0",
			revision, events, lifecycle)
	}
}

func TestPluginWebhookControl084ActivationRequestBinding(t *testing.T) {
	t.Run("null rotation is rejected", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(time.Hour))
		if err := activatePluginWebhookSecretsResult084(t, pool, identity, resource,
			uuid.Nil, []uuid.UUID{pending}, pluginWebhook084Now.Add(2*time.Hour)); err == nil {
			t.Fatal("activation request without rotation identity committed")
		}
	})

	t.Run("wrong rotation is rejected", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(time.Hour))
		if err := activatePluginWebhookSecretsResult084(t, pool, identity, resource,
			uuid.New(), []uuid.UUID{pending}, pluginWebhook084Now.Add(2*time.Hour)); err == nil {
			t.Fatal("activation request with wrong rotation identity committed")
		}
	})

	t.Run("one request cannot activate two rotations", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		first := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(time.Hour))
		err := activatePluginWebhookTwiceResult084(t, pool, identity, resource,
			first, first, pluginWebhook084Now.Add(2*time.Hour))
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("null request cannot activate twice", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		first := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(time.Hour))
		if err := activatePluginWebhookTwiceResult084(t, pool, identity, resource,
			uuid.Nil, first, pluginWebhook084Now.Add(2*time.Hour)); err == nil {
			t.Fatal("one unbound activation request authorized two rotations")
		}
	})

	t.Run("exact rotation activates once", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(time.Hour))
		if err := activatePluginWebhookSecretsResult084(t, pool, identity, resource,
			pending, []uuid.UUID{pending}, pluginWebhook084Now.Add(2*time.Hour)); err != nil {
			t.Fatalf("activate exact rotation: %v", err)
		}
	})
}

func TestPluginWebhookControl084ActorProvenanceBinding(t *testing.T) {
	t.Run("outbox rejects different authorized manager", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		err := insertPluginWebhookPendingBundleActorResult084(t, pool, identity, resource,
			identity.tenantScope, identity.adminUser, pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("outbox accepts command actor", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		if err := insertPluginWebhookPendingBundleActorResult084(t, pool, identity, resource,
			identity.tenantScope, identity.ownerUser, pluginWebhook084Now); err != nil {
			t.Fatalf("outbox correct provenance: %v", err)
		}
	})

	t.Run("dead letter rejects unrelated membership", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		err := insertPluginWebhookDeadLetterActorResult084(t, pool, identity, resource,
			identity.tenantScope, identity.memberUser, pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("dead letter accepts attempt actor", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		if err := insertPluginWebhookDeadLetterActorResult084(t, pool, identity, resource,
			identity.tenantScope, identity.ownerUser, pluginWebhook084Now); err != nil {
			t.Fatalf("dead letter correct provenance: %v", err)
		}
	})
}

func TestPluginWebhookControl084CanonicalBodyContract(t *testing.T) {
	t.Run("authoritative v2 bytes persist and queue", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event := uuid.Must(uuid.NewV7())
		expected := pluginWebhookAuthoritativeBody084(identity, resource, event, nil, 1, pluginWebhook084Now)
		mirrored := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
		if string(mirrored) != string(expected) {
			t.Errorf("mirrored canonical bytes=%s want=%s", mirrored, expected)
		}
		digest := sha256.Sum256(expected)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, event, nil, expected, digest[:],
			pluginWebhook084Now); err != nil {
			t.Fatalf("insert authoritative event: %v", err)
		}
		delivery, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, event, uuid.Nil,
			pluginWebhook084Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertPluginWebhookOutbox084(t, tx, identity, resource, event, delivery, expected,
			digest[:], "plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
		if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.test_delivery.create",
			resource.subscription, delivery, pluginWebhook084Now,
			pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		var stored, queued, storedDigest, queuedDigest []byte
		if err := pool.QueryRow(t.Context(), `SELECT event.canonical_body,outbox.queue_body,
			event.body_sha256,outbox.queue_body_sha256
			FROM plugin_webhook_events event JOIN plugin_webhook_outbox outbox
			  ON outbox.tenant_scope_id=event.tenant_scope_id
			 AND outbox.subscription_id=event.subscription_id AND outbox.event_id=event.id
			WHERE event.tenant_scope_id=$1 AND event.subscription_id=$2 AND event.id=$3`,
			identity.tenantScope, resource.subscription, event).Scan(
			&stored, &queued, &storedDigest, &queuedDigest); err != nil {
			t.Fatal(err)
		}
		if string(stored) != string(expected) || string(queued) != string(expected) ||
			string(storedDigest) != string(digest[:]) || string(queuedDigest) != string(digest[:]) {
			t.Fatalf("authoritative event/outbox bytes or digests drifted")
		}
	})

	t.Run("legacy v2 constants are rejected", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		event := uuid.Must(uuid.NewV7())
		body := pluginWebhookAuthoritativeBody084(identity, resource, event, nil, 1, pluginWebhook084Now)
		legacy := strings.ReplaceAll(string(body), "/control-plane/plugin-webhooks", "/control-plane/plugin_webhook")
		legacy = strings.ReplaceAll(legacy,
			"https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
			"https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json")
		digest := sha256.Sum256([]byte(legacy))
		err := insertPluginWebhookEvent084(t, pool, identity, resource, event, nil, []byte(legacy), digest[:],
			pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	for _, name := range []string{"invalid utf8", "invalid json", "semantic drift", "wrong order", "extra field"} {
		t.Run(name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			event := uuid.Must(uuid.NewV7())
			good := pluginWebhookCanonicalBody084(t, identity, resource, event, nil, 1, pluginWebhook084Now)
			var body []byte
			switch name {
			case "invalid utf8":
				body = []byte{'{', '"', 0xff, '"', '}', '\n'}
			case "invalid json":
				body = []byte(`{"specversion":"1.0"`)
			case "semantic drift":
				body = []byte(strings.Replace(string(good), identity.tenantID.String(),
					identity.foreignTenant.String(), 1))
			case "wrong order":
				text := string(good)
				prefix := `{"specversion":"1.0","id":`
				boundary := strings.Index(text, `,"source":`)
				if boundary < len(prefix) {
					t.Fatalf("canonical prefix missing: %s", text)
				}
				body = []byte(`{"id":` + text[len(prefix):boundary] +
					`,"specversion":"1.0"` + text[boundary:])
			case "extra field":
				body = append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"extra":true}`)...)
			}
			digest := sha256.Sum256(body)
			err := insertPluginWebhookEvent084(t, pool, identity, resource, event, nil, body, digest[:],
				pluginWebhook084Now)
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}
}

func TestPluginWebhookControl084LiveManagePermissionContract(t *testing.T) {
	checks := []struct {
		name       string
		actorScope func(pluginWebhookIdentity084) uuid.UUID
		actorUser  func(pluginWebhookIdentity084) uuid.UUID
	}{
		{name: "tenant member read only", actorScope: func(v pluginWebhookIdentity084) uuid.UUID { return v.tenantScope },
			actorUser: func(v pluginWebhookIdentity084) uuid.UUID { return v.memberUser }},
		{name: "tenant viewer read only", actorScope: func(v pluginWebhookIdentity084) uuid.UUID { return v.tenantScope },
			actorUser: func(v pluginWebhookIdentity084) uuid.UUID { return v.viewerUser }},
		{name: "platform reader", actorScope: func(v pluginWebhookIdentity084) uuid.UUID { return v.platformScope },
			actorUser: func(v pluginWebhookIdentity084) uuid.UUID { return v.platformReader }},
	}
	for _, check := range checks {
		t.Run(check.name+" cannot create", func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 83)
			identity := seedPluginWebhookIdentity084(t, pool)
			if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
				t.Fatal(err)
			}
			seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
			_, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
				check.actorScope(identity), check.actorUser(identity), pluginWebhook084Now)
			assertPluginWebhookCode084(t, err, "P8402")
		})
	}

	t.Run("custom live grant creates", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
		_, _ = seedPluginWebhookCustomRole084(t, pool, identity)
		if _, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.customUser, pluginWebhook084Now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("custom revoke denies create", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
		_, grant := seedPluginWebhookCustomRole084(t, pool, identity)
		revokePluginWebhookCustomRole084(t, pool, identity, grant)
		_, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.customUser, pluginWebhook084Now)
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("custom revoke denies transition", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
		_, grant := seedPluginWebhookCustomRole084(t, pool, identity)
		resource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.customUser, pluginWebhook084Now)
		revokePluginWebhookCustomRole084(t, pool, identity, grant)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
				revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription,
			pluginWebhookDatabaseTime084(t, pool))
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("read only actor cannot claim", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		var revision, lifecycle string
		var secret uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT revision::text,lifecycle_sequence::text,active_secret_version_id
			FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
			resource.subscription).Scan(&revision, &lifecycle, &secret); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_delivery_attempts(
			tenant_scope_id,subscription_id,delivery_id,actor_scope_id,actor_user_id,
			attempt_number,claim_token,claim_sequence,claimed_subscription_revision,
			secret_version_id,status,claimed_at
		) VALUES($1,$2,$3,$1,$4,1,$5,($6::numeric+1),$7,$8,'claimed',$9)`,
			identity.tenantScope, resource.subscription, delivery, identity.memberUser, uuid.New(),
			lifecycle, revision, secret, pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("read only actor cannot revoke", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET actor_user_id=$3,status='revoked',revision=revision+1,
				lifecycle_sequence=lifecycle_sequence+1,revoke_sequence=lifecycle_sequence+1,
				updated_at=$4,revoked_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
			resource.subscription, identity.memberUser, pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookCode084(t, err, "P8402")
	})
}

func TestPluginWebhookControl084OriginProvenanceAndCurrentManagerContract(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	_, originGrant := seedPluginWebhookCustomRole084(t, pool, identity)
	origin := identity
	origin.ownerUser = identity.customUser
	rotatedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.customUser, pluginWebhook084Now)
	revokedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.customUser, pluginWebhook084Now.Add(time.Second))
	backgroundResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.customUser, pluginWebhook084Now.Add(2*time.Second))
	_, backgroundDelivery := seedPluginWebhookPendingBundle084(t, pool, origin, backgroundResource,
		pluginWebhook084Now.Add(time.Minute))

	var receiptRequest uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM plugin_webhook_write_requests
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
		backgroundResource.subscription).Scan(&receiptRequest); err != nil {
		t.Fatalf("find origin create receipt: %v", err)
	}

	revokePluginWebhookCustomRole084(t, pool, identity, originGrant)
	publishPluginWebhookOutbox084(t, pool, identity.tenantScope, backgroundResource.subscription,
		backgroundDelivery, pluginWebhook084Now.Add(3*time.Hour))
	claim := claimPluginWebhookDelivery084(t, pool, origin, backgroundResource, backgroundDelivery,
		pluginWebhook084Now.Add(3*time.Hour+time.Minute))
	startPluginWebhookAttempt084(t, pool, claim, pluginWebhook084Now.Add(3*time.Hour+2*time.Minute))
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='succeeded',completed_at=$2,http_status=204,response_sha256=$3,response_bytes=0,
			response_preview=''::bytea,sanitized_headers='{}'::jsonb WHERE claim_token=$1`, claim,
		pluginWebhook084Now.Add(3*time.Hour+3*time.Minute), bytes084(32, 0xb6)); err != nil {
		t.Fatalf("finish background delivery after origin revoke: %v", err)
	}
	agePluginWebhookReceipt084(t, pool, receiptRequest)
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=$2,
			receipt_cleared_reason='expired' WHERE id=$1`,
		receiptRequest, pluginWebhook084Now.Add(26*time.Hour)); err != nil {
		t.Fatalf("clear receipt after origin revoke: %v", err)
	}

	pending := uuid.New()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	rotationAt := pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.adminUser, "plugin_webhook.secret.rotate",
		rotatedResource.subscription, pending, rotationAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`, pending,
		identity.tenantScope, rotatedResource.subscription, identity.adminUser,
		pluginWebhookSecretAAD084(identity.tenantScope, rotatedResource.subscription, pending, 2,
			"plugin-webhook-kek-v1"), bytes084(12, 0xb7), bytes084(48, 0xb8), bytes084(32, 0xb9),
		rotationAt, rotationAt.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.adminUser, "plugin_webhook.secret.activate",
		rotatedResource.subscription, pending, rotationAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		rotatedResource.subscription, rotatedResource.secret, rotationAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		rotatedResource.subscription, pending, rotationAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
		rotatedResource.subscription, pending, rotationAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("different live manager rotates origin subscription: %v", err)
	}

	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	revokeAt := pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.adminUser, "plugin_webhook.subscription.revoke",
		revokedResource.subscription, uuid.Nil, revokeAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, revokedResource.subscription,
		revokeAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("different live manager revokes origin subscription: %v", err)
	}
}

func TestPluginWebhookControl084CustomRoleGrantRevokeLinearization(t *testing.T) {
	t.Run("revocation commits before waiting management fact", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
		roleID, grantID := seedPluginWebhookCustomRole084(t, pool, identity)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		revokeConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revokeConn.Release()
		factConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer factConn.Release()
		var revokePID, factPID int32
		if err := revokeConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revokePID); err != nil {
			t.Fatal(err)
		}
		if err := factConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&factPID); err != nil {
			t.Fatal(err)
		}
		revokeTx, err := revokeConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revokeTx.Rollback(ctx)
		if err := insertPluginWebhookGrantRevocation084(ctx, revokeTx, identity, roleID, grantID,
			pluginWebhook084Now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		subscription, secret := uuid.New(), uuid.New()
		factResult := make(chan error, 1)
		go func() {
			factTx, beginErr := factConn.Begin(ctx)
			if beginErr != nil {
				factResult <- beginErr
				return
			}
			factErr := insertPluginWebhookSubscriptionFacts084(ctx, factTx, identity.tenantScope,
				identity.tenantScope, identity.customUser, subscription, secret, pluginWebhook084Now.Add(3*time.Second))
			if factErr == nil {
				factErr = factTx.Commit(ctx)
			} else {
				_ = factTx.Rollback(ctx)
			}
			factResult <- factErr
		}()
		waitForPluginWebhookBlock084(t, pool, factPID, revokePID)
		if err := revokeTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-factResult:
			assertPluginWebhookCode084(t, err, "P8402")
		case <-ctx.Done():
			t.Fatalf("waiting management fact did not finish after revoke commit: %v", ctx.Err())
		}
		assertPluginWebhookFactCounts084(t, pool, identity.tenantScope, subscription, secret, grantID, 0, 0, 1)
	})

	t.Run("management fact commits before waiting revocation", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
		roleID, grantID := seedPluginWebhookCustomRole084(t, pool, identity)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		factConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer factConn.Release()
		revokeConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revokeConn.Release()
		var factPID, revokePID int32
		if err := factConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&factPID); err != nil {
			t.Fatal(err)
		}
		if err := revokeConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revokePID); err != nil {
			t.Fatal(err)
		}
		factTx, err := factConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer factTx.Rollback(ctx)
		subscription, secret := uuid.New(), uuid.New()
		if err := insertPluginWebhookSubscriptionFacts084(ctx, factTx, identity.tenantScope,
			identity.tenantScope, identity.customUser, subscription, secret, pluginWebhook084Now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		revokeResult := make(chan error, 1)
		go func() {
			revokeTx, beginErr := revokeConn.Begin(ctx)
			if beginErr != nil {
				revokeResult <- beginErr
				return
			}
			revokeErr := insertPluginWebhookGrantRevocation084(ctx, revokeTx, identity, roleID, grantID,
				pluginWebhook084Now.Add(4*time.Second))
			if revokeErr == nil {
				revokeErr = revokeTx.Commit(ctx)
			} else {
				_ = revokeTx.Rollback(ctx)
			}
			revokeResult <- revokeErr
		}()
		waitForPluginWebhookBlock084(t, pool, revokePID, factPID)
		if err := factTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-revokeResult:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatalf("waiting revocation did not finish after fact commit: %v", ctx.Err())
		}
		assertPluginWebhookFactCounts084(t, pool, identity.tenantScope, subscription, secret, grantID, 1, 1, 1)

		postRevokeSubscription, postRevokeSecret := uuid.New(), uuid.New()
		postRevokeTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer postRevokeTx.Rollback(ctx)
		err = insertPluginWebhookSubscriptionFacts084(ctx, postRevokeTx, identity.tenantScope,
			identity.tenantScope, identity.customUser, postRevokeSubscription, postRevokeSecret,
			pluginWebhook084Now.Add(5*time.Second))
		assertPluginWebhookCode084(t, err, "P8402")
		assertPluginWebhookFactCounts084(t, pool, identity.tenantScope, postRevokeSubscription,
			postRevokeSecret, grantID, 0, 0, 1)
	})
}

func TestPluginWebhookControl084ConcurrentAuthorizedWriteLocks(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	firstConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstConn.Release()
	secondConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Release()
	firstTx, err := firstConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstTx.Rollback(context.Background())
	secondTx, err := secondConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondTx.Rollback(context.Background())
	lockAuthorizedFacts := func(tx pgx.Tx) error {
		if _, lockErr := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`); lockErr != nil {
			return lockErr
		}
		if _, lockErr := tx.Exec(ctx, `SELECT role_id FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 ORDER BY role_id FOR SHARE`, identity.tenantScope,
			identity.ownerUser); lockErr != nil {
			return lockErr
		}
		_, lockErr := tx.Exec(ctx, `SELECT role.id FROM roles role
			JOIN role_assignments assignment ON assignment.role_id=role.id
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2 ORDER BY role.id FOR SHARE OF role`,
			identity.tenantScope, identity.ownerUser)
		return lockErr
	}
	if err = lockAuthorizedFacts(firstTx); err != nil {
		t.Fatal(err)
	}
	if err = lockAuthorizedFacts(secondTx); err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'plugin-webhook-rate-tenant:'||$1::uuid::text||':plugin_webhook.subscription.create',84))`,
		identity.tenantScope); err != nil {
		t.Fatal(err)
	}
	var firstPID, secondPID int32
	if err = firstTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	if err = secondTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	first := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	second := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	secondAt := pluginWebhookDatabaseTime084(t, secondTx)
	secondResult := make(chan error, 1)
	go func() {
		writeErr := func() error {
			if _, lockErr := secondTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
				'plugin-webhook-rate-tenant:'||$1::uuid::text||':plugin_webhook.subscription.create',84))`,
				identity.tenantScope); lockErr != nil {
				return lockErr
			}
			if lockErr := insertPluginWebhookSubscriptionFacts084(ctx, secondTx, identity.tenantScope,
				identity.tenantScope, identity.ownerUser, second.subscription, second.secret,
				secondAt); lockErr != nil {
				return lockErr
			}
			return secondTx.Commit(ctx)
		}()
		secondResult <- writeErr
	}()
	waitForPluginWebhookBlock084(t, pool, secondPID, firstPID)
	firstErr := insertPluginWebhookSubscriptionFacts084(ctx, firstTx, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, first.subscription, first.secret,
		pluginWebhookDatabaseTime084(t, firstTx))
	if firstErr == nil {
		firstErr = firstTx.Commit(ctx)
	} else {
		_ = firstTx.Rollback(context.Background())
	}
	secondErr := <-secondResult
	if firstErr != nil || secondErr != nil {
		t.Fatalf("concurrent authorized writes deadlocked or failed: first=%v second=%v", firstErr, secondErr)
	}
	var subscriptions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM plugin_webhook_subscriptions
		WHERE tenant_scope_id=$1 AND id=ANY($2::uuid[])`, identity.tenantScope,
		[]uuid.UUID{first.subscription, second.subscription}).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 2 {
		t.Fatalf("concurrent authorized subscriptions=%d want=2", subscriptions)
	}
}

func TestPluginWebhookControl084SystemRoleRevokeLinearization(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	revokeConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeConn.Release()
	factConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer factConn.Release()
	revokeTx, err := revokeConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeTx.Rollback(context.Background())
	if _, err = revokeTx.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, identity.tenantScope,
		identity.ownerUser, identity.ownerRole); err != nil {
		t.Fatal(err)
	}
	var revokePID, factPID int32
	if err = revokeTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revokePID); err != nil {
		t.Fatal(err)
	}
	if err = factConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&factPID); err != nil {
		t.Fatal(err)
	}
	subscription, secret := uuid.New(), uuid.New()
	factResult := make(chan error, 1)
	go func() {
		factTx, beginErr := factConn.Begin(ctx)
		if beginErr != nil {
			factResult <- beginErr
			return
		}
		factErr := insertPluginWebhookSubscriptionFacts084(ctx, factTx, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, subscription, secret,
			pluginWebhook084Now.Add(time.Second))
		if factErr == nil {
			factErr = factTx.Commit(ctx)
		} else {
			_ = factTx.Rollback(context.Background())
		}
		factResult <- factErr
	}()
	waitForPluginWebhookBlock084(t, pool, factPID, revokePID)
	if err = revokeTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-factResult:
		assertPluginWebhookCode084(t, err, "P8402")
	case <-ctx.Done():
		t.Fatalf("role revoke winner did not release waiting fact: %v", ctx.Err())
	}
	assertPluginWebhookFactCounts084(t, pool, identity.tenantScope, subscription, secret,
		uuid.Nil, 0, 0, 0)
}

func TestPluginWebhookControl084SuccessfulRequestResultBinding(t *testing.T) {
	checks := []struct {
		operation string
		status    int
	}{
		{operation: "plugin_webhook.subscription.create", status: 201},
		{operation: "plugin_webhook.test_delivery.create", status: 202},
		{operation: "plugin_webhook.delivery.replay", status: 202},
		{operation: "plugin_webhook.secret.rotate", status: 201},
		{operation: "plugin_webhook.secret.activate", status: 200},
		{operation: "plugin_webhook.subscription.revoke", status: 200},
	}
	for _, check := range checks {
		t.Run(check.operation, func(t *testing.T) {
			err := insertPluginWebhookStandaloneCompletedRequest084(t, check.operation, check.status)
			if err == nil {
				t.Fatal("standalone successful request committed without its exact result transition")
			}
		})
	}
}

func TestPluginWebhookControl084EventCommandAndSingleUseBinding(t *testing.T) {
	t.Run("orphan event", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		err := insertPluginWebhookEvent084(t, pool, identity, resource, uuid.Must(uuid.NewV7()), nil,
			nil, nil, pluginWebhook084Now)
		if err == nil {
			t.Fatal("event committed without delivery/outbox/write/rate/audit command bundle")
		}
	})

	t.Run("non replay event reuse", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		eventID, _ := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
		err := insertPluginWebhookSecondNonReplayDelivery084(t, pool, identity, resource, eventID,
			pluginWebhook084Now.Add(time.Minute))
		if err == nil {
			t.Fatal("one event authorized a second non-replay delivery")
		}
	})
}

func TestPluginWebhookControl084RotationCommandRateBinding(t *testing.T) {
	checks := []struct {
		name      string
		rateActor uuid.UUID
		rateAt    time.Duration
		withRate  bool
	}{
		{name: "missing rate"},
		{name: "different actor rate", rateActor: uuid.New(), withRate: true},
		{name: "different window rate", rateAt: -2 * time.Hour, withRate: true},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := insertPluginWebhookRotationBundleResult084(t, check.withRate, check.rateActor,
				pluginWebhook084Now.Add(time.Hour+check.rateAt))
			if err == nil {
				t.Fatal("rotation committed without its exact durable 5/hour rate fact")
			}
		})
	}
}

func TestPluginWebhookControl084ActivationClaimOverlap(t *testing.T) {
	t.Run("pre activation claim remains startable", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		rotatePluginWebhookSecret084(t, pool, identity, resource, pluginWebhook084Now.Add(2*time.Minute))
		if err := startPluginWebhookAttemptResult084(t, pool, claim, false,
			pluginWebhook084Now.Add(4*time.Minute)); err != nil {
			t.Fatalf("pre-activation claim did not retain its signing overlap: %v", err)
		}
	})

	t.Run("activation retains old encrypted signing material", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		_ = claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		rotatePluginWebhookSecret084(t, pool, identity, resource, pluginWebhook084Now.Add(2*time.Minute))
		var retained bool
		if err := pool.QueryRow(t.Context(), `SELECT status='retired' AND nonce IS NOT NULL AND
			ciphertext IS NOT NULL AND expires_at IS NOT NULL FROM plugin_webhook_secret_versions
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if !retained {
			t.Fatal("activation cleared the claim-bound previous secret before overlap expiry")
		}
	})

	t.Run("post activation claim uses new secret", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		active := rotatePluginWebhookSecret084(t, pool, identity, resource,
			pluginWebhook084Now.Add(2*time.Minute))
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource,
			pluginWebhook084Now.Add(5*time.Minute))
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(6*time.Minute))
		var bound uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT secret_version_id
			FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, claim).Scan(&bound); err != nil {
			t.Fatal(err)
		}
		if bound != active {
			t.Fatalf("post-activation claim secret=%s want=%s", bound, active)
		}
		if err := startPluginWebhookAttemptResult084(t, pool, claim, false,
			pluginWebhook084Now.Add(7*time.Minute)); err != nil {
			t.Fatalf("post-activation claim start: %v", err)
		}
	})

	t.Run("expired overlap requeues unstarted claim", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		active := rotatePluginWebhookSecret084(t, pool, identity, resource,
			pluginWebhook084Now.Add(2*time.Minute))
		agePluginWebhookSecretExpiry084(t, pool, identity.tenantScope,
			resource.subscription, resource.secret)
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='expired',nonce=NULL,ciphertext=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret); err != nil {
			t.Fatalf("expire overlap: %v", err)
		}
		var attemptStatus, deliveryStatus string
		if err := pool.QueryRow(t.Context(), `SELECT attempt.status,delivery.status
			FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
			  ON delivery.tenant_scope_id=attempt.tenant_scope_id
			 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
			WHERE attempt.claim_token=$1`, claim).Scan(&attemptStatus, &deliveryStatus); err != nil {
			t.Fatal(err)
		}
		if attemptStatus != "revoked" || deliveryStatus != "retry_scheduled" {
			t.Fatalf("expired overlap attempt/delivery=%s/%s want revoked/retry_scheduled",
				attemptStatus, deliveryStatus)
		}
		reclaimed := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(26*time.Hour))
		var rebound uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT secret_version_id
				FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, reclaimed).Scan(&rebound); err != nil {
			t.Fatal(err)
		}
		if rebound != active {
			t.Fatalf("expired overlap rebound secret=%s want=%s", rebound, active)
		}
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='started',started_at=$2,request_sha256=$3 WHERE claim_token=$1`, claim,
			pluginWebhook084Now.Add(26*time.Hour), bytes084(32, 0xf4))
		assertPluginWebhookCode084(t, err, "P8404")
	})
}

func TestPluginWebhookControl084ClaimRebindContract(t *testing.T) {
	rebindTx := func(database pluginWebhookDB084, tenantScope, subscription, claim uuid.UUID) error {
		var revision, lifecycle string
		var active uuid.UUID
		if err := database.QueryRow(t.Context(), `SELECT revision::text,active_secret_version_id,
			lifecycle_sequence::text FROM plugin_webhook_subscriptions
			WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, tenantScope, subscription).
			Scan(&revision, &active, &lifecycle); err != nil {
			return err
		}
		_, err := database.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET claimed_subscription_revision=$2::numeric,secret_version_id=$3,
				claim_sequence=$4::numeric+1,claimed_at=clock_timestamp()
			WHERE claim_token=$1 AND status='claimed'`, claim, revision, active, lifecycle)
		return err
	}
	rebind := func(pool *pgxpool.Pool, tenantScope, subscription, claim uuid.UUID) error {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(t.Context())
		if err := rebindTx(tx, tenantScope, subscription, claim); err != nil {
			return err
		}
		return tx.Commit(t.Context())
	}
	assertClaimed := func(pool *pgxpool.Pool, identity pluginWebhookIdentity084,
		resource pluginWebhookResource084, delivery, claim, active uuid.UUID, attempt string,
	) {
		t.Helper()
		var attemptNumber, attemptCount, attemptStatus, deliveryStatus string
		var secret uuid.UUID
		var rebound, noHTTP bool
		var deadLetters int
		if err := pool.QueryRow(t.Context(), `SELECT attempt.attempt_number::text,
			delivery.attempt_count::text,attempt.status,delivery.status,attempt.secret_version_id,
			attempt.claimed_subscription_revision=subscription.revision AND
			attempt.claim_sequence=subscription.lifecycle_sequence AND
			attempt.claimed_at=delivery.claimed_at,
			attempt.started_at IS NULL AND attempt.completed_at IS NULL AND
			attempt.http_status IS NULL AND attempt.failure_code IS NULL AND
			attempt.request_sha256 IS NULL AND attempt.response_sha256 IS NULL AND
			attempt.response_bytes IS NULL AND attempt.response_preview IS NULL AND
			attempt.sanitized_headers IS NULL,
			(SELECT count(*) FROM plugin_webhook_dead_letters dead_letter
			 WHERE dead_letter.tenant_scope_id=attempt.tenant_scope_id
			   AND dead_letter.subscription_id=attempt.subscription_id
			   AND dead_letter.delivery_id=attempt.delivery_id)
			FROM plugin_webhook_delivery_attempts attempt
			JOIN plugin_webhook_deliveries delivery
			  ON delivery.tenant_scope_id=attempt.tenant_scope_id
			 AND delivery.subscription_id=attempt.subscription_id
			 AND delivery.id=attempt.delivery_id
			JOIN plugin_webhook_subscriptions subscription
			  ON subscription.tenant_scope_id=attempt.tenant_scope_id
			 AND subscription.id=attempt.subscription_id
			WHERE attempt.claim_token=$1`, claim).Scan(&attemptNumber, &attemptCount,
			&attemptStatus, &deliveryStatus, &secret, &rebound, &noHTTP, &deadLetters); err != nil {
			t.Fatal(err)
		}
		if attemptNumber != attempt || attemptCount != attempt || attemptStatus != "claimed" ||
			deliveryStatus != "claimed" || secret != active || !rebound || !noHTTP || deadLetters != 0 {
			t.Fatalf("rebound attempt/count/status/delivery/secret/fence/no-http/dlq="+
				"%s/%s/%s/%s/%s/%t/%t/%d want %s/%s/claimed/claimed/%s/true/true/0",
				attemptNumber, attemptCount, attemptStatus, deliveryStatus, secret, rebound,
				noHTTP, deadLetters, attempt, attempt, active)
		}
	}

	t.Run("activation rebinds the unstarted attempt", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		active := rotatePluginWebhookSecret084(t, pool, identity, resource,
			pluginWebhook084Now.Add(2*time.Minute))
		if err := rebind(pool, identity.tenantScope, resource.subscription, claim); err != nil {
			t.Fatalf("rebind unstarted claim after activation: %v", err)
		}
		assertClaimed(pool, identity, resource, delivery, claim, active, "1")
		if err := startPluginWebhookAttemptResult084(t, pool, claim, false,
			pluginWebhook084Now.Add(3*time.Minute)); err != nil {
			t.Fatalf("start rebound claim with current secret: %v", err)
		}
	})

	t.Run("rebind without a newer activation is rejected", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		assertPluginWebhookCode084(t,
			rebind(pool, identity.tenantScope, resource.subscription, claim), "P8407")
		assertClaimed(pool, identity, resource, delivery, claim, resource.secret, "1")
	})

	t.Run("activation and rebind linearize before revoke", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(2*time.Minute))

		activationConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer activationConn.Release()
		activationTx, err := activationConn.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer activationTx.Rollback(t.Context())
		commandAt := pluginWebhookDatabaseTime084(t, activationTx)
		if err := insertPluginWebhookActivationRequestTx084(t.Context(), activationTx, identity,
			resource.subscription, pending, commandAt); err != nil {
			t.Fatal(err)
		}
		if _, err := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='retired',retired_at=$4,expires_at=$4::timestamptz+interval '24 hours'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret, commandAt); err != nil {
			t.Fatal(err)
		}
		if _, err := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='active',activated_at=$4,expires_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, pending, commandAt); err != nil {
			t.Fatal(err)
		}
		if _, err := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET active_secret_version_id=$3,revision=revision+1,
				lifecycle_sequence=lifecycle_sequence+1,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
			resource.subscription, pending, commandAt); err != nil {
			t.Fatal(err)
		}
		var activationPID int32
		if err := activationTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&activationPID); err != nil {
			t.Fatal(err)
		}

		rebindConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rebindConn.Release()
		var rebindPID int32
		if err := rebindConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&rebindPID); err != nil {
			t.Fatal(err)
		}
		rebound := make(chan error, 1)
		go func() {
			tx, err := rebindConn.Begin(t.Context())
			if err == nil {
				err = rebindTx(tx, identity.tenantScope, resource.subscription, claim)
			}
			if err == nil {
				err = tx.Commit(t.Context())
			} else if tx != nil {
				_ = tx.Rollback(t.Context())
			}
			rebound <- err
		}()
		waitForPluginWebhookBlock084(t, pool, rebindPID, activationPID)
		if err := activationTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-rebound; err != nil {
			t.Fatalf("rebind after concurrent activation: %v", err)
		}
		assertClaimed(pool, identity, resource, delivery, claim, pending, "1")
		revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
			pluginWebhook084Now.Add(4*time.Minute))
		var attemptStatus, deliveryStatus string
		var noHTTP bool
		if err := pool.QueryRow(t.Context(), `SELECT attempt.status,delivery.status,
			attempt.started_at IS NULL AND attempt.request_sha256 IS NULL
			FROM plugin_webhook_delivery_attempts attempt
			JOIN plugin_webhook_deliveries delivery
			  ON delivery.tenant_scope_id=attempt.tenant_scope_id
			 AND delivery.subscription_id=attempt.subscription_id
			 AND delivery.id=attempt.delivery_id WHERE attempt.claim_token=$1`, claim).
			Scan(&attemptStatus, &deliveryStatus, &noHTTP); err != nil {
			t.Fatal(err)
		}
		if attemptStatus != "revoked" || deliveryStatus != "revoked" || !noHTTP {
			t.Fatalf("revoke after rebind attempt/delivery/no-http=%s/%s/%t want revoked/revoked/true",
				attemptStatus, deliveryStatus, noHTTP)
		}
	})

	t.Run("attempt five rebind does not dead letter", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET attempt_number=5 WHERE claim_token=$1`, claim); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries SET attempt_count=5
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, delivery); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		active := rotatePluginWebhookSecret084(t, pool, identity, resource,
			pluginWebhook084Now.Add(2*time.Minute))
		if err := rebind(pool, identity.tenantScope, resource.subscription, claim); err != nil {
			t.Fatalf("rebind attempt five: %v", err)
		}
		assertClaimed(pool, identity, resource, delivery, claim, active, "5")
	})
}

func TestPluginWebhookControl084OldKeyPhysicalStartClock(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
	databaseNow := pluginWebhookDatabaseTime084(t, pool)
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		databaseNow.Add(-25*time.Hour))
	rotatePluginWebhookSecret084(t, pool, identity, resource, databaseNow)

	expiresAt := pluginWebhookDatabaseTime084(t, pool).Add(-time.Second)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET retired_at=$4::timestamptz - interval '24 hours',expires_at=$4
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, resource.secret, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	err = startPluginWebhookAttemptResult084(t, pool, claim, false, expiresAt.Add(-time.Second))
	assertPluginWebhookCode084(t, err, "P8407")
}

func TestPluginWebhookControl084RetryClaimServerClock(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
	databaseNow := pluginWebhookDatabaseTime084(t, pool)
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		databaseNow.Add(-3*time.Hour))
	startPluginWebhookAttempt084(t, pool, claim, databaseNow.Add(-2*time.Hour))
	callerCompletedAt := databaseNow.Add(-time.Hour)
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='temporary_failure',completed_at=$2,http_status=503,
			failure_code='upstream_timeout',retry_after_seconds=1,response_sha256=$3,
			response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
		WHERE claim_token=$1`, claim, callerCompletedAt, bytes084(32, 0xf5)); err != nil {
		t.Fatal(err)
	}

	_, err := insertPluginWebhookClaim084(t, pool, identity, resource, delivery, callerCompletedAt)
	assertPluginWebhookCode084(t, err, "P8407")
	var completedAt, nextAttemptAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT attempt.completed_at,delivery.next_attempt_at
		FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		WHERE attempt.claim_token=$1`, claim).Scan(&completedAt, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if completedAt.Equal(callerCompletedAt) || !nextAttemptAt.Equal(completedAt.Add(time.Second)) {
		t.Fatalf("retry clock completed/next=%s/%s caller=%s", completedAt, nextAttemptAt,
			callerCompletedAt)
	}
	if _, err := pool.Exec(t.Context(), `SELECT pg_sleep(
		GREATEST(EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())),0)+0.01)`,
		nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	boundClaim, err := insertPluginWebhookClaim084(t, pool, identity, resource, delivery,
		nextAttemptAt)
	if err != nil {
		t.Fatalf("claim at retry bound: %v", err)
	}
	var claimRecordedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_recorded_at
		FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, boundClaim).Scan(&claimRecordedAt); err != nil {
		t.Fatal(err)
	}
	if claimRecordedAt.Before(nextAttemptAt) {
		t.Fatalf("claim recorded_at=%s before next_attempt_at=%s", claimRecordedAt, nextAttemptAt)
	}
}

func TestPluginWebhookControl084AttemptTransitionLockClock(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	runBlocked := func(hold time.Duration, transition func(*pgxpool.Conn) error) time.Time {
		t.Helper()
		blocker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Release()
		worker, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Release()
		blockerTx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blockerTx.Rollback(context.Background())
		if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM plugin_webhook_subscriptions
			WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, identity.tenantScope,
			resource.subscription); err != nil {
			t.Fatal(err)
		}
		var blockerPID, workerPID int32
		if err := blockerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- transition(worker) }()
		waitForPluginWebhookBlock084(t, pool, workerPID, blockerPID)
		var releasedAt time.Time
		if err := blockerTx.QueryRow(ctx,
			`SELECT clock_timestamp() FROM (SELECT pg_sleep($1)) delayed`,
			hold.Seconds()).Scan(&releasedAt); err != nil {
			t.Fatal(err)
		}
		if err := blockerTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatalf("blocked attempt transition did not finish: %v", ctx.Err())
		}
		return releasedAt
	}

	var revision, lifecycle, attempts string
	var activeSecret uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT subscription.revision::text,
		subscription.lifecycle_sequence::text,subscription.active_secret_version_id,
		delivery.attempt_count::text
		FROM plugin_webhook_subscriptions subscription
		JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=subscription.tenant_scope_id
		 AND delivery.subscription_id=subscription.id AND delivery.id=$3
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`, identity.tenantScope,
		resource.subscription, delivery).Scan(&revision, &lifecycle, &activeSecret, &attempts); err != nil {
		t.Fatal(err)
	}
	claim := uuid.New()
	claimRelease := runBlocked(0, func(worker *pgxpool.Conn) error {
		_, err := worker.Exec(ctx, `INSERT INTO plugin_webhook_delivery_attempts(
			tenant_scope_id,subscription_id,delivery_id,actor_scope_id,actor_user_id,
			attempt_number,claim_token,claim_sequence,claimed_subscription_revision,
			secret_version_id,status,claimed_at
		) VALUES($1,$2,$3,$1,$4,($5::numeric+1),$6,($7::numeric+1),$8,$9,'claimed',
			clock_timestamp())`, identity.tenantScope, resource.subscription, delivery,
			identity.ownerUser, attempts, claim, lifecycle, revision, activeSecret)
		return err
	})
	var claimedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT claimed_at FROM plugin_webhook_delivery_attempts
		WHERE claim_token=$1`, claim).Scan(&claimedAt); err != nil {
		t.Fatal(err)
	}

	startRelease := runBlocked(0, func(worker *pgxpool.Conn) error {
		_, err := worker.Exec(ctx, `UPDATE plugin_webhook_delivery_attempts attempt
			SET status='started',started_at=clock_timestamp(),request_sha256=event.body_sha256
			FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
			  ON event.tenant_scope_id=delivery.tenant_scope_id
			 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
			WHERE attempt.claim_token=$1 AND delivery.tenant_scope_id=attempt.tenant_scope_id
			  AND delivery.subscription_id=attempt.subscription_id
			  AND delivery.id=attempt.delivery_id`, claim)
		return err
	})
	var startedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT started_at FROM plugin_webhook_delivery_attempts
		WHERE claim_token=$1`, claim).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}

	completeRelease := runBlocked(1100*time.Millisecond, func(worker *pgxpool.Conn) error {
		_, err := worker.Exec(ctx, `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=clock_timestamp(),http_status=503,
				failure_code='upstream_timeout',retry_after_seconds=1,response_sha256=$2,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, bytes084(32, 0xf6))
		return err
	})
	var completedAt, nextAttemptAt, committedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT attempt.completed_at,delivery.next_attempt_at,clock_timestamp()
		FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		WHERE attempt.claim_token=$1`, claim).Scan(&completedAt, &nextAttemptAt, &committedAt); err != nil {
		t.Fatal(err)
	}

	reconnected, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	var durableClaimedAt, durableStartedAt, durableCompletedAt, durableNextAttemptAt time.Time
	if err := reconnected.QueryRow(ctx, `SELECT attempt.claimed_at,attempt.started_at,
		attempt.completed_at,delivery.next_attempt_at
		FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		WHERE attempt.claim_token=$1`, claim).Scan(&durableClaimedAt, &durableStartedAt,
		&durableCompletedAt, &durableNextAttemptAt); err != nil {
		t.Fatal(err)
	}

	var failures []string
	if claimedAt.Before(claimRelease) {
		failures = append(failures, fmt.Sprintf("claim=%s before lock release=%s", claimedAt, claimRelease))
	}
	if startedAt.Before(startRelease) {
		failures = append(failures, fmt.Sprintf("start=%s before lock release=%s", startedAt, startRelease))
	}
	if completedAt.Before(completeRelease) {
		failures = append(failures, fmt.Sprintf("complete=%s before lock release=%s", completedAt, completeRelease))
	}
	if claimedAt.After(startedAt) || startedAt.After(completedAt) {
		failures = append(failures, fmt.Sprintf("lifecycle order claim/start/complete=%s/%s/%s",
			claimedAt, startedAt, completedAt))
	}
	if !nextAttemptAt.Equal(completedAt.Add(time.Second)) || !nextAttemptAt.After(committedAt) {
		failures = append(failures, fmt.Sprintf("retry complete/next/commit=%s/%s/%s",
			completedAt, nextAttemptAt, committedAt))
	}
	if !durableClaimedAt.Equal(claimedAt) || !durableStartedAt.Equal(startedAt) ||
		!durableCompletedAt.Equal(completedAt) || !durableNextAttemptAt.Equal(nextAttemptAt) {
		failures = append(failures, "reconnected attempt lifecycle timestamps changed")
	}
	if len(failures) != 0 {
		t.Fatalf("attempt transitions used pre-lock transaction time: %s", strings.Join(failures, "; "))
	}
}

func TestPluginWebhookControl084PhysicalCleanupClock(t *testing.T) {
	t.Run("pending secret cannot expire early", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		databaseNow := pluginWebhookDatabaseTime084(t, pool)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2, databaseNow)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='expired',nonce=NULL,ciphertext=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, pending)
		if err == nil {
			t.Fatal("pending secret expired before its physical expiry")
		}
		assertPluginWebhookCode084(t, err, "P8406")
	})

	t.Run("retired secret cannot terminate a claim early", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		rotatePluginWebhookSecret084(t, pool, identity, resource, pluginWebhook084Now)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='expired',nonce=NULL,ciphertext=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret)
		if err == nil {
			var attemptStatus, deliveryStatus string
			var completedAt, expiresAt time.Time
			if scanErr := pool.QueryRow(t.Context(), `SELECT attempt.status,delivery.status,
				attempt.completed_at,secret.expires_at
				FROM plugin_webhook_delivery_attempts attempt
				JOIN plugin_webhook_deliveries delivery
				  ON delivery.tenant_scope_id=attempt.tenant_scope_id
				 AND delivery.subscription_id=attempt.subscription_id
				 AND delivery.id=attempt.delivery_id
				JOIN plugin_webhook_secret_versions secret
				  ON secret.tenant_scope_id=attempt.tenant_scope_id
				 AND secret.subscription_id=attempt.subscription_id
				 AND secret.id=attempt.secret_version_id
				WHERE attempt.claim_token=$1`, claim).Scan(&attemptStatus, &deliveryStatus,
				&completedAt, &expiresAt); scanErr != nil {
				t.Fatal(scanErr)
			}
			t.Fatalf("early retired-secret expiry committed attempt/delivery=%s/%s completed=%s expiry=%s",
				attemptStatus, deliveryStatus, completedAt, expiresAt)
		}
		assertPluginWebhookCode084(t, err, "P8406")
	})

	for _, operation := range []string{
		"plugin_webhook.subscription.create",
		"plugin_webhook.secret.rotate",
	} {
		t.Run(operation+" receipt cannot clear early", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			if operation == "plugin_webhook.secret.rotate" {
				if _, err := insertPluginWebhookPendingSecretResult084(t, pool, identity, resource,
					pluginWebhookDatabaseTime084(t, pool)); err != nil {
					t.Fatal(err)
				}
			}
			var requestID uuid.UUID
			var receiptExpiresAt time.Time
			if err := pool.QueryRow(t.Context(), `SELECT id,receipt_expires_at
				FROM plugin_webhook_write_requests
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND operation=$3`,
				identity.tenantScope, resource.subscription, operation).
				Scan(&requestID, &receiptExpiresAt); err != nil {
				t.Fatal(err)
			}
			_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
				SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=$2,
					receipt_cleared_reason='expired' WHERE id=$1`,
				requestID, receiptExpiresAt.Add(time.Hour))
			if err == nil {
				t.Fatalf("%s receipt cleared before physical expiry %s", operation, receiptExpiresAt)
			}
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}

	t.Run("post expiry cleanup remains available", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhookDatabaseTime084(t, pool))
		agePluginWebhookSecretExpiry084(t, pool, identity.tenantScope,
			resource.subscription, pending)
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='expired',nonce=NULL,ciphertext=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, pending); err != nil {
			t.Fatalf("expire pending secret after physical boundary: %v", err)
		}
	})
}

func TestPluginWebhookControl084ExpiredCiphertextRoleIsolation(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	rotatePluginWebhookSecret084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))

	var requestID uuid.UUID
	var requestDigest []byte
	var requestKey string
	if err := pool.QueryRow(t.Context(), `SELECT id,request_digest,idempotency_key
		FROM plugin_webhook_write_requests
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
		resource.subscription).Scan(&requestID, &requestDigest, &requestKey); err != nil {
		t.Fatal(err)
	}
	controlPool := pluginWebhookLoginPool084(t, pool, "open084_control_login")
	runtimePool := pluginWebhookLoginPool084(t, pool, "open084_runtime_login")

	t.Run("raw secret and receipt columns are denied", func(t *testing.T) {
		if _, err := runtimePool.Exec(t.Context(), `SELECT nonce,ciphertext
			FROM plugin_webhook_secret_versions
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret); err == nil {
			t.Fatal("runtime login read raw secret envelope")
		} else {
			assertPluginWebhookCode084(t, err, "42501")
		}
		if _, err := controlPool.Exec(t.Context(), `SELECT receipt_nonce,receipt_ciphertext
			FROM plugin_webhook_write_requests WHERE id=$1`, requestID); err == nil {
			t.Fatal("control login read raw receipt envelope")
		} else {
			assertPluginWebhookCode084(t, err, "42501")
		}
	})

	t.Run("retired secret envelope expires at the physical boundary", func(t *testing.T) {
		var nonce, ciphertext []byte
		if err := runtimePool.QueryRow(t.Context(), `SELECT nonce,ciphertext
			FROM read_plugin_webhook_secret_envelope_084($1,$2,$3)`, identity.tenantScope,
			resource.subscription, resource.secret).Scan(&nonce, &ciphertext); err != nil {
			t.Fatalf("read live retired secret envelope: %v", err)
		}
		if len(nonce) != 12 || len(ciphertext) != 48 {
			t.Fatalf("live retired secret envelope lengths=%d/%d", len(nonce), len(ciphertext))
		}
		agePluginWebhookSecretExpiry084(t, pool, identity.tenantScope,
			resource.subscription, resource.secret)
		err := runtimePool.QueryRow(t.Context(), `SELECT nonce,ciphertext
			FROM read_plugin_webhook_secret_envelope_084($1,$2,$3)`, identity.tenantScope,
			resource.subscription, resource.secret).Scan(&nonce, &ciphertext)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expired retired secret envelope remains readable: %v", err)
		}
		var cleared bool
		if err := pool.QueryRow(t.Context(), `SELECT status='expired' AND nonce IS NULL AND ciphertext IS NULL
			FROM plugin_webhook_secret_versions
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
			resource.subscription, resource.secret).Scan(&cleared); err != nil || !cleared {
			t.Fatalf("expired retired secret physical cleanup=%t err=%v", cleared, err)
		}
	})

	t.Run("receipt envelope expires at the physical boundary", func(t *testing.T) {
		var nonce, ciphertext []byte
		if err := controlPool.QueryRow(t.Context(), `SELECT receipt_nonce,receipt_ciphertext
			FROM read_plugin_webhook_receipt_envelope_084($1,$2,$3,$4)`,
			identity.tenantScope, identity.tenantScope, identity.ownerUser, requestKey).
			Scan(&nonce, &ciphertext); err != nil {
			t.Fatalf("read live receipt envelope: %v", err)
		}
		if len(nonce) != 12 || len(ciphertext) != 48 {
			t.Fatalf("live receipt envelope lengths=%d/%d", len(nonce), len(ciphertext))
		}
		agePluginWebhookReceipt084(t, pool, requestID)
		err := controlPool.QueryRow(t.Context(), `SELECT receipt_nonce,receipt_ciphertext
			FROM read_plugin_webhook_receipt_envelope_084($1,$2,$3,$4)`,
			identity.tenantScope, identity.tenantScope, identity.ownerUser, requestKey).
			Scan(&nonce, &ciphertext)
		if err != nil || len(nonce) != 0 || len(ciphertext) != 0 {
			t.Fatalf("expired receipt envelope remains readable: nonce=%d ciphertext=%d err=%v",
				len(nonce), len(ciphertext), err)
		}
		var cleared bool
		if err := pool.QueryRow(t.Context(), `SELECT receipt_nonce IS NULL AND receipt_ciphertext IS NULL
				AND receipt_cleared_reason='expired'
			FROM plugin_webhook_write_requests WHERE id=$1`, requestID).Scan(&cleared); err != nil || !cleared {
			t.Fatalf("expired receipt physical cleanup=%t err=%v", cleared, err)
		}
	})

	t.Run("dual role login is denied both envelopes", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `GRANT cdnca_plugin_webhook_runtime TO open084_control_login`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Exec(t.Context(), `REVOKE cdnca_plugin_webhook_runtime FROM open084_control_login`); err != nil {
				t.Errorf("revoke temporary dual role: %v", err)
			}
		}()
		_, err := controlPool.Exec(t.Context(), `SELECT nonce,ciphertext
			FROM read_plugin_webhook_secret_envelope_084($1,$2,$3)`, identity.tenantScope,
			resource.subscription, resource.secret)
		assertPluginWebhookCode084(t, err, "P8408")
		_, err = controlPool.Exec(t.Context(), `SELECT receipt_nonce,receipt_ciphertext
			FROM read_plugin_webhook_receipt_envelope_084($1,$2,$3,$4)`,
			identity.tenantScope, identity.tenantScope, identity.ownerUser, requestKey)
		assertPluginWebhookCode084(t, err, "P8408")
	})
}

func TestPluginWebhookControl084ResponsePreviewRedaction(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		pluginWebhookDatabaseTime084(t, pool))
	startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
	err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_delivery_attempts
		SET status='succeeded',completed_at=clock_timestamp(),http_status=204,
			response_sha256=$2,response_bytes=24,response_preview=$3,
			sanitized_headers='{}'::jsonb WHERE claim_token=$1`, claim, bytes084(32, 0xb8),
		[]byte("token=must-not-persist"))
	if err != nil {
		t.Fatalf("terminal attempt with untrusted preview: %v", err)
	}
	var preview []byte
	if err := pool.QueryRow(t.Context(), `SELECT response_preview
		FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, claim).Scan(&preview); err != nil {
		t.Fatal(err)
	}
	if len(preview) != 0 {
		t.Fatalf("terminal response preview persisted %d bytes", len(preview))
	}
}

func TestPluginWebhookControl084ActivationStartLockOrder(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
		pluginWebhookDatabaseTime084(t, pool))
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		pluginWebhookDatabaseTime084(t, pool))
	requestID, requestKey, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.activate",
		resource.subscription, uuid.Nil, pending, pluginWebhookDatabaseTime084(t, pool))
	if err != nil {
		t.Fatal(err)
	}

	activationTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer activationTx.Rollback(t.Context())
	transitionAt := pluginWebhookDatabaseTime084(t, activationTx)
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), activationTx,
		identity.tenantScope, identity.tenantScope, identity.ownerUser,
		"plugin_webhook.secret.activate", "success", "accepted",
		"plugin_webhook_secret_version", pending.String(), requestKey, transitionAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET response_status=200,response_body=jsonb_build_object(
			'subscription_id',subscription_id::text,'rotation_id',rotation_id::text),
			audit_event_id=$2,completed_at=$3 WHERE id=$1`, requestID, auditID, transitionAt); err != nil {
		t.Fatal(err)
	}
	if _, err := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz+interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, resource.secret, transitionAt); err != nil {
		t.Fatal(err)
	}

	config := pool.Config().ConnConfig.Copy()
	config.User = "open084_runtime_login"
	runtimeConnection, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeConnection.Close(t.Context())
	runtimeTx, err := runtimeConnection.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeTx.Rollback(t.Context())
	var runtimePID int
	if err := runtimeTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&runtimePID); err != nil {
		t.Fatal(err)
	}
	startResult := make(chan error, 1)
	go func() {
		_, updateErr := runtimeTx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts attempt
			SET status='started',started_at=clock_timestamp(),request_sha256=event.body_sha256
			FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
			  ON event.tenant_scope_id=delivery.tenant_scope_id
			 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
			WHERE attempt.claim_token=$1 AND delivery.tenant_scope_id=attempt.tenant_scope_id
			  AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id`, claim)
		if updateErr == nil {
			updateErr = runtimeTx.Commit(t.Context())
		}
		startResult <- updateErr
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT COALESCE(wait_event_type='Lock',false)
			FROM pg_stat_activity WHERE pid=$1`, runtimePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("started-attempt transaction did not reach the secret lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_, pendingErr := activationTx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, pending, transitionAt)
	var subscriptionErr error
	if pendingErr == nil {
		_, subscriptionErr = activationTx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET active_secret_version_id=$3,revision=revision+1,
				lifecycle_sequence=lifecycle_sequence+1,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription,
			pending, transitionAt)
	}
	activationErr := pendingErr
	if activationErr == nil {
		activationErr = subscriptionErr
	}
	if activationErr == nil {
		activationErr = activationTx.Commit(t.Context())
	}
	startErr := <-startResult
	if pgErrCodeFromError084(activationErr) == "40P01" || pgErrCodeFromError084(startErr) == "40P01" {
		t.Fatalf("activation/start lock order deadlocked: activation=%v start=%v", activationErr, startErr)
	}
	if activationErr != nil || startErr != nil {
		t.Fatalf("activation/start overlap failed: activation=%v start=%v", activationErr, startErr)
	}
}

func TestPluginWebhookControl084RevokePhysicalLinearization(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	requestID, requestKey, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.subscription.revoke",
		resource.subscription, uuid.Nil, uuid.Nil, pluginWebhookDatabaseTime084(t, pool))
	if err != nil {
		t.Fatal(err)
	}

	revokeTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer revokeTx.Rollback(t.Context())
	transactionStart := pluginWebhookDatabaseTime084(t, revokeTx)
	if _, err := revokeTx.Exec(t.Context(), `SELECT pg_sleep(0.1)`); err != nil {
		t.Fatal(err)
	}
	var physicalBoundary time.Time
	if err := revokeTx.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&physicalBoundary); err != nil {
		t.Fatal(err)
	}
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), revokeTx,
		identity.tenantScope, identity.tenantScope, identity.ownerUser,
		"plugin_webhook.subscription.revoke", "success", "accepted",
		"plugin_webhook_subscription", resource.subscription.String(), requestKey, transactionStart)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokeTx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET response_status=200,response_body=jsonb_build_object(
			'subscription_id',subscription_id::text),audit_event_id=$2,completed_at=$3
		WHERE id=$1`, requestID, auditID, transactionStart); err != nil {
		t.Fatal(err)
	}
	if _, err := revokeTx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription,
		transactionStart); err != nil {
		t.Fatal(err)
	}
	if err := revokeTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	var revokedAt, requestCompletedAt, auditOccurredAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT subscription.revoked_at,request.completed_at,audit.occurred_at
		FROM plugin_webhook_subscriptions subscription
		JOIN plugin_webhook_write_requests request
		  ON request.tenant_scope_id=subscription.tenant_scope_id
		 AND request.subscription_id=subscription.id
		 AND request.operation='plugin_webhook.subscription.revoke'
		JOIN audit_events audit ON audit.id=request.audit_event_id
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`, identity.tenantScope,
		resource.subscription).Scan(&revokedAt, &requestCompletedAt, &auditOccurredAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt.Before(physicalBoundary) || !revokedAt.Equal(requestCompletedAt) ||
		!revokedAt.Equal(auditOccurredAt) {
		t.Fatalf("revoke physical marker transaction/boundary/request/audit=%s/%s/%s/%s/%s",
			transactionStart, physicalBoundary, revokedAt, requestCompletedAt, auditOccurredAt)
	}
}

func TestPluginWebhookControl084RetryBackoffPolicy(t *testing.T) {
	t.Run("server backoff grows beyond the response header cap", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		ranges := []struct {
			minimum time.Duration
			maximum time.Duration
		}{
			{minimum: 45 * time.Second, maximum: 60 * time.Second},
			{minimum: 90 * time.Second, maximum: 120 * time.Second},
			{minimum: 180 * time.Second, maximum: 240 * time.Second},
			{minimum: 360 * time.Second, maximum: 480 * time.Second},
		}
		for index, expected := range ranges {
			claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
				pluginWebhookDatabaseTime084(t, pool))
			startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
			if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
				SET status='temporary_failure',completed_at=$2,http_status=503,
					failure_code='upstream_timeout',response_sha256=$3,response_bytes=0,
					response_preview=''::bytea,sanitized_headers='{}'::jsonb
				WHERE claim_token=$1`, claim, pluginWebhook084Now.Add(time.Duration(index)*time.Hour),
				bytes084(32, byte(0xd0+index))); err != nil {
				t.Fatal(err)
			}
			var completedAt, nextAttemptAt time.Time
			var storedDelay int
			if err := pool.QueryRow(t.Context(), `SELECT attempt.completed_at,delivery.next_attempt_at
				,attempt.retry_delay_seconds
				FROM plugin_webhook_delivery_attempts attempt
				JOIN plugin_webhook_deliveries delivery
				  ON delivery.tenant_scope_id=attempt.tenant_scope_id
				 AND delivery.subscription_id=attempt.subscription_id
				 AND delivery.id=attempt.delivery_id
				WHERE attempt.claim_token=$1`, claim).Scan(&completedAt, &nextAttemptAt, &storedDelay); err != nil {
				t.Fatal(err)
			}
			delay := nextAttemptAt.Sub(completedAt)
			if delay < expected.minimum || delay > expected.maximum ||
				storedDelay != int(delay/time.Second) {
				t.Fatalf("attempt %d server backoff=%s want %s..%s", index+1, delay,
					expected.minimum, expected.maximum)
			}
			if index == len(ranges)-1 {
				break
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
				_ = tx.Rollback(t.Context())
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
				SET next_attempt_at=clock_timestamp()-interval '1 microsecond'
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
				resource.subscription, delivery); err != nil {
				_ = tx.Rollback(t.Context())
				t.Fatal(err)
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("derived jitter is deterministic capped and not caller writable", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		completedAt := pluginWebhookDatabaseTime084(t, pool)
		deliveryID := uuid.New()
		var first, repeated, capped int
		if err := pool.QueryRow(t.Context(), `SELECT
			plugin_webhook_retry_delay_seconds_084($1,4,$2,NULL),
			plugin_webhook_retry_delay_seconds_084($1,4,$2,NULL),
			plugin_webhook_retry_delay_seconds_084($1,5,$2,NULL)`, deliveryID, completedAt).
			Scan(&first, &repeated, &capped); err != nil {
			t.Fatal(err)
		}
		if first != repeated || first < 360 || first > 480 || capped < 675 || capped > 900 {
			t.Fatalf("derived retry delays first/repeated/capped=%d/%d/%d", first, repeated, capped)
		}

		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=$2,http_status=503,
				failure_code='upstream_timeout',retry_delay_seconds=777,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now, bytes084(32, 0xd4))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("response Retry-After keeps the five minute bound", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=$2,http_status=503,
				failure_code='upstream_timeout',retry_after_seconds=300,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now, bytes084(32, 0xd5)); err != nil {
			t.Fatal(err)
		}
		var delaySeconds int
		if err := pool.QueryRow(t.Context(), `SELECT extract(epoch FROM
			(delivery.next_attempt_at-attempt.completed_at))::integer
			FROM plugin_webhook_delivery_attempts attempt
			JOIN plugin_webhook_deliveries delivery
			  ON delivery.tenant_scope_id=attempt.tenant_scope_id
			 AND delivery.subscription_id=attempt.subscription_id
			 AND delivery.id=attempt.delivery_id
			WHERE attempt.claim_token=$1`, claim).Scan(&delaySeconds); err != nil {
			t.Fatal(err)
		}
		if delaySeconds != 300 {
			t.Fatalf("Retry-After delay=%d want=300", delaySeconds)
		}

		pool, identity, resource = setupPluginWebhook084(t)
		delivery = seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim = claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=$2,http_status=503,
				failure_code='upstream_timeout',retry_after_seconds=301,response_sha256=$3,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, pluginWebhook084Now, bytes084(32, 0xd6))
		if err == nil {
			t.Fatal("response Retry-After above 300 seconds was accepted")
		}
	})
}

func TestPluginWebhookControl084AttemptRequestDigestBinding(t *testing.T) {
	t.Run("unrelated digest", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		err := startPluginWebhookAttemptResult084(t, pool, claim, true, pluginWebhook084Now.Add(2*time.Minute))
		if err == nil {
			t.Fatal("attempt accepted a request digest unrelated to the canonical event body")
		}
	})

	t.Run("canonical event digest", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhook084Now.Add(time.Minute))
		if err := startPluginWebhookAttemptResult084(t, pool, claim, false,
			pluginWebhook084Now.Add(2*time.Minute)); err != nil {
			t.Fatalf("canonical event digest rejected: %v", err)
		}
	})
}

func TestPluginWebhookControl084InitialSecretActorBinding(t *testing.T) {
	if err := insertPluginWebhookSplitCreateActorResult084(t); err == nil {
		t.Fatal("initial active secret accepted a different authorized manager provenance")
	}
	pool, identity, resource := setupPluginWebhook084(t)
	var sameActor bool
	if err := pool.QueryRow(t.Context(), `SELECT subscription.actor_scope_id=secret.actor_scope_id AND
		subscription.actor_user_id=secret.actor_user_id FROM plugin_webhook_subscriptions subscription
		JOIN plugin_webhook_secret_versions secret ON secret.tenant_scope_id=subscription.tenant_scope_id
		 AND secret.subscription_id=subscription.id AND secret.id=subscription.active_secret_version_id
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`, identity.tenantScope,
		resource.subscription).Scan(&sameActor); err != nil || !sameActor {
		t.Fatalf("exact initial secret provenance=%t err=%v", sameActor, err)
	}
}

func TestPluginWebhookControl084AuditResourceRequestBinding(t *testing.T) {
	for _, drift := range []string{"resource type", "resource id", "request id"} {
		t.Run(drift, func(t *testing.T) {
			if err := revokePluginWebhookWithAuditDriftResult084(t, drift); err == nil {
				t.Fatalf("management fact accepted mismatched audit %s", drift)
			}
		})
	}
}

func TestPluginWebhookControl084ExactResponseStatus(t *testing.T) {
	checks := []struct {
		operation string
		status    int
	}{
		{operation: "plugin_webhook.subscription.create", status: 200},
		{operation: "plugin_webhook.test_delivery.create", status: 201},
		{operation: "plugin_webhook.delivery.replay", status: 204},
		{operation: "plugin_webhook.secret.rotate", status: 202},
		{operation: "plugin_webhook.secret.activate", status: 201},
		{operation: "plugin_webhook.subscription.revoke", status: 202},
	}
	for _, check := range checks {
		t.Run(check.operation, func(t *testing.T) {
			err := insertPluginWebhookStandaloneCompletedRequest084(t, check.operation, check.status)
			assertPluginWebhookCode084(t, err, "23514")
		})
	}
}

func TestPluginWebhookControl084PendingCompletionLiveAuthorization(t *testing.T) {
	checks := []struct {
		operation  string
		revocation string
	}{
		{operation: "plugin_webhook.subscription.create", revocation: "membership"},
		{operation: "plugin_webhook.test_delivery.create", revocation: "user"},
		{operation: "plugin_webhook.delivery.replay", revocation: "role"},
		{operation: "plugin_webhook.secret.rotate", revocation: "custom_grant"},
		{operation: "plugin_webhook.secret.activate", revocation: "membership"},
		{operation: "plugin_webhook.subscription.revoke", revocation: "custom_grant"},
	}
	for _, check := range checks {
		t.Run(check.operation+"/"+check.revocation, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			actorUser := identity.ownerUser
			var grantID uuid.UUID
			if check.revocation == "custom_grant" {
				_, grantID = seedPluginWebhookCustomRole084(t, pool, identity)
				actorUser = identity.customUser
			}
			delivery := uuid.Nil
			if check.operation == "plugin_webhook.test_delivery.create" ||
				check.operation == "plugin_webhook.delivery.replay" {
				delivery = seedPluginWebhookDelivery084(t, pool, identity, resource,
					pluginWebhook084Now.Add(time.Hour))
			}
			rotation := uuid.Nil
			if check.operation == "plugin_webhook.secret.rotate" ||
				check.operation == "plugin_webhook.secret.activate" {
				rotation = resource.secret
			}
			requestID, key, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
				identity.tenantScope, actorUser, check.operation, resource.subscription, delivery,
				rotation, pluginWebhook084Now.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			switch check.revocation {
			case "membership":
				_, err = pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
					WHERE scope_id=$1 AND user_id=$2`, identity.tenantScope, actorUser)
			case "user":
				_, err = pool.Exec(t.Context(), `UPDATE users SET status='disabled',revision=revision+1,
					updated_at=$2 WHERE id=$1`, actorUser, pluginWebhook084Now.Add(2*time.Hour+time.Second))
			case "role":
				_, err = pool.Exec(t.Context(), `DELETE FROM role_assignments
					WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, identity.tenantScope,
					actorUser, identity.ownerRole)
			case "custom_grant":
				revokePluginWebhookCustomRole084(t, pool, identity, grantID)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = completePluginWebhookIncompleteRequest084(t, pool, identity, requestID, key,
				identity.tenantScope, actorUser, check.operation, resource.subscription, delivery,
				rotation, pluginWebhook084Now.Add(3*time.Hour))
			assertPluginWebhookCode084(t, err, "P8402")
			var incomplete bool
			if err := pool.QueryRow(t.Context(), `SELECT completed_at IS NULL AND audit_event_id IS NULL
				FROM plugin_webhook_write_requests WHERE id=$1`, requestID).Scan(&incomplete); err != nil || !incomplete {
				t.Fatalf("revoked actor request stayed incomplete=%t err=%v", incomplete, err)
			}
		})
	}

	for _, revocation := range []string{"user", "membership", "role"} {
		t.Run("platform/"+revocation, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			requestID, key, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
				identity.platformScope, identity.platformAdmin, "plugin_webhook.subscription.revoke",
				resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			switch revocation {
			case "user":
				_, err = pool.Exec(t.Context(), `UPDATE users SET status='disabled',revision=revision+1,
					updated_at=$2 WHERE id=$1`, identity.platformAdmin,
					pluginWebhook084Now.Add(2*time.Hour+time.Second))
			case "membership":
				_, err = pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
					WHERE scope_id=$1 AND user_id=$2`, identity.platformScope, identity.platformAdmin)
			case "role":
				_, err = pool.Exec(t.Context(), `DELETE FROM role_assignments
					WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, identity.platformScope,
					identity.platformAdmin, identity.platformRoles["platform_admin"])
			}
			if err != nil {
				t.Fatal(err)
			}
			err = completePluginWebhookIncompleteRequest084(t, pool, identity, requestID, key,
				identity.platformScope, identity.platformAdmin, "plugin_webhook.subscription.revoke",
				resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(3*time.Hour))
			assertPluginWebhookCode084(t, err, "P8402")
			var incomplete, active bool
			if err := pool.QueryRow(t.Context(), `SELECT request.completed_at IS NULL,
				subscription.status='active' FROM plugin_webhook_write_requests request
				JOIN plugin_webhook_subscriptions subscription
				  ON subscription.tenant_scope_id=request.tenant_scope_id
				 AND subscription.id=request.subscription_id WHERE request.id=$1`, requestID).Scan(
				&incomplete, &active); err != nil || !incomplete || !active {
				t.Fatalf("platform revoke left incomplete/active=%t/%t err=%v", incomplete, active, err)
			}
		})
	}

	t.Run("platform/custom grant", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, identity.platformScope, identity.platformReader,
			identity.platformRoles["platform_admin"]); err != nil {
			t.Fatal(err)
		}
		var tenantMembership bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM memberships
			WHERE scope_id=$1 AND user_id=$2)`, identity.tenantScope,
			identity.platformReader).Scan(&tenantMembership); err != nil || tenantMembership {
			t.Fatalf("platform custom actor tenant membership=%t err=%v", tenantMembership, err)
		}
		requestID, key, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
			identity.platformScope, identity.platformReader, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, identity.platformScope,
			identity.platformReader, identity.platformRoles["platform_admin"]); err != nil {
			t.Fatal(err)
		}
		err = completePluginWebhookIncompleteRequest084(t, pool, identity, requestID, key,
			identity.platformScope, identity.platformReader, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(3*time.Hour))
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("platform reader cannot precreate management request", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, _, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
			identity.platformScope, identity.platformReader, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(2*time.Hour))
		assertPluginWebhookCode084(t, err, "P8402")
	})

	t.Run("platform actor retains explicit target scope", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		requestID, key, err := insertPluginWebhookIncompleteRequest084(t, pool, identity,
			identity.platformScope, identity.platformAdmin, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := completePluginWebhookIncompleteRequest084(t, pool, identity, requestID, key,
			identity.platformScope, identity.platformAdmin, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, uuid.Nil, pluginWebhook084Now.Add(3*time.Hour)); err != nil {
			t.Fatalf("live platform actor explicit tenant target: %v", err)
		}
	})
}

func TestPluginWebhookControl084DatabaseRateClockContract(t *testing.T) {
	for _, operation := range []string{
		"plugin_webhook.subscription.create",
		"plugin_webhook.test_delivery.create",
		"plugin_webhook.delivery.replay",
		"plugin_webhook.secret.rotate",
	} {
		for _, offset := range []time.Duration{-2 * time.Hour, 2 * time.Hour} {
			name := "backdated"
			if offset > 0 {
				name = "future"
			}
			t.Run(operation+"/"+name, func(t *testing.T) {
				pool, identity, resource := setupPluginWebhook084(t)
				databaseNow := pluginWebhookDatabaseTime084(t, pool)
				err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
					resource.subscription, operation, databaseNow.Add(offset))
				assertPluginWebhookCode084(t, err, "P8408")
			})
		}

		t.Run(operation+"/database window", func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			limit := 5
			if operation == "plugin_webhook.subscription.create" {
				limit = 9
			}
			for index := 0; index < limit; index++ {
				if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
					resource.subscription, operation, time.Time{}); err != nil {
					t.Fatalf("database-clock rate %d/%d: %v", index+1, limit, err)
				}
			}
			err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
				resource.subscription, operation, time.Time{})
			assertPluginWebhookCode084(t, err, "P8408")
		})
	}

	t.Run("server marker schema and window source", func(t *testing.T) {
		pool, _, _ := setupPluginWebhook084(t)
		var columns int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
			WHERE column_name='plugin_webhook_recorded_at' AND data_type='timestamp with time zone'
			  AND table_schema=current_schema() AND table_name = ANY($1::text[])`, []string{
			"audit_events", "plugin_webhook_subscriptions", "plugin_webhook_secret_versions",
			"plugin_webhook_write_requests", "plugin_webhook_events", "plugin_webhook_deliveries",
			"plugin_webhook_delivery_attempts", "plugin_webhook_dead_letters",
			"plugin_webhook_rate_events",
		}).Scan(&columns); err != nil {
			t.Fatal(err)
		}
		if columns != 9 {
			t.Fatalf("server-recorded command marker columns=%d want=9", columns)
		}
		source := pluginWebhookFunctionSource084(t, pool, "enforce_plugin_webhook_rate_084()")
		if !strings.Contains(source, "plugin_webhook_recorded_at") ||
			strings.Contains(source, "NEW.occurred_at - interval") {
			t.Fatal("durable rate window still trusts caller occurred_at")
		}
	})
}

func TestPluginWebhookControl084RateLinearizationEvidence(t *testing.T) {
	t.Run("exact lower window boundary", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		for index := 0; index < 4; index++ {
			if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
				resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		var position int64
		var previous []byte
		if err := pool.QueryRow(t.Context(), `SELECT stream_position,event_hash FROM audit_events
			WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, identity.tenantScope).
			Scan(&position, &previous); err != nil {
			t.Fatal(err)
		}
		seedTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		seedAt := pluginWebhookDatabaseTime084(t, seedTx)
		seedRate, seedAudit, seedHash, err := insertPluginWebhookTestRateAuditTx084(t.Context(), seedTx,
			identity, resource.subscription, position+1, previous, seedAt)
		if err == nil {
			err = insertPluginWebhookTestRateRowTx084(t.Context(), seedTx, identity,
				resource.subscription, seedRate, seedAudit, seedAt)
		}
		if err == nil {
			err = seedTx.Commit(t.Context())
		} else {
			_ = seedTx.Rollback(t.Context())
		}
		if err != nil {
			t.Fatal(err)
		}

		boundaryTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer boundaryTx.Rollback(t.Context())
		windowNow := pluginWebhookDatabaseTime084(t, boundaryTx)
		if _, err := boundaryTx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			t.Fatal(err)
		}
		if _, err := boundaryTx.Exec(t.Context(), `UPDATE plugin_webhook_rate_events
			SET occurred_at=$2::timestamptz-interval '1 minute',
				plugin_webhook_recorded_at=$2::timestamptz-interval '1 minute',
				plugin_webhook_physical_recorded_at=$2::timestamptz-interval '1 minute' WHERE id=$1`,
			seedRate, windowNow); err != nil {
			t.Fatal(err)
		}
		if _, err := boundaryTx.Exec(t.Context(), `UPDATE audit_events
			SET occurred_at=$2::timestamptz-interval '1 minute',
				plugin_webhook_recorded_at=$2::timestamptz-interval '1 minute' WHERE id=$1`,
			seedAudit, windowNow); err != nil {
			t.Fatal(err)
		}
		if _, err := boundaryTx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`); err != nil {
			t.Fatal(err)
		}
		rateID, auditID, _, err := insertPluginWebhookTestRateAuditTx084(t.Context(), boundaryTx,
			identity, resource.subscription, position+2, seedHash, windowNow)
		if err == nil {
			err = insertPluginWebhookTestRateRowTx084(t.Context(), boundaryTx, identity,
				resource.subscription, rateID, auditID, windowNow)
		}
		if err != nil {
			t.Fatalf("exact lower boundary counted inside the open window: %v", err)
		}
		if err := boundaryTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		err = insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
			resource.subscription, "plugin_webhook.test_delivery.create", time.Time{})
		assertPluginWebhookCode084(t, err, "P8408")
	})

	t.Run("final allowance contention and reconnect", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		for index := 0; index < 4; index++ {
			if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
				resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		firstConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer firstConn.Release()
		secondConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer secondConn.Release()
		var position int64
		var previous []byte
		if err := pool.QueryRow(ctx, `SELECT stream_position,event_hash FROM audit_events
			WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, identity.tenantScope).
			Scan(&position, &previous); err != nil {
			t.Fatal(err)
		}
		firstTx, err := firstConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer firstTx.Rollback(context.Background())
		firstAt := pluginWebhookDatabaseTime084(t, firstTx)
		firstRate, firstAudit, firstHash, err := insertPluginWebhookTestRateAuditTx084(ctx, firstTx,
			identity, resource.subscription, position+1, previous, firstAt)
		if err == nil {
			err = insertPluginWebhookTestRateRowTx084(ctx, firstTx, identity,
				resource.subscription, firstRate, firstAudit, firstAt)
		}
		if err != nil {
			t.Fatal(err)
		}
		secondTx, err := secondConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer secondTx.Rollback(context.Background())
		secondAt := pluginWebhookDatabaseTime084(t, secondTx)
		secondRate, secondAudit, _, err := insertPluginWebhookTestRateAuditTx084(ctx, secondTx,
			identity, resource.subscription, position+2, firstHash, secondAt)
		if err != nil {
			t.Fatal(err)
		}
		var firstPID, secondPID int32
		if err := firstTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
			t.Fatal(err)
		}
		if err := secondTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
			t.Fatal(err)
		}
		secondResult := make(chan error, 1)
		go func() {
			secondResult <- insertPluginWebhookTestRateRowTx084(ctx, secondTx, identity,
				resource.subscription, secondRate, secondAudit, secondAt)
		}()
		waitForPluginWebhookBlock084(t, pool, secondPID, firstPID)
		if err := firstTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookCode084(t, <-secondResult, "P8408")
		if err := secondTx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatal(err)
		}
		var allowed int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM plugin_webhook_rate_events
			WHERE tenant_scope_id=$1 AND subscription_id=$2
			  AND operation='plugin_webhook.test_delivery.create' AND outcome='allowed'`,
			identity.tenantScope, resource.subscription).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != 5 {
			t.Fatalf("contended final allowance count=%d want=5", allowed)
		}

		config := pool.Config().Copy()
		reconnected, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer reconnected.Close()
		if err := reconnected.QueryRow(ctx, `SELECT count(*) FROM plugin_webhook_rate_events
			WHERE tenant_scope_id=$1 AND subscription_id=$2
			  AND operation='plugin_webhook.test_delivery.create' AND outcome='allowed'`,
			identity.tenantScope, resource.subscription).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != 5 {
			t.Fatalf("reconnected allowance count=%d want=5", allowed)
		}
		err = insertPluginWebhookStandaloneRateOperation084(t, reconnected, identity,
			resource.subscription, "plugin_webhook.test_delivery.create", time.Time{})
		assertPluginWebhookCode084(t, err, "P8408")
	})
}

func TestPluginWebhookControl084TenantRateLinearizationEvidence(t *testing.T) {
	pool, identity, initial := setupPluginWebhook084(t)
	resources := []pluginWebhookResource084{initial}
	for index := 0; index < 6; index++ {
		resources = append(resources, insertPluginWebhookSubscription084(t, pool,
			identity.tenantScope, identity.tenantScope, identity.ownerUser,
			pluginWebhook084Now.Add(time.Duration(index+1)*time.Second)))
	}
	seedCounts := []int{5, 5, 5, 5, 1, 4, 4}
	for resourceIndex, count := range seedCounts {
		for index := 0; index < count; index++ {
			if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
				resources[resourceIndex].subscription,
				"plugin_webhook.test_delivery.create", time.Time{}); err != nil {
				t.Fatalf("seed tenant allowance resource=%d count=%d: %v", resourceIndex, index, err)
			}
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	firstConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstConn.Release()
	secondConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Release()
	var position int64
	var previous []byte
	if err := pool.QueryRow(ctx, `SELECT stream_position,event_hash FROM audit_events
		WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, identity.tenantScope).
		Scan(&position, &previous); err != nil {
		t.Fatal(err)
	}
	firstTx, err := firstConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstTx.Rollback(context.Background())
	firstAt := pluginWebhookDatabaseTime084(t, firstTx)
	firstRate, firstAudit, firstHash, err := insertPluginWebhookTestRateAuditTx084(ctx, firstTx,
		identity, resources[5].subscription, position+1, previous, firstAt)
	if err == nil {
		err = insertPluginWebhookTestRateRowTx084(ctx, firstTx, identity,
			resources[5].subscription, firstRate, firstAudit, firstAt)
	}
	if err != nil {
		t.Fatal(err)
	}
	secondTx, err := secondConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondTx.Rollback(context.Background())
	secondAt := pluginWebhookDatabaseTime084(t, secondTx)
	secondRate, secondAudit, _, err := insertPluginWebhookTestRateAuditTx084(ctx, secondTx,
		identity, resources[6].subscription, position+2, firstHash, secondAt)
	if err != nil {
		t.Fatal(err)
	}
	var firstPID, secondPID int32
	if err := firstTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	if err := secondTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- insertPluginWebhookTestRateRowTx084(ctx, secondTx, identity,
			resources[6].subscription, secondRate, secondAudit, secondAt)
	}()
	waitForPluginWebhookBlock084(t, pool, secondPID, firstPID)
	if err := firstTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertPluginWebhookCode084(t, <-secondResult, "P8408")
	if err := secondTx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}

	var tenantAllowed, firstAllowed, secondAllowed int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE outcome='allowed'),
		count(*) FILTER (WHERE subscription_id=$2 AND outcome='allowed'),
		count(*) FILTER (WHERE subscription_id=$3 AND outcome='allowed')
		FROM plugin_webhook_rate_events
		WHERE tenant_scope_id=$1 AND operation='plugin_webhook.test_delivery.create'`,
		identity.tenantScope, resources[5].subscription, resources[6].subscription).
		Scan(&tenantAllowed, &firstAllowed, &secondAllowed); err != nil {
		t.Fatal(err)
	}
	if tenantAllowed != 30 || firstAllowed != 5 || secondAllowed != 4 {
		t.Fatalf("tenant contention allowances tenant/first/second=%d/%d/%d want=30/5/4",
			tenantAllowed, firstAllowed, secondAllowed)
	}

	config := pool.Config().Copy()
	reconnected, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	if err := reconnected.QueryRow(ctx, `SELECT count(*) FROM plugin_webhook_rate_events
		WHERE tenant_scope_id=$1 AND operation='plugin_webhook.test_delivery.create'
		  AND outcome='allowed'`, identity.tenantScope).Scan(&tenantAllowed); err != nil {
		t.Fatal(err)
	}
	if tenantAllowed != 30 {
		t.Fatalf("reconnected tenant allowance count=%d want=30", tenantAllowed)
	}
	err = insertPluginWebhookStandaloneRateOperation084(t, reconnected, identity,
		resources[6].subscription, "plugin_webhook.test_delivery.create", time.Time{})
	assertPluginWebhookCode084(t, err, "P8408")
}

func TestPluginWebhookControl084RateReverseCommitOrdering(t *testing.T) {
	t.Run("subscription final slot committed before older inserter", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		for index := 0; index < 4; index++ {
			if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
				resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		older, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer older.Rollback(t.Context())
		olderAt := pluginWebhookDatabaseTime084(t, older)
		if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
			resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
			t.Fatalf("newer final slot: %v", err)
		}
		err = insertPluginWebhookTestRateInOpenTx084(t.Context(), t, older, identity,
			resource.subscription, olderAt)
		assertPluginWebhookCode084(t, err, "P8408")
	})

	t.Run("tenant final slot committed before older inserter", func(t *testing.T) {
		pool, identity, initial := setupPluginWebhook084(t)
		resources := []pluginWebhookResource084{initial}
		for index := 0; index < 6; index++ {
			resources = append(resources, insertPluginWebhookSubscription084(t, pool,
				identity.tenantScope, identity.tenantScope, identity.ownerUser,
				pluginWebhookDatabaseTime084(t, pool)))
		}
		for resourceIndex := 0; resourceIndex < 6; resourceIndex++ {
			allowances := 5
			if resourceIndex == 5 {
				allowances = 4
			}
			for index := 0; index < allowances; index++ {
				if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
					resources[resourceIndex].subscription,
					"plugin_webhook.test_delivery.create", time.Time{}); err != nil {
					t.Fatal(err)
				}
			}
		}
		older, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer older.Rollback(t.Context())
		olderAt := pluginWebhookDatabaseTime084(t, older)
		if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
			resources[5].subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
			t.Fatalf("newer tenant final slot: %v", err)
		}
		err = insertPluginWebhookTestRateInOpenTx084(t.Context(), t, older, identity,
			resources[6].subscription, olderAt)
		assertPluginWebhookCode084(t, err, "P8408")
	})
}

func TestPluginWebhookControl084PhysicalActivationClock(t *testing.T) {
	t.Run("future and backdated command time", func(t *testing.T) {
		for _, check := range []struct {
			name          string
			pendingOffset time.Duration
			commandOffset time.Duration
		}{
			{name: "future", commandOffset: time.Hour},
			{name: "backdated", pendingOffset: -2 * time.Hour, commandOffset: -time.Hour},
		} {
			t.Run(check.name, func(t *testing.T) {
				pool, identity, resource := setupPluginWebhook084(t)
				databaseNow := pluginWebhookDatabaseTime084(t, pool)
				pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2, databaseNow)
				if check.pendingOffset != 0 {
					rewritePluginWebhookPendingClock084(t, pool, identity, resource, pending,
						databaseNow.Add(check.pendingOffset))
				}
				commandAt := databaseNow.Add(check.commandOffset)
				err := activatePluginWebhookAtResult084(t, pool, identity, resource, pending,
					commandAt, commandAt, commandAt)
				if err == nil {
					t.Fatal("caller-controlled activation time was accepted")
				}
			})
		}
	})

	t.Run("exact database command time", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhookDatabaseTime084(t, pool))
		if err := activatePluginWebhookAtDatabaseTime084(t, pool, identity, resource, pending, 0); err != nil {
			t.Fatalf("database-time activation rejected: %v", err)
		}
	})

	t.Run("commit after physical expiry", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		databaseNow := pluginWebhookDatabaseTime084(t, pool)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2, databaseNow)
		deadline := rewritePluginWebhookPendingClock084(t, pool, identity, resource, pending,
			databaseNow.Add(-24*time.Hour+3*time.Second))
		err := activatePluginWebhookAtDatabaseTime084(t, pool, identity, resource, pending,
			time.Until(deadline)+250*time.Millisecond)
		if err == nil {
			t.Fatal("activation transaction committed after the physical secret deadline")
		}
	})
}

func TestPluginWebhookControl084CompletedRevokeCommandBinding(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	err := revokePluginWebhookWithIncompleteRequest084(t, pool, identity, resource,
		pluginWebhook084Now.Add(time.Hour))
	if err == nil {
		t.Fatal("subscription revoke committed through an incomplete unaudited request")
	}
	var active bool
	if queryErr := pool.QueryRow(t.Context(), `SELECT status='active' FROM plugin_webhook_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription).Scan(&active); queryErr != nil || !active {
		t.Fatalf("failed incomplete revoke left subscription active=%t err=%v", active, queryErr)
	}
}

func TestPluginWebhookControl084DeliveryTargetBinding(t *testing.T) {
	checks := []struct {
		name string
		url  string
		host string
		path string
	}{
		{name: "host drift", url: "https://alternate.example.com/v1/events",
			host: "alternate.example.com", path: "/v1/events"},
		{name: "path drift", url: "https://hooks.example.com/other",
			host: "hooks.example.com", path: "/other"},
	}
	for _, operation := range []string{"plugin_webhook.test_delivery.create", "plugin_webhook.delivery.replay"} {
		for _, check := range checks {
			t.Run(operation+"/"+check.name, func(t *testing.T) {
				err := insertPluginWebhookTargetBundleResult084(t, operation, check.url, check.host, check.path)
				assertPluginWebhookCode084(t, err, "P8404")
			})
		}
		t.Run(operation+"/exact target", func(t *testing.T) {
			if err := insertPluginWebhookTargetBundleResult084(t, operation,
				"https://hooks.example.com/v1/events", "hooks.example.com", "/v1/events"); err != nil {
				t.Fatalf("exact subscription target rejected: %v", err)
			}
		})
	}
	t.Run("explicit default port is noncanonical", func(t *testing.T) {
		err := insertPluginWebhookTargetBundleResult084(t, "plugin_webhook.test_delivery.create",
			"https://hooks.example.com:443/v1/events", "hooks.example.com", "/v1/events")
		assertPluginWebhookCode084(t, err, "23514")
	})
}

func TestPluginWebhookControl084ActivationCommandTimeBinding(t *testing.T) {
	checks := []struct {
		name             string
		requestOffset    time.Duration
		auditOffset      time.Duration
		activationOffset time.Duration
	}{
		{name: "expired request backdated before expiry", requestOffset: 25 * time.Hour,
			auditOffset: 25 * time.Hour, activationOffset: 23 * time.Hour},
		{name: "activation predates secret creation", requestOffset: time.Hour,
			auditOffset: time.Hour, activationOffset: -time.Minute},
		{name: "audit time drift", requestOffset: time.Hour,
			auditOffset: 59 * time.Minute, activationOffset: time.Hour},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
				pluginWebhook084Now.Add(2*time.Hour))
			base := pluginWebhook084Now.Add(2 * time.Hour)
			err := activatePluginWebhookAtResult084(t, pool, identity, resource, pending,
				base.Add(check.requestOffset), base.Add(check.auditOffset),
				base.Add(check.activationOffset))
			if err == nil {
				t.Fatal("activation accepted expired, backdated, or mismatched command time")
			}
		})
	}
	t.Run("exact command time", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
			pluginWebhook084Now.Add(2*time.Hour))
		if err := activatePluginWebhookAtDatabaseTime084(t, pool, identity, resource, pending, 0); err != nil {
			t.Fatalf("exact activation command time rejected: %v", err)
		}
	})
}

func TestPluginWebhookControl084TopLevelTransactionIdentity(t *testing.T) {
	for _, operation := range []string{"create", "rotate", "test", "replay", "revoke"} {
		t.Run(operation+" savepoint bundle", func(t *testing.T) {
			if err := insertPluginWebhookSavepointBundle084(t, operation, false); err != nil {
				t.Fatalf("top-level xid8 rejected %s savepoint bundle: %v", operation, err)
			}
		})
	}
	t.Run("rolled back savepoint leaves no command fact", func(t *testing.T) {
		if err := insertPluginWebhookSavepointBundle084(t, "revoke", true); err == nil {
			t.Fatal("rolled-back savepoint request authorized a parent-transaction revoke")
		}
	})
	t.Run("schema and function sources use xid8", func(t *testing.T) {
		pool, _, _ := setupPluginWebhook084(t)
		assertPluginWebhookXID8Contract084(t, pool)
	})
}

func TestPluginWebhookControl084LifecycleStartUsesDatabaseTime(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	databaseNow := pluginWebhookDatabaseTime084(t, pool)
	backdated := databaseNow.Add(-48 * time.Hour)

	pending, err := insertPluginWebhookPendingSecretResult084(t, pool, identity, resource, backdated)
	if err != nil {
		t.Fatalf("insert backdated pending secret fixture: %v", err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='expired',nonce=NULL,ciphertext=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, pending)
	assertPluginWebhookCode084(t, err, "P8406")

	backdatedResource, err := insertPluginWebhookSubscriptionResult084(t, pool,
		identity.tenantScope, identity.tenantScope, identity.ownerUser, backdated)
	if err != nil {
		t.Fatalf("insert backdated create fixture: %v", err)
	}
	var requestID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM plugin_webhook_write_requests
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
		backdatedResource.subscription).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=clock_timestamp(),
			receipt_cleared_reason='expired'
		WHERE id=$1`, requestID)
	assertPluginWebhookCode084(t, err, "P8404")

	var secretCreated, secretRecorded, secretPhysical, secretExpires time.Time
	if err := pool.QueryRow(t.Context(), `SELECT created_at,plugin_webhook_recorded_at,
		plugin_webhook_physical_created_at,expires_at
		FROM plugin_webhook_secret_versions
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, pending).Scan(&secretCreated, &secretRecorded, &secretPhysical,
		&secretExpires); err != nil {
		t.Fatal(err)
	}
	if !secretCreated.Equal(secretRecorded) || !secretExpires.Equal(secretPhysical.Add(24*time.Hour)) ||
		secretPhysical.Before(secretRecorded) {
		t.Fatalf("pending secret lifecycle start/recorded/physical/expiry=%s/%s/%s/%s",
			secretCreated, secretRecorded, secretPhysical, secretExpires)
	}
	var requestCreated, requestRecorded, requestPhysical, receiptExpires time.Time
	if err := pool.QueryRow(t.Context(), `SELECT created_at,plugin_webhook_recorded_at,
		plugin_webhook_physical_created_at,receipt_expires_at
		FROM plugin_webhook_write_requests WHERE id=$1`, requestID).Scan(
		&requestCreated, &requestRecorded, &requestPhysical, &receiptExpires); err != nil {
		t.Fatal(err)
	}
	if !requestCreated.Equal(requestRecorded) || !receiptExpires.Equal(requestPhysical.Add(24*time.Hour)) ||
		requestPhysical.Before(requestRecorded) {
		t.Fatalf("receipt lifecycle start/recorded/physical/expiry=%s/%s/%s/%s",
			requestCreated, requestRecorded, requestPhysical, receiptExpires)
	}
}

func TestPluginWebhookControl084PhysicalCreationMarker(t *testing.T) {
	pool, identity, _ := setupPluginWebhook084(t)
	var columns int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND table_name = ANY(ARRAY['plugin_webhook_secret_versions',
		                            'plugin_webhook_write_requests'])
		  AND column_name='plugin_webhook_physical_created_at'
		  AND data_type='timestamp with time zone' AND is_nullable='NO'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 2 {
		t.Fatalf("physical lifecycle creation marker columns=%d want=2", columns)
	}
	source := pluginWebhookFunctionSource084(t, pool, "stamp_plugin_webhook_xact_id_084()")
	if !strings.Contains(source, "plugin_webhook_physical_created_at := clock_timestamp()") {
		t.Fatal("lifecycle creation still derives from transaction start instead of physical server time")
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	transactionStart := pluginWebhookDatabaseTime084(t, tx)
	if _, err := tx.Exec(t.Context(), `SELECT pg_sleep(0.1)`); err != nil {
		t.Fatal(err)
	}
	resource, err := insertPluginWebhookRawSubscriptionRowsTx084(t.Context(), tx, identity,
		identity.tenantScope, identity.ownerUser, 1, 0, 0, "active", transactionStart)
	if err == nil {
		err = insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.subscription.create",
			resource.subscription, uuid.Nil, transactionStart,
			pluginWebhookCommandFacts084{audit: true, write: true, rate: true})
	}
	pending := uuid.New()
	if err == nil {
		err = insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.rotate",
			resource.subscription, pending, transactionStart)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
			id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
			wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
		) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
			pending, identity.tenantScope, resource.subscription, identity.ownerUser,
			pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 2,
				"plugin-webhook-kek-v1"), bytes084(12, 0xa7), bytes084(48, 0xa8),
			bytes084(32, 0xa9), transactionStart, transactionStart.Add(24*time.Hour))
	}
	if err == nil {
		err = tx.Commit(t.Context())
	}
	if err != nil {
		t.Fatalf("old transaction physical creation bundle: %v", err)
	}
	var secretPhysical, secretExpiry, receiptPhysical, receiptExpiry time.Time
	if err := pool.QueryRow(t.Context(), `SELECT secret.plugin_webhook_physical_created_at,
		secret.expires_at,request.plugin_webhook_physical_created_at,request.receipt_expires_at
		FROM plugin_webhook_secret_versions secret
		JOIN plugin_webhook_write_requests request
		  ON request.tenant_scope_id=secret.tenant_scope_id
		 AND request.subscription_id=secret.subscription_id
		WHERE secret.tenant_scope_id=$1 AND secret.subscription_id=$2
		  AND secret.id=$3 AND request.operation='plugin_webhook.secret.rotate'
		  AND request.rotation_id=secret.id`, identity.tenantScope,
		resource.subscription, pending).Scan(&secretPhysical, &secretExpiry, &receiptPhysical,
		&receiptExpiry); err != nil {
		t.Fatal(err)
	}
	if !secretPhysical.After(transactionStart) || !receiptPhysical.After(transactionStart) ||
		!secretExpiry.Equal(secretPhysical.Add(24*time.Hour)) ||
		!receiptExpiry.Equal(receiptPhysical.Add(24*time.Hour)) {
		t.Fatalf("old transaction retained transaction-start lifetime: tx=%s secret=%s/%s receipt=%s/%s",
			transactionStart, secretPhysical, secretExpiry, receiptPhysical, receiptExpiry)
	}
}

func TestPluginWebhookControl084DurableOutboxPublishBoundary(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	token := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, token); err != nil {
		t.Fatalf("lease durable outbox before broker I/O: %v", err)
	}
	var deliveryStatus, outboxStatus string
	var sequence *string
	if err := pool.QueryRow(t.Context(), `SELECT delivery.status,outbox.status,
		delivery.nats_stream_sequence::text
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id
		 AND outbox.subscription_id=delivery.subscription_id AND outbox.delivery_id=delivery.id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		identity.tenantScope, resource.subscription, delivery).Scan(&deliveryStatus, &outboxStatus,
		&sequence); err != nil {
		t.Fatal(err)
	}
	if deliveryStatus != "pending" || outboxStatus != "leased" || sequence != nil {
		t.Fatalf("pre-publish delivery/outbox/sequence=%s/%s/%v", deliveryStatus, outboxStatus,
			sequence)
	}

	const brokerSequence = 98421
	attestPluginWebhookOutbox084(t, pool, attestation, identity.tenantScope,
		resource.subscription, delivery, token, 101, brokerSequence)
	var storedSequence int
	if err := pool.QueryRow(t.Context(), `SELECT delivery.status,outbox.status,
		delivery.nats_stream_sequence::int
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id
		 AND outbox.subscription_id=delivery.subscription_id AND outbox.delivery_id=delivery.id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		identity.tenantScope, resource.subscription, delivery).Scan(&deliveryStatus, &outboxStatus,
		&storedSequence); err != nil {
		t.Fatal(err)
	}
	if deliveryStatus != "queued" || outboxStatus != "published" || storedSequence != brokerSequence {
		t.Fatalf("published delivery/outbox/sequence=%s/%s/%d", deliveryStatus, outboxStatus,
			storedSequence)
	}
}

func TestPluginWebhookControl084OutboxLeaseStateMachine(t *testing.T) {
	lease := func(t *testing.T, pool *pgxpool.Pool, identity pluginWebhookIdentity084,
		resource pluginWebhookResource084, delivery uuid.UUID, leasedAt, expiresAt time.Time,
		attempt int,
	) error {
		t.Helper()
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,leased_at=$5,lease_expires_at=$6,
				publish_attempt=$7
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery, uuid.New(), leasedAt,
			expiresAt, attempt)
		return err
	}

	t.Run("available at must be physically due", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		now := pluginWebhookDatabaseTime084(t, pool)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, now)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET available_at=clock_timestamp()+interval '1 hour'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		err = lease(t, pool, identity, resource, delivery, now, now.Add(time.Minute), 1)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	for _, check := range []struct {
		name       string
		leasedAt   time.Duration
		expiresAt  time.Duration
		wantReject bool
	}{
		{name: "backdated caller lease time", leasedAt: -time.Hour, expiresAt: time.Minute},
		{name: "future caller lease time", leasedAt: time.Hour, expiresAt: time.Minute},
		{name: "nonpositive lease", expiresAt: 0, wantReject: true},
		{name: "unbounded lease", expiresAt: time.Hour, wantReject: true},
	} {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
				pluginWebhook084Now)
			before := pluginWebhookDatabaseTime084(t, pool)
			err := lease(t, pool, identity, resource, delivery, before.Add(check.leasedAt),
				before.Add(check.expiresAt), 1)
			if check.wantReject {
				assertPluginWebhookCode084(t, err, "P8404")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var stored time.Time
			if err := pool.QueryRow(t.Context(), `SELECT leased_at FROM plugin_webhook_outbox
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
				identity.tenantScope, resource.subscription, delivery).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored.Before(before) || stored.After(time.Now().Add(time.Minute)) {
				t.Fatalf("lease time was not server stamped: %s", stored)
			}
		})
	}

	t.Run("recovery waits for physical expiry and preserves attempt", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now)
		now := pluginWebhookDatabaseTime084(t, pool)
		if err := lease(t, pool, identity, resource, delivery, now, now.Add(time.Second), 1); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='pending',lease_token=NULL,leased_at=NULL,lease_expires_at=NULL,
				publish_attempt=2
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("publication requires an unexpired lease", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now)
		now := pluginWebhookDatabaseTime084(t, pool)
		if err := lease(t, pool, identity, resource, delivery, now, now.Add(250*time.Millisecond), 1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='published',lease_token=NULL,lease_expires_at=NULL,
				published_at=clock_timestamp()
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery)
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("expired lease recovery is single winner and reconnect durable", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
			pluginWebhook084Now)
		now := pluginWebhookDatabaseTime084(t, pool)
		if err := lease(t, pool, identity, resource, delivery, now, now.Add(250*time.Millisecond), 1); err != nil {
			t.Fatal(err)
		}
		config := pool.Config().Copy()
		reconnected, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer reconnected.Close()
		var status string
		var attempt int
		if err := reconnected.QueryRow(t.Context(), `SELECT status,publish_attempt::int
			FROM plugin_webhook_outbox WHERE tenant_scope_id=$1 AND subscription_id=$2
			  AND delivery_id=$3`, identity.tenantScope, resource.subscription, delivery).
			Scan(&status, &attempt); err != nil || status != "leased" || attempt != 1 {
			t.Fatalf("reconnected lease status/attempt=%s/%d err=%v", status, attempt, err)
		}
		time.Sleep(300 * time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		first, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Release()
		second, err := reconnected.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Release()
		firstTx, err := first.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer firstTx.Rollback(context.Background())
		firstTag, err := firstTx.Exec(ctx, `UPDATE plugin_webhook_outbox
			SET status='pending',lease_token=NULL,leased_at=NULL,lease_expires_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3
			  AND status='leased'`, identity.tenantScope, resource.subscription, delivery)
		if err != nil || firstTag.RowsAffected() != 1 {
			t.Fatalf("first recovery rows=%d err=%v", firstTag.RowsAffected(), err)
		}
		secondTx, err := second.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer secondTx.Rollback(context.Background())
		var firstPID, secondPID int32
		if err := firstTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
			t.Fatal(err)
		}
		if err := secondTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
			t.Fatal(err)
		}
		secondResult := make(chan struct {
			tag pgconn.CommandTag
			err error
		}, 1)
		go func() {
			tag, updateErr := secondTx.Exec(ctx, `UPDATE plugin_webhook_outbox
				SET status='pending',lease_token=NULL,leased_at=NULL,lease_expires_at=NULL
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3
				  AND status='leased'`, identity.tenantScope, resource.subscription, delivery)
			secondResult <- struct {
				tag pgconn.CommandTag
				err error
			}{tag: tag, err: updateErr}
		}()
		waitForPluginWebhookBlock084(t, pool, secondPID, firstPID)
		if err := firstTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-secondResult
		if result.err != nil || result.tag.RowsAffected() != 0 {
			t.Fatalf("second recovery rows=%d err=%v", result.tag.RowsAffected(), result.err)
		}
		if err := secondTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := reconnected.QueryRow(ctx, `SELECT status,publish_attempt::int
			FROM plugin_webhook_outbox WHERE tenant_scope_id=$1 AND subscription_id=$2
			  AND delivery_id=$3`, identity.tenantScope, resource.subscription, delivery).
			Scan(&status, &attempt); err != nil || status != "pending" || attempt != 1 {
			t.Fatalf("durable recovery status/attempt=%s/%d err=%v", status, attempt, err)
		}
	})
}

func TestPluginWebhookControl084TenantStateBackgroundBoundary(t *testing.T) {
	for _, tenantStatus := range []string{"suspended", "closed"} {
		t.Run(tenantStatus, func(t *testing.T) {
			pool, identity, resource := setupPluginWebhook084(t)
			pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
				pluginWebhookDatabaseTime084(t, pool))
			agePluginWebhookSecretExpiry084(t, pool, identity.tenantScope,
				resource.subscription, pending)

			var receiptRequest uuid.UUID
			if err := pool.QueryRow(t.Context(), `SELECT id FROM plugin_webhook_write_requests
				WHERE tenant_scope_id=$1 AND subscription_id=$2
				  AND operation='plugin_webhook.subscription.create'`, identity.tenantScope,
				resource.subscription).Scan(&receiptRequest); err != nil {
				t.Fatal(err)
			}
			agePluginWebhookReceipt084(t, pool, receiptRequest)

			startedDelivery := seedPluginWebhookDelivery084(t, pool, identity, resource,
				pluginWebhookDatabaseTime084(t, pool))
			startedClaim := claimPluginWebhookDelivery084(t, pool, identity, resource,
				startedDelivery, pluginWebhookDatabaseTime084(t, pool))
			startPluginWebhookAttempt084(t, pool, startedClaim, pluginWebhookDatabaseTime084(t, pool))
			blockedDelivery := seedPluginWebhookDelivery084(t, pool, identity, resource,
				pluginWebhookDatabaseTime084(t, pool))

			if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status=$2,updated_at=clock_timestamp()
				WHERE id=$1`, identity.tenantID, tenantStatus); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
				SET status='expired',nonce=NULL,ciphertext=NULL
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
				resource.subscription, pending); err != nil {
				t.Fatalf("%s tenant blocked secret cleanup: %v", tenantStatus, err)
			}
			if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
				SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=clock_timestamp(),
					receipt_cleared_reason='expired'
				WHERE id=$1`, receiptRequest); err != nil {
				t.Fatalf("%s tenant blocked receipt cleanup: %v", tenantStatus, err)
			}
			if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
				SET status='succeeded',completed_at=clock_timestamp(),http_status=204,
					response_sha256=$2,response_bytes=0,response_preview=''::bytea,
					sanitized_headers='{}'::jsonb WHERE claim_token=$1`, startedClaim,
				bytes084(32, 0xe7)); err != nil {
				t.Fatalf("%s tenant blocked pre-started outcome: %v", tenantStatus, err)
			}
			assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
				resource.subscription, startedDelivery, "delivered")

			_, err := insertPluginWebhookClaim084(t, pool, identity, resource, blockedDelivery,
				pluginWebhookDatabaseTime084(t, pool))
			assertPluginWebhookCode084(t, err, "P8402")
			_, err = insertPluginWebhookPendingSecretResult084(t, pool, identity, resource,
				pluginWebhookDatabaseTime084(t, pool))
			assertPluginWebhookCode084(t, err, "P8402")
		})
	}
}

func TestPluginWebhookControl084DeadLetterDurability(t *testing.T) {
	t.Run("terminal delivery requires atomic DLQ", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='permanent_failure',completed_at=clock_timestamp(),http_status=503,
				failure_code='upstream_permanent_failure',response_sha256=$2,response_bytes=0,
				response_preview=''::bytea,sanitized_headers='{}'::jsonb WHERE claim_token=$1`,
			claim, bytes084(32, 0xe8))
		assertPluginWebhookCode084(t, err, "P8404")
	})

	t.Run("terminal delivery and DLQ commit together", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		if err := finishPluginWebhookDeadLetter084(t, pool, claim, "permanent_failure",
			identity.tenantScope, identity.ownerUser, bytes084(32, 0xe9)); err != nil {
			t.Fatalf("atomic terminal DLQ rejected: %v", err)
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
	})

	t.Run("replay requires durable DLQ", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		seedPluginWebhookOrphanDeadLetter084(t, pool, claim)
		err := insertPluginWebhookReplayOfResult084(t, pool, identity, resource, delivery)
		assertPluginWebhookCode084(t, err, "P8404")
	})
}

func TestPluginWebhookControl084RevokeClearsRetiredSecret(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	active := rotatePluginWebhookSecret084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
		pluginWebhookDatabaseTime084(t, pool))
	var residual, revoked int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE nonce IS NOT NULL OR ciphertext IS NOT NULL),
		count(*) FILTER (WHERE status='revoked')
		FROM plugin_webhook_secret_versions
		WHERE tenant_scope_id=$1 AND subscription_id=$2`, identity.tenantScope,
		resource.subscription).Scan(&residual, &revoked); err != nil {
		t.Fatal(err)
	}
	if residual != 0 || revoked != 2 {
		t.Fatalf("revoke retained decryptable retired key residual/revoked=%d/%d active=%s",
			residual, revoked, active)
	}
}

func TestPluginWebhookControl084RevokeClearsSecretReceipts(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	_ = rotatePluginWebhookSecret084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	revokePluginWebhookSubscription084(t, pool, identity, resource.subscription,
		pluginWebhookDatabaseTime084(t, pool))

	var recoverable, permanent, invalidated int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE receipt_nonce IS NOT NULL OR receipt_ciphertext IS NOT NULL),
		count(*) FILTER (WHERE completed_at IS NOT NULL AND response_status IS NOT NULL),
		count(*) FILTER (WHERE receipt_cleared_reason='subscription_revoked')
		FROM plugin_webhook_write_requests
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation IN ('plugin_webhook.subscription.create','plugin_webhook.secret.rotate')`,
		identity.tenantScope, resource.subscription).Scan(&recoverable, &permanent, &invalidated); err != nil {
		t.Fatal(err)
	}
	if recoverable != 0 || permanent != 2 || invalidated != 2 {
		t.Fatalf("revoke receipt recoverable/permanent/invalidated=%d/%d/%d want 0/2/2",
			recoverable, permanent, invalidated)
	}
}

func TestPluginWebhookControl084SecretTransitionEnvelopeImmutable(t *testing.T) {
	for _, transition := range []string{"pending_to_active", "active_to_retired"} {
		t.Run(transition, func(t *testing.T) {
			err := mutatePluginWebhookSecretTransition084(t, transition)
			assertPluginWebhookCode084(t, err, "P8406")
		})
	}
}

func TestPluginWebhookControl084StartedAtImmutable(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		pluginWebhookDatabaseTime084(t, pool))
	startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
	var startedAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT started_at
		FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, claim).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='succeeded',started_at=$2,completed_at=clock_timestamp(),http_status=204,
			response_sha256=$3,response_bytes=0,response_preview=''::bytea,
			sanitized_headers='{}'::jsonb WHERE claim_token=$1`, claim, startedAt.Add(-time.Second),
		bytes084(32, 0xeb))
	assertPluginWebhookCode084(t, err, "P8404")
}

func TestPluginWebhookControl084DeadLetterPublicationIdentity(t *testing.T) {
	t.Run("stream sequence is globally unique", func(t *testing.T) {
		pool, identity, first := setupPluginWebhook084(t)
		second := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
		firstDelivery := seedPluginWebhookDelivery084(t, pool, identity, first, pluginWebhook084Now)
		firstClaim := claimPluginWebhookDelivery084(t, pool, identity, first, firstDelivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, firstClaim, pluginWebhookDatabaseTime084(t, pool))
		if err := finishPluginWebhookDeadLetter084(t, pool, firstClaim, "permanent_failure",
			identity.tenantScope, identity.ownerUser, bytes084(32, 0xec)); err != nil {
			t.Fatal(err)
		}
		secondDelivery := seedPluginWebhookDelivery084(t, pool, identity, second,
			pluginWebhook084Now.Add(time.Minute))
		secondClaim := claimPluginWebhookDelivery084(t, pool, identity, second, secondDelivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, secondClaim, pluginWebhookDatabaseTime084(t, pool))
		err := finishPluginWebhookDeadLetter084(t, pool, secondClaim, "permanent_failure",
			identity.tenantScope, identity.ownerUser, bytes084(32, 0xed))
		assertPluginWebhookCode084(t, err, "23505")
	})

	t.Run("publish intent requires durable acknowledgement before replay", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		if err := insertPluginWebhookDeadLetterIntent084(t, pool, claim); err != nil {
			t.Fatalf("persist DLQ publish intent: %v", err)
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_letter_pending")
		assertPluginWebhookCode084(t,
			insertPluginWebhookReplayOfResult084(t, pool, identity, resource, delivery), "P8404")

		conn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var pending string
		err = conn.QueryRow(t.Context(), `SELECT publish_state FROM plugin_webhook_dead_letters
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
			identity.tenantScope, resource.subscription, delivery).Scan(&pending)
		conn.Release()
		if err != nil || pending != "pending" {
			t.Fatalf("reconnected DLQ intent state=%q err=%v", pending, err)
		}
		if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, 41); err != nil {
			t.Fatalf("acknowledge DLQ publish: %v", err)
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
		if err := insertPluginWebhookReplayOfResult084(t, pool, identity, resource, delivery); err != nil {
			t.Fatalf("acknowledged DLQ was not replayable: %v", err)
		}
	})

	t.Run("payload digest drift is rejected", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
		claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
		err := insertPluginWebhookDeadLetterIntentOverride084(t, pool, claim, "", bytes084(32, 0xef))
		assertPluginWebhookConstraint084(t, err, "23514",
			"plugin_webhook_dead_letters_payload_084_check")
	})

	t.Run("message id cannot be reused for another delivery", func(t *testing.T) {
		pool, identity, first := setupPluginWebhook084(t)
		firstDelivery := seedPluginWebhookDelivery084(t, pool, identity, first, pluginWebhook084Now)
		firstClaim := claimPluginWebhookDelivery084(t, pool, identity, first, firstDelivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, firstClaim, pluginWebhookDatabaseTime084(t, pool))
		if err := insertPluginWebhookDeadLetterIntent084(t, pool, firstClaim); err != nil {
			t.Fatal(err)
		}
		var messageID string
		if err := pool.QueryRow(t.Context(), `SELECT nats_message_id FROM plugin_webhook_dead_letters
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
			first.subscription, firstDelivery).Scan(&messageID); err != nil {
			t.Fatal(err)
		}
		second := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
		secondDelivery := seedPluginWebhookDelivery084(t, pool, identity, second,
			pluginWebhook084Now.Add(time.Minute))
		secondClaim := claimPluginWebhookDelivery084(t, pool, identity, second, secondDelivery,
			pluginWebhookDatabaseTime084(t, pool))
		startPluginWebhookAttempt084(t, pool, secondClaim, pluginWebhookDatabaseTime084(t, pool))
		err := insertPluginWebhookDeadLetterIntentOverride084(t, pool, secondClaim, messageID, nil)
		assertPluginWebhookConstraint084(t, err, "23514",
			"plugin_webhook_dead_letters_message_id_084_check")
	})
}

func TestPluginWebhookControl084P8400RBACBaselineDrift(t *testing.T) {
	checks := []struct {
		name   string
		mutate string
	}{
		{name: "function body", mutate: `CREATE OR REPLACE FUNCTION custom_rbac_effective_permissions(requested_scope_id uuid, requested_user_id uuid)
			RETURNS TABLE(permission_name text) LANGUAGE sql STABLE AS 'SELECT NULL::text WHERE false'`},
		{name: "function attribute", mutate: `ALTER FUNCTION guard_system_role_permission_mutation() SECURITY DEFINER`},
		{name: "function owner", mutate: `ALTER FUNCTION custom_rbac_effective_permissions(uuid,uuid)
			OWNER TO pg_database_owner`},
		{name: "function ACL", mutate: `REVOKE ALL ON FUNCTION custom_rbac_effective_permissions(uuid,uuid) FROM PUBLIC`},
		{name: "trigger binding", mutate: `DROP TRIGGER role_permissions_system_role_guard ON role_permissions`},
		{name: "revision validator body", mutate: `CREATE OR REPLACE FUNCTION validate_custom_role_revision()
			RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN
				-- custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.created_by_user_id)
				RETURN NEW;
			END $function$`},
		{name: "grant validator body", mutate: `CREATE OR REPLACE FUNCTION validate_custom_role_grant()
			RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN
				-- custom_rbac_effective_permissions(NEW.tenant_scope_id, NEW.granted_by_user_id)
				RETURN NEW;
			END $function$`},
		{name: "revision validator attribute", mutate: `ALTER FUNCTION validate_custom_role_revision()
			SECURITY DEFINER`},
		{name: "grant validator ACL", mutate: `REVOKE ALL ON FUNCTION validate_custom_role_grant()
			FROM PUBLIC`},
		{name: "grant validator owner", mutate: `ALTER FUNCTION validate_custom_role_grant()
				OWNER TO pg_database_owner`},
		{name: "grant validator cost", mutate: `ALTER FUNCTION validate_custom_role_grant() COST 1`},
		{name: "grant validator overload", mutate: `CREATE FUNCTION validate_custom_role_grant(integer)
				RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT $1'`},
		{name: "grant validator config", mutate: `ALTER FUNCTION validate_custom_role_grant()
				SET search_path = public`},
		{name: "revision validator trigger", mutate: `DROP TRIGGER custom_role_revisions_validate
			ON custom_role_revisions`},
		{name: "grant validator trigger", mutate: `DROP TRIGGER custom_role_grants_validate
			ON custom_role_grants`},
		{name: "schema owner", mutate: `DO $do$ BEGIN EXECUTE format(
			'ALTER SCHEMA %I OWNER TO pg_database_owner',current_schema()); END $do$`},
		{name: "schema ACL", mutate: `DO $do$ BEGIN EXECUTE format(
			'GRANT CREATE ON SCHEMA %I TO open084_control_login',current_schema()); END $do$`},
		{name: "control default table ACL", mutate: `DO $do$ BEGIN EXECUTE format(
			'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO cdnca_control_app',
			current_schema()); END $do$`},
		{name: "runtime default table ACL", mutate: `DO $do$ BEGIN EXECUTE format(
			'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO cdnca_plugin_webhook_runtime',
			current_schema()); END $do$`},
		{name: "login default table ACL", mutate: `DO $do$ BEGIN EXECUTE format(
			'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO open084_control_login',
			current_schema()); END $do$`},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 83)
			if _, err := pool.Exec(t.Context(), check.mutate, pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			script, err := controlmigrations.FS.ReadFile("084_plugin_webhook_control.up.sql")
			if err != nil {
				t.Fatal(err)
			}
			_, err = pool.Exec(t.Context(), string(script), pgx.QueryExecModeSimpleProtocol)
			assertPluginWebhookCode084(t, err, "P8400")
			assertPluginWebhookHead084(t, pool, 83)
			assertPluginWebhookTables084(t, pool, false)
		})
	}
}

func TestPluginWebhookControl084DeadLetterReconcileAckLockOrder(t *testing.T) {
	pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
	if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
		resource.subscription, delivery, reverseScan084()[0]); err != nil {
		t.Fatal(err)
	}
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	var eventID, deadLetterID, generation uuid.UUID
	var stream, subject, messageID string
	var semanticDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT event_id,id,reconcile_generation,
		nats_stream,nats_subject,nats_message_id,payload_sha256
		FROM plugin_webhook_dead_letters WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND delivery_id=$3`, identity.tenantScope, resource.subscription,
		delivery).Scan(&eventID, &deadLetterID, &generation, &stream, &subject,
		&messageID, &semanticDigest); err != nil {
		t.Fatal(err)
	}
	wireDigest := sha256.Sum256([]byte("plugin-webhook-dlq-wire-084:" + delivery.String() + ":9"))
	fields := [][]byte{
		[]byte("cdnca.plugin-webhook.nats-publication/dead-letter/v1"),
		[]byte(strconv.FormatInt(attestation.generation, 10)), []byte(attestation.keyID),
		[]byte(attestation.natsDomain), []byte(identity.tenantScope.String()),
		[]byte(resource.subscription.String()), []byte(delivery.String()), []byte(eventID.String()),
		[]byte(deadLetterID.String()), []byte(generation.String()), []byte("reverse_scan"),
		[]byte("10"), []byte("1"), []byte("9"), []byte(stream), []byte("1"), []byte(subject),
		[]byte("9"), []byte(messageID), []byte(fmt.Sprintf("%x", semanticDigest)),
		[]byte(fmt.Sprintf("%x", wireDigest[:])), []byte("8"),
	}
	digest := sha256.Sum256(pluginWebhookAttestationFrame084(fields))
	signature := ed25519.Sign(attestation.privateKey, digest[:])

	runtimePool := pluginWebhookLoginPool084(t, pool, "open084_runtime_login")
	reconcileTx, err := runtimePool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer reconcileTx.Rollback(t.Context())
	var reconcilePID int32
	if err := reconcileTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&reconcilePID); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileTx.Exec(t.Context(), `SELECT
		transition_plugin_webhook_dead_letter_reconcile_084(
			$1,$2,$3,$4,'reverse_scan',1,10,1,10,
			$4,'reverse_scan',1,10,1,9
		)`, identity.tenantScope, resource.subscription, delivery, generation); err != nil {
		t.Fatal(err)
	}

	ackTx, err := runtimePool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer ackTx.Rollback(t.Context())
	var ackPID int32
	if err := ackTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&ackPID); err != nil {
		t.Fatal(err)
	}
	ackResult := make(chan error, 1)
	go func() {
		_, ackErr := ackTx.Exec(t.Context(), `SELECT acknowledge_plugin_webhook_dead_letter_084(
			$1,$2,$3,$4,'reverse_scan',1,10,1,9,
			$5,$6,1,$7,9,$8,$9,$10,8,$11,$12,$13
		)`, identity.tenantScope, resource.subscription, delivery, generation,
			attestation.natsDomain, stream, subject, messageID, semanticDigest, wireDigest[:],
			attestation.generation, attestation.keyID, signature)
		if ackErr == nil {
			ackErr = ackTx.Commit(t.Context())
		}
		ackResult <- ackErr
	}()
	waitForPluginWebhookBlock084(t, pool, ackPID, reconcilePID)
	reconcileErr := reconcileTx.Commit(t.Context())
	ackErr := <-ackResult
	if pgErrCodeFromError084(reconcileErr) == "40P01" || pgErrCodeFromError084(ackErr) == "40P01" {
		t.Fatalf("DLQ reconcile/ack lock order deadlocked: reconcile=%v ack=%v",
			reconcileErr, ackErr)
	}
	if reconcileErr != nil {
		t.Fatalf("commit reconcile transition: %v", reconcileErr)
	}
	if ackErr != nil {
		t.Fatalf("commit acknowledgement after reconcile: %v", ackErr)
	}
	assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
		resource.subscription, delivery, "dead_lettered")
}

func TestPluginWebhookControl084DeadLetterReconcileStateContract(t *testing.T) {
	t.Run("valid scan, publish, reset, and acknowledgement path", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		assertPluginWebhookDeadLetterReconcile084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "pending", "uninitialized", nil, nil, nil, nil)

		steps := []struct {
			set      string
			phase    string
			epoch    *string
			high     *string
			boundary *string
			cursor   *string
		}{
			{
				set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=101,
						reconcile_high_watermark=10,reconcile_scan_boundary=1,reconcile_cursor=10`,
				phase: "reverse_scan", epoch: text084("101"), high: text084("10"),
				boundary: text084("1"), cursor: text084("10"),
			},
			{
				set: `reconcile_cursor=9`, phase: "reverse_scan", epoch: text084("101"),
				high: text084("10"), boundary: text084("1"), cursor: text084("9"),
			},
			{
				set: `reconcile_cursor=1`, phase: "reverse_scan", epoch: text084("101"),
				high: text084("10"), boundary: text084("1"), cursor: text084("1"),
			},
			{
				set:   `reconcile_phase='publish_ready',reconcile_scan_boundary=NULL,reconcile_cursor=NULL`,
				phase: "publish_ready", epoch: text084("101"), high: text084("10"),
			},
			{
				set: `reconcile_phase='forward_scan',reconcile_high_watermark=20,
						reconcile_scan_boundary=11,reconcile_cursor=11`,
				phase: "forward_scan", epoch: text084("101"), high: text084("20"),
				boundary: text084("11"), cursor: text084("11"),
			},
			{
				set: `reconcile_cursor=12`, phase: "forward_scan", epoch: text084("101"),
				high: text084("20"), boundary: text084("11"), cursor: text084("12"),
			},
			{
				set: `reconcile_cursor=20`, phase: "forward_scan", epoch: text084("101"),
				high: text084("20"), boundary: text084("11"), cursor: text084("20"),
			},
			{
				set:   `reconcile_phase='publish_ready',reconcile_scan_boundary=NULL,reconcile_cursor=NULL`,
				phase: "publish_ready", epoch: text084("101"), high: text084("20"),
			},
			{
				set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=202,
						reconcile_high_watermark=7,reconcile_scan_boundary=1,reconcile_cursor=7`,
				phase: "reverse_scan", epoch: text084("202"), high: text084("7"),
				boundary: text084("1"), cursor: text084("7"),
			},
		}
		for _, step := range steps {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, step.set); err != nil {
				t.Fatalf("transition to %s: %v", step.phase, err)
			}
			assertPluginWebhookDeadLetterReconcile084(t, pool, identity.tenantScope,
				resource.subscription, delivery, "pending", step.phase,
				step.epoch, step.high, step.boundary, step.cursor)
			assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
				resource.subscription, delivery, "dead_letter_pending")
		}
		if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, 7); err != nil {
			t.Fatalf("acknowledge exact reverse scan hit: %v", err)
		}
		assertPluginWebhookDeadLetterReconcile084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "acknowledged", "complete", nil, nil, nil, nil)
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
		assertPluginWebhookCode084(t, updatePluginWebhookDeadLetter084(t, pool,
			identity.tenantScope, resource.subscription, delivery,
			`publish_state='pending',reconcile_phase='uninitialized',nats_dlq_sequence=NULL,
				nats_ack_id=NULL,acknowledged_at=NULL`), "P8403")
	})

	t.Run("empty stream publish ready acknowledges next sequence", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_phase='publish_ready',
				reconcile_stream_created_unix_nano=303,reconcile_high_watermark=0`); err != nil {
			t.Fatal(err)
		}
		if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, 1); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
	})

	envelopeCases := []struct {
		name string
		set  string
	}{
		{name: "unknown phase", set: `reconcile_phase='unknown'`},
		{name: "uninitialized epoch", set: `reconcile_stream_created_unix_nano=1`},
		{name: "reverse missing epoch", set: `reconcile_phase='reverse_scan',reconcile_high_watermark=1,reconcile_cursor=1`},
		{name: "zero epoch", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=0,reconcile_high_watermark=1,reconcile_cursor=1`},
		{name: "epoch over int64", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=9223372036854775808,reconcile_high_watermark=1,reconcile_cursor=1`},
		{name: "reverse zero high", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=0,reconcile_cursor=1`},
		{name: "reverse missing cursor", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=1`},
		{name: "reverse zero cursor", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=1,reconcile_cursor=0`},
		{name: "cursor above high", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=1,reconcile_cursor=2`},
		{name: "high over uint64", set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=18446744073709551616,reconcile_cursor=1`},
		{name: "publish ready cursor", set: `reconcile_phase='publish_ready',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=0,reconcile_cursor=1`},
		{name: "forward zero high", set: `reconcile_phase='forward_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=0,reconcile_cursor=1`},
		{name: "pending complete", set: `reconcile_phase='complete'`},
		{name: "ack without complete", set: `publish_state='acknowledged',nats_dlq_sequence=1,nats_ack_id=nats_stream || ':1',acknowledged_at=clock_timestamp()`},
		{name: "ack wrong identity", set: `publish_state='acknowledged',reconcile_phase='complete',nats_dlq_stream_created_unix_nano=reconcile_stream_created_unix_nano,nats_dlq_sequence=1,nats_ack_id='wrong:1',acknowledged_at=clock_timestamp()`},
	}
	for _, check := range envelopeCases {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
			err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, check.set)
			if err == nil {
				t.Fatalf("invalid reconcile envelope committed: %s", check.set)
			}
		})
	}

	transitionCases := []struct {
		name   string
		prefix []string
		set    string
	}{
		{name: "uninitialized to forward scan", set: `reconcile_phase='forward_scan',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=1,reconcile_cursor=1`},
		{name: "reverse cursor unchanged", prefix: reverseScan084(), set: `reconcile_cursor=10`},
		{name: "reverse cursor increases", prefix: reverseScan084(), set: `reconcile_cursor=11`},
		{name: "reverse same epoch high changes", prefix: reverseScan084(), set: `reconcile_high_watermark=11,reconcile_cursor=9`},
		{name: "reverse completes with high drift", prefix: reverseScan084(), set: `reconcile_phase='publish_ready',reconcile_high_watermark=9,reconcile_scan_boundary=NULL,reconcile_cursor=NULL`},
		{name: "publish ready same epoch reverse", prefix: publishReady084(), set: `reconcile_phase='reverse_scan',reconcile_high_watermark=10,reconcile_scan_boundary=1,reconcile_cursor=10`},
		{name: "publish ready forward high unchanged", prefix: publishReady084(), set: `reconcile_phase='forward_scan',reconcile_high_watermark=10,reconcile_scan_boundary=11,reconcile_cursor=11`},
		{name: "publish ready forward wrong cursor", prefix: publishReady084(), set: `reconcile_phase='forward_scan',reconcile_high_watermark=20,reconcile_scan_boundary=11,reconcile_cursor=12`},
		{name: "forward cursor unchanged", prefix: forwardScan084(), set: `reconcile_cursor=11`},
		{name: "forward cursor lowers", prefix: forwardScan084(), set: `reconcile_cursor=10`},
		{name: "forward same epoch high changes", prefix: forwardScan084(), set: `reconcile_high_watermark=21,reconcile_cursor=12`},
		{name: "forward completes with high drift", prefix: forwardScan084(), set: `reconcile_phase='publish_ready',reconcile_high_watermark=19,reconcile_scan_boundary=NULL,reconcile_cursor=NULL`},
		{name: "epoch reset cursor not high", prefix: publishReady084(), set: `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=2,reconcile_high_watermark=5,reconcile_scan_boundary=1,reconcile_cursor=4`},
		{name: "epoch reset nonempty publish ready", prefix: publishReady084(), set: `reconcile_stream_created_unix_nano=2,reconcile_high_watermark=5`},
		{name: "reverse wrong wire sequence", prefix: reverseScan084(), set: `publish_state='acknowledged',reconcile_phase='complete',nats_dlq_stream_created_unix_nano=reconcile_stream_created_unix_nano,reconcile_stream_created_unix_nano=NULL,reconcile_high_watermark=NULL,reconcile_scan_boundary=NULL,reconcile_cursor=NULL,nats_dlq_sequence=9,nats_ack_id=nats_stream || ':9',acknowledged_at=clock_timestamp()`},
		{name: "publish ready stale wire sequence", prefix: publishReady084(), set: `publish_state='acknowledged',reconcile_phase='complete',nats_dlq_stream_created_unix_nano=reconcile_stream_created_unix_nano,reconcile_stream_created_unix_nano=NULL,reconcile_high_watermark=NULL,nats_dlq_sequence=10,nats_ack_id=nats_stream || ':10',acknowledged_at=clock_timestamp()`},
		{name: "publish ready future wire sequence", prefix: publishReady084(), set: `publish_state='acknowledged',reconcile_phase='complete',nats_dlq_stream_created_unix_nano=reconcile_stream_created_unix_nano,reconcile_stream_created_unix_nano=NULL,reconcile_high_watermark=NULL,nats_dlq_sequence=12,nats_ack_id=nats_stream || ':12',acknowledged_at=clock_timestamp()`},
		{name: "empty publish ready future wire sequence", prefix: []string{`reconcile_phase='publish_ready',reconcile_stream_created_unix_nano=1,reconcile_high_watermark=0`}, set: `publish_state='acknowledged',reconcile_phase='complete',nats_dlq_stream_created_unix_nano=reconcile_stream_created_unix_nano,reconcile_stream_created_unix_nano=NULL,reconcile_high_watermark=NULL,nats_dlq_sequence=2,nats_ack_id=nats_stream || ':2',acknowledged_at=clock_timestamp()`},
	}
	for _, check := range transitionCases {
		t.Run(check.name, func(t *testing.T) {
			pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
			for _, transition := range check.prefix {
				if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
					resource.subscription, delivery, transition); err != nil {
					t.Fatalf("valid prefix: %v", err)
				}
			}
			assertPluginWebhookCode084(t, updatePluginWebhookDeadLetter084(t, pool,
				identity.tenantScope, resource.subscription, delivery, check.set), "P8403")
			assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
				resource.subscription, delivery, "dead_letter_pending")
		})
	}
	for _, reset := range []struct {
		name   string
		prefix []string
	}{
		{name: "reverse scan", prefix: reverseScan084()},
		{name: "publish ready", prefix: publishReady084()},
		{name: "forward scan", prefix: forwardScan084()},
	} {
		t.Run("new epoch resets "+reset.name, func(t *testing.T) {
			pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
			for _, transition := range reset.prefix {
				if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
					resource.subscription, delivery, transition); err != nil {
					t.Fatal(err)
				}
			}
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, `reconcile_phase='reverse_scan',
						reconcile_stream_created_unix_nano=2,reconcile_high_watermark=5,
						reconcile_scan_boundary=1,reconcile_cursor=5`); err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, identityMutation := range []struct {
		name string
		set  func(pluginWebhookIdentity084) string
	}{
		{name: "id", set: func(pluginWebhookIdentity084) string { return `id='00000000-0000-0000-0000-000000000111'` }},
		{name: "tenant", set: func(identity pluginWebhookIdentity084) string {
			return fmt.Sprintf("tenant_scope_id='%s'", identity.foreignScope)
		}},
		{name: "subscription", set: func(pluginWebhookIdentity084) string { return `subscription_id='00000000-0000-0000-0000-000000000112'` }},
		{name: "delivery", set: func(pluginWebhookIdentity084) string { return `delivery_id='00000000-0000-0000-0000-000000000113'` }},
		{name: "event", set: func(pluginWebhookIdentity084) string { return `event_id='00000000-0000-0000-0000-000000000114'` }},
		{name: "attempt", set: func(pluginWebhookIdentity084) string { return `final_attempt_number=2` }},
		{name: "actor scope", set: func(identity pluginWebhookIdentity084) string {
			return fmt.Sprintf("actor_scope_id='%s',actor_user_id='%s'", identity.platformScope,
				identity.platformOwner)
		}},
		{name: "actor user", set: func(identity pluginWebhookIdentity084) string {
			return fmt.Sprintf("actor_user_id='%s'", identity.adminUser)
		}},
		{name: "stream", set: func(pluginWebhookIdentity084) string { return `nats_stream='OTHER'` }},
		{name: "subject", set: func(pluginWebhookIdentity084) string { return `nats_subject='other'` }},
		{name: "message id", set: func(pluginWebhookIdentity084) string { return `nats_message_id='other'` }},
		{name: "payload digest", set: func(pluginWebhookIdentity084) string { return `payload_sha256=decode(repeat('aa',32),'hex')` }},
		{name: "reason", set: func(pluginWebhookIdentity084) string { return `reason_code='other'` }},
		{name: "http status", set: func(pluginWebhookIdentity084) string { return `http_status=502` }},
		{name: "request digest", set: func(pluginWebhookIdentity084) string { return `request_sha256=decode(repeat('bb',32),'hex')` }},
		{name: "response digest", set: func(pluginWebhookIdentity084) string { return `response_sha256=decode(repeat('cc',32),'hex')` }},
		{name: "response bytes", set: func(pluginWebhookIdentity084) string { return `response_bytes=1` }},
		{name: "failed at", set: func(pluginWebhookIdentity084) string { return `failed_at=failed_at + interval '1 second'` }},
	} {
		t.Run("immutable "+identityMutation.name, func(t *testing.T) {
			pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, identityMutation.set(identity)); err == nil {
				t.Fatalf("DLQ identity mutation %s committed", identityMutation.name)
			}
		})
	}

	t.Run("recovery continues after tenant suspension", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended',
			updated_at=clock_timestamp() WHERE id=$1`, identity.tenantID); err != nil {
			t.Fatal(err)
		}
		for _, transition := range []string{
			`reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=404,reconcile_high_watermark=3,reconcile_scan_boundary=1,reconcile_cursor=3`,
			`reconcile_cursor=2`,
			`reconcile_cursor=1`,
			`reconcile_phase='publish_ready',reconcile_scan_boundary=NULL,reconcile_cursor=NULL`,
		} {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, transition); err != nil {
				t.Fatalf("suspended tenant recovery: %v", err)
			}
		}
		if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, 4); err != nil {
			t.Fatalf("suspended tenant acknowledgement: %v", err)
		}
		assertPluginWebhookDeliveryStatus084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "dead_lettered")
	})
}

func TestPluginWebhookControl084DeadLetterReconcileDownGuards(t *testing.T) {
	states := []struct {
		name        string
		steps       []string
		acknowledge bool
	}{
		{name: "uninitialized"},
		{name: "reverse scan", steps: reverseScan084()},
		{name: "publish ready", steps: publishReady084()},
		{name: "forward scan", steps: forwardScan084()},
		{name: "acknowledged", steps: reverseScan084(), acknowledge: true},
	}
	for _, state := range states {
		t.Run("fact "+state.name, func(t *testing.T) {
			pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
			for _, transition := range state.steps {
				if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
					resource.subscription, delivery, transition); err != nil {
					t.Fatal(err)
				}
			}
			if state.acknowledge {
				if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
					resource.subscription, delivery, 10); err != nil {
					t.Fatal(err)
				}
			}
			assertPluginWebhookDownP8401NoMutation084(t, pool)
		})
	}

	t.Run("empty down and up", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 84)
		if err := migrateVersionIsolated(t.Context(), pool, "down", 84); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookHead084(t, pool, 83)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookHead084(t, pool, 84)
	})

	drifts := []struct {
		name   string
		mutate string
	}{
		{name: "actor function body", mutate: `CREATE OR REPLACE FUNCTION
			validate_plugin_webhook_actor_target_084() RETURNS trigger LANGUAGE plpgsql
			AS $$ BEGIN RETURN NEW; END $$`},
		{name: "guard function body", mutate: `CREATE OR REPLACE FUNCTION
			guard_plugin_webhook_dead_letter_084() RETURNS trigger LANGUAGE plpgsql
			AS $$ BEGIN RETURN NEW; END $$`},
		{name: "validate function body", mutate: `CREATE OR REPLACE FUNCTION
			validate_plugin_webhook_dead_letter_084() RETURNS trigger LANGUAGE plpgsql
			AS $$ BEGIN RETURN NEW; END $$`},
		{name: "projection function body", mutate: `CREATE OR REPLACE FUNCTION
			project_plugin_webhook_dead_letter_ack_084() RETURNS trigger LANGUAGE plpgsql
			AS $$ BEGIN RETURN NULL; END $$`},
		{name: "guard function attribute", mutate: `ALTER FUNCTION
			guard_plugin_webhook_dead_letter_084() COST 1`},
		{name: "xact trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_00_xact_084 ON plugin_webhook_dead_letters`},
		{name: "actor trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_actor_target_084 ON plugin_webhook_dead_letters`},
		{name: "guard trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_guard_084 ON plugin_webhook_dead_letters`},
		{name: "delivery trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_delivery_084 ON plugin_webhook_dead_letters`},
		{name: "terminal trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_terminal_084 ON plugin_webhook_dead_letters`},
		{name: "truncate trigger", mutate: `DROP TRIGGER plugin_webhook_dead_letters_truncate_084 ON plugin_webhook_dead_letters`},
		{name: "phase column", mutate: `ALTER TABLE plugin_webhook_dead_letters DROP COLUMN reconcile_phase CASCADE`},
		{name: "epoch column", mutate: `ALTER TABLE plugin_webhook_dead_letters DROP COLUMN reconcile_stream_created_unix_nano CASCADE`},
		{name: "high column", mutate: `ALTER TABLE plugin_webhook_dead_letters DROP COLUMN reconcile_high_watermark CASCADE`},
		{name: "cursor column", mutate: `ALTER TABLE plugin_webhook_dead_letters DROP COLUMN reconcile_cursor CASCADE`},
		{name: "reconcile constraint", mutate: `ALTER TABLE plugin_webhook_dead_letters DROP CONSTRAINT plugin_webhook_dead_letters_reconcile_084_check`},
		{name: "reconcile index", mutate: `DROP INDEX plugin_webhook_dead_letters_reconcile_084`},
	}
	for _, drift := range drifts {
		t.Run(drift.name+" drift", func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 84)
			if _, err := pool.Exec(t.Context(), drift.mutate, pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			assertPluginWebhookDownP8401NoMutation084(t, pool)
		})
	}
}

func TestPluginWebhookControl084EntitlementDecisionRED(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	var present bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('control_entitlement_revocation_lkg') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("RED: 084 accepts a protected create without the required entitlement revocation LKG")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM control_entitlement_revocation_lkg`); err != nil {
		t.Fatal(err)
	}
	_, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now)
	if err == nil {
		t.Fatal("RED: protected create committed without a current entitlement decision")
	}
}

func TestPluginWebhookControl084EntitlementDecisionContract(t *testing.T) {
	checks := []struct {
		name    string
		feature bool
		quota   int64
		revoked []uint64
		mutate  string
	}{
		{name: "feature absent", quota: 100},
		{name: "quota denied", feature: true, quota: 0},
		{name: "lease revoked", feature: true, quota: 100, revoked: []uint64{1}},
		{name: "lease expired", feature: true, quota: 100, mutate: `UPDATE entitlement_cached_leases
			SET status='expired',not_before=clock_timestamp()-interval '2 hours',
				expires_at=clock_timestamp()-interval '1 hour',grace_until=clock_timestamp()
			WHERE serial=1`},
		{name: "grace ended", feature: true, quota: 100, mutate: `UPDATE entitlement_cached_leases
			SET status='grace',not_before=clock_timestamp()-interval '3 hours',
				expires_at=clock_timestamp()-interval '2 hours',grace_until=clock_timestamp()-interval '1 second'
			WHERE serial=1`},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			pool, identity := setupPluginWebhookEntitlementOnly084(t, check.feature, check.quota, check.revoked)
			if check.mutate != "" {
				tx, err := pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context())
				if _, err := tx.Exec(t.Context(), check.mutate, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			_, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
				identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
			assertPluginWebhookCode084(t, err, "P8408")
			assertPluginWebhookProtectedFacts084(t, pool, identity.tenantScope, 0)
		})
	}

	t.Run("quota counts durable active subscriptions", func(t *testing.T) {
		pool, identity := setupPluginWebhookEntitlementOnly084(t, true, 1, nil)
		insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
		_, err := insertPluginWebhookSubscriptionResult084(t, pool, identity.tenantScope,
			identity.platformScope, identity.platformAdmin, pluginWebhookDatabaseTime084(t, pool))
		assertPluginWebhookCode084(t, err, "P8408")
		assertPluginWebhookProtectedFacts084(t, pool, identity.tenantScope, 1)
	})

	t.Run("quota final slot is linearized and reconnect durable", func(t *testing.T) {
		pool, identity := setupPluginWebhookEntitlementOnly084(t, true, 1, nil)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		firstConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer firstConn.Release()
		secondConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer secondConn.Release()
		firstTx, err := firstConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer firstTx.Rollback(context.Background())
		first := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
		if err := insertPluginWebhookSubscriptionFacts084(ctx, firstTx, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, first.subscription, first.secret,
			pluginWebhookDatabaseTime084(t, firstTx)); err != nil {
			t.Fatal(err)
		}
		secondTx, err := secondConn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer secondTx.Rollback(context.Background())
		var firstPID, secondPID int32
		if err := firstTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
			t.Fatal(err)
		}
		if err := secondTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
			t.Fatal(err)
		}
		second := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
		secondAt := pluginWebhookDatabaseTime084(t, secondTx)
		secondResult := make(chan error, 1)
		go func() {
			secondResult <- insertPluginWebhookSubscriptionFacts084(ctx, secondTx,
				identity.tenantScope, identity.platformScope, identity.platformAdmin,
				second.subscription, second.secret, secondAt)
		}()
		waitForPluginWebhookBlock084(t, pool, secondPID, firstPID)
		if err := firstTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookCode084(t, <-secondResult, "P8408")
		if err := secondTx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatal(err)
		}
		reconnected, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer reconnected.Close()
		assertPluginWebhookProtectedFacts084(t, reconnected, identity.tenantScope, 1)
	})

	t.Run("accepted commands persist exact provenance", func(t *testing.T) {
		pool, identity, resource := setupPluginWebhook084(t)
		platformResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
			identity.platformScope, identity.platformAdmin, pluginWebhookDatabaseTime084(t, pool))
		if platformResource.subscription == uuid.Nil {
			t.Fatal("platform command did not retain its explicit target tenant")
		}
		original := seedPluginWebhookDelivery084(t, pool, identity, resource,
			pluginWebhookDatabaseTime084(t, pool))
		completePluginWebhookDelivery084(t, pool, identity, resource, original,
			pluginWebhookDatabaseTime084(t, pool))
		if err := insertPluginWebhookReplayOfResult084(t, pool, identity, resource, original); err != nil {
			t.Fatal(err)
		}
		rotatePluginWebhookSecret084(t, pool, identity, resource, pluginWebhookDatabaseTime084(t, pool))
		var operations int
		if err := pool.QueryRow(t.Context(), `SELECT count(DISTINCT operation)
			FROM plugin_webhook_entitlement_decisions
			WHERE tenant_scope_id=$1 AND feature_key='extensions.webhooks'
			  AND lease_status='valid' AND lease_serial=1
			  AND octet_length(lease_sha256)=32 AND revocation_revision=1
			  AND octet_length(revocation_sha256)=32 AND quota_allowed
			  AND evaluated_at>=lease_not_before AND evaluated_at<lease_grace_until
			  AND evaluated_at>=revocation_issued_at`,
			identity.tenantScope).Scan(&operations); err != nil {
			t.Fatal(err)
		}
		if operations != 4 {
			t.Fatalf("protected command entitlement operations=%d want 4", operations)
		}
		var activationDecision bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM plugin_webhook_entitlement_decisions
			WHERE tenant_scope_id=$1 AND operation='plugin_webhook.secret.activate'
		)`, identity.tenantScope).Scan(&activationDecision); err != nil {
			t.Fatal(err)
		}
		if activationDecision {
			t.Fatal("activation unexpectedly recorded an entitlement decision")
		}
		var platformBound bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM plugin_webhook_entitlement_decisions decision
			JOIN plugin_webhook_write_requests request ON request.id=decision.request_id
			WHERE decision.tenant_scope_id=$1 AND decision.actor_scope_id=$2
			  AND decision.actor_user_id=$3 AND decision.subscription_id=$4
			  AND decision.request_digest=request.request_digest
		)`, identity.tenantScope, identity.platformScope, identity.platformAdmin,
			platformResource.subscription).Scan(&platformBound); err != nil || !platformBound {
			t.Fatalf("platform entitlement provenance bound=%t err=%v", platformBound, err)
		}
	})
}

func TestPluginWebhookControl084ActivationEntitlementBoundary(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	now := pluginWebhookDatabaseTime084(t, pool)
	original := seedPluginWebhookDelivery084(t, pool, identity, resource, now)
	completePluginWebhookDelivery084(t, pool, identity, resource, original, now.Add(time.Minute))
	pending := insertPluginWebhookPendingSecret084(t, pool, identity, resource, 2,
		pluginWebhookDatabaseTime084(t, pool))

	forgedResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
	forgedPending := insertPluginWebhookPendingSecret084(t, pool, identity, forgedResource, 2,
		pluginWebhookDatabaseTime084(t, pool))
	expiredResource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
	expiredPending := insertPluginWebhookPendingSecret084(t, pool, identity, expiredResource, 2,
		pluginWebhookDatabaseTime084(t, pool))
	agePluginWebhookSecretExpiry084(t, pool, identity.tenantScope,
		expiredResource.subscription, expiredPending)

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `UPDATE entitlement_cached_leases
		SET status='expired',not_before=clock_timestamp()-interval '2 hours',
			expires_at=clock_timestamp()-interval '1 hour',grace_until=clock_timestamp()
		WHERE serial=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET issued_at=clock_timestamp()-interval '16 minutes',
			expires_at=clock_timestamp()-interval '1 minute',
			accepted_at=clock_timestamp()-interval '2 minutes' WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	testTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer testTx.Rollback(t.Context())
	testAt := pluginWebhookDatabaseTime084(t, testTx)
	eventID := uuid.Must(uuid.NewV7())
	body := pluginWebhookCanonicalBody084(t, identity, resource, eventID, nil, 2, testAt)
	digest := sha256.Sum256(body)
	if err = insertPluginWebhookEvent084(t, testTx, identity, resource, eventID, nil,
		body, digest[:], testAt); err != nil {
		t.Fatal(err)
	}
	deliveryID, err := insertPluginWebhookDeliveryRow084(t, testTx, identity, resource,
		eventID, uuid.Nil, testAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertPluginWebhookOutbox084(t, testTx, identity, resource, eventID, deliveryID,
		body, digest[:], "plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()), testAt); err != nil {
		t.Fatal(err)
	}
	err = insertPluginWebhookCommandFactsTx084(t.Context(), t, testTx, identity,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.test_delivery.create",
		resource.subscription, deliveryID, testAt,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true})
	assertPluginWebhookCode084(t, err, "P8408")
	if err = testTx.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}

	err = insertPluginWebhookReplayOfResult084(t, pool, identity, resource, original)
	assertPluginWebhookCode084(t, err, "P8408")
	_, err = insertPluginWebhookPendingSecretResult084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	assertPluginWebhookCode084(t, err, "P8408")

	if err = activatePluginWebhookSecretsResult084(t, pool, identity, resource,
		pending, []uuid.UUID{pending}, pluginWebhookDatabaseTime084(t, pool)); err != nil {
		t.Fatalf("activate pending secret after entitlement loss: %v", err)
	}
	var activationDecisions int
	if err = pool.QueryRow(t.Context(), `SELECT count(*)
		FROM plugin_webhook_entitlement_decisions decision
		JOIN plugin_webhook_write_requests request ON request.id=decision.request_id
		WHERE request.operation='plugin_webhook.secret.activate'`).Scan(&activationDecisions); err != nil {
		t.Fatal(err)
	}
	if activationDecisions != 0 {
		t.Fatalf("activation entitlement decisions=%d want=0", activationDecisions)
	}

	forgedTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer forgedTx.Rollback(t.Context())
	err = insertPluginWebhookManagementRequestTx084(t.Context(), t, forgedTx, identity,
		identity.tenantScope, identity.memberUser, "plugin_webhook.secret.activate",
		forgedResource.subscription, forgedPending, pluginWebhookDatabaseTime084(t, forgedTx))
	assertPluginWebhookCode084(t, err, "P8402")
	if err = forgedTx.Rollback(t.Context()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}

	err = activatePluginWebhookSecretsResult084(t, pool, identity, expiredResource,
		expiredPending, []uuid.UUID{expiredPending}, pluginWebhookDatabaseTime084(t, pool))
	assertPluginWebhookCode084(t, err, "P8406")
}

func TestPluginWebhookControl084RevocationPersistenceContract(t *testing.T) {
	pool, _ := setupPluginWebhookEntitlementOnly084(t, true, 100, nil)
	now := pluginWebhookDatabaseTime084(t, pool).Truncate(time.Second)
	artifact, digest, etag, expiresAt := pluginWebhookSignedRevocation084(t, 2, now, []uint64{1, 7})
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	for _, serial := range []uint64{1, 7} {
		if _, err := tx.Exec(t.Context(), `INSERT INTO control_entitlement_revoked_serials(
			installation_id,license_id,serial,first_revision,first_artifact_sha256,recorded_at
		) VALUES('22222222-2222-4222-8222-222222222222',
			'33333333-3333-4333-8333-333333333333',$1,2,$2,$3)`, serial, digest[:], now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET revision=2,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
			issued_at=$4,expires_at=$5,accepted_at=$4 WHERE singleton=true`,
		artifact, digest[:], etag, now, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET status='revoked' WHERE serial=1`); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET status='valid' WHERE serial=1`)
	assertPluginWebhookCode084(t, err, "P8408")

	conflictArtifact, conflictDigest, conflictETag, conflictExpires :=
		pluginWebhookSignedRevocation084(t, 2, now, []uint64{1, 7, 9})
	_, err = pool.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET revision=2,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
			issued_at=$4,expires_at=$5 WHERE singleton=true`, conflictArtifact,
		conflictDigest[:], conflictETag, now, conflictExpires)
	assertPluginWebhookCode084(t, err, "P8408")

	lowerIssued := now.Add(time.Second)
	lowerArtifact, lowerDigest, lowerETag, lowerExpires :=
		pluginWebhookSignedRevocation084(t, 1, lowerIssued, []uint64{1, 7})
	_, err = pool.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET revision=1,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
			issued_at=$4,expires_at=$5 WHERE singleton=true`, lowerArtifact,
		lowerDigest[:], lowerETag, lowerIssued, lowerExpires)
	assertPluginWebhookCode084(t, err, "P8408")

	shrinkIssued := now.Add(time.Second)
	shrinkArtifact, shrinkDigest, shrinkETag, shrinkExpires :=
		pluginWebhookSignedRevocation084(t, 3, shrinkIssued, []uint64{1})
	_, err = pool.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET revision=3,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
			issued_at=$4,expires_at=$5 WHERE singleton=true`, shrinkArtifact,
		shrinkDigest[:], shrinkETag, shrinkIssued, shrinkExpires)
	assertPluginWebhookCode084(t, err, "P8408")

	_, err = pool.Exec(t.Context(), `UPDATE control_entitlement_revoked_serials
		SET recorded_at=clock_timestamp() WHERE serial=7`)
	assertPluginWebhookCode084(t, err, "P8408")
	_, err = pool.Exec(t.Context(), `DELETE FROM control_entitlement_revoked_serials WHERE serial=7`)
	assertPluginWebhookCode084(t, err, "P8408")
	_, err = pool.Exec(t.Context(), `TRUNCATE control_entitlement_revoked_serials`)
	assertPluginWebhookCode084(t, err, "P8408")

	reconnected, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	var revision, revokedCount int
	if err := reconnected.QueryRow(t.Context(), `SELECT
		(SELECT revision::int FROM control_entitlement_revocation_lkg WHERE singleton=true),
		(SELECT count(*) FROM control_entitlement_revoked_serials)`).Scan(&revision, &revokedCount); err != nil {
		t.Fatal(err)
	}
	if revision != 2 || revokedCount != 2 {
		t.Fatalf("reconnected revocation revision/count=%d/%d want=2/2", revision, revokedCount)
	}
	var projectionMismatch bool
	if err := reconnected.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT (value #>> '{}')::bigint AS serial
		FROM control_entitlement_revocation_lkg lkg,
		LATERAL jsonb_array_elements(
			(convert_from(lkg.artifact,'UTF8')::jsonb)->'body'->'revoked_serials') value
		EXCEPT SELECT serial FROM control_entitlement_revoked_serials
	) OR EXISTS(
		SELECT serial FROM control_entitlement_revoked_serials
		EXCEPT SELECT (value #>> '{}')::bigint
		FROM control_entitlement_revocation_lkg lkg,
		LATERAL jsonb_array_elements(
			(convert_from(lkg.artifact,'UTF8')::jsonb)->'body'->'revoked_serials') value
	)`).Scan(&projectionMismatch); err != nil {
		t.Fatal(err)
	}
	if projectionMismatch {
		t.Fatal("signed revocation serials and permanent projection differ")
	}
}

func TestPluginWebhookControl084RevocationProjectionExactEqualityRED(t *testing.T) {
	for _, check := range []struct {
		name      string
		signed    []uint64
		projected []uint64
		extraOnly bool
	}{
		{name: "omitted signed serial", signed: []uint64{7}},
		{name: "partial signed serial set", signed: []uint64{7, 9}, projected: []uint64{7}},
		{name: "unsigned projected serial", projected: []uint64{9}, extraOnly: true},
	} {
		t.Run(check.name, func(t *testing.T) {
			pool, _ := setupPluginWebhookEntitlementOnly084(t, true, 100, nil)
			now := pluginWebhookDatabaseTime084(t, pool).Truncate(time.Second)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			revision := int64(1)
			var digest []byte
			if !check.extraOnly {
				revision = 2
				artifact, foundDigest, etag, expiresAt :=
					pluginWebhookSignedRevocation084(t, 2, now, check.signed)
				digest = append([]byte(nil), foundDigest[:]...)
				if _, err := tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
					SET revision=2,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
						issued_at=$4,expires_at=$5 WHERE singleton=true`, artifact, digest[:],
					etag, now, expiresAt); err != nil {
					t.Fatal(err)
				}
			} else if err := tx.QueryRow(t.Context(), `SELECT artifact_sha256
				FROM control_entitlement_revocation_lkg WHERE singleton=true`).Scan(&digest); err != nil {
				t.Fatal(err)
			}
			for _, serial := range check.projected {
				if _, err := tx.Exec(t.Context(), `INSERT INTO control_entitlement_revoked_serials(
					installation_id,license_id,serial,first_revision,first_artifact_sha256,recorded_at
				) VALUES('22222222-2222-4222-8222-222222222222',
					'33333333-3333-4333-8333-333333333333',$1,$2,$3,$4)`, serial,
					revision, digest, now); err != nil {
					t.Fatal(err)
				}
			}
			err = tx.Commit(t.Context())
			if err == nil {
				t.Fatal("RED: signed artifact and serial projection committed with unequal sets")
			}
			assertPluginWebhookCode084(t, err, "P8408")
			var currentRevision, serialCount int
			if err := pool.QueryRow(t.Context(), `SELECT
				(SELECT revision::int FROM control_entitlement_revocation_lkg WHERE singleton=true),
				(SELECT count(*) FROM control_entitlement_revoked_serials)`).
				Scan(&currentRevision, &serialCount); err != nil {
				t.Fatal(err)
			}
			if currentRevision != 1 || serialCount != 0 {
				t.Fatalf("rejected projection mutated revision/count=%d/%d", currentRevision, serialCount)
			}
		})
	}
}

func TestPluginWebhookControl084RevocationLKGSignatureRED(t *testing.T) {
	pool, _ := setupPluginWebhookEntitlementOnly084(t, true, 100, nil)
	var rfcValid, rfcInvalid bool
	if err := pool.QueryRow(t.Context(), `SELECT
		plugin_webhook_ed25519_verify_084(
			decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','hex'),
			''::bytea,
			decode('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
				|| '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b','hex')),
		plugin_webhook_ed25519_verify_084(
			decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','hex'),
			''::bytea,
			decode('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
				|| '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100a','hex'))`).
		Scan(&rfcValid, &rfcInvalid); err != nil {
		t.Fatal(err)
	}
	if !rfcValid || rfcInvalid {
		t.Fatalf("RFC8032 empty-message verification valid/invalid=%t/%t", rfcValid, rfcInvalid)
	}
	for _, invalidPoint := range []struct {
		name      string
		publicKey string
		message   string
		signature string
	}{
		{name: "identity",
			publicKey: "0100000000000000000000000000000000000000000000000000000000000000",
			signature: "5866666666666666666666666666666666666666666666666666666666666666" +
				"0100000000000000000000000000000000000000000000000000000000000000"},
		{name: "order eight",
			publicKey: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
			message:   "6c6f772d6f726465722d36",
			signature: "0100000000000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000000"},
		{name: "mixed order",
			publicKey: "55ae61520ca466adcc4ae4a32dc1633a5d749c64a5b50f136fc3469f27e487e6",
			message:   "6d697865642d6f726465722d31",
			signature: "5866666666666666666666666666666666666666666666666666666666666666" +
				"89c67682a1bfb19bd2178c78f06e4520afb71062487676062a7435ab1fb8c308"},
	} {
		t.Run("reject "+invalidPoint.name+" public key", func(t *testing.T) {
			var accepted bool
			if err := pool.QueryRow(t.Context(), `SELECT plugin_webhook_ed25519_verify_084(
				decode($1,'hex'),decode($2,'hex'),decode($3,'hex'))`, invalidPoint.publicKey,
				invalidPoint.message, invalidPoint.signature).Scan(&accepted); err != nil {
				t.Fatal(err)
			}
			if accepted {
				t.Fatal("RED: non-prime-subgroup Ed25519 public key was accepted")
			}
		})
	}

	now := pluginWebhookDatabaseTime084(t, pool).Truncate(time.Second)
	validArtifact, _, _, validExpires := pluginWebhookSignedRevocation084(t, 2, now, nil)
	var valid entitlement.SignedRevocationSet
	if err := json.Unmarshal(validArtifact, &valid); err != nil {
		t.Fatal(err)
	}
	encode := func(value entitlement.SignedRevocationSet) []byte {
		artifact, err := value.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	unsigned := valid
	unsigned.Signature = strings.Repeat("A", 86)
	flipped := valid
	replacement := byte('A')
	if flipped.Signature[0] == replacement {
		replacement = 'B'
	}
	flipped.Signature = string(replacement) + flipped.Signature[1:]
	missingKey := valid
	missingKey.KeyID = "missing-plugin-webhook-key-084"
	tampered := valid
	tampered.Body.Revision = 3
	noncanonical := append(append([]byte{}, validArtifact...), '\n')

	cases := []struct {
		name     string
		artifact []byte
		revision int64
		keyID    string
	}{
		{name: "unsigned canonical", artifact: encode(unsigned), revision: 2,
			keyID: unsigned.KeyID},
		{name: "bit flipped signature", artifact: encode(flipped), revision: 2,
			keyID: flipped.KeyID},
		{name: "missing trusted key", artifact: encode(missingKey), revision: 2,
			keyID: missingKey.KeyID},
		{name: "tampered signed body", artifact: encode(tampered), revision: 3,
			keyID: tampered.KeyID},
		{name: "noncanonical bytes", artifact: noncanonical, revision: 2,
			keyID: valid.KeyID},
	}
	var baselineRevision int64
	var baselineDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT revision,artifact_sha256
		FROM control_entitlement_revocation_lkg WHERE singleton=true`).
		Scan(&baselineRevision, &baselineDigest); err != nil {
		t.Fatal(err)
	}
	for _, check := range cases {
		t.Run(check.name, func(t *testing.T) {
			digest := entitlement.RevocationSetDigest(check.artifact)
			_, err := pool.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
				SET revision=$1,key_id=$2,artifact=$3,artifact_sha256=$4,artifact_etag=$5,
					issued_at=$6,expires_at=$7,accepted_at=$6 WHERE singleton=true`,
				check.revision, check.keyID, check.artifact, digest[:],
				entitlement.RevocationSetETag(check.artifact), now, validExpires)
			assertPluginWebhookCode084(t, err, "P8408")
			var revision int64
			var foundDigest []byte
			if err := pool.QueryRow(t.Context(), `SELECT revision,artifact_sha256
				FROM control_entitlement_revocation_lkg WHERE singleton=true`).
				Scan(&revision, &foundDigest); err != nil {
				t.Fatal(err)
			}
			if revision != baselineRevision || string(foundDigest) != string(baselineDigest) {
				t.Fatalf("rejected LKG mutated revision/digest=%d/%x", revision, foundDigest)
			}
		})
	}
	for _, raw := range []struct {
		name      string
		revision  string
		serials   string
		storedRev int64
	}{
		{name: "fractional revision token", revision: "2.0", serials: "[]", storedRev: 2},
		{name: "exponent revision token", revision: "2e0", serials: "[]", storedRev: 2},
		{name: "fractional serial token", revision: "2", serials: "[1.0]", storedRev: 2},
		{name: "exponent serial token", revision: "2", serials: "[1e0]", storedRev: 2},
		{name: "serial above signed range", revision: "2", serials: "[9223372036854775808]", storedRev: 2},
		{name: "serial above uint64", revision: "2", serials: "[18446744073709551616]", storedRev: 2},
	} {
		t.Run(raw.name, func(t *testing.T) {
			artifact, digest, etag := pluginWebhookRawSignedRevocation084(t, now,
				raw.revision, raw.serials)
			_, err := pool.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
				SET revision=$1,artifact=$2,artifact_sha256=$3,artifact_etag=$4,
					issued_at=$5,expires_at=$6 WHERE singleton=true`, raw.storedRev, artifact,
				digest[:], etag, now, now.Add(entitlement.RevocationSetWindow))
			assertPluginWebhookCode084(t, err, "P8408")
		})
	}
}

func TestPluginWebhookControl084RevocationCurrentKeyProjectionRED(t *testing.T) {
	pool, _ := setupPluginWebhookEntitlementOnly084(t, true, 100, nil)
	now := pluginWebhookDatabaseTime084(t, pool).Truncate(time.Second)
	artifact, digest, etag, expiresAt := pluginWebhookSignedRevocation084(t, 2, now, nil)
	for _, check := range []struct {
		name   string
		mutate string
		args   []any
	}{
		{name: "missing current key", mutate: `DELETE FROM entitlement_signing_keyset_current_keys`},
		{name: "retired current key", mutate: `UPDATE entitlement_signing_keyset_current_keys SET status='retired'`},
		{name: "stale keyset digest", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET keyset_payload_sha256=decode(repeat('aa',32),'hex')`},
		{name: "wrong valid public key", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET public_key=$1`, args: []any{ed25519.NewKeyFromSeed(bytes084(32, 0xab)).Public().(ed25519.PublicKey)}},
		{name: "not before after issue", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET not_before=$1`, args: []any{now.Add(time.Second)}},
		{name: "sign window too short", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET sign_until=$1`, args: []any{expiresAt.Add(-time.Second)}},
		{name: "verify window too short", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET sign_until=$1,verify_until=$2`,
			args: []any{expiresAt.Add(-2 * time.Second), expiresAt.Add(-time.Second)}},
		{name: "stale projection acceptance", mutate: `UPDATE entitlement_signing_keyset_current_keys
			SET accepted_at=accepted_at + interval '1 microsecond'`},
	} {
		t.Run(check.name, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if _, err := tx.Exec(t.Context(), check.mutate, check.args...); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
				SET revision=2,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
					issued_at=$4,expires_at=$5 WHERE singleton=true`, artifact, digest[:], etag,
				now, expiresAt)
			assertPluginWebhookCode084(t, err, "P8408")
		})
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `UPDATE entitlement_signing_keyset_current_keys
		SET status='verify_only',not_before=$1,sign_until=$2,verify_until=$2`, now, expiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_entitlement_revocation_lkg
		SET revision=2,artifact=$1,artifact_sha256=$2,artifact_etag=$3,
			issued_at=$4,expires_at=$5 WHERE singleton=true`, artifact, digest[:], etag,
		now, expiresAt); err != nil {
		t.Fatalf("exact verify-only key window rejected: %v", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var publicDML bool
	if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege(
		'public','entitlement_signing_keyset_current_keys','INSERT,UPDATE,DELETE,TRUNCATE')`).
		Scan(&publicDML); err != nil {
		t.Fatal(err)
	}
	if publicDML {
		t.Fatal("PUBLIC has DML on current entitlement signing keys")
	}
}
func TestPluginWebhookControl084DeadLetterInsertStartsPendingRED(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	now := pluginWebhookDatabaseTime084(t, pool)
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, now)
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		pluginWebhookDatabaseTime084(t, pool))
	if err := startPluginWebhookAttemptResult084(t, pool, claim, false,
		pluginWebhookDatabaseTime084(t, pool)); err != nil {
		t.Fatal(err)
	}
	var originalStatus string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, delivery).Scan(&originalStatus); err != nil {
		t.Fatal(err)
	}
	assertUnchanged := func() {
		var deadLetters int
		var status string
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM plugin_webhook_dead_letters WHERE delivery_id=$1),
			(SELECT status FROM plugin_webhook_deliveries WHERE tenant_scope_id=$2
			 AND subscription_id=$3 AND id=$1)`, delivery, identity.tenantScope,
			resource.subscription).Scan(&deadLetters, &status); err != nil {
			t.Fatal(err)
		}
		if deadLetters != 0 || status != originalStatus {
			t.Fatalf("forged DLQ changed count/status=%d/%s want=0/%s",
				deadLetters, status, originalStatus)
		}
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='permanent_failure',completed_at=clock_timestamp(),http_status=503,
			failure_code='upstream_permanent_failure',response_sha256=$2,response_bytes=0,
			response_preview=''::bytea,sanitized_headers='{}'::jsonb WHERE claim_token=$1`,
		claim, bytes084(32, 0xed)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_dead_letters(
		id,tenant_scope_id,subscription_id,delivery_id,event_id,final_attempt_number,
		actor_scope_id,actor_user_id,nats_stream,nats_subject,nats_message_id,payload_sha256,
		publish_state,reconcile_phase,nats_dlq_stream_created_unix_nano,nats_dlq_sequence,
		nats_ack_id,acknowledged_at,
		reason_code,http_status,request_sha256,response_sha256,response_bytes,failed_at
	) SELECT $2,attempt.tenant_scope_id,attempt.subscription_id,attempt.delivery_id,delivery.event_id,
		attempt.attempt_number,attempt.actor_scope_id,attempt.actor_user_id,'PLUGIN_WEBHOOK_DLQ',
		'cdnca.plugin-webhook.dead-letter.v1','plugin-webhook-dlq-v1-' || encode(sha256(
			convert_to(attempt.delivery_id::text || ':' || attempt.attempt_number::text,'UTF8')),'hex'),
		plugin_webhook_dead_letter_payload_sha256_084(attempt.tenant_scope_id,
			attempt.subscription_id,attempt.delivery_id,delivery.event_id,attempt.attempt_number,
			attempt.failure_code,attempt.http_status,attempt.request_sha256,attempt.response_sha256,
			attempt.response_bytes),'acknowledged','complete',101,17,'PLUGIN_WEBHOOK_DLQ:17',
		clock_timestamp(),attempt.failure_code,attempt.http_status,attempt.request_sha256,
		attempt.response_sha256,attempt.response_bytes,attempt.completed_at
	FROM plugin_webhook_delivery_attempts attempt JOIN plugin_webhook_deliveries delivery
	  ON delivery.tenant_scope_id=attempt.tenant_scope_id
	 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
	WHERE attempt.claim_token=$1`, claim, uuid.New()); err != nil {
		assertPluginWebhookCode084(t, err, "P8403")
		if rollbackErr := tx.Rollback(t.Context()); rollbackErr != nil &&
			!errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Fatal(rollbackErr)
		}
		assertUnchanged()
		return
	}
	if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
		SET status='dead_lettered' WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		identity.tenantScope, resource.subscription, delivery); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(t.Context())
	if err == nil {
		t.Fatal("RED: direct acknowledged/complete INSERT forged a dead-lettered delivery")
	}
	assertPluginWebhookCode084(t, err, "P8403")
	assertUnchanged()
}

func TestPluginWebhookControl084ReconcileNoSkipRED(t *testing.T) {
	t.Run("reverse scan cannot become ready before its lower boundary", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		start := `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=101,
			reconcile_high_watermark=10,reconcile_cursor=10`
		ready := `reconcile_phase='publish_ready',reconcile_cursor=NULL`
		if pluginWebhookColumnExists084(t, pool, "plugin_webhook_dead_letters", "reconcile_scan_boundary") {
			start += `,reconcile_scan_boundary=1`
			ready += `,reconcile_scan_boundary=NULL`
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, start); err != nil {
			t.Fatal(err)
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_cursor=9`); err != nil {
			t.Fatal(err)
		}
		err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, ready)
		if err == nil {
			t.Fatal("RED: reverse scan became ready before reaching its persisted lower boundary")
		}
		assertPluginWebhookCode084(t, err, "P8403")
	})

	t.Run("forward scan cannot become ready before its frozen high watermark", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		for _, transition := range publishReady084() {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, transition); err != nil {
				t.Fatal(err)
			}
		}
		start := `reconcile_phase='forward_scan',reconcile_high_watermark=20,reconcile_cursor=11`
		ready := `reconcile_phase='publish_ready',reconcile_cursor=NULL`
		if pluginWebhookColumnExists084(t, pool, "plugin_webhook_dead_letters", "reconcile_scan_boundary") {
			start += `,reconcile_scan_boundary=11`
			ready += `,reconcile_scan_boundary=NULL`
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, start); err != nil {
			t.Fatal(err)
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_cursor=12`); err != nil {
			t.Fatal(err)
		}
		err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, ready)
		if err == nil {
			t.Fatal("RED: forward scan became ready before exhausting its frozen high watermark")
		}
		assertPluginWebhookCode084(t, err, "P8403")
	})

	t.Run("one checkpoint cannot claim more than 32 inspected sequences", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		start := `reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=101,
			reconcile_high_watermark=100,reconcile_cursor=100`
		if pluginWebhookColumnExists084(t, pool, "plugin_webhook_dead_letters", "reconcile_scan_boundary") {
			start += `,reconcile_scan_boundary=1`
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, start); err != nil {
			t.Fatal(err)
		}
		err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_cursor=67`)
		if err == nil {
			t.Fatal("RED: reverse scan checkpoint skipped more than the frozen 32-sequence batch")
		}
		assertPluginWebhookCode084(t, err, "P8403")
	})

	t.Run("forward checkpoint cannot skip more than 32 inspected sequences", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		for _, transition := range publishReady084() {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, transition); err != nil {
				t.Fatal(err)
			}
		}
		if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_phase='forward_scan',
				reconcile_high_watermark=100,reconcile_scan_boundary=11,reconcile_cursor=11`); err != nil {
			t.Fatal(err)
		}
		err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `reconcile_cursor=44`)
		if err == nil {
			t.Fatal("RED: forward scan checkpoint skipped more than the frozen 32-sequence batch")
		}
		assertPluginWebhookCode084(t, err, "P8403")
	})

	t.Run("publication acknowledgement must complete reconcile CAS", func(t *testing.T) {
		pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
		for _, transition := range publishReady084() {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, transition); err != nil {
				t.Fatal(err)
			}
		}
		err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
			resource.subscription, delivery, `publish_state='acknowledged',
				nats_dlq_sequence=11,nats_ack_id=nats_stream || ':11'`)
		if err == nil {
			t.Fatal("RED: broker ACK committed without the complete reconcile CAS")
		}
		assertPluginWebhookCode084(t, err, "P8403")
		assertPluginWebhookDeadLetterReconcile084(t, pool, identity.tenantScope,
			resource.subscription, delivery, "pending", "publish_ready",
			text084("1"), text084("10"), nil, nil)
	})
}

func TestPluginWebhookControl084DeliveryStreamIncarnationRED(t *testing.T) {
	pool, identity, first := setupPluginWebhook084(t)
	second := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
	third := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhookDatabaseTime084(t, pool))
	_, firstDelivery := seedPluginWebhookPendingBundle084(t, pool, identity, first,
		pluginWebhookDatabaseTime084(t, pool))
	_, secondDelivery := seedPluginWebhookPendingBundle084(t, pool, identity, second,
		pluginWebhookDatabaseTime084(t, pool))
	_, thirdDelivery := seedPluginWebhookPendingBundle084(t, pool, identity, third,
		pluginWebhookDatabaseTime084(t, pool))
	hasEpoch := pluginWebhookColumnExists084(t, pool, "plugin_webhook_deliveries",
		"nats_stream_created_unix_nano")
	if !hasEpoch {
		t.Fatal("delivery stream-incarnation column is absent")
	}
	if err := queuePluginWebhookDeliveryIdentity084(t, pool, identity.tenantScope,
		first.subscription, firstDelivery, 101, 7, hasEpoch); err != nil {
		t.Fatal(err)
	}
	err := queuePluginWebhookDeliveryIdentity084(t, pool, identity.tenantScope,
		second.subscription, secondDelivery, 101, 7, hasEpoch)
	if err == nil {
		t.Fatal("RED: two deliveries bound the same stream incarnation and sequence")
	}
	assertPluginWebhookCode084(t, err, "23505")
	if err := queuePluginWebhookDeliveryIdentity084(t, pool, identity.tenantScope,
		third.subscription, thirdDelivery, 202, 7, hasEpoch); err != nil {
		t.Fatalf("same-name recreated stream identity: %v", err)
	}
	for name, mutation := range map[string]string{
		"epoch":    `nats_stream_created_unix_nano=102`,
		"sequence": `nats_stream_sequence=8`,
		"pair":     `nats_stream_created_unix_nano=102,nats_stream_sequence=8`,
	} {
		t.Run("immutable "+name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_deliveries SET `+mutation+`
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
				first.subscription, firstDelivery)
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}
	reconnected, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	var epoch, sequence string
	if err := reconnected.QueryRow(t.Context(), `SELECT
		nats_stream_created_unix_nano::text,nats_stream_sequence::text
		FROM plugin_webhook_deliveries WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		identity.tenantScope, first.subscription, firstDelivery).Scan(&epoch, &sequence); err != nil {
		t.Fatal(err)
	}
	if epoch != "101" || sequence != "7" {
		t.Fatalf("reconnected broker identity=%s/%s want=101/7", epoch, sequence)
	}

	for _, check := range []struct {
		name     string
		epoch    uint64
		sequence uint64
	}{
		{name: "zero epoch", epoch: 0, sequence: 1},
		{name: "epoch above MaxInt64", epoch: uint64(1 << 63), sequence: 1},
		{name: "zero sequence", epoch: 1, sequence: 0},
	} {
		t.Run(check.name, func(t *testing.T) {
			boundsPool, boundsIdentity, boundsResource := setupPluginWebhook084(t)
			_, boundsDelivery := seedPluginWebhookPendingBundle084(t, boundsPool, boundsIdentity,
				boundsResource, pluginWebhookDatabaseTime084(t, boundsPool))
			err := queuePluginWebhookDeliveryIdentity084(t, boundsPool, boundsIdentity.tenantScope,
				boundsResource.subscription, boundsDelivery, check.epoch, check.sequence, true)
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}
}

func TestPluginWebhookControl084DeadLetterTerminalStreamIncarnationRED(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	first := seedPluginWebhookPendingDeadLetterInPool084(t, pool, identity, resource)
	second := seedPluginWebhookPendingDeadLetterInPool084(t, pool, identity, resource)
	third := seedPluginWebhookPendingDeadLetterInPool084(t, pool, identity, resource)

	prepare := func(delivery uuid.UUID, epoch uint64) {
		t.Helper()
		for _, transition := range []string{
			fmt.Sprintf(`reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=%d,
				reconcile_high_watermark=6,reconcile_scan_boundary=1,reconcile_cursor=6`, epoch),
			`reconcile_cursor=1`,
			`reconcile_phase='publish_ready',reconcile_scan_boundary=NULL,reconcile_cursor=NULL`,
		} {
			if err := updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
				resource.subscription, delivery, transition); err != nil {
				t.Fatal(err)
			}
		}
	}
	prepare(first, 101)
	if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
		resource.subscription, first, 7); err != nil {
		t.Fatal(err)
	}
	var epoch, sequence string
	if err := pool.QueryRow(t.Context(), `SELECT nats_dlq_stream_created_unix_nano::text,
		nats_dlq_sequence::text FROM plugin_webhook_dead_letters WHERE delivery_id=$1`, first).
		Scan(&epoch, &sequence); err != nil {
		t.Fatal(err)
	}
	if epoch != "101" || sequence != "7" {
		t.Fatalf("terminal DLQ broker identity=%s/%s want=101/7", epoch, sequence)
	}
	prepare(second, 101)
	err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
		resource.subscription, second, 7)
	assertPluginWebhookCode084(t, err, "23505")
	prepare(third, 202)
	if err := acknowledgePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
		resource.subscription, third, 7); err != nil {
		t.Fatalf("same stream and sequence in a recreated stream: %v", err)
	}

	fourth := seedPluginWebhookPendingDeadLetterInPool084(t, pool, identity, resource)
	prepare(fourth, 303)
	err = updatePluginWebhookDeadLetter084(t, pool, identity.tenantScope,
		resource.subscription, fourth, `publish_state='acknowledged',reconcile_phase='complete',
			nats_dlq_stream_created_unix_nano=304,reconcile_stream_created_unix_nano=NULL,
			reconcile_high_watermark=NULL,nats_dlq_sequence=1,
			nats_ack_id=nats_stream || ':1'`)
	assertPluginWebhookCode084(t, err, "P8403")

	for name, assignment := range map[string]string{
		"epoch":    `nats_dlq_stream_created_unix_nano=102`,
		"sequence": `nats_dlq_sequence=8`,
	} {
		t.Run("immutable "+name, func(t *testing.T) {
			assertPluginWebhookCode084(t, updatePluginWebhookDeadLetter084(t, pool,
				identity.tenantScope, resource.subscription, first, assignment), "P8403")
		})
	}
	reconnected, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	if err := reconnected.QueryRow(t.Context(), `SELECT nats_dlq_stream_created_unix_nano::text,
		nats_dlq_sequence::text FROM plugin_webhook_dead_letters WHERE delivery_id=$1`, third).
		Scan(&epoch, &sequence); err != nil {
		t.Fatal(err)
	}
	if epoch != "202" || sequence != "7" {
		t.Fatalf("reconnected terminal DLQ identity=%s/%s want=202/7", epoch, sequence)
	}
}

func TestPluginWebhookControl084CompleteP8401RED(t *testing.T) {
	t.Run("clean catalog down and up", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 84)
		if err := migrateVersionIsolated(t.Context(), pool, "down", 84); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookHead084(t, pool, 83)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		assertPluginWebhookHead084(t, pool, 84)
	})
	drifts := []struct {
		name   string
		mutate string
	}{
		{name: "uncovered function attribute", mutate: `ALTER FUNCTION guard_plugin_webhook_delivery_084() COST 1`},
		{name: "crypto function body", mutate: `CREATE OR REPLACE FUNCTION
			plugin_webhook_mod_084(value numeric,modulus numeric)
			RETURNS numeric LANGUAGE sql IMMUTABLE STRICT
			AS 'SELECT 0::numeric'`},
		{name: "crypto function owner", mutate: `ALTER FUNCTION
			plugin_webhook_mod_084(numeric,numeric) OWNER TO pg_database_owner`},
		{name: "crypto function ACL", mutate: `GRANT EXECUTE ON FUNCTION
			plugin_webhook_mod_084(numeric,numeric) TO PUBLIC`},
		{name: "function missing", mutate: `DROP FUNCTION plugin_webhook_mod_084(numeric,numeric) CASCADE`},
		{name: "uncovered trigger", mutate: `DROP TRIGGER plugin_webhook_deliveries_guard_084 ON plugin_webhook_deliveries`},
		{name: "trigger disabled", mutate: `ALTER TABLE plugin_webhook_deliveries
			DISABLE TRIGGER plugin_webhook_deliveries_guard_084`},
		{name: "trigger misbound", mutate: `DROP TRIGGER plugin_webhook_deliveries_guard_084
			ON plugin_webhook_deliveries; CREATE TRIGGER plugin_webhook_deliveries_guard_084
			BEFORE UPDATE ON plugin_webhook_deliveries FOR EACH ROW
			EXECUTE FUNCTION guard_plugin_webhook_attempt_084()`},
		{name: "table owner", mutate: `ALTER TABLE plugin_webhook_deliveries OWNER TO pg_database_owner`},
		{name: "table ACL", mutate: `GRANT SELECT ON plugin_webhook_deliveries TO PUBLIC`},
		{name: "uncovered constraint", mutate: `ALTER TABLE plugin_webhook_dead_letters
			DROP CONSTRAINT plugin_webhook_dead_letters_message_id_084_check`},
		{name: "uncovered index", mutate: `DROP INDEX plugin_webhook_deliveries_retry_084`},
		{name: "broker identity index", mutate: `DROP INDEX plugin_webhook_deliveries_nats_identity_084`},
		{name: "uncovered column rename", mutate: `ALTER TABLE plugin_webhook_deliveries
			RENAME COLUMN nats_stream_sequence TO nats_stream_sequence_drifted`},
		{name: "delivery stream epoch", mutate: `ALTER TABLE plugin_webhook_deliveries
			RENAME COLUMN nats_stream_created_unix_nano TO nats_stream_created_unix_nano_drifted`},
		{name: "DLQ scan boundary", mutate: `ALTER TABLE plugin_webhook_dead_letters
			RENAME COLUMN reconcile_scan_boundary TO reconcile_scan_boundary_drifted`},
		{name: "DLQ terminal stream epoch", mutate: `ALTER TABLE plugin_webhook_dead_letters
			RENAME COLUMN nats_dlq_stream_created_unix_nano TO nats_dlq_stream_created_unix_nano_drifted`},
		{name: "DLQ terminal broker uniqueness", mutate: `ALTER TABLE plugin_webhook_dead_letters
			DROP CONSTRAINT plugin_webhook_dead_letters_broker_identity_084_key`},
		{name: "key projection column", mutate: `ALTER TABLE entitlement_signing_keyset_current_keys
			RENAME COLUMN verify_until TO verify_until_drifted`},
		{name: "key projection constraint", mutate: `ALTER TABLE entitlement_signing_keyset_current_keys
			DROP CONSTRAINT entitlement_signing_keyset_current_keys_windows_084`},
		{name: "DLQ phase default", mutate: `ALTER TABLE plugin_webhook_dead_letters
			ALTER COLUMN reconcile_phase SET DEFAULT 'publish_ready'`},
		{name: "audit recorded column", mutate: `ALTER TABLE audit_events
			RENAME COLUMN plugin_webhook_recorded_at TO plugin_webhook_recorded_at_drifted`},
		{name: "policy while RLS disabled", mutate: `CREATE POLICY plugin_webhook_policy_drift_084
			ON plugin_webhook_deliveries USING (true)`},
		{name: "composite type ACL", mutate: `REVOKE USAGE ON TYPE
			plugin_webhook_deliveries FROM PUBLIC`},
		{name: "composite type comment", mutate: `COMMENT ON TYPE
			plugin_webhook_deliveries IS 'drift'`},
		{name: "array type comment", mutate: `COMMENT ON TYPE
			_plugin_webhook_deliveries IS 'drift'`},
		{name: "trigger comment", mutate: `COMMENT ON TRIGGER
			plugin_webhook_deliveries_guard_084 ON plugin_webhook_deliveries IS 'drift'`},
		{name: "rewrite rule", mutate: `CREATE RULE plugin_webhook_rule_drift_084 AS
			ON UPDATE TO plugin_webhook_deliveries DO INSTEAD NOTHING`},
		{name: "schema extra ACL", mutate: `DO $do$ BEGIN EXECUTE format(
			'GRANT USAGE ON SCHEMA %I TO PUBLIC',current_schema()); END $do$`},
		{name: "attestation table ACL", mutate: `GRANT UPDATE ON
			plugin_webhook_runtime_attestation_keys TO PUBLIC`},
		{name: "attestation key column", mutate: `ALTER TABLE
			plugin_webhook_runtime_attestation_keys RENAME COLUMN key_id TO key_id_drifted`},
		{name: "attestation head trigger", mutate: `ALTER TABLE
			plugin_webhook_runtime_attestation_head DISABLE TRIGGER
			plugin_webhook_runtime_attestation_head_guard_084`},
		{name: "attestation guard function", mutate: `ALTER FUNCTION
			guard_plugin_webhook_runtime_attestation_head_084() COST 1`},
		{name: "attestation key index", mutate: `ALTER TABLE
			plugin_webhook_runtime_attestation_keys DROP CONSTRAINT
			plugin_webhook_runtime_attestation_keys_key_id_key`},
		{name: "outbox attestation column", mutate: `ALTER TABLE plugin_webhook_outbox
			RENAME COLUMN publication_attestation_signature TO publication_attestation_signature_drifted`},
		{name: "DLQ attestation column", mutate: `ALTER TABLE plugin_webhook_dead_letters
			RENAME COLUMN publication_attestation_signature TO publication_attestation_signature_drifted`},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 84)
			if _, err := pool.Exec(t.Context(), drift.mutate, pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			assertPluginWebhookDownP8401NoMutation084(t, pool)
		})
	}
}

func TestPluginWebhookControl084PublishLeaseTokenRED(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource, pluginWebhook084Now)
	tokenA := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,leased_at=clock_timestamp(),
			lease_expires_at=clock_timestamp()+interval '1 minute',publish_attempt=publish_attempt+1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, tokenA); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries
			SET status='queued',queued_at=clock_timestamp(),nats_stream_created_unix_nano=101,
				nats_stream_sequence=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, delivery); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_outbox
		SET status='published',lease_token=NULL,lease_expires_at=NULL,published_at=clock_timestamp()
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery)
	if err == nil {
		t.Fatal("RED: publication committed without proving the caller's current lease token")
	}
}

func TestPluginWebhookControl084UnsignedBrokerPublicationRED(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	token := uuid.New()
	err := pluginWebhookRoleExec084(t, pool, "open084_control_login", `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, token)
	assertPluginWebhookCode084(t, err, "P8408")
	if err = pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, token); err != nil {
		t.Fatal(err)
	}
	wrongAttestation := attestation
	wrongAttestation.privateKey = ed25519.NewKeyFromSeed(bytes084(ed25519.SeedSize, 0xe4))
	err = attestPluginWebhookOutboxResult084(t, pool, wrongAttestation, identity.tenantScope,
		resource.subscription, delivery, token, 101, 1)
	if err == nil {
		t.Fatal("RED: runtime database caller fabricated terminal publication without signed NATS evidence")
	}
	assertPluginWebhookCode084(t, err, "P8404")
}

func TestPluginWebhookControl084StaleDeadLetterReconcileRED(t *testing.T) {
	pool, identity, resource, delivery := setupPluginWebhookPendingDeadLetter084(t)
	var generationA uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT reconcile_generation
		FROM plugin_webhook_dead_letters WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND delivery_id=$3`, identity.tenantScope, resource.subscription,
		delivery).Scan(&generationA); err != nil {
		t.Fatal(err)
	}
	generationB := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool,
		`SELECT transition_plugin_webhook_dead_letter_reconcile_084(
			$1,$2,$3,$4,'uninitialized',NULL,NULL,NULL,NULL,
			$5,'publish_ready',101,0,NULL,NULL
		)`, identity.tenantScope, resource.subscription, delivery, generationA, generationB); err != nil {
		t.Fatal(err)
	}
	if err := pluginWebhookRuntimeExec084(t, pool,
		`SELECT transition_plugin_webhook_dead_letter_reconcile_084(
			$1,$2,$3,$4,'publish_ready',101,0,NULL,NULL,
			$4,'forward_scan',101,10,1,1
		)`, identity.tenantScope, resource.subscription, delivery, generationB); err != nil {
		t.Fatal(err)
	}
	err := pluginWebhookRuntimeExec084(t, pool,
		`SELECT transition_plugin_webhook_dead_letter_reconcile_084(
			$1,$2,$3,$4,'publish_ready',101,0,NULL,NULL,
			$5,'publish_ready',100,0,NULL,NULL
		)`, identity.tenantScope, resource.subscription, delivery, generationB, uuid.New())
	if err == nil {
		t.Fatal("RED: stale same-generation worker reset the DLQ stream epoch")
	}
	assertPluginWebhookCode084(t, err, "P8403")
	assertPluginWebhookDeadLetterReconcile084(t, pool, identity.tenantScope,
		resource.subscription, delivery, "pending", "forward_scan",
		text084("101"), text084("10"), text084("1"), text084("1"))
}

func TestPluginWebhookControl084TrustedRuntimeBoundary(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))

	for _, signature := range []string{
		"publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)",
		"transition_plugin_webhook_dead_letter_reconcile_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,uuid,text,numeric,numeric,numeric,numeric)",
		"acknowledge_plugin_webhook_dead_letter_084(uuid,uuid,uuid,uuid,text,numeric,numeric,numeric,numeric,text,text,numeric,text,numeric,text,bytea,bytea,numeric,numeric,text,bytea)",
	} {
		for role, want := range map[string]bool{
			"cdnca_control_app":            false,
			"cdnca_plugin_webhook_runtime": true,
		} {
			var got bool
			if err := pool.QueryRow(t.Context(), `SELECT has_function_privilege(
				to_regrole($1),to_regprocedure($2),'EXECUTE')`, role, signature).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("role %s execute %s=%t want=%t", role, signature, got, want)
			}
		}
		var securityDefiner, usesSessionUser, fixedSearchPath, ownerIsService bool
		if err := pool.QueryRow(t.Context(), `SELECT procedure.prosecdef,
			position('session_user' in procedure.prosrc) > 0,
			procedure.proconfig = ARRAY['search_path=pg_catalog'],
			owner.rolname IN ('cdnca_control_app','cdnca_plugin_webhook_runtime',
				'open084_control_login','open084_runtime_login')
			FROM pg_proc procedure JOIN pg_roles owner ON owner.oid=procedure.proowner
			WHERE procedure.oid=to_regprocedure($1)`, signature).Scan(&securityDefiner,
			&usesSessionUser, &fixedSearchPath, &ownerIsService); err != nil {
			t.Fatal(err)
		}
		if !securityDefiner || !usesSessionUser || !fixedSearchPath || ownerIsService {
			t.Fatalf("terminal function %s security=%t/session=%t/path=%t/service-owner=%t",
				signature, securityDefiner, usesSessionUser, fixedSearchPath, ownerIsService)
		}
	}

	err := pluginWebhookRoleExec084(t, pool, "open084_control_login", `UPDATE plugin_webhook_deliveries
		SET status='queued',queued_at=clock_timestamp(),nats_stream_created_unix_nano=1,
			nats_stream_sequence=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, delivery)
	assertPluginWebhookCode084(t, err, "P8408")
	for name, statement := range map[string]string{
		"set runtime role": `SET ROLE cdnca_plugin_webhook_runtime`,
		"disable trigger": `ALTER TABLE plugin_webhook_deliveries
			DISABLE TRIGGER plugin_webhook_deliveries_guard_084`,
		"disable trigger enforcement": `SET session_replication_role='replica'`,
		"call terminal function": `SELECT publish_plugin_webhook_outbox_084(
			NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`,
	} {
		t.Run(name, func(t *testing.T) {
			assertPluginWebhookCode084(t,
				pluginWebhookRoleExec084(t, pool, "open084_control_login", statement), "42501")
		})
	}
	publicationSignature := `publish_plugin_webhook_outbox_084(
		uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)`
	if _, err = pool.Exec(t.Context(), `GRANT EXECUTE ON FUNCTION `+publicationSignature+
		` TO open084_control_login`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `REVOKE EXECUTE ON FUNCTION `+
			publicationSignature+` FROM open084_control_login`, pgx.QueryExecModeSimpleProtocol)
	})
	err = pluginWebhookRoleExec084(t, pool, "open084_control_login", `SELECT
		publish_plugin_webhook_outbox_084(
		NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`)
	assertPluginWebhookCode084(t, err, "P8408")
	if _, err = pool.Exec(t.Context(), `REVOKE EXECUTE ON FUNCTION `+publicationSignature+
		` FROM open084_control_login`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
}

func TestPluginWebhookControl084EntitlementPhysicalDecisionRED(t *testing.T) {
	pool, identity := setupPluginWebhookEntitlementOnly084(t, true, 100, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer workerConn.Release()
	blockerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blockerConn.Release()
	workerTx, err := workerConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer workerTx.Rollback(context.Background())
	oldStart := pluginWebhookDatabaseTime084(t, workerTx)
	blockerTx, err := blockerConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blockerTx.Rollback(context.Background())
	if _, err = blockerTx.Exec(ctx, `SELECT 1 FROM control_installation_entitlement
		WHERE singleton=true FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	// Grace counts as usable and a stale revocation list stays LKG (user
	// decision 2026-10-21), so the physical boundary is the lease grace end.
	if _, err = blockerTx.Exec(ctx, `UPDATE entitlement_cached_leases
		SET status='grace',expires_at=$1::timestamptz+interval '1 microsecond',
			grace_until=$1::timestamptz+interval '1 microsecond'
		WHERE serial=1`, oldStart); err != nil {
		t.Fatal(err)
	}
	var workerPID, blockerPID int32
	if err = workerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
		t.Fatal(err)
	}
	if err = blockerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	resource := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	result := make(chan error, 1)
	go func() {
		result <- insertPluginWebhookSubscriptionFacts084(ctx, workerTx, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, resource.subscription, resource.secret, oldStart)
	}()
	waitForPluginWebhookBlock084(t, pool, workerPID, blockerPID)
	var releaseAt time.Time
	if err = blockerTx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&releaseAt); err != nil {
		t.Fatal(err)
	}
	if err = blockerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-result
	if err == nil {
		err = workerTx.Commit(ctx)
	}
	if err == nil {
		t.Fatal("RED: transaction-start entitlement decision committed after physical expiry")
	}
	assertPluginWebhookCode084(t, err, "P8408")
	if !releaseAt.After(oldStart) {
		t.Fatalf("entitlement release=%s not after old transaction=%s", releaseAt, oldStart)
	}
	assertPluginWebhookProtectedFacts084(t, pool, identity.tenantScope, 0)
}

func TestPluginWebhookControl084RateSharedPhysicalBoundaryRED(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	for range 5 {
		if err := insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
			resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer workerConn.Release()
	blockerConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blockerConn.Release()
	workerTx, err := workerConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer workerTx.Rollback(context.Background())
	oldStart := pluginWebhookDatabaseTime084(t, workerTx)
	blockerTx, err := blockerConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blockerTx.Rollback(context.Background())
	if _, err = blockerTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'plugin-webhook-rate-tenant:' || $1::uuid::text ||
		':plugin_webhook.test_delivery.create',84))`, identity.tenantScope); err != nil {
		t.Fatal(err)
	}
	if _, err = blockerTx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'plugin-webhook-rate-subscription:' || $1::uuid::text || ':' || $2::uuid::text ||
		':plugin_webhook.test_delivery.create',84))`, identity.tenantScope,
		resource.subscription); err != nil {
		t.Fatal(err)
	}
	if _, err = blockerTx.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	var agedID uuid.UUID
	if err = blockerTx.QueryRow(ctx, `SELECT id FROM plugin_webhook_rate_events
		WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.test_delivery.create'
		ORDER BY plugin_webhook_physical_recorded_at,id LIMIT 1`, identity.tenantScope,
		resource.subscription).Scan(&agedID); err != nil {
		t.Fatal(err)
	}
	if _, err = blockerTx.Exec(ctx, `UPDATE plugin_webhook_rate_events
		SET plugin_webhook_physical_recorded_at=$2::timestamptz-interval '1 minute'+interval '1 microsecond'
		WHERE id=$1`, agedID, oldStart); err != nil {
		t.Fatal(err)
	}
	var workerPID, blockerPID int32
	if err = workerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
		t.Fatal(err)
	}
	if err = blockerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- insertPluginWebhookTestRateInOpenTx084(ctx, t, workerTx, identity,
			resource.subscription, oldStart)
	}()
	waitForPluginWebhookBlock084(t, pool, workerPID, blockerPID)
	var releaseAt time.Time
	if err = blockerTx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&releaseAt); err != nil {
		t.Fatal(err)
	}
	if err = blockerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatalf("RED: transaction-start rate window rejected a physically admissible fact: %v", err)
	}
	if err = workerTx.Commit(ctx); err != nil {
		t.Fatalf("commit physically admissible rate fact: %v", err)
	}
	var marker, agedMarker time.Time
	var inWindow int
	if err = pool.QueryRow(ctx, `SELECT
		max(plugin_webhook_physical_recorded_at),
		max(plugin_webhook_physical_recorded_at) FILTER (WHERE id=$3),
		count(*) FILTER (WHERE plugin_webhook_physical_recorded_at > (
			SELECT max(plugin_webhook_physical_recorded_at) FROM plugin_webhook_rate_events
			WHERE tenant_scope_id=$1 AND subscription_id=$2
			  AND operation='plugin_webhook.test_delivery.create'
		)-interval '1 minute')
		FROM plugin_webhook_rate_events WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.test_delivery.create'`, identity.tenantScope,
		resource.subscription, agedID).Scan(&marker, &agedMarker, &inWindow); err != nil {
		t.Fatal(err)
	}
	if marker.Before(releaseAt) || agedMarker.After(marker.Add(-time.Minute)) || inWindow != 5 {
		t.Fatalf("physical rate marker/release/aged/count=%s/%s/%s/%d", marker,
			releaseAt, agedMarker, inWindow)
	}
	if err = insertPluginWebhookStandaloneRateOperation084(t, pool, identity,
		resource.subscription, "plugin_webhook.test_delivery.create", time.Time{}); err == nil {
		t.Fatal("sixth rate fact inside the physical window committed")
	} else {
		assertPluginWebhookCode084(t, err, "P8408")
	}
	reconnected, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	var reconnectMarker time.Time
	var reconnectCount int
	if err = reconnected.QueryRow(ctx, `SELECT max(plugin_webhook_physical_recorded_at),count(*)
		FILTER (WHERE plugin_webhook_physical_recorded_at > $3::timestamptz-interval '1 minute')
		FROM plugin_webhook_rate_events WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND operation='plugin_webhook.test_delivery.create'`, identity.tenantScope,
		resource.subscription, marker).Scan(&reconnectMarker, &reconnectCount); err != nil {
		t.Fatal(err)
	}
	if !reconnectMarker.Equal(marker) || reconnectCount != 5 {
		t.Fatalf("reconnect physical marker/count=%s/%d, want %s/5", reconnectMarker,
			reconnectCount, marker)
	}
}

func TestPluginWebhookControl084PublishLeaseTokenContract(t *testing.T) {
	pool, identity, resource := setupPluginWebhook084(t)
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	_, delivery := seedPluginWebhookPendingBundle084(t, pool, identity, resource,
		pluginWebhookDatabaseTime084(t, pool))
	tokenA := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '250 milliseconds',
			leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, tokenA); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='pending',lease_token=NULL,leased_at=NULL,lease_expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery); err != nil {
		t.Fatal(err)
	}
	tokenB := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			leased_at=NULL,publish_attempt=2
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, identity.tenantScope,
		resource.subscription, delivery, tokenB); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]uuid.UUID{
		"stale": tokenA,
		"wrong": uuid.New(),
		"nil":   uuid.Nil,
	} {
		t.Run(name, func(t *testing.T) {
			err := attestPluginWebhookOutboxResult084(t, pool, attestation,
				identity.tenantScope, resource.subscription, delivery, token, 101, 1)
			assertPluginWebhookCode084(t, err, "P8404")
		})
	}
	if err := attestPluginWebhookOutboxResult084(t, pool, attestation,
		identity.tenantScope, resource.subscription, delivery, tokenB, 101, 1); err != nil {
		t.Fatal(err)
	}
	reconnected, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	var status string
	var attempt int
	var tokenCleared bool
	if err := reconnected.QueryRow(t.Context(), `SELECT status,publish_attempt::int,lease_token IS NULL
		FROM plugin_webhook_outbox WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
		identity.tenantScope, resource.subscription, delivery).Scan(&status, &attempt, &tokenCleared); err != nil {
		t.Fatal(err)
	}
	if status != "published" || attempt != 2 || !tokenCleared {
		t.Fatalf("reconnected publication status/attempt/token=%s/%d/%t", status, attempt, tokenCleared)
	}
}

func TestPluginWebhookControl084DownGuards(t *testing.T) {
	t.Run("wrong head", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 84)
		if _, err := pool.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=83`); err != nil {
			t.Fatal(err)
		}
		script, err := controlmigrations.FS.ReadFile("084_plugin_webhook_control.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(t.Context(), string(script), pgx.QueryExecModeSimpleProtocol)
		assertPluginWebhookCode084(t, err, "P8401")
	})
	t.Run("RBAC drift", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 83)
		identity := seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			t.Fatal(err)
		}
		_, _ = seedPluginWebhookCustomRole084(t, pool, identity)
		assertPluginWebhookCode084(t, migrateVersionIsolated(t.Context(), pool, "down", 84), "P8401")
	})
	for _, check := range []struct {
		name   string
		mutate string
	}{
		{name: "entitlement function drift", mutate: `ALTER FUNCTION
			record_plugin_webhook_entitlement_decision_084() COST 1`},
		{name: "entitlement table ACL drift", mutate: `GRANT SELECT ON
			plugin_webhook_entitlement_decisions TO PUBLIC`},
		{name: "entitlement trigger drift", mutate: `DROP TRIGGER
			plugin_webhook_write_requests_entitlement_084 ON plugin_webhook_write_requests`},
	} {
		t.Run(check.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 84)
			if _, err := pool.Exec(t.Context(), check.mutate, pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			assertPluginWebhookCode084(t,
				migrateVersionIsolated(t.Context(), pool, "down", 84), "P8401")
			assertPluginWebhookHead084(t, pool, 84)
			assertPluginWebhookTables084(t, pool, true)
		})
	}
	for _, function := range []struct {
		name      string
		signature string
		body      string
	}{
		{
			name:      "effective permissions",
			signature: "custom_rbac_effective_permissions(uuid,uuid)",
			body: `CREATE OR REPLACE FUNCTION custom_rbac_effective_permissions(
				requested_scope_id uuid, requested_user_id uuid)
				RETURNS TABLE(permission_name text) LANGUAGE sql STABLE
				AS $$ SELECT 'plugin_webhooks.read'::text $$`,
		},
		{
			name:      "system role guard",
			signature: "guard_system_role_permission_mutation()",
			body: `CREATE OR REPLACE FUNCTION guard_system_role_permission_mutation()
				RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
		},
	} {
		for _, drift := range []struct {
			name   string
			mutate func(string) string
		}{
			{name: "body", mutate: func(string) string { return function.body }},
			{name: "attribute", mutate: func(signature string) string {
				return "ALTER FUNCTION " + signature + " COST 1"
			}},
			{name: "owner", mutate: func(signature string) string {
				return "ALTER FUNCTION " + signature + " OWNER TO pg_database_owner"
			}},
			{name: "ACL", mutate: func(signature string) string {
				return "REVOKE EXECUTE ON FUNCTION " + signature + " FROM PUBLIC"
			}},
		} {
			t.Run(function.name+" "+drift.name+" drift", func(t *testing.T) {
				pool := packageCommerceRBAC079Pool(t, 84)
				if _, err := pool.Exec(t.Context(), drift.mutate(function.signature),
					pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal(err)
				}
				assertPluginWebhookCode084(t,
					migrateVersionIsolated(t.Context(), pool, "down", 84), "P8401")
				assertPluginWebhookHead084(t, pool, 84)
				assertPluginWebhookTables084(t, pool, true)
			})
		}
	}
	requiredRelations := []string{
		"schema_migrations",
		"access_scopes",
		"audit_events",
		"tenants",
		"memberships",
		"users",
		"roles",
		"role_permissions",
		"role_assignments",
		"permissions",
		"custom_rbac_permission_catalog",
		"custom_roles",
		"custom_role_revisions",
		"custom_role_grants",
		"custom_role_grant_revocations",
		"plugin_webhook_rbac_catalog_additions_084",
		"plugin_webhook_rbac_grant_additions_084",
		"plugin_webhook_subscriptions",
		"plugin_webhook_secret_versions",
		"plugin_webhook_write_requests",
		"plugin_webhook_events",
		"plugin_webhook_deliveries",
		"plugin_webhook_outbox",
		"plugin_webhook_delivery_attempts",
		"plugin_webhook_dead_letters",
		"plugin_webhook_rate_events",
		"plugin_webhook_entitlement_decisions",
		"control_entitlement_revocation_lkg",
		"control_entitlement_revoked_serials",
		"entitlement_signing_keyset_current_keys",
		"plugin_webhook_runtime_attestation_keys",
		"plugin_webhook_runtime_attestation_head",
		"control_installation_entitlement",
		"entitlement_cached_leases",
	}
	for _, relation := range requiredRelations {
		for _, mutation := range []string{"missing", "renamed"} {
			t.Run(mutation+" "+relation, func(t *testing.T) {
				pool := packageCommerceRBAC079Pool(t, 84)
				original := pgx.Identifier{relation}.Sanitize()
				probe := relation
				var statement string
				if mutation == "missing" {
					statement = "DROP TABLE " + original + " CASCADE"
				} else {
					probe = relation + "_drift"
					statement = "ALTER TABLE " + original + " RENAME TO " +
						pgx.Identifier{probe}.Sanitize()
				}
				if _, err := pool.Exec(t.Context(), statement, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal(err)
				}
				script, err := controlmigrations.FS.ReadFile("084_plugin_webhook_control.down.sql")
				if err != nil {
					t.Fatal(err)
				}
				_, err = pool.Exec(t.Context(), string(script), pgx.QueryExecModeSimpleProtocol)
				assertPluginWebhookCode084(t, err, "P8401")
				var sentinelFunction, driftedTable bool
				if err := pool.QueryRow(t.Context(), `SELECT
					to_regprocedure('publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)') IS NOT NULL,
					to_regclass($1) IS NOT NULL`, probe).Scan(&sentinelFunction, &driftedTable); err != nil {
					t.Fatal(err)
				}
				if !sentinelFunction || (mutation == "renamed" && !driftedTable) {
					t.Fatalf("down partially mutated head: sentinel=%t drifted_table=%t",
						sentinelFunction, driftedTable)
				}
				if relation != "schema_migrations" {
					assertPluginWebhookHead084(t, pool, 84)
				} else if mutation == "renamed" {
					var count, minimum, maximum int64
					if err := pool.QueryRow(t.Context(), `SELECT count(*),min(version),max(version)
						FROM schema_migrations_drift`).Scan(&count, &minimum, &maximum); err != nil {
						t.Fatal(err)
					}
					if count != 84 || minimum != 1 || maximum != 84 {
						t.Fatalf("renamed ledger count/min/max=%d/%d/%d", count, minimum, maximum)
					}
				}
			})
		}
	}
}

func insertPluginWebhookIncompleteRequest084(t *testing.T, pool *pgxpool.Pool,
	identity pluginWebhookIdentity084, actorScope, actorUser uuid.UUID, operation string,
	subscription, delivery, rotation uuid.UUID, now time.Time,
) (uuid.UUID, string, error) {
	t.Helper()
	requestID := uuid.New()
	key := "pending-" + operation + "-" + requestID.String()
	digest := sha256.Sum256([]byte(key))
	var deliveryValue, rotationValue any
	if delivery != uuid.Nil {
		deliveryValue = delivery
	}
	if rotation != uuid.Nil {
		rotationValue = rotation
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,delivery_id,rotation_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, requestID, identity.tenantScope,
		actorScope, actorUser, operation, key, digest[:], subscription, deliveryValue, rotationValue, now)
	return requestID, key, err
}

func completePluginWebhookIncompleteRequest084(t *testing.T, pool *pgxpool.Pool,
	identity pluginWebhookIdentity084, requestID uuid.UUID, key string, actorScope, actorUser uuid.UUID,
	operation string, subscription, delivery, rotation uuid.UUID, now time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	completedAt := pluginWebhookDatabaseTime084(t, tx)
	resourceType, resourceID := "plugin_webhook_subscription", subscription.String()
	if operation == "plugin_webhook.test_delivery.create" || operation == "plugin_webhook.delivery.replay" {
		resourceType, resourceID = "plugin_webhook_delivery", delivery.String()
	} else if operation == "plugin_webhook.secret.rotate" || operation == "plugin_webhook.secret.activate" {
		resourceType, resourceID = "plugin_webhook_secret_version", rotation.String()
	}
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, identity.tenantScope,
		actorScope, actorUser, operation, "success", "accepted", resourceType, resourceID, key, completedAt)
	if err != nil {
		return err
	}
	switch operation {
	case "plugin_webhook.subscription.create":
		var createdAt time.Time
		if err := tx.QueryRow(t.Context(), `SELECT created_at FROM plugin_webhook_write_requests
			WHERE id=$1`, requestID).Scan(&createdAt); err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests SET response_status=201,
			response_body=jsonb_build_object('subscription_id',subscription_id::text),
			receipt_wrapping_key_id='plugin-webhook-kek-v1',receipt_aad_sha256=$2,
			receipt_nonce=$3,receipt_ciphertext=$4,receipt_expires_at=$5,audit_event_id=$6,completed_at=$7
			WHERE id=$1`, requestID, pluginWebhookReceiptAAD084(identity.tenantScope, actorScope,
			actorUser, key, operation, subscription), bytes084(12, 0xc5), bytes084(48, 0xc6),
			createdAt.Add(24*time.Hour), auditID, completedAt)
	case "plugin_webhook.secret.rotate":
		var createdAt time.Time
		if err := tx.QueryRow(t.Context(), `SELECT created_at FROM plugin_webhook_write_requests
			WHERE id=$1`, requestID).Scan(&createdAt); err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests SET response_status=201,
			response_body=jsonb_build_object('subscription_id',subscription_id::text,
			'rotation_id',rotation_id::text),receipt_wrapping_key_id='plugin-webhook-kek-v1',
			receipt_aad_sha256=$2,receipt_nonce=$3,receipt_ciphertext=$4,receipt_expires_at=$5,
			audit_event_id=$6,completed_at=$7 WHERE id=$1`, requestID,
			pluginWebhookReceiptAAD084(identity.tenantScope, actorScope, actorUser, key, operation, rotation),
			bytes084(12, 0xc7), bytes084(48, 0xc8), createdAt.Add(24*time.Hour), auditID, completedAt)
	case "plugin_webhook.test_delivery.create", "plugin_webhook.delivery.replay":
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests SET response_status=202,
			response_body=jsonb_build_object('subscription_id',subscription_id::text,
			'delivery_id',delivery_id::text),audit_event_id=$2,completed_at=$3 WHERE id=$1`,
			requestID, auditID, completedAt)
	case "plugin_webhook.secret.activate":
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests SET response_status=200,
			response_body=jsonb_build_object('subscription_id',subscription_id::text,
			'rotation_id',rotation_id::text),audit_event_id=$2,completed_at=$3 WHERE id=$1`,
			requestID, auditID, completedAt)
	case "plugin_webhook.subscription.revoke":
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests SET response_status=200,
			response_body=jsonb_build_object('subscription_id',subscription_id::text),
			audit_event_id=$2,completed_at=$3 WHERE id=$1`, requestID, auditID, completedAt)
	}
	if err != nil {
		return err
	}
	if operation == "plugin_webhook.subscription.revoke" {
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
				revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, subscription, completedAt); err != nil {
			return err
		}
	}
	return tx.Commit(t.Context())
}

func revokePluginWebhookWithIncompleteRequest084(t *testing.T, pool *pgxpool.Pool,
	identity pluginWebhookIdentity084, resource pluginWebhookResource084, now time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	requestID := uuid.New()
	key := "incomplete-revoke-" + requestID.String()
	digest := sha256.Sum256([]byte(key))
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,created_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.revoke',$4,$5,$6,$7)`, requestID,
		identity.tenantScope, identity.ownerUser, key, digest[:], resource.subscription, now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription, now); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookTargetBundleResult084(t *testing.T, operation, targetURL, targetHost,
	targetPath string,
) error {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	now := pluginWebhook084Now.Add(time.Hour)
	var eventID, replayOf uuid.UUID
	var body, digest []byte
	if operation == "plugin_webhook.delivery.replay" {
		replayOf = seedPluginWebhookDelivery084(t, pool, identity, resource, now)
		completePluginWebhookDelivery084(t, pool, identity, resource, replayOf, now.Add(time.Minute))
		if err := pool.QueryRow(t.Context(), `SELECT event.id,event.canonical_body,event.body_sha256
			FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
			  ON event.tenant_scope_id=delivery.tenant_scope_id
			 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
			WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
			identity.tenantScope, resource.subscription, replayOf).Scan(&eventID, &body, &digest); err != nil {
			return err
		}
	} else {
		eventID = uuid.Must(uuid.NewV7())
		body = pluginWebhookCanonicalBody084(t, identity, resource, eventID, nil, 1, now)
		hash := sha256.Sum256(body)
		digest = hash[:]
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if operation != "plugin_webhook.delivery.replay" {
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, eventID, nil, body, digest, now); err != nil {
			return err
		}
	}
	deliveryID := uuid.New()
	var revision string
	if err := tx.QueryRow(t.Context(), `SELECT revision::text FROM plugin_webhook_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription).Scan(&revision); err != nil {
		return err
	}
	var replayValue any
	if replayOf != uuid.Nil {
		replayValue = replayOf
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_deliveries(
		id,tenant_scope_id,subscription_id,event_id,actor_scope_id,actor_user_id,replay_of,
		delivery_idempotency_key,target_url,target_host,target_path,status,subscription_revision,
		attempt_count,created_at
	) VALUES($1,$2,$3,$4,$2,$5,$6,$7,$8,$9,$10,'pending',$11,0,$12)`, deliveryID,
		identity.tenantScope, resource.subscription, eventID, identity.ownerUser, replayValue,
		"plugin-webhook-v2-"+hexDigest084(deliveryID.String()), targetURL, targetHost, targetPath,
		revision, now); err != nil {
		return err
	}
	if err := insertPluginWebhookOutbox084(t, tx, identity, resource, eventID, deliveryID, body, digest,
		"plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()), now); err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.ownerUser, operation, resource.subscription, deliveryID, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func activatePluginWebhookAtResult084(t *testing.T, pool *pgxpool.Pool,
	identity pluginWebhookIdentity084, resource pluginWebhookResource084, pending uuid.UUID,
	requestAt, auditAt, activationAt time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	requestID := uuid.New()
	key := "activation-time-" + requestID.String()
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.activate", "success", "accepted",
		"plugin_webhook_secret_version", pending.String(), key, auditAt)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(key))
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,rotation_id,response_status,response_body,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.secret.activate',$4,$5,$6,$7,200,
		jsonb_build_object('subscription_id',$6::uuid::text,'rotation_id',$7::uuid::text),$8,$9,$9)`,
		requestID, identity.tenantScope, identity.ownerUser, key, digest[:], resource.subscription,
		pending, auditID, requestAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, resource.secret, activationAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, identity.tenantScope,
		resource.subscription, pending, activationAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope,
		resource.subscription, pending, activationAt); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookSavepointBundle084(t *testing.T, operation string, rollbackNested bool) error {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		return err
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	if operation == "create" {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(t.Context())
		nested, err := tx.Begin(t.Context())
		if err != nil {
			return err
		}
		resource := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
		if err := insertPluginWebhookSubscriptionFacts084(t.Context(), nested, identity.tenantScope,
			identity.tenantScope, identity.ownerUser, resource.subscription, resource.secret,
			pluginWebhook084Now); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
		if err := nested.Commit(t.Context()); err != nil {
			return err
		}
		return tx.Commit(t.Context())
	}
	resource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now)
	if operation == "replay" {
		original := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now.Add(time.Hour))
		completePluginWebhookDelivery084(t, pool, identity, resource, original,
			pluginWebhook084Now.Add(2*time.Hour))
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	nested, err := tx.Begin(t.Context())
	if err != nil {
		return err
	}
	now := pluginWebhookDatabaseTime084(t, tx)
	switch operation {
	case "rotate":
		pending := uuid.New()
		if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, nested, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.rotate",
			resource.subscription, pending, now); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
		if _, err := nested.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
			id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
			wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
		) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
			pending, identity.tenantScope, resource.subscription, identity.ownerUser,
			pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 2,
				"plugin-webhook-kek-v1"), bytes084(12, 0xca), bytes084(48, 0xcb), bytes084(32, 0xcc),
			now, now.Add(24*time.Hour)); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
	case "test":
		if err := insertPluginWebhookSavepointDelivery084(t, nested, identity, resource, uuid.Nil,
			"plugin_webhook.test_delivery.create", now); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
	case "replay":
		var original uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT id FROM plugin_webhook_deliveries
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND status='delivered'
			ORDER BY created_at DESC LIMIT 1`, identity.tenantScope, resource.subscription).Scan(&original); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
		if err := insertPluginWebhookSavepointDelivery084(t, nested, identity, resource, original,
			"plugin_webhook.delivery.replay", now); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
	case "revoke":
		if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, nested, identity,
			identity.tenantScope, identity.ownerUser, "plugin_webhook.subscription.revoke",
			resource.subscription, uuid.Nil, now); err != nil {
			_ = nested.Rollback(t.Context())
			return err
		}
	}
	if rollbackNested {
		if err := nested.Rollback(t.Context()); err != nil {
			return err
		}
	} else if err := nested.Commit(t.Context()); err != nil {
		return err
	}
	if operation == "revoke" {
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
				revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
			WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription, now); err != nil {
			return err
		}
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookSavepointDelivery084(t *testing.T, tx pgx.Tx,
	identity pluginWebhookIdentity084, resource pluginWebhookResource084, replayOf uuid.UUID,
	operation string, now time.Time,
) error {
	t.Helper()
	var eventID uuid.UUID
	var body, digest []byte
	if replayOf != uuid.Nil {
		if err := tx.QueryRow(t.Context(), `SELECT event.id,event.canonical_body,event.body_sha256
			FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
			  ON event.tenant_scope_id=delivery.tenant_scope_id
			 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
			WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
			identity.tenantScope, resource.subscription, replayOf).Scan(&eventID, &body, &digest); err != nil {
			return err
		}
	} else {
		eventID = uuid.Must(uuid.NewV7())
		body = pluginWebhookCanonicalBody084(t, identity, resource, eventID, nil, 1, now)
		hash := sha256.Sum256(body)
		digest = hash[:]
		if err := insertPluginWebhookEvent084(t, tx, identity, resource, eventID, nil, body, digest, now); err != nil {
			return err
		}
	}
	deliveryID, err := insertPluginWebhookDeliveryRow084(t, tx, identity, resource, eventID, replayOf, now)
	if err != nil {
		return err
	}
	if err := insertPluginWebhookOutbox084(t, tx, identity, resource, eventID, deliveryID, body, digest,
		"plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()), now); err != nil {
		return err
	}
	return insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.ownerUser, operation, resource.subscription, deliveryID, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true})
}

func assertPluginWebhookXID8Contract084(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var xid8Columns int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE column_name='plugin_webhook_xact_id' AND udt_name='xid8'
		  AND table_schema=current_schema() AND table_name = ANY($1::text[])`, []string{
		"audit_events", "plugin_webhook_subscriptions", "plugin_webhook_secret_versions",
		"plugin_webhook_write_requests", "plugin_webhook_events", "plugin_webhook_deliveries",
		"plugin_webhook_delivery_attempts", "plugin_webhook_dead_letters",
		"plugin_webhook_rate_events",
	}).Scan(&xid8Columns); err != nil {
		t.Fatal(err)
	}
	if xid8Columns != 9 {
		t.Fatalf("xid8 transaction marker columns=%d want=9", xid8Columns)
	}
	var sources string
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(pg_get_functiondef(oid), E'\n')
		FROM pg_proc WHERE proname LIKE '%plugin_webhook%084'`).Scan(&sources); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sources, "xmin::text") || strings.Contains(sources, "pg_current_xact_id()::text") {
		t.Fatal("plugin webhook current-transaction contract still narrows or stringifies xid identity")
	}
	if !strings.Contains(sources, "plugin_webhook_xact_id") ||
		!strings.Contains(sources, "pg_current_xact_id()") {
		t.Fatal("plugin webhook validators do not use the explicit xid8 top-level transaction marker")
	}
}

func insertPluginWebhookStandaloneCompletedRequest084(t *testing.T, operation string, status int) error {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	auditID := appendPluginWebhookAudit084(t, pool, identity.tenantScope, identity.tenantScope,
		identity.ownerUser, operation, "success", "accepted", pluginWebhook084Now.Add(time.Hour))
	requestID := uuid.New()
	key := "standalone-" + requestID.String()
	digest := sha256.Sum256([]byte(key))
	delivery, rotation := uuid.New(), uuid.New()
	switch operation {
	case "plugin_webhook.subscription.create":
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,response_status,response_body,receipt_wrapping_key_id,receipt_aad_sha256,
			receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,created_at,completed_at
		) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,jsonb_build_object('subscription_id',$7::uuid::text),
			'plugin-webhook-kek-v1',$9,$10,$11,$12,$13,$14,$14)`, requestID, identity.tenantScope,
			identity.ownerUser, operation, key, digest[:], resource.subscription, status,
			pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
				key, operation, resource.subscription), bytes084(12, 0xe3), bytes084(48, 0xe4),
			pluginWebhook084Now.Add(25*time.Hour), auditID, pluginWebhook084Now.Add(time.Hour))
		return err
	case "plugin_webhook.test_delivery.create", "plugin_webhook.delivery.replay":
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,delivery_id,response_status,response_body,audit_event_id,created_at,completed_at
		) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,
			jsonb_build_object('subscription_id',$7::uuid::text,'delivery_id',$8::uuid::text),$10,$11,$11)`,
			requestID, identity.tenantScope, identity.ownerUser, operation, key, digest[:],
			resource.subscription, delivery, status, auditID, pluginWebhook084Now.Add(time.Hour))
		return err
	case "plugin_webhook.secret.rotate":
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,rotation_id,response_status,response_body,receipt_wrapping_key_id,
			receipt_aad_sha256,receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,
			created_at,completed_at
		) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,
			jsonb_build_object('subscription_id',$7::uuid::text,'rotation_id',$8::uuid::text),
			'plugin-webhook-kek-v1',$10,$11,$12,$13,$14,$15,$15)`, requestID, identity.tenantScope,
			identity.ownerUser, operation, key, digest[:], resource.subscription, rotation, status,
			pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
				key, operation, rotation), bytes084(12, 0xe5), bytes084(48, 0xe6),
			pluginWebhook084Now.Add(25*time.Hour), auditID, pluginWebhook084Now.Add(time.Hour))
		return err
	case "plugin_webhook.secret.activate":
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,rotation_id,response_status,response_body,audit_event_id,created_at,completed_at
		) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,
			jsonb_build_object('subscription_id',$7::uuid::text,'rotation_id',$8::uuid::text),$10,$11,$11)`,
			requestID, identity.tenantScope, identity.ownerUser, operation, key, digest[:],
			resource.subscription, rotation, status, auditID, pluginWebhook084Now.Add(time.Hour))
		return err
	default:
		_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,response_status,response_body,audit_event_id,created_at,completed_at
		) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,jsonb_build_object('subscription_id',$7::uuid::text),
			$9,$10,$10)`, requestID, identity.tenantScope, identity.ownerUser, operation, key,
			digest[:], resource.subscription, status, auditID, pluginWebhook084Now.Add(time.Hour))
		return err
	}
}

func insertPluginWebhookSecondNonReplayDelivery084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, eventID uuid.UUID, now time.Time,
) error {
	t.Helper()
	var body, digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_body,body_sha256 FROM plugin_webhook_events
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, eventID).Scan(&body, &digest); err != nil {
		return err
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	delivery, err := insertPluginWebhookDeliveryRow084(t, tx, fixture, resource, eventID, uuid.Nil, now)
	if err != nil {
		return err
	}
	if err := insertPluginWebhookOutbox084(t, tx, fixture, resource, eventID, delivery, body, digest,
		"plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), now); err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.test_delivery.create",
		resource.subscription, delivery, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookRotationBundleResult084(t *testing.T, withRate bool, rateActor uuid.UUID,
	rateAt time.Time,
) error {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	pending := uuid.New()
	now := pluginWebhook084Now.Add(time.Hour)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	requestID := uuid.New()
	key := "plugin_webhook.secret.rotate-" + requestID.String()
	requestAudit, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.secret.rotate", "success", "accepted",
		"plugin_webhook_secret_version", pending.String(), key, now)
	if err != nil {
		return err
	}
	requestDigest := sha256.Sum256([]byte(key))
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,rotation_id,response_status,response_body,receipt_wrapping_key_id,
		receipt_aad_sha256,receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,
		created_at,completed_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.secret.rotate',$4,$5,$6,$7,201,
		jsonb_build_object('subscription_id',$6::uuid::text,'rotation_id',$7::uuid::text),
		'plugin-webhook-kek-v1',$8,$9,$10,$11,$12,$13,$13)`, requestID, identity.tenantScope,
		identity.ownerUser, key, requestDigest[:], resource.subscription, pending,
		pluginWebhookReceiptAAD084(identity.tenantScope, identity.tenantScope, identity.ownerUser,
			key, "plugin_webhook.secret.rotate", pending), bytes084(12, 0xee), bytes084(48, 0xef),
		now.Add(24*time.Hour), requestAudit, now); err != nil {
		return err
	}
	if withRate {
		actor := identity.ownerUser
		if rateActor != uuid.Nil {
			actor = identity.adminUser
		}
		rateID := uuid.New()
		rateAudit, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, identity.tenantScope,
			identity.tenantScope, actor, "plugin_webhook.secret.rotate", "success", "accepted",
			"plugin_webhook_subscription", resource.subscription.String(), "rate-"+rateID.String(), rateAt)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_rate_events(
			id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
			reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,$3,$2,$4,'plugin_webhook.secret.rotate','allowed','accepted',$5,$6)`,
			rateID, identity.tenantScope, resource.subscription, actor, rateAudit, rateAt); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
		pending, identity.tenantScope, resource.subscription, identity.ownerUser,
		pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, pending, 2,
			"plugin-webhook-kek-v1"), bytes084(12, 0xe7), bytes084(48, 0xe8), bytes084(32, 0xe9),
		now, now.Add(24*time.Hour)); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func startPluginWebhookAttemptResult084(t *testing.T, pool *pgxpool.Pool, claim uuid.UUID,
	wrongDigest bool, now time.Time,
) error {
	t.Helper()
	if wrongDigest {
		_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='started',started_at=$2,request_sha256=$3 WHERE claim_token=$1`, claim, now,
			bytes084(32, 0xea))
		return err
	}
	_, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts attempt
		SET status='started',started_at=$2,request_sha256=event.body_sha256
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
		WHERE attempt.claim_token=$1 AND delivery.tenant_scope_id=attempt.tenant_scope_id
		  AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id`, claim, now)
	return err
}

func insertPluginWebhookSplitCreateActorResult084(t *testing.T) error {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		return err
	}
	resource := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_subscriptions(
		id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,
		event_types,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,
		created_at,updated_at
	) VALUES($1,$2,$2,$3,'split actor','https://hooks.example.com/v1/events','hooks.example.com',
		'/v1/events',ARRAY['io.cdnca.webhook.v1.test'],$4,'active',1,0,0,$5,$5)`,
		resource.subscription, identity.tenantScope, identity.ownerUser, resource.secret,
		pluginWebhook084Now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,activated_at
	) VALUES($1,$1,$2,$3,$2,$4,1,'active','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$9)`,
		resource.secret, identity.tenantScope, resource.subscription, identity.adminUser,
		pluginWebhookSecretAAD084(identity.tenantScope, resource.subscription, resource.secret, 1,
			"plugin-webhook-kek-v1"), bytes084(12, 0xeb), bytes084(48, 0xec), bytes084(32, 0xed),
		pluginWebhook084Now); err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, identity,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.subscription.create",
		resource.subscription, uuid.Nil, pluginWebhook084Now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func revokePluginWebhookWithAuditDriftResult084(t *testing.T, drift string) error {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	requestID := uuid.New()
	key := "audit-drift-" + requestID.String()
	resourceType, resourceID, auditRequestID := "plugin_webhook_subscription",
		resource.subscription.String(), key
	switch drift {
	case "resource type":
		resourceType = "plugin_webhook_delivery"
	case "resource id":
		resourceID = uuid.NewString()
	case "request id":
		auditRequestID = "unrelated-" + requestID.String()
	}
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, "plugin_webhook.subscription.revoke", "success",
		"accepted", resourceType, resourceID, auditRequestID, pluginWebhook084Now.Add(time.Hour))
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(key))
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,response_status,response_body,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.revoke',$4,$5,$6,200,
		jsonb_build_object('subscription_id',$6::uuid::text),$7,$8,$8)`, requestID,
		identity.tenantScope, identity.ownerUser, key, digest[:], resource.subscription, auditID,
		pluginWebhook084Now.Add(time.Hour)); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
		WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, resource.subscription,
		pluginWebhook084Now.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func appendPluginWebhookAuditIdentityTx084(ctx context.Context, tx pgx.Tx, targetScope, actorScope,
	actorUser uuid.UUID, action, result, reason, resourceType, resourceID, requestID string, now time.Time,
) (uuid.UUID, error) {
	var position int64
	var previous []byte
	err := tx.QueryRow(ctx, `SELECT stream_position,event_hash FROM audit_events
		WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, targetScope).Scan(&position, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		position, previous, err = 0, nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	hash := sha256.Sum256([]byte(id.String()))
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,
		jsonb_build_object('actor_scope_id',$10::uuid::text,'target_scope_id',$2::uuid::text,
			'operation',$5::text,'reason',$11::text),$12,$13,$14)`, id, targetScope, position+1,
		actorUser, action, resourceType, resourceID, requestID, result, actorScope, reason,
		previous, hash[:], now)
	return id, err
}

func setupPluginWebhook084(t *testing.T) (*pgxpool.Pool, pluginWebhookIdentity084, pluginWebhookResource084) {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	resource := insertPluginWebhookSubscription084(t, pool, identity.tenantScope,
		identity.tenantScope, identity.ownerUser, pluginWebhook084Now)
	return pool, identity, resource
}

func setupPluginWebhookEntitlementOnly084(t *testing.T, feature bool, quota int64,
	revoked []uint64,
) (*pgxpool.Pool, pluginWebhookIdentity084) {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 83)
	identity := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		t.Fatal(err)
	}
	seedPluginWebhookEntitlement084(t, pool, feature, quota, revoked)
	return pool, identity
}

func assertPluginWebhookProtectedFacts084(t *testing.T, pool *pgxpool.Pool,
	tenantScope uuid.UUID, wantSubscriptions int,
) {
	t.Helper()
	var subscriptions, secrets, requests, rates, decisions int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1),
		(SELECT count(*) FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1),
		(SELECT count(*) FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1),
		(SELECT count(*) FROM plugin_webhook_rate_events WHERE tenant_scope_id=$1),
		(SELECT count(*) FROM plugin_webhook_entitlement_decisions WHERE tenant_scope_id=$1)`,
		tenantScope).Scan(&subscriptions, &secrets, &requests, &rates, &decisions); err != nil {
		t.Fatal(err)
	}
	if subscriptions != wantSubscriptions || secrets != wantSubscriptions ||
		requests != wantSubscriptions || rates != wantSubscriptions || decisions != wantSubscriptions {
		t.Fatalf("protected facts subscriptions/secrets/requests/rates/decisions=%d/%d/%d/%d/%d want=%d",
			subscriptions, secrets, requests, rates, decisions, wantSubscriptions)
	}
}

func pluginWebhookCanonicalBody084(t *testing.T, fixture pluginWebhookIdentity084,
	resource pluginWebhookResource084, eventID uuid.UUID, traceparent *string, sequence uint64, now time.Time,
) []byte {
	t.Helper()
	body, err := json.Marshal(pluginWebhookCanonicalEvent084{
		SpecVersion: "1.0", ID: eventID, Source: "/control-plane/plugin-webhooks",
		Type: "io.cdnca.webhook.v1.test", Subject: "webhook_subscription/" + resource.subscription.String(),
		Time: now.UTC(), DataContentType: "application/json",
		DataSchema: "https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",
		TenantID:   fixture.tenantID, RequestID: "request-084", Traceparent: traceparent, Sequence: sequence,
		Data: pluginWebhookEventData084{SubscriptionID: resource.subscription, Test: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func pluginWebhookAuthoritativeBody084(fixture pluginWebhookIdentity084, resource pluginWebhookResource084,
	eventID uuid.UUID, traceparent *string, sequence uint64, now time.Time,
) []byte {
	trace := ""
	if traceparent != nil {
		trace = `,"traceparent":` + strconv.Quote(*traceparent)
	}
	return []byte(`{"specversion":"1.0","id":` + strconv.Quote(eventID.String()) +
		`,"source":"/control-plane/plugin-webhooks","type":"io.cdnca.webhook.v1.test","subject":` +
		strconv.Quote("webhook_subscription/"+resource.subscription.String()) + `,"time":` +
		strconv.Quote(now.UTC().Format(time.RFC3339Nano)) + `,"datacontenttype":"application/json",` +
		`"dataschema":"https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json",` +
		`"tenant_id":` + strconv.Quote(fixture.tenantID.String()) + `,"request_id":"request-084"` + trace +
		`,"sequence":` + strconv.FormatUint(sequence, 10) + `,"data":{"subscription_id":` +
		strconv.Quote(resource.subscription.String()) + `,"test":true}}`)
}

func insertPluginWebhookEvent084(t *testing.T, pool pluginWebhookDB084, fixture pluginWebhookIdentity084,
	resource pluginWebhookResource084, eventID uuid.UUID, traceparent *string, body, digest []byte, now time.Time,
) error {
	t.Helper()
	var sequence string
	if err := pool.QueryRow(t.Context(), `SELECT (event_sequence+1)::text
		FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2`,
		fixture.tenantScope, resource.subscription).Scan(&sequence); err != nil {
		return err
	}
	if body == nil {
		parsedSequence, err := strconv.ParseUint(sequence, 10, 64)
		if err != nil {
			return err
		}
		body = pluginWebhookCanonicalBody084(t, fixture, resource, eventID, traceparent, parsedSequence, now)
	}
	if digest == nil {
		calculated := sha256.Sum256(body)
		digest = calculated[:]
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,sequence,event_type,
		subject,request_id,traceparent,event_time,data,canonical_body,body_sha256,created_at
	) VALUES($1,$2,$3,$2,$4,$5,'io.cdnca.webhook.v1.test',$6,'request-084',$7,$8,
		jsonb_build_object('subscription_id',$3::uuid::text,'test',true),$9,$10,$8)`,
		eventID, fixture.tenantScope, resource.subscription, fixture.ownerUser, sequence,
		"webhook_subscription/"+resource.subscription.String(), traceparent, now, body, digest)
	return err
}

func insertPluginWebhookCommandResult084(t *testing.T, operation string,
	facts pluginWebhookCommandFacts084,
) error {
	t.Helper()
	var pool *pgxpool.Pool
	var fixture pluginWebhookIdentity084
	var resource pluginWebhookResource084
	if operation == "plugin_webhook.subscription.create" {
		pool = packageCommerceRBAC079Pool(t, 83)
		fixture = seedPluginWebhookIdentity084(t, pool)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
			return err
		}
		seedPluginWebhookEntitlement084(t, pool, true, 100, nil)
	} else {
		pool, fixture, resource = setupPluginWebhook084(t)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if operation == "plugin_webhook.subscription.create" {
		resource, err = insertPluginWebhookRawSubscriptionRowsTx084(t.Context(), tx, fixture,
			fixture.tenantScope, fixture.ownerUser, 1, 0, 0, "active", pluginWebhook084Now)
		if err != nil {
			return err
		}
		if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
			fixture.tenantScope, fixture.ownerUser, operation, resource.subscription, uuid.Nil,
			pluginWebhook084Now, facts); err != nil {
			return err
		}
		return tx.Commit(t.Context())
	}

	var eventID uuid.UUID
	var replayOf uuid.UUID
	var body, digest []byte
	if operation == "plugin_webhook.delivery.replay" {
		replayOf = seedPluginWebhookDelivery084(t, pool, fixture, resource, pluginWebhook084Now)
		completePluginWebhookDelivery084(t, pool, fixture, resource, replayOf,
			pluginWebhook084Now.Add(time.Minute))
		if err := pool.QueryRow(t.Context(), `SELECT event.id,event.canonical_body,event.body_sha256
			FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
			  ON event.tenant_scope_id=delivery.tenant_scope_id
			 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
			WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
			fixture.tenantScope, resource.subscription, replayOf).Scan(&eventID, &body, &digest); err != nil {
			return err
		}
	} else {
		eventID = uuid.Must(uuid.NewV7())
		body = pluginWebhookCanonicalBody084(t, fixture, resource, eventID, nil, 1, pluginWebhook084Now)
		calculated := sha256.Sum256(body)
		digest = calculated[:]
		if err := insertPluginWebhookEvent084(t, tx, fixture, resource, eventID, nil, body, digest,
			pluginWebhook084Now); err != nil {
			return err
		}
	}
	deliveryID, err := insertPluginWebhookDeliveryRow084(t, tx, fixture, resource, eventID,
		replayOf, pluginWebhook084Now)
	if err != nil {
		return err
	}
	if err := insertPluginWebhookOutbox084(t, tx, fixture, resource, eventID, deliveryID, body,
		digest, "plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()),
		pluginWebhook084Now); err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, operation, resource.subscription, deliveryID,
		pluginWebhook084Now, facts); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookCommandFactsTx084(ctx context.Context, t *testing.T, tx pgx.Tx,
	fixture pluginWebhookIdentity084, actorScope, actorUser uuid.UUID, operation string,
	subscription, delivery uuid.UUID, now time.Time, facts pluginWebhookCommandFacts084,
) error {
	t.Helper()
	recordedAt := pluginWebhookDatabaseTime084(t, tx)
	var auditID uuid.UUID
	var err error
	requestID := uuid.New()
	key := operation + "-" + requestID.String()
	rateID := uuid.New()
	if facts.audit {
		resourceType, resourceID, auditRequestID := "plugin_webhook_delivery", delivery.String(), key
		if operation == "plugin_webhook.subscription.create" {
			resourceType, resourceID = "plugin_webhook_subscription", subscription.String()
		}
		if !facts.write {
			resourceType, resourceID, auditRequestID = "plugin_webhook_subscription",
				subscription.String(), "rate-"+rateID.String()
			if operation == "plugin_webhook.subscription.create" {
				resourceType, resourceID = "plugin_webhook_tenant", fixture.tenantScope.String()
			}
		}
		auditID, err = appendPluginWebhookAuditIdentityTx084(ctx, tx, fixture.tenantScope, actorScope,
			actorUser, operation, "success", "accepted", resourceType, resourceID, auditRequestID, recordedAt)
		if err != nil {
			return err
		}
	}
	if facts.write {
		digest := sha256.Sum256([]byte(key))
		if operation == "plugin_webhook.subscription.create" {
			_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
				id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,
				request_digest,subscription_id,response_status,response_body,receipt_wrapping_key_id,
				receipt_aad_sha256,receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,
				created_at,completed_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,201,
				jsonb_build_object('subscription_id',$8::uuid::text),'plugin-webhook-kek-v1',$9,
				$10,$11,$12,$13,$14,$15)`, requestID, fixture.tenantScope, actorScope, actorUser,
				operation, key, digest[:], subscription,
				pluginWebhookReceiptAAD084(fixture.tenantScope, actorScope, actorUser, key,
					operation, subscription), bytes084(12, 0xe1), bytes084(48, 0xe2),
				now.Add(24*time.Hour), auditID, now, recordedAt)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
				id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,
				request_digest,subscription_id,delivery_id,response_status,response_body,
				audit_event_id,created_at,completed_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,202,
				jsonb_build_object('subscription_id',$8::uuid::text,'delivery_id',$9::uuid::text),
				$10,$11,$12)`, requestID, fixture.tenantScope, actorScope, actorUser,
				operation, key, digest[:], subscription, delivery, auditID, now, recordedAt)
		}
		if err != nil {
			return err
		}
	}
	if !facts.rate {
		return nil
	}
	if operation == "plugin_webhook.subscription.create" {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
			id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
			reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,NULL,$3,$4,$5,'allowed','accepted',$6,$7)`, rateID,
			fixture.tenantScope, actorScope, actorUser, operation, auditID, recordedAt)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
			id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
			reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,$3,$4,$5,$6,'allowed','accepted',$7,$8)`, rateID,
			fixture.tenantScope, subscription, actorScope, actorUser, operation, auditID, recordedAt)
	}
	return err
}

func insertPluginWebhookRawSubscriptionRowsTx084(ctx context.Context, tx pgx.Tx,
	fixture pluginWebhookIdentity084, actorScope, actorUser uuid.UUID,
	revision, events, lifecycle uint64, status string, now time.Time,
) (pluginWebhookResource084, error) {
	resource := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	var revokeSequence any
	var revokedAt any
	if status == "revoked" {
		revokeSequence = lifecycle
		revokedAt = now
	}
	_, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_subscriptions(
		id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,
		event_types,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,
		revoke_sequence,created_at,updated_at,revoked_at
	) VALUES($1,$2,$3,$4,'Webhook test','https://hooks.example.com/v1/events',
		'hooks.example.com','/v1/events',ARRAY['io.cdnca.webhook.v1.test'],$5,$6,$7,$8,$9,
		$10,$11,$11,$12)`, resource.subscription, fixture.tenantScope, actorScope, actorUser,
		resource.secret, status, revision, events, lifecycle, revokeSequence, now, revokedAt)
	if err != nil || status != "active" {
		return resource, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,activated_at
	) VALUES($1,$1,$2,$3,$4,$5,1,'active','plugin-webhook-kek-v1',$6,$7,$8,$9,$10,$10)`,
		resource.secret, fixture.tenantScope, resource.subscription, actorScope, actorUser,
		pluginWebhookSecretAAD084(fixture.tenantScope, resource.subscription, resource.secret, 1,
			"plugin-webhook-kek-v1"), bytes084(12, 0xf1), bytes084(48, 0xf2),
		bytes084(32, 0xf3), now)
	return resource, err
}

func insertPluginWebhookInitialSubscriptionResult084(t *testing.T, revision, events,
	lifecycle uint64, status string,
) error {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 83)
	fixture := seedPluginWebhookIdentity084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 84); err != nil {
		return err
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if _, err := insertPluginWebhookRawSubscriptionRowsTx084(t.Context(), tx, fixture,
		fixture.tenantScope, fixture.ownerUser, revision, events, lifecycle, status,
		pluginWebhook084Now); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookDeliveryRow084(t *testing.T, pool pluginWebhookDB084,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, eventID, replayOf uuid.UUID,
	now time.Time,
) (uuid.UUID, error) {
	t.Helper()
	deliveryID := uuid.New()
	var revision string
	if err := pool.QueryRow(t.Context(), `SELECT revision::text FROM plugin_webhook_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope, resource.subscription).Scan(&revision); err != nil {
		return uuid.Nil, err
	}
	var replay any
	if replayOf != uuid.Nil {
		replay = replayOf
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_deliveries(
		id,tenant_scope_id,subscription_id,event_id,actor_scope_id,actor_user_id,replay_of,
		delivery_idempotency_key,target_url,target_host,target_path,status,subscription_revision,
		attempt_count,created_at
	) VALUES($1,$2,$3,$4,$2,$5,$6,$7,'https://hooks.example.com/v1/events',
		'hooks.example.com','/v1/events','pending',$8,0,$9)`, deliveryID, fixture.tenantScope,
		resource.subscription, eventID, fixture.ownerUser, replay,
		"plugin-webhook-v2-"+hexDigest084(deliveryID.String()), revision, now)
	return deliveryID, err
}

func insertPluginWebhookOutbox084(t *testing.T, pool pluginWebhookDB084,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, eventID, deliveryID uuid.UUID,
	body, digest []byte, messageID string, now time.Time,
) error {
	t.Helper()
	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_outbox(
		id,tenant_scope_id,subscription_id,event_id,delivery_id,actor_scope_id,actor_user_id,
		queue_schema,queue_body,queue_body_sha256,message_id,status,publish_attempt,
		available_at,created_at
	) VALUES($1,$2,$3,$4,$5,$2,$6,'cdnca.plugin-webhook.queue/v2',$7,$8,$9,
		'pending',0,$10,$10)`, uuid.New(), fixture.tenantScope, resource.subscription, eventID,
		deliveryID, fixture.ownerUser, body, digest, messageID, now)
	return err
}

func completePluginWebhookDelivery084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, delivery uuid.UUID, now time.Time,
) {
	t.Helper()
	claim := claimPluginWebhookDelivery084(t, pool, fixture, resource, delivery, now)
	startPluginWebhookAttempt084(t, pool, claim, now.Add(time.Second))
	if _, err := pool.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='succeeded',completed_at=$2,http_status=204,response_sha256=$3,
			response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
		WHERE claim_token=$1`, claim, now.Add(2*time.Second), bytes084(32, 0xb1)); err != nil {
		t.Fatal(err)
	}
}

func startPluginWebhookAttempt084(t *testing.T, pool *pgxpool.Pool, claim uuid.UUID, now time.Time) {
	t.Helper()
	if err := startPluginWebhookAttemptResult084(t, pool, claim, false, now); err != nil {
		t.Fatal(err)
	}
}

func insertPluginWebhookClaim084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, delivery uuid.UUID, now time.Time,
) (uuid.UUID, error) {
	t.Helper()
	claim := uuid.New()
	var revision, lifecycle, attempts string
	var activeSecret uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT subscription.revision::text,
		subscription.lifecycle_sequence::text,subscription.active_secret_version_id,
		delivery.attempt_count::text
		FROM plugin_webhook_subscriptions subscription
		JOIN plugin_webhook_deliveries delivery
		  ON delivery.tenant_scope_id=subscription.tenant_scope_id
		 AND delivery.subscription_id=subscription.id AND delivery.id=$3
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2`, fixture.tenantScope,
		resource.subscription, delivery).Scan(&revision, &lifecycle, &activeSecret, &attempts); err != nil {
		return uuid.Nil, err
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO plugin_webhook_delivery_attempts(
		tenant_scope_id,subscription_id,delivery_id,actor_scope_id,actor_user_id,
		attempt_number,claim_token,claim_sequence,claimed_subscription_revision,
		secret_version_id,status,claimed_at
	) VALUES($1,$2,$3,$1,$4,($5::numeric+1),$6,($7::numeric+1),$8,$9,'claimed',$10)`,
		fixture.tenantScope, resource.subscription, delivery, fixture.ownerUser, attempts, claim,
		lifecycle, revision, activeSecret, now)
	return claim, err
}

func pluginWebhookSecretAAD084(targetScope, subscription, secretVersion uuid.UUID, version uint64,
	wrappingKeyID string,
) []byte {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		"cdnca.plugin-webhook.secret/v1", targetScope.String(), subscription.String(),
		secretVersion.String(), strconv.FormatUint(version, 10), wrappingKeyID,
	}, "\x00")))
	return digest[:]
}

func pluginWebhookReceiptAAD084(targetScope, actorScope, actorUser uuid.UUID, idempotencyKey,
	operation string, resource uuid.UUID,
) []byte {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		"cdnca.plugin-webhook.receipt/v1", targetScope.String(), actorScope.String(), actorUser.String(),
		idempotencyKey, operation, resource.String(),
	}, "\x00")))
	return digest[:]
}

func insertPluginWebhookManagementRequestTx084(ctx context.Context, t *testing.T, tx pgx.Tx,
	fixture pluginWebhookIdentity084, actorScope, actorUser uuid.UUID, operation string,
	subscription, rotation uuid.UUID, now time.Time,
) error {
	t.Helper()
	recordedAt := pluginWebhookDatabaseTime084(t, tx)
	requestID := uuid.New()
	key := operation + "-" + requestID.String()
	resourceType, resourceID := "plugin_webhook_subscription", subscription.String()
	if operation == "plugin_webhook.secret.rotate" || operation == "plugin_webhook.secret.activate" {
		resourceType, resourceID = "plugin_webhook_secret_version", rotation.String()
	}
	auditID, err := appendPluginWebhookAuditIdentityTx084(ctx, tx, fixture.tenantScope, actorScope,
		actorUser, operation, "success", "accepted", resourceType, resourceID, key, recordedAt)
	if err != nil {
		return err
	}
	requestDigest := sha256.Sum256([]byte(key))
	if operation == "plugin_webhook.secret.rotate" {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,rotation_id,response_status,response_body,receipt_wrapping_key_id,
			receipt_aad_sha256,receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,
			created_at,completed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,201,
			jsonb_build_object('subscription_id',$8::uuid::text,'rotation_id',$9::uuid::text),
			'plugin-webhook-kek-v1',$10,$11,$12,$13,$14,$15,$16)`, requestID, fixture.tenantScope,
			actorScope, actorUser, operation, key, requestDigest[:], subscription, rotation,
			pluginWebhookReceiptAAD084(fixture.tenantScope, actorScope, actorUser, key, operation, rotation),
			bytes084(12, 0xd1), bytes084(48, 0xd2), now.Add(24*time.Hour), auditID, now, recordedAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
			id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
			reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,$3,$4,$5,'plugin_webhook.secret.rotate','allowed','accepted',$6,$7)`,
			uuid.New(), fixture.tenantScope, subscription, actorScope, actorUser, auditID, recordedAt)
		return err
	}
	if operation == "plugin_webhook.secret.activate" {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
			id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			subscription_id,rotation_id,response_status,response_body,audit_event_id,created_at,completed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,200,
			jsonb_build_object('subscription_id',$8::uuid::text,'rotation_id',$9::uuid::text),
			$10,$11,$12)`, requestID, fixture.tenantScope, actorScope, actorUser, operation, key,
			requestDigest[:], subscription, rotation, auditID, now, recordedAt)
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,response_status,response_body,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,200,
		jsonb_build_object('subscription_id',$8::uuid::text),$9,$10,$11)`, requestID,
		fixture.tenantScope, actorScope, actorUser, operation, key, requestDigest[:], subscription,
		auditID, now, recordedAt)
	return err
}

func insertPluginWebhookPendingSecretResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, now time.Time,
) (uuid.UUID, error) {
	t.Helper()
	pending := uuid.New()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(t.Context())
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.rotate",
		resource.subscription, pending, now); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
		pending, fixture.tenantScope, resource.subscription, fixture.ownerUser,
		pluginWebhookSecretAAD084(fixture.tenantScope, resource.subscription, pending, 2,
			"plugin-webhook-kek-v1"), bytes084(12, 0xa4), bytes084(48, 0xa5),
		bytes084(32, 0xa6), now, now.Add(24*time.Hour)); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(t.Context()); err != nil {
		return uuid.Nil, err
	}
	return pending, nil
}

func insertPluginWebhookStandaloneRotationRate084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, now time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	recordedAt := pluginWebhookDatabaseTime084(t, tx)
	rateID := uuid.New()
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, fixture.tenantScope,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.rotate", "success", "accepted",
		"plugin_webhook_subscription", subscription.String(), "rate-"+rateID.String(), recordedAt)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
	) VALUES($1,$2,$3,$2,$4,'plugin_webhook.secret.rotate','allowed','accepted',$5,$6)`,
		rateID, fixture.tenantScope, subscription, fixture.ownerUser, auditID, recordedAt); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookTestRateAuditTx084(ctx context.Context, tx pgx.Tx,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, position int64, previous []byte,
	recordedAt time.Time,
) (uuid.UUID, uuid.UUID, []byte, error) {
	rateID := uuid.New()
	auditID := uuid.New()
	eventHash := sha256.Sum256([]byte(auditID.String()))
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,$3,$4,'plugin_webhook.test_delivery.create','plugin_webhook_subscription',$5,
		$6,'success',jsonb_build_object('actor_scope_id',$2::uuid::text,
			'target_scope_id',$2::uuid::text,'operation','plugin_webhook.test_delivery.create',
			'reason','accepted'),$7,$8,$9)`, auditID, fixture.tenantScope, position,
		fixture.ownerUser, subscription.String(), "rate-"+rateID.String(), previous, eventHash[:],
		recordedAt)
	return rateID, auditID, eventHash[:], err
}

func insertPluginWebhookTestRateRowTx084(ctx context.Context, tx pgx.Tx,
	fixture pluginWebhookIdentity084, subscription, rateID, auditID uuid.UUID, recordedAt time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
	) VALUES($1,$2,$3,$2,$4,'plugin_webhook.test_delivery.create','allowed','accepted',$5,$6)`,
		rateID, fixture.tenantScope, subscription, fixture.ownerUser, auditID, recordedAt)
	return err
}

func insertPluginWebhookTestRateInOpenTx084(ctx context.Context, t *testing.T, tx pgx.Tx,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, recordedAt time.Time,
) error {
	t.Helper()
	var position int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_position,event_hash FROM audit_events
		WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, fixture.tenantScope).
		Scan(&position, &previous); err != nil {
		return err
	}
	rateID, auditID, _, err := insertPluginWebhookTestRateAuditTx084(ctx, tx, fixture,
		subscription, position+1, previous, recordedAt)
	if err != nil {
		return err
	}
	return insertPluginWebhookTestRateRowTx084(ctx, tx, fixture, subscription, rateID,
		auditID, recordedAt)
}

func pluginWebhookDatabaseTime084(t *testing.T, db pluginWebhookDB084) time.Time {
	t.Helper()
	var now time.Time
	if err := db.QueryRow(t.Context(), `SELECT transaction_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

func pluginWebhookLoginPool084(t *testing.T, ownerPool *pgxpool.Pool, login string) *pgxpool.Pool {
	t.Helper()
	var schema string
	if err := ownerPool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	config := ownerPool.Config().Copy()
	config.ConnConfig.User = login
	delete(config.ConnConfig.RuntimeParams, "options")
	config.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize()
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var sessionUser string
	var currentUser string
	if err := pool.QueryRow(t.Context(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser,
	); err != nil {
		t.Fatal(err)
	}
	if sessionUser != login || currentUser != login {
		t.Fatalf("login identity=%s/%s, want %s/%s", sessionUser, currentUser, login, login)
	}
	return pool
}

func agePluginWebhookReceipt084(t *testing.T, pool *pgxpool.Pool, requestID uuid.UUID) time.Time {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	now := pluginWebhookDatabaseTime084(t, tx)
	expiresAt := now.Add(-time.Second)
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_write_requests
		SET created_at=$2::timestamptz-interval '24 hours',
			plugin_webhook_physical_created_at=$2::timestamptz-interval '24 hours',
			receipt_expires_at=$2
		WHERE id=$1`, requestID, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return expiresAt
}

func agePluginWebhookSecretExpiry084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, secret uuid.UUID,
) time.Time {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	now := pluginWebhookDatabaseTime084(t, tx)
	expiresAt := now.Add(-time.Second)
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET created_at=CASE WHEN status='pending' THEN $4::timestamptz-interval '24 hours'
				ELSE created_at END,
			plugin_webhook_physical_created_at=CASE WHEN status='pending'
				THEN $4::timestamptz-interval '24 hours'
				ELSE plugin_webhook_physical_created_at END,
			retired_at=CASE WHEN status='retired' THEN $4::timestamptz-interval '24 hours'
				ELSE retired_at END,
			expires_at=$4
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3
		  AND status IN ('pending','retired')`, tenantScope, subscription, secret, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return expiresAt
}

func insertPluginWebhookStandaloneRateOperation084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, operation string, occurredAt time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if occurredAt.IsZero() {
		occurredAt = pluginWebhookDatabaseTime084(t, tx)
	}
	rateID := uuid.New()
	resourceType, resourceID := "plugin_webhook_subscription", subscription.String()
	var subscriptionValue any = subscription
	if operation == "plugin_webhook.subscription.create" {
		resourceType, resourceID = "plugin_webhook_tenant", fixture.tenantScope.String()
		subscriptionValue = nil
	}
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, fixture.tenantScope,
		fixture.tenantScope, fixture.ownerUser, operation, "success", "accepted", resourceType,
		resourceID, "rate-"+rateID.String(), occurredAt)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
	) VALUES($1,$2,$3,$2,$4,$5,'allowed','accepted',$6,$7)`, rateID, fixture.tenantScope,
		subscriptionValue, fixture.ownerUser, operation, auditID, occurredAt); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func rewritePluginWebhookPendingClock084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, pending uuid.UUID,
	createdAt time.Time,
) time.Time {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	var deadline time.Time
	if err := tx.QueryRow(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET created_at=$4,plugin_webhook_physical_created_at=$4,
			expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 RETURNING expires_at`,
		fixture.tenantScope, resource.subscription, pending, createdAt).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return deadline
}

func activatePluginWebhookAtDatabaseTime084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, pending uuid.UUID,
	wait time.Duration,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	commandAt := pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookActivationRequestTx084(t.Context(), tx, fixture,
		resource.subscription, pending, commandAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, resource.secret, commandAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, pending, commandAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope,
		resource.subscription, pending, commandAt); err != nil {
		return err
	}
	if wait > 0 {
		if wait < 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}
		if wait > 5*time.Second {
			return errors.New("activation expiry wait exceeded five seconds")
		}
		if _, err := tx.Exec(t.Context(), `SELECT pg_sleep($1)`, wait.Seconds()); err != nil {
			return err
		}
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookPendingSecret084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, version uint64, now time.Time,
) uuid.UUID {
	t.Helper()
	pending := uuid.New()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.rotate",
		resource.subscription, pending, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,$5,'pending','plugin-webhook-kek-v1',$6,$7,$8,$9,$10,$11)`,
		pending, fixture.tenantScope, resource.subscription, fixture.ownerUser, version,
		pluginWebhookSecretAAD084(fixture.tenantScope, resource.subscription, pending, version,
			"plugin-webhook-kek-v1"), bytes084(12, 0xa4), bytes084(48, 0xa5),
		bytes084(32, 0xa6), now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return pending
}

func insertPluginWebhookActivationRequestTx084(ctx context.Context, tx pgx.Tx,
	fixture pluginWebhookIdentity084, subscription, rotation uuid.UUID, now time.Time,
) error {
	requestID := uuid.New()
	key := "plugin_webhook.secret.activate-" + requestID.String()
	auditID, err := appendPluginWebhookAuditIdentityTx084(ctx, tx, fixture.tenantScope,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.activate",
		"success", "accepted", "plugin_webhook_secret_version", rotation.String(), key, now)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(key))
	var rotationValue any
	if rotation != uuid.Nil {
		rotationValue = rotation
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,rotation_id,response_status,response_body,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.secret.activate',$4,$5,$6,$7,200,
		jsonb_build_object('subscription_id',$6::uuid::text,'rotation_id',$7::uuid::text),$8,$9,$9)`, requestID,
		fixture.tenantScope, fixture.ownerUser, key, digest[:], subscription, rotationValue,
		auditID, now)
	return err
}

func activatePluginWebhookSecretsResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, requestRotation uuid.UUID,
	targets []uuid.UUID, now time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	now = pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookActivationRequestTx084(t.Context(), tx, fixture,
		resource.subscription, requestRotation, now); err != nil {
		return err
	}
	current := resource.secret
	for index, target := range targets {
		transitionedAt := now.Add(time.Duration(index) * time.Second)
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, current, transitionedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='active',activated_at=$4,expires_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, target, transitionedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
			SET active_secret_version_id=$3,revision=revision+1,
				lifecycle_sequence=lifecycle_sequence+1,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope, resource.subscription,
			target, transitionedAt); err != nil {
			return err
		}
		current = target
	}
	return tx.Commit(t.Context())
}

func activatePluginWebhookTwiceResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, requestRotation,
	first uuid.UUID, now time.Time,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	now = pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookActivationRequestTx084(t.Context(), tx, fixture,
		resource.subscription, requestRotation, now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, resource.secret, now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, first, now); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,
			lifecycle_sequence=lifecycle_sequence+1,updated_at=$4
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope, resource.subscription,
		first, now); err != nil {
		return err
	}

	second := uuid.New()
	secondAt := now
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.rotate",
		resource.subscription, second, secondAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,3,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
		second, fixture.tenantScope, resource.subscription, fixture.ownerUser,
		pluginWebhookSecretAAD084(fixture.tenantScope, resource.subscription, second, 3,
			"plugin-webhook-kek-v1"), bytes084(12, 0xa7), bytes084(48, 0xa8),
		bytes084(32, 0xa9), secondAt, secondAt.Add(24*time.Hour)); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, first, secondAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
		resource.subscription, second, secondAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,
			lifecycle_sequence=lifecycle_sequence+1,updated_at=$4
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope, resource.subscription,
		second, secondAt); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookPendingBundleActorResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084,
	actorScope, actorUser uuid.UUID, now time.Time,
) error {
	t.Helper()
	eventID := uuid.Must(uuid.NewV7())
	body := pluginWebhookCanonicalBody084(t, fixture, resource, eventID, nil, 1, now)
	digest := sha256.Sum256(body)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if err := insertPluginWebhookEvent084(t, tx, fixture, resource, eventID, nil, body,
		digest[:], now); err != nil {
		return err
	}
	deliveryID, err := insertPluginWebhookDeliveryRow084(t, tx, fixture, resource, eventID,
		uuid.Nil, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_outbox(
		id,tenant_scope_id,subscription_id,event_id,delivery_id,actor_scope_id,actor_user_id,
		queue_schema,queue_body,queue_body_sha256,message_id,status,publish_attempt,available_at,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,'cdnca.plugin-webhook.queue/v2',$8,$9,$10,
		'pending',0,$11,$11)`, uuid.New(), fixture.tenantScope, resource.subscription,
		eventID, deliveryID, actorScope, actorUser, body, digest[:],
		"plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()), now)
	if err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.test_delivery.create",
		resource.subscription, deliveryID, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func insertPluginWebhookDeadLetterActorResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084,
	actorScope, actorUser uuid.UUID, now time.Time,
) error {
	t.Helper()
	delivery := seedPluginWebhookDelivery084(t, pool, fixture, resource, now)
	claim := claimPluginWebhookDelivery084(t, pool, fixture, resource, delivery, now.Add(time.Minute))
	startPluginWebhookAttempt084(t, pool, claim, now.Add(2*time.Minute))
	return finishPluginWebhookDeadLetter084(t, pool, claim, "permanent_failure",
		actorScope, actorUser, bytes084(32, 0xb5))
}

func mutatePluginWebhookSecretTransition084(t *testing.T, transition string) error {
	t.Helper()
	pool, fixture, resource := setupPluginWebhook084(t)
	pending, err := insertPluginWebhookPendingSecretResult084(t, pool, fixture, resource,
		pluginWebhookDatabaseTime084(t, pool))
	if err != nil {
		return err
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	now := pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookActivationRequestTx084(t.Context(), tx, fixture,
		resource.subscription, pending, now); err != nil {
		return err
	}
	if transition == "active_to_retired" {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='retired',nonce=$4,ciphertext=$5,activated_at=activated_at+interval '1 microsecond',
				retired_at=$6,expires_at=$6::timestamptz+interval '24 hours'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, resource.secret, bytes084(12, 0xf1), bytes084(48, 0xf2), now)
	} else {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='retired',retired_at=$4,expires_at=$4::timestamptz+interval '24 hours'
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, resource.secret, now)
	}
	if err != nil {
		return err
	}
	if transition == "pending_to_active" {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='active',nonce=$4,ciphertext=$5,activated_at=$6,expires_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, pending, bytes084(12, 0xf3), bytes084(48, 0xf4), now)
	} else {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
			SET status='active',activated_at=$4,expires_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, fixture.tenantScope,
			resource.subscription, pending, now)
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope,
		resource.subscription, pending, now); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func text084(value string) *string { return &value }

func reverseScan084() []string {
	return []string{`reconcile_phase='reverse_scan',reconcile_stream_created_unix_nano=1,
		reconcile_high_watermark=10,reconcile_scan_boundary=1,reconcile_cursor=10`}
}

func publishReady084() []string {
	return []string{
		reverseScan084()[0],
		`reconcile_cursor=1`,
		`reconcile_phase='publish_ready',reconcile_scan_boundary=NULL,reconcile_cursor=NULL`,
	}
}

func forwardScan084() []string {
	return append(publishReady084(),
		`reconcile_phase='forward_scan',reconcile_high_watermark=20,
			reconcile_scan_boundary=11,reconcile_cursor=11`)
}

func setupPluginWebhookPendingDeadLetter084(t *testing.T) (*pgxpool.Pool,
	pluginWebhookIdentity084, pluginWebhookResource084, uuid.UUID,
) {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	delivery := seedPluginWebhookPendingDeadLetterInPool084(t, pool, identity, resource)
	return pool, identity, resource, delivery
}

func seedPluginWebhookPendingDeadLetterInPool084(t *testing.T, pool *pgxpool.Pool,
	identity pluginWebhookIdentity084, resource pluginWebhookResource084,
) uuid.UUID {
	t.Helper()
	delivery := seedPluginWebhookDelivery084(t, pool, identity, resource, pluginWebhook084Now)
	claim := claimPluginWebhookDelivery084(t, pool, identity, resource, delivery,
		pluginWebhookDatabaseTime084(t, pool))
	startPluginWebhookAttempt084(t, pool, claim, pluginWebhookDatabaseTime084(t, pool))
	if err := insertPluginWebhookDeadLetterIntent084(t, pool, claim); err != nil {
		t.Fatal(err)
	}
	return delivery
}

func updatePluginWebhookDeadLetter084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, assignments string,
) error {
	t.Helper()
	_, err := pool.Exec(t.Context(), fmt.Sprintf(`UPDATE plugin_webhook_dead_letters SET %s
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, assignments),
		tenantScope, subscription, delivery)
	return err
}

func assertPluginWebhookDeadLetterReconcile084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, publishState, phase string, wantEpoch, wantHigh,
	wantBoundary, wantCursor *string,
) {
	t.Helper()
	var gotPublish, gotPhase string
	var gotEpoch, gotHigh, gotBoundary, gotCursor *string
	if err := pool.QueryRow(t.Context(), `SELECT publish_state,reconcile_phase,
		reconcile_stream_created_unix_nano::text,reconcile_high_watermark::text,
		reconcile_scan_boundary::text,reconcile_cursor::text FROM plugin_webhook_dead_letters
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, tenantScope,
		subscription, delivery).Scan(&gotPublish, &gotPhase, &gotEpoch, &gotHigh,
		&gotBoundary, &gotCursor); err != nil {
		t.Fatal(err)
	}
	if gotPublish != publishState || gotPhase != phase ||
		!equalOptionalText084(gotEpoch, wantEpoch) || !equalOptionalText084(gotHigh, wantHigh) ||
		!equalOptionalText084(gotBoundary, wantBoundary) ||
		!equalOptionalText084(gotCursor, wantCursor) {
		t.Fatalf("DLQ state=%s/%s/%v/%v/%v/%v want=%s/%s/%v/%v/%v/%v", gotPublish,
			gotPhase, gotEpoch, gotHigh, gotBoundary, gotCursor, publishState, phase,
			wantEpoch, wantHigh, wantBoundary, wantCursor)
	}
}

func equalOptionalText084(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func pluginWebhookColumnExists084(t *testing.T, pool *pgxpool.Pool, table, column string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
	)`, table, column).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func queuePluginWebhookDeliveryIdentity084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, epoch, sequence uint64, hasEpoch bool,
) error {
	t.Helper()
	if !hasEpoch {
		return fmt.Errorf("delivery stream incarnation column is unavailable")
	}
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	token := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, tenantScope,
		subscription, delivery, token); err != nil {
		return err
	}
	return attestPluginWebhookOutboxResult084(t, pool, attestation, tenantScope, subscription,
		delivery, token, epoch, sequence)
}

func assertPluginWebhookDownP8401NoMutation084(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	assertPluginWebhookCode084(t, migrateVersionIsolated(t.Context(), pool, "down", 84), "P8401")
	assertPluginWebhookHead084(t, pool, 84)
	var earliestTrigger, earliestFunction, lateFunction, lateTable bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='plugin_webhook_entitlement_decisions'::regclass
			AND tgname='plugin_webhook_entitlement_decisions_validate_084'),
		to_regprocedure('validate_plugin_webhook_entitlement_decision_084()') IS NOT NULL,
		to_regprocedure('publish_plugin_webhook_outbox_084(uuid,uuid,uuid,uuid,text,text,numeric,text,numeric,text,bytea,numeric,numeric,text,bytea)') IS NOT NULL,
		to_regclass('plugin_webhook_runtime_attestation_keys') IS NOT NULL`).
		Scan(&earliestTrigger, &earliestFunction, &lateFunction, &lateTable); err != nil {
		t.Fatal(err)
	}
	if !earliestTrigger || !earliestFunction || !lateFunction || !lateTable {
		t.Fatal("down partially dropped 084 objects")
	}
}

func insertPluginWebhookDeadLetterIntent084(t *testing.T, pool *pgxpool.Pool, claim uuid.UUID) error {
	t.Helper()
	return insertPluginWebhookDeadLetterIntentOverride084(t, pool, claim, "", nil)
}

func insertPluginWebhookDeadLetterIntentOverride084(t *testing.T, pool *pgxpool.Pool,
	claim uuid.UUID, messageID string, payloadDigest []byte,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='permanent_failure',completed_at=clock_timestamp(),http_status=503,
			failure_code='upstream_permanent_failure',response_sha256=$2,response_bytes=0,
			response_preview=''::bytea,sanitized_headers='{}'::jsonb WHERE claim_token=$1`,
		claim, bytes084(32, 0xee)); err != nil {
		return err
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_dead_letters(
		id,tenant_scope_id,subscription_id,delivery_id,event_id,final_attempt_number,
		actor_scope_id,actor_user_id,nats_stream,nats_subject,nats_message_id,payload_sha256,
		publish_state,reason_code,http_status,request_sha256,response_sha256,response_bytes,failed_at
	) SELECT $2,attempt.tenant_scope_id,attempt.subscription_id,attempt.delivery_id,delivery.event_id,
		attempt.attempt_number,attempt.actor_scope_id,attempt.actor_user_id,'PLUGIN_WEBHOOK_DLQ',
		'cdnca.plugin-webhook.dead-letter.v1',CASE WHEN $3='' THEN
			'plugin-webhook-dlq-v1-' || encode(sha256(convert_to(
				attempt.delivery_id::text || ':' || attempt.attempt_number::text,'UTF8')),'hex')
			ELSE $3 END,COALESCE($4::bytea,plugin_webhook_dead_letter_payload_sha256_084(attempt.tenant_scope_id,
			attempt.subscription_id,attempt.delivery_id,delivery.event_id,attempt.attempt_number,
			attempt.failure_code,attempt.http_status,attempt.request_sha256,attempt.response_sha256,
			attempt.response_bytes)),'pending',attempt.failure_code,attempt.http_status,
		attempt.request_sha256,attempt.response_sha256,attempt.response_bytes,attempt.completed_at
	FROM plugin_webhook_delivery_attempts attempt
	JOIN plugin_webhook_deliveries delivery
	  ON delivery.tenant_scope_id=attempt.tenant_scope_id
	 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
	WHERE attempt.claim_token=$1`, claim, uuid.New(), messageID, payloadDigest)
	if err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func acknowledgePluginWebhookDeadLetter084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, sequence uint64,
) error {
	t.Helper()
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	var eventID, deadLetterID, generation uuid.UUID
	var phase, stream, subject, messageID string
	var epoch *string
	var high, boundary, cursor *string
	var semanticDigest []byte
	readState := func() error {
		return pool.QueryRow(t.Context(), `SELECT event_id,id,reconcile_generation,
		reconcile_phase,reconcile_stream_created_unix_nano::text,
		reconcile_high_watermark::text,reconcile_scan_boundary::text,reconcile_cursor::text,
		nats_stream,nats_subject,nats_message_id,payload_sha256
		FROM plugin_webhook_dead_letters WHERE tenant_scope_id=$1 AND subscription_id=$2
		  AND delivery_id=$3`, tenantScope, subscription, delivery).Scan(&eventID, &deadLetterID,
			&generation, &phase, &epoch, &high, &boundary, &cursor, &stream, &subject,
			&messageID, &semanticDigest)
	}
	if err := readState(); err != nil {
		return err
	}
	if phase == "uninitialized" {
		newGeneration := uuid.New()
		streamEpoch := "101"
		if sequence == 1 {
			zero := "0"
			if err := transitionPluginWebhookDeadLetter084(t, pool, tenantScope, subscription,
				delivery, generation, phase, epoch, high, boundary, cursor, newGeneration,
				"publish_ready", &streamEpoch, &zero, nil, nil); err != nil {
				return err
			}
		} else {
			highValue := sequence - 1
			highText := strconv.FormatUint(highValue, 10)
			boundaryText := "1"
			cursorText := highText
			if err := transitionPluginWebhookDeadLetter084(t, pool, tenantScope, subscription,
				delivery, generation, phase, epoch, high, boundary, cursor, newGeneration,
				"reverse_scan", &streamEpoch, &highText, &boundaryText, &cursorText); err != nil {
				return err
			}
			for highValue > 1 {
				next := uint64(1)
				if highValue > 33 {
					next = highValue - 32
				}
				nextText := strconv.FormatUint(next, 10)
				if err := transitionPluginWebhookDeadLetter084(t, pool, tenantScope,
					subscription, delivery, newGeneration, "reverse_scan", &streamEpoch,
					&highText, &boundaryText, &cursorText, newGeneration, "reverse_scan",
					&streamEpoch, &highText, &boundaryText, &nextText); err != nil {
					return err
				}
				highValue = next
				cursorText = nextText
			}
			if err := transitionPluginWebhookDeadLetter084(t, pool, tenantScope, subscription,
				delivery, newGeneration, "reverse_scan", &streamEpoch, &highText,
				&boundaryText, &cursorText, newGeneration, "publish_ready", &streamEpoch,
				&highText, nil, nil); err != nil {
				return err
			}
		}
		if err := readState(); err != nil {
			return err
		}
	}
	wireDigest := sha256.Sum256([]byte("plugin-webhook-dlq-wire-084:" + delivery.String() +
		":" + strconv.FormatUint(sequence, 10)))
	numericField := func(value *string) []byte {
		if value == nil {
			return []byte{}
		}
		return []byte(*value)
	}
	fields := [][]byte{
		[]byte("cdnca.plugin-webhook.nats-publication/dead-letter/v1"),
		[]byte(strconv.FormatInt(attestation.generation, 10)), []byte(attestation.keyID),
		[]byte(attestation.natsDomain), []byte(tenantScope.String()), []byte(subscription.String()),
		[]byte(delivery.String()), []byte(eventID.String()), []byte(deadLetterID.String()),
		[]byte(generation.String()), []byte(phase), []byte(dereferenceText084(high)),
		numericField(boundary), numericField(cursor), []byte(stream),
		[]byte(dereferenceText084(epoch)), []byte(subject),
		[]byte(strconv.FormatUint(sequence, 10)), []byte(messageID),
		[]byte(fmt.Sprintf("%x", semanticDigest)), []byte(fmt.Sprintf("%x", wireDigest[:])),
		[]byte(strconv.FormatUint(sequence-1, 10)),
	}
	digest := sha256.Sum256(pluginWebhookAttestationFrame084(fields))
	signature := ed25519.Sign(attestation.privateKey, digest[:])
	return pluginWebhookRuntimeExec084(t, pool, `SELECT acknowledge_plugin_webhook_dead_letter_084(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
	)`, tenantScope, subscription, delivery, generation, phase, epoch, high, boundary, cursor,
		attestation.natsDomain, stream, epoch, subject, strconv.FormatUint(sequence, 10),
		messageID, semanticDigest, wireDigest[:], strconv.FormatUint(sequence-1, 10),
		attestation.generation, attestation.keyID, signature)
}

func transitionPluginWebhookDeadLetter084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery, expectedGeneration uuid.UUID, expectedPhase string,
	expectedEpoch, expectedHigh, expectedBoundary, expectedCursor *string,
	newGeneration uuid.UUID, newPhase string, newEpoch, newHigh, newBoundary, newCursor *string,
) error {
	t.Helper()
	return pluginWebhookRuntimeExec084(t, pool, `SELECT
		transition_plugin_webhook_dead_letter_reconcile_084(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, tenantScope,
		subscription, delivery, expectedGeneration, expectedPhase, expectedEpoch, expectedHigh,
		expectedBoundary, expectedCursor, newGeneration, newPhase, newEpoch, newHigh,
		newBoundary, newCursor)
}

func dereferenceText084(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func finishPluginWebhookDeadLetter084(t *testing.T, pool *pgxpool.Pool, claim uuid.UUID,
	status string, actorScope, actorUser uuid.UUID, responseDigest []byte,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	if status == "temporary_failure" {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='temporary_failure',completed_at=clock_timestamp(),http_status=503,
				failure_code='upstream_timeout',retry_after_seconds=0,response_sha256=$2,
				response_bytes=0,response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, responseDigest)
	} else {
		_, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
			SET status='permanent_failure',completed_at=clock_timestamp(),http_status=503,
				failure_code='upstream_permanent_failure',response_sha256=$2,response_bytes=0,
				response_preview=''::bytea,sanitized_headers='{}'::jsonb
			WHERE claim_token=$1`, claim, responseDigest)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_dead_letters(
		id,tenant_scope_id,subscription_id,delivery_id,event_id,final_attempt_number,
		actor_scope_id,actor_user_id,nats_stream,nats_subject,nats_message_id,payload_sha256,
		publish_state,reason_code,http_status,request_sha256,response_sha256,response_bytes,failed_at
	) SELECT $2,attempt.tenant_scope_id,attempt.subscription_id,attempt.delivery_id,delivery.event_id,
		attempt.attempt_number,$3,$4,'PLUGIN_WEBHOOK_DLQ','cdnca.plugin-webhook.dead-letter.v1',
		'plugin-webhook-dlq-v1-' || encode(sha256(convert_to(
			attempt.delivery_id::text || ':' || attempt.attempt_number::text,'UTF8')),'hex'),
		plugin_webhook_dead_letter_payload_sha256_084(attempt.tenant_scope_id,
			attempt.subscription_id,attempt.delivery_id,delivery.event_id,attempt.attempt_number,
			attempt.failure_code,attempt.http_status,attempt.request_sha256,attempt.response_sha256,
			attempt.response_bytes),'pending',attempt.failure_code,attempt.http_status,
		attempt.request_sha256,attempt.response_sha256,attempt.response_bytes,attempt.completed_at
	FROM plugin_webhook_delivery_attempts attempt
	JOIN plugin_webhook_deliveries delivery
	  ON delivery.tenant_scope_id=attempt.tenant_scope_id
	 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
	WHERE attempt.claim_token=$1`, claim, uuid.New(), actorScope, actorUser)
	if err != nil {
		return err
	}
	if err := tx.Commit(t.Context()); err != nil {
		return err
	}
	var tenantScope, subscription, delivery uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_scope_id,subscription_id,delivery_id
		FROM plugin_webhook_delivery_attempts WHERE claim_token=$1`, claim).
		Scan(&tenantScope, &subscription, &delivery); err != nil {
		return err
	}
	return acknowledgePluginWebhookDeadLetter084(t, pool, tenantScope, subscription, delivery, 1)
}

func seedPluginWebhookOrphanDeadLetter084(t *testing.T, pool *pgxpool.Pool, claim uuid.UUID) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	completedAt := pluginWebhookDatabaseTime084(t, tx)
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_delivery_attempts
		SET status='permanent_failure',completed_at=$2,http_status=503,
			failure_code='upstream_permanent_failure',response_sha256=$3,response_bytes=0,
			response_preview=''::bytea,sanitized_headers='{}'::jsonb WHERE claim_token=$1`,
		claim, completedAt, bytes084(32, 0xea)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries delivery
		SET status='dead_lettered',completed_at=$2,next_attempt_at=NULL
		FROM plugin_webhook_delivery_attempts attempt
		WHERE attempt.claim_token=$1 AND delivery.tenant_scope_id=attempt.tenant_scope_id
		  AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id`,
		claim, completedAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func insertPluginWebhookReplayOfResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, original uuid.UUID,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	var eventID uuid.UUID
	var body, digest []byte
	if err := tx.QueryRow(t.Context(), `SELECT event.id,event.canonical_body,event.body_sha256
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		fixture.tenantScope, resource.subscription, original).Scan(&eventID, &body, &digest); err != nil {
		return err
	}
	now := pluginWebhookDatabaseTime084(t, tx)
	delivery, err := insertPluginWebhookDeliveryRow084(t, tx, fixture, resource, eventID, original, now)
	if err != nil {
		return err
	}
	if err := insertPluginWebhookOutbox084(t, tx, fixture, resource, eventID, delivery, body, digest,
		"plugin-webhook-v2-"+hexDigest084("msg-"+delivery.String()), now); err != nil {
		return err
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.delivery.replay",
		resource.subscription, delivery, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func assertPluginWebhookAuditPayloadRejected084(t *testing.T, payload string) {
	t.Helper()
	pool, identity, resource := setupPluginWebhook084(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var position int64
	var previous []byte
	err = tx.QueryRow(t.Context(), `SELECT stream_position,event_hash FROM audit_events
		WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, identity.tenantScope).Scan(&position, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		position, previous, err = 0, nil, nil
	}
	if err != nil {
		t.Fatal(err)
	}
	auditID := uuid.New()
	hash := sha256.Sum256([]byte(auditID.String()))
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,$3,$4,$5,'plugin_webhook',$6,$7,'success',`+payload+`,$9,$10,$11)`,
		auditID, identity.tenantScope, position+1, identity.ownerUser,
		"plugin_webhook.subscription.revoke", auditID.String(), "audit-"+auditID.String(),
		identity.tenantScope, previous, hash[:], pluginWebhook084Now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,response_status,response_body,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$2,$3,'plugin_webhook.subscription.revoke',$4,$5,$6,200,
		jsonb_build_object('subscription_id',$6::uuid::text),$7,$8,$8)`, uuid.New(),
		identity.tenantScope, identity.ownerUser, "audit-extra-"+auditID.String(), bytes084(32, 0xd3),
		resource.subscription, auditID, pluginWebhook084Now); err != nil {
		t.Fatal(err)
	}
	assertPluginWebhookCode084(t, tx.Commit(t.Context()), "P8405")
}

func string084(value string) *string { return &value }

func seedPluginWebhookIdentity084(t *testing.T, pool *pgxpool.Pool) pluginWebhookIdentity084 {
	t.Helper()
	fixture := pluginWebhookIdentity084{
		tenantID: uuid.New(), tenantScope: uuid.New(), foreignTenant: uuid.New(),
		foreignScope: uuid.New(), platformScope: uuid.New(), ownerUser: uuid.New(),
		adminUser: uuid.New(), memberUser: uuid.New(), viewerUser: uuid.New(),
		customUser: uuid.New(), foreignUser: uuid.New(), platformOwner: uuid.New(),
		platformAdmin: uuid.New(), platformReader: uuid.New(), ownerRole: uuid.New(),
		adminRole: uuid.New(), memberRole: uuid.New(), viewerRole: uuid.New(),
		platformRoles: map[string]uuid.UUID{
			"platform_owner": uuid.New(), "platform_admin": uuid.New(), "platform_reader": uuid.New(),
		},
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES
		($1,'Plugin webhook 084'),($2,'Plugin webhook foreign')`, fixture.tenantID, fixture.foreignTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES
		($1,'tenant',$2),($3,'tenant',$4),($5,'platform',NULL)`,
		fixture.tenantScope, fixture.tenantID, fixture.foreignScope, fixture.foreignTenant,
		fixture.platformScope); err != nil {
		t.Fatal(err)
	}
	users := []struct {
		id      uuid.UUID
		name    string
		scopeID uuid.UUID
	}{
		{fixture.ownerUser, "plugin-084-owner", fixture.tenantScope},
		{fixture.adminUser, "plugin-084-admin", fixture.tenantScope},
		{fixture.memberUser, "plugin-084-member", fixture.tenantScope},
		{fixture.viewerUser, "plugin-084-viewer", fixture.tenantScope},
		{fixture.customUser, "plugin-084-custom", fixture.tenantScope},
		{fixture.foreignUser, "plugin-084-foreign", fixture.foreignScope},
		{fixture.platformOwner, "plugin-084-platform-owner", fixture.platformScope},
		{fixture.platformAdmin, "plugin-084-platform-admin", fixture.platformScope},
		{fixture.platformReader, "plugin-084-platform-reader", fixture.platformScope},
	}
	for _, user := range users {
		if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$2,'plugin-webhook-084-unused')`, user.id, user.name); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			user.scopeID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$5,'tenant_owner','owner',true),($2,$5,'tenant_admin','admin',true),
		($3,$5,'tenant_member','member',true),($4,$5,'tenant_viewer','viewer',true),
		($6,$9,'platform_owner','platform owner',true),
		($7,$9,'platform_admin','platform admin',true),
		($8,$9,'platform_reader','platform reader',true)`,
		fixture.ownerRole, fixture.adminRole, fixture.memberRole, fixture.viewerRole,
		fixture.tenantScope, fixture.platformRoles["platform_owner"],
		fixture.platformRoles["platform_admin"], fixture.platformRoles["platform_reader"],
		fixture.platformScope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
		($1,$2,$6),($1,$3,$7),($1,$4,$8),($1,$5,$9),
		($10,$11,$14),($10,$12,$15),($10,$13,$16)`,
		fixture.tenantScope, fixture.ownerUser, fixture.adminUser, fixture.memberUser,
		fixture.viewerUser, fixture.ownerRole, fixture.adminRole, fixture.memberRole,
		fixture.viewerRole, fixture.platformScope, fixture.platformOwner, fixture.platformAdmin,
		fixture.platformReader, fixture.platformRoles["platform_owner"],
		fixture.platformRoles["platform_admin"], fixture.platformRoles["platform_reader"]); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func seedPluginWebhookCustomRole084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	roleID, grantID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_roles(
		id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
		created_by_scope_id,created_at,updated_at
	) VALUES($1,$2,$3,0,'plugin_webhook_manager',$4,$3,$5,$5)`,
		roleID, fixture.tenantID, fixture.tenantScope, fixture.ownerUser, pluginWebhook084Now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,$2,$3,1,'plugin_webhook_manager',
		ARRAY['plugin_webhooks.manage','plugin_webhooks.read'],
		'identity.custom_role.create',$4,$3,$5)`,
		roleID, fixture.tenantID, fixture.tenantScope, fixture.ownerUser, pluginWebhook084Now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$2 WHERE id=$1`,
		roleID, pluginWebhook084Now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var roleActive, subjectActive, actorCanManage, requiresStepUp bool
	var missingPermissions []string
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT deactivated_at IS NULL AND current_revision=1 FROM custom_roles WHERE id=$1),
		(SELECT tenant.status='active' AND account.status='active' AND membership.status='active'
		 FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		 JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
		 JOIN users account ON account.id=membership.user_id
		 WHERE scope.id=$3 AND scope.kind='tenant'),
		custom_rbac_actor_can_manage($3,$4),
		EXISTS(SELECT 1 FROM custom_role_revisions revision
		 JOIN custom_rbac_permission_catalog catalog
		 ON catalog.permission_name=ANY(revision.permissions) AND catalog.step_up_required
		 WHERE revision.role_id=$1 AND revision.revision=1),
		ARRAY(SELECT requested.permission FROM custom_role_revisions revision,
		 unnest(revision.permissions) requested(permission)
		 WHERE revision.role_id=$1 AND revision.revision=1
		 EXCEPT SELECT permission_name FROM custom_rbac_effective_permissions($3,$4))`,
		roleID, fixture.customUser, fixture.tenantScope, fixture.ownerUser).Scan(
		&roleActive, &subjectActive, &actorCanManage, &requiresStepUp, &missingPermissions); err != nil {
		t.Fatal(err)
	}
	if !roleActive || !subjectActive || !actorCanManage || requiresStepUp || len(missingPermissions) != 0 {
		t.Fatalf("custom grant preconditions role/subject/manage/step/missing=%t/%t/%t/%t/%v",
			roleActive, subjectActive, actorCanManage, requiresStepUp, missingPermissions)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7)`,
		grantID, fixture.tenantID, fixture.tenantScope, roleID, fixture.customUser,
		fixture.ownerUser, pluginWebhook084Now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertPluginWebhookEffective084(t, pool, fixture.tenantScope, fixture.customUser, true, true)
	return roleID, grantID
}

func revokePluginWebhookCustomRole084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, grantID uuid.UUID,
) {
	t.Helper()
	var roleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT role_id FROM custom_role_grants WHERE id=$1`, grantID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_grant_revocations(
		id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		revoked_by_user_id,revoked_by_scope_id,revoked_at
	) VALUES($1,$2,$3,$4,$5,1,$6,$7,$4,$8)`,
		uuid.New(), grantID, fixture.tenantID, fixture.tenantScope, roleID,
		fixture.customUser, fixture.ownerUser, pluginWebhook084Now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func insertPluginWebhookGrantRevocation084(ctx context.Context, tx pgx.Tx,
	fixture pluginWebhookIdentity084, roleID, grantID uuid.UUID, revokedAt time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO custom_role_grant_revocations(
		id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		revoked_by_user_id,revoked_by_scope_id,revoked_at
	) VALUES($1,$2,$3,$4,$5,1,$6,$7,$4,$8)`, uuid.New(), grantID, fixture.tenantID,
		fixture.tenantScope, roleID, fixture.customUser, fixture.ownerUser, revokedAt)
	return err
}

func insertPluginWebhookSubscriptionFacts084(ctx context.Context, tx pgx.Tx, tenantScope,
	actorScope, actorUser, subscription, secret uuid.UUID, now time.Time,
) error {
	var recordedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&recordedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_subscriptions(
		id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,
		event_types,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,
		created_at,updated_at
	) VALUES($1,$2,$3,$4,'Webhook linearization','https://hooks.example.com/v1/events',
		'hooks.example.com','/v1/events',ARRAY['io.cdnca.webhook.v1.test'],$5,'active',1,0,0,$6,$6)`,
		subscription, tenantScope, actorScope, actorUser, secret, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,activated_at
	) VALUES($1,$1,$2,$3,$4,$5,1,'active','plugin-webhook-kek-v1',$6,$7,$8,$9,$10,$10)`,
		secret, tenantScope, subscription, actorScope, actorUser,
		pluginWebhookSecretAAD084(tenantScope, subscription, secret, 1, "plugin-webhook-kek-v1"),
		bytes084(12, 0xc2), bytes084(48, 0xc3), bytes084(32, 0xc4), now)
	if err != nil {
		return err
	}
	requestID := uuid.New()
	key := "plugin_webhook.subscription.create-" + requestID.String()
	auditID, err := appendPluginWebhookAuditIdentityTx084(ctx, tx, tenantScope, actorScope, actorUser,
		"plugin_webhook.subscription.create", "success", "accepted", "plugin_webhook_subscription",
		subscription.String(), key, recordedAt)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(key))
	if _, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		subscription_id,response_status,response_body,receipt_wrapping_key_id,receipt_aad_sha256,
		receipt_nonce,receipt_ciphertext,receipt_expires_at,audit_event_id,created_at,completed_at
	) VALUES($1,$2,$3,$4,'plugin_webhook.subscription.create',$5,$6,$7,201,
		jsonb_build_object('subscription_id',$7::uuid::text),'plugin-webhook-kek-v1',$8,$9,$10,$11,
		$12,$13,$14)`, requestID, tenantScope, actorScope, actorUser, key, digest[:], subscription,
		pluginWebhookReceiptAAD084(tenantScope, actorScope, actorUser, key,
			"plugin_webhook.subscription.create", subscription), bytes084(12, 0xc5),
		bytes084(48, 0xc6), now.Add(24*time.Hour), auditID, now, recordedAt); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
	) VALUES($1,$2,NULL,$3,$4,'plugin_webhook.subscription.create','allowed','accepted',$5,$6)`,
		uuid.New(), tenantScope, actorScope, actorUser, auditID, recordedAt)
	return err
}

func waitForPluginWebhookBlock084(t *testing.T, pool *pgxpool.Pool, blockedPID, blockerPID int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $2::integer = ANY(pg_blocking_pids($1::integer))`,
			blockedPID, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d was not blocked by %d: %v", blockedPID, blockerPID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertPluginWebhookFactCounts084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, secret, grantID uuid.UUID, subscriptions, secrets, revocations int,
) {
	t.Helper()
	var foundSubscriptions, foundSecrets, foundRevocations int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2),
		(SELECT count(*) FROM plugin_webhook_secret_versions
		 WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3),
		(SELECT count(*) FROM custom_role_grant_revocations WHERE grant_id=$4)`, tenantScope,
		subscription, secret, grantID).Scan(&foundSubscriptions, &foundSecrets, &foundRevocations); err != nil {
		t.Fatal(err)
	}
	if foundSubscriptions != subscriptions || foundSecrets != secrets || foundRevocations != revocations {
		t.Fatalf("fact counts subscription/secret/revocation=%d/%d/%d want=%d/%d/%d",
			foundSubscriptions, foundSecrets, foundRevocations, subscriptions, secrets, revocations)
	}
}

func insertPluginWebhookSubscription084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	actorScope, actorUser uuid.UUID, now time.Time,
) pluginWebhookResource084 {
	t.Helper()
	resource, err := insertPluginWebhookSubscriptionResult084(t, pool, tenantScope, actorScope, actorUser, now)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func insertPluginWebhookSubscriptionResult084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	actorScope, actorUser uuid.UUID, now time.Time,
) (pluginWebhookResource084, error) {
	t.Helper()
	resource := pluginWebhookResource084{subscription: uuid.New(), secret: uuid.New()}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return pluginWebhookResource084{}, err
	}
	defer tx.Rollback(t.Context())
	if err := insertPluginWebhookSubscriptionFacts084(t.Context(), tx, tenantScope, actorScope,
		actorUser, resource.subscription, resource.secret, now); err != nil {
		return pluginWebhookResource084{}, err
	}
	if err := tx.Commit(t.Context()); err != nil {
		return pluginWebhookResource084{}, err
	}
	return resource, nil
}

func rotatePluginWebhookSecret084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, now time.Time,
) uuid.UUID {
	t.Helper()
	pending := uuid.New()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	now = pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.rotate",
		resource.subscription, pending, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_secret_versions(
		id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,
		wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at
	) VALUES($1,$1,$2,$3,$2,$4,2,'pending','plugin-webhook-kek-v1',$5,$6,$7,$8,$9,$10)`,
		pending, fixture.tenantScope, resource.subscription, fixture.ownerUser,
		pluginWebhookSecretAAD084(fixture.tenantScope, resource.subscription, pending, 2,
			"plugin-webhook-kek-v1"), bytes084(12, 0x52), bytes084(48, 0x53), bytes084(32, 0x54),
		now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.secret.activate",
		resource.subscription, pending, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='retired',retired_at=$4,expires_at=$4::timestamptz + interval '24 hours'
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		fixture.tenantScope, resource.subscription, resource.secret, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_secret_versions
		SET status='active',activated_at=$4,expires_at=NULL
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		fixture.tenantScope, resource.subscription, pending, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`,
		fixture.tenantScope, resource.subscription, pending, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return pending
}

func seedPluginWebhookDelivery084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, now time.Time,
) uuid.UUID {
	t.Helper()
	_, deliveryID := seedPluginWebhookPendingBundle084(t, pool, fixture, resource, now)
	publishPluginWebhookOutbox084(t, pool, fixture.tenantScope, resource.subscription, deliveryID,
		now.Add(time.Second))
	return deliveryID
}

func seedPluginWebhookPendingBundle084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, now time.Time,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	eventID := uuid.Must(uuid.NewV7())
	var sequenceText string
	if err := pool.QueryRow(t.Context(), `SELECT (event_sequence+1)::text
		FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope,
		resource.subscription).Scan(&sequenceText); err != nil {
		t.Fatal(err)
	}
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	body := pluginWebhookCanonicalBody084(t, fixture, resource, eventID, nil, sequence, now)
	digest := sha256.Sum256(body)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err := insertPluginWebhookEvent084(t, tx, fixture, resource, eventID, nil, body, digest[:], now); err != nil {
		t.Fatal(err)
	}
	deliveryID, err := insertPluginWebhookDeliveryRow084(t, tx, fixture, resource, eventID, uuid.Nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertPluginWebhookOutbox084(t, tx, fixture, resource, eventID, deliveryID, body,
		digest[:], "plugin-webhook-v2-"+hexDigest084("msg-"+deliveryID.String()), now); err != nil {
		t.Fatal(err)
	}
	if err := insertPluginWebhookCommandFactsTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.test_delivery.create",
		resource.subscription, deliveryID, now,
		pluginWebhookCommandFacts084{audit: true, write: true, rate: true}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return eventID, deliveryID
}

func publishPluginWebhookOutbox084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, now time.Time,
) {
	t.Helper()
	_ = now
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	token := uuid.New()
	if err := pluginWebhookRuntimeExec084(t, pool, `UPDATE plugin_webhook_outbox
		SET status='leased',lease_token=$4,
			lease_expires_at=clock_timestamp()+interval '1 minute',leased_at=NULL,publish_attempt=1
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`, tenantScope,
		subscription, delivery, token); err != nil {
		t.Fatalf("runtime lease outbox: %v", err)
	}
	deliveryDigest := sha256.Sum256([]byte(delivery.String()))
	sequence := int64(binary.BigEndian.Uint64(deliveryDigest[:8]) & uint64(^uint64(0)>>1))
	if sequence == 0 {
		sequence = 1
	}
	attestPluginWebhookOutbox084(t, pool, attestation, tenantScope, subscription, delivery,
		token, 101, uint64(sequence))
}

func seedPluginWebhookRuntimeAttestation084(t *testing.T,
	pool *pgxpool.Pool,
) pluginWebhookRuntimeAttestation084 {
	t.Helper()
	seed := sha256.Sum256([]byte("plugin-webhook-runtime-attestation-key-084"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	attestation := pluginWebhookRuntimeAttestation084{
		generation:            1,
		keyID:                 "plugin-webhook-runtime-084-key-1",
		privateKey:            privateKey,
		natsDomain:            "",
		deliveryStream:        "PLUGIN_WEBHOOK_DELIVERY",
		deliverySubjectPrefix: "cdnca.plugin-webhook.delivery.v2",
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM plugin_webhook_runtime_attestation_head WHERE singleton=true
	)`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		return attestation
	}
	now := pluginWebhookDatabaseTime084(t, pool)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_runtime_attestation_keys(
		key_generation,key_id,public_key,status,not_before,expires_at
	) VALUES($1,$2,$3,'active',$4,$5)`, attestation.generation, attestation.keyID,
		privateKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO plugin_webhook_runtime_attestation_head(
		singleton,key_generation,key_id,public_key,status,not_before,expires_at,nats_domain,
		delivery_stream,delivery_subject_prefix,dead_letter_stream,dead_letter_subject
	) VALUES(true,$1,$2,$3,'active',$4,$5,$6,$7,$8,'PLUGIN_WEBHOOK_DLQ',
		'cdnca.plugin-webhook.dead-letter.v1')`, attestation.generation, attestation.keyID,
		privateKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(24*time.Hour),
		attestation.natsDomain, attestation.deliveryStream,
		attestation.deliverySubjectPrefix); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return attestation
}

func pluginWebhookRuntimeExec084(t *testing.T, pool *pgxpool.Pool, statement string,
	arguments ...any,
) error {
	t.Helper()
	return pluginWebhookRoleExec084(t, pool, "open084_runtime_login", statement, arguments...)
}

func pluginWebhookRoleExec084(t *testing.T, pool *pgxpool.Pool, login, statement string,
	arguments ...any,
) error {
	t.Helper()
	config := pool.Config().ConnConfig.Copy()
	config.User = login
	connection, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		return err
	}
	defer connection.Close(t.Context())
	tx, err := connection.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	var sessionUser, currentUser string
	if err = tx.QueryRow(t.Context(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser); err != nil {
		return err
	}
	if sessionUser != login || currentUser != sessionUser {
		return fmt.Errorf("database identity=%s/%s want=%s", sessionUser, currentUser, login)
	}
	if _, err = tx.Exec(t.Context(), statement, arguments...); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func attestPluginWebhookOutbox084(t *testing.T, pool *pgxpool.Pool,
	attestation pluginWebhookRuntimeAttestation084, tenantScope, subscription, delivery,
	token uuid.UUID, streamEpoch, sequence uint64,
) {
	t.Helper()
	if err := attestPluginWebhookOutboxResult084(t, pool, attestation, tenantScope,
		subscription, delivery, token, streamEpoch, sequence); err != nil {
		t.Fatalf("attested outbox publish: %v", err)
	}
}

func attestPluginWebhookOutboxResult084(t *testing.T, pool *pgxpool.Pool,
	attestation pluginWebhookRuntimeAttestation084, tenantScope, subscription, delivery,
	token uuid.UUID, streamEpoch, sequence uint64,
) error {
	t.Helper()
	var eventID, outboxID uuid.UUID
	var publishAttempt int64
	var messageID string
	var queueDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT delivery.event_id,outbox.id,
		outbox.publish_attempt::bigint,outbox.message_id,outbox.queue_body_sha256
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id
		 AND outbox.subscription_id=delivery.subscription_id AND outbox.delivery_id=delivery.id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		tenantScope, subscription, delivery).Scan(&eventID, &outboxID, &publishAttempt,
		&messageID, &queueDigest); err != nil {
		return fmt.Errorf("read attested outbox facts: %w", err)
	}
	subject := attestation.deliverySubjectPrefix + "." + tenantScope.String() + "." +
		subscription.String() + "_" + delivery.String()
	fields := [][]byte{
		[]byte("cdnca.plugin-webhook.nats-publication/outbox/v1"),
		[]byte(strconv.FormatInt(attestation.generation, 10)), []byte(attestation.keyID),
		[]byte(attestation.natsDomain), []byte(tenantScope.String()), []byte(subscription.String()),
		[]byte(delivery.String()), []byte(eventID.String()), []byte(outboxID.String()),
		[]byte(token.String()), []byte(strconv.FormatInt(publishAttempt, 10)),
		[]byte(attestation.deliveryStream), []byte(strconv.FormatUint(streamEpoch, 10)),
		[]byte(subject), []byte(strconv.FormatUint(sequence, 10)), []byte(messageID),
		[]byte(fmt.Sprintf("%x", queueDigest)), []byte("0"),
	}
	digest := sha256.Sum256(pluginWebhookAttestationFrame084(fields))
	signature := ed25519.Sign(attestation.privateKey, digest[:])
	config := pool.Config().ConnConfig.Copy()
	config.User = "open084_runtime_login"
	connection, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		return err
	}
	defer connection.Close(t.Context())
	tx, err := connection.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	var sessionUser, currentUser string
	if err = tx.QueryRow(t.Context(), `SELECT session_user,current_user`).Scan(
		&sessionUser, &currentUser); err != nil {
		return err
	}
	if sessionUser != "open084_runtime_login" || currentUser != sessionUser {
		return fmt.Errorf("runtime database identity=%s/%s", sessionUser, currentUser)
	}
	if _, err = tx.Exec(t.Context(), `SELECT publish_plugin_webhook_outbox_084(
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
	)`, tenantScope, subscription, delivery, token, attestation.natsDomain,
		attestation.deliveryStream, strconv.FormatUint(streamEpoch, 10), subject,
		strconv.FormatUint(sequence, 10), messageID, queueDigest, 0,
		attestation.generation, attestation.keyID, signature); err != nil {
		return err
	}
	if err = tx.Commit(t.Context()); err != nil {
		return err
	}
	return nil
}

func pluginWebhookAttestationFrame084(fields [][]byte) []byte {
	length := 0
	for _, field := range fields {
		length += 4 + len(field)
	}
	framed := make([]byte, 0, length)
	var size [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		framed = append(framed, size[:]...)
		framed = append(framed, field...)
	}
	return framed
}

func seedPluginWebhookEntitlement084(t *testing.T, pool *pgxpool.Pool, feature bool,
	quota int64, revoked []uint64,
) {
	t.Helper()
	now := pluginWebhookDatabaseTime084(t, pool).Truncate(time.Second)
	installationID := "22222222-2222-4222-8222-222222222222"
	customerID := "11111111-1111-4111-8111-111111111111"
	licenseID := "33333333-3333-4333-8333-333333333333"
	keyID := "plugin-webhook-entitlement-key-084"
	seed := sha256.Sum256([]byte("plugin-webhook-entitlement-test-key-084"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signer := pluginWebhookEntitlementSigner084{keyID: keyID, private: privateKey}
	features := []entitlement.Feature{}
	if feature {
		features = append(features, entitlement.Feature{Code: entitlement.FeatureExtensionsWebhooks})
	}
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: customerID, InstallationID: installationID, LicenseID: licenseID,
		Serial: 1, NotBefore: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:   features,
		Quotas:     []entitlement.Quota{{Code: entitlement.QuotaExtensionsWebhooksCount, Limit: quota}},
	}
	signedLease, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	encodedLease, err := signedLease.Encode()
	if err != nil {
		t.Fatal(err)
	}
	revocation := entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: customerID, InstallationID: installationID, LicenseID: licenseID, Revision: 1,
		IssuedAt:       now.Add(-time.Second).Unix(),
		ExpiresAt:      now.Add(-time.Second).Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: append([]uint64{}, revoked...),
	}
	verifyUntil := time.Unix(revocation.ExpiresAt, 0).UTC()
	signedRevocation, err := entitlement.SignRevocationSet(t.Context(), revocation, signer,
		entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &verifyUntil,
			VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signedRevocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := entitlement.RevocationSetDigest(artifact)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_installation_entitlement(
		singleton,installation_id,current_serial,last_status,last_verified_at
	) VALUES(true,$1,NULL,'uninstalled',$2)`, installationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO entitlement_verification_keys(
		key_id,public_key,first_seen_at,updated_at
	) VALUES($1,$2,$3,$3)`, keyID, publicKey, now); err != nil {
		t.Fatal(err)
	}
	keyFingerprint := sha256.Sum256(publicKey)
	keyNotBefore := now.Add(-time.Hour)
	keyUntil := now.Add(24 * time.Hour)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		keyID, keyID, base64.RawURLEncoding.EncodeToString(publicKey),
		base64.RawURLEncoding.EncodeToString(keyFingerprint[:]),
		keyNotBefore.Format(time.RFC3339Nano), keyUntil.Format(time.RFC3339Nano),
		keyUntil.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if _, err := tx.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,
		accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, keyID,
		keysetPayload, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, keyID, publicKey, keyNotBefore,
		keyUntil, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO entitlement_cached_leases(
		serial,installation_id,customer_id,license_id,key_id,signed_lease,status,
		not_before,expires_at,grace_until,verified_at,installed_at
	) VALUES(1,$1,$2,$3,$4,$5,'valid',$6,$7,$8,$9,$9)`, installationID, customerID,
		licenseID, keyID, encodedLease, time.Unix(lease.NotBefore, 0).UTC(),
		time.Unix(lease.ExpiresAt, 0).UTC(), time.Unix(lease.GraceUntil, 0).UTC(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control_installation_entitlement
		SET current_serial=1,last_status='valid',last_verified_at=$2,updated_at=$2
		WHERE singleton=true AND installation_id=$1`, installationID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO control_entitlement_revocation_lkg(
		singleton,installation_id,customer_id,license_id,revision,key_id,artifact,
		artifact_sha256,artifact_etag,issued_at,expires_at,accepted_at
	) VALUES(true,$1,$2,$3,1,$4,$5,$6,$7,$8,$9,$8)`, installationID, customerID, licenseID,
		keyID, artifact, digest[:], entitlement.RevocationSetETag(artifact),
		time.Unix(revocation.IssuedAt, 0).UTC(), time.Unix(revocation.ExpiresAt, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	for _, serial := range revoked {
		if _, err := tx.Exec(t.Context(), `INSERT INTO control_entitlement_revoked_serials(
			installation_id,license_id,serial,first_revision,first_artifact_sha256,recorded_at
		) VALUES($1,$2,$3,1,$4,$5)`, installationID, licenseID, serial, digest[:], now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func pluginWebhookSignedRevocation084(t *testing.T, revision uint64, issuedAt time.Time,
	revoked []uint64,
) ([]byte, [sha256.Size]byte, string, time.Time) {
	t.Helper()
	seed := sha256.Sum256([]byte("plugin-webhook-entitlement-test-key-084"))
	signer := pluginWebhookEntitlementSigner084{
		keyID: "plugin-webhook-entitlement-key-084", private: ed25519.NewKeyFromSeed(seed[:]),
	}
	expiresAt := issuedAt.Add(entitlement.RevocationSetWindow)
	signed, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333",
		Revision:       revision, IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		RevokedSerials: append([]uint64{}, revoked...),
	}, signer, entitlement.RevocationKeyWindow{
		NotBefore: issuedAt.Add(-time.Hour), SignUntil: &expiresAt, VerifyUntil: &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return artifact, entitlement.RevocationSetDigest(artifact),
		entitlement.RevocationSetETag(artifact), expiresAt
}

func pluginWebhookRawSignedRevocation084(t *testing.T, issuedAt time.Time,
	rawRevision, rawSerials string,
) ([]byte, [sha256.Size]byte, string) {
	t.Helper()
	keyID := "plugin-webhook-entitlement-key-084"
	seed := sha256.Sum256([]byte("plugin-webhook-entitlement-test-key-084"))
	body := `{"schema":"cdnca.entitlement.revocation-set/v2",` +
		`"audience":"cdnca-control-plane",` +
		`"customer_id":"11111111-1111-4111-8111-111111111111",` +
		`"installation_id":"22222222-2222-4222-8222-222222222222",` +
		`"license_id":"33333333-3333-4333-8333-333333333333",` +
		`"revision":` + rawRevision + `,"issued_at":` + strconv.FormatInt(issuedAt.Unix(), 10) +
		`,"expires_at":` + strconv.FormatInt(issuedAt.Add(entitlement.RevocationSetWindow).Unix(), 10) +
		`,"revoked_serials":` + rawSerials + `}`
	signingDocument := []byte(`{"domain":"cdnca-entitlement-revocation-set-signature/v2",` +
		`"algorithm":"Ed25519","key_id":"` + keyID + `","body":` + body + `}`)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), signingDocument)
	artifact := []byte(`{"algorithm":"Ed25519","key_id":"` + keyID + `","body":` + body +
		`,"signature":"` + base64.RawURLEncoding.EncodeToString(signature) + `"}`)
	digest := sha256.Sum256(artifact)
	return artifact, digest, `"sha256-` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
}

func assertPluginWebhookDeliveryOutboxStatuses084(t *testing.T, pool *pgxpool.Pool, tenantScope,
	subscription, delivery uuid.UUID, deliveryStatus, outboxStatus string,
) {
	t.Helper()
	var foundDelivery, foundOutbox string
	if err := pool.QueryRow(t.Context(), `SELECT delivery.status,outbox.status
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_outbox outbox
		  ON outbox.tenant_scope_id=delivery.tenant_scope_id
		 AND outbox.subscription_id=delivery.subscription_id AND outbox.delivery_id=delivery.id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		tenantScope, subscription, delivery).Scan(&foundDelivery, &foundOutbox); err != nil {
		t.Fatal(err)
	}
	if foundDelivery != deliveryStatus || foundOutbox != outboxStatus {
		t.Fatalf("delivery/outbox status=%s/%s want=%s/%s", foundDelivery, foundOutbox,
			deliveryStatus, outboxStatus)
	}
}

func claimPluginWebhookDelivery084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, resource pluginWebhookResource084, delivery uuid.UUID,
	now time.Time,
) uuid.UUID {
	t.Helper()
	claim, err := insertPluginWebhookClaim084(t, pool, fixture, resource, delivery, now)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func revokePluginWebhookSubscription084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, now time.Time,
) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	now = pluginWebhookDatabaseTime084(t, tx)
	if err := insertPluginWebhookManagementRequestTx084(t.Context(), t, tx, fixture,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.subscription.revoke",
		subscription, uuid.Nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_subscriptions
		SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,
			revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.tenantScope, subscription, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func insertPluginWebhookRate084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, now time.Time, allowed bool,
) {
	t.Helper()
	if err := insertPluginWebhookRateResult084(t, pool, fixture, subscription, now, allowed); err != nil {
		t.Fatal(err)
	}
}

func insertPluginWebhookRateResult084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084, subscription uuid.UUID, now time.Time, allowed bool,
) error {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(t.Context())
	recordedAt := pluginWebhookDatabaseTime084(t, tx)
	outcome, result, reason := "denied", "denied", "rate_limited"
	if allowed {
		outcome, result, reason = "allowed", "success", "accepted"
	}
	rateID := uuid.New()
	auditID, err := appendPluginWebhookAuditIdentityTx084(t.Context(), tx, fixture.tenantScope,
		fixture.tenantScope, fixture.ownerUser, "plugin_webhook.test_delivery.create",
		result, reason, "plugin_webhook_subscription", subscription.String(),
		"rate-"+rateID.String(), recordedAt)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_webhook_rate_events(
		id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,
		reason_code,audit_event_id,occurred_at
		) VALUES($1,$2,$3,$2,$4,'plugin_webhook.test_delivery.create',$5,$6,$7,$8)`,
		rateID, fixture.tenantScope, subscription, fixture.ownerUser, outcome, reason,
		auditID, recordedAt); err != nil {
		return err
	}
	return tx.Commit(t.Context())
}

func appendPluginWebhookAudit084(t *testing.T, pool *pgxpool.Pool, targetScope, actorScope,
	actorUser uuid.UUID, action, result, reason string, now time.Time,
) uuid.UUID {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	id, err := appendPluginWebhookAuditTx084(t.Context(), tx, targetScope, actorScope,
		actorUser, action, result, reason, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return id
}

func appendPluginWebhookAuditTx084(ctx context.Context, tx pgx.Tx, targetScope, actorScope,
	actorUser uuid.UUID, action, result, reason string, now time.Time,
) (uuid.UUID, error) {
	var position int64
	var previous []byte
	err := tx.QueryRow(ctx, `SELECT stream_position,event_hash FROM audit_events
		WHERE scope_id=$1 ORDER BY stream_position DESC LIMIT 1`, targetScope).Scan(&position, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		position, previous, err = 0, nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	hash := sha256.Sum256([]byte(id.String()))
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,$3,$4,$5,'plugin_webhook',$6,$7,$8,
		jsonb_build_object('actor_scope_id',$9::uuid::text,'target_scope_id',$2::uuid::text,
			'operation',$5::text,'reason',$10::text),$11,$12,$13)`,
		id, targetScope, position+1, actorUser, action, id.String(), "audit-"+id.String(),
		result, actorScope, reason, previous, hash[:], now)
	return id, err
}

func assertPluginWebhookRoleGrants084(t *testing.T, pool *pgxpool.Pool,
	fixture pluginWebhookIdentity084,
) {
	t.Helper()
	checks := []struct {
		roleID uuid.UUID
		read   bool
		manage bool
	}{
		{fixture.ownerRole, true, true}, {fixture.adminRole, true, true},
		{fixture.memberRole, true, false}, {fixture.viewerRole, true, false},
		{fixture.platformRoles["platform_owner"], true, true},
		{fixture.platformRoles["platform_admin"], true, true},
		{fixture.platformRoles["platform_reader"], false, false},
	}
	for _, check := range checks {
		for permission, want := range map[string]bool{
			"plugin_webhooks.read": check.read, "plugin_webhooks.manage": check.manage,
		} {
			var got bool
			if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
				WHERE role_id=$1 AND permission_name=$2)`, check.roleID, permission).Scan(&got); err != nil || got != want {
				t.Fatalf("role=%s permission=%s got=%t want=%t err=%v", check.roleID, permission, got, want, err)
			}
		}
	}
}

func assertPluginWebhookEffective084(t *testing.T, pool *pgxpool.Pool, scope, user uuid.UUID,
	wantRead, wantManage bool,
) {
	t.Helper()
	for permission, want := range map[string]bool{
		"plugin_webhooks.read": wantRead, "plugin_webhooks.manage": wantManage,
	} {
		var got bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3
		)`, scope, user, permission).Scan(&got); err != nil || got != want {
			t.Fatalf("effective user=%s permission=%s got=%t want=%t err=%v", user, permission, got, want, err)
		}
	}
}

func assertPluginWebhookDeliveryStatus084(t *testing.T, pool *pgxpool.Pool,
	tenantScope, subscription, delivery uuid.UUID, want string,
) {
	t.Helper()
	var got string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
		tenantScope, subscription, delivery).Scan(&got); err != nil || got != want {
		t.Fatalf("delivery status=%q want=%q err=%v", got, want, err)
	}
}

func assertPluginWebhookTables084(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	tables := []string{
		"plugin_webhook_rbac_catalog_additions_084", "plugin_webhook_rbac_grant_additions_084",
		"plugin_webhook_subscriptions", "plugin_webhook_secret_versions",
		"plugin_webhook_write_requests", "plugin_webhook_events", "plugin_webhook_deliveries",
		"plugin_webhook_outbox", "plugin_webhook_delivery_attempts",
		"plugin_webhook_dead_letters", "plugin_webhook_rate_events",
		"plugin_webhook_entitlement_decisions", "control_entitlement_revocation_lkg",
		"control_entitlement_revoked_serials", "entitlement_signing_keyset_current_keys",
		"plugin_webhook_runtime_attestation_keys", "plugin_webhook_runtime_attestation_head",
	}
	for _, table := range tables {
		var got bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&got); err != nil || got != want {
			t.Fatalf("table %s exists=%t want=%t err=%v", table, got, want, err)
		}
	}
}

func assertPluginWebhookColumnContracts084(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var numericColumns, publicTables, permissionCount int
	var retryDelayColumn bool
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name LIKE 'plugin_webhook_%'
		  AND data_type='numeric' AND numeric_precision=20 AND numeric_scale=0`).Scan(&numericColumns); err != nil {
		t.Fatal(err)
	}
	if numericColumns != 30 {
		t.Fatalf("UInt64-compatible NUMERIC(20,0) columns=%d want 30", numericColumns)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.tables
		WHERE table_schema=current_schema() AND table_name LIKE 'plugin_webhook_%'
		  AND has_table_privilege('public',table_name,'SELECT')`).Scan(&publicTables); err != nil || publicTables != 0 {
		t.Fatalf("PUBLIC-readable plugin webhook tables=%d want 0 err=%v", publicTables, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM permissions
		WHERE name IN ('plugin_webhooks.read','plugin_webhooks.manage')`).Scan(&permissionCount); err != nil || permissionCount != 2 {
		t.Fatalf("plugin webhook permissions=%d want 2 err=%v", permissionCount, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='plugin_webhook_delivery_attempts'
		  AND column_name='retry_delay_seconds' AND data_type='integer'
	)`).Scan(&retryDelayColumn); err != nil || !retryDelayColumn {
		t.Fatalf("server retry delay column exists=%t want=true err=%v", retryDelayColumn, err)
	}
	var maximumAccepted, overflowRejected bool
	if err := pool.QueryRow(t.Context(), `SELECT
		plugin_webhook_u64_084(18446744073709551615),
		NOT plugin_webhook_u64_084(18446744073709551616)`).Scan(
		&maximumAccepted, &overflowRejected); err != nil || !maximumAccepted || !overflowRejected {
		t.Fatalf("UInt64 maximum/overflow=%t/%t want true/true err=%v",
			maximumAccepted, overflowRejected, err)
	}
}

func pluginWebhookFunctionSource084(t *testing.T, pool *pgxpool.Pool, signature string) string {
	t.Helper()
	var source string
	if err := pool.QueryRow(t.Context(), `SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure($1)`,
		signature).Scan(&source); err != nil {
		t.Fatal(err)
	}
	return source
}

func assertPluginWebhookHead084(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var count, minimum, maximum int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(min(version),0),COALESCE(max(version),0)
		FROM schema_migrations`).Scan(&count, &minimum, &maximum); err != nil {
		t.Fatal(err)
	}
	if count != want || minimum != 1 || maximum != want {
		t.Fatalf("migration ledger count/min/max=%d/%d/%d want=%d/1/%d", count, minimum, maximum, want, want)
	}
}

func assertPluginWebhookCode084(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v want code=%s", err, want)
	}
}

func pgErrCodeFromError084(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	return pgErr.Code
}

func assertPluginWebhookConstraint084(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code || pgErr.ConstraintName != constraint {
		t.Fatalf("PostgreSQL error=%v code/constraint=%s/%s want=%s/%s",
			err, pgErrCode084(pgErr), pgErrConstraint084(pgErr), code, constraint)
	}
}

func assertPluginWebhookPublicExecute084(t *testing.T, pool *pgxpool.Pool, signature string, want bool) {
	t.Helper()
	var found, allowed bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regprocedure($1) IS NOT NULL,
		EXISTS (
			SELECT 1 FROM pg_proc procedure,
			LATERAL aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) privilege
			WHERE procedure.oid=to_regprocedure($1) AND privilege.grantee=0
			  AND privilege.privilege_type='EXECUTE'
		)`, signature).Scan(&found, &allowed); err != nil {
		t.Fatal(err)
	}
	if !found || allowed != want {
		t.Fatalf("function %s found/public execute=%t/%t want=true/%t", signature, found, allowed, want)
	}
}

func pgErrCode084(err *pgconn.PgError) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func pgErrConstraint084(err *pgconn.PgError) string {
	if err == nil {
		return ""
	}
	return err.ConstraintName
}

func bytes084(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func hexDigest084(value string) string {
	digest := sha256.Sum256([]byte(value))
	const alphabet = "0123456789abcdef"
	result := make([]byte, 64)
	for index, item := range digest {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0x0f]
	}
	return string(result)
}
