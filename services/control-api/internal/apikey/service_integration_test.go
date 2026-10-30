package apikey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type apiKeyTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *apiKeyTestClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *apiKeyTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

type apiKeyIntegrationFixture struct {
	pool    *pgxpool.Pool
	service *Service
	clock   *apiKeyTestClock
	admin   identity.Principal
	alice   identity.Principal
	bob     identity.Principal
}

func TestAPIKeyDatabaseLifecycleInvariants(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()
	issued := mustCreateSelfKey(t, fixture, "db-invariant-create")
	standaloneID := uuid.New()
	standaloneKeyID, err := randomKeyID()
	if err != nil {
		t.Fatalf("create standalone key ID: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO api_keys (
			id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,pepper_version,status,
			activated_at,created_by_user_id,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,'standalone',ARRAY['sites.read'],
			decode(repeat('44',32),'hex'),'legacy-v1','active',$7,$6,$7,$7)`,
		standaloneID, standaloneKeyID, standaloneKeyID+".", fixture.alice.ScopeID,
		*fixture.alice.TenantID, fixture.alice.UserID, fixture.clock.Now()); err != nil {
		t.Fatalf("insert standalone canonical API key: %v", err)
	}

	for name, statement := range map[string]string{
		"id":                 `UPDATE api_keys SET id=$2 WHERE id=$1`,
		"key identity":       `UPDATE api_keys SET key_id='cfk_BBBBBBBBBBBBBBBBBBBBBB', key_prefix='cfk_BBBBBBBBBBBBBBBBBBBBBB.' WHERE id=$1`,
		"ownership":          `UPDATE api_keys SET scope_id=$2, tenant_id=$3, user_id=$4 WHERE id=$1`,
		"creator":            `UPDATE api_keys SET created_by_user_id=$2 WHERE id=$1`,
		"creation time":      `UPDATE api_keys SET created_at=created_at-interval '1 second' WHERE id=$1`,
		"secret":             `UPDATE api_keys SET secret_digest=decode(repeat('ab',32),'hex') WHERE id=$1`,
		"status":             `UPDATE api_keys SET status='revoked', revoked_at=updated_at, revoked_by_user_id=user_id WHERE id=$1`,
		"revision jump":      `UPDATE api_keys SET name='revision jump', revision=revision+2, updated_at=updated_at+interval '1 second' WHERE id=$1`,
		"time reversal":      `UPDATE api_keys SET name='time reversal', revision=revision+1, updated_at=updated_at-interval '1 second' WHERE id=$1`,
		"activation rewrite": `UPDATE api_keys SET name='activation rewrite', activated_at=activated_at+interval '1 second', revision=revision+1, updated_at=updated_at+interval '1 second' WHERE id=$1`,
	} {
		t.Run("rejects immutable "+name, func(t *testing.T) {
			arguments := []any{standaloneID}
			switch name {
			case "id":
				arguments = append(arguments, uuid.New())
			case "ownership":
				arguments = append(arguments, fixture.bob.ScopeID, *fixture.bob.TenantID, fixture.bob.UserID)
			case "creator":
				arguments = append(arguments, fixture.bob.UserID)
			}
			expectAPIKeySQLRejected(t, fixture.pool, statement, arguments...)
		})
	}

	t.Run("creation facts must be canonical", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `
			INSERT INTO api_keys (
				id, key_id, key_prefix, scope_id, tenant_id, user_id, name, scopes,
				secret_digest, pepper_version, status, activated_at, created_by_user_id, revision, created_at, updated_at
			) VALUES ($1,'cfk_CCCCCCCCCCCCCCCCCCCCCC','cfk_CCCCCCCCCCCCCCCCCCCCCC.',$2,$3,$4,
				'noncanonical',ARRAY['sites.read'],decode(repeat('cd',32),'hex'),'legacy-v1','active',$5,$4,2,$5,$5)`,
			uuid.New(), fixture.alice.ScopeID, *fixture.alice.TenantID, fixture.alice.UserID, fixture.clock.Now())
	})

	t.Run("usage is a separate monotonic path", func(t *testing.T) {
		firstUsed := fixture.clock.Now()
		if _, err := fixture.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, issued.Key.ID, firstUsed); err != nil {
			t.Fatalf("valid usage-only update failed: %v", err)
		}
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, issued.Key.ID, firstUsed.Add(-time.Second))
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_keys SET last_used_at=$2, name='usage smuggle' WHERE id=$1`, issued.Key.ID, firstUsed.Add(time.Second))
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_keys SET last_used_at=$2, revision=revision+1 WHERE id=$1`, issued.Key.ID, firstUsed.Add(time.Second))

		expiring := mustCreateSelfKeyWithExpiry(t, fixture, "db-expiring-create", fixture.clock.Now().Add(time.Minute))
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, expiring.Key.ID, fixture.clock.Now().Add(2*time.Minute))
	})

	t.Run("revoked state is terminal", func(t *testing.T) {
		revoked, err := fixture.service.RevokeSelf(ctx, fixture.alice, MutationInput{
			ID: issued.Key.ID, ExpectedRevision: issued.Key.Revision,
			IdempotencyKey: "db-invariant-revoke", RequestID: "db-invariant-revoke",
		})
		if err != nil {
			t.Fatalf("revoke key: %v", err)
		}
		expectAPIKeySQLRejected(t, fixture.pool, `
			UPDATE api_keys SET status='active', revoked_at=NULL, revoked_by_user_id=NULL,
				revision=revision+1, updated_at=updated_at+interval '1 second'
			WHERE id=$1`, revoked.ID)
		expectAPIKeySQLRejected(t, fixture.pool, `
			UPDATE api_keys SET name='revoked rewrite', revision=revision+1,
				updated_at=updated_at+interval '1 second' WHERE id=$1`, revoked.ID)
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_keys SET last_used_at=updated_at+interval '1 second' WHERE id=$1`, revoked.ID)
	})

	t.Run("delete and truncate are forbidden", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `DELETE FROM api_keys WHERE id=$1`, standaloneID)
		expectAPIKeySQLRejected(t, fixture.pool, `TRUNCATE api_keys CASCADE`)
	})
}

func TestAPIKeyWriteRequestInvariants(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()
	issued := mustCreateSelfKey(t, fixture, "write-request-key")

	t.Run("completed insert is rejected", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `
			INSERT INTO api_key_write_requests (
				id, actor_user_id, actor_scope_id, target_scope_id, target_user_id,
				operation, idempotency_key, request_digest, resource_id, response_body,
				created_at, completed_at
			) VALUES ($1,$2,$3,$3,$2,'api_key.self.update','forged-completed',
				decode(repeat('11',32),'hex'),$4,'{}'::jsonb,$5,$5)`,
			uuid.New(), fixture.alice.UserID, fixture.alice.ScopeID, issued.Key.ID, fixture.clock.Now())
	})

	t.Run("cross-tenant self request is rejected", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `
			INSERT INTO api_key_write_requests (
				id, actor_user_id, actor_scope_id, target_scope_id, target_user_id,
				operation, idempotency_key, request_digest, created_at
			) VALUES ($1,$2,$3,$4,$5,'api_key.self.create','cross-tenant-self',
				decode(repeat('55',32),'hex'),$6)`,
			uuid.New(), fixture.alice.UserID, fixture.alice.ScopeID,
			fixture.bob.ScopeID, fixture.bob.UserID, fixture.clock.Now())
	})

	requestID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO api_key_write_requests (
			id, actor_user_id, actor_scope_id, target_scope_id, target_user_id,
			operation, idempotency_key, request_digest, created_at, pepper_version
		) VALUES ($1,$2,$3,$3,$2,'api_key.self.update','direct-unfinished',
			decode(repeat('22',32),'hex'),$4,'legacy-v1')`,
		requestID, fixture.alice.UserID, fixture.alice.ScopeID, fixture.clock.Now()); err != nil {
		t.Fatalf("insert unfinished write request: %v", err)
	}

	t.Run("request facts are immutable", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_key_write_requests SET actor_user_id=$2, actor_scope_id=$3 WHERE id=$1`,
			requestID, fixture.bob.UserID, fixture.bob.ScopeID)
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_key_write_requests SET target_user_id=$2, target_scope_id=$3 WHERE id=$1`,
			requestID, fixture.bob.UserID, fixture.bob.ScopeID)
		expectAPIKeySQLRejected(t, fixture.pool,
			`UPDATE api_key_write_requests SET request_digest=decode(repeat('33',32),'hex') WHERE id=$1`, requestID)
	})

	t.Run("completion cannot persist a secret field", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `
			UPDATE api_key_write_requests
			SET resource_id=$2::uuid, response_body=jsonb_build_object(
				'id',$2::text,'secret','redacted-test-value'), completed_at=$3
			WHERE id=$1`, requestID, issued.Key.ID, fixture.clock.Now())
	})

	if _, err := fixture.pool.Exec(ctx, `
		UPDATE api_key_write_requests
		SET resource_id=$2::uuid, response_body=jsonb_build_object('id',$2::text), completed_at=$3
		WHERE id=$1`, requestID, issued.Key.ID, fixture.clock.Now()); err != nil {
		t.Fatalf("complete write request once: %v", err)
	}

	t.Run("completion is one shot", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `
			UPDATE api_key_write_requests SET response_body=jsonb_build_object('id',$2::text),
				completed_at=$3 WHERE id=$1`, requestID, issued.Key.ID, fixture.clock.Now().Add(time.Second))
	})

	t.Run("delete and truncate are forbidden", func(t *testing.T) {
		expectAPIKeySQLRejected(t, fixture.pool, `DELETE FROM api_key_write_requests WHERE id=$1`, requestID)
		expectAPIKeySQLRejected(t, fixture.pool, `TRUNCATE api_key_write_requests`)
	})
}

func TestAPIKeyServiceLifecycleAndIsolation(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()
	issued := mustCreateSelfKey(t, fixture, "service-create")
	if issued.Secret == "" || issued.Key.Status != StatusActive || issued.Key.Revision != 1 {
		t.Fatal("self create did not return an active revision-one key and one-time secret")
	}

	var secretInKey, secretInWrite, secretInAudit bool
	if err := fixture.pool.QueryRow(ctx, `
		SELECT position($2 in encode(k.secret_digest,'escape')) > 0,
		       position($2 in w.response_body::text) > 0,
		       EXISTS (SELECT 1 FROM audit_events a WHERE a.resource_id=k.id::text AND position($2 in a.payload::text) > 0)
		FROM api_keys k
		JOIN api_key_write_requests w ON w.resource_id=k.id AND w.operation='api_key.self.create'
		WHERE k.id=$1`, issued.Key.ID, issued.Secret).Scan(&secretInKey, &secretInWrite, &secretInAudit); err != nil {
		t.Fatalf("inspect persisted credential material: %v", err)
	}
	if secretInKey || secretInWrite || secretInAudit {
		t.Fatal("one-time API key secret was persisted")
	}

	updated, err := fixture.service.UpdateSelf(ctx, fixture.alice, UpdateInput{
		ID: issued.Key.ID, ExpectedRevision: 1, Name: "updated key", Scopes: []string{"sites.manage"},
		ExpiresAt: issued.Key.ExpiresAt, IdempotencyKey: "service-update", RequestID: "service-update",
	})
	if err != nil || updated.Revision != 2 || updated.Name != "updated key" {
		t.Fatalf("update active key failed: revision=%d err=%v", updated.Revision, err)
	}
	if _, err := fixture.service.Authenticate(ctx, issued.Key.KeyID+"."+issued.Secret); err != nil {
		t.Fatalf("authenticate credential before rotation: %v", err)
	}
	usedBeforeRotation := fixture.clock.Now().Add(time.Minute)
	if _, err := fixture.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=$2 WHERE id=$1`,
		issued.Key.ID, usedBeforeRotation); err != nil {
		t.Fatalf("seed historical usage before rotation: %v", err)
	}
	fixture.clock.Advance(time.Minute)

	rotated, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: issued.Key.ID, ExpectedRevision: 2, IdempotencyKey: "service-rotate", RequestID: "service-rotate",
	})
	if err != nil || rotated.Key.Revision != 3 || rotated.Secret == "" || rotated.Secret == issued.Secret {
		t.Fatalf("rotate active key failed: revision=%d has_secret=%v changed=%v err=%v",
			rotated.Key.Revision, rotated.Secret != "", rotated.Secret != issued.Secret, err)
	}
	if rotated.Key.LastUsedAt == nil || !rotated.Key.LastUsedAt.Equal(usedBeforeRotation) {
		t.Fatal("rotation did not preserve last_used_at")
	}
	if _, err := fixture.service.Authenticate(ctx, issued.Key.KeyID+"."+issued.Secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("old credential after rotation error=%v", err)
	}
	if _, err := fixture.service.Authenticate(ctx, rotated.Key.KeyID+"."+rotated.Secret); err != nil {
		t.Fatalf("authenticate rotated credential: %v", err)
	}
	var usageAfterAuth time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT last_used_at FROM api_keys WHERE id=$1`, issued.Key.ID).
		Scan(&usageAfterAuth); err != nil {
		t.Fatalf("read usage after authentication: %v", err)
	}
	if !usageAfterAuth.Equal(usedBeforeRotation) {
		t.Fatalf("authentication changed disconnected usage telemetry to %v", usageAfterAuth)
	}
	fixture.clock.Advance(6 * time.Minute)
	if _, err := fixture.service.Authenticate(ctx, rotated.Key.KeyID+"."+rotated.Secret); err != nil {
		t.Fatalf("authenticate rotated credential again: %v", err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT last_used_at FROM api_keys WHERE id=$1`, issued.Key.ID).
		Scan(&usageAfterAuth); err != nil {
		t.Fatalf("read usage after repeated authentication: %v", err)
	}
	if !usageAfterAuth.Equal(usedBeforeRotation) {
		t.Fatalf("repeated authentication changed disconnected usage telemetry to %v", usageAfterAuth)
	}

	revoked, err := fixture.service.RevokeSelf(ctx, fixture.alice, MutationInput{
		ID: issued.Key.ID, ExpectedRevision: 3, IdempotencyKey: "service-revoke", RequestID: "service-revoke",
	})
	if err != nil || revoked.Status != StatusRevoked || revoked.Revision != 4 {
		t.Fatalf("revoke active key failed: status=%s revision=%d err=%v", revoked.Status, revoked.Revision, err)
	}
	if revoked.LastUsedAt == nil || !revoked.LastUsedAt.Equal(usedBeforeRotation) {
		t.Fatal("revoke did not preserve the historical usage timestamp")
	}
	if _, err := fixture.service.Authenticate(ctx, rotated.Key.KeyID+"."+rotated.Secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("revoked credential error=%v", err)
	}

	pending, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "admin pending", Scopes: []string{"sites.read"},
		PendingTTL: time.Hour, IdempotencyKey: "admin-pending", RequestID: "admin-pending",
	})
	if err != nil || pending.Status != StatusPendingActivation || pending.Revision != 1 {
		t.Fatalf("admin pending create failed: status=%s revision=%d err=%v", pending.Status, pending.Revision, err)
	}
	if _, err := fixture.service.UpdateSelf(ctx, fixture.alice, UpdateInput{
		ID: pending.ID, ExpectedRevision: 1, Name: "pending rewrite", Scopes: []string{"sites.read"},
		IdempotencyKey: "pending-update", RequestID: "pending-update",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pending metadata update error=%v", err)
	}
	activated, err := fixture.service.ActivateSelf(ctx, fixture.alice, MutationInput{
		ID: pending.ID, ExpectedRevision: 1, IdempotencyKey: "pending-activate", RequestID: "pending-activate",
	})
	if err != nil || activated.Key.Status != StatusActive || activated.Key.Revision != 2 || activated.Secret == "" {
		t.Fatalf("target activation failed: status=%s revision=%d has_secret=%v err=%v",
			activated.Key.Status, activated.Key.Revision, activated.Secret != "", err)
	}
	if _, err := fixture.service.AdminRevoke(ctx, fixture.admin, AdminRevokeInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		ID: pending.ID, ExpectedRevision: 2,
		IdempotencyKey: "admin-revoke", RequestID: "admin-revoke",
	}); err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	if _, err := fixture.service.ActivateSelf(ctx, fixture.admin, MutationInput{
		ID: pending.ID, ExpectedRevision: 3, IdempotencyKey: "admin-activate", RequestID: "admin-activate",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("admin activation boundary error=%v", err)
	}

	for name, principal := range map[string]identity.Principal{
		"cross tenant": {
			UserID: fixture.alice.UserID, ScopeID: fixture.bob.ScopeID, ScopeKind: "tenant",
			TenantID: fixture.bob.TenantID, Permissions: fixture.alice.Permissions,
		},
		"platform as self": fixture.admin,
	} {
		t.Run(name+" create fails closed", func(t *testing.T) {
			before := countAPIKeys(t, fixture.pool)
			_, err := fixture.service.CreateSelf(ctx, principal, CreateInput{
				Name: name, Scopes: []string{"sites.read"}, IdempotencyKey: "boundary-" + strings.ReplaceAll(name, " ", "-"),
				RequestID: "boundary-" + strings.ReplaceAll(name, " ", "-"),
			})
			if err == nil || countAPIKeys(t, fixture.pool) != before {
				t.Fatalf("boundary create error=%v", err)
			}
		})
	}
	if _, err := fixture.service.AdminCreatePending(ctx, fixture.alice, AdminCreateInput{
		TargetScopeID: fixture.bob.ScopeID, TargetUserID: fixture.bob.UserID,
		Name: "tenant as admin", Scopes: []string{"sites.read"},
		IdempotencyKey: "tenant-admin", RequestID: "tenant-admin",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant admin boundary error=%v", err)
	}
	// A missing scope is refused before any lookup; a user who is not an
	// active member of the named tenant scope is not found there (the same
	// contract as AdminListPage, list_page_test.go). Neither creates a key.
	for name, test := range map[string]struct {
		scopeID uuid.UUID
		want    error
	}{
		"missing scope": {uuid.Nil, ErrPermissionDenied},
		"wrong scope":   {fixture.bob.ScopeID, ErrNotFound},
	} {
		before := countAPIKeys(t, fixture.pool)
		if _, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
			TargetScopeID: test.scopeID, TargetUserID: fixture.alice.UserID,
			Name: name, Scopes: []string{"sites.read"},
			IdempotencyKey: strings.ReplaceAll(name, " ", "-"), RequestID: strings.ReplaceAll(name, " ", "-"),
		}); !errors.Is(err, test.want) || countAPIKeys(t, fixture.pool) != before {
			t.Fatalf("%s admin boundary error=%v, want %v", name, err, test.want)
		}
	}

	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO memberships (scope_id,user_id,created_at) VALUES ($1,$2,$3)`,
		fixture.bob.ScopeID, fixture.alice.UserID, fixture.clock.Now()); err != nil {
		t.Fatalf("create ambiguous tenant membership: %v", err)
	}
	before := countAPIKeys(t, fixture.pool)
	created, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "explicit target", Scopes: []string{"sites.read"},
		IdempotencyKey: "explicit-target", RequestID: "explicit-target",
	})
	if err != nil || created.ScopeID != fixture.alice.ScopeID || countAPIKeys(t, fixture.pool) != before+1 {
		t.Fatalf("explicit admin target = (%#v, %v)", created, err)
	}
}

func TestAPIKeyConcurrentMutationsHaveSingleWinner(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()

	pending, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "activation race", Scopes: []string{"sites.read"},
		PendingTTL: time.Hour, IdempotencyKey: "activation-race-create", RequestID: "activation-race-create",
	})
	if err != nil {
		t.Fatalf("create activation race key: %v", err)
	}
	activation := runConcurrentMutations(func(index int) error {
		_, err := fixture.service.ActivateSelf(ctx, fixture.alice, MutationInput{
			ID: pending.ID, ExpectedRevision: 1, IdempotencyKey: fmt.Sprintf("activation-race-%d", index),
			RequestID: fmt.Sprintf("activation-race-%d", index),
		})
		return err
	})
	assertSingleMutationWinner(t, activation, ErrRevisionConflict)

	rotation := runConcurrentMutations(func(index int) error {
		_, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
			ID: pending.ID, ExpectedRevision: 2, IdempotencyKey: fmt.Sprintf("rotation-race-%d", index),
			RequestID: fmt.Sprintf("rotation-race-%d", index),
		})
		return err
	})
	assertSingleMutationWinner(t, rotation, ErrRevisionConflict)

	revocation := runConcurrentMutations(func(index int) error {
		_, err := fixture.service.RevokeSelf(ctx, fixture.alice, MutationInput{
			ID: pending.ID, ExpectedRevision: 3, IdempotencyKey: fmt.Sprintf("revocation-race-%d", index),
			RequestID: fmt.Sprintf("revocation-race-%d", index),
		})
		return err
	})
	assertSingleMutationWinner(t, revocation, ErrInvalidTransition)

	type createResult struct {
		keyID  uuid.UUID
		secret string
		err    error
	}
	created := make(chan createResult, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := fixture.service.CreateSelf(ctx, fixture.alice, CreateInput{
				Name: "idempotent race", Scopes: []string{"sites.read"},
				IdempotencyKey: "idempotent-create-race", RequestID: "idempotent-create-race",
			})
			created <- createResult{keyID: result.Key.ID, secret: result.Secret, err: err}
		}()
	}
	wait.Wait()
	close(created)
	var first createResult
	for result := range created {
		if result.err != nil {
			t.Fatalf("idempotent create race failed: %v", result.err)
		}
		if first.keyID == uuid.Nil {
			first = result
			continue
		}
		if result.keyID != first.keyID || result.secret != first.secret {
			t.Fatal("idempotent create race returned different issuance results")
		}
	}
	var count int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT count(*) FROM api_key_write_requests WHERE idempotency_key='idempotent-create-race'`).Scan(&count); err != nil {
		t.Fatalf("count idempotent writes: %v", err)
	}
	if count != 1 {
		t.Fatalf("idempotent create write count=%d", count)
	}
}

func TestAPIKeyAuthorityMutationWaitsForGlobalExclusive(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	issued := mustCreateSelfKey(t, fixture, "stage2-authority-wait")
	holder, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.RevokeSelf(context.Background(), fixture.alice, MutationInput{
			ID: issued.Key.ID, ExpectedRevision: issued.Key.Revision,
			IdempotencyKey: "stage2-authority-revoke", RequestID: "stage2-authority-revoke",
		})
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("API key revoke did not wait for global exclusive lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeyAuthenticationDoesNotSynchronouslyMutateUsageTelemetry(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	issued := mustCreateSelfKey(t, fixture, "stage2-telemetry-disabled")
	if _, err := fixture.service.Authenticate(t.Context(), issued.Key.KeyID+"."+issued.Secret); err != nil {
		t.Fatal(err)
	}
	var lastUsed *time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`,
		issued.Key.ID).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed != nil {
		t.Fatalf("authentication synchronously updated last_used_at to %v", *lastUsed)
	}
}

func TestAPIKeyAuthenticationRejectsSuspendedTenant(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	issued := mustCreateSelfKey(t, fixture, "tenant-status-create")
	credential := issued.Key.KeyID + "." + issued.Secret
	if _, err := fixture.service.Authenticate(t.Context(), credential); err != nil {
		t.Fatalf("authenticate active tenant credential: %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		UPDATE tenants SET status='suspended',revision=revision+1,updated_at=$2 WHERE id=$1`,
		*fixture.alice.TenantID, fixture.clock.Now()); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	if _, err := fixture.service.Authenticate(t.Context(), credential); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("suspended tenant credential error=%v", err)
	}
}

func TestAPIKeyAuthenticationUsesLiveUserMembershipAndRBAC(t *testing.T) {
	t.Run("scopes remain the live RBAC intersection", func(t *testing.T) {
		fixture := newAPIKeyIntegrationFixture(t)
		expiresAt := fixture.clock.Now().Add(24 * time.Hour)
		issued, err := fixture.service.CreateSelf(t.Context(), fixture.alice, CreateInput{
			Name: "live-rbac", Scopes: []string{"sites.read", "sites.manage"},
			ExpiresAt:      &expiresAt,
			IdempotencyKey: "live-rbac-create", RequestID: "live-rbac-create",
		})
		if err != nil {
			t.Fatalf("create live RBAC key: %v", err)
		}
		credential := issued.Key.KeyID + "." + issued.Secret
		principal, err := fixture.service.Authenticate(t.Context(), credential)
		if err != nil || strings.Join(principal.Permissions, ",") != "sites.manage,sites.read" {
			t.Fatalf("initial effective permissions=%v err=%v", principal.Permissions, err)
		}
		readOnlyRoleID := uuid.New()
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `
				INSERT INTO roles (id,scope_id,name,description,system_role,created_at)
				VALUES ($1,$2,'tenant_viewer','API key live RBAC probe',true,$3)`,
				readOnlyRoleID, fixture.alice.ScopeID, fixture.clock.Now()); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `
				INSERT INTO role_permissions (role_id,permission_name) VALUES ($1,'sites.read')`, readOnlyRoleID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
				fixture.alice.ScopeID, fixture.alice.UserID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `
				INSERT INTO role_assignments (scope_id,user_id,role_id,assigned_at)
				VALUES ($1,$2,$3,$4)`, fixture.alice.ScopeID, fixture.alice.UserID,
				readOnlyRoleID, fixture.clock.Now()); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatalf("replace assignment with read-only role: %v", err)
		}
		principal, err = fixture.service.Authenticate(t.Context(), credential)
		if err != nil || strings.Join(principal.Permissions, ",") != "sites.read" {
			t.Fatalf("narrowed effective permissions=%v err=%v", principal.Permissions, err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.alice.ScopeID,
			fixture.alice.UserID, readOnlyRoleID); err != nil {
			t.Fatalf("revoke read-only role assignment: %v", err)
		}
		if _, err := fixture.service.Authenticate(t.Context(), credential); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("credential without effective scopes error=%v", err)
		}
	})

	for _, probe := range []struct {
		name      string
		statement string
		arguments func(*apiKeyIntegrationFixture) []any
	}{
		{
			name:      "disabled user",
			statement: `UPDATE users SET status='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`,
			arguments: func(fixture *apiKeyIntegrationFixture) []any {
				return []any{fixture.alice.UserID, fixture.clock.Now()}
			},
		},
		{
			name:      "suspended membership",
			statement: `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
			arguments: func(fixture *apiKeyIntegrationFixture) []any {
				return []any{fixture.alice.ScopeID, fixture.alice.UserID}
			},
		},
	} {
		t.Run(probe.name, func(t *testing.T) {
			fixture := newAPIKeyIntegrationFixture(t)
			issued := mustCreateSelfKey(t, fixture, "live-principal-"+strings.ReplaceAll(probe.name, " ", "-"))
			credential := issued.Key.KeyID + "." + issued.Secret
			if _, err := fixture.service.Authenticate(t.Context(), credential); err != nil {
				t.Fatalf("authenticate active credential: %v", err)
			}
			if _, err := fixture.pool.Exec(t.Context(), probe.statement, probe.arguments(fixture)...); err != nil {
				t.Fatalf("apply %s: %v", probe.name, err)
			}
			if _, err := fixture.service.Authenticate(t.Context(), credential); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("%s credential error=%v", probe.name, err)
			}
		})
	}
}

func TestAPIKeyMigration025DownUp(t *testing.T) {
	pool := newAPIKeyTestPool(t, 25)
	ctx := context.Background()
	execAPIKeyMigration(t, pool, "025_api_keys.down.sql")
	var relation *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_keys')::text`).Scan(&relation); err != nil {
		t.Fatalf("inspect rolled-back API key table: %v", err)
	}
	if relation != nil {
		t.Fatal("api_keys exists after 025 rollback")
	}
	execAPIKeyMigration(t, pool, "025_api_keys.up.sql")
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_keys')::text`).Scan(&relation); err != nil || relation == nil {
		t.Fatalf("api_keys missing after 025 reapply: relation=%v err=%v", relation, err)
	}
	var triggerCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_trigger trigger
		JOIN pg_class relation ON relation.oid=trigger.tgrelid
		WHERE NOT trigger.tgisinternal AND relation.relnamespace=current_schema()::regnamespace
		  AND relation.relname IN ('api_keys','api_key_write_requests')`).Scan(&triggerCount); err != nil {
		t.Fatalf("inspect reapplied API key triggers: %v", err)
	}
	if triggerCount != 4 {
		t.Fatalf("reapplied API key trigger count=%d, want 4", triggerCount)
	}
}

func newAPIKeyIntegrationFixture(t *testing.T) *apiKeyIntegrationFixture {
	t.Helper()
	// The service under test runs against the release head (migration 196
	// holds platform_system_other_settings, migration 085 needs the
	// migrator's ledger columns).
	pool := databasetest.MigratedPool(t, nil)
	ctx := context.Background()
	clock := &apiKeyTestClock{now: time.Now().UTC().Truncate(time.Second)}
	adminUser, adminScope, adminRole := uuid.New(), uuid.New(), uuid.New()
	aliceUser, aliceTenant, aliceScope, aliceRole := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	bobUser, bobTenant, bobScope, bobRole := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			WITH new_scope AS (
				INSERT INTO access_scopes (id,kind,created_at) VALUES ($1,'platform',$4)
			), new_user AS (
				INSERT INTO users (id,username,display_name,password_hash,created_at,updated_at)
				VALUES ($2,'apikey-admin','API Key Admin','test-hash',$4,$4)
			), new_membership AS (
				INSERT INTO memberships (scope_id,user_id,created_at) VALUES ($1,$2,$4)
			), new_role AS (
				INSERT INTO roles (id,scope_id,name,description,system_role,created_at)
				VALUES ($3,$1,'platform_owner','Platform owner',true,$4)
			), new_permission AS (
				INSERT INTO role_permissions (role_id,permission_name) VALUES ($3,'api_keys.admin.manage')
			)
			INSERT INTO role_assignments (scope_id,user_id,role_id,assigned_at) VALUES ($1,$2,$3,$4)`,
			adminScope, adminUser, adminRole, clock.Now()); err != nil {
			return err
		}
		for _, tenant := range []struct {
			id, scopeID, userID, roleID uuid.UUID
			name, username, displayName string
		}{
			{aliceTenant, aliceScope, aliceUser, aliceRole, "Alice tenant", "apikey-alice", "API Key Alice"},
			{bobTenant, bobScope, bobUser, bobRole, "Bob tenant", "apikey-bob", "API Key Bob"},
		} {
			if _, err := tx.Exec(ctx, `
				WITH new_tenant AS (
					INSERT INTO tenants (id,display_name,created_at,updated_at) VALUES ($1,$5,$8,$8)
				), new_scope AS (
					INSERT INTO access_scopes (id,kind,tenant_id,created_at) VALUES ($2,'tenant',$1,$8)
				), new_user AS (
					INSERT INTO users (id,username,display_name,password_hash,created_at,updated_at)
					VALUES ($3,$6,$7,'test-hash',$8,$8)
				), new_membership AS (
					INSERT INTO memberships (scope_id,user_id,created_at) VALUES ($2,$3,$8)
				), new_role AS (
					INSERT INTO roles (id,scope_id,name,description,system_role,created_at)
					VALUES ($4,$2,'tenant_owner','Tenant owner',true,$8)
				), new_permissions AS (
					INSERT INTO role_permissions (role_id,permission_name)
					SELECT $4,name FROM permissions
					WHERE name=ANY(ARRAY['api_keys.self.manage','sites.read','sites.manage'])
				)
				INSERT INTO role_assignments (scope_id,user_id,role_id,assigned_at) VALUES ($2,$3,$4,$8)`,
				tenant.id, tenant.scopeID, tenant.userID, tenant.roleID,
				tenant.name, tenant.username, tenant.displayName, clock.Now()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed API key integration principals: %v", err)
	}
	return &apiKeyIntegrationFixture{
		pool: pool, clock: clock, service: NewService(pool, bytes.Repeat([]byte{0x42}, 32), clock.Now),
		admin: identity.Principal{UserID: adminUser, ScopeID: adminScope, ScopeKind: "platform",
			Permissions: []string{"api_keys.admin.manage"}},
		alice: identity.Principal{UserID: aliceUser, ScopeID: aliceScope, ScopeKind: "tenant", TenantID: &aliceTenant,
			Permissions: []string{"api_keys.self.manage", "sites.read", "sites.manage"}},
		bob: identity.Principal{UserID: bobUser, ScopeID: bobScope, ScopeKind: "tenant", TenantID: &bobTenant,
			Permissions: []string{"api_keys.self.manage", "sites.read", "sites.manage"}},
	}
}

func newAPIKeyTestPool(t *testing.T, migrationLimit int) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open API key test administration pool: %v", err)
	}
	schema := "apikey_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^apikey_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unexpected API key test schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatalf("create API key test schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatalf("parse API key test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("open isolated API key test pool: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create API key migration ledger: %v", err)
	}
	for version := 1; version <= migrationLimit; version++ {
		matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("resolve migration %03d: matches=%v err=%v", version, matches, err)
		}
		script, err := fs.ReadFile(controlmigrations.FS, matches[0])
		if err != nil {
			t.Fatalf("read migration %03d: %v", version, err)
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version)
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop API key test schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func execAPIKeyMigration(t *testing.T, pool *pgxpool.Pool, name string) {
	t.Helper()
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if _, err := pool.Exec(context.Background(), string(script)); err != nil {
		t.Fatalf("execute %s: %v", name, err)
	}
}

func mustCreateSelfKey(t *testing.T, fixture *apiKeyIntegrationFixture, idempotencyKey string) IssuedKey {
	t.Helper()
	return mustCreateSelfKeyWithExpiry(t, fixture, idempotencyKey, fixture.clock.Now().Add(24*time.Hour))
}

func mustCreateSelfKeyWithExpiry(
	t *testing.T,
	fixture *apiKeyIntegrationFixture,
	idempotencyKey string,
	expiresAt time.Time,
) IssuedKey {
	t.Helper()
	result, err := fixture.service.CreateSelf(context.Background(), fixture.alice, CreateInput{
		Name: idempotencyKey, Scopes: []string{"sites.read"}, ExpiresAt: &expiresAt,
		IdempotencyKey: idempotencyKey, RequestID: idempotencyKey,
	})
	if err != nil {
		t.Fatalf("create self API key %q: %v", idempotencyKey, err)
	}
	return result
}

func expectAPIKeySQLRejected(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin rejected SQL probe: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(context.Background(), statement, arguments...)
	if err == nil {
		t.Fatal("database accepted a forbidden API key mutation")
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "P0001" ||
		!strings.Contains(strings.ToLower(databaseError.Message), "api key") {
		t.Fatalf("forbidden mutation was not rejected by an API key invariant trigger: %v", err)
	}
}

func countAPIKeys(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys`).Scan(&count); err != nil {
		t.Fatalf("count API keys: %v", err)
	}
	return count
}

func runConcurrentMutations(run func(int) error) []error {
	errorsByCall := make([]error, 2)
	var wait sync.WaitGroup
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByCall[index] = run(index)
		}(index)
	}
	wait.Wait()
	return errorsByCall
}

func assertSingleMutationWinner(t *testing.T, results []error, loser error) {
	t.Helper()
	winners, losers := 0, 0
	for _, result := range results {
		switch {
		case result == nil:
			winners++
		case errors.Is(result, loser):
			losers++
		default:
			t.Fatalf("unexpected concurrent mutation error: %v", result)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent mutation winners/losers=%d/%d", winners, losers)
	}
}

// fix-smallfu：简单版"重置密钥"轮换 secret 并把权限刷新为当前可授予的全部；同账号其它密钥不受影响；
// 普通轮换保持原权限；审计记录改前→改后权限。
func TestAPIKeyRotateGrantAllScopesRefreshesOnlyTargetKey(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()
	create := func(key string) IssuedKey {
		issued, err := fixture.service.CreateSelf(ctx, fixture.alice, CreateInput{
			Name: key, Scopes: []string{"sites.read"}, IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
		return issued
	}
	primary, other := create("grant-all-primary"), create("grant-all-other")

	rotated, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: primary.Key.ID, ExpectedRevision: primary.Key.Revision, GrantAllScopes: true,
		IdempotencyKey: "grant-all-rotate", RequestID: "grant-all-rotate",
	})
	if err != nil || rotated.Secret == "" || rotated.Secret == primary.Secret ||
		strings.Join(rotated.Key.Scopes, ",") != "sites.manage,sites.read" {
		t.Fatalf("grant-all rotate = scopes %v err %v", rotated.Key.Scopes, err)
	}
	replay, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: primary.Key.ID, ExpectedRevision: primary.Key.Revision, GrantAllScopes: true,
		IdempotencyKey: "grant-all-rotate", RequestID: "grant-all-rotate",
	})
	if err != nil || replay.Secret != rotated.Secret || replay.Key.Revision != rotated.Key.Revision {
		t.Fatalf("grant-all rotate replay = revision %d err %v", replay.Key.Revision, err)
	}
	if _, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: primary.Key.ID, ExpectedRevision: primary.Key.Revision,
		IdempotencyKey: "grant-all-rotate", RequestID: "grant-all-rotate",
	}); err == nil {
		t.Fatal("same idempotency key with a different grant_all_scopes body must not replay")
	}
	untouched, err := fixture.service.GetSelf(ctx, fixture.alice, other.Key.ID)
	if err != nil || strings.Join(untouched.Scopes, ",") != "sites.read" || untouched.Revision != other.Key.Revision {
		t.Fatalf("other key changed: scopes %v revision %d err %v", untouched.Scopes, untouched.Revision, err)
	}
	plain, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: other.Key.ID, ExpectedRevision: other.Key.Revision,
		IdempotencyKey: "plain-rotate", RequestID: "plain-rotate",
	})
	if err != nil || strings.Join(plain.Key.Scopes, ",") != "sites.read" {
		t.Fatalf("plain rotate scopes %v err %v", plain.Key.Scopes, err)
	}
	var from, to string
	if err := fixture.pool.QueryRow(ctx, `
		SELECT payload->'changes'->'scopes'->>'from', payload->'changes'->'scopes'->>'to'
		FROM audit_events WHERE action='api_key.self.rotate' AND resource_id=$1`, primary.Key.ID.String()).
		Scan(&from, &to); err != nil {
		t.Fatalf("read rotate audit: %v", err)
	}
	if from != `["sites.read"]` || to != `["sites.manage", "sites.read"]` {
		t.Fatalf("rotate audit changes = %s -> %s", from, to)
	}
}
