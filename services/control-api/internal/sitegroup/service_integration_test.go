//go:build integration

package sitegroup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var siteGroupTestNow = time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)

func TestServiceReplayTimestampRepresentation(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	request := CreateRequest{TargetScopeID: fixture.tenantAScope, Name: "timestamp replay", WriteMetadata: metadata("timestamp-replay")}
	created, err := fixture.service.Create(t.Context(), actor, request)
	if err != nil || created.Replayed {
		t.Fatalf("initial create: %#v %v", created, err)
	}
	replayed, err := fixture.service.Create(t.Context(), actor, request)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replayed create: %#v %v", replayed, err)
	}
	if !created.Group.CreatedAt.Equal(replayed.Group.CreatedAt) || !created.Group.UpdatedAt.Equal(replayed.Group.UpdatedAt) {
		t.Fatal("replay changed time instants")
	}
	assertSiteGroupReplayContent(t, created.Group, replayed)
	_, offset := created.Group.CreatedAt.Zone()
	differentLocation := time.FixedZone("same offset, distinct location", offset)
	alternate := replayed
	alternate.Group.CreatedAt = alternate.Group.CreatedAt.In(differentLocation)
	alternate.Group.UpdatedAt = alternate.Group.UpdatedAt.In(differentLocation)
	if alternate.Group.CreatedAt.Location() == created.Group.CreatedAt.Location() ||
		!alternate.Group.CreatedAt.Equal(created.Group.CreatedAt) {
		t.Fatal("fixture must preserve the instant while changing the location pointer")
	}
	assertSiteGroupReplayContent(t, created.Group, alternate)
	t.Logf("initial location=%s replay location=%s same location=%v same instant=%v; complete wire content verified",
		created.Group.CreatedAt.Location(), replayed.Group.CreatedAt.Location(),
		created.Group.CreatedAt.Location() == replayed.Group.CreatedAt.Location(),
		created.Group.CreatedAt.Equal(replayed.Group.CreatedAt))
}

func TestServiceCRUDIsolationIdempotencyAndReferences(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	tenantA := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	tenantB := fixture.actor(fixture.tenantBScope, fixture.tenantBUser)
	platform := fixture.actor(fixture.platformScope, fixture.platformUser)
	viewer := fixture.actor(fixture.tenantAScope, fixture.tenantAViewer)

	if _, err := fixture.service.Create(t.Context(), viewer, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "denied", WriteMetadata: metadata("denied"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer create error = %v", err)
	}

	created, err := fixture.service.Create(t.Context(), tenantA, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "  默认分组  ", WriteMetadata: metadata("create-a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Group.Name != "默认分组" || created.Group.Revision != 1 || created.Replayed {
		t.Fatalf("created group = %#v", created)
	}
	replayed, err := fixture.service.Create(t.Context(), tenantA, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "默认分组", WriteMetadata: metadata("create-a"),
	})
	if err != nil || !replayed.Replayed {
		t.Fatalf("create replay = %#v error=%v", replayed, err)
	}
	assertSiteGroupReplayContent(t, created.Group, replayed)
	_, err = fixture.service.Create(t.Context(), tenantA, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "changed", WriteMetadata: metadata("create-a"),
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
	_, err = fixture.service.Create(t.Context(), tenantA, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "默认分组", WriteMetadata: metadata("duplicate-name"),
	})
	if !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate name error = %v", err)
	}

	if _, err := fixture.service.Get(t.Context(), tenantB, fixture.tenantBScope, created.Group.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get error = %v", err)
	}
	if _, err := fixture.service.Get(t.Context(), tenantA, fixture.tenantBScope, created.Group.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant target override error = %v", err)
	}
	platformCreated, err := fixture.service.Create(t.Context(), platform, CreateRequest{
		TargetScopeID: fixture.tenantBScope, Name: "平台目标分组", WriteMetadata: metadata("platform-create"),
	})
	if err != nil || platformCreated.Group.Name != "平台目标分组" {
		t.Fatalf("platform create = %#v error=%v", platformCreated, err)
	}
	page, err := fixture.service.List(t.Context(), platform, ListRequest{
		TargetScopeID: fixture.tenantBScope, Page: 1, Limit: 20,
	})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != platformCreated.Group.ID {
		t.Fatalf("platform target page = %#v error=%v", page, err)
	}
	if _, err := fixture.service.Create(t.Context(), platform, CreateRequest{
		TargetScopeID: fixture.platformScope, Name: "invalid platform target",
		WriteMetadata: metadata("platform-target"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform-scope target error = %v", err)
	}
	var invalidTargetReceipts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM site_group_write_requests
		WHERE idempotency_key='platform-target'`).Scan(&invalidTargetReceipts); err != nil {
		t.Fatal(err)
	}
	if invalidTargetReceipts != 0 {
		t.Fatalf("platform-scope target receipts = %d, want 0", invalidTargetReceipts)
	}

	renamed, err := fixture.service.Rename(t.Context(), tenantA, RenameRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: 1,
		Name: "生产分组", WriteMetadata: metadata("rename-a"),
	})
	if err != nil || renamed.Group.Revision != 2 || renamed.Group.Name != "生产分组" {
		t.Fatalf("rename = %#v error=%v", renamed, err)
	}
	_, err = fixture.service.Rename(t.Context(), tenantA, RenameRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: 1,
		Name: "stale", WriteMetadata: metadata("rename-stale"),
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale rename error = %v", err)
	}

	if err := fixture.insertSiteReference(t, created.Group.ID, "生产分组"); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.service.Delete(t.Context(), tenantA, DeleteRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: 2,
		WriteMetadata: metadata("delete-in-use"),
	})
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("in-use delete error = %v", err)
	}

	unused, err := fixture.service.Create(t.Context(), tenantA, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "未引用", WriteMetadata: metadata("create-unused"),
	})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := fixture.service.Delete(t.Context(), tenantA, DeleteRequest{
		TargetScopeID: fixture.tenantAScope, ID: unused.Group.ID, ExpectedRevision: 1,
		WriteMetadata: metadata("delete-unused"),
	})
	if err != nil || deleted.Group.DeletedAt == nil || deleted.Group.Revision != 2 {
		t.Fatalf("delete = %#v error=%v", deleted, err)
	}
	deleteReplay, err := fixture.service.Delete(t.Context(), tenantA, DeleteRequest{
		TargetScopeID: fixture.tenantAScope, ID: unused.Group.ID, ExpectedRevision: 1,
		WriteMetadata: metadata("delete-unused"),
	})
	if err != nil || !deleteReplay.Replayed {
		t.Fatalf("delete replay = %#v error=%v", deleteReplay, err)
	}
	assertSiteGroupReplayContent(t, deleted.Group, deleteReplay)

	if err := ValidateActiveReference(t.Context(), fixture.pool, fixture.tenantAScope,
		&created.Group.ID, stringPointer("生产分组")); err != nil {
		t.Fatalf("validate active reference: %v", err)
	}
	if err := ValidateActiveReference(t.Context(), fixture.pool, fixture.tenantAScope,
		&created.Group.ID, stringPointer("wrong")); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("wrong reference error = %v", err)
	}
	if err := ValidateActiveReference(t.Context(), fixture.pool, fixture.tenantAScope,
		nil, nil); err != nil {
		t.Fatalf("optional reference error = %v", err)
	}

	var auditCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action IN ('site_group.create','site_group.rename','site_group.delete')`,
		fixture.tenantAScope).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 4 {
		t.Fatalf("tenant A site-group audit count = %d, want 4", auditCount)
	}
}

func TestServiceRenameNoOpPreservesRevisionAndReplays(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	created, err := fixture.service.Create(t.Context(), actor, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "当前名称", WriteMetadata: metadata("rename-noop-create"),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		key  string
	}{
		{name: "当前名称", key: "rename-noop-current"},
		{name: "  当前名称  ", key: "rename-noop-trimmed"},
	} {
		request := RenameRequest{
			TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: created.Group.Revision,
			Name: test.name, WriteMetadata: metadata(test.key),
		}
		result, err := fixture.service.Rename(t.Context(), actor, request)
		if err != nil || result.Replayed {
			t.Fatalf("rename no-op %q = %#v error=%v", test.name, result, err)
		}
		assertSiteGroupReplayContent(t, created.Group, result)
		replayed, err := fixture.service.Rename(t.Context(), actor, request)
		if err != nil || !replayed.Replayed {
			t.Fatalf("rename no-op replay %q = %#v error=%v", test.name, replayed, err)
		}
		assertSiteGroupReplayContent(t, created.Group, replayed)
		var receipts, audits int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM site_group_write_requests WHERE idempotency_key=$1),
			(SELECT count(*) FROM audit_events WHERE request_id=$2)`, test.key, "request-"+test.key).Scan(
			&receipts, &audits); err != nil {
			t.Fatal(err)
		}
		if receipts != 1 || audits != 1 {
			t.Fatalf("rename no-op %q facts = receipts:%d audits:%d", test.name, receipts, audits)
		}
	}

	renamed, err := fixture.service.Rename(t.Context(), actor, RenameRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: created.Group.Revision,
		Name: "新名称", WriteMetadata: metadata("rename-noop-mutation"),
	})
	if err != nil || renamed.Group.Revision != created.Group.Revision+1 {
		t.Fatalf("rename mutation = %#v error=%v", renamed, err)
	}
	_, err = fixture.service.Rename(t.Context(), actor, RenameRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: created.Group.Revision,
		Name: renamed.Group.Name, WriteMetadata: metadata("rename-noop-stale"),
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale rename to current name error = %v", err)
	}
	var staleReceipts, staleAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_group_write_requests WHERE idempotency_key='rename-noop-stale'),
		(SELECT count(*) FROM audit_events WHERE request_id='request-rename-noop-stale')`).Scan(
		&staleReceipts, &staleAudits); err != nil {
		t.Fatal(err)
	}
	if staleReceipts != 0 || staleAudits != 0 {
		t.Fatalf("stale rename facts = receipts:%d audits:%d", staleReceipts, staleAudits)
	}
}

func TestServiceLiveIAMBeforeReplayAndAuditRollback(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	request := CreateRequest{TargetScopeID: fixture.tenantAScope, Name: "live IAM", WriteMetadata: metadata("live-iam")}
	created, err := fixture.service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantAScope,
		fixture.tenantAUser, fixture.tenantARole); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Create(t.Context(), actor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked replay error = %v", err)
	}
	var groups, receipts, audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_groups WHERE id=$1),
		(SELECT count(*) FROM site_group_write_requests WHERE resource_id=$1),
		(SELECT count(*) FROM audit_events WHERE resource_id=$2)`, created.Group.ID, created.Group.ID.String()).Scan(
		&groups, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if groups != 1 || receipts != 1 || audits != 1 {
		t.Fatalf("live IAM facts = groups:%d receipts:%d audits:%d", groups, receipts, audits)
	}

	failing, err := newServiceWithDependencies(fixture.pool, fixture.authorizer,
		func() time.Time { return siteGroupTestNow }, failingAuditAppender{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(
		scope_id,user_id,role_id,assigned_at
	) VALUES($1,$2,$3,$4)`, fixture.tenantAScope, fixture.tenantAUser,
		fixture.tenantARole, siteGroupTestNow.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = failing.Create(t.Context(), actor, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "audit rollback", WriteMetadata: metadata("audit-rollback"),
	})
	if err == nil || !strings.Contains(err.Error(), "simulated audit failure") {
		t.Fatalf("audit failure error = %v", err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_groups WHERE name='audit rollback'),
		(SELECT count(*) FROM site_group_write_requests WHERE idempotency_key='audit-rollback')`).Scan(
		&groups, &receipts); err != nil {
		t.Fatal(err)
	}
	if groups != 0 || receipts != 0 {
		t.Fatalf("audit rollback facts = groups:%d receipts:%d", groups, receipts)
	}
}

func TestServiceConcurrentExactReplaySingleResult(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	request := CreateRequest{TargetScopeID: fixture.tenantAScope, Name: "并发分组", WriteMetadata: metadata("concurrent")}
	const workers = 8
	results := make([]WriteResult, workers)
	errorsSeen := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errorsSeen[index] = fixture.service.Create(context.Background(), actor, request)
		}(index)
	}
	wait.Wait()
	firstID := results[0].Group.ID
	for index := range workers {
		if errorsSeen[index] != nil || results[index].Group.ID != firstID {
			t.Fatalf("worker %d result=%#v error=%v", index, results[index], errorsSeen[index])
		}
	}
	var groups, receipts, audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_groups WHERE name='并发分组'),
		(SELECT count(*) FROM site_group_write_requests WHERE idempotency_key='concurrent'),
		(SELECT count(*) FROM audit_events WHERE resource_id=$1)`, firstID.String()).Scan(
		&groups, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if groups != 1 || receipts != 1 || audits != 1 {
		t.Fatalf("concurrent facts = groups:%d receipts:%d audits:%d", groups, receipts, audits)
	}
}

func TestServiceIncompleteReceiptReturnsResultUnknown(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	request := CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "unknown result", WriteMetadata: metadata("unknown-result"),
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		Name          string    `json:"name"`
	}{request.TargetScopeID, request.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
		request_digest,resource_id,created_at
	) VALUES($1,$2,$3,$3,'site_group.create',$4,$5,$6,$7)`, uuid.New(), fixture.tenantAUser,
		fixture.tenantAScope, request.IdempotencyKey, digest[:], uuid.New(), siteGroupTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Create(t.Context(), actor, request); !errors.Is(err, ErrResultUnknown) {
		t.Fatalf("incomplete replay error = %v", err)
	}
	var groups, audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_groups WHERE name='unknown result'),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='site_group.create')`,
		fixture.tenantAScope).Scan(&groups, &audits); err != nil {
		t.Fatal(err)
	}
	if groups != 0 || audits != 0 {
		t.Fatalf("unknown result facts = groups:%d audits:%d", groups, audits)
	}
}

func TestServiceSerializesSiteReferenceAndGroupDelete(t *testing.T) {
	fixture := newSiteGroupFixture(t)
	actor := fixture.actor(fixture.tenantAScope, fixture.tenantAUser)
	created, err := fixture.service.Create(t.Context(), actor, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "reference first", WriteMetadata: metadata("reference-first"),
	})
	if err != nil {
		t.Fatal(err)
	}
	siteTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = siteTx.Rollback(context.Background()) }()
	if err := fixture.insertSiteRow(t.Context(), siteTx, created.Group.ID, created.Group.Name); err != nil {
		t.Fatal(err)
	}
	deleteTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deleteTx.Rollback(context.Background()) }()
	if _, err := deleteTx.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = deleteTx.Exec(t.Context(), `UPDATE site_groups SET
		active=false,deleted_at=$3,revision=revision+1,updated_at=$3
		WHERE scope_id=$1 AND id=$2`, fixture.tenantAScope, created.Group.ID, siteGroupTestNow.Add(time.Minute))
	assertSiteGroupPGCode(t, err, "55P03")
	if err := deleteTx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := siteTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Delete(t.Context(), actor, DeleteRequest{
		TargetScopeID: fixture.tenantAScope, ID: created.Group.ID, ExpectedRevision: 1,
		WriteMetadata: metadata("reference-first-delete"),
	}); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete after reference commit error = %v", err)
	}

	deleteFirst, err := fixture.service.Create(t.Context(), actor, CreateRequest{
		TargetScopeID: fixture.tenantAScope, Name: "delete first", WriteMetadata: metadata("delete-first"),
	})
	if err != nil {
		t.Fatal(err)
	}
	deleteTx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deleteTx.Rollback(context.Background()) }()
	if _, err := deleteTx.Exec(t.Context(), `UPDATE site_groups SET
		active=false,deleted_at=$3,revision=revision+1,updated_at=$3
		WHERE scope_id=$1 AND id=$2`, fixture.tenantAScope, deleteFirst.Group.ID,
		siteGroupTestNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	siteTx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = siteTx.Rollback(context.Background()) }()
	if _, err := siteTx.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	err = fixture.insertSiteRow(t.Context(), siteTx, deleteFirst.Group.ID, deleteFirst.Group.Name)
	assertSiteGroupPGCode(t, err, "55P03")
	if err := siteTx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := deleteTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateActiveReference(t.Context(), fixture.pool, fixture.tenantAScope,
		&deleteFirst.Group.ID, &deleteFirst.Group.Name); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("deleted group reference error = %v", err)
	}
}

type failingAuditAppender struct{}

func (failingAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("simulated audit failure")
}

type siteGroupFixture struct {
	pool          *pgxpool.Pool
	service       *Service
	authorizer    *iamlock.Authorizer
	tokens        *identity.TokenManager
	tenantAScope  uuid.UUID
	tenantBScope  uuid.UUID
	platformScope uuid.UUID
	tenantAUser   uuid.UUID
	tenantAViewer uuid.UUID
	tenantBUser   uuid.UUID
	platformUser  uuid.UUID
	tenantARole   uuid.UUID
	sessions      map[[2]uuid.UUID]uuid.UUID
}

func newSiteGroupFixture(t *testing.T) *siteGroupFixture {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "sitegroup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^sitegroup_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop sitegroup schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	fixture := &siteGroupFixture{
		pool: pool, tenantAScope: uuid.New(), tenantBScope: uuid.New(), platformScope: uuid.New(),
		tenantAUser: uuid.New(), tenantAViewer: uuid.New(), tenantBUser: uuid.New(), platformUser: uuid.New(),
		tenantARole: uuid.New(), sessions: make(map[[2]uuid.UUID]uuid.UUID),
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	viewerRole, tenantBRole, platformRole := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status) VALUES($1,'Tenant A','active'),($2,'Tenant B','active');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES
			($3,'tenant',$1),($4,'tenant',$2),($5,'platform',NULL);
		INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at) VALUES
			($6,$10,'Tenant A owner','unused','active',$14,$14),
			($7,$11,'Tenant A viewer','unused','active',$14,$14),
			($8,$12,'Tenant B owner','unused','active',$14,$14),
			($9,$13,'Platform owner','unused','active',$14,$14);
		INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES
			($3,$6,'active',$14),($3,$7,'active',$14),($4,$8,'active',$14),($5,$9,'active',$14);
		INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES
			($15,$3,'site_group_owner','owner',true,$14),($16,$3,'site_group_viewer','viewer',true,$14),
			($17,$4,'site_group_owner_b','owner',true,$14),($18,$5,'site_group_platform','platform',true,$14);
		INSERT INTO role_permissions(role_id,permission_name) VALUES
			($15,'sites.read'),($15,'sites.manage'),($16,'sites.read'),
			($17,'sites.read'),($17,'sites.manage'),($18,'sites.read'),($18,'sites.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES
			($3,$6,$15,$14),($3,$7,$16,$14),($4,$8,$17,$14),($5,$9,$18,$14)`,
		pgx.QueryExecModeSimpleProtocol, tenantA, tenantB, fixture.tenantAScope, fixture.tenantBScope,
		fixture.platformScope, fixture.tenantAUser, fixture.tenantAViewer, fixture.tenantBUser,
		fixture.platformUser, username("ta", fixture.tenantAUser), username("tv", fixture.tenantAViewer),
		username("tb", fixture.tenantBUser), username("pa", fixture.platformUser), siteGroupTestNow.Add(-time.Hour),
		fixture.tenantARole, viewerRole, tenantBRole, platformRole); err != nil {
		t.Fatal(err)
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("g", 32), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.tokens = tokens
	for _, pair := range [][2]uuid.UUID{
		{fixture.tenantAScope, fixture.tenantAUser}, {fixture.tenantAScope, fixture.tenantAViewer},
		{fixture.tenantBScope, fixture.tenantBUser}, {fixture.platformScope, fixture.platformUser},
	} {
		sessionID := uuid.New()
		fixture.sessions[pair] = sessionID
		refresh := sha256.Sum256(sessionID[:])
		if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), pair[1], pair[0], refresh[:],
			siteGroupTestNow.Add(-time.Hour), siteGroupTestNow.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return siteGroupTestNow })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x82}, 32), func() time.Time { return siteGroupTestNow })
	if err != nil {
		t.Fatal(err)
	}
	fixture.authorizer, err = iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service, err = NewService(pool, fixture.authorizer, func() time.Time { return siteGroupTestNow })
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *siteGroupFixture) actor(scopeID, userID uuid.UUID) Actor {
	sessionID := fixture.sessions[[2]uuid.UUID{scopeID, userID}]
	raw, _, err := fixture.tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		panic(err)
	}
	return Actor{Credential: Credential{Kind: CredentialSession, Raw: raw}}
}

func (fixture *siteGroupFixture) insertSiteReference(t *testing.T, groupID uuid.UUID, groupName string) error {
	t.Helper()
	return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		siteID := uuid.New()
		var displayID int64
		if err := tx.QueryRow(t.Context(), `INSERT INTO site_display_id_sequences(scope_id,next_value)
			VALUES($1,2) ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1
			RETURNING next_value-1`, fixture.tenantAScope).Scan(&displayID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,display_id,
			group_id,group_name,https_enabled,enabled,status,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1'],ARRAY['192.0.2.1'],$7,
			$5,$6,false,true,'active',$3,$3)`, siteID, fixture.tenantAScope, fixture.tenantAUser,
			"site-"+siteID.String()+".example.test", groupID, groupName, displayID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(
			site_id,position,host,port,weight,enabled
		) VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	})
}

func (fixture *siteGroupFixture) insertSiteRow(
	ctx context.Context,
	tx pgx.Tx,
	groupID uuid.UUID,
	groupName string,
) error {
	siteID := uuid.New()
	var displayID int64
	if err := tx.QueryRow(ctx, `INSERT INTO site_display_id_sequences(scope_id,next_value)
		VALUES($1,2) ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1
		RETURNING next_value-1`, fixture.tenantAScope).Scan(&displayID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO sites(
		id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,display_id,
		group_id,group_name,https_enabled,enabled,status,created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1'],ARRAY['192.0.2.1'],$7,
		$5,$6,false,true,'active',$3,$3)`, siteID, fixture.tenantAScope, fixture.tenantAUser,
		"site-"+siteID.String()+".example.test", groupID, groupName, displayID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO site_origins(
		site_id,position,host,port,weight,enabled
	) VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
	return err
}

func metadata(key string) WriteMetadata {
	return WriteMetadata{IdempotencyKey: key, RequestID: "request-" + key}
}

func username(prefix string, id uuid.UUID) string {
	return prefix + "-" + strings.ReplaceAll(id.String(), "-", "")
}

func stringPointer(value string) *string { return &value }

func assertSiteGroupReplayContent(t *testing.T, original Group, result WriteResult) {
	t.Helper()
	// time.Time equality also compares location pointers; compare every wire field.
	want, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(result.Group)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("group content changed: want=%s got=%s", want, got)
	}
	if result.Replayed {
		var content [2]map[string]any
		for i, body := range [][]byte{want, result.Response} {
			if !json.Valid(body) {
				t.Fatal("invalid replay JSON")
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&content[i]); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(content[0], content[1]) {
			t.Fatal("persisted replay response differs from the complete initial JSON content")
		}
	}
}

func assertSiteGroupPGCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want SQLSTATE %s", want)
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != want {
		t.Fatalf("error = %v, want SQLSTATE %s", err, want)
	}
}

func (group Group) String() string { return fmt.Sprintf("%s/%s", group.ID, group.Name) }
