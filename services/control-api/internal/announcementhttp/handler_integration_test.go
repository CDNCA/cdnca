package announcementhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var httpFixedNow = time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)

func TestHTTPSessionEnvelopeReauthorizesRevocationRaceAndReplay(t *testing.T) {
	tests := []struct {
		name   string
		revoke func(context.Context, pgx.Tx, httpAnnouncementFixture) error
	}{
		{name: "tenant", revoke: func(ctx context.Context, tx pgx.Tx, fixture httpAnnouncementFixture) error {
			_, err := tx.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=$1`, fixture.tenantID)
			return err
		}},
		{name: "user", revoke: func(ctx context.Context, tx pgx.Tx, fixture httpAnnouncementFixture) error {
			_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, fixture.userID)
			return err
		}},
		{name: "membership", revoke: func(ctx context.Context, tx pgx.Tx, fixture httpAnnouncementFixture) error {
			_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.userID)
			return err
		}},
		{name: "session", revoke: func(ctx context.Context, tx pgx.Tx, fixture httpAnnouncementFixture) error {
			_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test-revoke' WHERE id=$1`, fixture.sessionID, httpFixedNow)
			return err
		}},
		{name: "permission", revoke: func(ctx context.Context, tx pgx.Tx, fixture httpAnnouncementFixture) error {
			revisedAt := httpFixedNow.Add(time.Second)
			if _, err := tx.Exec(ctx, `INSERT INTO custom_role_revisions(
				role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
				created_by_user_id,created_by_scope_id,created_at
			) VALUES($1,$2,$3,2,'announcement-http',ARRAY['announcements.read']::text[],
				'identity.custom_role.publish',$4,$3,$5)`, fixture.roleID, fixture.tenantID,
				fixture.scopeID, fixture.managerID, revisedAt); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE custom_roles SET current_revision=2,updated_at=$2
				WHERE id=$1 AND current_revision=1`, fixture.roleID, revisedAt)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := isolatedHTTPAnnouncementPool(t)
			fixture := seedHTTPAnnouncementFixture(t, pool)
			principal := identity.Principal{
				UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant",
				Permissions: []string{"announcements.manage", "announcements.read"},
			}
			authenticate := AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
				return SessionEnvelope{Principal: principal, SessionID: fixture.sessionID}, nil
			})
			store := newHTTPAnnouncementStore(t, pool, httpTestAuthorizer{})
			handler, err := New(store, authenticate)
			if err != nil {
				t.Fatal(err)
			}
			first := performCreateRequest(handler.Handler(), "http-success", "HTTP 成功")
			if first.Code != http.StatusCreated {
				t.Fatalf("successful create = %d %s", first.Code, first.Body.String())
			}

			if test.name == "session" {
				userIDs := make([]uuid.UUID, 5001)
				groupIDs := make([]uuid.UUID, 5000)
				for index := range userIDs {
					userIDs[index] = uuid.New()
				}
				for index := range groupIDs {
					groupIDs[index] = uuid.New()
				}
				response := performCreateWithAudience(handler.Handler(), "http-audience-limit", userIDs, groupIDs)
				if response.Code != http.StatusBadRequest {
					t.Fatalf("combined oversized audience = %d %s", response.Code, response.Body.String())
				}
			}

			reachedAuthorization := make(chan struct{})
			continueAuthorization := make(chan struct{})
			raceStore := newHTTPAnnouncementStore(t, pool, httpTestAuthorizer{
				beforeAuthorization: reachedAuthorization, continueAuthorization: continueAuthorization,
			})
			raceHandler, err := New(raceStore, authenticate)
			if err != nil {
				t.Fatal(err)
			}
			raceResult := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				raceResult <- performCreateRequest(raceHandler.Handler(), "http-race", "不得提交")
			}()
			<-reachedAuthorization
			authorizationReleased := false
			releaseAuthorization := func() {
				if !authorizationReleased {
					close(continueAuthorization)
					authorizationReleased = true
				}
			}
			defer releaseAuthorization()
			revocation, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := test.revoke(t.Context(), revocation, fixture); err != nil {
				_ = revocation.Rollback(t.Context())
				t.Fatal(err)
			}
			if err := revocation.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			releaseAuthorization()
			if response := <-raceResult; response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"permission_denied"`) {
				t.Fatalf("commit-first revocation race = %d %s", response.Code, response.Body.String())
			}

			alreadyRevoked := performCreateRequest(handler.Handler(), "http-revoked", "不得提交")
			if alreadyRevoked.Code != http.StatusForbidden {
				t.Fatalf("already-revoked authorization = %d %s", alreadyRevoked.Code, alreadyRevoked.Body.String())
			}
			replayAfterRevoke := performCreateRequest(handler.Handler(), "http-success", "HTTP 成功")
			if replayAfterRevoke.Code != http.StatusForbidden {
				t.Fatalf("completed replay after revoke = %d %s", replayAfterRevoke.Code, replayAfterRevoke.Body.String())
			}
			assertHTTPAnnouncementCount(t, pool, "announcements", 1)
			assertHTTPAnnouncementCount(t, pool, "announcement_write_requests", 1)
			var auditCount int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='announcement.create'`).Scan(&auditCount); err != nil {
				t.Fatal(err)
			}
			if auditCount != 1 {
				t.Fatalf("announcement create audit count = %d, want 1", auditCount)
			}
		})
	}
}

func TestHTTPListResponseBudgetPaginatesWithoutGaps(t *testing.T) {
	pool := isolatedHTTPAnnouncementPool(t)
	fixture := seedHTTPAnnouncementFixture(t, pool)
	seedHTTPResponseBudgetFacts(t, pool, fixture, 16)
	store := newHTTPAnnouncementStore(t, pool, allowHTTPAnnouncementAuthorizer{})
	principal := identity.Principal{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant",
		Permissions: []string{"announcements.manage", "announcements.read"},
	}
	handler, err := New(store, AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
		return SessionEnvelope{Principal: principal, SessionID: fixture.sessionID}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	adminIDs := collectAnnouncementPages(t, handler.Handler(), "/v1/admin/announcements")
	if len(adminIDs) != 16 {
		t.Fatalf("admin IDs = %d, want 16", len(adminIDs))
	}
	inboxIDs := collectInboxPages(t, handler.Handler(), "/v1/account/messages?limit=100")
	if len(inboxIDs) != 16 {
		t.Fatalf("inbox IDs = %d, want 16", len(inboxIDs))
	}
}

func seedHTTPResponseBudgetFacts(t *testing.T, pool *pgxpool.Pool, fixture httpAnnouncementFixture, count int) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `ALTER TABLE announcement_state_facts DISABLE TRIGGER announcement_state_facts_append_only`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE announcement_state_watermarks DISABLE TRIGGER announcement_state_watermarks_guard`); err != nil {
		t.Fatal(err)
	}
	watermark := int64(0)
	for index := 0; index < count; index++ {
		announcementID, eventID := uuid.New(), uuid.New()
		publishedAt := httpFixedNow.Add(-time.Duration(index) * time.Second)
		version := map[string]any{
			"id": announcementID, "scope_id": fixture.scopeID, "version": 1, "revision": 1,
			"status": announcement.StatusPublished, "title": fmt.Sprintf("response budget %02d", index),
			"body": strings.Repeat("x", announcement.MaxBodyBytes), "audience_mode": "selected",
			"withdrawal_visibility": announcement.VisibilityRetain, "scheduled_at": nil, "published_at": publishedAt,
			"withdrawn_at": nil, "root_created_at": publishedAt, "state_changed_at": publishedAt,
			"audience_user_ids": []uuid.UUID{fixture.userID}, "audience_group_ids": []uuid.UUID{},
		}
		event := map[string]any{
			"id": eventID, "announcement_id": announcementID, "announcement_version": 1,
			"recipient_user_id": fixture.userID, "title": fmt.Sprintf("response budget %02d", index),
			"body": strings.Repeat("x", announcement.MaxBodyBytes), "published_at": publishedAt,
		}
		state := map[string]any{
			"event_id": eventID, "user_id": fixture.userID, "delivered_at": nil,
			"read_at": nil, "revision": 1, "updated_at": publishedAt,
		}
		watermark++
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_state_facts(
			tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,payload,occurred_at
		) VALUES($1,$2,'version',$3,1,$4,$5)`, fixture.scopeID, watermark, announcementID, mustHTTPJSON(t, version), publishedAt); err != nil {
			t.Fatal(err)
		}
		watermark++
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_state_facts(
			tenant_scope_id,watermark,fact_type,announcement_id,announcement_version,event_id,recipient_user_id,payload,occurred_at
		) VALUES($1,$2,'inbox_event',$3,1,$4,$5,$6,$7)`, fixture.scopeID, watermark, announcementID, eventID, fixture.userID, mustHTTPJSON(t, event), publishedAt); err != nil {
			t.Fatal(err)
		}
		watermark++
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_state_facts(
			tenant_scope_id,watermark,fact_type,event_id,recipient_user_id,payload,occurred_at
		) VALUES($1,$2,'inbox_state',$3,$4,$5,$6)`, fixture.scopeID, watermark, eventID, fixture.userID, mustHTTPJSON(t, state), publishedAt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_state_watermarks(tenant_scope_id,current_watermark)
		VALUES($1,$2) ON CONFLICT (tenant_scope_id) DO UPDATE SET current_watermark=EXCLUDED.current_watermark`, fixture.scopeID, watermark); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE announcement_state_facts ENABLE TRIGGER announcement_state_facts_append_only`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE announcement_state_watermarks ENABLE TRIGGER announcement_state_watermarks_guard`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func mustHTTPJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func collectAnnouncementPages(t *testing.T, handler http.Handler, firstPath string) []uuid.UUID {
	t.Helper()
	var result []uuid.UUID
	path := firstPath
	for path != "" {
		response := performListRequest(handler, path)
		if response.Code != http.StatusOK || response.Body.Len() > maxResponseBytes {
			t.Fatalf("admin page = %d bytes=%d body=%s", response.Code, response.Body.Len(), response.Body.String())
		}
		var page announcement.AnnouncementPage
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			result = appendUniqueHTTPID(t, result, item.ID)
		}
		path = nextHTTPPagePath(firstPath, page.NextCursor)
	}
	return result
}

func collectInboxPages(t *testing.T, handler http.Handler, firstPath string) []uuid.UUID {
	t.Helper()
	var result []uuid.UUID
	path := firstPath
	for path != "" {
		response := performListRequest(handler, path)
		if response.Code != http.StatusOK || response.Body.Len() > maxResponseBytes {
			t.Fatalf("inbox page = %d bytes=%d body=%s", response.Code, response.Body.Len(), response.Body.String())
		}
		var page announcement.InboxPage
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			result = appendUniqueHTTPID(t, result, item.ID)
		}
		path = nextHTTPPagePath(firstPath, page.NextCursor)
	}
	return result
}

func performListRequest(handler http.Handler, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-Request-ID", "req-response-budget")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func nextHTTPPagePath(base, cursor string) string {
	if cursor == "" {
		return ""
	}
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + "cursor=" + cursor
}

func appendUniqueHTTPID(t *testing.T, values []uuid.UUID, value uuid.UUID) []uuid.UUID {
	t.Helper()
	for _, existing := range values {
		if existing == value {
			t.Fatalf("duplicate page item %s", value)
		}
	}
	return append(values, value)
}

func performCreateRequest(handler http.Handler, key, title string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"title":%q,"body":"正文","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`, title)
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/announcements", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("X-Request-ID", "req-"+key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performCreateWithAudience(handler http.Handler, key string, userIDs, groupIDs []uuid.UUID) *httptest.ResponseRecorder {
	body, _ := json.Marshal(createRequest{
		Title: "组合受众上限", Body: "正文", UserIDs: &userIDs, GroupIDs: &groupIDs,
		WithdrawalVisibility: announcement.VisibilityRetain,
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/announcements", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("X-Request-ID", "req-"+key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type httpAnnouncementFixture struct {
	tenantID, scopeID, userID, managerID, sessionID, roleID uuid.UUID
}

func seedHTTPAnnouncementFixture(t *testing.T, pool *pgxpool.Pool) httpAnnouncementFixture {
	t.Helper()
	f := httpAnnouncementFixture{
		tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), managerID: uuid.New(),
		sessionID: uuid.New(), roleID: uuid.New(),
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'announcement-http')`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, f.scopeID, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'announcement-http','announcement-http','hash')`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'announcement-http-manager','announcement-http-manager','hash')`, f.managerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.scopeID, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.scopeID, f.managerID); err != nil {
		t.Fatal(err)
	}
	managerRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'announcement-http-manager','',true)`, managerRoleID, f.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES
		($1,'identity.roles.manage'),($1,'announcements.manage'),($1,'announcements.read')`, managerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.scopeID, f.managerID, managerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_roles(
		id,tenant_id,tenant_scope_id,current_name,created_by_user_id,created_by_scope_id,created_at,updated_at
	) VALUES($1,$2,$3,'announcement-http',$4,$3,$5,$5)`, f.roleID, f.tenantID, f.scopeID, f.managerID, httpFixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,$2,$3,1,'announcement-http',ARRAY['announcements.manage','announcements.read']::text[],
		'identity.custom_role.create',$4,$3,$5)`, f.roleID, f.tenantID, f.scopeID, f.managerID, httpFixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE custom_roles SET current_revision=1,updated_at=$2 WHERE id=$1`, f.roleID, httpFixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7)`, uuid.New(), f.tenantID, f.scopeID,
		f.roleID, f.userID, f.managerID, httpFixedNow); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.sessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.sessionID, uuid.New(), f.userID, f.scopeID,
		digest[:], httpFixedNow, httpFixedNow.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return f
}

type httpTestAuthorizer struct {
	beforeAuthorization   chan struct{}
	continueAuthorization chan struct{}
}

type allowHTTPAnnouncementAuthorizer struct{}

func (allowHTTPAnnouncementAuthorizer) Authorize(context.Context, pgx.Tx, announcement.Actor, string) error {
	return nil
}

func (a httpTestAuthorizer) Authorize(ctx context.Context, tx pgx.Tx, actor announcement.Actor, permission string) error {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return announcement.ErrPermissionDenied
	}
	if a.beforeAuthorization != nil {
		close(a.beforeAuthorization)
		<-a.continueAuthorization
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('announcement-authorization:' || $1::text,0))`, actor.ScopeID); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "tenant" || tenantID == nil {
		return announcement.ErrPermissionDenied
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR UPDATE`, *tenantID).Scan(&status); err != nil || status != "active" {
		return announcement.ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&status); err != nil || status != "active" {
		return announcement.ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).Scan(&status); err != nil || status != "active" {
		return announcement.ErrPermissionDenied
	}
	var revokedAt *time.Time
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `SELECT revoked_at,expires_at FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR UPDATE`, actor.SessionID, actor.UserID, actor.ScopeID).
		Scan(&revokedAt, &expiresAt); err != nil || revokedAt != nil || !httpFixedNow.Before(expiresAt) {
		return announcement.ErrPermissionDenied
	}
	rows, err := tx.Query(ctx, `SELECT role_id FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 ORDER BY role_id FOR SHARE`, actor.ScopeID, actor.UserID)
	if err != nil {
		return err
	}
	var roleIDs []uuid.UUID
	for rows.Next() {
		var roleID uuid.UUID
		if err := rows.Scan(&roleID); err != nil {
			rows.Close()
			return err
		}
		roleIDs = append(roleIDs, roleID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(roleIDs) == 0 {
		return announcement.ErrPermissionDenied
	}
	rows, err = tx.Query(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND id=ANY($2) ORDER BY id FOR SHARE`, actor.ScopeID, roleIDs)
	if err != nil {
		return err
	}
	lockedRoleIDs := roleIDs[:0]
	for rows.Next() {
		var roleID uuid.UUID
		if err := rows.Scan(&roleID); err != nil {
			rows.Close()
			return err
		}
		lockedRoleIDs = append(lockedRoleIDs, roleID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(lockedRoleIDs) == 0 {
		return announcement.ErrPermissionDenied
	}
	var granted string
	err = tx.QueryRow(ctx, `SELECT permission_name FROM role_permissions
		WHERE role_id=ANY($1) AND permission_name=$2 ORDER BY role_id LIMIT 1 FOR SHARE`, lockedRoleIDs, permission).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return announcement.ErrPermissionDenied
	}
	return err
}

func newHTTPAnnouncementStore(t *testing.T, pool *pgxpool.Pool, authorizer announcement.TxAuthorizer) *announcement.Store {
	t.Helper()
	store, err := announcement.NewStoreWithDependencies(
		pool, audit.New(pool), announcement.NoopPublicationOutbox{}, func() time.Time { return httpFixedNow },
		announcement.CursorKeyring{ActiveKID: "http-test", Keys: map[string][]byte{"http-test": bytes.Repeat([]byte{0x44}, 32)}},
		authorizer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func assertHTTPAnnouncementCount(t *testing.T, pool *pgxpool.Pool, table string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}

func isolatedHTTPAnnouncementPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "announcement_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, err := pgxpool.New(context.Background(), databaseURL)
		if err == nil {
			_, _ = cleanup.Exec(context.Background(), `DROP SCHEMA `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
			cleanup.Close()
		}
	})
	return pool
}
