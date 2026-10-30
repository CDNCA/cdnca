package tickets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

// memoryObjects is an in-memory ObjectStore that records the scope and key.
type memoryObjects struct {
	mu         sync.Mutex
	objects    map[string][]byte
	failDelete bool
}

func (store *memoryObjects) Put(_ context.Context, scopeID uuid.UUID, key string, body []byte, _ string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.objects[scopeID.String()+"/"+key] = append([]byte(nil), body...)
	digest := sha256.Sum256(body)
	return fmt.Sprintf("sha256:%x", digest), nil
}

func (store *memoryObjects) Open(_ context.Context, scopeID uuid.UUID, key, token string) (io.ReadCloser, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	body, ok := store.objects[scopeID.String()+"/"+key]
	digest := sha256.Sum256(body)
	if !ok || token != fmt.Sprintf("sha256:%x", digest) {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (store *memoryObjects) Delete(_ context.Context, scopeID uuid.UUID, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failDelete {
		return errors.New("object store down")
	}
	delete(store.objects, scopeID.String()+"/"+key)
	return nil
}

func (store *memoryObjects) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.objects)
}

// eicarScanner rejects bodies containing the EICAR marker.
type eicarScanner struct{}

func (eicarScanner) Scan(_ context.Context, body []byte) error {
	if bytes.Contains(body, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
		return fmt.Errorf("clamd: Eicar-Signature FOUND: %w", ErrAttachmentRejected)
	}
	return nil
}

type fixture struct {
	pool          *pgxpool.Pool
	clock         *testClock
	service       *Service
	objects       *memoryObjects
	notifications *notification.Store
	platformScope uuid.UUID
	manager       Actor // tickets.manage
	reader        Actor // tickets.read only
	outsider      Actor // platform member without ticket permissions
	tenantScope   uuid.UUID
	customer      Actor
	teammate      Actor // same tenant, different user
	otherTenant   Actor
	siteID        uuid.UUID
	otherSiteID   uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := databasetest.MigratedPool(t, nil)
	clock := &testClock{now: time.Now().UTC().Truncate(time.Second)}
	f := &fixture{pool: pool, clock: clock, objects: &memoryObjects{objects: map[string][]byte{}}}
	now := clock.Now()
	f.platformScope = uuid.New()
	exec(t, pool, `INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, f.platformScope, now)
	f.manager = seedActor(t, pool, f.platformScope, now, "staff-manager", PermissionManage, PermissionRead)
	f.reader = seedActor(t, pool, f.platformScope, now, "staff-reader", PermissionRead)
	f.outsider = seedActor(t, pool, f.platformScope, now, "staff-outsider", "sites.read")
	f.tenantScope = seedTenant(t, pool, now)
	f.customer = seedActor(t, pool, f.tenantScope, now, "customer")
	f.teammate = seedActor(t, pool, f.tenantScope, now, "teammate")
	otherScope := seedTenant(t, pool, now)
	f.otherTenant = seedActor(t, pool, otherScope, now, "other")
	f.siteID = seedSite(t, pool, f.tenantScope, f.customer.UserID)
	f.otherSiteID = seedSite(t, pool, otherScope, f.otherTenant.UserID)
	var err error
	f.notifications, err = notification.NewStoreWithClock(pool, audit.NewWithClock(pool, clock.Now), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.notifications.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	f.service, err = New(Config{Pool: pool, Notifier: f.notifications, Objects: f.objects, Scanner: eicarScanner{},
		Now: clock.Now, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func exec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[0:3], " "), err)
	}
}

func seedTenant(t *testing.T, pool *pgxpool.Pool, now time.Time) uuid.UUID {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,$2,'active',$3,$3)`,
		tenantID, "tickets "+tenantID.String()[:8], now)
	exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`, scopeID, tenantID, now)
	return scopeID
}

func seedSite(t *testing.T, pool *pgxpool.Pool, scopeID, owner uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	domain := "t" + strings.ReplaceAll(id.String(), "-", "")[:12] + ".example.com"
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`,
				[]any{id, scopeID, owner, domain}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{id}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{id}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedActor(t *testing.T, pool *pgxpool.Pool, scope uuid.UUID, now time.Time, name string, permissions ...string) Actor {
	t.Helper()
	user, session, role := uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256(session[:])
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
				VALUES($1,$2,$3,'not-used','active',$4,$4)`,
				[]any{user, "tk-" + strings.ReplaceAll(user.String(), "-", "")[:20], name, now}},
			{`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, []any{scope, user, now}},
			{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
				VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{session, user, scope, refresh[:], now.Add(-time.Hour), now.Add(30 * 24 * time.Hour)}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		if len(permissions) == 0 {
			return nil
		}
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'tickets',true,$4)`,
				[]any{role, scope, "tk_" + strings.ReplaceAll(role.String(), "-", "")[:20], now}},
			{`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`,
				[]any{role, permissions}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, []any{scope, user, role, now}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: user, ScopeID: scope, SessionID: session}
}

func (f *fixture) subscribe(t *testing.T, actor Actor, events ...string) {
	t.Helper()
	for _, event := range events {
		if err := f.notifications.SetSubscription(t.Context(), actor.ScopeID, actor.UserID, event,
			notification.Subscription{Email: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// outbox counts the customer's notification events and email deliveries of a type.
func (f *fixture) outbox(t *testing.T, actor Actor, event string) (events, deliveries int) {
	t.Helper()
	if err := f.pool.QueryRow(t.Context(), `SELECT count(DISTINCT event.id), count(outbox.id)
		FROM notification_events event LEFT JOIN notification_outbox outbox ON outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.recipient_user_id=$2 AND event.event_type=$3`,
		actor.ScopeID, actor.UserID, event).Scan(&events, &deliveries); err != nil {
		t.Fatal(err)
	}
	return events, deliveries
}

func (f *fixture) create(t *testing.T, actor Actor, key string, input CreateInput) Detail {
	t.Helper()
	if input.Category == "" {
		input.Category = "technical"
	}
	if input.Subject == "" {
		input.Subject = "网站 502"
	}
	if input.Body == "" {
		input.Body = "访问首页返回 502"
	}
	detail, err := f.service.Create(t.Context(), actor, key, "req-"+key, input)
	if err != nil {
		t.Fatalf("create %s: %v", key, err)
	}
	return detail
}

var pngBody = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
