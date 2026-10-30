//go:build integration

package certnotify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type noticeFixture struct {
	pool          *pgxpool.Pool
	now           time.Time
	notifications *notification.Store
	scope         uuid.UUID
	owner         uuid.UUID
	manager       uuid.UUID
	bystander     uuid.UUID
}

func newNoticeFixture(t *testing.T) *noticeFixture {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		var err error
		if pool, err = pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	f := &noticeFixture{pool: pool, now: time.Date(2026, 10, 18, 4, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }
	store, err := notification.NewStoreWithClock(pool, audit.NewWithClock(pool, clock), clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	f.notifications = store
	tenant := uuid.New()
	f.scope = uuid.New()
	exec(t, pool, `INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,'cert notices','active',$2,$2)`, tenant, f.now)
	exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$3)`, f.scope, tenant, f.now)
	f.owner = f.member(t, "owner")
	f.manager = f.member(t, "manager", "certificates.manage")
	f.bystander = f.member(t, "bystander", "sites.read")
	return f
}

func exec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[:3], " "), err)
	}
}

func (f *noticeFixture) member(t *testing.T, name string, permissions ...string) uuid.UUID {
	t.Helper()
	user, role := uuid.New(), uuid.New()
	exec(t, f.pool, `INSERT INTO users(id,username,display_name,password_hash,status,email,created_at,updated_at)
		VALUES($1,$2,$3,'unused','active',$4,$5,$5)`, user, "cn-"+strings.ReplaceAll(user.String(), "-", "")[:20], name,
		name+"@example.test", f.now)
	exec(t, f.pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, f.scope, user, f.now)
	if len(permissions) != 0 {
		exec(t, f.pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'cert',true,$4)`,
			role, f.scope, "cn_"+strings.ReplaceAll(role.String(), "-", "")[:20], f.now)
		exec(t, f.pool, `INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`,
			role, permissions)
		exec(t, f.pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.scope, user, role)
	}
	return user
}

// certificate inserts an uploaded certificate asset whose active version
// expires at notAfter; a second call with the same asset adds and activates
// a newer version.
func (f *noticeFixture) certificate(t *testing.T, asset uuid.UUID, version int, notAfter time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	seed := sha256.Sum256([]byte(id.String()))
	reference := "cert-notice:" + id.String()
	err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{}
		if version == 1 {
			statements = append(statements, struct {
				query string
				args  []any
			}{`INSERT INTO certificate_assets(tenant_scope_id,id,name,source,revision,created_by_scope_id,created_by_user_id,
				updated_by_scope_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'主站证书','uploaded',1,$1,$3,$1,$3,$4,$4)`,
				[]any{f.scope, asset, f.owner, f.now.Add(-90 * 24 * time.Hour)}})
		}
		statements = append(statements, []struct {
			query string
			args  []any
		}{
			{`INSERT INTO certificate_asset_versions(tenant_scope_id,id,asset_id,actor_scope_id,version,initial_status,
				fingerprint_sha256,certificate_pem,public_key_sha256,private_key_reference,private_key_aad_sha256,sans,leaf_subject,
				serial_number,public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,imported_by_user_id,imported_at)
				VALUES($1,$2,$3,$1,$4::bigint,CASE WHEN $4::bigint=1 THEN 'default' ELSE 'pending_activation' END,$5,$6,$5,$7,$5,
				ARRAY['www.example.test','example.test'],'CN=www.example.test',$8,'ed25519',256,'ed25519',$9,$10,$11,$9)`,
				[]any{f.scope, id, asset, version, seed[:], []byte("notice-test-certificate"), reference,
					fmt.Sprintf("%x", id[:]), f.now.Add(-80 * 24 * time.Hour), notAfter, f.owner}},
			{`INSERT INTO certificate_asset_private_key_envelope_facts(tenant_scope_id,asset_id,version_id,actor_scope_id,sequence,
				certificate_fingerprint_sha256,certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
				private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,changed_by_user_id,changed_at)
				VALUES($1,$2,$3,$1,1,$4,$4,$5,$4,$6,'notice-key',$7,'{}'::jsonb,'initial',$8,$9,$10)`,
				[]any{f.scope, asset, id, seed[:], reference, []byte("0123456789abcdef"), []byte("0123456789ab"),
					"notice-envelope-" + id.String(), f.owner, f.now.Add(-80 * 24 * time.Hour)}},
			{`UPDATE certificate_assets SET revision=revision+1,updated_at=$3,updated_by_user_id=$4 WHERE tenant_scope_id=$1 AND id=$2`,
				[]any{f.scope, asset, f.now.Add(-79 * 24 * time.Hour), f.owner}},
			{`INSERT INTO certificate_asset_activation_facts(tenant_scope_id,asset_id,actor_scope_id,sequence,version_id,
				previous_version_id,expected_asset_revision,resulting_asset_revision,request_id,activated_by_user_id,activated_at)
				SELECT $1,$2,$1,$3,$4,(SELECT version_id FROM certificate_asset_activation_facts WHERE tenant_scope_id=$1 AND asset_id=$2
				  ORDER BY sequence DESC LIMIT 1),revision-1,revision,$5,$6,$7 FROM certificate_assets WHERE tenant_scope_id=$1 AND id=$2`,
				[]any{f.scope, asset, version, id, "notice-activate-" + id.String(), f.owner, f.now.Add(-79 * 24 * time.Hour)}},
		}...)
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%s: %w", strings.Join(strings.Fields(statement.query)[:3], " "), err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *noticeFixture) events(t *testing.T, eventType string) map[uuid.UUID][]string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT recipient_user_id,source_event_id FROM notification_events
		WHERE scope_id=$1 AND event_type=$2 ORDER BY source_event_id`, f.scope, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[uuid.UUID][]string{}
	for rows.Next() {
		var recipient uuid.UUID
		var source string
		if err := rows.Scan(&recipient, &source); err != nil {
			t.Fatal(err)
		}
		result[recipient] = append(result[recipient], source)
	}
	return result
}

// A certificate is told once per notice day it enters, to its owner and the
// certificate managers (not other members); a replaced version and a
// certificate outside every window are not told; an expired active version
// is told once as certificate.expired; the platform's notice days apply.
func TestExpiryNoticesByThresholdOnceAndOnlyForActiveVersions(t *testing.T) {
	f := newNoticeFixture(t)
	days := []int{30, 7, 1}
	notifier, err := New(f.pool, f.notifications, func() time.Time { return f.now },
		func(context.Context, pgx.Tx) ([]int, error) { return days, nil })
	if err != nil {
		t.Fatal(err)
	}
	soon := f.certificate(t, uuid.New(), 1, f.now.Add(20*24*time.Hour)) // inside 30
	f.certificate(t, uuid.New(), 1, f.now.Add(45*24*time.Hour))         // outside every window
	replacedAsset := uuid.New()
	f.certificate(t, replacedAsset, 1, f.now.Add(5*24*time.Hour))       // replaced below
	f.certificate(t, replacedAsset, 2, f.now.Add(85*24*time.Hour))      // the active version
	expired := f.certificate(t, uuid.New(), 1, f.now.Add(-2*time.Hour)) // expired, still active

	run := func() int {
		t.Helper()
		sent, err := notifier.NotifyExpiring(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		return sent
	}
	if sent := run(); sent != 4 { // soon + expired, two recipients each
		t.Fatalf("first pass sent %d, want 4", sent)
	}
	if sent := run(); sent != 0 {
		t.Fatalf("second pass sent %d, want 0 (once per threshold)", sent)
	}
	expiring := f.events(t, EventExpiring)
	want := expiringSource + soon.String() + "/30"
	for _, recipient := range []uuid.UUID{f.owner, f.manager} {
		if len(expiring[recipient]) != 1 || expiring[recipient][0] != want {
			t.Fatalf("recipient %s expiring events = %v, want [%s]", recipient, expiring[recipient], want)
		}
	}
	if len(expiring[f.bystander]) != 0 || len(expiring) != 2 {
		t.Fatalf("expiring events = %v", expiring)
	}
	if got := f.events(t, EventExpired); len(got[f.owner]) != 1 || got[f.owner][0] != expiredSource+expired.String() {
		t.Fatalf("expired events = %v", got)
	}

	// 13 days later the certificate is inside the 7-day window: told again,
	// under the new threshold.
	f.now = f.now.Add(13 * 24 * time.Hour)
	if sent := run(); sent != 2 {
		t.Fatalf("7-day pass sent %d, want 2", sent)
	}
	if got := f.events(t, EventExpiring)[f.owner]; len(got) != 2 || got[1] != expiringSource+soon.String()+"/7" {
		t.Fatalf("owner events after 7 days = %v", got)
	}
	// A week after expiry an expired certificate is no longer looked at.
	f.now = f.now.Add(8 * 24 * time.Hour)
	run()
	if got := f.events(t, EventExpired)[f.owner]; len(got) != 2 {
		t.Fatalf("expired events after the lookback = %v", got)
	}

	// The rendered email carries the certificate's facts.
	var body string
	if err := f.pool.QueryRow(t.Context(), `SELECT outbox.body FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.source_event_id=$1 AND event.recipient_user_id=$2 AND outbox.channel='email'`,
		want, f.owner).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "主站证书") || !strings.Contains(body, "example.test、www.example.test") || !strings.Contains(body, "剩余约 20 天") {
		t.Fatalf("email body = %q", body)
	}
}

// A failed renewal order tells the owner and managers once; a failed first
// issuance is not a renewal and tells nobody.
func TestRenewFailedNoticeOnlyForRenewals(t *testing.T) {
	f := newNoticeFixture(t)
	parent, child, first := uuid.New(), uuid.New(), uuid.New()
	exec(t, f.pool, `INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,status,not_after,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,ARRAY['www.example.test'],'http-01','pending',NULL,$3,$3)`, parent, f.scope, f.owner)
	exec(t, f.pool, `INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,renewal_of_order_id,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,ARRAY['www.example.test'],'http-01',$3,$4,$4)`, child, f.scope, parent, f.owner)
	exec(t, f.pool, `INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,ARRAY['first.example.test'],'http-01',$3,$3)`, first, f.scope, f.owner)
	for range 2 {
		for _, order := range []uuid.UUID{child, first} {
			if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
				return RenewFailedTx(t.Context(), tx, f.notifications, f.scope, order, "acme_authorization_invalid")
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	events := f.events(t, EventRenewFailed)
	if len(events) != 2 || len(events[f.owner]) != 1 || len(events[f.manager]) != 1 ||
		events[f.owner][0] != renewFailedSource+child.String() {
		t.Fatalf("renew failed events = %v", events)
	}
	var body string
	if err := f.pool.QueryRow(t.Context(), `SELECT outbox.body FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.event_type=$1 AND event.recipient_user_id=$2 AND outbox.channel='email'`,
		EventRenewFailed, f.owner).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "证书签发机构验证域名失败") || !strings.Contains(body, "未知") {
		t.Fatalf("renew failed body = %q", body)
	}
}
