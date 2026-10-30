//go:build integration

package observabilitylog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAnonymousNotificationFactsPostgreSQL(t *testing.T) {
	pool := anonymousNotificationPool(t)
	now := time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)
	scopeA, scopeB, userA, userB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	contact, subject, body := "private-recipient@example.test", "private-notification-title", "private-notification-body"
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Notification A'),($2,'Notification B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash,email) VALUES
			($5,'notification-a','Notification A','unused',$7),($6,'notification-b','Notification B','unused',NULL);
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($3,$6),($4,$5);
		INSERT INTO notification_templates(template_id,version,channel,subject,body,created_at)
			VALUES('observability_test',1,'email',$8,$9,$10)`, pgx.QueryExecModeSimpleProtocol,
		uuid.New(), uuid.New(), scopeA, scopeB, userA, userB, contact, subject, body, now); err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		scope     uuid.UUID
		recipient *uuid.UUID
		outbox    uuid.UUID
	}{
		{scopeA, nil, uuid.New()}, {scopeA, &userA, uuid.New()}, {scopeA, &userB, uuid.New()},
		{scopeB, nil, uuid.New()}, {scopeB, &userA, uuid.New()},
	}
	for _, fixture := range fixtures {
		kind, eventType := "member", "announcement.published"
		var anonymousReference *uuid.UUID
		if fixture.recipient == nil {
			kind, eventType = "anonymous", "identity.account_recovery"
			reference := uuid.New()
			anonymousReference = &reference
		}
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,
				delivery_policy,request_digest,created_at,recipient_kind,anonymous_dispatch_reference)
				VALUES($1,$2,$3,$1::text,$4,'system_required',decode(repeat('01',32),'hex'),$5,$6,$7);
			INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,subject,body,
				dedup_key,status,attempt_count,available_at,created_at,updated_at,lease_token,lease_expires_at)
				VALUES($8,$2,$1,'email','observability_test',1,$9,$10,
				'notification-v1-'||repeat(replace($8::text,'-',''),2),'leased',1,$5,$5,$5,$11,$12);
			INSERT INTO notification_attempts(outbox_id,scope_id,attempt_number,lease_token,lease_expires_at,outcome,claimed_at)
				VALUES($8,$2,1,$11,$12,'leased',$5);
			INSERT INTO notification_delivery_facts_108(scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,observed_at,created_at)
				VALUES($2,$8,1,1,'dispatch_started','dispatching',$5,$5);
			INSERT INTO notification_delivery_settlements_108(scope_id,outbox_id,state,revision,attempt_number,created_at,updated_at)
				VALUES($2,$8,'dispatching',1,1,$5,$5)`, pgx.QueryExecModeSimpleProtocol,
			uuid.New(), fixture.scope, fixture.recipient, eventType, now.Add(-time.Minute), kind, anonymousReference,
			fixture.outbox, subject, body, uuid.New(), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	query := StoreQuery{ScopeID: scopeA, Kinds: []Kind{KindNotification}, From: now.Add(-time.Hour), To: now, SnapshotAt: now, Limit: 10}
	rows, err := store.ListFacts(t.Context(), query)
	if err != nil {
		t.Fatalf("scan member and anonymous notification facts: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("scope A facts=%d, want 3 including anonymous notification", len(rows))
	}
	for _, row := range rows {
		if row.ID == fixtures[0].outbox.String()+":1" && row.SubjectUserID != "" {
			t.Fatalf("anonymous subject=%q, want empty", row.SubjectUserID)
		}
	}
	service, err := NewService(store, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New(), ScopeKind: ScopePlatform, Permissions: []string{"platform.admin"}}
	tenant := Actor{UserID: userA, ScopeID: scopeA, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	for _, test := range []struct {
		name   string
		actor  Actor
		target *uuid.UUID
		want   []int
	}{
		{"platform scope A", platform, &scopeA, []int{0, 1, 2}},
		{"platform scope B", platform, &scopeB, []int{3, 4}},
		{"platform own scope", platform, nil, nil},
		{"tenant own recipient", tenant, nil, []int{1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Query{TargetScopeID: test.target, Kinds: []Kind{KindNotification}, From: query.From, To: now, Limit: 1}
			want := make(map[string]string, len(test.want))
			for _, index := range test.want {
				fixture := fixtures[index]
				subjectID := ""
				if fixture.recipient != nil {
					subjectID = fixture.recipient.String()
				}
				want[fixture.outbox.String()+":1"] = subjectID
			}
			for pageNumber := 0; ; pageNumber++ {
				if pageNumber > len(test.want) {
					t.Fatal("notification pagination did not terminate")
				}
				page, err := service.List(t.Context(), test.actor, input)
				if err != nil {
					t.Fatal(err)
				}
				if page.TotalCount != int64(len(test.want)) {
					t.Fatalf("total=%d, want %d", page.TotalCount, len(test.want))
				}
				for _, row := range page.Items {
					subjectID, exists := want[row.ID]
					if !exists || row.SubjectUserID != subjectID || row.ActorUserID != nil || row.ResultCode != "dispatching" {
						t.Fatalf("unexpected or cross-scope notification fact: %+v", row)
					}
					delete(want, row.ID)
				}
				encoded, err := json.Marshal(page)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{contact, subject, body, "anonymous_dispatch_reference", "lease_token", "dedup_key"} {
					if strings.Contains(string(encoded), secret) {
						t.Fatalf("notification log leaked %q", secret)
					}
				}
				if page.NextCursor == "" {
					break
				}
				input.Cursor = page.NextCursor
			}
			if len(want) != 0 {
				t.Fatalf("missing notification facts: %v", want)
			}
		})
	}
	if _, err := service.List(t.Context(), tenant, Query{TargetScopeID: &scopeB, Kinds: []Kind{KindNotification}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant cross-scope read=%v, want permission denied", err)
	}
}

func anonymousNotificationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "observability_notification_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := databasetest.CleanupContext()
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("remove isolated notification test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
