package notificationruntime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeliveryHistoryDispatchObservationPostgreSQL(t *testing.T) {
	// Migration 253's own round trip runs on a schema stopped at 253: from the
	// release head a down rolls back the newest migration, not 253.
	roundTrip := databasetest.MigratedThroughPool(t, "notification_observation_253", 253)
	if err := databasetest.MigrateThrough(t.Context(), roundTrip, "down", 253); err != nil {
		t.Fatalf("unused observation migration rollback: %v", err)
	}
	if err := databasetest.MigrateThrough(t.Context(), roundTrip, "up", 253); err != nil {
		t.Fatalf("observation migration reapply: %v", err)
	}
	pool := isolatedRuntimePool(t)
	if observationRollbackBlocked(t, pool) {
		t.Fatal("253 rollback guard blocked before any observation was recorded")
	}
	_, scopeID, userID := seedRuntimeMember(t, pool)
	admin := notificationcontrol.Actor{ScopeID: uuid.New(), UserID: uuid.New(), SessionID: uuid.New(), ScopeKind: "platform"}
	roleID := uuid.New()
	digest := sha256.Sum256(admin.SessionID[:])
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO users(id,username,display_name,password_hash) VALUES($2,'observation-admin','Observation admin','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2);
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'observation-reader','Observation reader',true);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($3,'system_configuration.read');
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($4,$4,$2,$1,$5,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
		pgx.QueryExecModeSimpleProtocol, admin.ScopeID, admin.UserID, roleID, admin.SessionID, digest[:]); err != nil {
		t.Fatal(err)
	}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	control, err := notificationcontrol.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	ref := notification.TemplateRef{ID: "observation_test", Version: 1, Channel: notification.ChannelEmail}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{Ref: ref, Subject: "private-title", Body: "private-body", Variables: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	enqueue := func(source string) uuid.UUID {
		t.Helper()
		result, err := store.Enqueue(t.Context(), notification.EnqueueRequest{ScopeID: scopeID, RecipientID: userID,
			SourceEventID: source, EventType: "runtime.observation", Policy: notification.DeliverySystemRequired,
			Templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: ref}, AuditRequestID: source})
		if err != nil || len(result.Deliveries) != 1 {
			t.Fatalf("enqueue=%+v err=%v", result, err)
		}
		return result.Deliveries[0].OutboxID
	}
	read := func(id uuid.UUID) []notificationcontrol.DeliveryHistoryFact {
		t.Helper()
		page, err := control.ListDeliveryHistory(t.Context(), admin, notificationcontrol.DeliveryHistoryQuery{ScopeID: scopeID.String(), Limit: "300"})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(page)
		for _, secret := range []string{"member@example.test", "changed@example.test", "private-title", "private-body"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("history leaked %q", secret)
			}
		}
		var facts []notificationcontrol.DeliveryHistoryFact
		for _, item := range page.Items {
			if item.OutboxID == id {
				facts = append(facts, item)
			}
		}
		return facts
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	resolver := &testContactResolver{contact: "member@example.test"}
	provider := &testProvider{result: ProviderResult{Disposition: ProviderTemporaryFailure, Code: "provider_unavailable"}}
	sender := newMemberSender(resolver, map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider}, time.Second)
	sender.now = func() time.Time { return started }
	config := notification.DefaultWorkerConfig()
	config.BatchSize = 1
	config.BaseDelay, config.MaxDelay = time.Millisecond, time.Millisecond
	worker, err := notification.NewWorker(store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	id := enqueue("observation-retry")
	first, err := worker.ProcessBatch(t.Context())
	if err != nil || first.RetryScheduled != 1 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	facts := read(id)
	if len(facts) != 2 || facts[0].RecipientAddress == nil || *facts[0].RecipientAddress != "m***@example.test" ||
		facts[0].ProviderCallStartedAt == nil || !facts[0].ProviderCallStartedAt.Equal(started) || facts[1].RecipientAddress != nil || facts[1].ProviderCallStartedAt != nil {
		t.Fatalf("first attempt history=%+v", facts)
	}
	firstStarted := started
	resolver.contact = "changed@example.test"
	started = time.Now().UTC().Truncate(time.Microsecond)
	provider.result = ProviderResult{Disposition: ProviderAccepted, ProviderDeliveryID: "provider-delivery"}
	time.Sleep(5 * time.Millisecond)
	second, err := worker.ProcessBatch(t.Context())
	if err != nil || second.Accepted != 1 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if _, err := store.RecordProviderReceipt(t.Context(), notification.ProviderReceipt{ScopeID: scopeID, OutboxID: id,
		Provider: "configured_email", ProviderDeliveryID: "provider-delivery", ProviderEventKey: "observation-receipt",
		State: notification.DeliveryDelivered, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	facts = read(id)
	if len(facts) != 5 {
		t.Fatalf("history rows=%d", len(facts))
	}
	for _, fact := range facts {
		if fact.FactKind == "dispatch_started" {
			if fact.RecipientAddress != nil || fact.ProviderCallStartedAt != nil || fact.RecipientAddressState != "unavailable" {
				t.Fatalf("dispatch read a future observation: %+v", fact)
			}
			continue
		}
		wantAddress, wantTime := "c***@example.test", started
		if fact.AttemptNumber == 1 {
			wantAddress, wantTime = "m***@example.test", firstStarted
		}
		if fact.RecipientAddressState != "masked" || fact.RecipientAddress == nil || *fact.RecipientAddress != wantAddress ||
			fact.ProviderCallStartedAt == nil || !fact.ProviderCallStartedAt.Equal(wantTime) {
			t.Fatalf("attempt/as-of observation mismatch: %+v", fact)
		}
	}
	if batch, err := worker.ProcessBatch(t.Context()); err != nil || batch.Claimed != 0 {
		t.Fatalf("delivered message resent: %+v %v", batch, err)
	}
	if messages, _ := provider.snapshot(); len(messages) != 2 {
		t.Fatalf("provider calls=%d, want exactly two attempts", len(messages))
	}
	if _, err := pool.Exec(t.Context(), `UPDATE notification_delivery_facts_108 SET recipient_address_masked='x***@example.test' WHERE outbox_id=$1 AND sequence=2`, id); err == nil {
		t.Fatal("immutable observation was mutable")
	}
	// Runtime code needs the release head, so 253's down guard is checked by
	// evaluating its own recorded-history predicate on these facts.
	if blocked := observationRollbackBlocked(t, pool); !blocked {
		t.Fatal("rollback discarded recorded delivery history")
	}
	for _, mode := range []string{"unrecognized", "resolver failure", "panic", "cancelled during send"} {
		t.Run(mode, func(t *testing.T) {
			resolver := &testContactResolver{contact: "member@example.test"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			provider := observationProvider{send: func(context.Context, ProviderMessage) (ProviderResult, error) {
				calls++
				if mode == "panic" {
					panic("private-provider-payload")
				}
				if mode == "cancelled during send" {
					cancel()
					return ProviderResult{}, context.Canceled
				}
				return ProviderResult{Disposition: ProviderAccepted}, nil
			}}
			if mode == "unrecognized" {
				resolver.contact = "unrecognized-contact"
			}
			if mode == "resolver failure" {
				resolver.contact = ""
				resolver.failure = &notification.Failure{Class: notification.FailurePermanent, Code: "recipient_unavailable"}
			}
			sender := newMemberSender(resolver, map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider}, time.Second)
			worker, err := notification.NewWorker(store, sender, config)
			if err != nil {
				t.Fatal(err)
			}
			id := enqueue("observation-" + strings.ReplaceAll(mode, " ", "-"))
			_, err = worker.ProcessBatch(ctx)
			if err != nil && !(mode == "cancelled during send" && errors.Is(err, context.Canceled)) {
				t.Fatal(err)
			}
			facts := read(id)
			if len(facts) != 2 {
				t.Fatalf("facts=%+v", facts)
			}
			called := mode != "resolver failure"
			if (facts[0].ProviderCallStartedAt != nil) != called || calls != boolInt(called) {
				t.Fatalf("call evidence facts=%+v calls=%d", facts, calls)
			}
			if mode == "unrecognized" || !called {
				if facts[0].RecipientAddress != nil || facts[0].RecipientAddressState != "unavailable" {
					t.Fatalf("unknown recipient=%+v", facts[0])
				}
			}
		})
	}
}

// observationRollbackBlocked evaluates the recorded-history condition of
// migration 253's down guard (P2531), taken from the migration file itself.
func observationRollbackBlocked(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	script, err := fs.ReadFile(controlmigrations.FS, "253_notification_dispatch_observation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	start := strings.Index(text, "EXISTS (\n        SELECT 1 FROM notification_delivery_facts_108")
	end := strings.Index(text, "\n    ) THEN")
	if start < 0 || end <= start {
		t.Fatal("253 recorded-history guard not found")
	}
	var blocked bool
	if err := pool.QueryRow(t.Context(), "SELECT "+text[start:end]+")").Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	return blocked
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
