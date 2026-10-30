//go:build integration

package pluginwebhookcontrol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventfanout"
	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type deliveredDomainEvent struct {
	subscription uuid.UUID
	deliveryID   uuid.UUID
	eventID      string
	eventType    string
	subject      string
	sequence     uint64
	requestID    string
	data         map[string]json.RawMessage
}

// TestDomainEventsReachPermittedInstallationsInOrder is the PA-20 acceptance
// at the database boundary: publishing a site appends site.updated and
// deployment.status_changed facts in the business transactions; fanout and
// the producer create one delivery per permitted subscription; each delivery
// rebuilds into a v2 queue item whose signature verifies with the secret the
// plugin was given; the permitted installation sees its events in order;
// replay creates a new delivery ID for the same event; an installation
// without the permission gets nothing, and revoking it also blocks replay.
//
// The JetStream hop (pluginwebhookruntime) only carries these queue items; it
// is exercised separately and is not needed to prove ordering or signatures.
func TestDomainEventsReachPermittedInstallationsInOrder(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	ctx := t.Context()
	scope := fixture.actor.TargetScopeID
	permitted := insertDomainEventInstallation(t, fixture, "com.example.events", []string{"events.deployment.read", "events.site.read"})
	siteOnly := insertDomainEventInstallation(t, fixture, "com.example.siteonly", []string{"events.site.read"})

	eventTypes := []string{domaineventsource.DeploymentStatusChangedType, domaineventsource.SiteUpdatedType}
	subscribe := func(key string, authorization uuid.UUID, types []string) SubscriptionReceipt {
		created, err := fixture.store.CreateSubscription(ctx, fixture.actor, CreateSubscriptionRequest{
			Name: key, TargetURL: "https://plugin.example.com/hooks/" + key, EventTypes: types,
			InstallationAuthorizationID: &authorization, IdempotencyKey: "domain-" + key,
		})
		if err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
		return created.Value
	}
	if _, err := fixture.store.CreateSubscription(ctx, fixture.actor, CreateSubscriptionRequest{
		Name: "denied", TargetURL: "https://plugin.example.com/hooks/denied", EventTypes: eventTypes,
		InstallationAuthorizationID: &siteOnly, IdempotencyKey: "domain-denied",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("subscription without permission = %v", err)
	}
	main := subscribe("main", permitted, eventTypes)
	sites := subscribe("sites", siteOnly, []string{domaineventsource.SiteUpdatedType})
	pluginSecrets := map[uuid.UUID][]byte{}
	for _, created := range []SubscriptionReceipt{main, sites} {
		raw, err := base64.RawURLEncoding.DecodeString(created.Secret)
		if err != nil || len(raw) != 32 {
			t.Fatalf("secret decode: %v", err)
		}
		pluginSecrets[created.Subscription.ID] = raw
	}

	// Publish a site: the sites row commits, and the deferred trigger of
	// migration 368 appends site.updated(created) in the same transaction.
	siteID, deploymentID := uuid.New(), uuid.New()
	enqueue := func(fact domaineventsource.Fact) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			_, err := domaineventsource.EnqueueTx(ctx, tx, fact)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	var owner uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT user_id FROM memberships WHERE scope_id=$1 LIMIT 1`, scope).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,1,$3,'events.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,now(),now());
		INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,now());
		INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.10',80,1,true)`,
		pgx.QueryExecModeSimpleProtocol, siteID, scope, owner); err != nil {
		t.Fatal(err)
	}
	occurred := time.Now().UTC().Truncate(time.Microsecond)
	rollout, node := uuid.New(), uuid.New()
	for index, state := range []string{"queued", "delivered", "healthy"} {
		fact, err := domaineventsource.NewDeploymentStatusFact(domaineventsource.DeploymentStatus{
			EventID: uuid.Must(uuid.NewV7()), TenantScopeID: scope, DeploymentID: deploymentID,
			NodeID: node, RolloutID: rollout, Attempt: 1, TransitionSequence: uint64(index + 1), State: state,
			OccurredAt: occurred.Add(time.Duration(index+1) * time.Millisecond),
		})
		if err != nil {
			t.Fatal(err)
		}
		enqueue(fact)
	}

	producer, err := pluginwebhook.NewDomainEventProducer(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := domaineventfanout.New(domaineventfanout.Config{Pool: fixture.pool, Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	drainFanout := func() {
		t.Helper()
		for range 16 {
			if err := fanout.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var unpublished int
		if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM domain_event_outbox_368
			WHERE delivery_state<>'published'`).Scan(&unpublished); err != nil || unpublished != 0 {
			t.Fatalf("unpublished source facts = %d, %v", unpublished, err)
		}
	}
	drainFanout()
	secrets, err := NewRuntimeSecretProvider(fixture.pool, fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	received := deliverPendingDomainEvents(t, fixture, secrets, pluginSecrets)
	var mainEvents []deliveredDomainEvent
	for _, event := range received {
		if event.subscription == main.Subscription.ID {
			mainEvents = append(mainEvents, event)
			continue
		}
		if event.subscription != sites.Subscription.ID || event.eventType != domaineventsource.SiteUpdatedType {
			t.Fatalf("site-only installation received %s", event.eventType)
		}
	}
	if len(mainEvents) != 4 || len(received) != 5 {
		rows, _ := fixture.pool.Query(ctx, `SELECT subscription_id::text,status,coalesce(error,'') FROM domain_event_fanout_receipts_368`)
		receipts, _ := pgx.CollectRows(rows, pgx.RowToMap)
		t.Fatalf("received %d events (%d on main); receipts %v", len(received), len(mainEvents), receipts)
	}
	// Delivery order (CloudEvents sequence) follows fact order; each subject
	// is seen with subject_sequence 1..n.
	var lastSequence uint64
	var deploymentStates []string
	for _, event := range mainEvents {
		if event.sequence <= lastSequence {
			t.Fatalf("subscription sequence went %d -> %d", lastSequence, event.sequence)
		}
		lastSequence = event.sequence
		if event.eventType == domaineventsource.DeploymentStatusChangedType {
			var state string
			_ = json.Unmarshal(event.data["state"], &state)
			deploymentStates = append(deploymentStates, state+"#"+string(event.data["subject_sequence"]))
			if event.subject != "deployment/"+deploymentID.String() {
				t.Fatalf("deployment subject = %q", event.subject)
			}
		} else if event.subject != "site/"+siteID.String() || string(event.data["subject_sequence"]) != "1" {
			t.Fatalf("site event subject=%q data=%v", event.subject, event.data)
		}
	}
	var change string
	_ = json.Unmarshal(mainEvents[0].data["change"], &change)
	if mainEvents[0].eventType != domaineventsource.SiteUpdatedType || change != "created" ||
		strings.Join(deploymentStates, ",") != "queued#1,delivered#2,healthy#3" {
		t.Fatalf("delivery order = %s then %v", mainEvents[0].eventType, deploymentStates)
	}
	// Both copies of the site fact share request_id (the source fact) but
	// have distinct event ids.
	for _, event := range received {
		if event.subscription == sites.Subscription.ID &&
			(event.requestID != mainEvents[0].requestID || event.eventID == mainEvents[0].eventID) {
			t.Fatalf("cross-subscription identity: %+v vs %+v", event, mainEvents[0])
		}
	}

	// Replay: same event, new delivery ID.
	first := mainEvents[0]
	replayed, err := fixture.store.ReplayDelivery(ctx, fixture.actor, main.Subscription.ID, first.deliveryID,
		WriteRequest{IdempotencyKey: "domain-replay-1"})
	if err != nil {
		t.Fatal(err)
	}
	again := deliverPendingDomainEvents(t, fixture, secrets, pluginSecrets)
	if replayed.Value.Delivery.ID == first.deliveryID || len(again) != 1 ||
		again[0].deliveryID != replayed.Value.Delivery.ID || again[0].eventID != first.eventID {
		t.Fatalf("replay delivered %+v, want new delivery of event %s", again, first.eventID)
	}

	// Revoke: a disabled installation gets no new events and no replays.
	if _, err := fixture.pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='disabled',revision=revision+1,
		updated_at=clock_timestamp() WHERE tenant_scope_id=$1 AND authorization_id=$2`, scope, permitted); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReplayDelivery(ctx, fixture.actor, main.Subscription.ID, first.deliveryID,
		WriteRequest{IdempotencyKey: "domain-replay-2"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("replay after revoke = %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET origins=ARRAY['192.0.2.20:80'],origin_hosts=ARRAY['192.0.2.20'],
		revision=revision+1,updated_at=now() WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	drainFanout()
	after := deliverPendingDomainEvents(t, fixture, secrets, pluginSecrets)
	if len(after) != 1 || after[0].subscription != sites.Subscription.ID || string(after[0].data["subject_sequence"]) != "2" {
		t.Fatalf("after revoke delivered %+v", after)
	}
}

// deliverPendingDomainEvents plays the runtime + plugin for every pending
// domain delivery: it rebuilds the v2 queue item from the stored canonical
// body (as the runtime does), signs it with the production v2 signer using the
// runtime-decrypted secret, verifies the request the way the receiver
// contract requires using the plugin's copy of the secret, and marks the
// delivery delivered.
func deliverPendingDomainEvents(t *testing.T, fixture storeIntegrationFixture, secrets *RuntimeSecretProvider,
	pluginSecrets map[uuid.UUID][]byte) []deliveredDomainEvent {
	t.Helper()
	ctx := t.Context()
	rows, err := fixture.pool.Query(ctx, `SELECT delivery.id,delivery.subscription_id,delivery.event_id,
		delivery.delivery_idempotency_key,delivery.target_url,event.canonical_body,subscription.active_secret_version_id,
		(SELECT tenant_id FROM access_scopes WHERE id=delivery.tenant_scope_id)
		FROM plugin_webhook_deliveries delivery
		JOIN plugin_webhook_events event ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
		JOIN plugin_webhook_subscriptions subscription ON subscription.tenant_scope_id=delivery.tenant_scope_id
		 AND subscription.id=delivery.subscription_id
		WHERE delivery.tenant_scope_id=$1 AND delivery.status='pending' AND event.event_type<>'io.cdnca.webhook.v1.test'
		ORDER BY delivery.created_at,event.sequence`, fixture.actor.TargetScopeID)
	if err != nil {
		t.Fatal(err)
	}
	type pending struct {
		delivery, subscription, event, secretVersion, tenant uuid.UUID
		key, target                                          string
		body                                                 []byte
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pending, error) {
		var item pending
		err := row.Scan(&item.delivery, &item.subscription, &item.event, &item.key, &item.target, &item.body,
			&item.secretVersion, &item.tenant)
		return item, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var result []deliveredDomainEvent
	for _, item := range items {
		queued, err := pluginwebhook.NewV2QueueItem(item.body, pluginwebhook.V2QueueIdentity{
			TargetScopeID: fixture.actor.TargetScopeID, TenantID: item.tenant, SubscriptionID: item.subscription,
			SecretVersionID: item.secretVersion, EventID: item.event, DeliveryID: item.delivery,
		}, item.key, item.target)
		if err != nil {
			t.Fatalf("delivery %s does not rebuild into a v2 queue item: %v\n%s", item.delivery, err, item.body)
		}
		runtimeSecret, err := secrets.Secret(ctx, fixture.actor.TargetScopeID, item.subscription, item.secretVersion)
		if err != nil {
			t.Fatal(err)
		}
		target, _ := url.Parse(queued.TargetURL)
		headers, err := pluginwebhook.SignV2(runtimeSecret, time.Now(), target.EscapedPath(), queued.EventID,
			queued.DeliveryID, queued.SecretVersionID, queued.RawEvent)
		clear(runtimeSecret)
		if err != nil {
			t.Fatal(err)
		}
		// Receiver side: raw-body digest, then the documented v2 HMAC input.
		digest := sha256.Sum256(queued.RawEvent)
		mac := hmac.New(sha256.New, pluginSecrets[item.subscription])
		_, _ = mac.Write([]byte(strings.Join([]string{"cdnca.webhook.signature/v2", "POST", target.EscapedPath(),
			headers.Timestamp, headers.EventID, headers.DeliveryID, headers.SecretVersionID,
			hex.EncodeToString(digest[:])}, "\n")))
		if headers.ContentSHA256 != hex.EncodeToString(digest[:]) ||
			!hmac.Equal([]byte("v2="+base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(headers.Signature)) {
			t.Fatalf("signature verification failed for delivery %s", item.delivery)
		}
		var event struct {
			ID        string                     `json:"id"`
			Type      string                     `json:"type"`
			Subject   string                     `json:"subject"`
			RequestID string                     `json:"request_id"`
			Sequence  uint64                     `json:"sequence"`
			Data      map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(queued.RawEvent, &event); err != nil || event.ID != headers.EventID {
			t.Fatalf("event body/header identity mismatch: %v", err)
		}
		result = append(result, deliveredDomainEvent{subscription: item.subscription, deliveryID: item.delivery,
			eventID: event.ID, eventType: event.Type, subject: event.Subject, sequence: event.Sequence,
			requestID: event.RequestID, data: event.Data})
		markDomainDeliveryDelivered(t, fixture, item.delivery)
	}
	return result
}

func insertDomainEventInstallation(t *testing.T, fixture storeIntegrationFixture, pluginID string, scopes []string) uuid.UUID {
	t.Helper()
	authorization := uuid.New()
	digest := sha256.Sum256([]byte(pluginID))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO plugin_installation_heads(
		tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,plugin_version,manifest_sha256,
		configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,status,revision,
		identity_generation,created_at,updated_at,entrypoint_type
	) VALUES($1,$2,$3,$4,$5,'1.0.0',$6,$6,$7,$7,ARRAY[]::text[],'enabled',1,1,clock_timestamp(),clock_timestamp(),'external_https')`,
		fixture.actor.TargetScopeID, authorization, uuid.New(), uuid.New(), pluginID, digest[:], scopes); err != nil {
		t.Fatal(err)
	}
	return authorization
}

// markDomainDeliveryDelivered records the runtime's terminal success on the
// delivery row only (the outbox publication proof belongs to the JetStream
// runtime, which this test does not run).
func markDomainDeliveryDelivered(t *testing.T, fixture storeIntegrationFixture, delivery uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE plugin_webhook_deliveries SET status='delivered',nats_stream_sequence=(SELECT coalesce(max(nats_stream_sequence),0)+1 FROM plugin_webhook_deliveries),
			nats_stream_created_unix_nano=1,attempt_count=1,queued_at=created_at,claimed_at=created_at,
			completed_at=created_at,next_attempt_at=NULL WHERE tenant_scope_id=$1 AND id=$2`,
			fixture.actor.TargetScopeID, delivery)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDomainEventSiteFilterAndReplayRange: a site-filtered subscription gets
// only site-bound events of its sites (no tenant-level deployment events);
// a filter naming another tenant's site is rejected; replay by time re-sends
// the range once per batch key (retry reuses the replays) with new delivery
// IDs, and only failed deliveries when asked to.
func TestDomainEventSiteFilterAndReplayRange(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	ctx := t.Context()
	scope := fixture.actor.TargetScopeID
	installation := insertDomainEventInstallation(t, fixture, "com.example.filtered",
		[]string{"events.deployment.read", "events.site.read"})
	var owner uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT user_id FROM memberships WHERE scope_id=$1 LIMIT 1`, scope).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	insertSite := func(id uuid.UUID, domain string) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx, `
			INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,(SELECT coalesce(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$3,$4,
				ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,now(),now());
			INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,now());
			INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.10',80,1,true)`,
			pgx.QueryExecModeSimpleProtocol, id, scope, owner, domain); err != nil {
			t.Fatal(err)
		}
	}
	selected, other := uuid.New(), uuid.New()
	insertSite(selected, "selected.example.test")
	insertSite(other, "other.example.test")

	create := func(key string, types []string, sites []uuid.UUID) (SubscriptionReceipt, error) {
		created, err := fixture.store.CreateSubscription(ctx, fixture.actor, CreateSubscriptionRequest{
			Name: key, TargetURL: "https://plugin.example.com/hooks/" + key, EventTypes: types,
			InstallationAuthorizationID: &installation, SiteIDs: sites, IdempotencyKey: "filter-" + key,
		})
		return created.Value, err
	}
	if _, err := create("foreign", []string{domaineventsource.SiteUpdatedType}, []uuid.UUID{uuid.New()}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("filter naming an unknown site = %v", err)
	}
	if _, err := create("no-site-event", []string{domaineventsource.DeploymentStatusChangedType}, []uuid.UUID{selected}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("filter without a site-bound event = %v", err)
	}
	filtered, err := create("filtered", []string{domaineventsource.DeploymentStatusChangedType, domaineventsource.SiteUpdatedType},
		[]uuid.UUID{selected})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Subscription.SiteIDs) != 1 || filtered.Subscription.SiteIDs[0] != selected {
		t.Fatalf("subscription site filter = %v", filtered.Subscription.SiteIDs)
	}
	secret, _ := base64.RawURLEncoding.DecodeString(filtered.Secret)
	pluginSecrets := map[uuid.UUID][]byte{filtered.Subscription.ID: secret}

	for _, id := range []uuid.UUID{selected, other} {
		if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET origins=ARRAY['192.0.2.30:80'],origin_hosts=ARRAY['192.0.2.30'],
			revision=revision+1,updated_at=now() WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := domaineventsource.NewDeploymentStatusFact(domaineventsource.DeploymentStatus{
		EventID: uuid.Must(uuid.NewV7()), TenantScopeID: scope, DeploymentID: uuid.New(), NodeID: uuid.New(),
		RolloutID: uuid.New(), Attempt: 1, TransitionSequence: 1, State: "queued", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		_, err := domaineventsource.EnqueueTx(ctx, tx, deployment)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	producer, err := pluginwebhook.NewDomainEventProducer(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := domaineventfanout.New(domaineventfanout.Config{Pool: fixture.pool, Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		if err := fanout.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := NewRuntimeSecretProvider(fixture.pool, fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}})
	if err != nil {
		t.Fatal(err)
	}
	received := deliverPendingDomainEvents(t, fixture, secrets, pluginSecrets)
	if len(received) != 1 || received[0].eventType != domaineventsource.SiteUpdatedType ||
		received[0].subject != "site/"+selected.String() || string(received[0].data["subject_sequence"]) != "2" {
		t.Fatalf("filtered subscription received %+v", received)
	}

	// Replay by time: one batch key, retried, replays the delivery once.
	window := ReplayRangeRequest{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Minute), Limit: 10,
		IdempotencyKey: "range-batch-1"}
	first, err := fixture.store.ReplayRange(ctx, fixture.actor, filtered.Subscription.ID, window)
	if err != nil || len(first.Items) != 1 || first.Items[0].Outcome != "replayed" || first.Remaining {
		t.Fatalf("first range replay = %+v, %v", first, err)
	}
	again, err := fixture.store.ReplayRange(ctx, fixture.actor, filtered.Subscription.ID, window)
	if err != nil || len(again.Items) != 1 || again.Items[0].Outcome != "already_replayed" ||
		again.Items[0].Delivery.ID != first.Items[0].Delivery.ID {
		t.Fatalf("retried range replay = %+v, %v", again, err)
	}
	if first.Items[0].Delivery.ID == received[0].deliveryID || first.Items[0].ReplayOf != received[0].deliveryID {
		t.Fatalf("range replay delivery %+v of %s", first.Items[0], received[0].deliveryID)
	}
	replayed := deliverPendingDomainEvents(t, fixture, secrets, pluginSecrets)
	if len(replayed) != 1 || replayed[0].eventID != received[0].eventID || replayed[0].deliveryID != first.Items[0].Delivery.ID {
		t.Fatalf("range replay delivered %+v", replayed)
	}
	// Only failed deliveries: none failed, nothing replayed.
	failedOnly := window
	failedOnly.Statuses, failedOnly.IdempotencyKey = []string{"dead_lettered"}, "range-batch-2"
	if result, err := fixture.store.ReplayRange(ctx, fixture.actor, filtered.Subscription.ID, failedOnly); err != nil || len(result.Items) != 0 {
		t.Fatalf("failed-only range replay = %+v, %v", result, err)
	}
	for name, mutate := range map[string]func(*ReplayRangeRequest){
		"inverted window": func(value *ReplayRangeRequest) { value.From, value.To = value.To, value.From },
		"too long":        func(value *ReplayRangeRequest) { value.From = value.To.Add(-32 * 24 * time.Hour) },
		"bad status":      func(value *ReplayRangeRequest) { value.Statuses = []string{"pending"} },
		"zero limit":      func(value *ReplayRangeRequest) { value.Limit = 0 },
	} {
		value := window
		mutate(&value)
		if _, err := fixture.store.ReplayRange(ctx, fixture.actor, filtered.Subscription.ID, value); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s = %v", name, err)
		}
	}
}
