package pluginwebhookcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	opCreate                  = "plugin_webhook.subscription.create"
	opTest                    = "plugin_webhook.test_delivery.create"
	opReplay                  = "plugin_webhook.delivery.replay"
	opRotate                  = "plugin_webhook.secret.rotate"
	opActivate                = "plugin_webhook.secret.activate"
	opRevoke                  = "plugin_webhook.subscription.revoke"
	maxSubscriptionEventTypes = 16
)

var versionedEventTypePattern = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)

// Only the test event and the available domain events (domaineventsource
// contracts, migration 368+ active rows) are subscribable; reserved catalog
// entries are not. The required installation permission comes from the same
// contract the fanout worker and delivery guard enforce.
func eventInstallationScope(eventType string) (string, bool) {
	contract, ok := domaineventsource.Lookup(eventType)
	return contract.RequiredPermission, ok
}

func knownWebhookEventType(eventType string) bool {
	if eventType == EventTypeTest {
		return true
	}
	_, ok := domaineventsource.Lookup(eventType)
	return ok
}

// NormalizeEventTypes validates the versioned event contract and returns a
// deterministic lexicographic copy. The input slice is never mutated.
func NormalizeEventTypes(eventTypes []string) ([]string, bool) {
	if len(eventTypes) < 1 || len(eventTypes) > maxSubscriptionEventTypes {
		return nil, false
	}
	result := append([]string(nil), eventTypes...)
	seen := make(map[string]struct{}, len(result))
	for _, eventType := range result {
		if !versionedEventTypePattern.MatchString(eventType) {
			return nil, false
		}
		if !knownWebhookEventType(eventType) {
			return nil, false
		}
		if _, duplicate := seen[eventType]; duplicate {
			return nil, false
		}
		seen[eventType] = struct{}{}
	}
	sort.Strings(result)
	return result, true
}

func subscriptionAuthorizationRequirements(eventTypes []string) ([]string, bool, bool) {
	testOnly := len(eventTypes) == 1 && eventTypes[0] == EventTypeTest
	unique := make(map[string]struct{}, len(eventTypes))
	for _, eventType := range eventTypes {
		if eventType == EventTypeTest {
			continue
		}
		scope, ok := eventInstallationScope(eventType)
		if !ok {
			return nil, false, false
		}
		unique[scope] = struct{}{}
	}
	required := make([]string, 0, len(unique))
	if len(unique) == 0 {
		return nil, testOnly, true
	}
	for scope := range unique {
		required = append(required, scope)
	}
	sort.Strings(required)
	return required, testOnly, true
}

type canonicalCreate struct {
	Name                        string      `json:"name"`
	TargetURL                   string      `json:"target_url"`
	EventTypes                  []string    `json:"event_types"`
	InstallationAuthorizationID *uuid.UUID  `json:"installation_authorization_id,omitempty"`
	SiteIDs                     []uuid.UUID `json:"site_ids,omitempty"`
}

const maxSubscriptionSiteIDs = 100

// normalizeSiteFilter returns the sorted site filter, or false when it is
// invalid: empty after being given, too long, nil or repeated ids, or given
// without any site-bound event type (it would match nothing).
func normalizeSiteFilter(siteIDs []uuid.UUID, eventTypes []string) ([]uuid.UUID, bool) {
	if siteIDs == nil {
		return nil, true
	}
	if len(siteIDs) < 1 || len(siteIDs) > maxSubscriptionSiteIDs {
		return nil, false
	}
	siteBound := false
	for _, eventType := range eventTypes {
		if contract, ok := domaineventsource.Lookup(eventType); ok && contract.SiteBound {
			siteBound = true
		}
	}
	if !siteBound {
		return nil, false
	}
	result := append([]uuid.UUID(nil), siteIDs...)
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	for index, id := range result {
		if id == uuid.Nil || (index > 0 && result[index-1] == id) {
			return nil, false
		}
	}
	return result, true
}

type installationAuthorization struct {
	InstallationID uuid.UUID
	PluginID       string
}

func lockInstallationAuthorization(ctx context.Context, tx pgx.Tx, tenantScopeID, authorizationID uuid.UUID, requiredScopes []string) (installationAuthorization, error) {
	var binding installationAuthorization
	var approvedScopes []string
	var status string
	err := tx.QueryRow(ctx, `SELECT installation_id,plugin_id,approved_scopes,status FROM plugin_installation_heads WHERE tenant_scope_id=$1 AND authorization_id=$2 FOR UPDATE`, tenantScopeID, authorizationID).Scan(&binding.InstallationID, &binding.PluginID, &approvedScopes, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationAuthorization{}, ErrPermissionDenied
	}
	if err != nil {
		return installationAuthorization{}, mapStoreError(err)
	}
	if status != "enabled" || binding.InstallationID == uuid.Nil || binding.PluginID == "" {
		return installationAuthorization{}, ErrPermissionDenied
	}
	approved := make(map[string]struct{}, len(approvedScopes))
	for _, scope := range approvedScopes {
		approved[scope] = struct{}{}
	}
	for _, required := range requiredScopes {
		if _, ok := approved[required]; !ok {
			return installationAuthorization{}, ErrPermissionDenied
		}
	}
	return binding, nil
}

func (store *Store) CreateSubscription(ctx context.Context, actor Actor, input CreateSubscriptionRequest) (WriteResult[SubscriptionReceipt], error) {
	eventTypes, validEvents := NormalizeEventTypes(input.EventTypes)
	siteIDs, validSites := normalizeSiteFilter(input.SiteIDs, eventTypes)
	if actor.validate() != nil || !validIdempotencyKey(input.IdempotencyKey) || !validSubscriptionName(input.Name) ||
		!validEvents || !validSites {
		return WriteResult[SubscriptionReceipt]{}, ErrInvalidInput
	}
	requiredScopes, testOnly, authorizable := subscriptionAuthorizationRequirements(eventTypes)
	if !authorizable {
		return WriteResult[SubscriptionReceipt]{}, ErrPermissionDenied
	}
	if testOnly {
		if input.InstallationAuthorizationID != nil {
			return WriteResult[SubscriptionReceipt]{}, ErrInvalidInput
		}
	} else if input.InstallationAuthorizationID == nil || *input.InstallationAuthorizationID == uuid.Nil {
		return WriteResult[SubscriptionReceipt]{}, ErrInvalidInput
	}
	target, err := store.targets.Validate(input.TargetURL)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	digest, err := requestDigest(actor, opCreate, input.IdempotencyKey, canonicalCreate{Name: input.Name, TargetURL: target.URL, EventTypes: eventTypes, InstallationAuthorizationID: input.InstallationAuthorizationID, SiteIDs: siteIDs})
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, ErrInvalidInput
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionManage); err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	if err = lockIdempotency(ctx, tx, actor, input.IdempotencyKey); err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	if stored, loadErr := loadStoredRequest(ctx, tx, actor, input.IdempotencyKey); loadErr == nil {
		return store.replayCreate(ctx, tx, actor, stored, digest, input.IdempotencyKey)
	} else if !errors.Is(loadErr, ErrNotFound) {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(loadErr)
	}
	var binding installationAuthorization
	if !testOnly {
		binding, err = lockInstallationAuthorization(ctx, tx, actor.TargetScopeID, *input.InstallationAuthorizationID, requiredScopes)
		if err != nil {
			return WriteResult[SubscriptionReceipt]{}, err
		}
	}
	if err = lockRate(ctx, tx, actor, opCreate, uuid.Nil); err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	subscriptionID, secretID, requestID := uuid.New(), uuid.New(), uuid.New()
	if err = store.checkEntitlement(ctx, tx, actor, opCreate, subscriptionID, subscriptionID, input.IdempotencyKey, true); err != nil {
		return WriteResult[SubscriptionReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	if err = store.checkRate(ctx, tx, actor, opCreate, uuid.Nil); err != nil {
		return WriteResult[SubscriptionReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	secretRecord, secret, err := store.cipher.encryptSecret(ctx, actor.TargetScopeID, subscriptionID, secretID, 1)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	defer secret.clear()
	receipt, err := store.cipher.encryptReceipt(ctx, []byte(secret.encoded()), actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, input.IdempotencyKey, opCreate, subscriptionID)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	var authorizationValue, installationValue, pluginValue any
	if !testOnly {
		authorizationValue = *input.InstallationAuthorizationID
		installationValue = binding.InstallationID
		pluginValue = binding.PluginID
	}
	var siteValue any
	if siteIDs != nil {
		siteValue = siteIDs
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_subscriptions(id,tenant_scope_id,actor_scope_id,actor_user_id,name,target_url,target_host,target_path,event_types,installation_authorization_id,installation_id,plugin_id,site_ids,active_secret_version_id,status,revision,event_sequence,lifecycle_sequence,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'active',1,0,0,$15,$15)`, subscriptionID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, input.Name, target.URL, target.Host, target.Path, eventTypes, authorizationValue, installationValue, pluginValue, siteValue, secretID, now)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_secret_versions(id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,activated_at) VALUES($1,$1,$2,$3,$4,$5,1,'active',$6,$7,$8,$9,$10,$11,$11)`, secretID, actor.TargetScopeID, subscriptionID, actor.ActorScopeID, actor.ActorUserID, secretRecord.WrappingKeyID, secretRecord.AADSHA256, secretRecord.Nonce, secretRecord.Ciphertext, secretRecord.SecretSHA256, now)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,subscription_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, requestID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, opCreate, input.IdempotencyKey, digest[:], subscriptionID, now)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	auditID, err := appendWebhookAudit(ctx, tx, webhookAuditInput{Actor: actor, Action: opCreate, Result: "success", Reason: "accepted", ResourceType: "plugin_webhook_subscription", ResourceID: subscriptionID, RequestID: input.IdempotencyKey, OccurredAt: now})
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	if err = insertAllowedRate(ctx, tx, actor, opCreate, uuid.Nil, auditID, now); err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `UPDATE plugin_webhook_write_requests SET response_status=201,response_body=jsonb_build_object('subscription_id',subscription_id::text),receipt_wrapping_key_id=$2,receipt_aad_sha256=$3,receipt_nonce=$4,receipt_ciphertext=$5,receipt_expires_at=$6,audit_event_id=$7,completed_at=$8 WHERE id=$1`, requestID, receipt.WrappingKeyID, receipt.AADSHA256, receipt.Nonce, receipt.Ciphertext, now.Add(24*time.Hour), auditID, now)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	value, err := getSubscriptionTx(ctx, tx, actor.TargetScopeID, subscriptionID, false)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	if err = store.commitBusinessWrite(ctx, tx); err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapWriteCommitError(err)
	}
	return WriteResult[SubscriptionReceipt]{Value: SubscriptionReceipt{Subscription: value, Secret: secret.encoded()}}, nil
}

func (store *Store) replayCreate(ctx context.Context, tx pgx.Tx, actor Actor, stored storedRequest, digest [32]byte, key string) (WriteResult[SubscriptionReceipt], error) {
	if err := validateStoredRequest(stored, opCreate, digest, uuid.Nil, nil); err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	secret, err := store.storedReceipt(ctx, tx, stored, actor, key, opCreate, stored.SubscriptionID)
	if err != nil {
		if errors.Is(err, ErrIdempotencyExpired) {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return WriteResult[SubscriptionReceipt]{}, mapStoreError(commitErr)
			}
		}
		return WriteResult[SubscriptionReceipt]{}, err
	}
	value, err := loadOriginalSubscription(ctx, tx, actor.TargetScopeID, stored.SubscriptionID)
	if err != nil {
		return WriteResult[SubscriptionReceipt]{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return WriteResult[SubscriptionReceipt]{}, mapStoreError(err)
	}
	return WriteResult[SubscriptionReceipt]{Value: SubscriptionReceipt{Subscription: value, Secret: secret}, Replayed: true}, nil
}

func (store *Store) CreateTestDelivery(ctx context.Context, actor Actor, subscription uuid.UUID, input WriteRequest) (WriteResult[DeliveryReceipt], error) {
	return store.createDelivery(ctx, actor, subscription, uuid.Nil, input, opTest)
}
func (store *Store) ReplayDelivery(ctx context.Context, actor Actor, subscription, delivery uuid.UUID, input WriteRequest) (WriteResult[DeliveryReceipt], error) {
	if delivery == uuid.Nil {
		return WriteResult[DeliveryReceipt]{}, ErrInvalidInput
	}
	return store.createDelivery(ctx, actor, subscription, delivery, input, opReplay)
}

func (store *Store) createDelivery(ctx context.Context, actor Actor, subscription, replayOf uuid.UUID, input WriteRequest, operation string) (WriteResult[DeliveryReceipt], error) {
	if actor.validate() != nil || subscription == uuid.Nil || !validIdempotencyKey(input.IdempotencyKey) {
		return WriteResult[DeliveryReceipt]{}, ErrInvalidInput
	}
	digestBody := any(struct{}{})
	if operation == opReplay {
		digestBody = struct {
			ReplayOf uuid.UUID `json:"replay_of"`
		}{ReplayOf: replayOf}
	}
	digest, _ := requestDigest(actor, operation, input.IdempotencyKey, digestBody)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionManage); err != nil {
		return WriteResult[DeliveryReceipt]{}, err
	}
	if err = lockIdempotency(ctx, tx, actor, input.IdempotencyKey); err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	if stored, loadErr := loadStoredRequest(ctx, tx, actor, input.IdempotencyKey); loadErr == nil {
		if err = validateStoredRequest(stored, operation, digest, subscription, nil); err != nil {
			return WriteResult[DeliveryReceipt]{}, err
		}
		if stored.DeliveryID == nil {
			return WriteResult[DeliveryReceipt]{}, ErrResultUnknown
		}
		value, readErr := getDeliveryTx(ctx, tx, actor.TargetScopeID, subscription, *stored.DeliveryID)
		if readErr != nil {
			return WriteResult[DeliveryReceipt]{}, readErr
		}
		if err = tx.Commit(ctx); err != nil {
			return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
		}
		return WriteResult[DeliveryReceipt]{Value: DeliveryReceipt{Delivery: value}, Replayed: true}, nil
	} else if !errors.Is(loadErr, ErrNotFound) {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(loadErr)
	}
	if err = lockRate(ctx, tx, actor, operation, subscription); err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	facts, err := lockSubscriptionFacts(ctx, tx, actor.TargetScopeID, subscription)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, err
	}
	if facts.Subscription.Status != "active" {
		return WriteResult[DeliveryReceipt]{}, ErrStateConflict
	}
	deliveryID, requestID := uuid.New(), uuid.New()
	if err = store.checkEntitlement(ctx, tx, actor, operation, subscription, deliveryID, input.IdempotencyKey, false); err != nil {
		return WriteResult[DeliveryReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	if err = store.checkRate(ctx, tx, actor, operation, subscription); err != nil {
		return WriteResult[DeliveryReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,subscription_id,delivery_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, requestID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, operation, input.IdempotencyKey, digest[:], subscription, deliveryID, now)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	var eventID uuid.UUID
	var body, bodyDigest []byte
	if operation == opTest {
		eventID, err = uuid.NewV7()
		if err != nil {
			return WriteResult[DeliveryReceipt]{}, ErrStoreUnavailable
		}
		sequence := facts.EventSequence + 1
		err = tx.QueryRow(ctx, `WITH body AS (SELECT $2::uuid AS ignored,plugin_webhook_canonical_body_084($1,(SELECT tenant_id FROM access_scopes WHERE id=$9),$3,$4,$5,$6,NULL,$7,jsonb_build_object('subscription_id',$8::uuid::text,'test',true)) AS value) INSERT INTO plugin_webhook_events(id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,sequence,event_type,subject,request_id,event_time,data,canonical_body,body_sha256,created_at) SELECT $1,$9,$8,$10,$11,$7,$3,$4,$6,$5,jsonb_build_object('subscription_id',$8::uuid::text,'test',true),value,sha256(value),$5 FROM body RETURNING canonical_body,body_sha256`, eventID, actor.TargetScopeID, EventTypeTest, "webhook_subscription/"+subscription.String(), now, input.IdempotencyKey, strconv.FormatUint(sequence, 10), subscription, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID).Scan(&body, &bodyDigest)
		if err != nil {
			return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
		}
	} else {
		var originalStatus string
		err = tx.QueryRow(ctx, `SELECT delivery.event_id,delivery.status,event.canonical_body,event.body_sha256 FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event ON event.tenant_scope_id=delivery.tenant_scope_id AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3 FOR SHARE OF delivery,event`, actor.TargetScopeID, subscription, replayOf).Scan(&eventID, &originalStatus, &body, &bodyDigest)
		if errors.Is(err, pgx.ErrNoRows) {
			return WriteResult[DeliveryReceipt]{}, ErrNotFound
		}
		if err != nil {
			return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
		}
		if originalStatus != "delivered" && originalStatus != "dead_lettered" {
			return WriteResult[DeliveryReceipt]{}, ErrDeliveryNotReplayable
		}
	}
	replayValue := nullableUUID(replayOf)
	deliveryKey := sha256.Sum256([]byte(deliveryID.String()))
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_deliveries(id,tenant_scope_id,subscription_id,event_id,actor_scope_id,actor_user_id,replay_of,delivery_idempotency_key,target_url,target_host,target_path,status,subscription_revision,attempt_count,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12,0,$13)`, deliveryID, actor.TargetScopeID, subscription, eventID, actor.ActorScopeID, actor.ActorUserID, replayValue, "plugin-webhook-v2-"+hex.EncodeToString(deliveryKey[:]), facts.Subscription.TargetURL, facts.TargetHost, facts.TargetPath, strconv.FormatUint(facts.Subscription.Revision, 10), now)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	message := sha256.Sum256([]byte("msg-" + deliveryID.String()))
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_outbox(id,tenant_scope_id,subscription_id,event_id,delivery_id,actor_scope_id,actor_user_id,queue_schema,queue_body,queue_body_sha256,message_id,status,publish_attempt,available_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'cdnca.plugin-webhook.queue/v2',$8,$9,$10,'pending',0,$11,$11)`, uuid.New(), actor.TargetScopeID, subscription, eventID, deliveryID, actor.ActorScopeID, actor.ActorUserID, body, bodyDigest, "plugin-webhook-v2-"+hex.EncodeToString(message[:]), now)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	auditID, err := appendWebhookAudit(ctx, tx, webhookAuditInput{Actor: actor, Action: operation, Result: "success", Reason: "accepted", ResourceType: "plugin_webhook_delivery", ResourceID: deliveryID, RequestID: input.IdempotencyKey, OccurredAt: now})
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	if err = insertAllowedRate(ctx, tx, actor, operation, subscription, auditID, now); err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `UPDATE plugin_webhook_write_requests SET response_status=202,response_body=jsonb_build_object('subscription_id',subscription_id::text,'delivery_id',delivery_id::text),audit_event_id=$2,completed_at=$3 WHERE id=$1`, requestID, auditID, now)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, mapStoreError(err)
	}
	value, err := getDeliveryTx(ctx, tx, actor.TargetScopeID, subscription, deliveryID)
	if err != nil {
		return WriteResult[DeliveryReceipt]{}, err
	}
	if err = store.commitBusinessWrite(ctx, tx); err != nil {
		return WriteResult[DeliveryReceipt]{}, mapWriteCommitError(err)
	}
	return WriteResult[DeliveryReceipt]{Value: DeliveryReceipt{Delivery: value}}, nil
}

func (store *Store) RotateSecret(ctx context.Context, actor Actor, subscription uuid.UUID, input WriteRequest) (WriteResult[RotationReceipt], error) {
	if actor.validate() != nil || subscription == uuid.Nil || input.Revision == 0 || !validIdempotencyKey(input.IdempotencyKey) {
		return WriteResult[RotationReceipt]{}, ErrInvalidInput
	}
	digest, _ := requestDigest(actor, opRotate, input.IdempotencyKey, struct {
		Revision uint64 `json:"revision"`
	}{Revision: input.Revision})
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionManage); err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	if err = lockIdempotency(ctx, tx, actor, input.IdempotencyKey); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	if stored, loadErr := loadStoredRequest(ctx, tx, actor, input.IdempotencyKey); loadErr == nil {
		return store.replayRotation(ctx, tx, actor, stored, digest, subscription, input.IdempotencyKey)
	} else if !errors.Is(loadErr, ErrNotFound) {
		return WriteResult[RotationReceipt]{}, mapStoreError(loadErr)
	}
	if err = lockRate(ctx, tx, actor, opRotate, subscription); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	facts, err := lockSubscriptionFacts(ctx, tx, actor.TargetScopeID, subscription)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	if facts.Subscription.Status != "active" {
		return WriteResult[RotationReceipt]{}, ErrStateConflict
	}
	if facts.Subscription.Revision != input.Revision {
		return WriteResult[RotationReceipt]{}, ErrRevisionConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE plugin_webhook_secret_versions SET status='expired',nonce=NULL,ciphertext=NULL WHERE tenant_scope_id=$1 AND subscription_id=$2 AND status IN ('pending','retired') AND clock_timestamp()>=expires_at`, actor.TargetScopeID, subscription); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND subscription_id=$2 AND status='pending')`, actor.TargetScopeID, subscription).Scan(&pending); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	if pending {
		return WriteResult[RotationReceipt]{}, ErrRotationPending
	}
	rotationID, requestID := uuid.New(), uuid.New()
	var versionText string
	if err = tx.QueryRow(ctx, `SELECT (COALESCE(max(version),0)+1)::text FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND subscription_id=$2`, actor.TargetScopeID, subscription).Scan(&versionText); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	version, err := parseU64(versionText)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	if err = store.checkEntitlement(ctx, tx, actor, opRotate, subscription, rotationID, input.IdempotencyKey, false); err != nil {
		return WriteResult[RotationReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	if err = store.checkRate(ctx, tx, actor, opRotate, subscription); err != nil {
		return WriteResult[RotationReceipt]{}, store.commitDenial(ctx, tx, err)
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	secretRecord, secret, err := store.cipher.encryptSecret(ctx, actor.TargetScopeID, subscription, rotationID, version)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	defer secret.clear()
	receipt, err := store.cipher.encryptReceipt(ctx, []byte(secret.encoded()), actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, input.IdempotencyKey, opRotate, rotationID)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,subscription_id,rotation_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, requestID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, opRotate, input.IdempotencyKey, digest[:], subscription, rotationID, now)
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_secret_versions(id,key_id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,version,status,wrapping_key_id,aad_sha256,nonce,ciphertext,secret_sha256,created_at,expires_at) VALUES($1,$1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11,$12,$13)`, rotationID, actor.TargetScopeID, subscription, actor.ActorScopeID, actor.ActorUserID, strconv.FormatUint(version, 10), secretRecord.WrappingKeyID, secretRecord.AADSHA256, secretRecord.Nonce, secretRecord.Ciphertext, secretRecord.SecretSHA256, now, now.Add(24*time.Hour))
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	auditID, err := appendWebhookAudit(ctx, tx, webhookAuditInput{Actor: actor, Action: opRotate, Result: "success", Reason: "accepted", ResourceType: "plugin_webhook_secret_version", ResourceID: rotationID, RequestID: input.IdempotencyKey, OccurredAt: now})
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	if err = insertAllowedRate(ctx, tx, actor, opRotate, subscription, auditID, now); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `UPDATE plugin_webhook_write_requests SET response_status=201,response_body=jsonb_build_object('subscription_id',subscription_id::text,'rotation_id',rotation_id::text),receipt_wrapping_key_id=$2,receipt_aad_sha256=$3,receipt_nonce=$4,receipt_ciphertext=$5,receipt_expires_at=$6,audit_event_id=$7,completed_at=$8 WHERE id=$1`, requestID, receipt.WrappingKeyID, receipt.AADSHA256, receipt.Nonce, receipt.Ciphertext, now.Add(24*time.Hour), auditID, now)
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	var expires time.Time
	var status string
	if err = tx.QueryRow(ctx, `SELECT status,expires_at FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, actor.TargetScopeID, subscription, rotationID).Scan(&status, &expires); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	if err = store.commitBusinessWrite(ctx, tx); err != nil {
		return WriteResult[RotationReceipt]{}, mapWriteCommitError(err)
	}
	return WriteResult[RotationReceipt]{Value: RotationReceipt{RotationID: rotationID, KeyID: rotationID, Status: status, ExpiresAt: expires.UTC(), Secret: secret.encoded(), SubscriptionRevision: facts.Subscription.Revision}}, nil
}

func (store *Store) replayRotation(ctx context.Context, tx pgx.Tx, actor Actor, stored storedRequest, digest [32]byte, subscription uuid.UUID, key string) (WriteResult[RotationReceipt], error) {
	if err := validateStoredRequest(stored, opRotate, digest, subscription, nil); err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	if stored.RotationID == nil {
		return WriteResult[RotationReceipt]{}, ErrResultUnknown
	}
	secret, err := store.storedReceipt(ctx, tx, stored, actor, key, opRotate, *stored.RotationID)
	if err != nil {
		if errors.Is(err, ErrIdempotencyExpired) {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return WriteResult[RotationReceipt]{}, mapStoreError(commitErr)
			}
		}
		return WriteResult[RotationReceipt]{}, err
	}
	var versionText, originalRevisionText string
	err = tx.QueryRow(ctx, `SELECT secret.version::text,count(prior.id)::text FROM plugin_webhook_secret_versions secret LEFT JOIN plugin_webhook_secret_versions prior ON prior.tenant_scope_id=secret.tenant_scope_id AND prior.subscription_id=secret.subscription_id AND prior.version<secret.version AND prior.activated_at IS NOT NULL WHERE secret.tenant_scope_id=$1 AND secret.subscription_id=$2 AND secret.id=$3 GROUP BY secret.version`, actor.TargetScopeID, subscription, *stored.RotationID).Scan(&versionText, &originalRevisionText)
	if err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	version, err := parseU64(versionText)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	originalRevision, err := parseU64(originalRevisionText)
	if err != nil {
		return WriteResult[RotationReceipt]{}, err
	}
	if version < 2 || originalRevision == 0 || stored.ReceiptExpires == nil {
		return WriteResult[RotationReceipt]{}, ErrResultUnknown
	}
	if err = tx.Commit(ctx); err != nil {
		return WriteResult[RotationReceipt]{}, mapStoreError(err)
	}
	return WriteResult[RotationReceipt]{Value: RotationReceipt{RotationID: *stored.RotationID, KeyID: *stored.RotationID, Status: "pending", ExpiresAt: stored.ReceiptExpires.UTC(), Secret: secret, SubscriptionRevision: originalRevision}, Replayed: true}, nil
}

func (store *Store) ActivateSecret(ctx context.Context, actor Actor, subscription, rotation uuid.UUID, input WriteRequest) (WriteResult[SubscriptionResult], error) {
	return store.lifecycle(ctx, actor, subscription, rotation, input, opActivate)
}
func (store *Store) RevokeSubscription(ctx context.Context, actor Actor, subscription uuid.UUID, input WriteRequest) (WriteResult[SubscriptionResult], error) {
	return store.lifecycle(ctx, actor, subscription, uuid.Nil, input, opRevoke)
}

func (store *Store) lifecycle(ctx context.Context, actor Actor, subscription, rotation uuid.UUID, input WriteRequest, operation string) (WriteResult[SubscriptionResult], error) {
	if actor.validate() != nil || subscription == uuid.Nil || operation == opActivate && rotation == uuid.Nil || input.Revision == 0 || !validIdempotencyKey(input.IdempotencyKey) {
		return WriteResult[SubscriptionResult]{}, ErrInvalidInput
	}
	digestBody := struct {
		Revision   uint64    `json:"revision"`
		RotationID uuid.UUID `json:"rotation_id,omitempty"`
	}{Revision: input.Revision, RotationID: rotation}
	digest, _ := requestDigest(actor, operation, input.IdempotencyKey, digestBody)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionManage); err != nil {
		return WriteResult[SubscriptionResult]{}, err
	}
	if err = lockIdempotency(ctx, tx, actor, input.IdempotencyKey); err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	if stored, loadErr := loadStoredRequest(ctx, tx, actor, input.IdempotencyKey); loadErr == nil {
		resource := (*uuid.UUID)(nil)
		if operation == opActivate {
			resource = &rotation
		}
		if err = validateStoredRequest(stored, operation, digest, subscription, resource); err != nil {
			return WriteResult[SubscriptionResult]{}, err
		}
		value, readErr := getSubscriptionTx(ctx, tx, actor.TargetScopeID, subscription, false)
		if readErr != nil {
			return WriteResult[SubscriptionResult]{}, readErr
		}
		if err = tx.Commit(ctx); err != nil {
			return WriteResult[SubscriptionResult]{}, mapStoreError(err)
		}
		return WriteResult[SubscriptionResult]{Value: SubscriptionResult{Subscription: value}, Replayed: true}, nil
	} else if !errors.Is(loadErr, ErrNotFound) {
		return WriteResult[SubscriptionResult]{}, mapStoreError(loadErr)
	}
	facts, err := lockSubscriptionFacts(ctx, tx, actor.TargetScopeID, subscription)
	if err != nil {
		return WriteResult[SubscriptionResult]{}, err
	}
	if facts.Subscription.Status != "active" {
		return WriteResult[SubscriptionResult]{}, ErrStateConflict
	}
	if facts.Subscription.Revision != input.Revision {
		return WriteResult[SubscriptionResult]{}, ErrRevisionConflict
	}
	requestID := uuid.New()
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	if operation == opActivate {
		var status string
		var unexpired bool
		if err = tx.QueryRow(ctx, `SELECT status,COALESCE(clock_timestamp()<expires_at,false) FROM plugin_webhook_secret_versions WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR UPDATE`, actor.TargetScopeID, subscription, rotation).Scan(&status, &unexpired); errors.Is(err, pgx.ErrNoRows) {
			return WriteResult[SubscriptionResult]{}, ErrNotFound
		}
		if err != nil {
			return WriteResult[SubscriptionResult]{}, mapStoreError(err)
		}
		if status != "pending" || !unexpired {
			return WriteResult[SubscriptionResult]{}, ErrStateConflict
		}
	}
	resourceType, resourceID := "plugin_webhook_subscription", subscription
	if operation == opActivate {
		resourceType, resourceID = "plugin_webhook_secret_version", rotation
	}
	auditID, err := appendWebhookAudit(ctx, tx, webhookAuditInput{Actor: actor, Action: operation, Result: "success", Reason: "accepted", ResourceType: resourceType, ResourceID: resourceID, RequestID: input.IdempotencyKey, OccurredAt: now})
	if err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	if operation == opActivate {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,subscription_id,rotation_id,response_status,response_body,audit_event_id,created_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,200,jsonb_build_object('subscription_id',$8::uuid::text,'rotation_id',$9::uuid::text),$10,$11,$11)`, requestID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, operation, input.IdempotencyKey, digest[:], subscription, rotation, auditID, now)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_write_requests(id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,subscription_id,response_status,response_body,audit_event_id,created_at,completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,200,jsonb_build_object('subscription_id',$8::uuid::text),$9,$10,$10)`, requestID, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, operation, input.IdempotencyKey, digest[:], subscription, auditID, now)
	}
	if err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	if operation == opActivate {
		_, err = tx.Exec(ctx, `UPDATE plugin_webhook_secret_versions SET status='retired',retired_at=$4::timestamptz,expires_at=$4::timestamptz+interval '24 hours' WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 AND status='active'`, actor.TargetScopeID, subscription, facts.Subscription.ActiveSecretVersionID, now)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE plugin_webhook_secret_versions SET status='active',activated_at=$4,expires_at=NULL WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 AND status='pending'`, actor.TargetScopeID, subscription, rotation, now)
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE plugin_webhook_subscriptions SET active_secret_version_id=$3,revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,updated_at=$4 WHERE tenant_scope_id=$1 AND id=$2`, actor.TargetScopeID, subscription, rotation, now)
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE plugin_webhook_subscriptions SET status='revoked',revision=revision+1,lifecycle_sequence=lifecycle_sequence+1,revoke_sequence=lifecycle_sequence+1,updated_at=$3,revoked_at=$3 WHERE tenant_scope_id=$1 AND id=$2`, actor.TargetScopeID, subscription, now)
	}
	if err != nil {
		return WriteResult[SubscriptionResult]{}, mapStoreError(err)
	}
	value, err := getSubscriptionTx(ctx, tx, actor.TargetScopeID, subscription, false)
	if err != nil {
		return WriteResult[SubscriptionResult]{}, err
	}
	if err = store.commitBusinessWrite(ctx, tx); err != nil {
		return WriteResult[SubscriptionResult]{}, mapWriteCommitError(err)
	}
	return WriteResult[SubscriptionResult]{Value: SubscriptionResult{Subscription: value}}, nil
}

type subscriptionFacts struct {
	Subscription  Subscription
	EventSequence uint64
	TargetHost    string
	TargetPath    string
}

func lockSubscriptionFacts(ctx context.Context, tx pgx.Tx, target, subscription uuid.UUID) (subscriptionFacts, error) {
	var result subscriptionFacts
	var revision, sequence string
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,name,target_url,target_host,target_path,event_types,installation_authorization_id,installation_id,plugin_id,site_ids,status,revision::text,event_sequence::text,active_secret_version_id,created_at,updated_at FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, target, subscription).Scan(&result.Subscription.ID, &result.Subscription.TenantScopeID, &result.Subscription.Name, &result.Subscription.TargetURL, &result.TargetHost, &result.TargetPath, &result.Subscription.EventTypes, &result.Subscription.InstallationAuthorizationID, &result.Subscription.InstallationID, &result.Subscription.PluginID, &result.Subscription.SiteIDs, &result.Subscription.Status, &revision, &sequence, &result.Subscription.ActiveSecretVersionID, &result.Subscription.CreatedAt, &result.Subscription.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, mapStoreError(err)
	}
	result.Subscription.Revision, err = parseU64(revision)
	if err == nil {
		result.EventSequence, err = parseU64(sequence)
	}
	normalizeSubscription(&result.Subscription)
	return result, err
}

func loadOriginalSubscription(ctx context.Context, tx pgx.Tx, target, subscription uuid.UUID) (Subscription, error) {
	var result Subscription
	err := tx.QueryRow(ctx, `SELECT subscription.id,subscription.tenant_scope_id,subscription.name,
		subscription.target_url,subscription.event_types,subscription.installation_authorization_id,
		subscription.installation_id,subscription.plugin_id,subscription.site_ids,secret.id,subscription.created_at
		FROM plugin_webhook_subscriptions subscription
		JOIN plugin_webhook_secret_versions secret
		  ON secret.tenant_scope_id=subscription.tenant_scope_id
		 AND secret.subscription_id=subscription.id AND secret.version=1
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2
		  AND secret.created_at=subscription.created_at
		FOR SHARE OF subscription,secret`, target, subscription).Scan(
		&result.ID, &result.TenantScopeID, &result.Name, &result.TargetURL, &result.EventTypes,
		&result.InstallationAuthorizationID, &result.InstallationID, &result.PluginID, &result.SiteIDs,
		&result.ActiveSecretVersionID, &result.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, ErrStoreUnavailable
	}
	if err != nil {
		return Subscription{}, mapStoreError(err)
	}
	result.Status = "active"
	result.Revision = 1
	result.UpdatedAt = result.CreatedAt
	normalizeSubscription(&result)
	return result, nil
}

func (store *Store) storedReceipt(ctx context.Context, tx pgx.Tx, stored storedRequest, actor Actor, key, operation string, resource uuid.UUID) (string, error) {
	if stored.ReceiptCleared != nil || stored.ReceiptKeyID == nil || len(stored.ReceiptNonce) == 0 || len(stored.ReceiptCipher) == 0 {
		return "", ErrIdempotencyExpired
	}
	if stored.ReceiptExpires == nil {
		return "", ErrSecretUnavailable
	}
	var expired bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()>=$1`, *stored.ReceiptExpires).Scan(&expired); err != nil {
		return "", mapStoreError(err)
	}
	if expired {
		if _, err := tx.Exec(ctx, `UPDATE plugin_webhook_write_requests SET receipt_nonce=NULL,receipt_ciphertext=NULL,receipt_cleared_at=transaction_timestamp(),receipt_cleared_reason='expired' WHERE id=$1`, stored.ID); err != nil {
			return "", mapStoreError(err)
		}
		return "", ErrIdempotencyExpired
	}
	plaintext, err := store.cipher.decryptReceipt(ctx, encryptedReceipt{WrappingKeyID: *stored.ReceiptKeyID, Nonce: stored.ReceiptNonce, Ciphertext: stored.ReceiptCipher}, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, key, operation, resource)
	if err != nil {
		return "", err
	}
	defer clearBytes(plaintext)
	if len(plaintext) != 43 {
		return "", ErrSecretUnavailable
	}
	return string(plaintext), nil
}

func (store *Store) checkEntitlement(ctx context.Context, tx pgx.Tx, actor Actor, operation string, subscription, resource uuid.UUID, requestID string, quota bool) error {
	check := entitlementguard.FeatureCheck{TargetScopeID: actor.TargetScopeID, ActorScopeID: actor.ActorScopeID, ActorUserID: actor.ActorUserID, ResourceType: "plugin_webhook_subscription", ResourceID: resource, RequestID: requestID, Operation: operation, Feature: entitlementguard.FeatureExtensionsWebhooks}
	if quota {
		check.Quota = entitlementguard.QuotaExtensionsWebhooksCount
		check.Count = func(ctx context.Context, tx pgx.Tx) (int64, error) {
			var count int64
			err := tx.QueryRow(ctx, `SELECT count(*) FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND status='active'`, actor.TargetScopeID).Scan(&count)
			return count, err
		}
	}
	decision, err := store.entitlement.CheckFeature(ctx, tx, check)
	if err == nil {
		boundary, boundaryErr := databaseTime(ctx, tx)
		if boundaryErr != nil {
			return mapStoreError(boundaryErr)
		}
		if !entitlementDecisionUsable(decision, boundary) {
			return ErrEntitlementDenied
		}
		return nil
	}
	if errors.Is(err, entitlementguard.ErrQuotaExceeded) || errors.Is(err, entitlementguard.ErrQuotaDenied) {
		return ErrQuotaExceeded
	}
	if entitlementguard.IsDenial(err) {
		return ErrEntitlementDenied
	}
	return mapStoreError(err)
}

// entitlementDecisionUsable mirrors migration 084: grace counts as usable and
// the last verified revocation list is kept past its 15-minute window until the
// lease grace ends.
func entitlementDecisionUsable(decision entitlementguard.FeatureDecision, boundary time.Time) bool {
	return !boundary.Before(decision.NotBefore) && boundary.Before(decision.GraceUntil) &&
		!boundary.Before(decision.RevocationIssuedAt)
}

func (store *Store) commitDenial(ctx context.Context, tx pgx.Tx, denial error) error {
	if err := tx.Commit(ctx); err != nil {
		return mapStoreError(err)
	}
	return denial
}

func (store *Store) checkRate(ctx context.Context, tx pgx.Tx, actor Actor, operation string, subscription uuid.UUID) error {
	window, tenantLimit, subscriptionLimit := time.Hour, 10, 0
	switch operation {
	case opTest:
		window, tenantLimit, subscriptionLimit = time.Minute, 30, 5
	case opReplay:
		window, tenantLimit, subscriptionLimit = time.Minute, 10, 5
	case opRotate:
		window, tenantLimit, subscriptionLimit = time.Hour, 0, 5
	}
	boundary, err := databaseTime(ctx, tx)
	if err != nil {
		return mapStoreError(err)
	}
	tenantCount, tenantRemaining, subscriptionCount, subscriptionRemaining, err := rateWindowCounts(
		ctx, tx, actor.TargetScopeID, operation, subscription, window, &boundary,
	)
	if err != nil {
		return mapStoreError(err)
	}
	tenantBlocked := tenantLimit > 0 && tenantCount >= tenantLimit
	subscriptionBlocked := subscriptionLimit > 0 && subscriptionCount >= subscriptionLimit
	if !tenantBlocked && !subscriptionBlocked {
		return nil
	}
	remaining := make([]int64, 0, 2)
	if tenantBlocked {
		remaining = append(remaining, tenantRemaining)
	}
	if subscriptionBlocked {
		remaining = append(remaining, subscriptionRemaining)
	}
	retry := boundedRetryAfter(remaining...)
	rateID := uuid.New()
	resourceType, resourceID := "plugin_webhook_subscription", subscription
	if subscription == uuid.Nil {
		resourceType, resourceID = "plugin_webhook_tenant", actor.TargetScopeID
	}
	now, err := databaseTime(ctx, tx)
	if err != nil {
		return mapStoreError(err)
	}
	auditID, err := appendWebhookAudit(ctx, tx, webhookAuditInput{Actor: actor, Action: operation, Result: "denied", Reason: "rate_limited", ResourceType: resourceType, ResourceID: resourceID, RequestID: "rate-" + rateID.String(), OccurredAt: now})
	if err != nil {
		return mapStoreError(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,reason_code,audit_event_id,occurred_at) VALUES($1,$2,$3,$4,$5,$6,'denied','rate_limited',$7,$8)`, rateID, actor.TargetScopeID, nullableUUID(subscription), actor.ActorScopeID, actor.ActorUserID, operation, auditID, now)
	if err != nil {
		return mapStoreError(err)
	}
	return RateLimitError{RetryAfter: retry}
}

func lockRate(ctx context.Context, tx pgx.Tx, actor Actor, operation string, subscription uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('plugin-webhook-rate-tenant:'||$1::uuid::text||':'||$2,84))`, actor.TargetScopeID, operation); err != nil {
		return err
	}
	if subscription != uuid.Nil {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('plugin-webhook-rate-subscription:'||$1::uuid::text||':'||$2::uuid::text||':'||$3,84))`, actor.TargetScopeID, subscription, operation); err != nil {
			return err
		}
	}
	return nil
}

func rateWindowCounts(ctx context.Context, tx pgx.Tx, tenantScope uuid.UUID, operation string, subscription uuid.UUID, window time.Duration, fixedBoundary *time.Time) (int, int64, int, int64, error) {
	var tenantCount, subscriptionCount int
	var tenantRemaining, subscriptionRemaining int64
	err := tx.QueryRow(ctx, `WITH boundary AS MATERIALIZED (
			SELECT COALESCE($5::timestamptz,clock_timestamp()) AS now
		), scoped AS (
			SELECT rate.id,rate.subscription_id,rate.plugin_webhook_physical_recorded_at,boundary.now
			FROM boundary
			LEFT JOIN plugin_webhook_rate_events rate
			  ON rate.tenant_scope_id=$1 AND rate.operation=$2 AND rate.outcome='allowed'
			 AND rate.plugin_webhook_physical_recorded_at>boundary.now-$3::interval
		)
		SELECT count(id)::int,
			COALESCE(ceil(extract(epoch FROM (min(plugin_webhook_physical_recorded_at)+$3::interval-min(now))))::bigint,0),
			count(id) FILTER (WHERE subscription_id=$4)::int,
			COALESCE(ceil(extract(epoch FROM (min(plugin_webhook_physical_recorded_at) FILTER (WHERE subscription_id=$4)+$3::interval-min(now))))::bigint,0)
		FROM scoped`, tenantScope, operation, intervalLiteral(window), subscription, fixedBoundary).Scan(
		&tenantCount, &tenantRemaining, &subscriptionCount, &subscriptionRemaining,
	)
	return tenantCount, tenantRemaining, subscriptionCount, subscriptionRemaining, err
}

func insertAllowedRate(ctx context.Context, tx pgx.Tx, actor Actor, operation string, subscription, auditID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO plugin_webhook_rate_events(id,tenant_scope_id,subscription_id,actor_scope_id,actor_user_id,operation,outcome,reason_code,audit_event_id,occurred_at) VALUES($1,$2,$3,$4,$5,$6,'allowed','accepted',$7,$8)`, uuid.New(), actor.TargetScopeID, nullableUUID(subscription), actor.ActorScopeID, actor.ActorUserID, operation, auditID, now)
	return err
}

func validSubscriptionName(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && len([]rune(value)) <= 128 && !strings.ContainsFunc(value, unicode.IsControl)
}
func intervalLiteral(value time.Duration) string {
	if value == time.Minute {
		return "1 minute"
	}
	return "1 hour"
}

func boundedRetryAfter(seconds ...int64) time.Duration {
	remaining := int64(1)
	for _, value := range seconds {
		if value > remaining {
			remaining = value
		}
	}
	if remaining > 3600 {
		remaining = 3600
	}
	return time.Duration(remaining) * time.Second
}
