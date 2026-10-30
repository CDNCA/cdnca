package pluginwebhookcontrol

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) ListSubscriptions(ctx context.Context, actor Actor, query ListQuery) (SubscriptionPage, error) {
	if query.Limit < 1 || query.Limit > 100 {
		return SubscriptionPage{}, ErrInvalidInput
	}
	before, id, err := decodeCursor(query.Cursor)
	if err != nil {
		return SubscriptionPage{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return SubscriptionPage{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionRead); err != nil {
		return SubscriptionPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT id,tenant_scope_id,name,target_url,event_types,installation_authorization_id,installation_id,plugin_id,site_ids,status,revision::text,active_secret_version_id,created_at,updated_at FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND ($2::timestamptz IS NULL OR (updated_at,id)<($2,$3)) ORDER BY updated_at DESC,id DESC LIMIT $4`, actor.TargetScopeID, nullableTime(before), nullableUUID(id), query.Limit+1)
	if err != nil {
		return SubscriptionPage{}, mapStoreError(err)
	}
	defer rows.Close()
	page := SubscriptionPage{Items: make([]Subscription, 0, query.Limit)}
	for rows.Next() {
		var value Subscription
		var revision string
		if err := rows.Scan(&value.ID, &value.TenantScopeID, &value.Name, &value.TargetURL, &value.EventTypes, &value.InstallationAuthorizationID, &value.InstallationID, &value.PluginID, &value.SiteIDs, &value.Status, &revision, &value.ActiveSecretVersionID, &value.CreatedAt, &value.UpdatedAt); err != nil {
			return SubscriptionPage{}, mapStoreError(err)
		}
		value.Revision, err = parseU64(revision)
		if err != nil {
			return SubscriptionPage{}, err
		}
		normalizeSubscription(&value)
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return SubscriptionPage{}, mapStoreError(err)
	}
	if len(page.Items) > query.Limit {
		last := page.Items[query.Limit-1]
		page.Items = page.Items[:query.Limit]
		page.NextCursor = encodeCursor(last.UpdatedAt, last.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		return SubscriptionPage{}, mapStoreError(err)
	}
	return page, nil
}

func (store *Store) GetSubscription(ctx context.Context, actor Actor, id uuid.UUID) (Subscription, error) {
	if id == uuid.Nil {
		return Subscription{}, ErrInvalidInput
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Subscription{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionRead); err != nil {
		return Subscription{}, err
	}
	value, err := getSubscriptionTx(ctx, tx, actor.TargetScopeID, id, false)
	if err != nil {
		return Subscription{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Subscription{}, mapStoreError(err)
	}
	return value, nil
}

func getSubscriptionTx(ctx context.Context, tx pgx.Tx, target, id uuid.UUID, lock bool) (Subscription, error) {
	var value Subscription
	var revision string
	query := `SELECT id,tenant_scope_id,name,target_url,event_types,installation_authorization_id,installation_id,plugin_id,site_ids,status,revision::text,active_secret_version_id,created_at,updated_at FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	err := tx.QueryRow(ctx, query, target, id).Scan(&value.ID, &value.TenantScopeID, &value.Name, &value.TargetURL, &value.EventTypes, &value.InstallationAuthorizationID, &value.InstallationID, &value.PluginID, &value.SiteIDs, &value.Status, &revision, &value.ActiveSecretVersionID, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	if err != nil {
		return Subscription{}, mapStoreError(err)
	}
	value.Revision, err = parseU64(revision)
	if err != nil {
		return Subscription{}, err
	}
	normalizeSubscription(&value)
	return value, nil
}

func (store *Store) ListDeliveries(ctx context.Context, actor Actor, subscription uuid.UUID, query ListQuery) (DeliveryPage, error) {
	if subscription == uuid.Nil || query.Limit < 1 || query.Limit > 100 {
		return DeliveryPage{}, ErrInvalidInput
	}
	before, id, err := decodeCursor(query.Cursor)
	if err != nil {
		return DeliveryPage{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return DeliveryPage{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionRead); err != nil {
		return DeliveryPage{}, err
	}
	if _, err = getSubscriptionTx(ctx, tx, actor.TargetScopeID, subscription, false); err != nil {
		return DeliveryPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT id,subscription_id,event_id,replay_of,status,attempt_count::text,next_attempt_at,created_at,completed_at FROM plugin_webhook_deliveries WHERE tenant_scope_id=$1 AND subscription_id=$2 AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4)) ORDER BY created_at DESC,id DESC LIMIT $5`, actor.TargetScopeID, subscription, nullableTime(before), nullableUUID(id), query.Limit+1)
	if err != nil {
		return DeliveryPage{}, mapStoreError(err)
	}
	defer rows.Close()
	page := DeliveryPage{Items: make([]Delivery, 0, query.Limit)}
	for rows.Next() {
		var value Delivery
		var attempts string
		if err := rows.Scan(&value.ID, &value.SubscriptionID, &value.EventID, &value.ReplayOf, &value.Status, &attempts, &value.NextAttemptAt, &value.CreatedAt, &value.CompletedAt); err != nil {
			return DeliveryPage{}, mapStoreError(err)
		}
		value.AttemptCount, err = parseU64(attempts)
		if err != nil {
			return DeliveryPage{}, err
		}
		normalizeDelivery(&value)
		page.Items = append(page.Items, value)
	}
	if err = rows.Err(); err != nil {
		return DeliveryPage{}, mapStoreError(err)
	}
	if len(page.Items) > query.Limit {
		last := page.Items[query.Limit-1]
		page.Items = page.Items[:query.Limit]
		page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	if err = tx.Commit(ctx); err != nil {
		return DeliveryPage{}, mapStoreError(err)
	}
	return page, nil
}

func (store *Store) GetDelivery(ctx context.Context, actor Actor, subscription, delivery uuid.UUID) (Delivery, error) {
	if subscription == uuid.Nil || delivery == uuid.Nil {
		return Delivery{}, ErrInvalidInput
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Delivery{}, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionRead); err != nil {
		return Delivery{}, err
	}
	value, err := getDeliveryTx(ctx, tx, actor.TargetScopeID, subscription, delivery)
	if err != nil {
		return Delivery{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Delivery{}, mapStoreError(err)
	}
	return value, nil
}

func getDeliveryTx(ctx context.Context, tx pgx.Tx, target, subscription, delivery uuid.UUID) (Delivery, error) {
	var value Delivery
	var attempts string
	err := tx.QueryRow(ctx, `SELECT id,subscription_id,event_id,replay_of,status,attempt_count::text,next_attempt_at,created_at,completed_at FROM plugin_webhook_deliveries WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`, target, subscription, delivery).Scan(&value.ID, &value.SubscriptionID, &value.EventID, &value.ReplayOf, &value.Status, &attempts, &value.NextAttemptAt, &value.CreatedAt, &value.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, ErrNotFound
	}
	if err != nil {
		return Delivery{}, mapStoreError(err)
	}
	value.AttemptCount, err = parseU64(attempts)
	if err != nil {
		return Delivery{}, err
	}
	normalizeDelivery(&value)
	return value, nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}
