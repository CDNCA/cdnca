package l4forward

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func requireStreamPorts(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID, fields Fields, current *Forward, at time.Time) error {
	// No package: no package admission and no port quota (community edition).
	if fields.PackageSubscriptionID == nil {
		return nil
	}
	subscriptionID := *fields.PackageSubscriptionID
	// Package changes release the old reservation and consume the new one in the
	// same transaction. Lock in a fixed order, including when both sides are full.
	if current != nil && current.PackageSubscriptionID != nil && *current.PackageSubscriptionID != subscriptionID {
		rows, err := tx.Query(ctx, `SELECT id FROM package_subscriptions
			WHERE tenant_scope_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR UPDATE`,
			scopeID, []uuid.UUID{*current.PackageSubscriptionID, subscriptionID})
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	limits, err := packageaddon.LockRuntimeLimits(ctx, tx, scopeID, subscriptionID, at)
	if err != nil {
		return err
	}
	if limits.OwnerUserID != ownerID {
		return ErrPermissionDenied
	}
	if limits.StreamPorts == -1 {
		return nil
	}
	var used int64
	var excluded uuid.UUID
	if current != nil {
		excluded = current.ID
	}
	// A TCP and UDP listener on the same port reserve distinct sockets; a port
	// range counts every port (migration 334). Disabled forwards retain their
	// sockets; only deletion or retiring an extra frees one.
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(COALESCE(listener.port_end, listener.port)-listener.port+1),0)
		FROM l4_forward_listeners listener
		JOIN l4_forwards forward ON forward.id=listener.stream_id
		WHERE forward.scope_id=$1 AND forward.package_subscription_id=$2 AND forward.id<>$3
		  AND forward.deleted_at IS NULL AND listener.retired_at IS NULL`,
		scopeID, subscriptionID, excluded).Scan(&used); err != nil {
		return err
	}
	requested := int64(0)
	for _, socket := range fieldSockets(&fields) {
		requested += socketPorts(socket.Port, socket.PortEnd)
	}
	if used+requested <= limits.StreamPorts {
		return nil
	}
	if current != nil && current.PackageSubscriptionID != nil && *current.PackageSubscriptionID == subscriptionID {
		previous := socketPorts(current.ListenPort, current.ListenPortEnd)
		for _, socket := range current.AdditionalListeners {
			previous += socketPorts(socket.Port, socket.PortEnd)
		}
		if (requested < previous && (current.Enabled || !fields.Enabled)) || (!fields.Enabled && requested <= previous) {
			return nil
		}
	}
	return packageaddon.ErrQuotaExceeded
}

// socketPorts is how many ports a listener reserves (a range: every port).
func socketPorts(port, end uint16) int64 {
	if end > port {
		return int64(end) - int64(port) + 1
	}
	return 1
}
