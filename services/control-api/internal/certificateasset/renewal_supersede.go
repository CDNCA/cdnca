package certificateasset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-dnscert4: a user's binding change wins over an in-flight renewal
// delivery. Nodes order a site's certificate by binding revision and refuse
// the same revision with another version, so:
//
//   - a renewal delivery reserves the revisions it sends
//     (certificate_site_binding_reservations, migration 578) and the user's
//     next binding is numbered past them (nextBindingRevisionTx);
//   - the user's change, in its own transaction, cancels the delivery's
//     queued node commands and marks it superseded_by_user; nodes that already
//     took the renewed version keep it unused (the user's publication at the
//     higher revision replaces it, the node retires it);
//   - the deliverer then re-plans the renewal from the user's new binding.

// RenewalSupersededByUser is the delivery state (and failure code) of a
// renewal whose round a user's binding change cancelled.
const RenewalSupersededByUser = "superseded_by_user"

const auditRenewalSupersededByUser = "certificate.renewal.superseded_by_user"

// RenewalDeliveryCanceller cancels a superseded delivery round's rollout in
// the caller's transaction (edgedeployment.CancelSystemSecretRolloutTx).
type RenewalDeliveryCanceller func(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID, requestID string) error

// WithRenewalDeliveryCanceller wires the rollout canceller; without one a
// superseded round is only marked (its node commands still run, and the
// reserved revisions keep the user's publication from colliding with them).
func (s *Store) WithRenewalDeliveryCanceller(canceller RenewalDeliveryCanceller) *Store {
	if s != nil {
		s.cancelRenewal = canceller
	}
	return s
}

// nextBindingRevisionTx is the site's next binding revision: past both its
// latest binding fact and any revision a renewal delivery reserved. The
// site row is locked by the caller.
func nextBindingRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, latest int64) (int64, error) {
	var reserved int64
	err := tx.QueryRow(ctx, `SELECT reserved_revision FROM certificate_site_binding_reservations
		WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`, scopeID, siteID).Scan(&reserved)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("read certificate binding reservation: %w", err)
	}
	return max(latest, reserved) + 1, nil
}

// ReserveRenewalBindingRevisionsTx records the revisions a renewal delivery
// round sends (each site's next revision) under requestID; the switch writes
// its bindings at exactly these.
func ReserveRenewalBindingRevisionsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	sites []RenewalSiteRevision, requestID string) error {
	for _, site := range sites {
		command, err := tx.Exec(ctx, `INSERT INTO certificate_site_binding_reservations(
				tenant_scope_id,site_id,reserved_revision,request_id) VALUES($1,$2,$3,$4)
			ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET reserved_revision=EXCLUDED.reserved_revision,
			  request_id=EXCLUDED.request_id,reserved_at=clock_timestamp()
			WHERE certificate_site_binding_reservations.reserved_revision<EXCLUDED.reserved_revision`,
			scopeID, site.SiteID, site.BindingRevision, requestID)
		if err != nil {
			return fmt.Errorf("reserve certificate binding revision: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrRenewalSuperseded // a later reservation exists: re-plan
		}
	}
	return nil
}

// requireRenewalReservationsTx: every site still holds the reservation the
// round made, above its latest binding fact.
func requireRenewalReservationsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sites []RenewalSiteRevision,
	requestID string) error {
	for _, site := range sites {
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_site_binding_reservations reservation
			WHERE reservation.tenant_scope_id=$1 AND reservation.site_id=$2 AND reservation.reserved_revision=$3
			  AND reservation.request_id=$4 AND NOT EXISTS (SELECT 1 FROM certificate_site_binding_facts fact
			    WHERE fact.tenant_scope_id=$1 AND fact.site_id=$2 AND fact.sequence>=$3))`,
			scopeID, site.SiteID, site.BindingRevision, requestID).Scan(&held); err != nil {
			return err
		}
		if !held {
			return ErrRenewalSuperseded
		}
	}
	return nil
}

// sameRenewalSiteSet: the same sites with the same default flag (revisions
// are checked against the reservations, not the latest facts).
func sameRenewalSiteSet(current, delivered []RenewalSiteRevision) bool {
	if len(current) != len(delivered) {
		return false
	}
	for index := range current {
		if current[index].SiteID != delivered[index].SiteID || current[index].Default != delivered[index].Default {
			return false
		}
	}
	return true
}

// supersedeRenewalDeliveriesTx cancels every in-flight renewal delivery round
// that sends a version to siteID (the user is changing the site's binding):
// its rollout's queued node commands are cancelled, the delivery becomes
// superseded_by_user and is re-planned shortly from the new binding. Runs
// after the site row is locked and before the binding fact is written.
func (s *Store) supersedeRenewalDeliveriesTx(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, siteID uuid.UUID,
	requestID string) error {
	rows, err := tx.Query(ctx, `SELECT order_id,asset_id,version_id,rollout_id,attempt FROM certificate_renewal_deliveries
		WHERE scope_id=$1 AND state='delivering' AND $2=ANY(site_ids) ORDER BY order_id FOR UPDATE`, scopeID, siteID)
	if err != nil {
		return fmt.Errorf("lock in-flight certificate renewal deliveries: %w", err)
	}
	type delivery struct {
		orderID, assetID, versionID uuid.UUID
		rolloutID                   *uuid.UUID
		attempt                     int
	}
	deliveries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (delivery, error) {
		var value delivery
		err := row.Scan(&value.orderID, &value.assetID, &value.versionID, &value.rolloutID, &value.attempt)
		return value, err
	})
	if err != nil {
		return err
	}
	for _, item := range deliveries {
		if item.rolloutID != nil && s.cancelRenewal != nil {
			if err := s.cancelRenewal(ctx, tx, scopeID, *item.rolloutID, requestID); err != nil {
				return fmt.Errorf("cancel superseded certificate renewal delivery: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_renewal_deliveries SET state='superseded_by_user',
			failure_code='superseded_by_user',next_attempt_at=clock_timestamp()+$3::bigint*interval '1 millisecond',
			updated_at=clock_timestamp() WHERE scope_id=$1 AND order_id=$2`, scopeID, item.orderID,
			renewalReplanDelay.Milliseconds()); err != nil {
			return err
		}
		payload := map[string]any{
			"order_id": item.orderID.String(), "asset_id": item.assetID.String(), "version_id": item.versionID.String(),
			"site_id": siteID.String(), "attempt": item.attempt, "reason_code": RenewalSupersededByUser,
			"cause": "user_binding_change", "state": RenewalSupersededByUser,
			"changes": map[string]any{"state": map[string]any{"before": "delivering", "after": RenewalSupersededByUser}},
		}
		if item.rolloutID != nil {
			payload["rollout_id"] = item.rolloutID.String()
		}
		if err := s.appendAudit(ctx, tx, actor, scopeID, requestID, auditRenewalSupersededByUser,
			"certificate_order", item.orderID, payload); err != nil {
			return err
		}
	}
	return nil
}

// renewalReplanDelay: a superseded renewal is re-planned after the user's
// own publication had a moment to be claimed (it waits for that anyway).
const renewalReplanDelay = 10 * time.Second
