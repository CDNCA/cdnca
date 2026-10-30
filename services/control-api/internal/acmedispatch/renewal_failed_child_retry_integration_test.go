//go:build integration

package acmedispatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

func TestRenewalSchedulerReopensOnlyAnAgedFailedChild(t *testing.T) {
	fixture := newDispatchFixture(t, isolatedDispatchPool(t), dispatchFixtureOptions{
		finalizing: true, certificateLifetime: dueRenewalLifetime,
	})
	if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
		t.Fatal(err)
	}
	activateDispatchFixture(t, fixture)
	store := dnsacme.NewStore(fixture.pool)
	if scheduled, err := store.ScheduleDueRenewal(context.Background(), 30*24*time.Hour, 10*time.Minute); err != nil || !scheduled {
		t.Fatalf("initial renewal scheduling=%t error=%v", scheduled, err)
	}
	var failedChild uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT id FROM certificate_orders
		WHERE scope_id=$1 AND renewal_of_order_id=$2`, fixture.tenant.scopeID,
		fixture.request.CertificateOrderID).Scan(&failedChild); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE certificate_orders SET
		status='failed',failure_code='acme_test_failed',revision=revision+1,updated_at=statement_timestamp()
		WHERE scope_id=$1 AND id=$2`, fixture.tenant.scopeID, failedChild); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	outcome, err := store.ScheduleDueRenewalDetailed(
		context.Background(), 30*24*time.Hour, 10*time.Minute, time.Millisecond,
	)
	if err != nil || !outcome.Scheduled || !outcome.Reopened {
		t.Fatalf("failed-child retry outcome=%+v error=%v", outcome, err)
	}
	var eventTypes []string
	var auditPayload []byte
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		(SELECT array_agg(event_type ORDER BY revision) FROM acme_renewal_claim_facts
		 WHERE tenant_scope_id=$1 AND source_order_id=$2),
		(SELECT payload FROM audit_events WHERE scope_id=$1 AND action='certificate.order.renew'
		 ORDER BY occurred_at DESC LIMIT 1)`, fixture.tenant.scopeID,
		fixture.request.CertificateOrderID).Scan(&eventTypes, &auditPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Join(eventTypes, ",") != "claim_created,completed,claim_reopened,completed" {
		t.Fatalf("renewal claim events=%v", eventTypes)
	}
	var payload map[string]any
	if err := json.Unmarshal(auditPayload, &payload); err != nil ||
		payload["reason"] != "failed_renewal_retry" || payload["previous_child_order_id"] != failedChild.String() {
		t.Fatalf("retry audit payload=%s error=%v", auditPayload, err)
	}

	var latestRevision int64
	var pendingChild uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `SELECT max(revision),renewal_order_id
		FROM acme_renewal_claim_facts WHERE tenant_scope_id=$1 AND source_order_id=$2
		GROUP BY renewal_order_id HAVING renewal_order_id IS NOT NULL ORDER BY max(revision) DESC LIMIT 1`,
		fixture.tenant.scopeID, fixture.request.CertificateOrderID).Scan(&latestRevision, &pendingChild); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.pool.Exec(context.Background(), `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,lease_token,lease_expires_at,reopened_from_order_id,occurred_at
	) VALUES($1,$2,$3,$4,'claim_reopened','active',$5,$5,statement_timestamp()+interval '1 minute',$6,statement_timestamp())`,
		fixture.tenant.scopeID, fixture.request.CertificateOrderID, latestRevision+1,
		fixture.tenant.userID, uuid.New(), pendingChild)
	var pgErr interface{ SQLState() string }
	if err == nil || !errors.As(err, &pgErr) {
		t.Fatalf("pending-child claim_reopened error=%v", err)
	}
}
