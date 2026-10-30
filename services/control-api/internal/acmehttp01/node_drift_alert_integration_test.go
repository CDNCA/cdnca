//go:build integration

package acmehttp01

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A candidate that joins a site's line group while its epoch is open stays
// out of the frozen required set (drift, ADR-0003); the platform members who
// manage nodes are told once per epoch and drifting set, in the transaction
// that detected it, and repeats stop once the epoch closes.
func TestNodeHTTP01EpochDriftAlertsNodeManagers(t *testing.T) {
	f := newNodeFixture(t, true)
	manager := uuid.New()
	role := uuid.New()
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($1,$2,'node manager','x',now(),now())`, manager, "http01-ops-"+manager.String()[:8])
		exec(`INSERT INTO memberships(scope_id,user_id) SELECT id,$1 FROM access_scopes WHERE kind='platform'`, manager)
		exec(`INSERT INTO roles(id,scope_id,name,system_role) SELECT $1,id,'http01_ops',false FROM access_scopes
			WHERE kind='platform'`, role)
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage')`, role)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT id,$1,$2 FROM access_scopes
			WHERE kind='platform'`, manager, role)
	})
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	})
	alerts, err := notification.NewStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	f.store.EnableDriftAlerts(alerts)
	first := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if got := f.driftAlerts(t); len(got) != 0 {
		t.Fatalf("alert without drift %+v", got)
	}
	joined := f.addNode(t)
	challenges := []acmeworker.ChallengeIdentity{first}
	for range 2 { // the same drift is reported once, also by reconciliation
		challenge := f.challenge(t, "a.example.test")
		if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
			t.Fatal(err)
		}
		challenges = append(challenges, challenge)
		f.reconcile(t)
	}
	got := f.driftAlerts(t)
	if len(got) != 1 || got[0].recipient != manager || got[0].site == nil || *got[0].site != f.sites["a.example.test"] {
		t.Fatalf("drift alerts %+v", got)
	}
	// Email only by default (migration 347); the body names the site and node.
	var channels []string
	if err := f.pool.QueryRow(t.Context(), `SELECT array_agg(outbox.channel ORDER BY outbox.channel)
		FROM notification_outbox outbox JOIN notification_events event ON event.id=outbox.event_id
		WHERE event.event_type=$1 AND position('a.example.test' in outbox.body)>0
		  AND position($2 in outbox.body)>0`, EventTypeEpochDrift, "http01-"+joined.String()[:8]).Scan(&channels); err != nil {
		t.Fatal(err)
	}
	if len(channels) != 1 || channels[0] != "email" {
		t.Fatalf("drift alert outbox channels %v", channels)
	}
	if got := f.gate(t, "a.example.test", joined); got != "epoch_not_member" {
		t.Fatalf("drifting node gate %q", got)
	}
	// A larger drifting set is a new alert.
	f.addNode(t)
	f.reconcile(t)
	if got := f.driftAlerts(t); len(got) != 2 || got[1].source == got[0].source {
		t.Fatalf("drift alerts after a second join %+v", got)
	}
	// Repeats are kept only while the epoch is open.
	guard := func() bool {
		t.Helper()
		var keep bool
		err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			var err error
			keep, err = EpochDriftReplayGuard(t.Context(), tx, notification.ReplayCandidate{
				EventType: EventTypeEpochDrift, SourceEventID: got[0].source, Generation: 2})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return keep
	}
	if !guard() {
		t.Fatal("repeat withdrawn while the epoch is open")
	}
	for _, challenge := range challenges {
		if err := f.store.WithdrawChallenge(t.Context(), challenge); err != nil {
			t.Fatal(err)
		}
	}
	if guard() {
		t.Fatal("repeat kept after the epoch closed")
	}
	if got := f.gate(t, "a.example.test", joined); got != "" {
		t.Fatalf("closed epoch still gates the joined node: %q", got)
	}
}

type driftAlert struct {
	recipient uuid.UUID
	source    string
	site      *uuid.UUID // notification_events.subject_site_id (502)
}

func (f *nodeFixture) driftAlerts(t *testing.T) []driftAlert {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT recipient_user_id,source_event_id,subject_site_id FROM notification_events
		WHERE event_type=$1 ORDER BY created_at,id`, EventTypeEpochDrift)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (driftAlert, error) {
		var item driftAlert
		return item, row.Scan(&item.recipient, &item.source, &item.site)
	})
	if err != nil {
		t.Fatal(err)
	}
	return alerts
}
