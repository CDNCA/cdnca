//go:build integration

package nodescheduler

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Deleting a line group a package, a
// subscription snapshot or a site still routes to is refused with what holds
// it; soft-deleted holders do not count.
func TestDeleteGroupRefusesLiveReferences(t *testing.T) {
	for name, check := range map[string]struct {
		seed  func(t *testing.T, fixture *integrationFixture, groupID uuid.UUID)
		match func(inUse *LineGroupInUseError) bool
	}{
		"package": {
			seed: func(t *testing.T, fixture *integrationFixture, groupID uuid.UUID) {
				seedLineGroupProduct(t, fixture, "香港默认体验2G", `{"node_group_id":"`+groupID.String()+`"}`, false)
				seedLineGroupProduct(t, fixture, "已删套餐", `{"node_group_id":"`+groupID.String()+`"}`, true)
				seedLineGroupProduct(t, fixture, "备用套餐", `{"backup_node_group_id":"`+groupID.String()+`"}`, false)
			},
			match: func(inUse *LineGroupInUseError) bool {
				return fmt.Sprint(inUse.Products) == "[备用套餐 香港默认体验2G]" && inUse.Subscriptions == 0 && inUse.Sites == 0
			},
		},
		"subscription snapshot": {
			seed: func(t *testing.T, fixture *integrationFixture, groupID uuid.UUID) {
				seedLineGroupSubscription(t, fixture, groupID, false)
				seedLineGroupSubscription(t, fixture, groupID, false)
				seedLineGroupSubscription(t, fixture, groupID, true)
			},
			match: func(inUse *LineGroupInUseError) bool {
				return len(inUse.Products) == 0 && inUse.Subscriptions == 2 && inUse.Sites == 0
			},
		},
		"site and fallback chain": {
			seed: func(t *testing.T, fixture *integrationFixture, groupID uuid.UUID) {
				seedLineGroupSite(t, fixture, groupID, false)
				seedLineGroupSite(t, fixture, groupID, true)
				lineGroupFixtureExec(t, fixture, `INSERT INTO fallback_chain_settings(last_resort_owner_scope_id,last_resort_line_group_id,updated_at)
					VALUES($1,$2,now()) ON CONFLICT (singleton) DO UPDATE SET
					last_resort_owner_scope_id=EXCLUDED.last_resort_owner_scope_id,last_resort_line_group_id=EXCLUDED.last_resort_line_group_id`,
					fixture.actor.ScopeID, groupID)
			},
			match: func(inUse *LineGroupInUseError) bool {
				return len(inUse.Products) == 0 && inUse.Subscriptions == 0 && inUse.Sites == 1 && inUse.Streams == 0 &&
					fmt.Sprint(inUse.Other) == "["+LineGroupUseFallbackLastResort+"]"
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			groupID := uuid.New()
			if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, fixture.putRequest(groupID, 0, "香港默认体验2G", "line-group-in-use-create")); err != nil {
				t.Fatal(err)
			}
			check.seed(t, fixture, groupID)
			_, err := fixture.service.DeleteGroup(t.Context(), fixture.actor, groupID, 1, "line-group-in-use-delete", "line-group-in-use-delete-request")
			var inUse *LineGroupInUseError
			if !errors.Is(err, ErrReferenceConflict) || !errors.As(err, &inUse) || !check.match(inUse) {
				t.Fatalf("delete err = %v (%#v)", err, inUse)
			}
			var alive bool
			if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM node_line_groups
				WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, fixture.actor.ScopeID, groupID).Scan(&alive); err != nil || !alive {
				t.Fatalf("refused delete removed the group: alive=%v err=%v", alive, err)
			}
		})
	}
}

func TestDeleteGroupWithoutLiveReferencesSucceeds(t *testing.T) {
	fixture := newIntegrationFixture(t)
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, fixture.putRequest(groupID, 0, "无引用", "line-group-free-create")); err != nil {
		t.Fatal(err)
	}
	// Only soft-deleted holders and another group's references remain.
	seedLineGroupProduct(t, fixture, "已删套餐", `{"node_group_id":"`+groupID.String()+`"}`, true)
	seedLineGroupProduct(t, fixture, "别的线路", `{"node_group_id":"`+uuid.NewString()+`"}`, false)
	seedLineGroupSubscription(t, fixture, groupID, true)
	// A cancelled subscription serves nothing (an expired active one may be renewed).
	seedLineGroupSubscription(t, fixture, groupID, false)
	lineGroupFixtureExec(t, fixture, `UPDATE package_subscriptions SET lifecycle_status='cancelled',cancelled_at=now()
		WHERE deleted_at IS NULL AND product_snapshot->'spec'->>'node_group_id'=$1`, groupID.String())
	seedLineGroupSite(t, fixture, groupID, true)
	if _, err := fixture.service.DeleteGroup(t.Context(), fixture.actor, groupID, 1, "line-group-free-delete", "line-group-free-delete-request"); err != nil {
		t.Fatalf("delete err = %v", err)
	}
}

// lineGroupFixtureExec writes a referencing row with foreign keys and
// triggers off (session_replication_role replica): only the reference columns matter.
func lineGroupFixtureExec(t *testing.T, fixture *integrationFixture, query string, args ...any) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), query, args...)
		return err
	}); err != nil {
		t.Fatalf("%.60s: %v", query, err)
	}
}

func seedLineGroupProduct(t *testing.T, fixture *integrationFixture, name, spec string, deleted bool) {
	t.Helper()
	lineGroupFixtureExec(t, fixture, `INSERT INTO package_products(id,name,spec,created_by_user_id,updated_by_user_id,created_at,updated_at,deleted_at,owner_scope_id)
		VALUES($1,$2,$3::jsonb,$4,$4,now(),now(),CASE WHEN $5 THEN now() END,$6)`, uuid.New(), name, spec, fixture.actor.UserID, deleted,
		fixture.actor.ScopeID)
}

func seedLineGroupSubscription(t *testing.T, fixture *integrationFixture, groupID uuid.UUID, deleted bool) {
	t.Helper()
	lineGroupFixtureExec(t, fixture, `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
			domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
			tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at,deleted_at)
		VALUES($1,$2,$3,1,jsonb_build_object('revision',1,'name','snapshot','spec',jsonb_build_object('node_group_id',$4::text)),
			10,10,10,0,now()-interval '1 hour',now()+interval '30 days','UTC','monthly',1,1,$5,$5,now(),now(),CASE WHEN $6 THEN now() END)`,
		uuid.New(), fixture.actor.ScopeID, uuid.New(), groupID.String(), fixture.actor.UserID, deleted)
}

func seedLineGroupSite(t *testing.T, fixture *integrationFixture, groupID uuid.UUID, deleted bool) {
	t.Helper()
	site := uuid.New()
	lineGroupFixtureExec(t, fixture, `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
			updated_by_user_id,display_id,node_group_id,deleted_at)
		VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites),$5,CASE WHEN $6 THEN now() END)`,
		site, fixture.actor.ScopeID, fixture.actor.UserID, "s"+site.String()[:8]+".line-group.example", groupID, deleted)
}
