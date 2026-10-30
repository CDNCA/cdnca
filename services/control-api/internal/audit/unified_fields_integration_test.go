package audit

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Append stores the unified-log columns, the v2 hash covers them, and the
// 361 CHECKs refuse inconsistent rows written around Append.
func TestAppendStoresUnifiedFieldsAndChainCoversThem(t *testing.T) {
	pool := isolatedAuditPool(t)
	ctx := context.Background()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO tenants(id,display_name) VALUES($1,'Unified Log')", []any{tenantID}},
		{"INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)", []any{scopeID, tenantID}},
		{"INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ulog-user','Unified','unused')", []any{userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	log := New(pool)
	requestCtx := WithSourceIP(ctx, netip.MustParseAddr("203.0.113.9"))
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := log.Append(requestCtx, tx, Event{
			ScopeID: scopeID, ActorUserID: &userID, Action: "firewall.policy.put", ResourceType: "site",
			ResourceID: "site-1", RequestID: "ulog-1", Result: "success",
			Payload: map[string]any{"changes": []map[string]any{{"field": "cc_enabled", "before": false, "after": true},
				{"field": "origin_password", "before": "old-pass", "after": "new-pass"}}},
		}); err != nil {
			return err
		}
		pluginCtx := WithActor(ctx, ContextActor{Kind: ActorPlugin, Ref: "plugin:waf-pack"})
		return log.Append(pluginCtx, tx, Event{
			ScopeID: scopeID, Action: "site.update", ResourceType: "site", ResourceID: "site-1",
			RequestID: "ulog-2", Result: "denied", Payload: map[string]any{"reason_code": "permission_denied"},
		})
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT category, actor_kind, actor_ref, source_ip, reason_code, changes::text
		FROM audit_events WHERE scope_id=$1 ORDER BY stream_position`, scopeID)
	if err != nil {
		t.Fatal(err)
	}
	type stored struct{ category, kind, ref, ip, reason, changes string }
	got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (stored, error) {
		var value stored
		err := row.Scan(&value.category, &value.kind, &value.ref, &value.ip, &value.reason, &value.changes)
		return value, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d", len(got))
	}
	if got[0].category != "security" || got[0].kind != "user" || got[0].ip != "203.0.113.9" ||
		got[0].changes != `[{"after": true, "field": "cc_enabled", "before": false}, {"after": "[REDACTED]", "field": "origin_password", "before": "[REDACTED]"}]` {
		t.Fatalf("first row = %+v", got[0])
	}
	if got[1].category != "site" || got[1].kind != "plugin" || got[1].ref != "plugin:waf-pack" ||
		got[1].reason != "permission_denied" || got[1].ip != "" {
		t.Fatalf("second row = %+v", got[1])
	}
	if err := log.VerifyScope(ctx, scopeID); err != nil {
		t.Fatalf("verify v2 chain: %v", err)
	}

	// The hash covers the new columns: rewriting one (bypassing the
	// append-only trigger as only a superuser could) breaks verification.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE audit_events SET source_ip='198.51.100.1' WHERE scope_id=$1 AND stream_position=1`, scopeID)
		return err
	}); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := log.VerifyScope(ctx, scopeID); !errors.Is(err, ErrInvalidChain) {
		t.Fatalf("verify after tampering source_ip = %v, want ErrInvalidChain", err)
	}

	for name, sql := range map[string]string{
		"user kind without user": `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
			request_id,result,event_hash,occurred_at,previous_hash,actor_kind)
			VALUES(gen_random_uuid(),$1,99,'x.y','t','r','q','success',decode(repeat('00',32),'hex'),now(),decode(repeat('00',32),'hex'),'user')`,
		"bad category": `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
			request_id,result,event_hash,occurred_at,previous_hash,category)
			VALUES(gen_random_uuid(),$1,99,'x.y','t','r','q','success',decode(repeat('00',32),'hex'),now(),decode(repeat('00',32),'hex'),'misc')`,
		"cidr source ip": `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
			request_id,result,event_hash,occurred_at,previous_hash,source_ip)
			VALUES(gen_random_uuid(),$1,99,'x.y','t','r','q','success',decode(repeat('00',32),'hex'),now(),decode(repeat('00',32),'hex'),'10.0.0.0/8')`,
		"changes not array": `INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,
			request_id,result,event_hash,occurred_at,previous_hash,changes)
			VALUES(gen_random_uuid(),$1,99,'x.y','t','r','q','success',decode(repeat('00',32),'hex'),now(),decode(repeat('00',32),'hex'),'{}')`,
	} {
		_, err := pool.Exec(ctx, sql, scopeID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("%s: err = %v, want check violation 23514", name, err)
		}
	}
}
