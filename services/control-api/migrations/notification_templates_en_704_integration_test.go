//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestNotificationTemplatesEN704: 704 adds users.locale and an English copy of every seeded template's
// current version with the Chinese row's version, channel and variables; down removes both and up applies again.
func TestNotificationTemplatesEN704(t *testing.T) {
	const version = 704
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	state := func() (english, mismatched int, column bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE source.template_id IS NULL OR source.variables <> english.variables)
			FROM notification_templates english
			LEFT JOIN notification_templates source
			  ON source.template_id IN (left(english.template_id, -6), left(english.template_id, -6) || '.zh-cn')
			 AND source.version = english.version AND source.channel = english.channel
			WHERE english.template_id LIKE '%.en-us'`).Scan(&english, &mismatched); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='users' AND column_name='locale')`).Scan(&column); err != nil {
			t.Fatal(err)
		}
		return english, mismatched, column
	}
	// An English version the operator already created on the templates page is kept as written.
	if _, err := pool.Exec(ctx, `INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at)
		SELECT 'ticket_created.en-us', version, channel, 'Operator subject', 'Operator body {{.ticket_no}} {{.subject}}', variables, now()
		FROM notification_templates WHERE template_id='ticket_created' AND version=1 AND channel='email'`); err != nil {
		t.Fatal(err)
	}
	operatorSubject := func() string {
		t.Helper()
		var subject string
		if err := pool.QueryRow(ctx, `SELECT subject FROM notification_templates
			WHERE template_id='ticket_created.en-us' AND version=1 AND channel='email'`).Scan(&subject); err != nil {
			t.Fatal(err)
		}
		return subject
	}
	for index, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		english, mismatched, column := state()
		if step == "down" {
			// 回退只删 704 插入的英文模板：运营升级前自建的 ticket_created.en-us 原样保留，登记表随之删除。
			var seedTable bool
			if err := pool.QueryRow(ctx, `SELECT to_regclass('notification_templates_seed_704') IS NOT NULL`).Scan(&seedTable); err != nil {
				t.Fatal(err)
			}
			if english != 1 || column || seedTable || operatorSubject() != "Operator subject" {
				t.Fatalf("704 down: %d English templates left (want only the operator's), users.locale=%v, seed table=%v",
					english, column, seedTable)
			}
			continue
		}
		if operatorSubject() != "Operator subject" {
			t.Fatalf("704 %s (step %d) overwrote the operator's English template", step, index)
		}
		if english != 224 || mismatched != 0 || !column {
			t.Fatalf("704 up: %d English templates, %d without a matching Chinese row, users.locale=%v",
				english, mismatched, column)
		}
	}
	var missing []string
	rows, err := pool.Query(ctx, `SELECT DISTINCT ON (template_id, channel) template_id || '/' || channel
		FROM notification_templates source
		WHERE template_id NOT LIKE '%.en-us' AND template_id <> 'tenant_member_invitation' AND NOT EXISTS (
			SELECT 1 FROM notification_templates english
			WHERE english.template_id = regexp_replace(source.template_id, '(\.zh-cn)?$', '.en-us')
			  AND english.channel = source.channel AND english.version = (
				SELECT max(version) FROM notification_templates latest
				WHERE latest.template_id = source.template_id AND latest.channel = source.channel))
		ORDER BY template_id, channel`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		missing = append(missing, key)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	if len(missing) != 0 {
		t.Errorf("704 left seeded templates without an English current version: %v", missing)
	}
	var check string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='users'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%locale%'`).Scan(&check); err != nil {
		t.Fatalf("users.locale check: %v", err)
	}

	// 回退拒绝条件按 (template_id, version, channel) 精确匹配 704 登记行：
	// 运营在 704 英文模板名下新建的版本入队不挡回退；704 自己的版本入队才拒绝。
	var seedID, seedChannel string
	var seedVersion int64
	if err := pool.QueryRow(ctx, `SELECT template_id, version, channel FROM notification_templates_seed_704
		WHERE channel='email' ORDER BY template_id LIMIT 1`).Scan(&seedID, &seedVersion, &seedChannel); err != nil {
		t.Fatal(err)
	}
	enqueue := func(version int64, key string) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,
				subject,body,dedup_key,status,attempt_count,available_at,created_at,updated_at,generation)
				VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),$1,$2,$3,
				's','b','notification-v1-'||encode(sha256($4::bytea),'hex'),'pending',0,now(),now(),now(),1)`,
				seedChannel, seedID, version, key)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	operatorVersion := seedVersion + 100
	if _, err := pool.Exec(ctx, `INSERT INTO notification_templates(template_id,version,channel,subject,body,variables,created_at)
		SELECT template_id, $2, channel, 'Operator v', body, variables, now() FROM notification_templates
		WHERE template_id=$1 AND version=$3 AND channel=$4`, seedID, operatorVersion, seedVersion, seedChannel); err != nil {
		t.Fatal(err)
	}
	enqueue(operatorVersion, "operator-version-704")
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("704 down refused although only the operator's own version is queued: %v", err)
	}
	var operatorKept bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_templates
		WHERE template_id=$1 AND version=$2 AND channel=$3)`, seedID, operatorVersion, seedChannel).Scan(&operatorKept); err != nil {
		t.Fatal(err)
	}
	if !operatorKept {
		t.Fatal("704 down deleted the operator's own version of an English template")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("704 up again: %v", err)
	}
	enqueue(seedVersion, "seed-version-704")
	err = migrateVersionIsolated(ctx, pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P7041" {
		t.Fatalf("704 down with its own English template queued: %v", err)
	}
}
