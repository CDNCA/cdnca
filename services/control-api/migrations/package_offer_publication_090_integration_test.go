//go:build integration

package migrations_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPackageOfferPublication090MigrationContract(t *testing.T) {
	up := mustReadPackageOffer090(t, "090_package_offer_publication.up.sql")
	down := mustReadPackageOffer090(t, "090_package_offer_publication.down.sql")

	for _, fragment := range []string{
		"LOCK TABLE package_groups,",
		"migration 090 requires the exact verified 089 release head",
		"ERRCODE = 'P9000'",
		"abc482b3051e91756fa85e6805f17f477cb7500c1b686704c2ea5a8eaa433356",
		"0489adafea3720243cd4518a15b53485fba0c7db2844803f7788d12186a2a4e9",
		"CREATE TABLE package_offer_publication_events",
		"CREATE TABLE package_offer_publication_heads",
		"CREATE TABLE package_offer_lifecycle_lock",
		"CREATE TABLE package_catalog_commit_watermark_090",
		"CREATE TABLE package_group_state_facts_090",
		"CREATE TABLE package_product_state_facts_090",
		"CREATE TABLE package_catalog_audit_links_090",
		"CREATE FUNCTION capture_package_group_state_090()",
		"CREATE FUNCTION capture_package_product_state_090()",
		"CREATE FUNCTION bind_package_catalog_audit_090()",
		"CREATE FUNCTION current_package_catalog_xid_090()",
		"source.id=NEW.group_id AND source.revision=NEW.revision",
		"audit.id=NEW.audit_event_id",
		"audit.xmin=current_package_catalog_xid_090()",
		"CREATE CONSTRAINT TRIGGER package_catalog_watermark_completed_090",
		"CREATE CONSTRAINT TRIGGER package_group_state_facts_audited_090",
		"CREATE CONSTRAINT TRIGGER package_product_state_facts_audited_090",
		"catalog_sequence bigint NOT NULL",
		"package_offer_publication_events_append_only",
		"package_offer_catalog_requests_provenance_immutable_090",
		"package_offer_catalog_requests_no_truncate_090",
		"clock_timestamp()",
		"ERRCODE = 'P9002'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("090 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"migration 090 rollback requires the verified 090 head",
		"1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284",
		"migration 090 rollback would discard package offer publication facts",
		"catalog_sequence > 0",
		"operation IN ('package.product.publish','package.product.withdraw')",
		"ERRCODE = 'P9001'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("090 down missing %q", fragment)
		}
	}
	if strings.Contains(up, "pg_current_xact_id()") || strings.Contains(up, "::text::xid") {
		t.Error("090 publication head projection depends on epoch-unsafe transaction identity")
	}
}

func TestPackageOfferPublication090RejectsLegacyAutoPublication(t *testing.T) {
	up := mustReadPackageOffer090(t, "090_package_offer_publication.up.sql")
	for _, forbidden := range []string{
		"INSERT INTO package_offer_publication_heads SELECT",
		"INSERT INTO package_offer_publication_events SELECT",
	} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("090 migration auto-publishes legacy enabled products via %q", forbidden)
		}
	}
}

func TestPackageOfferPublication090RoundTripAndFrozenHead(t *testing.T) {
	t.Run("fresh chain and empty down up", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 89)
		identity := seedPackageOfferIdentity090(t, pool)
		seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)

		applyPackageOfferMigration090(t, pool)
		assertPackageCommerceRBAC079Ledger(t, pool, 90)
		assertPackageOfferFacts090(t, pool, 0, 0)
		if err := migrateVersionIsolated(t.Context(), pool, "down", 90); err != nil {
			t.Fatalf("empty 090 down: %v", err)
		}
		assertPackageCommerceRBAC079Ledger(t, pool, 89)
		if err := migrateVersionIsolated(t.Context(), pool, "up", 90); err != nil {
			t.Fatalf("reapply 090: %v", err)
		}
		assertPackageCommerceRBAC079Ledger(t, pool, 90)
	})

	t.Run("wrong 089 head", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 89)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=repeat('a',64) WHERE version=89`); err != nil {
			t.Fatal(err)
		}
		up, err := os.ReadFile("090_package_offer_publication.up.sql")
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(t.Context(), string(up))
		assertPackageOfferCode090(t, err, "P9000")
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.package_offer_publication_events') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("090 facts exist after rejected wrong-head migration")
		}
	})
}

func TestPackageOfferPublication090CapturesImmutableCatalogFacts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	identity := seedPackageOfferIdentity090(t, pool)
	foreign := seedPackageOfferTenantIdentity090(t, pool)
	groupID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_groups(
		id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,'Legacy package group',true,10,1,$2,$2,clock_timestamp(),clock_timestamp())`,
		groupID, identity.userID); err != nil {
		t.Fatal(err)
	}
	productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
	applyPackageOfferMigration090(t, pool)

	var groupBaseline, productBaseline, highWater int64
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM package_group_state_facts_090 WHERE catalog_sequence=0),
		(SELECT count(*) FROM package_product_state_facts_090 WHERE catalog_sequence=0),
		(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton)`).Scan(
		&groupBaseline, &productBaseline, &highWater); err != nil {
		t.Fatal(err)
	}
	if groupBaseline != 1 || productBaseline != 1 || highWater != 0 {
		t.Fatalf("baseline group/product/high-water=%d/%d/%d", groupBaseline, productBaseline, highWater)
	}

	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE package_groups SET
			name='Updated package group',visible=false,sort_order=20,revision=2,
			updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`, groupID, identity.userID); err != nil {
			return err
		}
		return insertPackageCatalogAudit090(t.Context(), tx, identity, "package.group.update",
			"package_group", groupID, map[string]any{"revision": int64(2), "visible": false})
	}); err != nil {
		t.Fatalf("valid group fact: %v", err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE package_products SET
			name='Updated package offer',enabled=false,sort_order=50,revision=2,
			updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`, productID, identity.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			SELECT id,revision,name,enabled,sort_order,spec,false,$2,clock_timestamp()
			FROM package_products WHERE id=$1`, productID, identity.userID); err != nil {
			return err
		}
		return insertPackageCatalogAudit090(t.Context(), tx, identity, "package.product.update",
			"package_product", productID, map[string]any{"revision": int64(2), "enabled": false})
	}); err != nil {
		t.Fatalf("valid product fact: %v", err)
	}

	var groupSequence, productSequence int64
	var groupName, productName string
	if err := pool.QueryRow(t.Context(), `SELECT catalog_sequence,name FROM package_group_state_facts_090
		WHERE group_id=$1 AND revision=2`, groupID).Scan(&groupSequence, &groupName); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT catalog_sequence,name FROM package_product_state_facts_090
		WHERE product_id=$1 AND revision=2`, productID).Scan(&productSequence, &productName); err != nil {
		t.Fatal(err)
	}
	if groupSequence != 1 || productSequence != 2 || groupName != "Updated package group" ||
		productName != "Updated package offer" {
		t.Fatalf("captured group/product=(%d,%q)/(%d,%q)",
			groupSequence, groupName, productSequence, productName)
	}

	if _, err := pool.Exec(t.Context(), `INSERT INTO package_product_state_facts_090(
		product_id,revision,name,enabled,sort_order,spec,deleted,actor_user_id,action,catalog_sequence)
		SELECT product_id,revision,name,enabled,sort_order,spec,deleted,actor_user_id,action,999
		FROM package_product_state_facts_090 WHERE product_id=$1 AND revision=2`, productID); err == nil {
		t.Fatal("direct product fact insertion succeeded")
	} else {
		assertPackageOfferCode090(t, err, "P9002")
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE package_fact_decoy_090(id uuid PRIMARY KEY);
		CREATE FUNCTION package_fact_decoy_insert_090() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO package_product_state_facts_090(
				product_id,revision,name,enabled,sort_order,spec,deleted,
				actor_user_id,action,catalog_sequence)
			SELECT product_id,999,name,enabled,sort_order,spec,deleted,
				actor_user_id,'baseline',0
			FROM package_product_state_facts_090 WHERE product_id=NEW.id AND revision=2;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER package_fact_decoy_insert_090 AFTER INSERT ON package_fact_decoy_090
		FOR EACH ROW EXECUTE FUNCTION package_fact_decoy_insert_090()`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_fact_decoy_090(id) VALUES($1)`, productID); err == nil {
		t.Fatal("nested trigger forged a sequence-zero product fact")
	} else {
		assertPackageOfferCode090(t, err, "P9002")
	}

	probeAuditID := uuid.New()
	if _, err := pool.Exec(t.Context(), `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,'package.catalog.integrity.check',
		'package_group',$4,'catalog-integrity-check','success','{}'::jsonb,
		previous.event_hash,$5,clock_timestamp()
	FROM (SELECT true) seed LEFT JOIN previous ON true`, probeAuditID, identity.scopeID,
		identity.userID, groupID.String(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE package_catalog_integrity_probe_090(
		group_id uuid PRIMARY KEY,audit_event_id uuid NOT NULL,scope_id uuid NOT NULL,actor_user_id uuid NOT NULL);
		CREATE FUNCTION package_catalog_integrity_probe_insert_090() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO package_catalog_audit_links_090(
				catalog_sequence,audit_event_id,fact_kind,scope_id,actor_user_id,
				action,resource_id,resource_revision)
			SELECT fact.catalog_sequence,NEW.audit_event_id,'group',NEW.scope_id,NEW.actor_user_id,
				'package.group.update',NEW.group_id,fact.revision
			FROM package_group_state_facts_090 fact
			WHERE fact.group_id=NEW.group_id AND fact.revision=3;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER package_catalog_integrity_probe_insert_090
		AFTER INSERT ON package_catalog_integrity_probe_090
		FOR EACH ROW EXECUTE FUNCTION package_catalog_integrity_probe_insert_090()`); err != nil {
		t.Fatal(err)
	}
	integrityTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = integrityTx.Exec(t.Context(), `UPDATE package_groups SET
		visible=true,revision=3,updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`,
		groupID, identity.userID); err == nil {
		_, err = integrityTx.Exec(t.Context(), `INSERT INTO package_catalog_integrity_probe_090(
			group_id,audit_event_id,scope_id,actor_user_id) VALUES($1,$2,$3,$4)`,
			groupID, probeAuditID, identity.scopeID, identity.userID)
	}
	if err == nil {
		err = integrityTx.Commit(t.Context())
	} else {
		_ = integrityTx.Rollback(t.Context())
	}
	assertPackageOfferCode090(t, err, "P9002")
	var groupRevision, integrityHighWater int64
	if err := pool.QueryRow(t.Context(), `SELECT revision,
		(SELECT high_water FROM package_catalog_commit_watermark_090 WHERE singleton)
		FROM package_groups WHERE id=$1`, groupID).Scan(&groupRevision, &integrityHighWater); err != nil {
		t.Fatal(err)
	}
	if groupRevision != 2 || integrityHighWater != 2 {
		t.Fatalf("group revision/high-water=%d/%d, want 2/2", groupRevision, integrityHighWater)
	}

	duplicateTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = insertPackageCatalogAudit090(t.Context(), duplicateTx, identity, "package.product.update",
		"package_product", productID, map[string]any{"revision": int64(2), "enabled": false})
	if err == nil {
		err = duplicateTx.Commit(t.Context())
	} else {
		_ = duplicateTx.Rollback(t.Context())
	}
	assertPackageOfferCode090(t, err, "P9002")

	sourceOnlyTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sourceOnlyTx.Exec(t.Context(), `UPDATE package_groups SET
		visible=true,revision=3,updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`,
		groupID, identity.userID); err == nil {
		err = sourceOnlyTx.Commit(t.Context())
	} else {
		_ = sourceOnlyTx.Rollback(t.Context())
	}
	assertPackageOfferCode090(t, err, "P9002")

	mismatchTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mismatchTx.Exec(t.Context(), `UPDATE package_products SET
		name='Third package offer',revision=3,updated_by_user_id=$2,updated_at=clock_timestamp()
		WHERE id=$1`, productID, identity.userID); err == nil {
		_, err = mismatchTx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			SELECT id,revision,'forged version name',enabled,sort_order,spec,false,$2,clock_timestamp()
			FROM package_products WHERE id=$1`, productID, identity.userID)
	}
	if err == nil {
		err = insertPackageCatalogAudit090(t.Context(), mismatchTx, identity, "package.product.update",
			"package_product", productID, map[string]any{"revision": int64(3), "enabled": false})
	}
	if err == nil {
		err = mismatchTx.Commit(t.Context())
	} else {
		_ = mismatchTx.Rollback(t.Context())
	}
	assertPackageOfferCode090(t, err, "P9002")

	foreignTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = foreignTx.Exec(t.Context(), `UPDATE package_groups SET
		visible=true,revision=3,updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`,
		groupID, identity.userID); err == nil {
		err = insertPackageCatalogAudit090(t.Context(), foreignTx, foreign, "package.group.update",
			"package_group", groupID, map[string]any{"revision": int64(3), "visible": true})
	}
	if err == nil {
		err = foreignTx.Commit(t.Context())
	} else {
		_ = foreignTx.Rollback(t.Context())
	}
	assertPackageOfferCode090(t, err, "P9002")
	assertPackageOfferCode090(t, migrateVersionIsolated(t.Context(), pool, "down", 90), "P9001")
}

func TestPackageOfferPublication090SerializesGroupBaselineCapture(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	identity := seedPackageOfferIdentity090(t, pool)
	groupID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_groups(
		id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,'Concurrent package group',true,10,1,$2,$2,clock_timestamp(),clock_timestamp())`,
		groupID, identity.userID); err != nil {
		t.Fatal(err)
	}

	writer, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(t.Context())
	var writerPID int32
	if err := writer.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `UPDATE package_groups SET
		name='Concurrent package group revision 2',revision=2,
		updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`, groupID, identity.userID); err != nil {
		t.Fatal(err)
	}

	migrationResult := make(chan error, 1)
	go func() {
		migrationResult <- migrateVersionIsolated(context.Background(), pool, "up", 90)
	}()
	waitCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for {
		select {
		case migrationErr := <-migrationResult:
			t.Fatalf("migration completed before package group writer committed: %v", migrationErr)
		default:
		}
		var blocked bool
		if err := pool.QueryRow(waitCtx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity activity
			WHERE $1=ANY(pg_blocking_pids(activity.pid)))`, writerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if waitCtx.Err() != nil {
			t.Fatalf("migration was not serialized behind package group writer %d", writerPID)
		}
	}
	if err := writer.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-migrationResult; err != nil {
		t.Fatal(err)
	}
	var sourceRevision, factRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT source.revision,fact.revision
		FROM package_groups source
		JOIN package_group_state_facts_090 fact
		  ON fact.group_id=source.id AND fact.revision=source.revision
		WHERE source.id=$1`, groupID).Scan(&sourceRevision, &factRevision); err != nil {
		t.Fatal(err)
	}
	if sourceRevision != 2 || factRevision != 2 {
		t.Fatalf("source/fact revision=%d/%d, want 2/2", sourceRevision, factRevision)
	}
}

func TestPackageOfferPublication090DownRejectsPublicationWriteRequests(t *testing.T) {
	for _, operation := range []string{"package.product.publish", "package.product.withdraw"} {
		for _, completed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/completed=%t", operation, completed), func(t *testing.T) {
				pool := packageCommerceRBAC079Pool(t, 90)
				identity := seedPackageOfferIdentity090(t, pool)
				claimID := uuid.New()
				if _, err := pool.Exec(t.Context(), `INSERT INTO package_catalog_write_requests(
				id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at,
				resource_id,response_status,response_body,completed_at)
				VALUES($1,$2,$3,$4,$5,$6,clock_timestamp(),
					CASE WHEN $7 THEN $8::uuid END,CASE WHEN $7 THEN 200 END,
					CASE WHEN $7 THEN '{}'::jsonb END,CASE WHEN $7 THEN clock_timestamp() END)`,
					claimID, identity.userID, identity.scopeID, operation,
					"down-request-"+claimID.String(), make([]byte, 32), completed, uuid.New()); err != nil {
					t.Fatal(err)
				}
				assertPackageOfferCode090(t, migrateVersionIsolated(t.Context(), pool, "down", 90), "P9001")
			})
		}
	}
}

func TestPackageOfferPublication090TransitionsAndGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)

	publishPackageOffer090(t, pool, identity, productID, 1, 1, "publish", nil, "publish-1")
	assertPackageOfferHead090(t, pool, productID, 1, 1, "published")

	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE package_products SET revision=2,
			updated_by_user_id=$2,updated_at=clock_timestamp() WHERE id=$1`, productID, identity.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			SELECT id,2,name,enabled,sort_order,spec,false,$2,clock_timestamp()
			FROM package_products WHERE id=$1`, productID, identity.userID); err != nil {
			return err
		}
		return insertPackageCatalogAudit090(t.Context(), tx, identity, "package.product.update",
			"package_product", productID, map[string]any{"revision": int64(2), "enabled": true})
	}); err != nil {
		t.Fatal(err)
	}
	previous := int64(1)
	publishPackageOffer090(t, pool, identity, productID, 2, 2, "replace", &previous, "replace-2")
	assertPackageOfferHead090(t, pool, productID, 2, 2, "published")
	publishPackageOffer090(t, pool, identity, productID, 2, 3, "withdraw", packageOfferInt64Ptr090(2), "withdraw-2")
	assertPackageOfferHead090(t, pool, productID, 2, 3, "withdrawn")
	assertPackageOfferFacts090(t, pool, 3, 1)

	if _, err := pool.Exec(t.Context(), `UPDATE package_offer_publication_heads SET state='published'
		WHERE product_id=$1`, productID); err == nil {
		t.Fatal("direct publication head update unexpectedly succeeded")
	} else {
		assertPackageOfferCode090(t, err, "P9002")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM package_offer_lifecycle_lock`); err == nil {
		t.Fatal("package offer lifecycle lock deletion unexpectedly succeeded")
	} else {
		assertPackageOfferCode090(t, err, "P9002")
	}
	for _, statement := range []string{
		`DELETE FROM package_offer_publication_events WHERE product_id='` + productID.String() + `'`,
		`TRUNCATE package_offer_publication_events CASCADE`,
		`DELETE FROM package_offer_publication_heads WHERE product_id='` + productID.String() + `'`,
		`TRUNCATE package_offer_publication_heads`,
		`UPDATE package_offer_lifecycle_lock SET singleton=true`,
		`TRUNCATE package_offer_lifecycle_lock`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Fatalf("immutable publication statement succeeded: %s", statement)
		} else {
			assertPackageOfferCode090(t, err, "P9002")
		}
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE package_offer_head_decoy_090(product_id uuid PRIMARY KEY);
		CREATE FUNCTION package_offer_head_decoy_update_090() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			UPDATE package_offer_publication_heads SET state='published' WHERE product_id=NEW.product_id;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER package_offer_head_decoy_update_090 AFTER INSERT ON package_offer_head_decoy_090
		FOR EACH ROW EXECUTE FUNCTION package_offer_head_decoy_update_090()`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_offer_head_decoy_090(product_id) VALUES($1)`, productID); err == nil {
		t.Fatal("nested trigger forged a publication head update")
	} else {
		assertPackageOfferCode090(t, err, "P9002")
	}
	assertPackageOfferCode090(t, migrateVersionIsolated(t.Context(), pool, "down", 90), "P9001")
}

func TestPackageOfferPublication090RejectsIncompleteAndInvalidFacts(t *testing.T) {
	t.Run("incomplete write claim", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 90)
		identity := seedPackageOfferIdentity090(t, pool)
		productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
		claimID := insertPackageOfferClaim090(t, tx, identity, "package.product.publish", "incomplete")
		insertPackageOfferEvent090(t, tx, identity, productID, 1, 1, "publish", nil, claimID)
		assertPackageOfferCode090(t, tx.Commit(t.Context()), "P9002")
		assertPackageOfferFacts090(t, pool, 0, 0)
	})

	t.Run("missing publication audit", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 90)
		identity := seedPackageOfferIdentity090(t, pool)
		productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
		claimID := insertPackageOfferClaim090(t, tx, identity, "package.product.publish", "missing-audit")
		insertPackageOfferEvent090(t, tx, identity, productID, 1, 1, "publish", nil, claimID)
		if _, err := tx.Exec(t.Context(), `UPDATE package_catalog_write_requests
			SET resource_id=$2,response_status=200,response_body='{}'::jsonb,completed_at=clock_timestamp()
			WHERE id=$1`, claimID, productID); err != nil {
			t.Fatal(err)
		}
		assertPackageOfferCode090(t, tx.Commit(t.Context()), "P9002")
		assertPackageOfferFacts090(t, pool, 0, 0)
	})

	t.Run("invalid first transition", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 90)
		identity := seedPackageOfferIdentity090(t, pool)
		productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
		claimID := insertPackageOfferClaim090(t, tx, identity, "package.product.publish", "invalid-first")
		_, err = tx.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
			id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
			write_request_id,actor_scope_id,actor_user_id,occurred_at)
			VALUES($1,$2,1,2,'publish',NULL,$3,$4,$5,clock_timestamp())`,
			uuid.New(), productID, claimID, identity.scopeID, identity.userID)
		assertPackageOfferCode090(t, err, "P9002")
	})

	t.Run("unsupported direct SQL policy", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 90)
		identity := seedPackageOfferIdentity090(t, pool)
		valid := validPackageOfferSpec090()
		mutatedSpec := func(mutate func(map[string]any)) string {
			t.Helper()
			var payload map[string]any
			if err := json.Unmarshal([]byte(valid), &payload); err != nil {
				t.Fatal(err)
			}
			mutate(payload)
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
		for index, test := range []struct {
			name    string
			spec    string
			enabled bool
		}{
			{name: "extra top level key", spec: mutatedSpec(func(spec map[string]any) { spec["extra"] = true }), enabled: true},
			{name: "missing region", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "region_id") }), enabled: true},
			{name: "nil region", spec: mutatedSpec(func(spec map[string]any) { spec["region_id"] = "00000000-0000-0000-0000-000000000000" }), enabled: true},
			{name: "missing node group", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "node_group_id") }), enabled: true},
			{name: "backup equals node group", spec: mutatedSpec(func(spec map[string]any) {
				spec["backup_node_group_id"] = spec["node_group_id"]
			}), enabled: true},
			{name: "noncanonical description", spec: mutatedSpec(func(spec map[string]any) { spec["description"] = " padded " }), enabled: true},
			{name: "missing prices", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "prices") }), enabled: true},
			{name: "extra price key", spec: mutatedSpec(func(spec map[string]any) { spec["prices"].(map[string]any)["weekly_minor"] = 1 }), enabled: true},
			{name: "missing monthly price", spec: mutatedSpec(func(spec map[string]any) {
				delete(spec["prices"].(map[string]any), "monthly_minor")
			}), enabled: true},
			{name: "string monthly price", spec: mutatedSpec(func(spec map[string]any) {
				spec["prices"].(map[string]any)["monthly_minor"] = "100"
			}), enabled: true},
			{name: "oversized monthly price", spec: mutatedSpec(func(spec map[string]any) {
				spec["prices"].(map[string]any)["monthly_minor"] = int64(1_000_000_000_000_001)
			}), enabled: true},
			{name: "missing limits", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "limits") }), enabled: true},
			{name: "extra limit key", spec: mutatedSpec(func(spec map[string]any) { spec["limits"].(map[string]any)["requests"] = 1 }), enabled: true},
			{name: "boolean domain limit", spec: mutatedSpec(func(spec map[string]any) {
				spec["limits"].(map[string]any)["domains"] = true
			}), enabled: true},
			{name: "fractional connection limit", spec: mutatedSpec(func(spec map[string]any) {
				spec["limits"].(map[string]any)["connections"] = 1.5
			}), enabled: true},
			{name: "oversized traffic limit", spec: mutatedSpec(func(spec map[string]any) {
				spec["limits"].(map[string]any)["monthly_traffic_bytes"] = int64(1<<60 + 1)
			}), enabled: true},
			{name: "empty groups", spec: mutatedSpec(func(spec map[string]any) { spec["group_ids"] = []any{} }), enabled: true},
			{name: "malformed group", spec: mutatedSpec(func(spec map[string]any) {
				spec["group_ids"] = []any{"NOT-A-UUID"}
			}), enabled: true},
			{name: "duplicate group", spec: mutatedSpec(func(spec map[string]any) {
				group := spec["group_ids"].([]any)[0]
				spec["group_ids"] = []any{group, group}
			}), enabled: true},
			{name: "name snapshot mismatch", spec: mutatedSpec(func(spec map[string]any) {
				spec["name"] = "forged offer name"
			}), enabled: true},
			{name: "missing protection", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "protection") }), enabled: true},
			{name: "oversized protection", spec: mutatedSpec(func(spec map[string]any) {
				spec["protection"].(map[string]any)["cc"] = strings.Repeat("x", 257)
			}), enabled: true},
			{name: "missing cname", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "cname") }), enabled: true},
			{name: "invalid cname domain", spec: mutatedSpec(func(spec map[string]any) {
				spec["cname"].(map[string]any)["domain"] = "Bad_Domain"
			}), enabled: true},
			{name: "unknown cname mode", spec: mutatedSpec(func(spec map[string]any) {
				spec["cname"].(map[string]any)["mode"] = "legacy"
			}), enabled: true},
			{name: "missing purchase", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "purchase") }), enabled: true},
			{name: "extra purchase key", spec: mutatedSpec(func(spec map[string]any) { spec["purchase"].(map[string]any)["trial"] = true }), enabled: true},
			{name: "string site limit", spec: strings.Replace(valid, `"site_limit":10`, `"site_limit":"10"`, 1), enabled: true},
			{name: "oversized site limit", spec: strings.Replace(valid, `"site_limit":10`, `"site_limit":1000000001`, 1), enabled: true},
			{name: "unknown timezone", spec: strings.Replace(valid, `"timezone":"Asia/Shanghai"`, `"timezone":"Mars/Olympus"`, 1), enabled: true},
			{name: "invalid custom cycle", spec: strings.Replace(strings.Replace(valid, `"cycle_kind":"monthly"`, `"cycle_kind":"custom_days"`, 1), `"custom_cycle_days":0`, `"custom_cycle_days":367`, 1), enabled: true},
			{name: "malformed sale expiry", spec: strings.Replace(valid, `"sale_expires_at":null`, `"sale_expires_at":"not-a-time"`, 1), enabled: true},
			{name: "infinite sale expiry", spec: strings.Replace(valid, `"sale_expires_at":null`, `"sale_expires_at":"infinity"`, 1), enabled: true},
			{name: "noncanonical sale expiry", spec: strings.Replace(valid, `"sale_expires_at":null`, `"sale_expires_at":"2099-01-01 00:00:00+00"`, 1), enabled: true},
			{name: "missing sort order", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "sort_order") }), enabled: true},
			{name: "negative sort order", spec: mutatedSpec(func(spec map[string]any) { spec["sort_order"] = -1 }), enabled: true},
			{name: "missing enabled", spec: mutatedSpec(func(spec map[string]any) { delete(spec, "enabled") }), enabled: true},
			{name: "wrong enabled type", spec: mutatedSpec(func(spec map[string]any) { spec["enabled"] = "true" }), enabled: true},
			{name: "disabled version", spec: valid, enabled: false},
		} {
			t.Run(test.name, func(t *testing.T) {
				productID := seedPackageOfferProductEnabled090(t, pool, identity.userID, test.spec, 1, test.enabled)
				tx, err := pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context())
				acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
				claimID := insertPackageOfferClaim090(t, tx, identity, "package.product.publish",
					fmt.Sprintf("bad-policy-%d", index))
				_, err = tx.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
					id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
					write_request_id,actor_scope_id,actor_user_id,occurred_at)
					VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
					uuid.New(), productID, claimID, identity.scopeID, identity.userID)
				assertPackageOfferCode090(t, err, "P9002")
			})
		}
		assertPackageOfferFacts090(t, pool, 0, 0)
	})
}

func TestPackageOfferPublication090AcceptsReducedTrafficFactor(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	spec := strings.Replace(validPackageOfferSpec090(),
		`"tcp_factor_numerator":1,"tcp_factor_denominator":1`,
		`"tcp_factor_numerator":1100000,"tcp_factor_denominator":1000000`, 1)
	productID := seedPackageOfferProduct090(t, pool, identity.userID, spec, 1)
	publishPackageOffer090(t, pool, identity, productID, 1, 1, "publish", nil, "reduced-factor")
	assertPackageOfferFacts090(t, pool, 1, 1)
}

func TestPackageOfferPublication090ProtectsCompletedProvenance(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
	publishPackageOffer090(t, pool, identity, productID, 1, 1, "publish", nil, "immutable-provenance")

	var claimID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT write_request_id
		FROM package_offer_publication_events WHERE product_id=$1`, productID).Scan(&claimID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE package_catalog_write_requests SET response_body='{"forged":true}'::jsonb WHERE id='` + claimID.String() + `'`,
		`DELETE FROM package_catalog_write_requests WHERE id='` + claimID.String() + `'`,
		`TRUNCATE package_catalog_write_requests CASCADE`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Fatalf("completed publication provenance mutation succeeded: %s", statement)
		} else {
			assertPackageOfferCode090(t, err, "P9002")
		}
	}
	var responseBody string
	if err := pool.QueryRow(t.Context(), `SELECT response_body::text
		FROM package_catalog_write_requests WHERE id=$1`, claimID).Scan(&responseBody); err != nil {
		t.Fatal(err)
	}
	if responseBody != `{}` {
		t.Fatalf("publication replay response changed to %s", responseBody)
	}
	assertPackageOfferFacts090(t, pool, 1, 1)
}

func TestPackageOfferPublication090RejectsMismatchedClaims(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	other := seedPackageOfferIdentity090(t, pool)

	tests := []struct {
		name      string
		operation string
		event     packageOfferIdentity090
		resource  uuid.UUID
		status    int
		commit    bool
	}{
		{name: "wrong operation", operation: "package.product.withdraw", event: identity},
		{name: "wrong actor and scope", operation: "package.product.publish", event: other},
		{name: "wrong completed resource", operation: "package.product.publish", event: identity,
			resource: uuid.New(), status: 200, commit: true},
		{name: "wrong completed status", operation: "package.product.publish", event: identity,
			status: 201, commit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			acquirePackageOfferIAMLocks090(t, tx, test.event.scopeID)
			claimID := insertPackageOfferClaim090(t, tx, identity, test.operation, "mismatch-"+test.name)
			_, err = tx.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
				id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
				write_request_id,actor_scope_id,actor_user_id,occurred_at)
				VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
				uuid.New(), productID, claimID, test.event.scopeID, test.event.userID)
			if !test.commit {
				assertPackageOfferCode090(t, err, "P9002")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			resourceID := test.resource
			if resourceID == uuid.Nil {
				resourceID = productID
			}
			if _, err := tx.Exec(t.Context(), `UPDATE package_catalog_write_requests
				SET resource_id=$2,response_status=$3,response_body='{}'::jsonb,
					completed_at=clock_timestamp() WHERE id=$1`, claimID, resourceID, test.status); test.status != 200 {
				assertPackageOfferCode090(t, err, "P9002")
				return
			} else if err != nil {
				t.Fatal(err)
			}
			assertPackageOfferCode090(t, tx.Commit(t.Context()), "P9002")
		})
	}
	assertPackageOfferFacts090(t, pool, 0, 0)
}

func TestPackageOfferPublication090RequiresLivePlatformManage(t *testing.T) {
	tests := []struct {
		name   string
		tenant bool
		mutate string
	}{
		{name: "tenant scope", tenant: true},
		{name: "disabled user", mutate: `WITH input AS (
			SELECT $1::uuid AS user_id,$2::uuid AS scope_id,$3::uuid AS role_id
		) UPDATE users SET status='disabled' FROM input WHERE id=input.user_id`},
		{name: "suspended membership", mutate: `WITH input AS (
			SELECT $1::uuid AS user_id,$2::uuid AS scope_id,$3::uuid AS role_id
		) UPDATE memberships SET status='suspended' FROM input
			WHERE memberships.scope_id=input.scope_id AND memberships.user_id=input.user_id`},
		{name: "assignment revoked", mutate: `WITH input AS (
			SELECT $1::uuid AS user_id,$2::uuid AS scope_id,$3::uuid AS role_id
		) DELETE FROM role_assignments USING input
			WHERE role_assignments.scope_id=input.scope_id AND role_assignments.user_id=input.user_id`},
		{name: "permission drift", mutate: `WITH input AS (
			SELECT $1::uuid AS user_id,$2::uuid AS scope_id,$3::uuid AS role_id
		) DELETE FROM role_permissions USING input
			WHERE role_permissions.role_id=input.role_id AND permission_name='packages.manage'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 90)
			platformIdentity := seedPackageOfferIdentity090(t, pool)
			productID := seedPackageOfferProduct090(t, pool, platformIdentity.userID,
				validPackageOfferSpec090(), 1)
			identity := platformIdentity
			if test.tenant {
				identity = seedPackageOfferTenantIdentity090(t, pool)
			}
			if test.mutate != "" {
				if _, err := pool.Exec(t.Context(), test.mutate, identity.userID, identity.scopeID, identity.roleID); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
			claimID := insertPackageOfferClaim090(t, tx, identity, "package.product.publish", "rbac-"+test.name)
			_, err = tx.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
				id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
				write_request_id,actor_scope_id,actor_user_id,occurred_at)
				VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
				uuid.New(), productID, claimID, identity.scopeID, identity.userID)
			assertPackageOfferCode090(t, err, "P9002")
			assertPackageOfferFacts090(t, pool, 0, 0)
		})
	}
}

func TestPackageOfferPublication090SerializesConcurrentRBACRevoke(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
	claimID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_catalog_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,'package.product.publish','rbac-race',$4,clock_timestamp())`,
		claimID, identity.userID, identity.scopeID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	revoker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer revoker.Rollback(t.Context())
	if _, err := revoker.Exec(t.Context(), `SELECT iam_global_lock_exclusive_v1()`); err != nil {
		t.Fatal(err)
	}
	if _, err := revoker.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, identity.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := revoker.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, identity.scopeID, identity.userID, identity.roleID); err != nil {
		t.Fatal(err)
	}
	var revokerPID int32
	if err := revoker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revokerPID); err != nil {
		t.Fatal(err)
	}

	waiterPID := make(chan int32, 1)
	result := make(chan error, 1)
	go func() {
		tx, beginErr := pool.Begin(context.Background())
		if beginErr != nil {
			result <- beginErr
			return
		}
		defer tx.Rollback(context.Background())
		var pid int32
		if beginErr = tx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); beginErr != nil {
			result <- beginErr
			return
		}
		waiterPID <- pid
		if _, beginErr = tx.Exec(context.Background(), `SELECT iam_global_lock_shared_v1()`); beginErr != nil {
			result <- beginErr
			return
		}
		if _, beginErr = tx.Exec(context.Background(), `SELECT iam_scope_locks_v1($1::uuid[])`,
			[]uuid.UUID{identity.scopeID}); beginErr != nil {
			result <- beginErr
			return
		}
		_, beginErr = tx.Exec(context.Background(), `INSERT INTO package_offer_publication_events(
			id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
			write_request_id,actor_scope_id,actor_user_id,occurred_at)
			VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
			uuid.New(), productID, claimID, identity.scopeID, identity.userID)
		result <- beginErr
	}()
	blockedPID := <-waiterPID
	waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		var blockers []int32
		if err := pool.QueryRow(waitCtx, `SELECT pg_blocking_pids($1)`, blockedPID).Scan(&blockers); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, blocker := range blockers {
			found = found || blocker == revokerPID
		}
		if found {
			break
		}
		if waitCtx.Err() != nil {
			t.Fatalf("publication backend %d was not blocked by RBAC revoker %d", blockedPID, revokerPID)
		}
	}
	if err := revoker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPackageOfferCode090(t, <-result, "P9002")
	assertPackageOfferFacts090(t, pool, 0, 0)
}

func TestPackageOfferPublication090SerializesDifferentProducts(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	firstProduct := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
	secondProduct := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)

	first, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(t.Context())
	acquirePackageOfferIAMLocks090(t, first, identity.scopeID)
	firstClaim := insertPackageOfferClaim090(t, first, identity, "package.product.publish", "serialize-first")
	insertPackageOfferEvent090(t, first, identity, firstProduct, 1, 1, "publish", nil, firstClaim)

	second, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(t.Context())
	if _, err := second.Exec(t.Context(), `SET LOCAL lock_timeout='250ms'`); err != nil {
		t.Fatal(err)
	}
	acquirePackageOfferIAMLocks090(t, second, identity.scopeID)
	secondClaim := insertPackageOfferClaim090(t, second, identity, "package.product.publish", "serialize-second")
	_, err = second.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
		id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
		write_request_id,actor_scope_id,actor_user_id,occurred_at)
		VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
		uuid.New(), secondProduct, secondClaim, identity.scopeID, identity.userID)
	assertPackageOfferCode090(t, err, "55P03")
}

func TestPackageOfferPublication090SameProductHasOneWinner(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 90)
	identity := seedPackageOfferIdentity090(t, pool)
	productID := seedPackageOfferProduct090(t, pool, identity.userID, validPackageOfferSpec090(), 1)
	first, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(t.Context())
	var firstPID int32
	if err := first.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	acquirePackageOfferIAMLocks090(t, first, identity.scopeID)
	firstClaim := insertPackageOfferClaim090(t, first, identity, "package.product.publish", "same-winner")
	insertPackageOfferEvent090(t, first, identity, productID, 1, 1, "publish", nil, firstClaim)
	insertPackageOfferAudit090(t, first, identity, productID, 1, 1, "publish")
	if _, err := first.Exec(t.Context(), `UPDATE package_catalog_write_requests
		SET resource_id=$2,response_status=200,response_body='{}'::jsonb,completed_at=clock_timestamp()
		WHERE id=$1`, firstClaim, productID); err != nil {
		t.Fatal(err)
	}

	secondPID := make(chan int32, 1)
	secondResult := make(chan error, 1)
	go func() {
		tx, beginErr := pool.Begin(context.Background())
		if beginErr != nil {
			secondResult <- beginErr
			return
		}
		defer tx.Rollback(context.Background())
		if _, beginErr = tx.Exec(context.Background(), `SELECT iam_global_lock_shared_v1()`); beginErr != nil {
			secondResult <- beginErr
			return
		}
		if _, beginErr = tx.Exec(context.Background(), `SELECT iam_scope_locks_v1($1::uuid[])`,
			[]uuid.UUID{identity.scopeID}); beginErr != nil {
			secondResult <- beginErr
			return
		}
		claimID := uuid.New()
		if _, beginErr = tx.Exec(context.Background(), `INSERT INTO package_catalog_write_requests(
			id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,'package.product.publish','same-loser',$4,clock_timestamp())`,
			claimID, identity.userID, identity.scopeID, make([]byte, 32)); beginErr != nil {
			secondResult <- beginErr
			return
		}
		var pid int32
		if beginErr = tx.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); beginErr != nil {
			secondResult <- beginErr
			return
		}
		secondPID <- pid
		_, beginErr = tx.Exec(context.Background(), `INSERT INTO package_offer_publication_events(
			id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
			write_request_id,actor_scope_id,actor_user_id,occurred_at)
			VALUES($1,$2,1,1,'publish',NULL,$3,$4,$5,clock_timestamp())`,
			uuid.New(), productID, claimID, identity.scopeID, identity.userID)
		secondResult <- beginErr
	}()
	waiterPID := <-secondPID
	waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		var blockers []int32
		if err := pool.QueryRow(waitCtx, `SELECT pg_blocking_pids($1)`, waiterPID).Scan(&blockers); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, blocker := range blockers {
			found = found || blocker == firstPID
		}
		if found {
			break
		}
		if waitCtx.Err() != nil {
			t.Fatalf("second publication was not blocked by first backend %d", firstPID)
		}
	}
	if err := first.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPackageOfferCode090(t, <-secondResult, "P9002")
	assertPackageOfferFacts090(t, pool, 1, 1)
}

type packageOfferIdentity090 struct {
	scopeID uuid.UUID
	userID  uuid.UUID
	roleID  uuid.UUID
}

func seedPackageOfferIdentity090(t *testing.T, pool *pgxpool.Pool) packageOfferIdentity090 {
	t.Helper()
	identity := packageOfferIdentity090{userID: uuid.New(), roleID: uuid.New()}
	username := "offer-" + strings.ReplaceAll(identity.userID.String(), "-", "")
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind)
			SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`,
			uuid.New()); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&identity.scopeID); err != nil {
			return err
		}
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'offer actor','hash')`, []any{identity.userID, username}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{identity.scopeID, identity.userID}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'offer role',true)`,
				[]any{identity.roleID, identity.scopeID, "offer_role_" + strings.ReplaceAll(identity.userID.String(), "-", "")}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'packages.manage')`, []any{identity.roleID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
				[]any{identity.scopeID, identity.userID, identity.roleID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func seedPackageOfferTenantIdentity090(t *testing.T, pool *pgxpool.Pool) packageOfferIdentity090 {
	t.Helper()
	identity := packageOfferIdentity090{scopeID: uuid.New(), userID: uuid.New(), roleID: uuid.New()}
	tenantID := uuid.New()
	username := "tenant-offer-" + strings.ReplaceAll(identity.userID.String(), "-", "")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'tenant offer 090')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{identity.scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'tenant offer actor','hash')`, []any{identity.userID, username}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{identity.scopeID, identity.userID}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','offer role',true)`, []any{identity.roleID, identity.scopeID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{identity.scopeID, identity.userID, identity.roleID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return identity
}

func seedPackageOfferProduct090(t *testing.T, pool *pgxpool.Pool, actorID uuid.UUID, spec string, revision int64) uuid.UUID {
	return seedPackageOfferProductEnabled090(t, pool, actorID, spec, revision, true)
}

func seedPackageOfferProductEnabled090(t *testing.T, pool *pgxpool.Pool, actorID uuid.UUID,
	spec string, revision int64, enabled bool,
) uuid.UUID {
	t.Helper()
	productID := uuid.New()
	name := "Offer " + productID.String()
	var payload map[string]any
	if err := json.Unmarshal([]byte(spec), &payload); err != nil {
		t.Fatal(err)
	}
	if current, ok := payload["name"].(string); !ok || current == "Published offer" {
		payload["name"] = name
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	spec = string(encoded)
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(
			id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,100,$4::jsonb,$5,$6,$6,clock_timestamp(),clock_timestamp())`,
			productID, name, enabled, spec, revision, actorID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			VALUES($1,$2,$3,$4,100,$5::jsonb,false,$6,clock_timestamp())`,
			productID, revision, name, enabled, spec, actorID); err != nil {
			return err
		}
		var durableSchema bool
		if err := tx.QueryRow(t.Context(), `SELECT to_regclass('package_catalog_commit_watermark_090') IS NOT NULL`).Scan(
			&durableSchema); err != nil || !durableSchema {
			return err
		}
		var scopeID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT membership.scope_id
			FROM memberships membership JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE membership.user_id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL`, actorID).Scan(&scopeID); err != nil {
			return err
		}
		return insertPackageCatalogAudit090(t.Context(), tx,
			packageOfferIdentity090{scopeID: scopeID, userID: actorID}, "package.product.create",
			"package_product", productID, map[string]any{"revision": revision, "enabled": enabled})
	})
	if err != nil {
		t.Fatal(err)
	}
	return productID
}

func publishPackageOffer090(t *testing.T, pool *pgxpool.Pool, identity packageOfferIdentity090,
	productID uuid.UUID, productRevision, lifecycleRevision int64, eventType string,
	previousRevision *int64, key string,
) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	operation := "package.product.publish"
	if eventType == "withdraw" {
		operation = "package.product.withdraw"
	}
	acquirePackageOfferIAMLocks090(t, tx, identity.scopeID)
	claimID := insertPackageOfferClaim090(t, tx, identity, operation, key)
	insertPackageOfferEvent090(t, tx, identity, productID, productRevision, lifecycleRevision,
		eventType, previousRevision, claimID)
	insertPackageOfferAudit090(t, tx, identity, productID, productRevision, lifecycleRevision, eventType)
	if _, err := tx.Exec(t.Context(), `UPDATE package_catalog_write_requests
		SET resource_id=$2,response_status=200,response_body='{}'::jsonb,completed_at=clock_timestamp()
		WHERE id=$1`, claimID, productID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func acquirePackageOfferIAMLocks090(t *testing.T, tx pgx.Tx, scopeIDs ...uuid.UUID) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1($1::uuid[])`, scopeIDs); err != nil {
		t.Fatal(err)
	}
}

func insertPackageOfferAudit090(t *testing.T, tx pgx.Tx, identity packageOfferIdentity090,
	productID uuid.UUID, productRevision, lifecycleRevision int64, eventType string,
) {
	t.Helper()
	action := "package.product.publish"
	payload := map[string]any{
		"product_revision": productRevision, "lifecycle_revision": lifecycleRevision,
	}
	if eventType == "withdraw" {
		action = "package.product.withdraw"
	} else {
		payload["event_type"] = eventType
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	), publication AS (
		SELECT occurred_at FROM package_offer_publication_events
		WHERE product_id=$5::uuid AND product_revision=$9 AND lifecycle_revision=$10
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
		SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,$4,'package_product',$5,
			$6,'success',$7::jsonb,previous.event_hash,$8,publication.occurred_at
		FROM publication LEFT JOIN previous ON true`, uuid.New(), identity.scopeID, identity.userID, action,
		productID.String(), "offer-audit-"+uuid.NewString(), encoded, make([]byte, 32),
		productRevision, lifecycleRevision); err != nil {
		t.Fatal(err)
	}
}

func insertPackageCatalogAudit090(ctx context.Context, tx pgx.Tx, identity packageOfferIdentity090,
	action, resourceType string, resourceID uuid.UUID, payload map[string]any,
) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,$4,$5,$6,
		$7,'success',$8::jsonb,previous.event_hash,$9,clock_timestamp()
	FROM (SELECT true) seed LEFT JOIN previous ON true`, uuid.New(), identity.scopeID,
		identity.userID, action, resourceType, resourceID.String(),
		"catalog-audit-"+uuid.NewString(), encoded, make([]byte, 32))
	return err
}

func insertPackageOfferClaim090(t *testing.T, tx pgx.Tx, identity packageOfferIdentity090,
	operation, key string,
) uuid.UUID {
	t.Helper()
	claimID := uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO package_catalog_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,clock_timestamp())`, claimID, identity.userID,
		identity.scopeID, operation, key, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return claimID
}

func insertPackageOfferEvent090(t *testing.T, tx pgx.Tx, identity packageOfferIdentity090,
	productID uuid.UUID, productRevision, lifecycleRevision int64, eventType string,
	previousRevision *int64, claimID uuid.UUID,
) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), `INSERT INTO package_offer_publication_events(
		id,product_id,product_revision,lifecycle_revision,event_type,previous_product_revision,
		write_request_id,actor_scope_id,actor_user_id,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())`, uuid.New(), productID,
		productRevision, lifecycleRevision, eventType, previousRevision, claimID,
		identity.scopeID, identity.userID); err != nil {
		t.Fatal(err)
	}
}

func assertPackageOfferFacts090(t *testing.T, pool *pgxpool.Pool, events, heads int64) {
	t.Helper()
	var gotEvents, gotHeads int64
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM package_offer_publication_events),
		(SELECT count(*) FROM package_offer_publication_heads)`).Scan(&gotEvents, &gotHeads); err != nil {
		t.Fatal(err)
	}
	if gotEvents != events || gotHeads != heads {
		t.Fatalf("publication facts events/heads=%d/%d want=%d/%d", gotEvents, gotHeads, events, heads)
	}
}

func assertPackageOfferHead090(t *testing.T, pool *pgxpool.Pool, productID uuid.UUID,
	productRevision, lifecycleRevision int64, state string,
) {
	t.Helper()
	var gotProductRevision, gotLifecycleRevision int64
	var gotState string
	if err := pool.QueryRow(t.Context(), `SELECT product_revision,lifecycle_revision,state
		FROM package_offer_publication_heads WHERE product_id=$1`, productID).Scan(
		&gotProductRevision, &gotLifecycleRevision, &gotState); err != nil {
		t.Fatal(err)
	}
	if gotProductRevision != productRevision || gotLifecycleRevision != lifecycleRevision || gotState != state {
		t.Fatalf("head revision/lifecycle/state=%d/%d/%s want=%d/%d/%s",
			gotProductRevision, gotLifecycleRevision, gotState, productRevision, lifecycleRevision, state)
	}
}

func assertPackageOfferCode090(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, want)
	}
}

func applyPackageOfferMigration090(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	err := migrateVersionIsolated(t.Context(), pool, "up", 90)
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Fatalf("apply 090: %v position=%d internal_position=%d where=%q internal_query=%q",
			err, pgErr.Position, pgErr.InternalPosition, pgErr.Where, pgErr.InternalQuery)
	}
	t.Fatalf("apply 090: %v", err)
}

func packageOfferInt64Ptr090(value int64) *int64 { return &value }

func validPackageOfferSpec090() string {
	groupID := uuid.NewString()
	return `{"name":"Published offer","description":"Published offer terms","group_ids":["` + groupID + `"],` +
		`"region_id":"11111111-1111-4111-8111-111111111111",` +
		`"node_group_id":"22222222-2222-4222-8222-222222222222","backup_node_group_id":null,` +
		`"limits":{"monthly_traffic_bytes":1024,"bandwidth_bps":1024,"connections":1,` +
		`"stream_ports":1,"domains":2,"root_domains":1,"http_ports":1,"custom_cc":false,` +
		`"websocket":true,"http3":true,"l2_origin":false},` +
		`"protection":{"cc":"","ddos":""},` +
		`"prices":{"currency":"CNY","monthly_minor":100,"quarterly_minor":270,"yearly_minor":1000},` +
		`"cname":{"hostname":"","domain":"cdn.example.com","mode":"per_site"},` +
		`"purchase":{"per_user_limit":-1,"sale_expires_at":null,"require_real_name":false,` +
		`"restrict_source_ips":false,"renew_before_days":-1},` +
		`"commercial_terms":{"timezone":"Asia/Shanghai","cycle_kind":"monthly","custom_cycle_days":0,` +
		`"site_limit":10,"node_limit":2,"tcp_factor_numerator":1,"tcp_factor_denominator":1},` +
		`"sort_order":100,"enabled":true}`
}

func mustReadPackageOffer090(t *testing.T, name string) string {
	t.Helper()
	payload, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
