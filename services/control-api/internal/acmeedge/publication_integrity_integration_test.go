//go:build integration

package acmeedge

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type directCleanupPublication struct {
	tx            pgx.Tx
	versionID     uuid.UUID
	createdAt     time.Time
	deadline      time.Time
	fixture       *integrationFixture
	priorRevision int64
}

func TestPublicationCommitRejectsIncompleteDuplicateAndMisboundDeliveryChains(t *testing.T) {
	t.Run("missing_chain", func(t *testing.T) {
		fixture, prior := publishDirectCleanupBase(t, 1)
		direct := beginDirectCleanupPublication(t, fixture, prior)
		advanceDirectCleanupState(t, direct)
		assertSQLState(t, direct.tx.Commit(t.Context()), "P0001")
	})

	t.Run("extra_retry_chain", func(t *testing.T) {
		fixture, prior := publishDirectCleanupBase(t, 1)
		direct := beginDirectCleanupPublication(t, fixture, prior)
		deploymentID := insertDirectInitialDelivery(t, direct, fixture.nodeIDs[0], fixture.nodeIDs[0])
		insertDirectRetryDelivery(t, direct, deploymentID, fixture.nodeIDs[0])
		advanceDirectCleanupState(t, direct)
		assertSQLState(t, direct.tx.Commit(t.Context()), "P0001")
	})

	t.Run("outbox_node_misbound", func(t *testing.T) {
		fixture, prior := publishDirectCleanupBase(t, 2)
		direct := beginDirectCleanupPublication(t, fixture, prior)
		insertDirectInitialDelivery(t, direct, fixture.nodeIDs[0], fixture.nodeIDs[1])
		insertDirectInitialDelivery(t, direct, fixture.nodeIDs[1], fixture.nodeIDs[1])
		advanceDirectCleanupState(t, direct)
		assertSQLStateAny(t, direct.tx.Commit(t.Context()), "P0001", "23503")
	})
}

func publishDirectCleanupBase(t *testing.T, nodeCount int) (*integrationFixture, Publication) {
	t.Helper()
	fixture := newIntegrationFixture(t, nodeCount, 1)
	publication, err := fixture.service.PublishSnapshot(
		t.Context(), fixture.request("direct-chain-base", 0, fixture.challenges),
	)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, publication
}

func beginDirectCleanupPublication(
	t *testing.T,
	fixture *integrationFixture,
	prior Publication,
) directCleanupPublication {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	publicationID, versionID := uuid.New(), uuid.New()
	createdAt := fixture.now.Add(time.Second)
	deadline := createdAt.Add(10 * time.Minute)
	requestDigest := [32]byte{1}
	snapshotDigest := [32]byte{2}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_publications(
			id,mode,tenant_scope_id,site_id,expected_revision,revision,idempotency_key,
			request_digest,request_id,token_count,node_count,max_attempts,deadline_at,created_at
		) VALUES($1,'cleanup',$2,$3,$4,$5,$6,$7,$8,1,$9,3,$10,$11)`, publicationID,
		fixture.scopeID, fixture.siteID, prior.Revision, prior.Revision+1,
		"direct-chain-"+uuid.NewString(), requestDigest[:], uuid.New(), len(fixture.nodeIDs), deadline, createdAt,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_versions(
			id,publication_id,tenant_scope_id,site_id,revision,sealed_snapshot_sha256,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, versionID, publicationID, fixture.scopeID,
		fixture.siteID, prior.Revision+1, snapshotDigest[:], createdAt,
	); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_token_facts(
			version_id,tenant_scope_id,site_id,revision,ordinal,operation_id,challenge_attempt_id,
			domain,token_sha256,value_sha256,key_id,nonce,ciphertext,aad_sha256,created_at
		)
		SELECT $1,tenant_scope_id,site_id,$2,ordinal,operation_id,challenge_attempt_id,
		       domain,token_sha256,value_sha256,key_id,nonce,ciphertext,aad_sha256,$3
		FROM acme_http01_overlay_token_facts WHERE version_id=$4`, versionID,
		prior.Revision+1, createdAt, prior.VersionID,
	); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("clone cleanup token: rows=%d error=%v", tag.RowsAffected(), err)
	}
	if tag, err := tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_targets(
			version_id,tenant_scope_id,site_id,revision,ordinal,node_id,created_at
		)
		SELECT $1,tenant_scope_id,site_id,$2,ordinal,node_id,$3
		FROM acme_http01_overlay_targets WHERE version_id=$4`, versionID,
		prior.Revision+1, createdAt, prior.VersionID,
	); err != nil || tag.RowsAffected() != int64(len(fixture.nodeIDs)) {
		t.Fatalf("clone cleanup targets: rows=%d error=%v", tag.RowsAffected(), err)
	}
	return directCleanupPublication{
		tx: tx, versionID: versionID, createdAt: createdAt, deadline: deadline,
		fixture: fixture, priorRevision: prior.Revision,
	}
}

func insertDirectInitialDelivery(
	t *testing.T,
	direct directCleanupPublication,
	deploymentNode uuid.UUID,
	outboxNode uuid.UUID,
) uuid.UUID {
	t.Helper()
	deploymentID, outboxID := uuid.New(), uuid.New()
	insertDirectDeployment(t, direct, deploymentID, 1, deploymentNode, uuid.Nil)
	if _, err := direct.tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_deployment_events(
			deployment_id,deployment_attempt,sequence,state,occurred_at
		) VALUES($1,1,1,'queued',$2)`, deploymentID, direct.createdAt); err != nil {
		t.Fatal(err)
	}
	insertDirectOutbox(t, direct, outboxID, deploymentID, 1, outboxNode)
	return deploymentID
}

func insertDirectRetryDelivery(
	t *testing.T,
	direct directCleanupPublication,
	deploymentID uuid.UUID,
	nodeID uuid.UUID,
) {
	t.Helper()
	insertDirectDeployment(t, direct, deploymentID, 2, nodeID, uuid.New())
	if _, err := direct.tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_deployment_events(
			deployment_id,deployment_attempt,sequence,state,occurred_at
		) VALUES($1,2,1,'retry_queued',$2)`, deploymentID, direct.createdAt); err != nil {
		t.Fatal(err)
	}
	insertDirectOutbox(t, direct, uuid.New(), deploymentID, 2, nodeID)
}

func insertDirectDeployment(
	t *testing.T,
	direct directCleanupPublication,
	deploymentID uuid.UUID,
	attempt int,
	nodeID uuid.UUID,
	retryRequestID uuid.UUID,
) {
	t.Helper()
	var retry any
	if retryRequestID != uuid.Nil {
		retry = retryRequestID
	}
	if _, err := direct.tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_deployments(
			id,attempt,version_id,tenant_scope_id,site_id,revision,node_id,retry_request_id,
			deadline_at,max_attempts,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,3,$10)`, deploymentID, attempt,
		direct.versionID, direct.fixture.scopeID, direct.fixture.siteID, direct.priorRevision+1,
		nodeID, retry, direct.deadline, direct.createdAt,
	); err != nil {
		t.Fatal(err)
	}
}

func insertDirectOutbox(
	t *testing.T,
	direct directCleanupPublication,
	outboxID uuid.UUID,
	deploymentID uuid.UUID,
	attempt int,
	nodeID uuid.UUID,
) {
	t.Helper()
	payloadDigest := [32]byte{3}
	if _, err := direct.tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_outbox(
			id,deployment_id,deployment_attempt,version_id,node_id,subject,payload_sha256,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, outboxID, deploymentID, attempt,
		direct.versionID, nodeID, "edge.acme.http01."+nodeID.String(), payloadDigest[:], direct.createdAt,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := direct.tx.Exec(t.Context(), `
		INSERT INTO acme_http01_overlay_outbox_states(
			outbox_id,status,publish_attempts,available_at,updated_at
		) VALUES($1,'pending',0,$2,$2)`, outboxID, direct.createdAt); err != nil {
		t.Fatal(err)
	}
}

func advanceDirectCleanupState(t *testing.T, direct directCleanupPublication) {
	t.Helper()
	if tag, err := direct.tx.Exec(t.Context(), `
		UPDATE acme_http01_overlay_states SET current_revision=$3,updated_at=$4
		WHERE tenant_scope_id=$1 AND site_id=$2 AND current_revision=$5`, direct.fixture.scopeID,
		direct.fixture.siteID, direct.priorRevision+1, direct.createdAt, direct.priorRevision,
	); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("advance direct cleanup: rows=%d error=%v", tag.RowsAffected(), err)
	}
}

func assertSQLStateAny(t *testing.T, err error, codes ...string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("SQL error = %v, want one of %v", err, codes)
	}
	for _, code := range codes {
		if postgresError.Code == code {
			return
		}
	}
	t.Fatalf("SQL state = %s (%s), want one of %v", postgresError.Code, fmt.Sprint(err), codes)
}
