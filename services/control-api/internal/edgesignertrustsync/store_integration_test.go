//go:build integration

package edgesignertrustsync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func signerTrustPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "edge_signer_trust_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_signer_trust_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatal("unsafe schema")
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, _ := pgxpool.ParseConfig(databaseURL)
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func seedNode(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `WITH scope AS (INSERT INTO access_scopes (id,kind) VALUES ($1,'platform'))
		INSERT INTO users (id,username,display_name,password_hash) VALUES ($2,$3,'signer trust','not-used')`,
		scopeID, userID, "signer-trust-"+strings.ReplaceAll(userID.String(), "-", "")[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1, updated_at=now()
			RETURNING next_value-1 AS display_id)
		INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, nodeID, scopeID,
		"signer-trust-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], userID); err != nil {
		t.Fatal(err)
	}
	return nodeID
}

func TestStoreAcceptsOnlyForwardAndKeepsRevocations(t *testing.T) {
	pool := signerTrustPool(t)
	pins := []edgesignertrust.RootPin{{KeyID: "offline-root", Generation: 1,
		PublicKey: seededKey("root").Public().(ed25519.PublicKey)}}
	store, err := NewStore(pool, pins, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	first := signedDocument(t, 1, "release-old")
	if accepted, err := store.Accept(t.Context(), first, SourceFetch); err != nil || accepted.Revision != 1 || accepted.Replayed {
		t.Fatalf("first = %#v, %v", accepted, err)
	}
	if accepted, err := store.Accept(t.Context(), first, SourceImport); err != nil || !accepted.Replayed {
		t.Fatalf("replay = %#v, %v", accepted, err)
	}
	for name, test := range map[string]struct {
		document []byte
		reason   string
	}{
		"conflict":           {signedDocument(t, 1, "release-other"), ReasonConflict},
		"dropped revocation": {signedDocument(t, 2), ReasonDroppedRevocation},
		"untrusted":          {forgedDocument(t), ReasonUntrusted},
		"invalid":            {[]byte(`{}`), ReasonInvalid},
	} {
		var rejected *RejectedError
		if _, err := store.Accept(t.Context(), test.document, SourceFetch); !errors.As(err, &rejected) || rejected.Reason != test.reason {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
	second := signedDocument(t, 2, "release-old", "release-older")
	if accepted, err := store.Accept(t.Context(), second, SourceFetch); err != nil || accepted.Revision != 2 {
		t.Fatalf("second = %#v, %v", accepted, err)
	}
	var rejected *RejectedError
	if _, err := store.Accept(t.Context(), first, SourceFetch); !errors.As(err, &rejected) || rejected.Reason != ReasonStale {
		t.Fatalf("stale error = %v", err)
	}
	latest, found, err := store.Latest(t.Context())
	if err != nil || !found || latest.Revision != 2 || string(latest.Document) != string(second) {
		t.Fatalf("latest = %#v, %v", latest, err)
	}
	var accepted, rejectedEvents int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE event='accepted'),
		count(*) FILTER (WHERE event='rejected') FROM edge_signer_trust_events`).Scan(&accepted, &rejectedEvents); err != nil ||
		accepted != 2 || rejectedEvents != 5 {
		t.Fatalf("events accepted=%d rejected=%d err=%v", accepted, rejectedEvents, err)
	}

	nodeID := seedNode(t, pool)
	receipt := edgesignertrust.Receipt{Schema: edgesignertrust.ReceiptSchema, NodeID: nodeID.String(),
		BundleSHA256: strings.Repeat("ab", 32), Revision: 2, Result: edgesignertrust.ResultApplied,
		ReportedAt: "2026-10-17T09:00:00Z"}
	if err := store.RecordReceipt(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	unknown := receipt
	unknown.NodeID = uuid.NewString()
	if err := store.RecordReceipt(t.Context(), unknown); err != nil {
		t.Fatal(err)
	}
	enforced, err := store.EnforcedRevisions(t.Context())
	if err != nil || len(enforced) != 1 || enforced[nodeID.String()] != 2 {
		t.Fatalf("enforced = %v, %v", enforced, err)
	}
	receipt.Result, receipt.Reason, receipt.Revision = edgesignertrust.ResultRejected, edgesignertrust.ReasonPersistence, 1
	if err := store.RecordReceipt(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	if enforced, err := store.EnforcedRevisions(t.Context()); err != nil || len(enforced) != 0 {
		t.Fatalf("rejected receipt still counted as enforced: %v, %v", enforced, err)
	}
	// The node still enforces revision 1 after rejecting: its tickets may go out (acc-a DA-1).
	if trusted, err := store.NodeTrustRevisions(t.Context()); err != nil || len(trusted) != 1 || trusted[nodeID.String()] != 1 {
		t.Fatalf("node trust revisions = %v, %v", trusted, err)
	}
	receipt.Revision = 0
	if err := store.RecordReceipt(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	if trusted, err := store.NodeTrustRevisions(t.Context()); err != nil || len(trusted) != 0 {
		t.Fatalf("node without an applied document counted as trusted: %v, %v", trusted, err)
	}
}

func forgedDocument(t *testing.T) []byte {
	t.Helper()
	document, _ := edgesignertrust.Decode(signedDocument(t, 3, "release-old"))
	encoded, err := edgesignertrust.Sign(document.Document, "offline-root", 1, seededKey("attacker"))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
