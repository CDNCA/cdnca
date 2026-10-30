//go:build integration

package installationban

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	itInstallation = "0190a000-0000-7000-8000-000000000001"
	itCustomer     = "0190a000-0000-7000-8000-000000000002"
	itBan          = "0190a000-0000-7000-8000-000000000003"
	itLicense      = "0190a000-0000-7000-8000-000000000004"
)

type itSigner struct{ private ed25519.PrivateKey }

func (itSigner) KeyID() string { return "lease-it" }
func (signer itSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	return databasetest.MigratedPool(t, nil)
}

func TestStoreAcceptsLocksAndKeepsLKG(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	pool := itPool(t)
	seed := sha256.Sum256([]byte("it"))
	signer := itSigner{private: ed25519.NewKeyFromSeed(seed[:])}
	forged := itSigner{private: ed25519.NewKeyFromSeed(make([]byte, 32))}
	keys := func(id string) (ed25519.PublicKey, bool) {
		if id != signer.KeyID() {
			return nil, false
		}
		return signer.private.Public().(ed25519.PublicKey), true
	}
	store, err := NewStore(pool, uuid.MustParse(itInstallation), keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	until := now.Add(time.Hour).Unix()
	notice := func(revision uint64, state string, signer contract.Signer) []byte {
		body := contract.BanNotice{Schema: contract.NoticeSchema, InstallationID: itInstallation, CustomerID: itCustomer,
			BanID: itBan, Revision: revision, State: state, ReasonCode: "abuse", ReasonText: "滥用",
			StartsAt: now.Unix(), Until: &until, IssuedAt: now.Unix()}
		encoded, err := contract.SignNotice(t.Context(), body, signer)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	ticket := func(revision uint64) []byte {
		encoded, err := contract.SignTicket(t.Context(), contract.ServiceTicket{Schema: contract.TicketSchema,
			InstallationID: itInstallation, CustomerID: itCustomer, LicenseID: itLicense, Revision: revision,
			IssuedAt: now.Unix(), NotAfter: now.Add(contract.DefaultNodeOfflineTolerance).Unix()}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	fetcher := &fakeFetcher{documents: Documents{Ticket: ticket(1)}}
	runtime := &Runtime{Fetcher: fetcher, Store: store, Now: func() time.Time { return now }}
	if err := runtime.SyncOnce(t.Context()); err != nil || installationlock.Locked() {
		t.Fatalf("active installation: err %v locked %v", err, installationlock.Locked())
	}
	// banned: the lock carries the reason and until
	fetcher.documents = Documents{Notice: notice(2, contract.StateBanned, signer)}
	if err := runtime.SyncOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	lock := installationlock.Current()
	if !lock.Locked || lock.ReasonText != "滥用" || lock.Until == nil || lock.Until.Unix() != until {
		t.Fatalf("banned lock = %+v", lock)
	}
	// a forged lifted notice and an old ticket are refused; the ban stays (LKG)
	fetcher.documents = Documents{Notice: notice(3, contract.StateLifted, forged), Ticket: ticket(1)}
	err = runtime.SyncOnce(t.Context())
	if !errors.Is(err, contract.ErrUntrusted) || !installationlock.Locked() {
		t.Fatalf("forged lift: err %v locked %v", err, installationlock.Locked())
	}
	fetcher.documents = Documents{Notice: notice(1, contract.StateLifted, signer)}
	if err := runtime.SyncOnce(t.Context()); !errors.Is(err, contract.ErrRevisionRollback) || !installationlock.Locked() {
		t.Fatalf("rollback lift: err %v", err)
	}
	// restart: a fresh runtime restores the lock from the database
	installationlock.Set(installationlock.Lock{})
	if err := (&Runtime{Fetcher: fetcher, Store: store, Now: func() time.Time { return now }}).Restore(t.Context()); err != nil ||
		!installationlock.Locked() {
		t.Fatalf("restore: err %v locked %v", err, installationlock.Locked())
	}
	// lifted with a higher revision, then a new ticket: unlocked
	fetcher.documents = Documents{Notice: notice(3, contract.StateLifted, signer), Ticket: ticket(4)}
	if err := runtime.SyncOnce(t.Context()); err != nil || installationlock.Locked() {
		t.Fatalf("lifted: err %v lock %+v", err, installationlock.Current())
	}
	var noticeRevision, ticketRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT notice_revision, ticket_revision FROM control_installation_ban_state`).
		Scan(&noticeRevision, &ticketRevision); err != nil || noticeRevision != 3 || ticketRevision != 4 {
		t.Fatalf("stored revisions %d %d (%v)", noticeRevision, ticketRevision, err)
	}
}

func TestStoreRecordsNodeReceipts(t *testing.T) {
	pool := itPool(t)
	store, err := NewStore(pool, uuid.MustParse(itInstallation), func(string) (ed25519.PublicKey, bool) { return nil, false })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `WITH scope AS (INSERT INTO access_scopes (id,kind) VALUES ($1,'platform'))
		INSERT INTO users (id,username,display_name,password_hash) VALUES ($2,$3,'ban','not-used')`,
		scopeID, userID, "ban-"+strings.ReplaceAll(userID.String(), "-", "")[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1, updated_at=now()
			RETURNING next_value-1 AS display_id)
		INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, nodeID, scopeID,
		"ban-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], userID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := func(revision uint64, applied bool, status, reason string) {
		t.Helper()
		if err := store.RecordReceipt(t.Context(), &agentv1.InstallationBanReceipt{NodeId: nodeID.String(),
			Revision: revision, Applied: applied, Status: status, Reason: reason}, now); err != nil {
			t.Fatal(err)
		}
	}
	delivery := func() NodeDelivery {
		t.Helper()
		deliveries, err := store.NodeDeliveries(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return deliveries[nodeID.String()]
	}
	record(5, true, "banned", "")
	record(3, true, "serving", "") // an older receipt arriving late does not move the node back
	if got := delivery(); got.Revision != 5 || got.AppliedRevision != 5 || got.Status != "banned" || got.FailureClass != FailureNone {
		t.Fatalf("applied 5: %+v", got)
	}
	// Revision 6 fails to persist twice, then applies; the
	// stored row keeps delivered 6 / applied 5 with the backoff until then.
	record(6, false, "banned", "persistence_failed")
	record(6, false, "banned", "enforce_failed")
	got := delivery()
	if got.Revision != 6 || got.AppliedRevision != 5 || got.FailureClass != FailureRetryable || got.FailedAttempts != 2 ||
		got.Reason != "enforce_failed" || got.NextRetryAt == nil || !got.NextRetryAt.Equal(now.Add(RetryBackoff(2))) {
		t.Fatalf("retryable 6: %+v", got)
	}
	if !deliveryDue(got, 6, now.Add(RetryBackoff(2))) || deliveryDue(got, 6, now) {
		t.Fatalf("retry schedule of %+v", got)
	}
	tickets, err := NodeTicketReader{Pool: pool}.NodeTickets(t.Context(), scopeID, []uuid.UUID{nodeID}, now)
	if err != nil || len(tickets) != 1 || tickets[0].Delivery == nil || tickets[0].Delivery.Reason != "enforce_failed" ||
		tickets[0].Delivery.NextRetryAt == nil {
		t.Fatalf("node page view %+v (%v)", tickets, err)
	}
	record(6, true, "serving", "")
	if got := delivery(); got.Revision != 6 || got.AppliedRevision != 6 || got.FailureClass != FailureNone ||
		got.FailedAttempts != 0 || got.NextRetryAt != nil {
		t.Fatalf("applied 6: %+v", got)
	}
	record(6, false, "serving", "persistence_failed") // a late refusal of an applied revision changes nothing
	if got := delivery(); got.AppliedRevision != 6 || got.FailureClass != FailureNone {
		t.Fatalf("late refusal: %+v", got)
	}
	// a permanent refusal is kept (no retry time) and the migration 529
	// constraint holds for every state written above
	record(7, false, "serving", "revision_conflict")
	if got := delivery(); got.Revision != 7 || got.AppliedRevision != 6 || got.FailureClass != FailurePermanent ||
		got.NextRetryAt != nil || deliveryDue(got, 7, now.Add(time.Hour)) || !deliveryDue(got, 8, now) {
		t.Fatalf("permanent 7: %+v", got)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE installation_ban_node_state SET failure_class='retryable' WHERE node_id=$1`,
		nodeID); err == nil {
		t.Fatal("a retryable row without a retry time passed the 529 constraint")
	}
	var status string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM installation_ban_node_state WHERE node_id=$1`, nodeID).
		Scan(&status); err != nil || status != "serving" {
		t.Fatalf("status %q (%v)", status, err)
	}
	if err := store.RecordReceipt(t.Context(), &agentv1.InstallationBanReceipt{NodeId: nodeID.String(), Revision: 9,
		Status: "paused"}, now); err == nil {
		t.Fatal("an unknown status was recorded")
	}
	nodes, err := ActiveNodes(pool)(t.Context())
	if err != nil || len(nodes) == 0 {
		t.Fatalf("active nodes %v (%v)", nodes, err)
	}
	for _, node := range nodes {
		if node.ID == nodeID.String() && node.Capable {
			t.Fatal("a node that never declared the capability is capable")
		}
	}
}
