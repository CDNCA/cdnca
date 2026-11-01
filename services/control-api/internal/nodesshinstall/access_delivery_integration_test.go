//go:build integration

package nodesshinstall

import (
	"bytes"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

// TestAccessDeliveryStoreAgainstPostgres (migration 608): SetAccess writes a
// pending revision; DueAccess reads it (no session: offline, not capable);
// the published bookkeeping, applied/confirmed receipts, a stale revision
// and a new revision resetting the bookkeeping move the row as the worker
// expects. Runs in the merge batch (PG integration), not in sub tasks.
func TestAccessDeliveryStoreAgainstPostgres(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ssh-access','SSH access','unused')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
			VALUES($1,$2,'edge-access','active',$3,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),'198.51.100.20')`,
			[]any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("ssh-test-key", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	access, err := NewAccessConfig([]string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Pool: pool, Cipher: cipher, Registration: fixedRegistration{}, Access: access})
	if err != nil {
		t.Fatal(err)
	}
	woken := 0
	service.OnAccessChange(func() { woken++ })
	actor := Actor{UserID: userID, ScopeID: scopeID, RequestID: "ssh-access-test", IP: "198.51.100.1"}
	set, err := service.SetAccess(ctx, actor, nodeID, AccessChange{Enabled: true, AllowCIDRs: []string{"203.0.113.0/24"}})
	if err != nil || set.State != AccessPending || set.Revision != 1 || set.Supported || woken != 1 {
		t.Fatalf("set = %+v, %v (woken %d)", set, err, woken)
	}
	due, err := service.DueAccess(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %+v, %v", due, err)
	}
	target := due[0]
	if target.Host != "198.51.100.20" || target.Online || target.Capable || target.SSHPort != 22 ||
		len(target.CIDRs) != 2 || target.CIDRs[0] != "192.0.2.10/32" || target.CIDRs[1] != "203.0.113.0/24" {
		t.Fatalf("target = %+v", target)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := service.MarkAccessPublished(ctx, nodeID, 1, contract.OperationApply, now); err != nil {
		t.Fatal(err)
	}
	report := func(revision uint64, state, code string) bool {
		t.Helper()
		changed, err := service.ReportAccess(ctx, nodeID, &agentv1.SSHAccessReceipt{NodeId: nodeID.String(), Revision: revision,
			State: state, FailureCode: code})
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if !report(1, contract.StateApplied, "") {
		t.Fatal("applied receipt ignored")
	}
	if report(9, contract.StateConfirmed, "") || report(1, contract.StateApplied, "") {
		t.Fatal("foreign revision or repeated applied receipt moved the row")
	}
	due, _ = service.DueAccess(ctx, 10)
	if len(due) != 1 || due[0].State != AccessApplied || due[0].AppliedAt == nil || due[0].PublishedOperation != contract.OperationApply {
		t.Fatalf("applied row = %+v", due)
	}
	if !report(1, contract.StateConfirmed, "") {
		t.Fatal("confirmed receipt ignored")
	}
	got, err := service.GetAccess(ctx, actor, nodeID)
	if err != nil || got.State != AccessConfirmed || got.ConfirmedAt == nil {
		t.Fatalf("confirmed = %+v, %v", got, err)
	}
	if due, _ := service.DueAccess(ctx, 10); len(due) != 0 {
		t.Fatalf("confirmed row still due: %+v", due)
	}
	// A new revision resets the delivery bookkeeping.
	if _, err := service.SetAccess(ctx, actor, nodeID, AccessChange{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	due, _ = service.DueAccess(ctx, 10)
	if len(due) != 1 || due[0].Revision != 2 || due[0].PublishedOperation != "" || due[0].PublishedAt != nil || due[0].Enabled {
		t.Fatalf("new revision = %+v", due)
	}
	if err := service.FailAccess(ctx, nodeID, 2, AccessFailureNotSupported); err != nil {
		t.Fatal(err)
	}
	if got, _ := service.GetAccess(ctx, actor, nodeID); got.State != AccessFailed || got.FailureCode != AccessFailureNotSupported {
		t.Fatalf("not supported = %+v", got)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='node.ssh_access.update'`).Scan(&audits); err != nil ||
		audits < 2 {
		t.Fatalf("audits = %d, %v", audits, err)
	}
}
