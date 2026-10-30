package acmeworker

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCertificateOrderAuthorityAllowsOnlyLiveRenewalParent32(t *testing.T) {
	active := "active"
	renewalDue := "renewal_due"
	revoked := "revoked"
	failed := "failed"
	tests := []struct {
		name   string
		child  string
		parent *string
		want   bool
	}{
		{name: "initial order", child: "pending", want: true},
		{name: "normal renewal", child: "validating", parent: &active, want: true},
		{name: "renewal due parent", child: "issuing", parent: &renewalDue, want: true},
		{name: "revoked parent", child: "pending", parent: &revoked},
		{name: "failed parent", child: "pending", parent: &failed},
		{name: "revoked child", child: "revoked", parent: &active},
		{name: "failed child", child: "failed", parent: &active},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := certificateOrderAuthorityAllows(test.child, test.parent); got != test.want {
				t.Fatalf("certificateOrderAuthorityAllows(%q,%v) = %t, want %t",
					test.child, test.parent, got, test.want)
			}
		})
	}
}

func TestPGOperationStoreFencesRevokedRenewalChild32(t *testing.T) {
	fixture := newPGFixtureAt(t, 47)
	if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE acme_issuance_operations
		ADD COLUMN certificate_order_id uuid, ADD COLUMN actor_user_id uuid,
		ADD COLUMN dns_provider_id uuid, ADD COLUMN account_key_ref text`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE acme_issuance_challenge_events
		ADD COLUMN provider_ref text, ADD COLUMN remote_record_ref text,
		ADD COLUMN exact_value_sha256 bytea`); err != nil {
		t.Fatal(err)
	}

	scopeID := fixture.addTenant(t)
	actorID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'ACME revocation fence actor','test-hash')`, actorID,
		"acme-fence-"+actorID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id)
		VALUES($1,$2)`, scopeID, actorID); err != nil {
		t.Fatal(err)
	}

	parentID := uuid.New()
	childID := uuid.New()
	var now, leaseUntil time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT statement_timestamp(),
		statement_timestamp()+interval '1 minute'`).Scan(&now, &leaseUntil); err != nil {
		t.Fatal(err)
	}
	now = now.UTC()
	leaseUntil = leaseUntil.UTC()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,domains,challenge_type,status,auto_renew,not_after,
		created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'http-01','active',true,$4,$5,$5)`,
		parentID, scopeID, []string{"renewal.example.test"}, now.Add(90*24*time.Hour), actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,domains,challenge_type,status,auto_renew,renewal_of_order_id,
		created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'http-01','pending',true,$4,$5,$5)`,
		childID, scopeID, []string{"renewal.example.test"}, parentID, actorID); err != nil {
		t.Fatal(err)
	}
	request := revocationChildIssueRequest32(scopeID, actorID, childID, "renewal.example.test")
	claim, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request), now, leaseUntil)
	if err != nil || claim.State != OperationClaimed {
		t.Fatalf("normal renewal claim = %+v, error = %v", claim, err)
	}
	claim.Lease = advancePGToAuthorizing(t, fixture.store, claim.Lease, now,
		[]string{"https://ca.example/authz/renewal"})
	challenge, err := fixture.store.PrepareChallenge(t.Context(), claim.Lease, ChallengeIdentity{
		TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID,
		AuthorizationURL: "https://ca.example/authz/renewal", ChallengeURL: "https://ca.example/challenge/renewal",
		ChallengeType: ChallengeHTTP01, Identifier: "renewal.example.test",
		RecordName: "renewal.example.test", Token: "revocation-token", ExactValue: "key-authorization",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE certificate_orders
		SET status='revoked',revision=revision+1,updated_at=statement_timestamp()
		WHERE scope_id=$1 AND id=$2 AND status='active'`, scopeID, parentID); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request),
		now, leaseUntil); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("revoked parent claim error = %v", err)
	}
	next := cloneOperationState(claim.Lease.State)
	next.OrderIntentPending = true
	if _, err := fixture.store.Advance(t.Context(), claim.Lease, "order_intent", next,
		now); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("revoked parent advance error = %v", err)
	}
	if _, err := fixture.store.PrepareChallenge(t.Context(), claim.Lease, ChallengeIdentity{
		TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID,
		AuthorizationURL: "https://ca.example/authz/second", ChallengeURL: "https://ca.example/challenge/second",
		ChallengeType: ChallengeHTTP01, Identifier: "renewal.example.test",
		RecordName: "renewal.example.test", Token: "second-token", ExactValue: "second-key-authorization",
	}, now); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("revoked parent challenge prepare error = %v", err)
	}
	if err := fixture.store.MarkChallenge(t.Context(), claim.Lease, challenge, "published",
		now); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("revoked parent challenge mark error = %v", err)
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.FenceTx(t.Context(), tx, claim.Lease); ErrorCodeOf(err) != CodeOperationConflict {
		_ = tx.Rollback(t.Context())
		t.Fatalf("revoked parent save fence error = %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil && err != pgx.ErrTxClosed {
		t.Fatal(err)
	}

	outstanding, err := fixture.store.OutstandingChallenges(t.Context(), claim.Lease, now)
	if err != nil || len(outstanding) != 1 || outstanding[0].AttemptID != challenge.AttemptID {
		t.Fatalf("cleanup authority = %#v, error = %v", outstanding, err)
	}
	if err := fixture.store.Release(t.Context(), claim.Lease, CodeOperationConflict, false,
		now, time.Time{}); err != nil {
		t.Fatalf("release after revocation = %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE certificate_orders
		SET status='revoked',not_after=$3,revision=revision+1,updated_at=statement_timestamp()
		WHERE scope_id=$1 AND id=$2 AND status='pending'`, scopeID, childID,
		now.Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Claim(t.Context(), request, issueRequestDigest(request),
		now, leaseUntil); ErrorCodeOf(err) != CodeOperationConflict {
		t.Fatalf("revoked child claim error = %v", err)
	}

	initialID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,domains,challenge_type,status,auto_renew,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'http-01','pending',true,$4,$4)`, initialID, scopeID,
		[]string{"initial.example.test"}, actorID); err != nil {
		t.Fatal(err)
	}
	initial := revocationChildIssueRequest32(scopeID, actorID, initialID, "initial.example.test")
	if err := fixture.pool.QueryRow(t.Context(), `SELECT statement_timestamp(),
		statement_timestamp()+interval '1 minute'`).Scan(&now, &leaseUntil); err != nil {
		t.Fatal(err)
	}
	if claim, err := fixture.store.Claim(t.Context(), initial, issueRequestDigest(initial),
		now.UTC(), leaseUntil.UTC()); err != nil || claim.State != OperationClaimed {
		t.Fatalf("initial non-renewal claim = %+v, error = %v", claim, err)
	}
}

func revocationChildIssueRequest32(
	scopeID uuid.UUID,
	actorID uuid.UUID,
	orderID uuid.UUID,
	domain string,
) IssueRequest {
	return IssueRequest{
		TenantID: scopeID, ScopeID: scopeID, OperationID: orderID.String(), CertificateOrderID: orderID,
		ActorUserID: actorID, DirectoryURL: "https://ca.example/directory",
		AccountKeyRef: "kms/account", CertificateKeyRef: "kms/certificate",
		Contacts: []string{"mailto:ops@example.test"}, AcceptTerms: true,
		Domains: []string{domain}, ChallengeType: ChallengeHTTP01,
	}
}
