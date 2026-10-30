//go:build integration

package edgepublish_test

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

type claimVerifier struct{}

func (claimVerifier) VerifyTXT(context.Context, string, string) (bool, string, error) {
	return true, "", nil
}
func (claimVerifier) VerifyHTTP(context.Context, string, string) (bool, string, error) {
	return true, "", nil
}

// G6 #12 + g11: a verified owner's claim disables the other account's site
// and, in the same transaction, queues a domain_ownership system
// republication that is due at once; its next artifact no longer carries the
// site.
func TestDomainClaimRepublishesWithoutTheClaimedSite(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	ctx := t.Context()
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-claim", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	site := []byte(scope.SiteID.String())
	if !bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("baseline publication lacks the site")
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := scope.Pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// The victim's site serves system-republish.example.com.
	exec(`INSERT INTO site_domain_facts(scope_id,site_id,site_revision,action,canonical_domain,actor_scope_id,
		actor_user_id,request_id,occurred_at) SELECT scope_id,id,revision,'activate',domain,scope_id,$2,'claim-seed',now()
		FROM sites WHERE id=$1`, scope.SiteID, scope.UserID)
	// The claimant tenant verified example.com by DNS TXT.
	tenantID, claimantScope, claimant, role := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'claimant')`, tenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, claimantScope, tenantID)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'claimant-syspub','claimant','x')`, claimant)
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, claimantScope, claimant)
	exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'claimant-owner','claim test',true)`, role, claimantScope)
	exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'sites.manage'),($1,'sites.read')`, role)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, claimantScope, claimant, role)
	exec(`INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,last_checked_at,
		created_by_user_id,created_at,updated_at) VALUES($1,$2,'example.com','dns_txt',repeat('d',48),'verified',now(),now(),$3,now(),now())`,
		uuid.New(), claimantScope, claimant)

	service, err := domainownership.NewService(scope.Pool, audit.New(scope.Pool), claimVerifier{}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Claim(ctx, domainownership.Actor{UserID: claimant, ScopeID: claimantScope, ScopeKind: "tenant"},
		domainownership.ClaimRequest{Apex: "example.com", Domains: []string{"system-republish.example.com"},
			IdempotencyKey: "syspub-claim-1", RequestID: "syspub-claim-1"})
	if err != nil || result.SuspendedSites != 1 {
		t.Fatalf("claim = %+v, %v", result, err)
	}
	// Queued with the claim and due at once: not the 5 s system debounce.
	if pending := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND state='pending' AND 'domain_ownership'=ANY(triggers) AND due_at<=updated_at+interval '10 milliseconds'`); pending != 1 {
		t.Fatalf("immediate domain_ownership republications = %d", pending)
	}
	time.Sleep(5 * time.Millisecond)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Equal(attempt.Triggers, []string{"domain_ownership"}) {
		t.Fatalf("claim republication attempt = %+v", attempt)
	}
	if bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("the claimed site is still in the published artifact")
	}
}
