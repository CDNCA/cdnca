package site

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
)

func TestOwnershipPolicyLevels(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()

	// Default (no settings row) is wildcard_only.
	if _, err := f.createSite(f.a, f.a, "*.policy-a.test"); !errors.Is(err, domaintrust.ErrOwnershipRequired) {
		t.Fatalf("wildcard without verification = %v", err)
	}
	if _, err := f.createSite(f.a, f.a, "www.policy-a.test"); err != nil {
		t.Fatalf("plain domain under wildcard_only: %v", err)
	}
	// Platform administrators skip the verification step.
	if _, err := f.createSite(f.admin, f.b, "*.policy-admin.test"); err != nil {
		t.Fatalf("admin wildcard: %v", err)
	}

	f.setPolicy("all")
	var detail *domaintrust.DomainError
	if _, err := f.createSite(f.a, f.a, "api.policy-all.test"); !errors.As(err, &detail) ||
		!errors.Is(err, domaintrust.ErrOwnershipRequired) || detail.Apex != "policy-all.test" {
		t.Fatalf("plain domain under all = %v", err)
	}
	f.verify(f.a, "policy-all.test", domainownership.MethodDNSTXT)
	if _, err := f.createSite(f.a, f.a, "api.policy-all.test", "*.policy-all.test"); err != nil {
		t.Fatalf("verified apex under all: %v", err)
	}

	f.setPolicy("off")
	if _, err := f.createSite(f.a, f.a, "*.policy-off.test"); err != nil {
		t.Fatalf("wildcard under off: %v", err)
	}
	if _, err := f.service.Start(ctx, f.a.ownership(), "x.policy-off.test", domainownership.MethodDNSTXT, "start-off"); !errors.Is(err, domainownership.ErrPolicyOff) {
		t.Fatalf("start under off = %v", err)
	}
}

func TestTXTVerificationAndCrossAccountRejection(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	started, err := f.service.Start(ctx, f.a.ownership(), "www.Victim.example.com", domainownership.MethodDNSTXT, "start-1")
	if err != nil {
		t.Fatal(err)
	}
	if started.Apex != "example.com" || started.TXTName != "_cdnca-verify.example.com" || len(started.Token) != 48 ||
		started.Status != domainownership.StatusPending {
		t.Fatalf("challenge = %+v", started)
	}
	// Wrong record: stays pending with a failure code.
	f.verifier.setTXT(started.TXTName, "wrong")
	checked, err := f.service.Check(ctx, f.a.ownership(), "example.com", "check-1")
	if err != nil || checked.Status != domainownership.StatusPending || checked.LastFailureCode != "txt_not_found" {
		t.Fatalf("failed check = %+v, %v", checked, err)
	}
	f.verifier.setTXT(started.TXTName, started.Token)
	checked, err = f.service.Check(ctx, f.a.ownership(), "example.com", "check-2")
	if err != nil || checked.Status != domainownership.StatusVerified || checked.VerifiedAt == nil {
		t.Fatalf("verified check = %+v, %v", checked, err)
	}
	// B cannot add any domain under A's verified apex, nor verify it.
	for _, domain := range []string{"shop.example.com", "*.example.com", "example.com"} {
		if _, err := f.createSite(f.b, f.b, domain); !errors.Is(err, domaintrust.ErrDomainVerifiedByOther) {
			t.Fatalf("B add %s = %v", domain, err)
		}
	}
	bStarted, err := f.service.Start(ctx, f.b.ownership(), "example.com", domainownership.MethodDNSTXT, "start-b")
	if err != nil {
		t.Fatal(err)
	}
	f.verifier.setTXT(bStarted.TXTName, bStarted.Token) // A's record is gone, A's proof still stands.
	if _, err := f.service.Check(ctx, f.b.ownership(), "example.com", "check-b"); !errors.Is(err, domainownership.ErrVerifiedByOther) {
		t.Fatalf("B check while A is verified = %v", err)
	}
	// Proofs never lapse: a failed check of A's own proof keeps it verified.
	again, err := f.service.Check(ctx, f.a.ownership(), "example.com", "check-a-again")
	if err != nil || again.Status != domainownership.StatusVerified || again.LastFailureCode != "txt_not_found" {
		t.Fatalf("A recheck without record = %+v, %v", again, err)
	}
	// Only an administrator's revoke frees the apex.
	var aID uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM domain_ownerships WHERE scope_id=$1`, f.a.scopeID).Scan(&aID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.AdminRevokeOwnership(ctx, f.admin.ownership(), aID, "admin-revoke-a"); err != nil {
		t.Fatal(err)
	}
	if verifiedB, err := f.service.Check(ctx, f.b.ownership(), "example.com", "check-b-2"); err != nil || verifiedB.Status != domainownership.StatusVerified {
		t.Fatalf("B after revoke = %+v, %v", verifiedB, err)
	}
	// Admins also cannot add a domain someone else verified.
	if _, err := f.createSite(f.admin, f.a, "x.example.com"); !errors.Is(err, domaintrust.ErrDomainVerifiedByOther) {
		t.Fatalf("admin add for A under B's apex = %v", err)
	}
}

func TestDNSTXTSupersedesHTTPFileProof(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	f.verify(f.a, "supersede.test", domainownership.MethodHTTPFile)
	f.verify(f.b, "supersede.test", domainownership.MethodDNSTXT)
	var status, code string
	if err := f.pool.QueryRow(ctx, `SELECT status,last_failure_code FROM domain_ownerships WHERE scope_id=$1`, f.a.scopeID).Scan(&status, &code); err != nil ||
		status != "expired" || code != "superseded_by_dns_txt" {
		t.Fatalf("superseded HTTP proof = %s/%s (%v)", status, code, err)
	}
}

func TestClaimDisablesConflictingSiteAndBlocksReenable(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	squatted, err := f.createSite(f.b, f.b, "www.claim.test", "other.test")
	if err != nil {
		t.Fatal(err)
	}
	f.verify(f.a, "claim.test", domainownership.MethodDNSTXT)
	conflicts, err := f.service.Conflicts(ctx, f.a.ownership(), "claim.test")
	if err != nil || len(conflicts) != 1 || conflicts[0].Domain != "www.claim.test" || !conflicts[0].Claimable {
		t.Fatalf("conflicts = %+v, %v", conflicts, err)
	}
	if _, err := f.createSite(f.a, f.a, "www.claim.test"); !errors.Is(err, ErrDomainConflict) {
		t.Fatalf("add before claim = %v", err)
	}
	request := domainownership.ClaimRequest{Apex: "claim.test", Domains: []string{"www.claim.test"},
		IdempotencyKey: "claim-1", RequestID: "claim-1"}
	claimed, err := f.service.Claim(ctx, f.a.ownership(), request)
	if err != nil || claimed.SuspendedSites != 1 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	replay, err := f.service.Claim(ctx, f.a.ownership(), request)
	if err != nil || !replay.Replayed || replay.SuspendedSites != 1 {
		t.Fatalf("claim replay = %+v, %v", replay, err)
	}
	if f.siteEnabled(squatted.Site.ID) {
		t.Fatal("conflicting site is still enabled")
	}
	if _, err := f.createSite(f.a, f.a, "www.claim.test"); err != nil {
		t.Fatalf("add after claim: %v", err)
	}
	// B cannot re-enable through batch or update while the domain is claimed.
	current, err := f.sites.Get(ctx, f.b.siteActor(), squatted.Site.ID)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := f.sites.BatchAction(ctx, f.b.siteActor(), BatchActionRequest{Action: BatchActionEnable,
		Items: []BatchActionItem{{ID: current.ID, ExpectedRevision: current.Revision}}, IdempotencyKey: "enable-1", RequestID: "enable-1"})
	if err != nil || batch.Items[0].Error == nil || batch.Items[0].Error.Code != "site_domain_claim_suspended" {
		t.Fatalf("batch enable = %+v, %v", batch, err)
	}
	fields := SiteFields{Domains: current.Domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
		Enabled: true, Status: StatusActive}
	if _, err := f.sites.Update(ctx, f.b.siteActor(), UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision,
		Fields: fields, IdempotencyKey: "update-1", RequestID: "update-1"}); !errors.Is(err, domaintrust.ErrClaimSuspended) {
		t.Fatalf("update enable = %v", err)
	}
	// Dropping the claimed domain releases the suspension in the same write.
	fields.Domains = []string{"other.test"}
	if _, err := f.sites.Update(ctx, f.b.siteActor(), UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision,
		Fields: fields, IdempotencyKey: "update-2", RequestID: "update-2"}); err != nil {
		t.Fatalf("drop claimed domain and enable: %v", err)
	}
	if !f.siteEnabled(squatted.Site.ID) {
		t.Fatal("site was not re-enabled")
	}
	var audits int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('domain_ownership.claim','site.domain_claim.suspend')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("claim audit events = %d (%v)", audits, err)
	}
}

func TestClaimRequiresDNSTXT(t *testing.T) {
	f := newTrustFixture(t)
	if _, err := f.createSite(f.b, f.b, "www.http-claim.test"); err != nil {
		t.Fatal(err)
	}
	f.verify(f.a, "http-claim.test", domainownership.MethodHTTPFile)
	_, err := f.service.Claim(context.Background(), f.a.ownership(), domainownership.ClaimRequest{
		Apex: "http-claim.test", Domains: []string{"www.http-claim.test"}, IdempotencyKey: "c", RequestID: "c"})
	if !errors.Is(err, domainownership.ErrClaimRequiresTXT) {
		t.Fatalf("http-file claim = %v", err)
	}
}

func TestAdminReleaseRefusedWhileClaimantHoldsDomain(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	squatted, err := f.createSite(f.b, f.b, "www.appeal.test")
	if err != nil {
		t.Fatal(err)
	}
	f.verify(f.a, "appeal.test", domainownership.MethodDNSTXT)
	if _, err := f.service.Claim(ctx, f.a.ownership(), domainownership.ClaimRequest{Apex: "appeal.test",
		Domains: []string{"www.appeal.test"}, IdempotencyKey: "c", RequestID: "c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.createSite(f.a, f.a, "www.appeal.test"); err != nil {
		t.Fatal(err)
	}
	suspensions, err := f.service.AdminListSuspensions(ctx, f.admin.ownership(), false, 0)
	if err != nil || len(suspensions) != 1 || suspensions[0].SiteID != squatted.Site.ID {
		t.Fatalf("suspensions = %+v, %v", suspensions, err)
	}
	if _, err := f.service.AdminReleaseSuspension(ctx, f.admin.ownership(), suspensions[0].ID, "release-1"); !errors.Is(err, domainownership.ErrStillClaimed) {
		t.Fatalf("release while held = %v", err)
	}
	if _, err := f.service.AdminListSuspensions(ctx, f.a.ownership(), false, 0); !errors.Is(err, domainownership.ErrPermissionDenied) {
		t.Fatalf("tenant admin list = %v", err)
	}
}

// Two accounts adding the same new domain at once: exactly one wins.
func TestConcurrentAddSameDomain(t *testing.T) {
	f := newTrustFixture(t)
	const workers = 8
	errs := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		owner := f.a
		if index%2 == 1 {
			owner = f.b
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, errs[index] = f.createSite(owner, owner, "race.test")
		}()
	}
	wait.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrDomainConflict):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins = %d, errors = %v", wins, errs)
	}
}
