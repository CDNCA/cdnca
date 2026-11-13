//go:build integration

package identity_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// TestTenantMemberDeleteHandsResourcesOver: deleting a member with
// transfer_to moves its sites, certificates and security policies to the
// receiving member in one audited transaction; the certificate owner stays
// immutable outside that handover; a package-bound site refuses it.
func TestTenantMemberDeleteHandsResourcesOver(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	service := fixture.service
	create := func(username string) identity.TenantMember {
		t.Helper()
		member, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
			Username: username, DisplayName: username, Password: "LongEnough-Pass1", RequestID: "create-" + username})
		if err != nil {
			t.Fatal(err)
		}
		return member
	}
	bob, carol := create("ho-bob"), create("ho-carol")

	siteID := insertSecondaryVerificationSite(t, fixture.pool, scopeID, bob.UserID, "handover.example.test", true, "", uuid.Nil)
	certificateID, policyID := uuid.New(), uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO certificate_assets(tenant_scope_id,id,name,source,revision,created_by_scope_id,
		created_by_user_id,updated_by_scope_id,updated_by_user_id,created_at,updated_at,owner_user_id)
		VALUES($1,$2,'bob cert','uploaded',1,$1,$3,$1,$3,now(),now(),$3)`, scopeID, certificateID, bob.UserID); err != nil {
		t.Fatal(err)
	}
	rules, _ := json.Marshal([]map[string]any{{"action": "block", "match": map[string]any{"field": "ip", "operator": "equals", "value": "192.0.2.9"}}})
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,
		revision,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'acl','bob acl',true,'allow',$5,1,$4,$4,now(),now())`,
		policyID, scopeID, *owner.TenantID, bob.UserID, rules); err != nil {
		t.Fatal(err)
	}

	// The certificate owner cannot change outside the handover (276).
	if _, err := fixture.pool.Exec(ctx, `UPDATE certificate_assets SET owner_user_id=$2,revision=revision+1,updated_at=now() WHERE id=$1`,
		certificateID, carol.UserID); err == nil {
		t.Fatal("certificate owner changed without a handover")
	}

	// Without transfer_to the deletion reports what would move.
	var owned *identity.TenantMemberOwnsResourcesError
	if err := service.DeleteTenantMember(ctx, owner, bob.UserID, nil, "d-no-target"); !errors.As(err, &owned) || owned.Resources.Transferable != 3 {
		t.Fatalf("delete without target: %v %+v", err, owned)
	}
	// The receiving member must be another active member.
	stranger := uuid.New()
	for name, target := range map[string]uuid.UUID{"self": bob.UserID, "stranger": stranger} {
		if err := service.DeleteTenantMember(ctx, owner, bob.UserID, &target, "d-"+name); !errors.Is(err, identity.ErrTenantMemberTransferTarget) {
			t.Fatalf("%s target: %v", name, err)
		}
	}
	if _, err := service.SetTenantMemberStatus(ctx, owner, carol.UserID, false, nil, "suspend-carol"); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteTenantMember(ctx, owner, bob.UserID, &carol.UserID, "d-suspended"); !errors.Is(err, identity.ErrTenantMemberTransferTarget) {
		t.Fatalf("suspended target: %v", err)
	}
	if _, err := service.SetTenantMemberStatus(ctx, owner, carol.UserID, true, nil, "resume-carol"); err != nil {
		t.Fatal(err)
	}

	if err := service.DeleteTenantMember(ctx, owner, bob.UserID, &carol.UserID, "delete-bob"); err != nil {
		t.Fatalf("delete with handover: %v", err)
	}
	for table, id := range map[string]uuid.UUID{"sites": siteID, "certificate_assets": certificateID, "security_policies": policyID} {
		var ownerID uuid.UUID
		if err := fixture.pool.QueryRow(ctx, `SELECT owner_user_id FROM `+table+` WHERE id=$1`, id).Scan(&ownerID); err != nil || ownerID != carol.UserID {
			t.Fatalf("%s owner=%s %v", table, ownerID, err)
		}
	}
	var siteRevision, certificateRevision int64
	var siteUpdatedBy, certificateUpdatedBy uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT s.revision,s.updated_by_user_id,c.revision,c.updated_by_user_id FROM sites s, certificate_assets c
		WHERE s.id=$1 AND c.id=$2`, siteID, certificateID).Scan(&siteRevision, &siteUpdatedBy, &certificateRevision, &certificateUpdatedBy); err != nil {
		t.Fatal(err)
	}
	if siteRevision != 2 || certificateRevision != 2 || siteUpdatedBy != owner.UserID || certificateUpdatedBy != owner.UserID {
		t.Fatalf("revisions site=%d/%s certificate=%d/%s", siteRevision, siteUpdatedBy, certificateRevision, certificateUpdatedBy)
	}
	// The handover setting does not outlive the transaction, and the removed
	// creator no longer blocks certificate updates (085 checks the creator
	// on insert only).
	if _, err := fixture.pool.Exec(ctx, `UPDATE certificate_assets SET revision=revision+1,updated_by_scope_id=$2,updated_by_user_id=$3,updated_at=now()
		WHERE id=$1`, certificateID, scopeID, carol.UserID); err != nil {
		t.Fatalf("update certificate created by removed member: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE certificate_assets SET owner_user_id=$2,revision=revision+1,updated_at=now() WHERE id=$1`,
		certificateID, owner.UserID); err == nil {
		t.Fatal("certificate owner changed after the handover")
	}

	var payload []byte
	if err := fixture.pool.QueryRow(ctx, `SELECT payload FROM audit_events WHERE action='identity.tenant_member.resources.transfer'
		AND resource_id=$1`, bob.UserID.String()).Scan(&payload); err != nil {
		t.Fatalf("transfer audit: %v", err)
	}
	var decoded struct {
		TransferredTo string           `json:"transferred_to"`
		Total         int64            `json:"total"`
		Resources     map[string]int64 `json:"resources"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded.TransferredTo != carol.UserID.String() || decoded.Total != 3 ||
		decoded.Resources["sites"] != 1 || decoded.Resources["certificates"] != 1 || decoded.Resources["security_policies"] != 1 {
		t.Fatalf("transfer payload %s %v", payload, err)
	}
	var deleteTarget string
	if err := fixture.pool.QueryRow(ctx, `SELECT payload->>'transferred_to' FROM audit_events WHERE action='identity.tenant_member.delete'
		AND resource_id=$1`, bob.UserID.String()).Scan(&deleteTarget); err != nil || deleteTarget != carol.UserID.String() {
		t.Fatalf("delete audit transferred_to=%q %v", deleteTarget, err)
	}

	// A site bound to a package keeps its owner: the deletion is refused and
	// nothing moves.
	dave := create("ho-dave")
	packageSite := insertSecondaryVerificationSite(t, fixture.pool, scopeID, carol.UserID, "pkg.example.test", true, "", uuid.Nil)
	if _, err := fixture.pool.Exec(ctx, `ALTER TABLE sites DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.pool.Exec(ctx, `UPDATE sites SET package_id=$2,package_name='p' WHERE id=$1`, packageSite, uuid.New())
	if _, enableErr := fixture.pool.Exec(ctx, `ALTER TABLE sites ENABLE TRIGGER USER`); enableErr != nil {
		t.Fatal(enableErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteTenantMember(ctx, owner, carol.UserID, &dave.UserID, "delete-carol"); !errors.As(err, &owned) ||
		owned.Resources.PackageSites != 1 {
		t.Fatalf("package site handover: %v %+v", err, owned)
	}
	var stillCarol bool
	if err := fixture.pool.QueryRow(ctx, `SELECT owner_user_id=$2 FROM sites WHERE id=$1`, siteID, carol.UserID).Scan(&stillCarol); err != nil || !stillCarol {
		t.Fatalf("refused handover moved resources: %v", err)
	}
}

// TestTenantMemberSuspendHandsResourcesOver: suspension can hand the
// resources over too.
func TestTenantMemberSuspendHandsResourcesOver(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	service := fixture.service
	bob, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "sh-bob", DisplayName: "Bob", Password: "LongEnough-Pass1", RequestID: "create-sh-bob"})
	if err != nil {
		t.Fatal(err)
	}
	siteID := insertSecondaryVerificationSite(t, fixture.pool, scopeID, bob.UserID, "suspend-handover.example.test", true, "", uuid.Nil)
	if _, err := service.SetTenantMemberStatus(ctx, owner, bob.UserID, true, &owner.UserID, "bad"); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("resume with transfer: %v", err)
	}
	suspended, err := service.SetTenantMemberStatus(ctx, owner, bob.UserID, false, &owner.UserID, "suspend-bob")
	if err != nil || suspended.Status != identity.MembershipStatusSuspended {
		t.Fatalf("suspend with handover: %+v %v", suspended, err)
	}
	var ownerID uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT owner_user_id FROM sites WHERE id=$1`, siteID).Scan(&ownerID); err != nil || ownerID != owner.UserID {
		t.Fatalf("site owner=%s %v", ownerID, err)
	}
}

// TestTenantMemberPasswordChangeRequired: the flag limits the member's
// sessions to reading the session and changing the password; sign-in still
// works; the change clears it; a viewer cannot set it; it is audited.
func TestTenantMemberPasswordChangeRequired(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	service := fixture.service
	const password = "LongEnough-Pass1"
	bob, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "pc-bob", DisplayName: "Bob", Password: password, RequestID: "create-pc-bob"})
	if err != nil {
		t.Fatal(err)
	}
	login := func(secret string) (identity.AuthResult, error) {
		return service.Login(ctx, identity.LoginInput{Username: "pc-bob", Password: secret},
			identity.RequestInfo{RequestID: "pc-" + uuid.NewString()[:8], SourceIP: "192.0.2.61"})
	}
	open, err := login(password)
	if err != nil {
		t.Fatal(err)
	}
	viewer := identity.Principal{UserID: bob.UserID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: owner.TenantID}
	if _, err := service.SetTenantMemberPasswordChangeRequired(ctx, viewer, owner.UserID, true, "v"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("viewer set: %v", err)
	}
	if _, err := service.SetTenantMemberPasswordChangeRequired(ctx, owner, owner.UserID, true, "self"); !errors.Is(err, identity.ErrTenantMemberProtected) {
		t.Fatalf("self set: %v", err)
	}
	member, err := service.SetTenantMemberPasswordChangeRequired(ctx, owner, bob.UserID, true, "require-bob")
	if err != nil || !member.PasswordChangeRequired {
		t.Fatalf("require: %+v %v", member, err)
	}
	// Repeating is a no-op (one audit event).
	if _, err := service.SetTenantMemberPasswordChangeRequired(ctx, owner, bob.UserID, true, "require-bob-2"); err != nil {
		t.Fatal(err)
	}
	// The open session is limited from the next request on.
	if _, err := service.Authenticate(ctx, open.AccessToken); !errors.Is(err, identity.ErrPasswordChangeRequired) {
		t.Fatalf("open session: %v", err)
	}
	// Sign-in still works and reports the requirement.
	session, err := login(password)
	if err != nil || !session.Principal.PasswordChangeRequired {
		t.Fatalf("login: %+v %v", session.Principal, err)
	}
	if _, err := service.AuthenticateSession(ctx, session.AccessToken); !errors.Is(err, identity.ErrPasswordChangeRequired) {
		t.Fatalf("session request: %v", err)
	}
	exempt := identity.WithPasswordChangeExempt(ctx)
	principal, err := service.Authenticate(exempt, session.AccessToken)
	if err != nil || !principal.PasswordChangeRequired {
		t.Fatalf("exempt request: %+v %v", principal, err)
	}
	if err := service.ChangePassword(exempt, identity.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, identity.ChangePasswordInput{CurrentPassword: password, NewPassword: "AnotherLong-Pass2", RequestID: "change-bob"}); err != nil {
		t.Fatalf("change password: %v", err)
	}
	session, err = login("AnotherLong-Pass2")
	if err != nil || session.Principal.PasswordChangeRequired {
		t.Fatalf("login after change: %+v %v", session.Principal, err)
	}
	if _, err := service.Authenticate(ctx, session.AccessToken); err != nil {
		t.Fatalf("session after change: %v", err)
	}
	// Releasing it is audited too.
	if _, err := service.SetTenantMemberPasswordChangeRequired(ctx, owner, bob.UserID, true, "require-again"); err != nil {
		t.Fatal(err)
	}
	if member, err := service.SetTenantMemberPasswordChangeRequired(ctx, owner, bob.UserID, false, "release-bob"); err != nil || member.PasswordChangeRequired {
		t.Fatalf("release: %+v %v", member, err)
	}
	var requires, releases int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='identity.tenant_member.password_change.require'),
		count(*) FILTER (WHERE action='identity.tenant_member.password_change.release') FROM audit_events WHERE resource_id=$1`,
		bob.UserID.String()).Scan(&requires, &releases); err != nil || requires != 2 || releases != 1 {
		t.Fatalf("audit require=%d release=%d %v", requires, releases, err)
	}
}
