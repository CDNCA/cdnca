package announcement

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// C32: the audience count shown before publication must equal the recipients
// publication actually snapshots.
func TestAudienceCountMatchesPublishedRecipients(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	other := seedAdditionalTenant(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	ctx := context.Background()

	// userB is selected directly and via the role: counted once.
	selected := mustCreateDraft(t, store, tenant.admin, "c32-selected", Audience{UserIDs: []uuid.UUID{tenant.userB}, GroupIDs: []uuid.UUID{tenant.groupID}})
	all := mustCreateDraft(t, store, tenant.admin, "c32-all", Audience{All: true})
	if _, err := pool.Exec(ctx, `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, tenant.scopeID, tenant.userA); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		item Announcement
		want int64
	}{{selected, 1}, {all, 2}} {
		count, err := store.AudienceCount(ctx, tenant.admin, test.item.ID)
		if err != nil || count.RecipientCount != test.want || count.Version != test.item.Version {
			t.Fatalf("audience count %s = %+v, %v; want %d", test.item.ID, count, err, test.want)
		}
		mustPublish(t, store, tenant.admin, test.item)
		assertCount(t, pool, `SELECT count(*) FROM announcement_recipient_snapshots WHERE announcement_id=$1`, int(test.want), test.item.ID)
	}
	if _, err := store.AudienceCount(ctx, Actor{ScopeID: other.scopeID, UserID: tenant.admin.UserID, SessionID: tenant.admin.SessionID}, selected.ID); err == nil {
		t.Fatal("audience count crossed the tenant boundary")
	}

	platform := seedGlobalPlatformActor(t, pool)
	global, err := store.CreateGlobalDraft(ctx, platform, CreateGlobalDraftRequest{
		Content: Content{Title: "c32", Body: "c32"},
		Audience: GlobalAudience{
			TenantScopeIDs: []uuid.UUID{other.scopeID},
			RoleTargets:    []GlobalRoleTarget{{ScopeID: tenant.scopeID, RoleID: tenant.groupID}},
			UserTargets:    []GlobalUserTarget{{ScopeID: tenant.scopeID, UserID: tenant.userB}},
		},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "c32-global", RequestID: "req-c32-global",
	})
	if err != nil {
		t.Fatal(err)
	}
	count, err := store.GlobalAudienceCount(ctx, platform, global.ID)
	if err != nil || count.RecipientCount != 2 {
		t.Fatalf("global audience count = %+v, %v; want 2", count, err)
	}
	published, err := store.PublishGlobal(ctx, platform, GlobalTransitionRequest{
		AnnouncementID: global.ID, ExpectedRevision: global.Revision, IdempotencyKey: "c32-global-publish", RequestID: "req-c32-global-publish",
	})
	if err != nil || published.RecipientCount != count.RecipientCount {
		t.Fatalf("published = %+v, %v; preview %d", published, err, count.RecipientCount)
	}
	if _, err := store.GlobalAudienceCount(ctx, tenant.admin, global.ID); err == nil {
		t.Fatal("tenant actor counted a global announcement")
	}
}

// C32: managers pick audience members by name with only the announcement
// permission, and stored IDs resolve back to names.
func TestAudienceDirectorySearchesByNameWithinScope(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	other := seedAdditionalTenant(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	ctx := context.Background()

	users, err := store.AudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindUser, Search: "USER-1", Limit: 20})
	if err != nil || len(users.Items) != 1 || users.Items[0].ID != tenant.userA || users.Items[0].Name != "tenant-main-user-1" || users.Items[0].ScopeID != nil {
		t.Fatalf("user search = %+v, %v", users, err)
	}
	leaked, err := store.AudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindUser, Search: "tenant-other", Limit: 20})
	if err != nil || len(leaked.Items) != 0 {
		t.Fatalf("tenant directory leaked another tenant: %+v, %v", leaked, err)
	}
	roles, err := store.AudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindRole, Search: "ops", Limit: 20})
	if err != nil || len(roles.Items) != 1 || roles.Items[0].ID != tenant.groupID || roles.Items[0].Name != "ops-group" {
		t.Fatalf("role search = %+v, %v", roles, err)
	}
	missing := uuid.New()
	lookup, err := store.AudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindRole, IDs: []uuid.UUID{tenant.groupID, other.groupID, missing}})
	if err != nil || len(lookup.Items) != 1 || lookup.Items[0].ID != tenant.groupID {
		t.Fatalf("role lookup = %+v, %v", lookup, err)
	}
	if _, err := store.AudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindTenant, Limit: 20}); err == nil {
		t.Fatal("tenant directory listed tenants")
	}

	platform := seedGlobalPlatformActor(t, pool)
	tenants, err := store.GlobalAudienceDirectory(ctx, platform, AudienceDirectoryRequest{Kind: AudienceKindTenant, Search: "main", Limit: 20})
	if err != nil || len(tenants.Items) != 1 || tenants.Items[0].ID != tenant.scopeID || tenants.Items[0].Name != "tenant-main" {
		t.Fatalf("tenant search = %+v, %v", tenants, err)
	}
	scoped, err := store.GlobalAudienceDirectory(ctx, platform, AudienceDirectoryRequest{Kind: AudienceKindUser, ScopeID: other.scopeID, Limit: 20})
	if err != nil || len(scoped.Items) != 1 || scoped.Items[0].ID != other.userID || scoped.Items[0].ScopeID == nil || *scoped.Items[0].ScopeID != other.scopeID {
		t.Fatalf("scoped user search = %+v, %v", scoped, err)
	}
	if _, err := store.GlobalAudienceDirectory(ctx, platform, AudienceDirectoryRequest{Kind: AudienceKindRole, Limit: 20}); err == nil {
		t.Fatal("global role search without a tenant was accepted")
	}
	if _, err := store.GlobalAudienceDirectory(ctx, tenant.admin, AudienceDirectoryRequest{Kind: AudienceKindTenant, Limit: 20}); err == nil {
		t.Fatal("tenant actor listed all tenants")
	}
}
