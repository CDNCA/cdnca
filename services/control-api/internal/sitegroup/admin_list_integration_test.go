//go:build integration

package sitegroup

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAdminGroupList(t *testing.T) {
	f := newSiteGroupFixture(t)
	platform := f.actor(f.platformScope, f.platformUser)
	a := f.actor(f.tenantAScope, f.tenantAUser)
	for _, scope := range []uuid.UUID{f.tenantAScope, f.tenantBScope} {
		if _, err := f.service.Create(t.Context(), platform, CreateRequest{TargetScopeID: scope, Name: "same name", WriteMetadata: metadata(scope.String())}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.service.ListAdmin(t.Context(), platform, 1, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("directory permission absent: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) SELECT id,'identity.users.manage' FROM roles WHERE scope_id=$1`, f.platformScope); err != nil {
		t.Fatal(err)
	}
	ownerRole := uuid.New()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','Owner',true)`, ownerRole, f.tenantAScope); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.tenantAScope, f.tenantAUser, ownerRole); err != nil {
		t.Fatal(err)
	}
	page, err := f.service.ListAdmin(t.Context(), platform, 1, 1)
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Limit != 1 {
		t.Fatalf("page: %#v %v", page, err)
	}
	all, err := f.service.ListAdmin(t.Context(), platform, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range all.Items {
		if item.DisplayID == "" || seen[item.DisplayID] {
			t.Fatalf("invalid display ID: %#v", item)
		}
		seen[item.DisplayID] = true
		if item.ScopeID == f.tenantAScope {
			if item.UserState != "resolved" || item.User == nil || item.User.ID != f.tenantAUser || item.User.DisplayID == "" {
				t.Fatalf("owner: %#v", item)
			}
		} else if item.UserState != "missing" || item.User != nil {
			t.Fatalf("must not guess owner: %#v", item)
		}
	}
	if _, err := f.service.ListAdmin(t.Context(), a, 1, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant global read: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.tenantAScope, f.tenantAViewer, ownerRole); err != nil {
		t.Fatal(err)
	}
	all, err = f.service.ListAdmin(t.Context(), platform, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range all.Items {
		if item.ScopeID == f.tenantAScope && (item.User != nil || item.UserState != "ambiguous") {
			t.Fatalf("ambiguous owner: %#v", item)
		}
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, f.tenantAScope, f.tenantAViewer); err != nil {
		t.Fatal(err)
	}
	all, err = f.service.ListAdmin(t.Context(), platform, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range all.Items {
		if item.ScopeID == f.tenantAScope && (item.UserState != "resolved" || item.User == nil || item.User.ID != f.tenantAUser) {
			t.Fatalf("inactive membership must not become an owner: %#v", item)
		}
	}
	for _, params := range [][2]int{{0, 10}, {1, 0}, {1, 101}} {
		if _, err := f.service.ListAdmin(t.Context(), platform, params[0], params[1]); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid pagination: %v", err)
		}
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, f.platformScope, f.platformUser); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.ListAdmin(t.Context(), platform, 1, 10); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("revoked global read: %v", err)
	}
}

func TestGroupRemarkCompatibility(t *testing.T) {
	f := newSiteGroupFixture(t)
	a := f.actor(f.tenantAScope, f.tenantAUser)
	legacy := CreateRequest{TargetScopeID: f.tenantAScope, Name: "legacy", WriteMetadata: metadata("legacy")}
	created, err := f.service.Create(t.Context(), a, legacy)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		Name          string    `json:"name"`
	}{f.tenantAScope, "legacy"})
	var digest, before []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT request_digest,response_body::text FROM site_group_write_requests WHERE idempotency_key='legacy'`).Scan(&digest, &before); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, want[:]) {
		t.Fatal("legacy digest changed")
	}
	remark := "第一行\n第二行"
	changed, err := f.service.Rename(t.Context(), a, RenameRequest{TargetScopeID: f.tenantAScope, ID: created.Group.ID, ExpectedRevision: 1, Name: "legacy", Remark: &remark, WriteMetadata: metadata("remark")})
	if err != nil || changed.Group.Revision != 2 || changed.Group.Remark != remark {
		t.Fatalf("remark edit: %#v %v", changed, err)
	}
	unchanged, err := f.service.Rename(t.Context(), a, RenameRequest{TargetScopeID: f.tenantAScope, ID: created.Group.ID, ExpectedRevision: 2, Name: "renamed", WriteMetadata: metadata("legacy-rename")})
	if err != nil || unchanged.Group.Revision != 3 || unchanged.Group.Remark != remark {
		t.Fatalf("omitted remark: %#v %v", unchanged, err)
	}
	get, err := f.service.Get(t.Context(), a, f.tenantAScope, created.Group.ID)
	if err != nil || get.Remark != remark || get.DisplayID == "" {
		t.Fatalf("exact get: %#v %v", get, err)
	}
	empty := ""
	cleared, err := f.service.Rename(t.Context(), a, RenameRequest{TargetScopeID: f.tenantAScope, ID: created.Group.ID, ExpectedRevision: 3, Name: "renamed", Remark: &empty, WriteMetadata: metadata("clear")})
	if err != nil || cleared.Group.Revision != 4 || cleared.Group.Remark != "" {
		t.Fatalf("clear remark: %#v %v", cleared, err)
	}
	replayed, err := f.service.Create(t.Context(), a, legacy)
	if err != nil || !replayed.Replayed || replayed.Group.Name != "legacy" || replayed.Group.Revision != 1 {
		t.Fatalf("legacy replay: %#v %v", replayed, err)
	}
	var after []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT response_body::text FROM site_group_write_requests WHERE idempotency_key='legacy'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !json.Valid(replayed.Response) {
		t.Fatal("stored response changed or not returned")
	}
	for _, invalid := range []string{"bad\x00remark", "bad\x7fremark", string(bytes.Repeat([]byte("x"), 1025))} {
		if _, err := f.service.Create(t.Context(), a, CreateRequest{TargetScopeID: f.tenantAScope, Name: "bad", Remark: &invalid, WriteMetadata: metadata("bad")}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid remark accepted: %v", err)
		}
	}
}
