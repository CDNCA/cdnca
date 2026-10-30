//go:build integration

package sitegroup

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceNewWriteDisplayID(t *testing.T) {
	f := newSiteGroupFixture(t)
	actor := f.actor(f.tenantAScope, f.tenantAUser)
	remark := "retained\nremark"
	var id uuid.UUID
	for _, step := range []struct {
		key      string
		revision int64
		deleted  bool
		write    func() (WriteResult, error)
	}{
		{"display-create", 1, false, func() (WriteResult, error) {
			return f.service.Create(t.Context(), actor, CreateRequest{TargetScopeID: f.tenantAScope, Name: "new", Remark: &remark, WriteMetadata: metadata("display-create")})
		}},
		{"display-rename", 2, false, func() (WriteResult, error) {
			return f.service.Rename(t.Context(), actor, RenameRequest{TargetScopeID: f.tenantAScope, ID: id, ExpectedRevision: 1, Name: "renamed", WriteMetadata: metadata("display-rename")})
		}},
		{"display-noop", 2, false, func() (WriteResult, error) {
			return f.service.Rename(t.Context(), actor, RenameRequest{TargetScopeID: f.tenantAScope, ID: id, ExpectedRevision: 2, Name: "renamed", WriteMetadata: metadata("display-noop")})
		}},
		{"display-delete", 3, true, func() (WriteResult, error) {
			return f.service.Delete(t.Context(), actor, DeleteRequest{TargetScopeID: f.tenantAScope, ID: id, ExpectedRevision: 2, WriteMetadata: metadata("display-delete")})
		}},
	} {
		result, err := step.write()
		if err != nil || result.Replayed {
			t.Fatalf("%s initial write: %#v %v", step.key, result, err)
		}
		if id == uuid.Nil {
			id = result.Group.ID
		}
		var display string
		if err := f.pool.QueryRow(t.Context(), `SELECT display_id::text FROM site_group_display_ids WHERE scope_id=$1 AND group_id=$2`, f.tenantAScope, id).Scan(&display); err != nil {
			t.Fatal(err)
		}
		if display == "" || result.Group.DisplayID != display || result.Group.ID != id || result.Group.ScopeID != f.tenantAScope ||
			result.Group.Revision != step.revision || result.Group.Remark != remark || (result.Group.DeletedAt != nil) != step.deleted {
			t.Errorf("%s metadata: display=%q group=%#v", step.key, display, result.Group)
		}
		if !step.deleted {
			current, err := f.service.Get(t.Context(), actor, f.tenantAScope, id)
			if err != nil {
				t.Fatal(err)
			}
			if current.DisplayID != result.Group.DisplayID {
				t.Errorf("%s write display ID %q differs from GET %q", step.key, result.Group.DisplayID, current.DisplayID)
			}
		}
		replay, err := step.write()
		if err != nil || !replay.Replayed {
			t.Fatalf("%s replay: %#v %v", step.key, replay, err)
		}
		assertSiteGroupReplayContent(t, result.Group, replay)
		var persisted []byte
		if err := f.pool.QueryRow(t.Context(), `SELECT response_body::text FROM site_group_write_requests WHERE idempotency_key=$1`, step.key).Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(replay.Response, persisted) {
			t.Fatalf("%s replay does not preserve stored bytes", step.key)
		}
		again, err := step.write()
		if err != nil || !again.Replayed || !bytes.Equal(again.Response, persisted) {
			t.Fatalf("%s repeated replay changed: %v", step.key, err)
		}
	}
}

func TestServiceLegacyReceiptWithoutDisplayID(t *testing.T) {
	f := newSiteGroupFixture(t)
	actor := f.actor(f.tenantAScope, f.tenantAUser)
	created, err := f.service.Create(t.Context(), actor, CreateRequest{TargetScopeID: f.tenantAScope, Name: "legacy", WriteMetadata: metadata("seed-display")})
	if err != nil {
		t.Fatal(err)
	}
	request := CreateRequest{TargetScopeID: f.tenantAScope, Name: "legacy", WriteMetadata: metadata("legacy-display")}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		Name          string    `json:"name"`
	}{request.TargetScopeID, request.Name})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(map[string]any{"id": created.Group.ID, "scope_id": f.tenantAScope, "name": "legacy", "revision": 1,
		"created_at": created.Group.CreatedAt, "updated_at": created.Group.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,resource_id,response_status,response_body,completed_at)
		VALUES($1,$2,$3,$3,'site_group.create','legacy-display',$4,$5,201,$6,now())`, uuid.New(), f.tenantAUser, f.tenantAScope, digest[:], created.Group.ID, legacy); err != nil {
		t.Fatal(err)
	}
	var before []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT response_body::text FROM site_group_write_requests WHERE idempotency_key='legacy-display'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Rename(t.Context(), actor, RenameRequest{TargetScopeID: f.tenantAScope, ID: created.Group.ID, ExpectedRevision: 1, Name: "current", Remark: stringPointer("current remark"), WriteMetadata: metadata("current-display")}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		replayed, err := f.service.Create(t.Context(), actor, request)
		if err != nil || !replayed.Replayed || !bytes.Equal(replayed.Response, before) || replayed.Group.DisplayID != "" ||
			replayed.Group.Remark != "" || replayed.Group.Name != "legacy" || replayed.Group.Revision != 1 {
			t.Fatalf("legacy response was enriched or changed: %#v %v", replayed, err)
		}
	}
	var after, afterDigest []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT response_body::text,request_digest FROM site_group_write_requests WHERE idempotency_key='legacy-display'`).Scan(&after, &afterDigest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !bytes.Equal(digest[:], afterDigest) {
		t.Fatal("legacy receipt or digest was rewritten")
	}
}

func TestServiceMissingDisplayIDRollsBack(t *testing.T) {
	f := newSiteGroupFixture(t)
	// Fault injection is confined to this test's freshly migrated, private schema.
	if _, err := f.pool.Exec(t.Context(), `ALTER TABLE site_groups DISABLE TRIGGER site_groups_assign_display_id_272`); err != nil {
		t.Fatal(err)
	}
	_, err := f.service.Create(t.Context(), f.actor(f.tenantAScope, f.tenantAUser), CreateRequest{
		TargetScopeID: f.tenantAScope, Name: "missing display", WriteMetadata: metadata("missing-display"),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("missing display mapping must fail closed: %v", err)
	}
	var groups, receipts, audits int
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM site_groups WHERE name='missing display'),
		(SELECT count(*) FROM site_group_write_requests WHERE idempotency_key='missing-display'),
		(SELECT count(*) FROM audit_events WHERE request_id='request-missing-display')`).Scan(&groups, &receipts, &audits); err != nil {
		t.Fatal(err)
	}
	if groups != 0 || receipts != 0 || audits != 0 {
		t.Fatalf("failed metadata lookup committed partial facts: groups=%d receipts=%d audits=%d", groups, receipts, audits)
	}
}
