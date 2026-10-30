//go:build integration

package rulepackcontrol

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/google/uuid"
)

func lastAudit(t *testing.T, w world, action string, scopeID uuid.UUID) audittest.Event {
	t.Helper()
	return audittest.Last(t, w.pool, `action=$1 AND scope_id=$2`, action, scopeID)
}

func countAudit(t *testing.T, w world, action string) int {
	t.Helper()
	return len(audittest.Query(t, w.pool, `action=$1`, action))
}

func findChange(t *testing.T, event audittest.Event, field string) audit.Change {
	t.Helper()
	for _, item := range event.Changes {
		if item.Field == field {
			return item
		}
	}
	t.Fatalf("%s: no change %q in %+v", event.Action, field, event.Changes)
	return audit.Change{}
}

func wantDenied(t *testing.T, event audittest.Event, actor Actor, reason string) {
	t.Helper()
	if event.Result != "denied" || event.ReasonCode != reason || event.ActorUserID == nil || *event.ActorUserID != actor.UserID {
		t.Fatalf("%s denied event = %+v, want reason %s by %s", event.Action, event, reason, actor.UserID)
	}
}

func withIP(actor Actor, requestID string) Actor {
	actor.SourceIP, actor.RequestID = "203.0.113.7", requestID
	return actor
}

func TestUpdatePackAudit(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	sqli := w.importFile(t, w.platform, "system-sqli.json")
	manual := "manual"
	platform := withIP(w.platform, "req-update-ok")
	if _, err := w.service.UpdatePack(ctx, platform, sqli.PackID, PackUpdate{UpdatePolicy: &manual}); err != nil {
		t.Fatal(err)
	}
	event := lastAudit(t, w, AuditPackUpdate, w.platform.ScopeID)
	if event.Result != "success" || event.ResourceID != sqli.PackID || event.RequestID != "req-update-ok" ||
		event.Payload["layer"] != "system" {
		t.Fatalf("success event = %+v", event)
	}
	if got := findChange(t, event, "update_policy"); got.Before != "auto" || got.After != "manual" {
		t.Fatalf("update_policy change = %+v", got)
	}

	// A tenant may not manage a system pack; the refusal is in its own stream.
	if _, err := w.service.UpdatePack(ctx, w.tenantA, sqli.PackID, PackUpdate{UpdatePolicy: &manual}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant update: %v", err)
	}
	wantDenied(t, lastAudit(t, w, AuditPackUpdate, w.tenantA.ScopeID), w.tenantA, "permission_denied")
	// An undownloaded version is refused, with what was requested.
	missing := "9.9.9"
	if _, err := w.service.UpdatePack(ctx, w.platform, sqli.PackID, PackUpdate{CurrentVersion: &missing}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing version: %v", err)
	}
	denied := lastAudit(t, w, AuditPackUpdate, w.platform.ScopeID)
	wantDenied(t, denied, w.platform, "invalid_input")
	if requested, _ := denied.Payload["requested"].(map[string]any); requested["current_version"] != missing {
		t.Fatalf("denied payload = %+v", denied.Payload)
	}
	if len(denied.Changes) != 0 {
		t.Fatalf("denied event records changes: %+v", denied.Changes)
	}
}

func TestDeleteVersionAudit(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	sqli := w.importFile(t, w.platform, "system-sqli.json")
	level, object := platformLevel()
	platformRow := OverrideInput{Level: level, LevelObjectID: object}
	if err := w.put(t, w.platform, with(platformRow, sqli.PackID, rulepack.StateEnabled, true)); err != nil {
		t.Fatal(err)
	}
	if err := w.service.DeleteVersion(ctx, w.tenantA, sqli.PackID, "1.0.0"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant delete: %v", err)
	}
	wantDenied(t, lastAudit(t, w, AuditVersionDelete, w.tenantA.ScopeID), w.tenantA, "permission_denied")
	if err := w.service.DeleteVersion(ctx, w.platform, sqli.PackID, "1.0.0"); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete enabled current: %v", err)
	}
	inUse := lastAudit(t, w, AuditVersionDelete, w.platform.ScopeID)
	wantDenied(t, inUse, w.platform, "in_use")
	if inUse.Payload["current"] != true || inUse.Payload["enabled"] != true || inUse.ResourceID != sqli.PackID+"@1.0.0" {
		t.Fatalf("in-use payload = %+v", inUse.Payload)
	}

	if err := w.put(t, w.platform, with(platformRow, sqli.PackID, rulepack.StateDisabled, true)); err != nil {
		t.Fatal(err)
	}
	if err := w.service.DeleteVersion(ctx, w.platform, sqli.PackID, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	event := lastAudit(t, w, AuditVersionDelete, w.platform.ScopeID)
	if event.Result != "success" || event.Payload["pack_removed"] != true {
		t.Fatalf("success event = %+v", event)
	}
	if got := findChange(t, event, "current_version"); got.Before != "1.0.0" || got.After != nil {
		t.Fatalf("current_version change = %+v", got)
	}
	findChange(t, event, "versions")
}

func TestPutOverrideAudit(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	sqli := w.importFile(t, w.platform, "system-sqli.json")
	// Locked by the platform: the tenant's refusal is in the tenant stream.
	tenantRow := with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), sqli.PackID, rulepack.StateEnabled, false)
	if err := w.put(t, w.tenantA, tenantRow); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	locked := lastAudit(t, w, AuditOverridePut, w.tenantA.ScopeID)
	wantDenied(t, locked, w.tenantA, "locked_by_upper_level")
	if requested, _ := locked.Payload["requested"].(map[string]any); requested["state"] != "enabled" {
		t.Fatalf("locked payload = %+v", locked.Payload)
	}

	level, object := platformLevel()
	enable := with(OverrideInput{Level: level, LevelObjectID: object}, sqli.PackID, rulepack.StateEnabled, true)
	enable.Params = json.RawMessage(`{"action":"log"}`)
	if err := w.put(t, w.platform, enable); err != nil {
		t.Fatal(err)
	}
	event := lastAudit(t, w, AuditOverridePut, w.platform.ScopeID)
	if event.Result != "success" || event.ResourceID != "platform/"+sqli.PackID || event.Payload["row_existed"] != false {
		t.Fatalf("platform event = %+v", event)
	}
	if got := findChange(t, event, "state"); got.Before != "inherit" || got.After != "enabled" {
		t.Fatalf("state change = %+v", got)
	}
	if got := findChange(t, event, "allow_lower"); got.Before != false || got.After != true {
		t.Fatalf("allow_lower change = %+v", got)
	}
	findChange(t, event, "params")

	// A site row is recorded in its tenant's stream; removing it records the
	// previous state.
	siteRow := with(ref(rulepack.LevelSite, w.siteA1), sqli.PackID, rulepack.StateDisabled, false)
	if err := w.put(t, w.tenantA, siteRow); err != nil {
		t.Fatal(err)
	}
	if got := findChange(t, lastAudit(t, w, AuditOverridePut, w.tenantA.ScopeID), "state"); got.Before != "inherit" || got.After != "disabled" {
		t.Fatalf("site state change = %+v", got)
	}
	if err := w.put(t, w.tenantA, with(siteRow, sqli.PackID, rulepack.StateInherit, false)); err != nil {
		t.Fatal(err)
	}
	removed := lastAudit(t, w, AuditOverridePut, w.tenantA.ScopeID)
	if removed.Payload["row_removed"] != true || findChange(t, removed, "state").Before != "disabled" {
		t.Fatalf("removed event = %+v", removed)
	}

	// Another tenant's site: not found, recorded in the actor's stream only.
	before := len(audittest.Query(t, w.pool, `action=$1 AND scope_id=$2`, AuditOverridePut, w.tenantA.ScopeID))
	if err := w.put(t, w.tenantB, with(ref(rulepack.LevelSite, w.siteA2), sqli.PackID, rulepack.StateEnabled, false)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	wantDenied(t, lastAudit(t, w, AuditOverridePut, w.tenantB.ScopeID), w.tenantB, "not_found")
	if after := len(audittest.Query(t, w.pool, `action=$1 AND scope_id=$2`, AuditOverridePut, w.tenantA.ScopeID)); after != before {
		t.Fatalf("cross-tenant refusal written to tenant A's stream: %d -> %d", before, after)
	}
	// Invalid input is refused before anything is read.
	if _, _, err := w.service.PutOverride(ctx, w.platform, OverrideInput{Level: level, PackID: sqli.PackID, State: "bogus"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bogus state: %v", err)
	}
	wantDenied(t, lastAudit(t, w, AuditOverridePut, w.platform.ScopeID), w.platform, "invalid_input")
}

func TestPublishSiteAudit(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	base := w.importFile(t, w.platform, "system-sqli.json")
	opposite := mustImportModified(t, w, "system-sqli.json", func(d map[string]any) {
		d["pack_id"] = "system/sqli-strict"
		rules := d["rules"].([]any)
		rules[0].(map[string]any)["waf"].(map[string]any)["action"] = "allow"
	})
	level, object := platformLevel()
	for _, id := range []string{base.PackID, opposite.PackID} {
		if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, id, rulepack.StateEnabled, true)); err != nil {
			t.Fatal(err)
		}
	}
	var conflict *ConflictError
	if _, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); !errors.As(err, &conflict) {
		t.Fatalf("conflict: %v", err)
	}
	denied := lastAudit(t, w, AuditSitePublish, w.tenantA.ScopeID)
	wantDenied(t, denied, w.tenantA, "mounts_conflict")
	if conflicts, _ := denied.Payload["conflicts"].([]any); len(conflicts) == 0 || denied.ResourceID != w.siteA1.String() {
		t.Fatalf("conflict payload = %+v", denied.Payload)
	}

	if err := w.put(t, w.tenantA, with(ref(rulepack.LevelTenant, w.tenantA.ScopeID), opposite.PackID, rulepack.StateDisabled, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil {
		t.Fatal(err)
	}
	event := lastAudit(t, w, AuditSitePublish, w.tenantA.ScopeID)
	if event.Result != "success" {
		t.Fatalf("publish event = %+v", event)
	}
	if got := findChange(t, event, "revision"); got.Before != float64(0) || got.After != float64(1) {
		t.Fatalf("revision change = %+v", got)
	}
	if got := findChange(t, event, "mounts"); !sameJSON(got.After, []string{base.PackID + "@1.0.0"}) {
		t.Fatalf("mounts change = %+v", got)
	}
	// Unchanged republish keeps the revision and is still recorded.
	if _, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1); err != nil {
		t.Fatal(err)
	}
	if again := lastAudit(t, w, AuditSitePublish, w.tenantA.ScopeID); again.Payload["unchanged"] != true || len(again.Changes) != 0 {
		t.Fatalf("unchanged event = %+v", again)
	}
	// Another tenant's site: not found in the actor's stream.
	if _, err := w.service.PublishSite(ctx, w.tenantB, w.siteA1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant publish: %v", err)
	}
	wantDenied(t, lastAudit(t, w, AuditSitePublish, w.tenantB.ScopeID), w.tenantB, "not_found")
	if countAudit(t, w, AuditSitePublish) != 4 {
		t.Fatalf("publish events = %d, want 4", countAudit(t, w, AuditSitePublish))
	}
}
