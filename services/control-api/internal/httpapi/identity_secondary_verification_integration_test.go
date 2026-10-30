package httpapi

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestManagedUserSecondaryVerificationHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	notifications, err := notification.NewStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	f.service.SetSecondaryVerificationNotifier(identity.NotificationSecondaryVerificationNotifier{Store: notifications})
	user, _ := f.create(t, "secondary", nil, false)
	path := metadataUserPath(user) + "/secondary-verification?tenant_scope_id=" + user["scope_id"].(string)
	initial := f.request(t, "GET", path, "secver-default", nil, 200)
	if initial["revision"] != float64(0) || initial["enabled"] != false || initial["expiry_action"] != "none" || initial["deadline"] != nil {
		t.Fatalf("default=%v", initial)
	}
	unauth := f
	unauth.admin = ""
	unauth.request(t, "GET", path, "secver-anon", nil, 401)
	deadline := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	for i, body := range []map[string]any{
		{"expected_revision": 0, "enabled": true},
		{"expected_revision": 0, "enabled": true, "expiry_action": "lock_sites"},
		{"expected_revision": 0, "enabled": true, "expiry_action": "lock_sites", "deadline": "2026-11-01 12:00:00"},
		{"expected_revision": 0, "enabled": true, "expiry_action": "delete_sites", "deadline": deadline},
		{"expected_revision": 0, "enabled": false, "expiry_action": "none", "deadline": deadline},
		{"expected_revision": 0, "enabled": true, "expiry_action": "none", "extra": 1},
	} {
		f.request(t, "PUT", path, "secver-invalid-"+string(rune('a'+i)), body, 400)
	}
	enabled := f.request(t, "PUT", path, "secver-enable", map[string]any{
		"expected_revision": 0, "enabled": true, "expiry_action": "lock_sites", "deadline": deadline}, 200)
	if enabled["revision"] != float64(1) || enabled["enabled"] != true || enabled["deadline"] != deadline ||
		enabled["completed"] != false || enabled["requested_at"] == nil {
		t.Fatalf("enabled=%v", enabled)
	}
	f.request(t, "PUT", path, "secver-stale", map[string]any{"expected_revision": 0, "enabled": true, "expiry_action": "none"}, 409)
	read := f.request(t, "GET", path, "secver-read", nil, 200)
	if read["revision"] != float64(1) || read["expiry_action"] != "lock_sites" {
		t.Fatalf("read=%v", read)
	}
	var outbox int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_events WHERE event_type='identity.secondary_verification'`).Scan(&outbox); err != nil || outbox != 1 {
		t.Fatalf("notification events=(%d,%v)", outbox, err)
	}
}
