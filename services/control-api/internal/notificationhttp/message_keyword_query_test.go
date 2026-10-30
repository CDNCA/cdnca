package notificationhttp

import (
	"net/http/httptest"
	"testing"
)

func TestMessageQueriesAcceptKeywords(t *testing.T) {
	admin := messageQuery(httptest.NewRequest("GET", "/v1/admin/notifications/messages?user=zhang&package=basic&site=example.test", nil))
	if admin.Invalid || admin.User != "zhang" || admin.Package != "basic" || admin.Site != "example.test" {
		t.Fatalf("admin=%+v", admin)
	}
	own := ownMessageQuery(httptest.NewRequest("GET", "/v1/account/notification-messages?package=basic&site=example.test", nil))
	if own.Invalid || own.Package != "basic" || own.Site != "example.test" {
		t.Fatalf("own=%+v", own)
	}
	if own := ownMessageQuery(httptest.NewRequest("GET", "/v1/account/notification-messages?user=x", nil)); !own.Invalid {
		t.Fatal("own messages must not take a user filter")
	}
}
