package marketsubscribehttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// u4d (C22): feedback relays. Buyer writes need purchase and an
// Idempotency-Key; the seller side needs sell; filters are pattern checked.
func TestFeedbackRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionBrowse, PermissionPurchase)
	h := buyerHandler(&current, f, &fakeStore{})
	sub, ticket := uuid.NewString(), uuid.NewString()
	key := map[string]string{"Idempotency-Key": "fb-1"}
	body := `{"category":"outage","title":"502","body":"x"}`
	if w := request(h, "POST", "/v1/admin/market/subscriptions/"+sub+"/feedback", body, key); w.Code != 200 {
		t.Fatalf("open: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/v1/admin/market/subscriptions/"+sub+"/feedback", body, nil); w.Code != 400 {
		t.Fatalf("open without key: %d", w.Code)
	}
	if w := request(h, "GET", "/v1/admin/market/buyer/feedback?state=open&subscription="+sub, "", nil); w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := request(h, "GET", "/v1/admin/market/buyer/feedback?state=bogus", "", nil); w.Code != 400 {
		t.Fatalf("bad state: %d", w.Code)
	}
	if w := request(h, "POST", "/v1/admin/market/buyer/feedback/"+ticket+"/escalate", `{"amount_minor":100}`, key); w.Code != 200 {
		t.Fatalf("escalate: %d %s", w.Code, w.Body)
	}
	want := []string{`POST /v1/subscriptions/` + sub + `/feedback key=fb-1 ` + body,
		`GET /v1/buyer/feedback?state=open&subscription=` + sub + ` key= `,
		`POST /v1/buyer/feedback/` + ticket + `/escalate key=fb-1 {"amount_minor":100}`}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	// A buyer-only controller cannot read or answer the seller side.
	for _, c := range [][2]string{{"GET", "/v1/admin/market/seller/feedback"}, {"POST", "/v1/admin/market/seller/feedback/" + ticket + "/messages"}} {
		if w := request(h, c[0], c[1], `{"body":"x"}`, key); w.Code != http.StatusForbidden {
			t.Fatalf("buyer %s %s: %d", c[0], c[1], w.Code)
		}
	}
	current = caller("platform", PermissionSell)
	if w := request(h, "POST", "/v1/admin/market/seller/feedback/"+ticket+"/messages", `{"state":"in_progress"}`, key); w.Code != 200 {
		t.Fatalf("seller reply: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/v1/admin/market/subscriptions/"+sub+"/feedback", body, key); w.Code != http.StatusForbidden {
		t.Fatalf("seller opens a buyer ticket: %d", w.Code)
	}
	for pattern := range memberRoutes {
		if strings.Contains(pattern, "/seller/feedback") && strings.HasSuffix(pattern, "/escalate") {
			t.Fatalf("seller escalation route: %s", pattern)
		}
	}
}
