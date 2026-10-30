package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const webpPreview = "RIFF\x00\x00\x00\x00WEBPVP8 rest"

type failingForwarder struct{}

func (failingForwarder) Forward(context.Context, string, string, string, []byte) (int, []byte, error) {
	return 0, nil, errors.New("down")
}

// The market theme preview is re-checked and re-served same-origin: only GET,
// only png/jpeg/webp at most 512 KiB, sniffed (never the market's type), with
// nosniff; everything else is a 404 so the card falls back to its colors.
func TestPluginPreviewRelay(t *testing.T) {
	id := uuid.NewString()
	path := "/v1/admin/market/plugins/" + id + "/preview"
	f := &scriptedForwarder{status: 200, body: webpPreview}
	current := caller("platform", PermissionBrowse)
	h := buyerHandler(&current, f, &fakeStore{})
	w := request(h, "GET", path, "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/webp" || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
		w.Body.String() != webpPreview || !strings.HasPrefix(w.Header().Get("ETag"), `"`) {
		t.Fatalf("preview: %d %v", w.Code, w.Header())
	}
	if got := strings.Join(f.calls, "\n"); got != "GET /v1/plugins/"+id+"/preview key= " {
		t.Fatalf("forwarded: %s", got)
	}
	if again := request(h, "GET", path, "", map[string]string{"If-None-Match": w.Header().Get("ETag")}); again.Code != http.StatusNotModified {
		t.Fatalf("etag: %d", again.Code)
	}
	for name, body := range map[string]string{
		"svg":  `<svg xmlns="http://www.w3.org/2000/svg"/>`,
		"html": `<html><script>alert(1)</script></html>`,
		"json": `{"error":"not_found"}`,
		"big":  "\x89PNG\r\n\x1a\n" + strings.Repeat("x", 512<<10),
	} {
		f.body = body
		if w := request(h, "GET", path, "", nil); w.Code != http.StatusNotFound || strings.HasPrefix(w.Header().Get("Content-Type"), "image/") {
			t.Fatalf("%s relayed: %d %s", name, w.Code, w.Header().Get("Content-Type"))
		}
	}
	f.status, f.body = 404, `{"error":"not_found"}`
	if w := request(h, "GET", path, "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("market 404: %d", w.Code)
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		if w := request(h, method, path, "", nil); w.Code == 200 {
			t.Fatalf("%s allowed", method)
		}
	}
	if w := request(h, "GET", "/v1/admin/market/plugins/not-a-uuid/preview", "", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", w.Code)
	}
	current = caller("tenant")
	if w := request(h, "GET", path, "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("tenant without permission: %d", w.Code)
	}
}

// With the market unreachable the copy kept is answered; without one, 502.
func TestPluginPreviewCache(t *testing.T) {
	id := uuid.NewString()
	path := "/v1/admin/market/plugins/" + id + "/preview"
	current := caller("platform", PermissionBrowse)
	forwarder := &switchForwarder{next: &scriptedForwarder{status: 200, body: webpPreview}}
	h := buyerHandler(&current, forwarder, &fakeStore{})
	if w := request(h, "GET", path, "", nil); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	forwarder.next = failingForwarder{}
	if w := request(h, "GET", path, "", nil); w.Code != 200 || w.Body.String() != webpPreview {
		t.Fatalf("cached: %d", w.Code)
	}
	if w := request(h, "GET", "/v1/admin/market/plugins/"+uuid.NewString()+"/preview", "", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("uncached: %d", w.Code)
	}
}

type switchForwarder struct{ next Forwarder }

func (s *switchForwarder) Forward(ctx context.Context, method, path, key string, body []byte) (int, []byte, error) {
	return s.next.Forward(ctx, method, path, key, body)
}
