package dnsproviderremote

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// N1 (73, 10-23): Record.List for domain=cdn.868yun.com (a subdomain of the
// hosted 868yun.com) answered code 13 "当前域名未添加解析". It fell through to
// malformedProviderResponse and the CNAME job failed silently. Code 13 is a
// distinct, non-temporary zone-not-hosted error.
func TestDNSPodCode13IsZoneNotHosted(t *testing.T) {
	config := ProviderConfig{ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": "123456", "dp_key": "dnspod-zone-not-hosted-secret"}}
	adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, writer, map[string]any{"status": map[string]any{
			"code": "13", "message": "当前域名未添加解析，请返回域名列表"}})
	}), time.Second)
	provider := &dnsPodProvider{adapter: adapter}
	_, err := provider.request(context.Background(), completeTestConfig(config), "/Record.List",
		url.Values{"domain": {testZone}})
	assertRemoteError(t, err, CodeZoneNotHosted)
	if remote, ok := err.(*Error); !ok || remote.Temporary {
		t.Fatalf("error = %#v, want a non-temporary zone-not-hosted error", err)
	}
}
