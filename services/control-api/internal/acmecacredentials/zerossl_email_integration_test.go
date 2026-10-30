//go:build integration

package acmecacredentials_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// fix-certops：按邮箱从（假）ZeroSSL 取 EAB 后经 Save 加密保存，Resolver 能解出，
// 平台默认签发机构可选 ZeroSSL。
func TestZeroSSLEABFromEmailSavesCredentials(t *testing.T) {
	pool := eabPool(t)
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-key-1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := acmecacredentials.NewStore(pool, cipher, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := platformActor(t, pool, "system_configuration.manage")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"eab_kid":"kid-from-email","eab_hmac_key":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"}`))
	}))
	defer server.Close()
	fetcher := &acmecacredentials.ZeroSSLEABFetcher{Endpoint: server.URL, Client: server.Client()}
	keyID, hmacKey, err := fetcher.Fetch(t.Context(), "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Save(t.Context(), actor, acmecacredentials.SaveRequest{
		CA: acmecacredentials.CAZeroSSL, KeyID: keyID, HMACKey: hmacKey, RequestID: "eab-email-1",
	})
	if err != nil || !view.Configured || view.KeyID != "kid-from-email" || view.Revision != 1 {
		t.Fatalf("save = %+v, %v", view, err)
	}
	resolver, err := acmecacredentials.NewResolver(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	gotKID, key, found, err := resolver.ExternalAccountBinding(t.Context(), acmecacredentials.Directory(acmecacredentials.CAZeroSSL))
	if err != nil || !found || gotKID != "kid-from-email" || string(key) != "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		t.Fatalf("resolve = %q %q %v %v", gotKID, key, found, err)
	}
	if configured, err := acmecacredentials.Configured(t.Context(), pool, acmecacredentials.CAZeroSSL); err != nil || !configured {
		t.Fatalf("configured = %v %v", configured, err)
	}
}
