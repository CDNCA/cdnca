package edgepublish

import (
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// G8-a 缺陷 3：v2 文档带站点全部域名，遥测身份清单曾要求每站恰好 1 个域名，
// 多域名站点的 v2 发布在 compileSiteRuntimeV2Facts 返回 ErrInvalidInput。
// 遥测按 (站点, 端口) 采集（日志路径不含域名），清单每个监听一条，以站点的
// 第一个域名为代表域名，与服务端 parseTelemetrySiteRuntimeV2 保持一致。
func TestSiteRuntimeV2TelemetryManifestAcceptsMultiDomainSite(t *testing.T) {
	scopeID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tenantID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	multiID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	singleID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	configID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: 3,
		ConfigVersionID: configID.String(), Sites: []siteRuntimeV2Site{
			{ID: multiID.String(), Domains: []string{"multi.example.test", "static.multi.example.test", "www.multi.example.test"},
				Listeners: []siteRuntimeV2Listener{{Port: 80}, {Port: 443}}},
			{ID: singleID.String(), Domains: []string{"single.example.test"}, Listeners: []siteRuntimeV2Listener{{Port: 80}}},
		},
	}
	stateRoot := filepath.Join(t.TempDir(), "edge")
	content, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7183"),
		configID, 3, document, nil, nil, noAccessLogFields, stateRoot)
	if err != nil {
		t.Fatalf("buildSiteRuntimeV2TelemetryManifest(multi-domain) error = %v", err)
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		site, domain string
		port         uint16
	}
	got := map[key]bool{}
	for _, site := range manifest.Sites {
		got[key{site.SiteID, site.Domain, site.ListenPort}] = true
	}
	want := []key{
		{multiID.String(), "multi.example.test", 80}, {multiID.String(), "multi.example.test", 443},
		{singleID.String(), "single.example.test", 80},
	}
	if len(manifest.Sites) != len(want) {
		t.Fatalf("manifest sites = %+v, want one entry per listener %v", manifest.Sites, want)
	}
	for _, item := range want {
		if !got[item] {
			t.Fatalf("manifest missing %+v: %+v", item, manifest.Sites)
		}
	}
}
