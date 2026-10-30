package edgepublish

import (
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"maps"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Brotli or a compression level of the site's own needs
// EDGE_BROTLI, WebP needs EDGE_WEBP; plain gzip settings need neither.
func TestSiteAccessCapabilities(t *testing.T) {
	gzip := &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"}}
	for name, test := range map[string]struct {
		access *edgeconfig.SiteAccess
		want   map[string]uint32
	}{
		"none":     {nil, nil},
		"gzip":     {&edgeconfig.SiteAccess{Compression: gzip}, map[string]uint32{}},
		"off":      {&edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Types: []string{}}}, map[string]uint32{}},
		"brotli":   {&edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"}, Encodings: []string{"br", "gzip"}}}, map[string]uint32{"edge_brotli": 1}},
		"level":    {&edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"text/css"}, GzipLevel: 4}}, map[string]uint32{"edge_brotli": 1}},
		"webp":     {&edgeconfig.SiteAccess{WebP: &edgeconfig.SiteWebP{Enabled: true}}, map[string]uint32{"edge_webp": 1}},
		"response": {&edgeconfig.SiteAccess{ResponseRules: []edgeconfig.SiteResponseRule{{ID: "r", Action: edgeconfig.ResponseActionLog}}}, map[string]uint32{"edge_response_rules": 1}},
		"together": {&edgeconfig.SiteAccess{Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"a/b"}, Encodings: []string{"br"}}, WebP: &edgeconfig.SiteWebP{Enabled: true}}, map[string]uint32{"edge_brotli": 1, "edge_webp": 1}},
	} {
		if got := siteAccessCapabilities(test.access); !maps.Equal(got, test.want) {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
	for name, capability := range map[string]agentv1.CapabilityName{
		"edge_brotli":         agentv1.CapabilityName_CAPABILITY_NAME_EDGE_BROTLI,
		"edge_webp":           agentv1.CapabilityName_CAPABILITY_NAME_EDGE_WEBP,
		"edge_response_rules": agentv1.CapabilityName_CAPABILITY_NAME_EDGE_RESPONSE_RULES,
	} {
		if got, ok := siteruntimecap.Name(name); !ok || got != capability {
			t.Errorf("%s maps to %v", name, got)
		}
		feature, gated := gatedFeature(&agentv1.Capability{Name: capability, ApiVersion: 1})
		if !gated || !strings.Contains(feature, "EDGE_") {
			t.Errorf("%s is not a gated feature: %q", name, feature)
		}
	}
}
