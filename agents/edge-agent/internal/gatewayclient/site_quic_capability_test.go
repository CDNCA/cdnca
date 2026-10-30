package gatewayclient

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// A v2 command's SITE_QUIC is the document's http3
// capability (QUIC on an HTTPS listener); HTTP_3 (the standalone HTTP/3
// runtime) is not a site runtime capability, so a v2 command naming it is
// refused as unknown.
func TestSiteRuntimeCommandSiteQUICIsTheDocumentHTTP3Capability(t *testing.T) {
	if name, known := siteRuntimeCapabilityName(agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC); !known || name != "http3" {
		t.Fatalf("SITE_QUIC maps to %q (known %v), want http3", name, known)
	}
	if name, known := siteRuntimeCapabilityName(agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3); known {
		t.Fatalf("HTTP_3 maps to site runtime capability %q", name)
	}
}
