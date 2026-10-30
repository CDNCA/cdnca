package securityactivation

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// A manually activated WAF (OWASP CRS module) or CC rule refused for node
// capability waits and resumes once the nodes are upgraded; so does
// a carrier / IDC / ASN / region WAF rule refused for IP_INTEL.
func TestWaitableCapabilitiesCoverGatedWAFAndCC(t *testing.T) {
	for name, want := range map[agentv1.CapabilityName]bool{
		agentv1.CapabilityName_CAPABILITY_NAME_CC:             true,
		agentv1.CapabilityName_CAPABILITY_NAME_JA4:            true,
		agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE: true,
		agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL:       true,
		// a v2 HTTPS listener needs SITE_QUIC; a node upgraded
		// to a QUIC-capable OpenResty declares it and the activation resumes.
		agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC: true,
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: false,
	} {
		if got := waitableCapability(name); got != want {
			t.Errorf("waitableCapability(%s)=%v want %v", name, got, want)
		}
	}
}
