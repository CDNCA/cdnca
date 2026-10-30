package edgepublish

import "testing"

func TestConfigurationArtifactHPKEUsesPublishedAgentProtocolDomain(t *testing.T) {
	// These are the existing wire domains published in agents/edge-agent/README.md
	// and consumed by gatewayclient/hpke.go. Product branding is not a wire upgrade.
	for name, pair := range map[string][2]string{
		"binding": {configurationArtifactHPKEBindingDomain, "cdnca-edge-artifact-hpke-binding-v1\x00"},
		"info":    {configurationArtifactHPKEInfoDomain, "cdnca-edge-artifact-hpke-info-v1\x00"},
		"aad":     {configurationArtifactHPKEAADDomain, "cdnca-edge-artifact-hpke-aad-v1\x00"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s domain differs from the published Agent protocol", name)
		}
	}
}
