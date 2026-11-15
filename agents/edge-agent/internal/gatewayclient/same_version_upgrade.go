package gatewayclient

import (
	"slices"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const sameVersionUpgradeAPIVersion = 1

// WithInstalledReleaseSequence reports the installed release
// manifest's release_sequence and declares SAME_VERSION_UPGRADE v1, both only
// after a Gateway listed SAME_VERSION_UPGRADE in known_capabilities: an older
// Gateway refuses unknown capability names and AgentCapabilities fields.
// Without an upgrade runtime the option is ignored.
func WithInstalledReleaseSequence(sequence uint64) ClientOption {
	return func(client *Client) error {
		if client == nil {
			return ErrInvalidConfiguration
		}
		client.installedReleaseSequence = sequence
		return nil
	}
}

// learnSameVersionUpgrade: true once a Gateway first lists the capability
// (the caller reconnects so the next hello declares it).
func (c *Client) learnSameVersionUpgrade(gatewayHello *agentv1.GatewayHello) bool {
	if c.installedReleaseSequence == 0 || c.upgrades == nil || c.gatewayKnowsSameVersion.Load() ||
		!slices.Contains(gatewayHello.GetKnownCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE) {
		return false
	}
	c.gatewayKnowsSameVersion.Store(true)
	return true
}

func (c *Client) declareSameVersionUpgrade(capabilities *agentv1.AgentCapabilities) {
	if c.installedReleaseSequence == 0 || c.upgrades == nil || !c.gatewayKnowsSameVersion.Load() ||
		hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE) {
		return
	}
	capabilities.Features = append(capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE, ApiVersion: sameVersionUpgradeAPIVersion,
	})
	capabilities.InstalledReleaseSequence = c.installedReleaseSequence
}
