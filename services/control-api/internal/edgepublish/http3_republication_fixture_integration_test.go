//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// AddHTTPSSite adds an HTTPS website (HTTP 80, HTTPS 443, an active
// certificate) to the scope: on site runtime v2 its HTTPS listener serves
// HTTP/3, so every target node must declare SITE_QUIC.
func (scope *SystemRepublishScope) AddHTTPSSite(t *testing.T, domain string) uuid.UUID {
	t.Helper()
	site := scope.fixture.createSiteWithPortSets(t, domain, []string{"80"}, []string{"443"}, true).Site
	seedSiteRuntimeV2CertificateBinding(t, scope.fixture, site)
	return site.ID
}

// SetSiteQUIC records a new Connect session for nodeID declaring (or, with an
// OpenResty lacking the HTTP/3 module, not declaring) SITE_QUIC, otherwise as AddNode.
func (scope *SystemRepublishScope) SetSiteQUIC(t *testing.T, nodeID uuid.UUID, declared bool) {
	t.Helper()
	features := slices.DeleteFunc(systemRepublishFeatures(6), func(capability *agentv1.Capability) bool {
		return !declared && capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC
	})
	version := "1.0.35-no-quic"
	if declared {
		version = "1.0.35-quic"
	}
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeID, version, features)
}

// PublishManuallyDefault publishes the scope's current facts as the platform
// operator with the default site runtime (v2).
func (scope *SystemRepublishScope) PublishManuallyDefault(t *testing.T, key string, nodeIDs ...uuid.UUID) error {
	t.Helper()
	request := siteRuntimeV2PublishRequest(scope.fixture, key, nodeIDs[0], DefaultSiteRuntimeSchema)
	request.NodeIDs = slices.Clone(nodeIDs)
	_, err := scope.fixture.service.Publish(t.Context(), request)
	return err
}
