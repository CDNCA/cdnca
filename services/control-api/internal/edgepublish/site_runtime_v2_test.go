package edgepublish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// Production API required by this RED:
//
//	compileSiteRuntimeV2Document(raw []byte) ([]byte, [32]byte, []*agentv1.Capability, bool, error)
//	siteRuntimeV2ArtifactIdentity(configVersionID uuid.UUID, canonical []byte) (uuid.UUID, [32]byte, error)
//	validateSiteRuntimeV2TargetCapabilities(required []*agentv1.Capability, requiresTLS bool,
//		advertised map[uuid.UUID][]*agentv1.Capability, advertisedTLS map[uuid.UUID]bool) error
//
// Publish must call target capability validation before it persists a rollout,
// node deployment, or command outbox row.
func TestCompileSiteRuntimeV2DocumentHasExactJCSRevisionAndCapabilities(t *testing.T) {
	canonical, digest, capabilities, requiresTLS, err := compileSiteRuntimeV2Document(siteRuntimeV2DocumentFixture())
	if err != nil {
		t.Fatalf("compileSiteRuntimeV2Document() error = %v", err)
	}
	const wantDigest = "1a06799172972c8ca1e1bc82f9525b148f29f7067a652c1f8e91b544d849f1ce"
	if hex.EncodeToString(digest[:]) != wantDigest || sha256.Sum256(canonical) != digest {
		t.Fatalf("canonical digest = %x, want %s", digest, wantDigest)
	}
	var document struct {
		Schema               string `json:"schema"`
		ConfigurationScopeID string `json:"configuration_scope_id"`
		SourceRevision       int64  `json:"source_revision"`
		ConfigVersionID      string `json:"config_version_id"`
		Sites                []struct {
			ID        string `json:"id"`
			Revision  int64  `json:"revision"`
			Listeners []struct {
				AddressFamily string   `json:"address_family"`
				Protocols     []string `json:"protocols"`
				TLS           *struct {
					CertificateVersionID string `json:"certificate_version_id"`
				} `json:"tls"`
			} `json:"listeners"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(canonical, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != "cdnca.edge.site-runtime/v2" ||
		document.ConfigurationScopeID != "018f47a2-5b9c-7d31-8a60-104c9c0b7101" ||
		document.SourceRevision != 41 || document.ConfigVersionID != "018f47a2-5b9c-7d31-8a60-104c9c0b7102" ||
		len(document.Sites) != 1 || document.Sites[0].Revision != 7 ||
		len(document.Sites[0].Listeners) != 1 || document.Sites[0].Listeners[0].TLS == nil ||
		document.Sites[0].Listeners[0].TLS.CertificateVersionID != "018f47a2-5b9c-7d31-8a60-104c9c0b7104" ||
		document.Sites[0].Listeners[0].AddressFamily != "dual_stack" ||
		!slices.Equal(document.Sites[0].Listeners[0].Protocols, []string{"http1", "http2", "http3"}) {
		t.Fatalf("source identity was not preserved: %+v", document)
	}
	wantCapabilities := []siteRuntimeV2CapabilityExpectation{
		{agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, 1},
		{agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, 1},
		{agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, 1},
		{agentv1.CapabilityName_CAPABILITY_NAME_IPV4, 1},
		{agentv1.CapabilityName_CAPABILITY_NAME_IPV6, 1},
		{agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, edgeconfig.MinSiteRuntimeVersion},
		{agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, 1},
	}
	gotCapabilities := make([]siteRuntimeV2CapabilityExpectation, len(capabilities))
	for index, capability := range capabilities {
		if capability == nil {
			t.Fatalf("capability %d is nil", index)
		}
		gotCapabilities[index] = siteRuntimeV2CapabilityExpectation{capability.Name, capability.ApiVersion}
	}
	if !slices.Equal(gotCapabilities, wantCapabilities) {
		t.Fatalf("required capabilities = %+v, want %+v", gotCapabilities, wantCapabilities)
	}
	if !requiresTLS {
		t.Fatal("TLS listener did not produce an independent TLS requirement")
	}
}

func TestSiteRuntimeV2TargetValidationRejectsEveryIncapableNodeBeforeDelivery(t *testing.T) {
	required := siteRuntimeV2RequiredCapabilities()
	first := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7201")
	second := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7202")
	capable := map[uuid.UUID][]*agentv1.Capability{
		first:  cloneSiteRuntimeV2Capabilities(required),
		second: cloneSiteRuntimeV2Capabilities(required),
	}
	capableTLS := map[uuid.UUID]bool{first: true, second: true}
	if err := validateSiteRuntimeV2TargetCapabilities(required, true, capable, capableTLS); err != nil {
		t.Fatalf("capable target rejected: %v", err)
	}

	for _, capability := range required {
		capability := capability
		t.Run(capability.Name.String(), func(t *testing.T) {
			advertised := cloneSiteRuntimeV2TargetCapabilities(capable)
			advertised[second] = slices.DeleteFunc(advertised[second], func(value *agentv1.Capability) bool {
				return value.Name == capability.Name
			})
			if err := validateSiteRuntimeV2TargetCapabilities(required, true, advertised, capableTLS); err == nil {
				t.Fatalf("target missing %s capability was accepted", capability.Name)
			}
		})
	}

	lowerSiteRuntime := cloneSiteRuntimeV2TargetCapabilities(capable)
	for _, value := range lowerSiteRuntime[second] {
		if value.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			value.ApiVersion = 1
		}
	}
	if err := validateSiteRuntimeV2TargetCapabilities(required, true, lowerSiteRuntime, capableTLS); err == nil {
		t.Fatal("target advertising site_runtime/v1 was accepted for a v2 rollout")
	}
	missingTLS := map[uuid.UUID]bool{first: true, second: false}
	if err := validateSiteRuntimeV2TargetCapabilities(required, true, capable, missingTLS); err == nil {
		t.Fatal("target missing independent TLS capability was accepted")
	}
	if err := validateSiteRuntimeV2TargetCapabilities(required, false, capable, nil); err != nil {
		t.Fatalf("non-TLS document unexpectedly required a TLS capability: %v", err)
	}
	unknownNode := cloneSiteRuntimeV2TargetCapabilities(capable)
	unknownNode[uuid.New()] = nil
	if err := validateSiteRuntimeV2TargetCapabilities(required, true, unknownNode, capableTLS); err == nil {
		t.Fatal("target without durable capability facts was accepted")
	}
}

func TestSiteRuntimeV2RolloutArtifactIdentityIsDeterministicAndWireBound(t *testing.T) {
	canonical, _, _, _, err := compileSiteRuntimeV2Document(siteRuntimeV2DocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	configID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102")
	firstID, firstDigest, err := siteRuntimeV2ArtifactIdentity(configID, canonical)
	if err != nil {
		t.Fatal(err)
	}
	secondID, secondDigest, err := siteRuntimeV2ArtifactIdentity(configID, append([]byte(nil), canonical...))
	if err != nil {
		t.Fatal(err)
	}
	wantID := uuid.NewSHA1(configID, []byte("site-runtime-v2"))
	if firstID != wantID || secondID != wantID || firstDigest != secondDigest || firstDigest != sha256.Sum256(canonical) {
		t.Fatalf("artifact identity = %s/%x then %s/%x, want %s/%x", firstID, firstDigest, secondID, secondDigest, wantID, sha256.Sum256(canonical))
	}
	changed := append([]byte(nil), canonical...)
	changed[len(changed)-1] ^= 1
	_, changedDigest, err := siteRuntimeV2ArtifactIdentity(configID, changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == firstDigest {
		t.Fatal("artifact digest did not bind exact wire bytes")
	}
}

type siteRuntimeV2CapabilityExpectation struct {
	name       agentv1.CapabilityName
	apiVersion uint32
}

// siteRuntimeV2RequiredCapabilities is what every site runtime v2 document
// requires: site_runtime at the current floor (v6, bindSiteRuntimeV2Cache).
func siteRuntimeV2RequiredCapabilities() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.LazyCertificateSiteRuntimeVersion},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1},
	}
}

// siteRuntimeV2NodeFeatures is what a node able to run every v2 release
// declares: the document capabilities with site runtime v8 (site object
// delivery, which every v2 publication uses).
func siteRuntimeV2NodeFeatures() []*agentv1.Capability {
	features := siteRuntimeV2RequiredCapabilities()
	for _, feature := range features {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			feature.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	// Every 1.0.35 node stamps its forwards' package.
	return append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION,
		ApiVersion: edgeconfig.L4PackageAttributionAPIVersion})
}

// siteRuntimeV2CapabilitiesWithoutSiteRuntime is the document capability set
// without site_runtime, for fixtures that declare their own version.
func siteRuntimeV2CapabilitiesWithoutSiteRuntime() []*agentv1.Capability {
	return slices.DeleteFunc(siteRuntimeV2RequiredCapabilities(), func(capability *agentv1.Capability) bool {
		return capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME
	})
}

func cloneSiteRuntimeV2Capabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*agentv1.Capability)
	}
	return result
}

func cloneSiteRuntimeV2TargetCapabilities(values map[uuid.UUID][]*agentv1.Capability) map[uuid.UUID][]*agentv1.Capability {
	result := make(map[uuid.UUID][]*agentv1.Capability, len(values))
	for nodeID, capabilities := range values {
		result[nodeID] = cloneSiteRuntimeV2Capabilities(capabilities)
	}
	return result
}

func siteRuntimeV2DocumentFixture() []byte {
	return []byte(`{"schema":"cdnca.edge.site-runtime/v2","configuration_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","source_revision":41,"config_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","sites":[{"id":"018f47a2-5b9c-7d31-8a60-104c9c0b7103","revision":7,"domains":["cdn.example.test"],"listeners":[{"id":"public-443","position":0,"address_family":"dual_stack","port":443,"protocols":["http1","http2","http3"],"tls":{"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104"}}],"origin_pools":[{"id":"primary","position":0,"kind":"origin","algorithm":"round_robin","origins":[{"id":"origin-a","position":0,"tier":"origin","scheme":"https","host":"192.0.2.10","port":443,"weight":100,"sni":"origin.example.test","trust_ref":"sha256:8b5e6f57d8f47ec690b6e1e0ef2fd5d7fa6ef74d8d17eb9e9fc2f0901e21a61d"}],"retry":{"methods":["GET","HEAD"],"bodyless_only":true,"response_not_started":true,"retry_on":["connect_error","connect_timeout","read_timeout","http_502","http_503","http_504"],"max_attempts":3,"connect_timeout_ms":3000,"read_timeout_ms":30000,"total_budget_ms":60000}},{"id":"l2","position":1,"kind":"l2","algorithm":"least_conn","origins":[{"id":"l2-a","position":0,"tier":"l2","scheme":"http","host":"2001:db8::10","port":8080,"weight":100,"node_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7105"}],"retry":{"methods":["GET","HEAD"],"bodyless_only":true,"response_not_started":true,"retry_on":["connect_error","connect_timeout","read_timeout","http_502","http_503","http_504"],"max_attempts":3,"connect_timeout_ms":3000,"read_timeout_ms":30000,"total_budget_ms":60000}}],"default_pool_id":"l2","websocket":true,"range":true,"l2":{"enabled":true,"direct_fallback_pool_id":"primary","probe_interval_ms":10000,"failure_threshold":3,"recovery_threshold":3,"single_half_open_probe":true,"max_hops":1}}],"required_capabilities":[{"name":"http1","api_version":1},{"name":"http2","api_version":1},{"name":"http3","api_version":1},{"name":"ipv4","api_version":1},{"name":"ipv6","api_version":1},{"name":"site_runtime","api_version":6},{"name":"websocket","api_version":1}]}`)
}
