package edgepublish

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// lazyTestDocument is the cache test document with one TLS listener on 443.
func lazyTestDocument(t *testing.T, tls bool) siteRuntimeV2Document {
	t.Helper()
	document := siteRuntimeCacheTestDocument(t, siteRuntimeCacheTestFact(), nil)
	if tls {
		site := &document.Sites[0]
		site.Listeners = append(site.Listeners, siteRuntimeV2Listener{
			ID: "https-443", Position: int64(len(site.Listeners)), AddressFamily: "dual_stack", Port: 443,
			Protocols: []string{"http1", "http2"},
			TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7104",
				Protocols: []string{"TLSv1.2", "TLSv1.3"}},
		})
		document.RequiredCapabilities = append(document.RequiredCapabilities[:1],
			append([]siteRuntimeV2Capability{{"http2", 1}}, document.RequiredCapabilities[1:]...)...)
	}
	return document
}

func lazyTestAdvertised(versions ...uint32) ([]uuid.UUID, map[uuid.UUID][]*agentv1.Capability) {
	nodes := make([]uuid.UUID, len(versions))
	advertised := make(map[uuid.UUID][]*agentv1.Capability, len(versions))
	for index, version := range versions {
		nodes[index] = uuid.New()
		advertised[nodes[index]] = []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
		}
	}
	return nodes, advertised
}

func requiredSiteRuntime(document siteRuntimeV2Document) uint32 {
	for _, capability := range document.RequiredCapabilities {
		if capability.Name == "site_runtime" {
			return capability.APIVersion
		}
	}
	return 0
}

// Every document that serves TLS uses lazy certificates (site runtime v7);
// there is no per-site certificate form for nodes below v7. Such a target is
// refused by the capability check, naming every node that lacks v7.
func TestSiteRuntimeV2LazyCertificatesWheneverTLSIsServed(t *testing.T) {
	for name, test := range map[string]struct {
		tls  bool
		lazy bool
	}{
		"TLS listener":    {true, true},
		"no TLS listener": {false, false},
	} {
		document := lazyTestDocument(t, test.tls)
		if err := applySiteRuntimeV2LazyCertificates(&document, 1234); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := document.LazyCertificates != nil; got != test.lazy {
			t.Fatalf("%s: lazy = %v, want %v", name, got, test.lazy)
		}
		want := siteRuntimeV6APIVersion
		if test.lazy {
			want = edgeconfig.LazyCertificateSiteRuntimeVersion
			if document.LazyCertificates.CacheMax != 1234 {
				t.Fatalf("%s: cache_max = %d", name, document.LazyCertificates.CacheMax)
			}
		}
		if requiredSiteRuntime(document) != want {
			t.Fatalf("%s: site_runtime = %d, want %d", name, requiredSiteRuntime(document), want)
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
		if strings.Contains(string(canonical), `"lazy_certificates"`) != test.lazy {
			t.Fatalf("%s: canonical = %s", name, canonical)
		}
		_, advertised := lazyTestAdvertised(7, 7)
		if err := validateSiteRuntimeV2TargetCapabilities(capabilities, false, advertised, nil); err != nil {
			t.Fatalf("%s: v7 targets refused: %v", name, err)
		}
	}

	document := lazyTestDocument(t, true)
	if err := applySiteRuntimeV2LazyCertificates(&document, 1234); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatal(err)
	}
	nodes, advertised := lazyTestAdvertised(7, 6, 6)
	refusal := siteRuntimeV2CapabilityRefusal(nodes, capabilities, advertised, nil)
	var target *TargetCapabilityError
	if !errors.As(refusal, &target) || !errors.Is(refusal, ErrTargetIneligible) || target.NodeID != nodes[1] ||
		target.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME ||
		target.Required != edgeconfig.LazyCertificateSiteRuntimeVersion || target.Advertised != 6 ||
		len(target.OtherNodeIDs) != 1 || target.OtherNodeIDs[0] != nodes[2] {
		t.Fatalf("v6 targets: refusal = %#v", refusal)
	}

	document = lazyTestDocument(t, true)
	if applySiteRuntimeV2LazyCertificates(&document, 0) == nil {
		t.Fatal("invalid cache_max accepted")
	}
}

func TestSiteRuntimeV2DocumentLazyCertificatesNeedV7(t *testing.T) {
	document := lazyTestDocument(t, true)
	document.LazyCertificates = &edgeconfig.SiteRuntimeLazyCertificates{CacheMax: 100}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("lazy certificates under site_runtime v6 accepted")
	}
	setSiteRuntimeV2CapabilityExact(document.RequiredCapabilities, "site_runtime", 7)
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
		t.Fatalf("v7 lazy document refused: %v", err)
	}
	document.LazyCertificates.CacheMax = edgeconfig.MaxLazyCertificateCacheMax + 1
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("cache_max above the bound accepted")
	}
	document.LazyCertificates = nil
	setSiteRuntimeV2CapabilityExact(document.RequiredCapabilities, "site_runtime", 8)
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("site_runtime v8 accepted")
	}
}

func TestSiteRuntimeV7GatedFeatureNamesLazyCertificates(t *testing.T) {
	feature, gated := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 7})
	if !gated || !strings.Contains(feature, "lazy") {
		t.Fatalf("v7 feature = %q", feature)
	}
}

func TestDefaultConfigLazyCertificateCacheMax(t *testing.T) {
	if DefaultConfig().LazyCertificateCacheMax != edgeconfig.DefaultLazyCertificateCacheMax {
		t.Fatalf("default cache_max = %d", DefaultConfig().LazyCertificateCacheMax)
	}
}
