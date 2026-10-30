package edgepublish

import (
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// siteRuntimeV2SecurityRequired is what a site runtime document requires for
// one listener carrying site's compiled security (compileSiteFact), as the
// publisher derives it (setSiteRuntimeV2SecurityCapabilities).
func siteRuntimeV2SecurityRequired(site edgeconfig.Site) []*agentv1.Capability {
	security := &edgeconfig.ListenerSecurity{Policies: site.SecurityPolicies, CC: site.CCV2}
	if len(security.Policies) == 0 && security.CC == nil {
		security = nil
	}
	document := siteRuntimeV2Document{Sites: []siteRuntimeV2Site{{Listeners: []siteRuntimeV2Listener{{Security: security}}}}}
	setSiteRuntimeV2SecurityCapabilities(&document)
	return siteRuntimeV2CapabilitiesForTest(document.RequiredCapabilities)
}

// siteRuntimeV2StreamsRequired is what a site runtime document requires for
// the L4 v2 streams, sharing ports with sitePorts (bindSiteRuntimeV2Streams).
func siteRuntimeV2StreamsRequired(streams []edgeconfig.L4StreamRuntimeV2, sitePorts ...uint16) []*agentv1.Capability {
	return siteRuntimeV2StreamsLifecycleRequired(streams, nil, sitePorts...)
}

// siteRuntimeV2StreamsLifecycleRequired adds the scope's L4 lifecycle
// requirements (loadL4V2LifecycleProtocols) to siteRuntimeV2StreamsRequired.
func siteRuntimeV2StreamsLifecycleRequired(streams []edgeconfig.L4StreamRuntimeV2, lifecycle []l4ProtocolCapability,
	sitePorts ...uint16) []*agentv1.Capability {
	document := siteRuntimeV2Document{}
	if len(sitePorts) > 0 {
		site := siteRuntimeV2Site{}
		for _, port := range sitePorts {
			site.Listeners = append(site.Listeners, siteRuntimeV2Listener{Port: int64(port)})
		}
		document.Sites = []siteRuntimeV2Site{site}
	}
	facts := make([]snapshotStream, len(streams))
	for index := range streams {
		facts[index] = snapshotStream{RuntimeV2: &streams[index]}
	}
	bindSiteRuntimeV2Streams(&document, uuid.New(), facts, lifecycle)
	return siteRuntimeV2CapabilitiesForTest(document.RequiredCapabilities)
}

func siteRuntimeV2CapabilitiesForTest(values []siteRuntimeV2Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, 0, len(values))
	for _, value := range values {
		if name, ok := siteruntimecap.Name(value.Name); ok {
			result = append(result, &agentv1.Capability{Name: name, ApiVersion: value.APIVersion})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// siteRuntimeV2StreamsFragmentError is the publisher's check of the scope's
// L4 v2 streams against the node health port (siteRuntimeStreamFragment).
func siteRuntimeV2StreamsFragmentError(tenantID string, healthPort uint16, streams ...edgeconfig.L4StreamRuntimeV2) error {
	document := siteRuntimeV2Document{ConfigVersionID: "01990000-0000-7000-8000-000000000001", SourceRevision: 9,
		Streams: &edgeconfig.StreamRuntime{TenantID: tenantID, StreamsV2: streams}}
	_, _, err := siteRuntimeStreamFragment(document, healthPort)
	return err
}
