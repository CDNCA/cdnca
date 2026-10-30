package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// The v2 document's L4 forwards travel on the dynamic routing scope
// (D13-c0): the node merges them into its L4 runtime.
func TestDynamicRoutingPublicationCarriesStreams(t *testing.T) {
	v8 := richSiteRuntimeV2Publication(t, 0, 2, 0)
	tenant := richTenantID.String()
	stream := "018f47a2-5b9c-7d31-8a60-104c9c0b7402"
	streams := &edgeconfig.StreamRuntime{TenantID: tenant, StreamsV2: []edgeconfig.L4StreamRuntimeV2{{
		SchemaVersion: "cdnca.edge.l4/v2", TenantID: tenant, StreamID: stream, Revision: 1,
		Listener: edgeconfig.L4ListenerV2{Protocol: "tcp", Address: "*", Port: 19000}, Endpoint: edgeconfig.L4EndpointV2{Address: "192.0.2.1", Port: 80},
		Geo:              edgeconfig.L4GeoPolicyV2{TenantID: tenant, StreamID: stream, Revision: 1, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 30000}}}
	v8.Streams = streams
	publication, _, err := buildDynamicRoutingPublication(v8, richTenantID, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := siteobject.ParseRootV2(publication.RootBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range publication.Objects {
		if object.SHA256 == root.ScopeSHA256 {
			scope, err := siteobject.ParseScopeV2(object.Plaintext)
			if err != nil || scope.Streams == nil || len(scope.Streams.StreamsV2) != 1 || scope.Streams.StreamsV2[0].StreamID != stream {
				t.Fatalf("v2 scope streams %+v %v", scope.Streams, err)
			}
			return
		}
	}
	t.Fatal("v2 scope missing")
}
