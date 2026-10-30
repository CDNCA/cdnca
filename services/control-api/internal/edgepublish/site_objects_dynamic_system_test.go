package edgepublish

import (
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// The v2 document's platform system block (nginx base, DDoS protection)
// travels on the dynamic routing scope (D13-c0), so the node renders it and
// applies the DDoS table.
func TestDynamicRoutingPublicationCarriesSystem(t *testing.T) {
	v8 := richSiteRuntimeV2Publication(t, 0, 2, 0)
	system, err := edgeconfig.NewSiteRuntimeSystem("018f47a2-5b9c-7d31-8a60-104c9c0b7301", 5, strings.Repeat("e", 64),
		edgeconfig.NginxSettings{WorkerProcesses: 2, WorkerRlimitNoFile: 65535, WorkerShutdownTimeout: 30 * time.Second,
			WorkerConnections: 20000, ResolverAddresses: []string{"1.1.1.1"}, ResolverTimeout: 5 * time.Second, GzipLevel: 5,
			GzipMinimumBytes: 1024, ProxyCacheMethods: []string{"GET", "HEAD"}, ProxyCacheMaxBytes: 1 << 30,
			ProxyCacheZoneBytes: 64 << 20, ProxyMaxTempFileBytes: 1 << 20, ProxyConnectTimeout: 10 * time.Second,
			ProxySendTimeout: 60 * time.Second, ProxyReadTimeout: 60 * time.Second, StreamProxyTimeout: 10 * time.Minute,
			ServerHeader: "cdnca", ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/html", KeepaliveRequests: 1000,
			KeepaliveTimeout: 75 * time.Second, ServerNamesHashMaxSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	protection := edgeconfig.DefaultDDoSProtection()
	protection.MaxConnectionsPerIP, protection.CCKernelBan = 50, edgeconfig.CCKernelBanSitePorts
	ddos, err := edgeconfig.NewSiteRuntimeDDoS(protection, []string{"198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	system.DDoS = &ddos
	v8.System = &system
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
			if err != nil || scope.System == nil || scope.System.Revision != 5 || scope.System.DDoS == nil ||
				scope.System.DDoS.Protection.CCKernelBan != edgeconfig.CCKernelBanSitePorts {
				t.Fatalf("v2 scope system %+v %v", scope.System, err)
			}
			return
		}
	}
	t.Fatal("v2 scope missing")
}
