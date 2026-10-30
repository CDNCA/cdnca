package edgepublish

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
)

// 带套餐的转发在运行时里写明套餐，节点把它记到会话事实上；
// 发布要求能力 66 L4_PACKAGE_ATTRIBUTION v1，旧节点被拒并给出升级提示。无套餐的转发不要求。
func TestL4PackageAttributionRequiresCapability66(t *testing.T) {
	stream := l4V2ContractStream("tcp")
	stream.PackageSubscriptionID = "66666666-6666-4666-8666-666666666666"
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err != nil {
		t.Fatal(err)
	}
	versions := map[agentv1.CapabilityName]uint32{}
	for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}) {
		versions[capability.Name] = capability.ApiVersion
	}
	if versions[agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION] != 1 {
		t.Fatalf("packaged forward capabilities = %v, want L4_PACKAGE_ATTRIBUTION v1", versions)
	}
	plain := stream
	plain.PackageSubscriptionID = ""
	for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{plain}) {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION {
			t.Fatal("forward without a package requires L4_PACKAGE_ATTRIBUTION")
		}
	}
	if name, ok := siteruntimecap.Name(edgeconfig.L4PackageAttributionCapability); !ok ||
		name != agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION {
		t.Fatalf("l4_package_attribution maps to %v, %v", name, ok)
	}
	if feature, gated := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION,
		ApiVersion: 1}); !gated || !strings.Contains(feature, "L4_PACKAGE_ATTRIBUTION") {
		t.Fatalf("gated feature = %q, %v", feature, gated)
	}
	// 非规范的套餐 ID 在契约校验时拒绝。
	for _, bad := range []string{"66666666-6666-4666-8666-66666666666G", "66666666-6666-4666-8666-66666666666A",
		"00000000-0000-0000-0000-000000000000"} {
		invalid := stream
		invalid.PackageSubscriptionID = bad
		if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, invalid); err == nil {
			t.Errorf("package subscription %q accepted", bad)
		}
	}
}
