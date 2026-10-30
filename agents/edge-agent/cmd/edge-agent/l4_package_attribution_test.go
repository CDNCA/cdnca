package main

import "testing"

// 四层遥测来源的身份带上运行时里转发的套餐，每个监听（含附加监听）一致。
func TestL4TelemetryRegistrationsCarryThePackage(t *testing.T) {
	const subscription = "88888888-8888-4888-8888-888888888883"
	document := multiListenerTelemetryDocument()
	document.Streams[0].PackageSubscriptionID = subscription
	sources, err := l4TelemetryRegistrations(telemetrySecureRoot(t), telemetryTestNodeID, document)
	if err != nil || len(sources) != 3 {
		t.Fatalf("sources = %+v, %v", sources, err)
	}
	for _, source := range sources {
		if source.Identity.PackageSubscriptionID != subscription {
			t.Fatalf("source %s package = %q", source.SourcePath, source.Identity.PackageSubscriptionID)
		}
	}
	document.Streams[0].PackageSubscriptionID = ""
	sources, err = l4TelemetryRegistrations(telemetrySecureRoot(t), telemetryTestNodeID, document)
	if err != nil || sources[0].Identity.PackageSubscriptionID != "" {
		t.Fatalf("forward without a package = %+v, %v", sources, err)
	}
}
