package main

import (
	"os"
	"strings"
	"testing"
)

func TestCurrentProductionBatchRunServerComposition(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"loadAnalyticsGeoArtifactRuntimeConfig()",
		"openAnalyticsGeoArtifactRuntime(",
		"analyticsGeoArtifactRuntime.Reader()",
		"AnalyticsGeoHandlerFactory:",
		"readinessProbes = append(readinessProbes, analyticsGeoArtifactRuntime)",
		"analyticsGeoArtifactRuntime.Close()",
		"errorPageConfig.Enabled && sitePublicationRuntime.Publisher == nil",
		"edge publication runtime is required for error page publication",
		"originauthpublicationhttp.NewRuntimeHandler(",
		"edgepublish.NewOriginAuthArtifactProducer(",
		"OriginAuthPublicationHandlerFactory:",
		"errorpageobjectstore.New(ctx, errorPageConfig.ObjectStore)",
		"errorPageScanner, err = errorpagescanner.New(ctx, errorPageConfig.Scanner)",
		"errorPageObjectStore, err = errorpageobjectstore.New(ctx, errorPageConfig.ObjectStore)",
		"ContentStore: errorPageObjectStore, Scanner: errorPageScanner",
		"errorpagescanner.Config{",
		"errorpagecontrolhttp.NewRuntime(ctx, errorPageConfig",
		"ErrorPageHandlerFactory:",
		"errorpagepublicationhttp.NewRuntimeHandler(",
		"edgepublish.NewErrorPagePublisher(",
		"ErrorPagePublicationHandlerFactory:",
		"readinessProbes = append(readinessProbes, errorPageRuntime)",
		"runRequiredErrorPageRuntime(ctx, errorPageRuntime, failures)",
		"errorPageRuntime.Close()",
		"loadControlUpgradePlanRuntimeConfig(",
		"openControlUpgradePlanRuntime(",
		"controlUpgradePlanRuntime.HandlerFactory()",
		"readinessProbes = append(readinessProbes, controlUpgradePlanRuntime)",
		"controlUpgradePlanRuntime.Close()",
		"securitycoordmetricshttp.NewHandler(",
		"SecurityCoordinationMetricsHandlerFactory:",
		"readinessProbes = append(readinessProbes, dnsReconcileRuntime)",
		"dnsReconcileRuntime.Close()",
		// the system republisher delivers theme
		// activations to every tenant's error pages.
		"errorPageSnapshotSource = compiler",
		"ErrorPageSource: errorPageSnapshotSource,",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("runServer production composition missing %q", required)
		}
	}
}

func TestCurrentProductionBatchDNSPropagationCompositionRemainsRequired(t *testing.T) {
	source, err := os.ReadFile("dns_reconcile_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		`"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS"`,
		`"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS"`,
		`"DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM"`,
		"dnspropagation.NewWireSource(",
		"dnspropagation.NewEngine(",
		"dnspropagation.NewPostgresRetryStore(",
		"propagationLifecycle.Ready()",
		"propagationLifecycle.Close()",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("DNS propagation production composition missing %q", required)
		}
	}
}
