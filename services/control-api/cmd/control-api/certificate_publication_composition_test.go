package main

import (
	"os"
	"strings"
	"testing"
)

func TestControlAPIMountsRequiredCertificatePublicationRuntime47(t *testing.T) {
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		"openCertificatePublicationProductionRuntime(",
		"newConfiguredACMEPublicationResolverKeyring(cfg)",
		"certificatePublicationRuntime.Start(ctx)",
		"certificatePublicationRuntime.Ready()",
		"certificatePublicationRuntime.Close()",
		"certificate publication runtime stopped",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("main.go does not mount required certificate publication runtime: missing %q", required)
		}
	}
}

func TestCertificatePublicationCompositionMountsOpaqueResolver(t *testing.T) {
	content, err := os.ReadFile("certificate_publication_composition.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		"OpaqueResolver certificateasset.OpaquePublicationResolver",
		"publicationConfig.OpaqueResolver = dependencies.OpaqueResolver",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("certificate publication composition missing %q", required)
		}
	}
}

func TestCertificatePublicationCompositionRejectsPartialDependencies47(t *testing.T) {
	config := defaultCertificatePublicationRuntimeConfig()
	if runtime, err := buildCertificatePublicationProductionRuntime(
		certificatePublicationProductionDependencies{}, config,
	); err == nil || runtime != nil {
		t.Fatalf("partial composition runtime=%v err=%v", runtime, err)
	}
	config.Enabled = false
	if runtime, err := buildCertificatePublicationProductionRuntime(
		certificatePublicationProductionDependencies{}, config,
	); err != nil || runtime == nil || runtime.state != certificatePublicationRuntimeUnconfigured {
		t.Fatalf("disabled composition runtime=%v err=%v", runtime, err)
	}
}
