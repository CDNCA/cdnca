package main

import (
	"os"
	"strings"
	"testing"
)

// B-D3: buildAndClearEdgePublishRuntime zeroes the configuration it is given
// (clearSecrets), so edgePublishConfig.Enabled read after it is always false.
// The certificate publication runtime gated on it was never started and its
// readiness probe never mounted: publication intents stayed pending forever
// while /health/ready answered 200.
func TestEdgePublishClearZeroesEnabled(t *testing.T) {
	config := edgePublishRuntimeConfig{Enabled: true}
	config.clearSecrets()
	if config.Enabled {
		t.Fatal("clearSecrets no longer zeroes Enabled; revisit the B-D3 gate")
	}
}

func TestCertificatePublicationGateDoesNotReadClearedEdgePublishConfig(t *testing.T) {
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	clearCall := strings.Index(source, "buildAndClearEdgePublishRuntime(&edgePublishConfig")
	if clearCall < 0 {
		t.Fatal("main.go no longer builds the edge publication runtime from edgePublishConfig")
	}
	if after := source[clearCall:]; strings.Contains(after, "edgePublishConfig.Enabled") {
		t.Fatal("main.go reads edgePublishConfig.Enabled after buildAndClearEdgePublishRuntime cleared it")
	}
	if !strings.Contains(source, "certificatePublicationConfig.Enabled = cfg.ACMERuntimeEnabled && edgePublishEnabled") {
		t.Fatal("certificate publication gate must use the edge publication flag captured before clearing")
	}
}
