package main

import (
	"strings"
	"testing"
)

func TestEdgePublishSignerEnvironmentAllowsConfiguredProviders(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "file", environment: []string{
			"EDGE_PUBLISH_SIGNER_PROVIDER=file",
			"EDGE_PUBLISH_SIGNING_KEY_ID=edge-file-test",
			"EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE=/var/run/secrets/edge-signing/private.pem",
		}},
		{name: "remote", environment: []string{
			"EDGE_PUBLISH_SIGNER_PROVIDER=remote",
			"EDGE_PUBLISH_SIGNING_KEY_ID=edge-remote-test",
			"EDGE_PUBLISH_SIGNING_PUBLIC_KEY_FILE=/var/run/secrets/edge-signing/public.pem",
			"EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT=https://signer.example.test/v1/sign",
			"EDGE_PUBLISH_SIGNER_REMOTE_CA_FILE=/var/run/secrets/edge-signing/ca.pem",
			"EDGE_PUBLISH_SIGNER_REMOTE_BEARER_TOKEN_FILE=/var/run/secrets/edge-signing/token",
			"EDGE_PUBLISH_SIGNER_REMOTE_TIMEOUT=2s",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := append(edgePublishRuntimeEnvironment(), test.environment...)
			config, err := loadEdgePublishRuntimeConfigFromEnvEntries(environment)
			defer config.clearSecrets()
			if err != nil {
				t.Fatalf("signer environment rejected before signer validation: %v", err)
			}
			if !config.Enabled || !config.Runtime.Enabled || config.Runtime.CursorActiveKey.ID != "active" {
				t.Fatal("signer environment changed the publication runtime configuration")
			}
		})
	}
}

func TestEdgePublishSignerEnvironmentRemainsStrict(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		environment := append(edgePublishRuntimeEnvironment(), "EDGE_PUBLISH_SIGNER_REMOTE_UNKNOWN=restricted-value-marker")
		config, err := loadEdgePublishRuntimeConfigFromEnvEntries(environment)
		defer config.clearSecrets()
		if err == nil || config.Enabled || config.Runtime.Enabled || !strings.HasPrefix(err.Error(), "unknown EDGE_PUBLISH_") {
			t.Fatal("unknown signer environment variable was not rejected")
		}
	})
	for _, name := range append([]string{edgePublishSignerProviderEnv}, edgePublishRemoteSignerEnvironment...) {
		t.Run("duplicate/"+name, func(t *testing.T) {
			environment := append(edgePublishRuntimeEnvironment(), name+"=restricted-value-marker", name+"=restricted-value-marker")
			config, err := loadEdgePublishRuntimeConfigFromEnvEntries(environment)
			defer config.clearSecrets()
			if err == nil || config.Enabled || config.Runtime.Enabled || !strings.HasPrefix(err.Error(), "duplicate EDGE_PUBLISH_") {
				t.Fatal("duplicate signer environment variable was not rejected as a duplicate")
			}
		})
		t.Run("disabled/"+name, func(t *testing.T) {
			config, err := loadEdgePublishRuntimeConfigFromEnvEntries([]string{
				"EDGE_PUBLISH_RUNTIME_ENABLED=false", name + "=restricted-value-marker",
			})
			defer config.clearSecrets()
			if err == nil || config.Enabled || config.Runtime.Enabled {
				t.Fatal("disabled publication runtime accepted signer configuration")
			}
		})
	}
}
