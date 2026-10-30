package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestOBS12ManifestCapturePolicyMapsExactlyToTailer(t *testing.T) {
	policy := edgeconfig.TelemetrySiteCapturePolicy{
		SiteID: telemetryTestSiteID, Enabled: true,
		RequestHeaderAllowlist:    []string{"Authorization", "X-Request-Id"},
		ResponseHeaderAllowlist:   []string{"X-Cache"},
		RequestBodyFieldAllowlist: []string{"profile"}, ResponseBodyFieldAllowlist: []string{"result"},
		MaxValueBytes: 128, MaxBodyBytes: 4096, MaxEventBytes: 32768,
	}
	got, err := eventspoolCapturePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	want := eventspool.CapturePolicy{
		Enabled:        true,
		RequestHeaders: []string{"Authorization", "X-Request-Id"}, ResponseHeaders: []string{"X-Cache"},
		RequestBodyFields: []string{"profile"}, ResponseBodyFields: []string{"result"},
		MaxHeaderValueBytes: 128, MaxBodyBytes: 4096, MaxEventBytes: 32768,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("eventspool capture policy = %+v, want %+v", got, want)
	}

	disabled, err := eventspoolCapturePolicy(edgeconfig.TelemetrySiteCapturePolicy{SiteID: telemetryTestSiteID})
	if err != nil || !reflect.DeepEqual(disabled, eventspool.CapturePolicy{}) {
		t.Fatalf("disabled eventspool capture policy = %+v, %v", disabled, err)
	}
}

func TestOBS12PrecheckRejectsUnavailableTaskAndJA4Capabilities(t *testing.T) {
	for _, capability := range []string{"task_binding", "ja4"} {
		t.Run(capability, func(t *testing.T) {
			root := telemetrySecureRoot(t)
			bundle := telemetryBundle(t, root, "cfg-v1")
			var manifest map[string]any
			if err := json.Unmarshal(bundle.Files[edgeconfig.TelemetryIdentityManifestPath], &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["source_capabilities"].(map[string]any)[capability] = true
			content, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Files[edgeconfig.TelemetryIdentityManifestPath] = append(content, '\n')
			release := filepath.Join(root, "releases", bundle.ManifestSHA256)
			writeTelemetryRelease(t, release, bundle)

			called := false
			prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error {
				called = true
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err == nil {
				t.Fatalf("unsupported %s capability was accepted", capability)
			}
			if called {
				t.Fatal("OpenResty delegate ran after telemetry capability rejection")
			}
			for _, site := range manifest["sites"].([]any) {
				entry := site.(map[string]any)
				for _, name := range []string{"access_log_path", "security_log_path"} {
					if _, err := os.Stat(entry[name].(string)); !os.IsNotExist(err) {
						t.Fatalf("telemetry source was created before capability rejection: %v", err)
					}
				}
			}
		})
	}
}
