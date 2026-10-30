package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A site runtime bundle fixture (seeds deployment managers in tests) and a
// gateway client over a deployment manager whose runtime only records
// activations.

type siteRuntimeRouteDelegate struct {
	root       string
	reloads    []string
	failHealth string
}

func (runtime *siteRuntimeRouteDelegate) Precheck(_ context.Context, _ string, path string) error {
	if _, err := os.Stat(filepath.Join(path, "site-runtime.v2.json")); err != nil {
		return fmt.Errorf("site artifact is not staged: %s: %v", path, err)
	}
	return nil
}

func (runtime *siteRuntimeRouteDelegate) Reload(ctx context.Context, version, path string) error {
	if err := runtime.Precheck(ctx, version, path); err != nil {
		return err
	}
	runtime.reloads = append(runtime.reloads, version)
	return nil
}

func (runtime *siteRuntimeRouteDelegate) Healthy(_ context.Context, version string) error {
	if version == runtime.failHealth {
		return errors.New("injected site health failure")
	}
	return nil
}

type siteRuntimeRouteHarness struct {
	client  *Client
	manager *deployment.Manager
	runtime *siteRuntimeRouteDelegate
	key     ed25519.PrivateKey
	scope   string
	root    string
}

func newSiteRuntimeRouteHarnessWithCapabilities(t *testing.T, features []*agentv1.Capability) *siteRuntimeRouteHarness {
	t.Helper()
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	runtime := &siteRuntimeRouteDelegate{root: filepath.Join(root, "site-runtime")}
	managerConfig := deployment.DefaultConfig()
	managerConfig.HealthTimeout, managerConfig.HealthInterval = 50*time.Millisecond, time.Millisecond
	manager, err := deployment.NewManagerWithConfig(filepath.Join(root, "deployment"), runtime, runtime, managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": public})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "journal"))
	config.Capabilities.Features = features
	config.ArtifactDecryptionPrivateKey, config.ArtifactEncryptionKeyID = newArtifactRecipient(t)
	client, err := New(config, &failingDialer{}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return &siteRuntimeRouteHarness{client: client, manager: manager, runtime: runtime, key: key, scope: uuid.NewString(), root: root}
}

func siteRuntimeRouteBundle(t *testing.T, scope, version string, revision int) edgeconfig.Bundle {
	t.Helper()
	raw := []byte(fmt.Sprintf(`{"schema":"cdnca.edge.site-runtime/v2","configuration_scope_id":%q,"config_version_id":%q,"source_revision":%d,
"required_capabilities":[{"name":"http1","api_version":1},{"name":"ipv4","api_version":1},{"name":"site_runtime","api_version":6}],
"sites":[{"id":"11111111-1111-4111-8111-111111111111","revision":3,"domains":["route.example.test"],"listeners":[
{"id":"http","position":0,"address_family":"ipv4","port":18090,"protocols":["http1"]},
{"id":"https","position":1,"address_family":"ipv4","port":18443,"protocols":["http1"],"tls":{"certificate_version_id":"22222222-2222-4222-8222-222222222222"}}],
"origin_pools":[{"id":"primary","position":0,"kind":"origin","algorithm":"round_robin","origins":[{"id":"origin","position":0,"tier":"origin","scheme":"http","host":"127.0.0.1","port":18091,"weight":100}],
"retry":{"methods":["GET","HEAD"],"bodyless_only":true,"response_not_started":true,"retry_on":["connect_error","connect_timeout","read_timeout","http_502","http_503","http_504"],"max_attempts":3,"connect_timeout_ms":1000,"read_timeout_ms":1000,"total_budget_ms":3000}}],
"default_pool_id":"primary","websocket":false,"range":true,"l2":{"enabled":false,"probe_interval_ms":10000,"failure_threshold":3,"recovery_threshold":3,"single_half_open_probe":true,"max_hops":1}}]}`, scope, version, revision))
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatalf("invalid fixture: %v", err)
	}
	content := compact.Bytes()
	sum := sha256.Sum256(content)
	manifest := edgeconfig.Manifest{Files: []edgeconfig.FileManifest{{Path: "site-runtime.v2.json", Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}}}
	digest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return edgeconfig.Bundle{Manifest: manifest, ManifestSHA256: digest, Files: map[string][]byte{"site-runtime.v2.json": content}}
}
