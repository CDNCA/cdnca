package main

// Edge-agent half of tests/dynroute-e2e/run.sh (D13-a3b ③, F1 S2), run inside the node runtime image
// (cdnca-native-runtime:edge-golden: OpenResty and the node Lua). It is the daemon's dynamic routing node wiring:
// object store, rule pack vault (opened with the node's enrolled artifact key), assembleDynamicRouting with the
// rule pack precheck plans, newDynamicRoutingManager, the node artifact set runtime (rule pack items, Reapply when
// packs change) and the production gateway client over mTLS (WithSiteObjectStore, WithDynamicRouting,
// WithArtifactSetRuntime, WithCertificateConsumer, cache tasks on the dynamic routing runtime). It declares what a
// dynamic routing node declares: the agent's capabilities with site_runtime 9.
//
// HTTP for the control half (published port): GET /state (artifact set revision, rule pack items, scopes),
// GET /get?host=&path= (one request to the node runtime's site port inside the container), POST /done.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/installationban"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackprecheck"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/google/uuid"
)

// Fixed in the control half (services/control-api/cmd/control-api/dynroute_e2e_test.go).
const (
	dynRouteE2ESitePort   = 18480
	dynRouteE2EOriginPort = 19480
)

type dynRouteNoCertificateRuntime struct{}

func (dynRouteNoCertificateRuntime) Precheck(context.Context, string) error { return nil }
func (dynRouteNoCertificateRuntime) Activate(context.Context, string) error { return nil }
func (dynRouteNoCertificateRuntime) Healthy(context.Context, []certstore.HealthTarget) error {
	return nil
}
func (dynRouteNoCertificateRuntime) Stop(context.Context, string) error { return nil }

func TestDynRouteAgentProcess(t *testing.T) {
	directory := os.Getenv("DYNROUTE_E2E_DIR")
	if directory == "" {
		t.Skip("DYNROUTE_E2E_DIR is not set; run tests/dynroute-e2e/run.sh")
	}
	// The node Lua tree is at the daemon's /usr/local/share/cdnca (run.sh mounts the repository's copy there).
	binary, listen := os.Getenv("DYNROUTE_E2E_OPENRESTY"), os.Getenv("DYNROUTE_E2E_AGENT_LISTEN")
	gatewayHost := os.Getenv("DYNROUTE_E2E_GATEWAY_HOST")
	if binary == "" || listen == "" {
		t.Skip("DYNROUTE_E2E_OPENRESTY and DYNROUTE_E2E_AGENT_LISTEN are required (inside the node runtime image)")
	}
	// The container's own state lives outside the shared directory (the node runtime's workers must traverse it).
	stateRoot := os.Getenv("DYNROUTE_E2E_STATE")
	if stateRoot == "" {
		stateRoot = t.TempDir()
	}
	// Traversable by the workers (the dynamic routing state is below it); secrets go to the owner-only identity dir.
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(stateRoot, "identity")
	var gateway artifactSetGatewayFixture
	waitJSON(t, filepath.Join(directory, "gateway.json"), &gateway)
	if gatewayHost != "" {
		// The gateway listens on every address of the host; the container reaches it by name.
		_, port, err := net.SplitHostPort(gateway.Address)
		if err != nil {
			t.Fatal(err)
		}
		gateway.Address = net.JoinHostPort(gatewayHost, port)
	}
	var control struct {
		TrustFile             string `json:"trust_file"`
		ArtifactKeyID         string `json:"artifact_key_id"`
		ArtifactPrivateKeyHex string `json:"artifact_private_key_file"`
	}
	waitJSON(t, filepath.Join(directory, "control.json"), &control)
	trust, err := gatewayclient.LoadTrustStore(copyOwnerOnly(t, control.TrustFile, filepath.Join(identity, "trust.json"), 0o400))
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := os.ReadFile(control.ArtifactPrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	artifactKey, err := hex.DecodeString(strings.TrimSpace(string(encodedKey)))
	if err != nil {
		t.Fatal(err)
	}

	deploymentRoot := filepath.Join(stateRoot, "deployments")
	if err := os.MkdirAll(deploymentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	// The image's worker group: nobody, or nogroup on Debian bases (dynamic_routing.worker_group).
	workerGroup := "nobody"
	if group := os.Getenv("DYNROUTE_E2E_WORKER_GROUP"); group != "" {
		workerGroup = group
	}
	gid, err := lookupWorkerGID(workerGroup)
	if err != nil {
		workerGroup = "nogroup"
		if gid, err = lookupWorkerGID(workerGroup); err != nil {
			t.Fatal(err)
		}
	}
	packRuntime := rulePackRuntimeRoot // tmpfs in the container (run.sh --tmpfs /run/cdnca)
	if root := os.Getenv("DYNROUTE_E2E_RULEPACK_RUNTIME"); root != "" {
		packRuntime = root
	}
	objects, err := openObjectStore(fileConfig{DeploymentRoot: deploymentRoot, DynamicRouting: dynamicRoutingSettings{Enabled: true, WorkerGroup: workerGroup}})
	if err != nil {
		t.Fatal(err)
	}
	vault, err := openRulePackVault(deploymentRoot, artifactKey, objects, packRuntime, gid)
	if err != nil || vault == nil {
		t.Fatalf("rule pack vault: %v", err)
	}
	certificates, err := certstore.NewManager(certstore.RuntimeConfig{StateRoot: filepath.Join(stateRoot, "certificates"),
		ListenAddress: "127.0.0.1", ListenPort: 18443}, dynRouteNoCertificateRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	config := fileConfig{DeploymentRoot: deploymentRoot, OpenResty: openRestySettings{Binary: binary, HealthURL: "http://127.0.0.1:18080/healthz"},
		DynamicRouting: dynamicRoutingSettings{Enabled: true, WorkerGroup: workerGroup}}
	// tests/telemetry-e2e: the daemon's telemetry pipeline (install-node.sh enables it).
	telemetryE2E := os.Getenv("DYNROUTE_E2E_TELEMETRY") == "1"
	if telemetryE2E {
		config.Telemetry = defaultFileConfig().Telemetry
		config.Telemetry.Enabled, config.Telemetry.SpoolRoot = true, filepath.Join(stateRoot, "event-spool")
	}
	runtime, err := assembleDynamicRouting(config, gateway.NodeID, certificates, nil, 20*time.Second, nil, rulepackprecheck.Plans{Vault: vault}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = runtime.Run(ctx, dynroute.DefaultIntervals) }()
	state, _ := dynamicRoutingRoots(config)
	manager, err := newDynamicRoutingManager(runtime, objects, filepath.Join(state, "scopes"))
	if err != nil {
		t.Fatal(err)
	}
	artifactSets, err := assembleArtifactSetRuntime(deploymentRoot, gateway.NodeID, objects, nil, manager.Reapply, vault)
	if err != nil {
		t.Fatal(err)
	}
	artifactSets.rulePacksChanged = manager.Reapply

	dialer, err := gatewayclient.NewMTLSDialer(gatewayclient.MTLSDialerConfig{Address: gateway.Address,
		ServerName: gateway.ServerName, RootCAFile: copyOwnerOnly(t, gateway.RootCAFile, filepath.Join(identity, "ca.pem"), 0o600),
		ClientCertificateFile: copyOwnerOnly(t, gateway.ClientCertificateFile, filepath.Join(identity, "node.pem"), 0o600),
		ClientPrivateKeyFile:  copyOwnerOnly(t, gateway.ClientPrivateKeyFile, filepath.Join(identity, "node-key.pem"), 0o600),
		MaximumReceiveBytes:   8 << 20, MaximumSendBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(stateRoot, "journal")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	clientConfig := gatewayclient.DefaultConfig()
	clientConfig.NodeID, clientConfig.BootID = gateway.NodeID, uuid.NewString()
	clientConfig.ArtifactEncryptionKeyID, clientConfig.ArtifactDecryptionPrivateKey = control.ArtifactKeyID, artifactKey
	clientConfig.JournalDir = journal
	clientConfig.Capabilities = agentCapabilitiesWithFirewall("", false, securityRuntimeStatus{WAFReady: true, CCReady: true})
	clientConfig.Capabilities.AgentVersion, clientConfig.Capabilities.BuildId = "1.0.35-e2e", "dynroute-e2e"
	declareSiteRuntimeVersion(clientConfig.Capabilities, edgeconfig.DynamicRoutingSiteRuntimeVersion)
	addHTTPProtocolCapabilities(clientConfig.Capabilities, true, false)
	clientConfig.InitialBackoff, clientConfig.MaximumBackoff = 100*time.Millisecond, time.Second
	options := []gatewayclient.ClientOption{
		gatewayclient.WithSiteObjectStore(objects), gatewayclient.WithCertificateConsumer(certificates),
		gatewayclient.WithCacheTaskManager(dynroute.CacheTasks{Runtime: runtime}),
		gatewayclient.WithArtifactSetRuntime(artifactSets), gatewayclient.WithDynamicRouting(manager)}
	// tests/license-ban-e2e (ADR 0014 LIC-BAN-07): the daemon's installation ban wiring (daemon.go
	// assembleInstallationBan + signer trust runtime), with the scenario's injected clock.
	var ban *installationban.Runtime
	if installation := os.Getenv("DYNROUTE_E2E_INSTALLATION_ID"); installation != "" {
		signerTrust, err := gatewayclient.NewSignerTrustRuntime(filepath.Join(journal, "signer-trust"), gateway.NodeID,
			trust, licenseBanE2EClock)
		if err != nil {
			t.Fatal(err)
		}
		// The node signer trust document naming the license key (usage installation-ban), as the installer
		// requires it before the first ticket (install-node.sh require_installation_ban_trust): the control half's
		// bundle of the offline-signed document, applied once like a pushed one.
		bundle, err := os.ReadFile(filepath.Join(directory, "signer-trust-bundle.json"))
		if err != nil {
			t.Fatal(err)
		}
		if receipt := signerTrust.Apply(bundle); receipt.Result != "applied" || len(trust.InstallationBanKeys()) != 1 {
			t.Fatalf("signer trust bundle: %+v, installation-ban keys %d", receipt, len(trust.InstallationBanKeys()))
		}
		ban, err = assembleInstallationBanWithClock(fileConfig{JournalDir: journal,
			Upgrade: upgradeSettings{InstallationID: installation}}, runtime, manager, trust, licenseBanE2EClock)
		if err != nil || ban == nil {
			t.Fatalf("installation ban runtime: %v", err)
		}
		if err := ban.Restore(ctx); err != nil {
			t.Fatal(err)
		}
		go runInstallationBanTicksEvery(ctx, ban, time.Second)
		options = append(options, gatewayclient.WithSignerTrustRuntime(signerTrust),
			gatewayclient.WithInstallationBan(failingInstallationBanAgent{inner: installationBanAgent{runtime: ban}}))
	}
	// tests/dynroute-e2e DYNROUTE_E2E_SITE_DROP=1 (攻击自动升级 D 级): the daemon's site drop wiring — runtime over
	// the dynamic routing sites, executor from newKernelSiteDropExecutor with the OpenResty control socket (no
	// XDP, no nftables in the unprivileged container: the shared plain port is closed by OpenResty 444).
	if os.Getenv("DYNROUTE_E2E_SITE_DROP") == "1" {
		executor := newKernelSiteDropExecutor(nil, nil, filepath.Join(state, edgeskeleton.ControlSocket))
		siteDrop := newSiteDropRuntime(gateway.NodeID, trust.Ed25519Key, runtime.RunningSites, func() bool { return false },
			executor, time.Now)
		if siteDrop == nil {
			t.Fatal("site drop runtime not built")
		}
		options = append(options, gatewayclient.WithSiteDrop(siteDrop))
	}
	client, err := gatewayclient.New(clientConfig, dialer, manager, trust, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var telemetry *telemetryE2EAgent
	if telemetryE2E {
		telemetry = startTelemetryE2EAgent(t, ctx, config, gateway, identity, runtime, manager)
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()

	origin, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(dynRouteE2EOriginPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = http.Serve(origin, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			fmt.Fprintf(writer, "origin %s %s", request.Host, request.URL.Path)
		}))
	}()

	done := make(chan struct{})
	handler := http.NewServeMux()
	handler.HandleFunc("/done", func(response http.ResponseWriter, _ *http.Request) {
		select {
		case <-done:
		default:
			close(done)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/get", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(dynRouteGet(request.URL.Query().Get("host"), request.URL.Query().Get("path")))
	})
	// /debug: the node runtime's error.log tail and the modes of the dynamic routing state (failure diagnosis).
	handler.HandleFunc("/debug", func(response http.ResponseWriter, _ *http.Request) {
		shared := filepath.Join(filepath.Dir(state), "shared")
		var report strings.Builder
		_ = filepath.Walk(filepath.Dir(state), func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() && strings.Count(strings.TrimPrefix(path, filepath.Dir(state)), "/") <= 2 {
				fmt.Fprintf(&report, "%s %s\n", info.Mode(), path)
			}
			return nil
		})
		if log, err := os.ReadFile(filepath.Join(shared, "error.log")); err == nil {
			if len(log) > 6000 {
				log = log[len(log)-6000:]
			}
			report.Write(log)
		}
		_, _ = io.WriteString(response, report.String())
	})
	// /ban (tests/license-ban-e2e): the enforced installation ban status and signer trust revision.
	handler.HandleFunc("/clock", func(response http.ResponseWriter, request *http.Request) {
		offset, err := strconv.ParseInt(request.URL.Query().Get("offset"), 10, 64)
		if err != nil || request.Method != http.MethodPost {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		licenseBanE2EOffset.Store(offset)
		if ban != nil {
			_, _ = ban.Tick(ctx)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	// /fail?count=N (tests/license-ban-e2e ⑦): the next N installation ban commands answer persistence_failed
	// without applying, as installationban.Runtime.Apply does when state.json cannot be written.
	handler.HandleFunc("/fail", func(response http.ResponseWriter, request *http.Request) {
		count, err := strconv.ParseInt(request.URL.Query().Get("count"), 10, 32)
		if err != nil || count < 0 || request.Method != http.MethodPost {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		licenseBanE2EFailures.Store(int32(count))
		response.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/ban", func(response http.ResponseWriter, _ *http.Request) {
		value := map[string]any{"enabled": ban != nil, "signer_trust_revision": trust.SignerTrustRevision(),
			"installation_ban_keys": len(trust.InstallationBanKeys()), "clock_offset": licenseBanE2EOffset.Load(),
			"pending_failures": licenseBanE2EFailures.Load()}
		if ban != nil {
			value["status"] = string(ban.Status())
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(value)
	})
	handler.HandleFunc("/state", func(response http.ResponseWriter, _ *http.Request) {
		value := map[string]any{"artifact_set_revision": 0, "rule_packs": []string{}, "scopes": manager.Scopes()}
		if active := artifactSets.executor.Active(); active != nil {
			value["artifact_set_revision"] = active.Revision
			packs := []string{}
			for _, item := range active.Items {
				if item.MediaType == artifactset.MediaTypeRulePack {
					packs = append(packs, item.SHA256)
				}
			}
			value["rule_packs"] = packs
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(value)
	})
	if telemetry != nil {
		telemetry.register(handler)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	encoded, _ := json.Marshal(map[string]bool{"ready": true})
	// 0644: the agent runs as root in its container and the control process
	// reads this from the host as another user (Linux bind mounts keep the uid).
	if err := os.WriteFile(filepath.Join(directory, "agent.json.tmp"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "agent.json.tmp"), filepath.Join(directory, "agent.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("dynamic routing agent for node %s against %s, control HTTP on %s", gateway.NodeID, gateway.Address, listen)
	select {
	case <-done:
	case err := <-clientDone:
		t.Fatalf("gateway client stopped: %v", err)
	case <-time.After(45 * time.Minute):
		t.Fatal("control half did not finish")
	}
	_ = runtime.Stop(context.Background())
}

type dynRouteAnswer struct {
	Status     int    `json:"status"`
	Body       string `json:"body"`
	RetryAfter string `json:"retry_after,omitempty"`
	Error      string `json:"error,omitempty"`
}

// licenseBanE2EOffset is the scenario's clock offset in seconds (tests/license-ban-e2e): the control half sets it
// over POST /clock (a file in the shared directory can be served stale by the container's bind mount).
var licenseBanE2EOffset atomic.Int64

func licenseBanE2EClock() time.Time {
	return time.Now().Add(time.Duration(licenseBanE2EOffset.Load()) * time.Second)
}

func dynRouteGet(host, path string) dynRouteAnswer {
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", dynRouteE2ESitePort, path), nil)
	if err != nil {
		return dynRouteAnswer{Error: err.Error()}
	}
	request.Host = host
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return dynRouteAnswer{Error: err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return dynRouteAnswer{Status: response.StatusCode, Body: string(body), RetryAfter: response.Header.Get("Retry-After")}
}

// copyOwnerOnly copies a file of the shared directory (bind mount: other owner, other modes) to path with mode,
// the owner-only files the gateway client requires.
func copyOwnerOnly(t *testing.T, from, path string, mode os.FileMode) string {
	t.Helper()
	content, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// licenseBanE2EFailures: installation ban commands still to refuse with persistence_failed (/fail).
var licenseBanE2EFailures atomic.Int32

type failingInstallationBanAgent struct{ inner installationBanAgent }

func (agent failingInstallationBanAgent) ApplyInstallationBan(ctx context.Context, notice, ticket []byte) gatewayclient.InstallationBanResult {
	for {
		left := licenseBanE2EFailures.Load()
		if left <= 0 {
			return agent.inner.ApplyInstallationBan(ctx, notice, ticket)
		}
		if licenseBanE2EFailures.CompareAndSwap(left, left-1) {
			result := gatewayclient.InstallationBanResult{Status: string(agent.inner.runtime.Status()),
				Reason: installationban.ReasonPersistence}
			if held := agent.inner.runtime.Ticket(); held != nil {
				result.TicketIssuedAt, result.TicketNotAfter = time.Unix(held.IssuedAt, 0).UTC(), time.Unix(held.NotAfter, 0).UTC()
			}
			return result
		}
	}
}
