//go:build scale

// G8-a 规模基准（主控侧）。只在 tests/scale/run.sh 用 -tags scale 调起。
// 不连数据库：按 compileSiteRuntimeV2Facts（site_runtime_v2.go:215-339）
// 在取完事实之后的纯计算部分逐步执行——规范化校验、遥测清单、bundle 封装、
// 每节点 HPKE 加密签名——记录耗时、内存、产物大小，并对照现有上限
// （bundle ≤4 MiB、单发布全部产物 ≤16 MiB 且 ≤128 个）。
//
//	CDNCA_SCALE_SITES  逗号分隔的单文档站点数，默认 1000
//	CDNCA_SCALE_NODES  每次发布的目标节点数，默认 1,5,20
//	CDNCA_SCALE_OUT    结果 JSON 追加写入的文件（必填）
package edgepublish

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type controlScaleResult struct {
	Sites                   int      `json:"sites"`
	Nodes                   int      `json:"nodes"`
	CanonicalBytes          int      `json:"canonical_bytes"`
	TelemetryManifestBytes  int      `json:"telemetry_manifest_bytes"`
	WireBytes               int      `json:"wire_bytes"`
	ArtifactBytesEach       int      `json:"artifact_bytes_each"`
	ArtifactBytesTotal      int      `json:"artifact_bytes_total"`
	CanonicalizeCPU         float64  `json:"canonicalize_cpu_seconds"`
	TelemetryCPU            float64  `json:"telemetry_cpu_seconds"`
	MarshalCPU              float64  `json:"marshal_cpu_seconds"`
	EncryptCPUPerNode       float64  `json:"encrypt_sign_cpu_seconds_per_node"`
	TotalCPU                float64  `json:"total_cpu_seconds"`
	TotalSeconds            float64  `json:"total_seconds"`
	AllocMiB                float64  `json:"alloc_mib"`
	Listeners               int      `json:"listeners"`
	TelemetryMultiDomainErr string   `json:"telemetry_multi_domain_error,omitempty"`
	LimitErrors             []string `json:"limit_errors,omitempty"`
	Error                   string   `json:"error,omitempty"`
}

func controlCPUSeconds() float64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}

func controlScaleInts(t *testing.T, name string, fallback []int) []int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	var values []int
	for _, field := range strings.Split(raw, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || value < 1 {
			t.Fatalf("invalid %s %q", name, raw)
		}
		values = append(values, value)
	}
	return values
}

// controlScaleDocument 与节点基准（agents/edge-agent/internal/siteruntimev2/scale_benchmark_test.go）
// 生成同形站点：一半 HTTPS、1/3 三个域名、30% 监听 ACL、10% 站点 80 端口 CC v2、1/4 两个源站。
func controlScaleDocument(t *testing.T, scopeID, configID uuid.UUID, count int) siteRuntimeV2Document {
	t.Helper()
	trueValue, falseValue := true, false
	required := map[string]uint32{"http1": 1, "ipv4": 1, "ipv6": 1, "site_runtime": 2, "websocket": 1}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: 1,
		ConfigVersionID: configID.String(), Sites: make([]siteRuntimeV2Site, 0, count),
	}
	for index := 0; index < count; index++ {
		siteID := fmt.Sprintf("%08x-0000-4000-8000-%012x", index, index)
		base := fmt.Sprintf("s%07d.scale.example", index)
		domains := []string{base}
		if index%3 == 0 {
			domains = []string{base, "static." + base, "www." + base}
		}
		site := siteRuntimeV2Site{
			ID: siteID, Revision: 1, Domains: domains, DefaultPoolID: "primary",
			WebSocket: &trueValue, Range: &trueValue,
			L2: siteRuntimeV2L2Policy{Enabled: &falseValue, ProbeIntervalMS: 10000, FailureThreshold: 3,
				RecoveryThreshold: 3, SingleHalfOpenProbe: &trueValue, MaxHops: 1},
		}
		ports := []int{80}
		if index%2 == 0 {
			ports = append(ports, 443)
			required["http2"], required["http3"] = 1, 1
		}
		for position, port := range ports {
			listener := siteRuntimeV2Listener{ID: "public-" + strconv.Itoa(port), Position: int64(position),
				AddressFamily: "dual_stack", Port: int64(port), Protocols: []string{"http1"}}
			if port == 443 {
				listener.Protocols = []string{"http1", "http2", "http3"}
				listener.TLS = &siteRuntimeV2ListenerTLS{
					CertificateVersionID: fmt.Sprintf("ce000000-%04x-4000-8000-%012x", index%0xffff, index),
					Protocols:            []string{"TLSv1.2", "TLSv1.3"},
				}
			}
			security := edgeconfig.ListenerSecurity{}
			if (index*3+position)%10 < 3 {
				security.Policies = []edgeconfig.SecurityPolicy{{
					Kind: edgeconfig.SecurityACL, PolicyID: "ac100000-0000-4000-8000-000000000001",
					PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: strings.Repeat("0", 64),
					Enabled: true, DefaultAction: edgeconfig.WAFAllow,
					Rules: []edgeconfig.WAFRule{{RuleID: "ac100000-0000-4000-8000-000000000002",
						Match: edgeconfig.WAFMatch{SourceCIDR: "198.51.100.0/24"}, Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFContinue}},
				}}
				required["waf"] = 1
			}
			if position == 0 && (index*7)%1000 < 100 {
				security.CC = controlScaleCC(t, scopeID.String(), siteID)
				required["cc"] = 2
			}
			if security.CC != nil || len(security.Policies) != 0 {
				listener.Security = &security
				required["site_runtime"] = 4
			}
			site.Listeners = append(site.Listeners, listener)
		}
		retry := siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: &trueValue, ResponseNotStarted: &trueValue,
			RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
			MaxAttempts: 2, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 60000}
		pool := siteRuntimeV2OriginPool{ID: "primary", Kind: "origin", Algorithm: "round_robin", Retry: retry,
			Origins: []siteRuntimeV2Origin{{ID: "origin-0", Tier: "origin", Scheme: "http", Host: "127.0.0.1", Port: 19001, Weight: 100}}}
		if index%4 == 0 {
			pool.Origins = append(pool.Origins, siteRuntimeV2Origin{ID: "origin-1", Position: 1, Tier: "origin", Scheme: "http", Host: "127.0.0.1", Port: 19002, Weight: 50})
		}
		site.OriginPools = []siteRuntimeV2OriginPool{pool}
		document.Sites = append(document.Sites, site)
	}
	for _, name := range []string{"cc", "http1", "http2", "http3", "ipv4", "ipv6", "site_runtime", "waf", "websocket"} {
		if version, ok := required[name]; ok {
			document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: version})
		}
	}
	return document
}

func controlScaleCC(t *testing.T, scopeID, siteID string) *edgeconfig.CCV2SiteBinding {
	t.Helper()
	policy := edgeconfig.CCV2Policy{
		SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: scopeID, SiteID: siteID,
		PolicyID: "cc200000-0000-4000-8000-000000000001", PolicyVersion: 1,
		BindingID: "cc200000-0000-4000-8000-000000000002", BindingRevision: 1,
		PublicationID: "cc200000-0000-4000-8000-000000000003", Enabled: true,
		TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []edgeconfig.CCV2Rule{{
			RuleID: "cc200000-0000-4000-8000-000000000004", Priority: 10, Flow: edgeconfig.CCV2FlowStop,
			Match:     edgeconfig.CCV2Match{Path: &edgeconfig.CCV2PathMatch{Kind: edgeconfig.CCV2PathPrefix, Value: "/limited"}},
			Dimension: edgeconfig.CCV2DimensionClientIP,
			Limit:     edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow, Requests: 2, WindowSeconds: 60},
			Action:    edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionTemporaryBan, BanSeconds: 120},
		}},
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return &edgeconfig.CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: hex.EncodeToString(digest[:]), Policy: policy}
}

// singleDomainCopy 只保留每站第一个域名：遥测清单当前拒绝多域名站点
// （site_capture_policy.go:137），基准用它测出遥测部分的开销，并单独报告多域名失败。
func singleDomainCopy(document siteRuntimeV2Document) siteRuntimeV2Document {
	copy := document
	copy.Sites = make([]siteRuntimeV2Site, len(document.Sites))
	for index, site := range document.Sites {
		site.Domains = site.Domains[:1]
		copy.Sites[index] = site
	}
	return copy
}

func TestScaleControlCompile(t *testing.T) {
	out := os.Getenv("CDNCA_SCALE_OUT")
	if out == "" {
		t.Skip("CDNCA_SCALE_OUT is required")
	}
	signer := newUnitConfigurationArtifactSigner(t)
	producer, err := newConfigurationArtifactProducer(signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, tenantID, installationID := uuid.New(), uuid.New(), uuid.New()
	for _, count := range controlScaleInts(t, "CDNCA_SCALE_SITES", []int{1000}) {
		for _, nodes := range controlScaleInts(t, "CDNCA_SCALE_NODES", []int{1, 5, 20}) {
			result := runControlScaleCase(t, producer, scopeID, tenantID, installationID, count, nodes)
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(append(encoded, '\n'))
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s", encoded)
		}
	}
}

func runControlScaleCase(t *testing.T, producer *configurationArtifactProducer, scopeID, tenantID, installationID uuid.UUID, count, nodes int) (result controlScaleResult) {
	t.Helper()
	result = controlScaleResult{Sites: count, Nodes: nodes}
	configID := uuid.New()
	document := controlScaleDocument(t, scopeID, configID, count)
	for _, site := range document.Sites {
		result.Listeners += len(site.Listeners)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started, cpu := time.Now(), controlCPUSeconds()
	defer func() {
		result.TotalSeconds = time.Since(started).Seconds()
		result.TotalCPU = controlCPUSeconds() - cpu
		runtime.ReadMemStats(&after)
		result.AllocMiB = float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	}()

	// compileSiteRuntimeV2Facts:305-312：Marshal → compileSiteRuntimeV2Document（解析、规范化、校验，含 1000 站上限）。
	step := controlCPUSeconds()
	raw, err := json.Marshal(document)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	result.CanonicalizeCPU = controlCPUSeconds() - step
	if err != nil {
		result.Error = "compileSiteRuntimeV2Document: " + err.Error()
		return result
	}
	result.CanonicalBytes = len(canonical)

	// :289-293 遥测身份清单。多域名站点曾在此失败（G8-a 缺陷 3，g8-fix 已修）；仍失败时记录并改用单域名副本继续。
	step = controlCPUSeconds()
	stateRoot := "/var/lib/cdnca-edge"
	manifest, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, installationID, configID, 1, document, nil, nil, noAccessLogFields, stateRoot)
	if err != nil {
		result.TelemetryMultiDomainErr = err.Error()
		manifest, err = buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, installationID, configID, 1, singleDomainCopy(document), nil, nil, noAccessLogFields, stateRoot)
	}
	result.TelemetryCPU = controlCPUSeconds() - step
	if err != nil {
		result.Error = "telemetry manifest: " + err.Error()
		return result
	}
	result.TelemetryManifestBytes = len(manifest)

	// :326-328 封装 bundle（含 edgeconfig.MarshalBundle 的 4 MiB 上限，bundle.go:128）。
	step = controlCPUSeconds()
	wire, err := marshalSiteRuntimeV2BundleWithPolicies(canonical, nil, nil, nil, nil, manifest)
	result.MarshalCPU = controlCPUSeconds() - step
	if err != nil {
		result.Error = "marshal bundle: " + err.Error()
		return result
	}
	result.WireBytes = len(wire)

	// service.go:610-622 每个节点各加密签名一次。
	step = controlCPUSeconds()
	artifacts := make([]edgedeployment.ArtifactInput, nodes)
	for index := range artifacts {
		binding, publicKey, _ := newUnitConfigurationArtifactBinding(t, configID)
		artifacts[index], err = producer.Build(context.Background(), binding, publicKey, wire, siteobject.KeyMediaType)
		if err != nil {
			result.Error = "artifact build: " + err.Error()
			return result
		}
		result.ArtifactBytesTotal += len(artifacts[index].WireBytes)
	}
	result.EncryptCPUPerNode = (controlCPUSeconds() - step) / float64(nodes)
	result.ArtifactBytesEach = len(artifacts[0].WireBytes)
	// edgedeployment/validate.go:32-35,163：单产物 ≤4 MiB、单发布 ≤128 个且合计 ≤16 MiB。
	if result.ArtifactBytesEach > 4<<20 {
		result.LimitErrors = append(result.LimitErrors, "artifact exceeds maxArtifactWireBytes 4 MiB")
	}
	if nodes > 128 {
		result.LimitErrors = append(result.LimitErrors, "artifacts exceed maxConfigArtifacts 128")
	}
	if result.ArtifactBytesTotal > 16<<20 {
		result.LimitErrors = append(result.LimitErrors, "artifacts exceed maxConfigArtifactBytes 16 MiB")
	}
	return result
}

// TestScaleControlCeiling 找出现状下单个配置 scope 能发布的最大站点数（同形站点、单域名），
// 即 1000 站上限、遥测清单 1000 条/1 MiB（libs/edgeconfig/telemetry.go:96,104）、
// bundle 4 MiB（bundle.go:128）里最先触发的那个。
func TestScaleControlCeiling(t *testing.T) {
	out := os.Getenv("CDNCA_SCALE_OUT")
	if out == "" {
		t.Skip("CDNCA_SCALE_OUT is required")
	}
	signer := newUnitConfigurationArtifactSigner(t)
	producer, err := newConfigurationArtifactProducer(signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, tenantID, installationID := uuid.New(), uuid.New(), uuid.New()
	ok := func(count int) controlScaleResult {
		result := runControlScaleCase(t, producer, scopeID, tenantID, installationID, count, 1)
		return result
	}
	low, high := 1, 1001
	for high-low > 1 {
		middle := (low + high) / 2
		if result := ok(middle); result.Error == "" {
			low = middle
		} else {
			high = middle
		}
	}
	last, first := ok(low), ok(high)
	encoded, err := json.Marshal(map[string]any{"ceiling_sites": low, "at_ceiling": last, "first_failure": first})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", encoded)
}
