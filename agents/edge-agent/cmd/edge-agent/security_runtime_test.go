package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestIndependentCCCapabilityContract(t *testing.T) {
	if got := agentv1.CapabilityName_CAPABILITY_NAME_CC.String(); got != "CAPABILITY_NAME_CC" {
		t.Fatalf("CC capability enum = %q", got)
	}
	if got := int32(agentv1.CapabilityName_CAPABILITY_NAME_CC); got != 20 {
		t.Fatalf("CC capability wire value = %d, want 20", got)
	}
	if agentv1.CapabilityName_CAPABILITY_NAME_CC == agentv1.CapabilityName_CAPABILITY_NAME_WAF {
		t.Fatal("CC capability aliases WAF")
	}
}

func TestSecurityRuntimeCapabilitiesRequireExactMountedAssetDigests(t *testing.T) {
	root := secureConfigTempDir(t)
	wafPath := filepath.Join(root, "cdnca_waf.lua")
	ccPath := filepath.Join(root, "cc.lua")
	adaptivePath := filepath.Join(root, "cc_adaptive.lua")
	write := func(path, content string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(content))
		return hex.EncodeToString(digest[:])
	}
	settings := securityRuntimeSettings{
		Enabled:   true,
		ReadyFile: filepath.Join(root, "security-runtime.ready"),
		WAF:       runtimeAssetSettings{Path: wafPath, SHA256: write(wafPath, "return {waf=true}\n")},
		CC:        runtimeAssetSettings{Path: ccPath, SHA256: write(ccPath, "return {cc=true}\n")},
		Adaptive:  runtimeAssetSettings{Path: adaptivePath, SHA256: write(adaptivePath, "return {adaptive=true}\n")},
	}
	marker, err := json.Marshal(map[string]any{
		"schema_version": "cdnca.security-runtime-ready/v1",
		"waf_sha256":     settings.WAF.SHA256, "cc_sha256": settings.CC.SHA256,
		"adaptive_sha256": settings.Adaptive.SHA256,
		"config_sha256":   strings.Repeat("0", 64),
		"cc_api_version":  2,
	})
	if err != nil || os.WriteFile(settings.ReadyFile, append(marker, '\n'), 0o444) != nil {
		t.Fatal("write security runtime ready marker")
	}
	status, err := validateSecurityRuntime(settings)
	if err != nil || !status.WAFReady || !status.CCReady {
		t.Fatalf("validateSecurityRuntime = %+v, %v", status, err)
	}
	capabilities := agentCapabilities("1.27.1", status)
	// WAF v2: challenge / ban actions, auto block, observe mode (ge-waf);
	// v3: the managed WAF's c3 context (ADR 0011 RI-03); v4: content_type /
	// http_version conditions and IP lists; v5: multipart
	// field names / part count / field length.
	if !hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, edgeconfig.WAFMultipartAPIVersion) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, edgeconfig.WAFConditionsAPIVersion) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, edgeconfig.WAFAdaptiveAPIVersion) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, 2) ||
		!hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, edgeconfig.CCAutoSwitchOverridesAPIVersion) ||
		!hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC_MATCH_KEYS, edgeconfig.CCMatchKeysAPIVersion) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 7) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 6) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 5) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 4) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 3) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 2) {
		t.Fatal("CC v8 (fix-fwregion auto switch overrides) + CC_MATCH_KEYS (fix-ja4rule count keys / JA4 match; v6 trusted crawlers, header matches, auto switch, counting keys, proof-of-work challenges) runtime capability was not advertised exactly")
	}

	stringVersion := strings.Replace(string(marker), `"cc_api_version":2`, `"cc_api_version":"2"`, 1)
	if err := os.Remove(settings.ReadyFile); err != nil ||
		os.WriteFile(settings.ReadyFile, []byte(stringVersion+"\n"), 0o444) != nil {
		t.Fatal("write string CC API version marker")
	}
	if status, err := validateSecurityRuntime(settings); err == nil || status.WAFReady || status.CCReady {
		t.Fatalf("string CC API version accepted: %+v, %v", status, err)
	}
	if err := os.Remove(settings.ReadyFile); err != nil ||
		os.WriteFile(settings.ReadyFile, append(marker, '\n'), 0o444) != nil {
		t.Fatal("restore security runtime ready marker")
	}

	settings.CC.SHA256 = settings.WAF.SHA256
	status, err = validateSecurityRuntime(settings)
	if err == nil || status.WAFReady || status.CCReady {
		t.Fatalf("digest mismatch accepted: %+v, %v", status, err)
	}
	capabilities = agentCapabilities("1.27.1", status)
	if hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, 1) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 1) {
		t.Fatal("unready security runtime capability was advertised")
	}
}

func TestSecurityRuntimeDisabledKeepsLegacyConfigAndEnrollmentTruthful(t *testing.T) {
	config := validFileConfig()
	config.SecurityRuntime = securityRuntimeSettings{}
	if _, err := config.validate(); err != nil {
		t.Fatalf("disabled security runtime rejected: %v", err)
	}
	status, err := validateSecurityRuntime(config.SecurityRuntime)
	if err != nil || status != (securityRuntimeStatus{}) {
		t.Fatalf("disabled security runtime = %+v, %v", status, err)
	}
	capabilities := agentCapabilities("1.27.1", status)
	if hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, 1) ||
		hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, 1) {
		t.Fatal("disabled security runtime was advertised")
	}
}

func TestSecurityRuntimeRejectsPartialUnsafeOrDuplicateAssets(t *testing.T) {
	root := secureConfigTempDir(t)
	asset := filepath.Join(root, "runtime.lua")
	if err := os.WriteFile(asset, []byte("return true\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("return true\n"))
	hexDigest := hex.EncodeToString(digest[:])
	tests := []struct {
		name     string
		settings securityRuntimeSettings
	}{
		{name: "partial", settings: securityRuntimeSettings{Enabled: true, WAF: runtimeAssetSettings{Path: asset, SHA256: hexDigest}}},
		{name: "relative", settings: securityRuntimeSettings{Enabled: true, WAF: runtimeAssetSettings{Path: "waf.lua", SHA256: hexDigest}, CC: runtimeAssetSettings{Path: asset, SHA256: hexDigest}, Adaptive: runtimeAssetSettings{Path: asset, SHA256: hexDigest}}},
		{name: "duplicate paths", settings: securityRuntimeSettings{Enabled: true, WAF: runtimeAssetSettings{Path: asset, SHA256: hexDigest}, CC: runtimeAssetSettings{Path: asset, SHA256: hexDigest}, Adaptive: runtimeAssetSettings{Path: asset, SHA256: hexDigest}}},
		{name: "noncanonical digest", settings: securityRuntimeSettings{Enabled: true, WAF: runtimeAssetSettings{Path: asset, SHA256: "AA" + hexDigest[2:]}, CC: runtimeAssetSettings{Path: filepath.Join(root, "cc.lua"), SHA256: hexDigest}, Adaptive: runtimeAssetSettings{Path: filepath.Join(root, "adaptive.lua"), SHA256: hexDigest}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateSecurityRuntime(test.settings); err == nil {
				t.Fatal("unsafe security runtime accepted")
			}
		})
	}
}

func TestSecurityRuntimeFileRejectsWritableHardlinkedAndSymlinkAncestorAssets(t *testing.T) {
	root := secureConfigTempDir(t)
	immutable := filepath.Join(root, "immutable.lua")
	if err := os.WriteFile(immutable, []byte("return true\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecurityRuntimeFile(immutable); err != nil {
		t.Fatalf("immutable asset rejected: %v", err)
	}
	writable := filepath.Join(root, "writable.lua")
	if err := os.WriteFile(writable, []byte("return true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecurityRuntimeFile(writable); err == nil {
		t.Fatal("writable asset accepted")
	}
	hardlink := filepath.Join(root, "hardlink.lua")
	if err := os.Link(immutable, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecurityRuntimeFile(immutable); err == nil {
		t.Fatal("hardlinked asset accepted")
	}
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(realDirectory, "asset.lua")
	if err := os.WriteFile(nested, []byte("return true\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecurityRuntimeFile(filepath.Join(linkedDirectory, "asset.lua")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func hasAgentCapability(capabilities *agentv1.AgentCapabilities, name agentv1.CapabilityName, version uint32) bool {
	for _, feature := range capabilities.GetFeatures() {
		if feature.GetName() == name && feature.GetApiVersion() == version {
			return true
		}
	}
	return false
}

// nativeSecurityFixture writes three immutable assets and a fake packaged
// OpenResty that, like the real init_by_lua self-test, compiles every file
// the generated configuration lists (luac-free: a file containing "SYNTAX
// ERROR" fails) and prints the success line.
func nativeSecurityFixture(t *testing.T) (string, string, securityRuntimeSettings) {
	t.Helper()
	root := secureConfigTempDir(t)
	asset := func(name, content string) runtimeAssetSettings {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(content))
		return runtimeAssetSettings{Path: path, SHA256: hex.EncodeToString(digest[:])}
	}
	settings := securityRuntimeSettings{Enabled: true, Mode: securityRuntimeModeNative,
		WAF: asset("cdnca_waf.lua", "return {waf=true}\n"), CC: asset("cc.lua", "return {cc=true}\n"),
		Adaptive: asset("cc_adaptive.lua", "return {adaptive=true}\n")}
	binary := filepath.Join(root, "openresty")
	script := `#!/bin/sh
[ "$1" = -p ] && [ "$3" = -c ] || exit 90
for file in $(grep -o '"/[^"]*\.lua"' "$4" | tr -d '"'); do
  [ -r "$file" ] || { echo "cdnca security self-test: cannot open $file" >&2; exit 1; }
  if grep -q 'SYNTAX ERROR' "$file"; then echo "cdnca security self-test: $file: unexpected symbol" >&2; exit 1; fi
done
echo "cdnca security self-test ok"
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, binary, settings
}

func TestNativeSecurityRuntimeDeclaresWAFAndCCAfterSelfTest(t *testing.T) {
	_, binary, settings := nativeSecurityFixture(t)
	// check-config (no OpenResty): assets verified, nothing declared yet.
	status, err := validateSecurityRuntime(settings)
	if err != nil || status != (securityRuntimeStatus{}) {
		t.Fatalf("native validateSecurityRuntime = %+v, %v", status, err)
	}
	status, err = validateNativeSecurityRuntime(t.Context(), binary, settings)
	if err != nil || !status.WAFReady || !status.CCReady {
		t.Fatalf("native self-test = %+v, %v", status, err)
	}
	capabilities := agentCapabilities("1.31.1.1", status)
	if !hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, edgeconfig.WAFNodeAPIVersion) ||
		edgeconfig.WAFNodeAPIVersion != 5 || !hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, ccAPIVersion) {
		t.Fatal("native node did not declare WAF v5 and CC")
	}
}

func TestNativeSecurityRuntimeRefusesBrokenAssets(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string, settings *securityRuntimeSettings)
		check  bool // validateSecurityRuntime (check-config) refuses too
		want   string
	}{
		{name: "digest mismatch", check: true, want: "security_runtime cc asset digest mismatch",
			mutate: func(_ *testing.T, _ string, settings *securityRuntimeSettings) {
				settings.CC.SHA256 = settings.WAF.SHA256
			}},
		{name: "missing file", check: true, want: "security_runtime adaptive asset",
			mutate: func(t *testing.T, _ string, settings *securityRuntimeSettings) {
				if err := os.Remove(settings.Adaptive.Path); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "symlink ancestor", check: true, want: "security_runtime waf asset",
			mutate: func(t *testing.T, root string, settings *securityRuntimeSettings) {
				if err := os.Symlink(root, filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
				settings.WAF.Path = filepath.Join(root, "current", "cdnca_waf.lua")
			}},
		{name: "ready file", check: true, want: "native security_runtime must not configure a ready file",
			mutate: func(_ *testing.T, root string, settings *securityRuntimeSettings) {
				settings.ReadyFile = filepath.Join(root, "ready")
			}},
		{name: "unknown mode", check: true, want: "security_runtime mode is unknown",
			mutate: func(_ *testing.T, _ string, settings *securityRuntimeSettings) { settings.Mode = "nativ" }},
		{name: "self-test fails", want: "native security self-test failed",
			mutate: func(t *testing.T, root string, settings *securityRuntimeSettings) {
				// Signed digest of a file OpenResty cannot compile.
				content := "return { SYNTAX ERROR\n"
				path := filepath.Join(root, "broken.lua")
				if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256([]byte(content))
				settings.WAF = runtimeAssetSettings{Path: path, SHA256: hex.EncodeToString(digest[:])}
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, binary, settings := nativeSecurityFixture(t)
			test.mutate(t, root, &settings)
			_, checkErr := validateSecurityRuntime(settings)
			if test.check != (checkErr != nil) || (test.check && !strings.Contains(checkErr.Error(), test.want)) {
				t.Fatalf("check-config error = %v, want refusal %v containing %q", checkErr, test.check, test.want)
			}
			status, err := validateNativeSecurityRuntime(t.Context(), binary, settings)
			if err == nil || !strings.Contains(err.Error(), test.want) || status.WAFReady || status.CCReady {
				t.Fatalf("native self-test = %+v, %v; want refusal containing %q", status, err, test.want)
			}
			capabilities := agentCapabilities("1.31.1.1", status)
			if hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF, edgeconfig.WAFNodeAPIVersion) ||
				hasAgentCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CC, ccAPIVersion) {
				t.Fatal("broken native security runtime was declared")
			}
		})
	}
}

// Real OpenResty acceptance (d7-native-waf): CDNCA_NATIVE_SECURITY_OPENRESTY
// is the packaged OpenResty binary, CDNCA_NATIVE_SECURITY_LUA the directory
// holding the shipped cdnca_waf.lua, cc.lua and cc_adaptive.lua. The real
// assets must pass the self-test; a signed-but-uncompilable copy must not.
func TestNativeSecurityRuntimeSelfTestWithRealOpenResty(t *testing.T) {
	binary, luaRoot := os.Getenv("CDNCA_NATIVE_SECURITY_OPENRESTY"), os.Getenv("CDNCA_NATIVE_SECURITY_LUA")
	if binary == "" || luaRoot == "" {
		t.Skip("set CDNCA_NATIVE_SECURITY_OPENRESTY and CDNCA_NATIVE_SECURITY_LUA to run against real OpenResty")
	}
	root := secureConfigTempDir(t)
	copyAsset := func(name string, broken bool) runtimeAssetSettings {
		content, err := os.ReadFile(filepath.Join(luaRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		if broken {
			content = append(content, []byte("\nreturn {\n")...)
		}
		path := filepath.Join(root, map[bool]string{false: "", true: "broken-"}[broken]+name)
		if err := os.WriteFile(path, content, 0o444); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		return runtimeAssetSettings{Path: path, SHA256: hex.EncodeToString(digest[:])}
	}
	settings := securityRuntimeSettings{Enabled: true, Mode: securityRuntimeModeNative,
		WAF: copyAsset("cdnca_waf.lua", false), CC: copyAsset("cc.lua", false), Adaptive: copyAsset("cc_adaptive.lua", false)}
	status, err := validateNativeSecurityRuntime(t.Context(), binary, settings)
	if err != nil || !status.WAFReady || !status.CCReady {
		t.Fatalf("real OpenResty self-test of shipped assets = %+v, %v", status, err)
	}
	t.Logf("shipped assets pass: waf %s cc %s adaptive %s", settings.WAF.SHA256, settings.CC.SHA256, settings.Adaptive.SHA256)
	settings.CC = copyAsset("cc.lua", true)
	status, err = validateNativeSecurityRuntime(t.Context(), binary, settings)
	if err == nil || status.WAFReady || status.CCReady || !strings.Contains(err.Error(), "native security self-test failed") {
		t.Fatalf("real OpenResty accepted an uncompilable asset: %+v, %v", status, err)
	}
	t.Logf("broken asset refused: %v", err)
}
