package main

// security_runtime: the node's mounted WAF/CC Lua assets and the runtime's
// ready marker gate whether the WAF and CC capabilities are declared. (The
// site runtime v2 release carries its listener security itself; the v1
// security provenance precheck is gone with the v1 bundle.)

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const maxSecurityRuntimeFileBytes = 1 << 20

type runtimeAssetSettings struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// securityRuntimeModeNative: the installed native node (dynamic routing). No
// runtime entrypoint writes a ready marker there (the Agent starts OpenResty
// itself); the Agent loads the assets with the packaged OpenResty at start
// instead (validateNativeSecurityRuntime).
const securityRuntimeModeNative = "native"

type securityRuntimeSettings struct {
	Enabled bool `json:"enabled"`
	// Mode "" is the container runtime (ready marker from entrypoint.sh);
	// "native" carries no ready_file.
	Mode      string               `json:"mode,omitempty"`
	ReadyFile string               `json:"ready_file,omitempty"`
	WAF       runtimeAssetSettings `json:"waf"`
	CC        runtimeAssetSettings `json:"cc"`
	Adaptive  runtimeAssetSettings `json:"adaptive"`
}

type securityRuntimeStatus struct {
	WAFReady bool
	CCReady  bool
}

func validateSecurityRuntime(settings securityRuntimeSettings) (securityRuntimeStatus, error) {
	if !settings.Enabled {
		if settings.Mode != "" || settings.ReadyFile != "" || settings.WAF != (runtimeAssetSettings{}) ||
			settings.CC != (runtimeAssetSettings{}) || settings.Adaptive != (runtimeAssetSettings{}) {
			return securityRuntimeStatus{}, errors.New("disabled security_runtime must not configure assets")
		}
		return securityRuntimeStatus{}, nil
	}
	switch settings.Mode {
	case "":
	case securityRuntimeModeNative:
		if settings.ReadyFile != "" {
			return securityRuntimeStatus{}, errors.New("native security_runtime must not configure a ready file")
		}
	default:
		return securityRuntimeStatus{}, errors.New("security_runtime mode is unknown")
	}
	if err := validateSecurityRuntimeAssets(settings); err != nil {
		return securityRuntimeStatus{}, err
	}
	if settings.Mode == securityRuntimeModeNative {
		// Assets verified. Readiness needs the load self-test, which runs once
		// at daemon start (validateNativeSecurityRuntime), not on check-config.
		return securityRuntimeStatus{}, nil
	}
	return validateSecurityRuntimeMarker(settings)
}

// validateSecurityRuntimeAssets checks the three assets' paths (absolute,
// distinct, no symlink ancestor) and their exact digests.
func validateSecurityRuntimeAssets(settings securityRuntimeSettings) error {
	assets := []struct {
		name  string
		asset runtimeAssetSettings
	}{{"waf", settings.WAF}, {"cc", settings.CC}, {"adaptive", settings.Adaptive}}
	seen := make(map[string]struct{}, len(assets))
	for _, entry := range assets {
		asset := entry.asset
		if !absoluteCleanPath(asset.Path) || asset.Path == string(filepath.Separator) ||
			len(asset.SHA256) != sha256.Size*2 || strings.ToLower(asset.SHA256) != asset.SHA256 {
			return fmt.Errorf("security_runtime %s asset identity is invalid", entry.name)
		}
		if _, err := hex.DecodeString(asset.SHA256); err != nil {
			return fmt.Errorf("security_runtime %s asset digest is invalid", entry.name)
		}
		if _, duplicate := seen[asset.Path]; duplicate {
			return errors.New("security_runtime asset paths must be distinct")
		}
		seen[asset.Path] = struct{}{}
		content, err := readSecurityRuntimeFile(asset.Path)
		if err != nil {
			return fmt.Errorf("security_runtime %s asset %s: %w", entry.name, asset.Path, err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != asset.SHA256 {
			return fmt.Errorf("security_runtime %s asset digest mismatch: %s", entry.name, asset.Path)
		}
	}
	return nil
}

func validateSecurityRuntimeMarker(settings securityRuntimeSettings) (securityRuntimeStatus, error) {
	if !absoluteCleanPath(settings.ReadyFile) || settings.ReadyFile == string(filepath.Separator) {
		return securityRuntimeStatus{}, errors.New("security_runtime ready file is invalid")
	}
	markerBytes, err := readSecurityRuntimeFile(settings.ReadyFile)
	if err != nil || edgeconfig.RejectDuplicateJSONKeys(markerBytes) != nil {
		return securityRuntimeStatus{}, errors.New("security_runtime ready marker is invalid")
	}
	var marker struct {
		SchemaVersion  string `json:"schema_version"`
		WAFSHA256      string `json:"waf_sha256"`
		CCSHA256       string `json:"cc_sha256"`
		AdaptiveSHA256 string `json:"adaptive_sha256"`
		ConfigSHA256   string `json:"config_sha256"`
		CCAPIVersion   uint32 `json:"cc_api_version"`
	}
	if err := strictSecurityJSON(markerBytes, &marker); err != nil ||
		marker.SchemaVersion != "cdnca.security-runtime-ready/v1" ||
		marker.WAFSHA256 != settings.WAF.SHA256 || marker.CCSHA256 != settings.CC.SHA256 ||
		marker.AdaptiveSHA256 != settings.Adaptive.SHA256 || !canonicalSHA256(marker.ConfigSHA256) || marker.CCAPIVersion != 2 {
		return securityRuntimeStatus{}, errors.New("security_runtime ready marker identity mismatch")
	}
	return securityRuntimeStatus{WAFReady: true, CCReady: true}, nil
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func readSecurityRuntimeFile(path string) ([]byte, error) {
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, errors.New("security runtime path is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 ||
		info.Size() > maxSecurityRuntimeFileBytes || info.Mode().Perm()&0o222 != 0 {
		return nil, errors.New("security runtime file must be a bounded regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open security runtime file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o222 != 0 ||
		opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return nil, errors.New("security runtime file changed while opening")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("security runtime file must have one link")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSecurityRuntimeFileBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxSecurityRuntimeFileBytes {
		return nil, errors.New("read security runtime file")
	}
	return content, nil
}

func strictSecurityJSON(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing security JSON")
	}
	return nil
}

// nativeSecurityAssetPath: the native self-test embeds the asset paths in a
// Lua string, so they are limited to plain path characters.
var nativeSecurityAssetPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// validateNativeSecurityRuntime is the native node's counterpart of the
// container entrypoint's load check: the packaged OpenResty compiles the
// three verified assets (loadfile, as entrypoint.sh does) in init_by_lua and
// exits. WAF and CC are declared only when this passes; it runs once at
// daemon start (capabilities are computed once, assembleClient).
func validateNativeSecurityRuntime(ctx context.Context, binary string, settings securityRuntimeSettings) (securityRuntimeStatus, error) {
	// Re-verify right before the load: the start-time digests must be the
	// bytes OpenResty compiles.
	if _, err := validateSecurityRuntime(settings); err != nil {
		return securityRuntimeStatus{}, err
	}
	if settings.Mode != securityRuntimeModeNative {
		return securityRuntimeStatus{}, errors.New("security_runtime is not native")
	}
	if !absoluteCleanPath(binary) {
		return securityRuntimeStatus{}, errors.New("native security self-test needs an absolute OpenResty binary")
	}
	files := make([]string, 0, 3)
	for _, asset := range []runtimeAssetSettings{settings.WAF, settings.CC, settings.Adaptive} {
		if !nativeSecurityAssetPath.MatchString(asset.Path) {
			return securityRuntimeStatus{}, fmt.Errorf("security_runtime asset path is not self-testable: %s", asset.Path)
		}
		files = append(files, `"`+asset.Path+`"`)
	}
	prefix, err := os.MkdirTemp("", "cdnca-security-selftest-")
	if err != nil {
		return securityRuntimeStatus{}, fmt.Errorf("native security self-test: %w", err)
	}
	defer os.RemoveAll(prefix)
	// nginx opens <prefix>/logs/error.log before reading error_log.
	if err := os.Mkdir(filepath.Join(prefix, "logs"), 0o700); err != nil {
		return securityRuntimeStatus{}, fmt.Errorf("native security self-test: %w", err)
	}
	conf := "daemon off;\nmaster_process off;\nworker_processes 1;\npid " + filepath.Join(prefix, "nginx.pid") + ";\n" +
		"error_log stderr;\nevents { worker_connections 16; }\nhttp {\n  access_log off;\n  init_by_lua_block {\n" +
		"    for _, file in ipairs({" + strings.Join(files, ", ") + "}) do\n" +
		"      local chunk, err = loadfile(file)\n" +
		"      if not chunk then io.stderr:write(\"cdnca security self-test: \", err, \"\\n\"); os.exit(1) end\n" +
		"    end\n    io.stdout:write(\"cdnca security self-test ok\\n\")\n    os.exit(0)\n  }\n}\n"
	confPath := filepath.Join(prefix, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return securityRuntimeStatus{}, fmt.Errorf("native security self-test: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, binary, "-p", prefix+"/", "-c", confPath)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil || !strings.Contains(stdout.String(), "cdnca security self-test ok") {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return securityRuntimeStatus{}, fmt.Errorf("native security self-test failed: %v: %s", err, detail)
	}
	return securityRuntimeStatus{WAFReady: true, CCReady: true}, nil
}
