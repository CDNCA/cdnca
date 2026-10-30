package nativebackup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// ReadEnvironmentFile parses KEY=VALUE lines (shell-style quotes removed).
// Callers must never log the returned values.
func ReadEnvironmentFile(path string) (map[string]string, error) {
	encoded, err := readPrivateFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(encoded))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	return values, scanner.Err()
}

// NativeFacts reads the identity of the running installation from the files
// the installer wrote. The schema version comes from the PostgreSQL capture.
func NativeFacts(_ context.Context, host *Host) (ControlFacts, error) {
	environment, err := ReadEnvironmentFile(host.Layout.Path(ConfigDirectory + "/control.env"))
	if err != nil {
		return ControlFacts{}, err
	}
	gateway, _ := ReadEnvironmentFile(host.Layout.Path(ConfigDirectory + "/gateway.env"))
	manifest, err := os.ReadFile(host.Layout.Path(NativeRoot + "/current/release.manifest.json"))
	if err != nil {
		return ControlFacts{}, err
	}
	var release struct {
		Version string `json:"version"`
		Source  struct {
			Commit string `json:"commit"`
		} `json:"source"`
	}
	if err := json.Unmarshal(manifest, &release); err != nil || release.Version == "" {
		return ControlFacts{}, errors.New("release manifest is unreadable")
	}
	if environment["CONTROL_VERSION"] != release.Version {
		return ControlFacts{}, errors.New("control.env version differs from the active release")
	}
	hostname, _ := os.Hostname()
	domain := ""
	if origin, err := os.ReadFile(host.Layout.Path(UpgradeConfig + "/api.env")); err == nil {
		for _, line := range strings.Split(string(origin), "\n") {
			if value, found := strings.CutPrefix(line, "CDNCA_NATIVE_UPGRADE_WEB_INDEX_URL="); found {
				domain = strings.TrimSuffix(strings.TrimPrefix(strings.Trim(value, `'"`), "https://"), "/dashboard/")
			}
		}
	}
	return ControlFacts{InstallationID: environment["CONTROL_INSTALLATION_ID"], InstallationName: environment["CONTROL_INSTALLATION_NAME"],
		Version: release.Version, SourceCommit: release.Source.Commit, SchemaVersion: 1, ControlDomain: domain,
		GatewayEndpoint: gateway["CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT"], Hostname: hostname}, nil
}
