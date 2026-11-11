package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/cdnca/cdnca/services/control-api/internal/nodedownloads"
)

const (
	nodeDownloadsSyncEnv     = "CONTROL_NODE_DOWNLOADS_SYNC"
	nodeDownloadsIntervalEnv = "CONTROL_NODE_DOWNLOADS_SYNC_INTERVAL"
	nodeDownloadsSourceEnv   = "CONTROL_NODE_DOWNLOADS_SOURCE"
)

// nodeDownloadsRuntime keeps /downloads/edge-agent/latest current
//. On by default on a native console whose release server is
// known: CONTROL_NODE_DOWNLOADS_SOURCE, else LICENSE_SERVICE_URL (the
// commercial authorization server that also serves /downloads). The
// community build has no LICENSE_SERVICE_URL and sets the source to its
// --release-server. CONTROL_NODE_DOWNLOADS_SYNC=false turns it off;
// CONTROL_NODE_DOWNLOADS_SYNC_INTERVAL (10m..24h, default 1h) sets the period.
// It returns the syncer (nil when off) and the status to report when off.
func nodeDownloadsRuntime(licenseServiceURL, controlVersion string) (*nodedownloads.Syncer, nodedownloads.Status, error) {
	enabled := os.Getenv(nodeDownloadsSyncEnv)
	if enabled != "" && enabled != "true" && enabled != "false" {
		return nil, nodedownloads.Status{}, fmt.Errorf("%s must be true or false", nodeDownloadsSyncEnv)
	}
	interval := time.Hour
	if raw := os.Getenv(nodeDownloadsIntervalEnv); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 10*time.Minute || parsed > 24*time.Hour {
			return nil, nodedownloads.Status{}, fmt.Errorf("%s must be within 10m..24h", nodeDownloadsIntervalEnv)
		}
		interval = parsed
	}
	if enabled == "false" {
		return nil, nodedownloads.DisabledStatus("switched_off"), nil
	}
	source := os.Getenv(nodeDownloadsSourceEnv)
	if source == "" {
		source = licenseServiceURL
	}
	downloads := nativebackup.DataDirectory + "/downloads"
	if source == "" || controlVersion == "" {
		return nil, nodedownloads.DisabledStatus("no_release_server"), nil
	}
	if info, err := os.Stat(filepath.Join(downloads, "edge-agent", "artifacts.json")); err != nil || !info.Mode().IsRegular() {
		// Not a native console (compose/Helm images serve their own downloads).
		return nil, nodedownloads.DisabledStatus("no_native_downloads"), nil
	}
	syncer, err := nodedownloads.New(nodedownloads.Config{Source: source, DownloadDir: downloads, ControlVersion: controlVersion,
		Interval: interval, Installers: []string{nativebackup.NativeRoot + "/current/static/web/downloads/install-node.sh",
			downloads + "/install-node.sh"}})
	if err != nil {
		return nil, nodedownloads.Status{}, fmt.Errorf("%s: %w", nodeDownloadsSourceEnv, err)
	}
	return syncer, nodedownloads.Status{}, nil
}
