package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodedownloads"
)

// The /downloads node package sync is on by default and
// reports why it is off; bad settings stop control-api.
func TestNodeDownloadsRuntimeSettings(t *testing.T) {
	for _, tc := range []struct {
		sync, interval, source, license, version string
		reason                                   string
		fails                                    bool
	}{
		{sync: "false", license: "https://auth.example", version: "1.0.35", reason: "switched_off"},
		{license: "", version: "1.0.35", reason: "no_release_server"},
		// This test host has no native /var/lib/cdnca-control/downloads.
		{license: "https://auth.example", version: "1.0.35", reason: "no_native_downloads"},
		{source: "https://www.cdnca.com/downloads/ce", version: "1.0.35", reason: "no_native_downloads"},
		{sync: "yes", fails: true},
		{interval: "1m", fails: true},
		{interval: "25h", fails: true},
	} {
		t.Setenv(nodeDownloadsSyncEnv, tc.sync)
		t.Setenv(nodeDownloadsIntervalEnv, tc.interval)
		t.Setenv(nodeDownloadsSourceEnv, tc.source)
		syncer, off, err := nodeDownloadsRuntime(tc.license, tc.version)
		if tc.fails {
			if err == nil {
				t.Errorf("%+v accepted", tc)
			}
			continue
		}
		if err != nil || syncer != nil || off != nodedownloads.DisabledStatus(tc.reason) {
			t.Errorf("%+v: syncer=%v off=%+v err=%v", tc, syncer != nil, off, err)
		}
	}
}
