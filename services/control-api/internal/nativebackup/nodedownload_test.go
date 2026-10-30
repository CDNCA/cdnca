package nativebackup

import (
	"context"
	"os"
	"strings"
	"testing"
)

// install-control.sh write_nginx_config ends the http block with
// "$(node_download_server)": an empty line on a plain host, the direct
// download server on a BaoTa host (pinned by testdata/node-download-server.conf,
// also checked against the installer by tests/install-control-bt-env.test.mjs).
const nginxTail = "    server {\n        listen 443 ssl http2;\n        server_name _;\n    }\n"

func TestNodeDownloadServerMatchesTheInstaller(t *testing.T) {
	want, err := os.ReadFile("testdata/node-download-server.conf")
	if err != nil {
		t.Fatal(err)
	}
	if got := NodeDownloadServer(19445); got != string(want) {
		t.Fatalf("NodeDownloadServer = %q, want %q", got, want)
	}
}

// fix-btenv3: a restore moves the node upgrade download endpoint with the
// layout, so the signed download policy nodes adopt names the right port and root.
func TestRetargetNodeDownloadBetweenPlainAndBaoTa(t *testing.T) {
	block, err := os.ReadFile("testdata/node-download-server.conf")
	if err != nil {
		t.Fatal(err)
	}
	plainNginx := "http {\n" + nginxTail + "\n}\n"
	btNginxConf := "http {\n" + nginxTail + string(block) + "}\n"
	plainEnv := "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com\n" +
		"CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://cdnca.com/downloads/edge-agent/upgrades/sha256\n" +
		"CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/etc/cdnca-control/keys/pki/public-cert.pem\nOTHER=1\n"
	btEnv := "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com\n" +
		"CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256\n" +
		"CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/etc/cdnca-control/keys/pki/root-ca-cert.pem\nOTHER=1\n"

	// plain -> BaoTa: direct port, private root, direct server added once.
	layout := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, layout, map[string]string{HostPortsFile: "ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\n",
		ConfigDirectory + "/nginx.conf": plainNginx, ConfigDirectory + "/control.env": plainEnv})
	for range 2 {
		if err := retargetNodeDownload(layout, mustHostPorts(t, layout), func(string, ...any) {}); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFixture(t, layout, ConfigDirectory+"/control.env"); got != btEnv {
		t.Fatalf("plain -> bt control.env = %q", got)
	}
	if got := readFixture(t, layout, ConfigDirectory+"/nginx.conf"); got != btNginxConf {
		t.Fatalf("plain -> bt nginx.conf = %q", got)
	}

	// BaoTa -> plain (management port 8443): server removed, base URL on the
	// management port; the private root stays (it verifies the built-in certificate).
	plain := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, plain, map[string]string{ConfigDirectory + "/nginx.conf": btNginxConf,
		ConfigDirectory + "/control.env": strings.Replace(btEnv, "https://cdnca.com\n", "https://cdnca.com:8443\n", 1)})
	if err := retargetNodeDownload(plain, mustHostPorts(t, plain), func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, plain, ConfigDirectory+"/nginx.conf"); got != plainNginx {
		t.Fatalf("bt -> plain nginx.conf = %q", got)
	}
	if got := readFixture(t, plain, ConfigDirectory+"/control.env"); !strings.Contains(got,
		"CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://cdnca.com:8443/downloads/edge-agent/upgrades/sha256\n") ||
		!strings.Contains(got, "CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/etc/cdnca-control/keys/pki/root-ca-cert.pem\n") {
		t.Fatalf("bt -> plain control.env = %q", got)
	}

	// The BaoTa direct port moved on the target (19445 taken there).
	moved := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, moved, map[string]string{HostPortsFile: "ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19447\n",
		ConfigDirectory + "/nginx.conf": btNginxConf, ConfigDirectory + "/control.env": btEnv})
	if err := RetargetPorts(context.Background(), moved, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, moved, ConfigDirectory+"/nginx.conf"); strings.Count(got, "listen 19447 ssl;") != 1 || strings.Contains(got, "19445") {
		t.Fatalf("moved nginx.conf = %q", got)
	}
	if got := readFixture(t, moved, ConfigDirectory+"/control.env"); !strings.Contains(got, "https://cdnca.com:19447/downloads/") {
		t.Fatalf("moved control.env = %q", got)
	}
}

func mustHostPorts(t *testing.T, layout Layout) HostPorts {
	t.Helper()
	ports, err := ReadHostPorts(layout)
	if err != nil {
		t.Fatal(err)
	}
	return ports
}
