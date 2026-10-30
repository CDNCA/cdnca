package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUpgradeRuntimeConfigIsDisabledByDefaultAndFailsClosed(t *testing.T) {
	config := defaultFileConfig()
	if config.Upgrade.Enabled {
		t.Fatal("upgrade runtime must be disabled by default")
	}
	config.Upgrade.Enabled = true
	if _, err := config.validate(); err == nil {
		t.Fatal("incomplete enabled upgrade runtime was accepted")
	}
}

func TestUpgradeRuntimeConfigAcceptsCanonicalPinnedContract(t *testing.T) {
	config := validUpgradeRuntimeFileConfig(t)
	if _, err := config.validate(); err != nil {
		t.Fatal(err)
	}
	protected := config.diskGuardProtectedPaths()
	for _, expected := range []string{
		config.Upgrade.Root,
		filepath.Dir(config.Upgrade.ControlExecutionTrustFile),
		filepath.Dir(config.Upgrade.EdgeExecutionTrustFile),
		filepath.Dir(config.Upgrade.InstallerReceiptTrustFile),
		filepath.Dir(config.Upgrade.DownloadRootCAFile),
	} {
		found := false
		for _, actual := range protected {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("upgrade path %q is absent from disk guard protection", expected)
		}
	}
}

func TestUpgradeRuntimeConfigRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fileConfig)
	}{
		{name: "noncanonical installation", mutate: func(config *fileConfig) { config.Upgrade.InstallationID = "00000000-0000-4000-8000-0000000000AA" }},
		{name: "relative root", mutate: func(config *fileConfig) { config.Upgrade.Root = "relative" }},
		{name: "deployment overlap", mutate: func(config *fileConfig) { config.Upgrade.Root = config.DeploymentRoot }},
		{name: "uppercase host", mutate: func(config *fileConfig) { config.Upgrade.DownloadHost = "Updates.example.com" }},
		{name: "punycode host", mutate: func(config *fileConfig) { config.Upgrade.DownloadHost = "xn--example.test" }},
		{name: "IP host with other addresses", mutate: func(config *fileConfig) { config.Upgrade.DownloadHost = "192.0.2.10" }},
		{name: "IP host with different address", mutate: func(config *fileConfig) {
			config.Upgrade.DownloadHost, config.Upgrade.DownloadAddresses = "192.0.2.10", []string{"192.0.2.11"}
		}},
		{name: "noncanonical IPv6 host", mutate: func(config *fileConfig) {
			config.Upgrade.DownloadHost, config.Upgrade.DownloadAddresses = "2001:DB8::10", []string{"2001:db8::10"}
		}},
		{name: "single-label host", mutate: func(config *fileConfig) { config.Upgrade.DownloadHost = "updates" }},
		{name: "trailing-dot host", mutate: func(config *fileConfig) { config.Upgrade.DownloadHost = "updates.example.com." }},
		{name: "zero port", mutate: func(config *fileConfig) { config.Upgrade.DownloadPort = 0 }},
		{name: "unspecified address", mutate: func(config *fileConfig) { config.Upgrade.DownloadAddresses = []string{"0.0.0.0"} }},
		{name: "multicast address", mutate: func(config *fileConfig) { config.Upgrade.DownloadAddresses = []string{"ff02::1"} }},
		{name: "mapped duplicate address", mutate: func(config *fileConfig) {
			config.Upgrade.DownloadAddresses = []string{"192.0.2.10", "::ffff:192.0.2.10"}
		}},
		{name: "zero timeout", mutate: func(config *fileConfig) { config.Upgrade.Timeout = "0s" }},
		{name: "unbounded timeout", mutate: func(config *fileConfig) { config.Upgrade.Timeout = (24*time.Hour + time.Second).String() }},
		{name: "zero artifact limit", mutate: func(config *fileConfig) { config.Upgrade.MaxArtifactBytes = 0 }},
		{name: "unbounded artifact limit", mutate: func(config *fileConfig) { config.Upgrade.MaxArtifactBytes = 285229183 }},
		{name: "negative disk reserve", mutate: func(config *fileConfig) { config.Upgrade.DiskReserveBytes = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validUpgradeRuntimeFileConfig(t)
			test.mutate(&config)
			if _, err := config.validate(); err == nil {
				t.Fatal("unsafe upgrade configuration was accepted")
			}
		})
	}

	t.Run("symlinked root", func(t *testing.T) {
		config := validUpgradeRuntimeFileConfig(t)
		realRoot := filepath.Join(filepath.Dir(config.Upgrade.Root), "real-upgrades")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedRoot := filepath.Join(filepath.Dir(config.Upgrade.Root), "linked-upgrades")
		if err := os.Symlink(realRoot, linkedRoot); err != nil {
			t.Fatal(err)
		}
		config.Upgrade.Root = filepath.Join(linkedRoot, "state")
		if _, err := config.validate(); err == nil {
			t.Fatal("symlinked upgrade root was accepted")
		}
	})
}

// An IP literal control plane (private CA certificate with an IP SAN) is a
// valid download host when it pins exactly that address.
func TestUpgradeRuntimeConfigAcceptsIPLiteralControlPlaneHost(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		config := validUpgradeRuntimeFileConfig(t)
		config.Upgrade.DownloadHost, config.Upgrade.DownloadAddresses = address, []string{address}
		if _, err := config.validate(); err != nil {
			t.Fatalf("IP literal download host %s rejected: %v", address, err)
		}
	}
}

func validUpgradeRuntimeFileConfig(t *testing.T) fileConfig {
	t.Helper()
	root := secureConfigTempDir(t)
	config := validFileConfig()
	config.Upgrade = upgradeSettings{
		Enabled: true, InstallationID: "00000000-0000-4000-8000-000000000013",
		Root:                      filepath.Join(root, "upgrades"),
		ControlExecutionTrustFile: filepath.Join(root, "trust", "control.json"),
		EdgeExecutionTrustFile:    filepath.Join(root, "trust", "edge.json"),
		InstallerReceiptTrustFile: filepath.Join(root, "trust", "receipts.json"),
		DownloadHost:              "updates.example.com", DownloadAddresses: []string{"192.0.2.10", "2001:db8::10"},
		DownloadPort: 443, DownloadRootCAFile: filepath.Join(root, "trust", "download-ca.pem"),
		Timeout: "10m", MaxArtifactBytes: 128 << 20, DiskReserveBytes: 512 << 20,
	}
	return config
}

// The success path needs the fixed cdnca-edge account that the packaging
// helper client resolves; Linux CI creates it, other hosts skip that case.
func TestAssembleUpgradeRuntimeLoadsInstalledTrustAndFailsClosed(t *testing.T) {
	config := writeUpgradeRuntimeFixture(t)
	nodeID := config.NodeID

	for name, test := range map[string]struct {
		reason string
		mutate func(*testing.T, *fileConfig)
	}{
		"missing control trust": {"control upgrade execution trust", func(t *testing.T, value *fileConfig) {
			value.Upgrade.ControlExecutionTrustFile = filepath.Join(filepath.Dir(value.Upgrade.ControlExecutionTrustFile), "absent.json")
		}},
		"group readable edge trust": {"edge upgrade execution trust", func(t *testing.T, value *fileConfig) {
			if err := os.Chmod(value.Upgrade.EdgeExecutionTrustFile, 0o440); err != nil {
				t.Fatal(err)
			}
		}},
		"helper pin used as receipt trust": {"installer receipt trust", func(t *testing.T, value *fileConfig) {
			path := filepath.Join(filepath.Dir(value.Upgrade.InstallerReceiptTrustFile), "helper-receipt-public.json")
			writeUpgradeFixtureFile(t, path, `{"schema_version":1,"key_id":"helper-1","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
			value.Upgrade.InstallerReceiptTrustFile = path
		}},
		"download CA is not a certificate": {"download root CA is invalid", func(t *testing.T, value *fileConfig) {
			path := filepath.Join(filepath.Dir(value.Upgrade.DownloadRootCAFile), "not-ca.pem")
			writeUpgradeFixtureFile(t, path, "not a certificate\n")
			value.Upgrade.DownloadRootCAFile = path
		}},
		"invalid timeout": {"timeout is invalid", func(t *testing.T, value *fileConfig) { value.Upgrade.Timeout = "soon" }},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := writeUpgradeRuntimeFixture(t)
			test.mutate(t, &candidate)
			runtime, err := assembleUpgradeRuntime(candidate, nodeID, nil)
			if err == nil || runtime != nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("assembleUpgradeRuntime() = (%v, %v), want rejection containing %q", runtime, err, test.reason)
			}
		})
	}

	t.Run("installed trust", func(t *testing.T) {
		if _, err := user.Lookup("cdnca-edge"); err != nil {
			t.Skip("cdnca-edge account is absent; run on Linux with the packaging account")
		}
		// Release builds stamp agentVersion with -ldflags; the test binary does not.
		previous := agentVersion
		agentVersion = "1.0.25"
		t.Cleanup(func() { agentVersion = previous })
		runtime, err := assembleUpgradeRuntime(config, nodeID, nil)
		if err != nil || runtime == nil {
			t.Fatalf("assembleUpgradeRuntime() = (%v, %v)", runtime, err)
		}
	})
}

func writeUpgradeRuntimeFixture(t *testing.T) fileConfig {
	t.Helper()
	config := validUpgradeRuntimeFileConfig(t)
	config.NodeID = uuid.NewString()
	trust := filepath.Dir(config.Upgrade.ControlExecutionTrustFile)
	if err := os.MkdirAll(trust, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.Upgrade.ControlExecutionTrustFile, config.Upgrade.EdgeExecutionTrustFile,
		config.Upgrade.InstallerReceiptTrustFile} {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		document, err := json.Marshal(map[string]any{"version": 1, "keys": []map[string]string{{
			"key_id": "fixture-" + filepath.Base(path), "public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		writeUpgradeFixtureFile(t, path, string(document))
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upgrade fixture root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	writeUpgradeFixtureFile(t, config.Upgrade.DownloadRootCAFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})))
	return config
}

func writeUpgradeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
}
