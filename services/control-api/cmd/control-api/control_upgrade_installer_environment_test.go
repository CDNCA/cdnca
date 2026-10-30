package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The native installer writes CONTROL_UPGRADE_* into control.env. Load exactly
// those lines (with the installer's ${...} placeholders bound to temporary
// files) through the production loader so the two cannot drift apart.
func TestNativeInstallerControlUpgradeEnvironmentLoads(t *testing.T) {
	script, err := os.ReadFile("../../../../scripts/install-control.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	start := strings.Index(text, "\nwrite_environment() {\n")
	if start < 0 {
		t.Fatal("installer write_environment is missing")
	}
	block := text[start:]
	block = block[:strings.Index(block, "\n}\n")]
	constants := map[string]string{}
	for _, name := range []string{"UPGRADE_CONTROL_KEY_ID", "UPGRADE_EDGE_KEY_ID"} {
		match := regexp.MustCompile(`(?m)^readonly ` + name + `="([^"]+)"$`).FindStringSubmatch(text)
		if match == nil {
			t.Fatalf("installer constant %s is missing", name)
		}
		constants[name] = match[1]
	}
	directory := t.TempDir()
	configDir := filepath.Join(directory, "config")
	keyDir := filepath.Join(directory, "upgrade")
	for _, path := range []string{configDir, keyDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	controlPublic := writeInstallerUpgradeKey(t, filepath.Join(keyDir, "control-execution.pem"))
	edgePublic := writeInstallerUpgradeKey(t, filepath.Join(keyDir, "edge-execution.pem"))
	if controlPublic.Equal(edgePublic) {
		t.Fatal("generated upgrade keys must differ")
	}
	// Same shape install-control.sh derives from /public/v1/signing-keyset.
	trust := `{"keys":[{"key_id":"license-signing","public_key":"` +
		base64.RawURLEncoding.EncodeToString(controlPublic) + `"}]}`
	if err := os.WriteFile(filepath.Join(configDir, "entitlement-trusted-keys.json"), []byte(trust), 0o400); err != nil {
		t.Fatal(err)
	}
	// Plain profile with the built-in certificate: upgrade_download_origin is
	// the control origin and upgrade_download_root_env names the private root.
	rootCA := filepath.Join(directory, "pki", "root-ca-cert.pem")
	replacer := strings.NewReplacer("$(upgrade_download_origin)", "https://cdnca.com",
		"$(upgrade_download_root_env)", "CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE="+rootCA,
		"${CONFIG_DIR}", configDir, "${UPGRADE_KEY_DIR}", keyDir,
		"${DOWNLOAD_DIR}", filepath.Join(directory, "downloads"), "${CONTROL_ORIGIN}", "https://cdnca.com",
		// fix-btenv2: the artifact origin is $(upgrade_download_origin), CONTROL_ORIGIN outside BaoTa.
		"$(upgrade_download_origin)", "https://cdnca.com",
		"${UPGRADE_CONTROL_KEY_ID}", constants["UPGRADE_CONTROL_KEY_ID"],
		"${UPGRADE_EDGE_KEY_ID}", constants["UPGRADE_EDGE_KEY_ID"])
	var environment []string
	for _, line := range strings.Split(block, "\n") {
		if line == "$(upgrade_download_root_env)" {
			line = replacer.Replace(line)
		}
		if !strings.HasPrefix(line, "CONTROL_UPGRADE_") {
			continue
		}
		resolved := replacer.Replace(line)
		if strings.Contains(resolved, "${") {
			t.Fatalf("installer upgrade setting has an unbound placeholder: %s", line)
		}
		environment = append(environment, resolved)
	}
	// cdncaCE: the community installer turns online upgrades off (they need
	// license-issued upgrade grants); the rest of the block must still load
	// once an operator turns them on.
	if config, err := loadControlUpgradeRuntimeConfigFromEnv(environment); err != nil || config.Enabled {
		t.Fatalf("community installer upgrade runtime = %+v, %v; want disabled", config, err)
	}
	environment = controlUpgradeReplaceEnvironment(environment, controlUpgradeEnabledEnv, "true")
	config, err := loadControlUpgradeRuntimeConfigFromEnv(environment)
	if err != nil {
		t.Fatalf("installer upgrade environment rejected: %v", err)
	}
	if config.DownloadRootCAFile != rootCA || config.ArtifactBaseURL != "https://cdnca.com/downloads/edge-agent/upgrades/sha256" {
		t.Fatalf("download policy settings = (%q, %q)", config.DownloadRootCAFile, config.ArtifactBaseURL)
	}
	if !config.Enabled || config.ControlSigningKeyID == config.EdgeSigningKeyID ||
		config.ControlSigner.Provider != controlUpgradeSignerProviderFile ||
		config.EdgeSigner.Provider != controlUpgradeSignerProviderFile ||
		config.ExecutionTTL > 15*time.Minute || config.CommandGrantTrustFile != filepath.Join(configDir, "entitlement-trusted-keys.json") {
		t.Fatalf("installer upgrade runtime = %+v", config)
	}
	if _, err := controlUpgradeLoadTrust(config.CommandGrantTrustFile); err != nil {
		t.Fatalf("installer grant trust rejected: %v", err)
	}
	for _, signer := range []controlUpgradeSignerProviderConfig{config.ControlSigner, config.EdgeSigner} {
		provider, err := openControlUpgradeSigningProvider(signer)
		if err != nil {
			t.Fatalf("installer signing key rejected: %v", err)
		}
		provider.Close()
	}

	for name, mutate := range map[string]func([]string) []string{
		"missing edge key": func(values []string) []string {
			return controlUpgradeDropEnvironment(values, controlUpgradeEdgeSigningPrivateKeyFileEnv)
		},
		"shared key file": func(values []string) []string {
			return controlUpgradeReplaceEnvironment(values, controlUpgradeEdgeSigningPrivateKeyFileEnv,
				filepath.Join(keyDir, "control-execution.pem"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if config, err := loadControlUpgradeRuntimeConfigFromEnv(mutate(append([]string(nil), environment...))); err == nil || config.Enabled {
				t.Fatalf("invalid installer environment accepted: %+v", config)
			}
		})
	}
}

func writeInstallerUpgradeKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o400); err != nil {
		t.Fatal(err)
	}
	return public
}
