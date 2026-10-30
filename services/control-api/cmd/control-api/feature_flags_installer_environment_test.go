package main

import (
	"context"
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

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphistory"
)

// fix-flags: the feature switches install-control.sh writes into control.env
// must load through the production loaders (the 73 console had them unset,
// leaving payment channels, package monitor and identity verification 404).
func TestNativeInstallerFeatureFlagsLoad(t *testing.T) {
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
	var pairs []string
	for _, match := range regexp.MustCompile(`\$\{([A-Z_]+_BASE64)\}`).FindAllStringSubmatch(block, -1) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, match[0], base64.StdEncoding.EncodeToString(raw))
	}
	pairs = append(pairs, "${CONTROL_ORIGIN}", "https://control.example.test:8443",
		"${INSTALLATION_ID}", "11111111-1111-4111-8111-111111111111")
	replacer := strings.NewReplacer(pairs...)
	prefixes := []string{"SYSTEM_SETTINGS_RUNTIME_", "HTTP_POLICY_RUNTIME_", "CHALLENGE_POLICY_",
		"IDENTITY_VERIFICATION_", "ACCOUNT_RECOVERY_", "ACCOUNT_REGISTRATION_",
		"PLUGIN_WEBHOOK_RUNTIME_", "CONTROL_BACKUP_RUN_"}
	environment := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		name, _, found := strings.Cut(line, "=")
		if !found || !hasAnyPrefix(name, prefixes) {
			continue
		}
		resolved := replacer.Replace(line)
		if strings.Contains(resolved, "${") {
			t.Fatalf("installer setting has an unbound placeholder: %s", line)
		}
		if _, duplicate := environment[name]; duplicate {
			t.Fatalf("installer writes %s twice", name)
		}
		_, environment[name], _ = strings.Cut(resolved, "=")
	}
	entries := make([]string, 0, len(environment))
	for name, value := range environment {
		entries = append(entries, name+"="+value)
		t.Setenv(name, value)
	}

	if config, err := loadSystemSettingsRuntimeConfig(); err != nil || !config.Enabled {
		t.Fatalf("system settings: %+v %v", config, err)
	}
	if enabled, err := loadRuntimeBool("HTTP_POLICY_RUNTIME_ENABLED"); err != nil || !enabled {
		t.Fatalf("HTTP policy: %v %v", enabled, err)
	}
	challenge, err := loadChallengePolicyRuntimeConfig()
	if err != nil || !challenge.Enabled || len(challenge.FactKey) != 32 {
		t.Fatalf("challenge policy: %v", err)
	}
	challenge.clear()
	verification, err := loadIdentityVerificationRuntimeConfigFromEnv(entries)
	if err != nil || !verification.Enabled || !verification.WorkerEnabled {
		t.Fatalf("identity verification: %v", err)
	}
	verification.clear()
	// No KYC provider: the case API mounts and the issuer stays off.
	if provider, err := loadIdentityVerificationProviderEnvironment(entries); err != nil || provider.Enabled {
		t.Fatalf("identity verification provider must stay unconfigured: %v", err)
	}
	if issuer, err := loadIdentityVerificationIssuerEnvironment(entries); err != nil || issuer.Enabled {
		t.Fatalf("identity verification issuer must load disabled: %v", err)
	}
	recovery, err := loadAccountRecoveryRuntimeConfigFromEnv(os.LookupEnv)
	if err != nil || recovery.Enabled {
		t.Fatalf("account recovery must load disabled: %v", err)
	}
	if registration, err := loadAccountRegistrationRuntimeConfigFromEnv(recovery, os.LookupEnv); err != nil || registration.Enabled {
		t.Fatalf("account registration must load disabled: %v", err)
	}
	// fix-flags2 E1: the webhook runtime needs NATS credentials + CA the local
	// NATS does not have, so the installer writes it off explicitly.
	if environment["PLUGIN_WEBHOOK_RUNTIME_ENABLED"] != "false" {
		t.Fatalf("plugin webhook runtime = %q, want false", environment["PLUGIN_WEBHOOK_RUNTIME_ENABLED"])
	}
	// fix-flags2 E4: with no backup runner bound the history reads as an empty,
	// unconfigured page instead of 503 backup_history_unavailable.
	if environment["CONTROL_BACKUP_RUN_INSTALLATION_ID"] == "" || environment["CONTROL_BACKUP_RUN_CURSOR_KEY_BASE64"] == "" {
		t.Fatalf("installer must write the backup history installation binding and cursor key")
	}
	for _, name := range backupRunnerBindings {
		if _, written := environment[name]; written {
			t.Fatalf("installer must not guess the backup runner binding %s", name)
		}
	}
	reader := loadBackupHistoryReader()
	if reader == nil {
		t.Fatal("backup history reader is unavailable on a fresh install")
	}
	page, err := reader.List(context.Background(), controlbackuphistory.Query{Limit: 10})
	if err != nil || !page.Unconfigured || len(page.Items) != 0 || page.TotalCount != 0 {
		t.Fatalf("backup history = %+v %v, want an empty unconfigured page", page, err)
	}
	// A partial runner binding is a misconfiguration and stays unavailable.
	t.Setenv("CONTROL_BACKUP_RUN_MANIFEST_DIRECTORY", t.TempDir())
	if reader := loadBackupHistoryReader(); reader != nil {
		t.Fatalf("partial backup runner binding produced reader %T", reader)
	}
	// A complete binding the reader rejects must stay a nil interface, not a
	// typed nil *FileReader the handler would call.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "backup-run.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTROL_BACKUP_RUN_SOURCE_CLUSTER_ID", "control-a")
	t.Setenv("CONTROL_BACKUP_RUN_SIGNING_KEY_ID", "backup-run-v1")
	t.Setenv("CONTROL_BACKUP_RUN_SIGNING_PUBLIC_KEY_FILE", keyFile)
	if _, ok := loadBackupHistoryReader().(*controlbackuphistory.FileReader); !ok {
		t.Fatal("complete backup runner binding did not build the signed file reader")
	}
	t.Setenv("CONTROL_BACKUP_RUN_INSTALLATION_ID", "not-a-uuid")
	if reader := loadBackupHistoryReader(); reader != nil {
		t.Fatalf("invalid installation binding produced reader %T", reader)
	}
}

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
