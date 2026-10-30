package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The native installer turns MFA and custom roles on (ui-fix4 F8): custom RBAC
// refuses to start without the MFA runtime (main.go customRBACConfig.Enabled),
// so both blocks must load through the production loaders together.
func TestNativeInstallerEnablesMFAAndCustomRBAC(t *testing.T) {
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
	secrets := text[strings.Index(text, "\ngenerate_runtime_secrets() {\n"):]
	secrets = secrets[:strings.Index(secrets, "\n}\n")]
	for _, name := range []string{"MFA_ENCRYPTION_KEY_BASE64", "CUSTOM_RBAC_CURSOR_KEY_BASE64"} {
		if !strings.Contains(secrets, "  "+name+"=$(openssl rand -base64 32 | tr -d '\\n')") {
			t.Fatalf("installer does not generate %s", name)
		}
	}
	keys := map[string]string{}
	for _, name := range []string{"MFA_ENCRYPTION_KEY_BASE64", "CUSTOM_RBAC_CURSOR_KEY_BASE64"} {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		keys["${"+name+"}"] = base64.StdEncoding.EncodeToString(raw)
	}
	pairs := make([]string, 0, len(keys)*2)
	for placeholder, value := range keys {
		pairs = append(pairs, placeholder, value)
	}
	replacer := strings.NewReplacer(pairs...)
	var mfaEnvironment, rbacEnvironment []string
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "MFA_") && !strings.HasPrefix(line, "CUSTOM_RBAC_") {
			continue
		}
		resolved := replacer.Replace(line)
		if strings.Contains(resolved, "${") {
			t.Fatalf("installer setting has an unbound placeholder: %s", line)
		}
		// systemd EnvironmentFile drops the single quotes around a value.
		if name, value, found := strings.Cut(resolved, "="); found && strings.HasPrefix(value, "'") {
			resolved = name + "=" + strings.Trim(value, "'")
		}
		if strings.HasPrefix(line, "MFA_") {
			mfaEnvironment = append(mfaEnvironment, resolved)
		} else {
			rbacEnvironment = append(rbacEnvironment, resolved)
		}
	}
	mfa, err := loadMFARuntimeConfigFromEnvEntries(mfaEnvironment)
	if err != nil {
		t.Fatalf("installer MFA environment rejected: %v", err)
	}
	defer mfa.clearSecrets()
	if !mfa.Enabled || len(mfa.Keys[mfa.ActiveKeyID]) != 32 {
		t.Fatal("installer must enable MFA with one active 32-byte key")
	}
	rbac, err := loadCustomRBACRuntimeConfigFromEnv(rbacEnvironment)
	if err != nil {
		t.Fatalf("installer custom RBAC environment rejected: %v", err)
	}
	defer rbac.clearSecrets()
	if !rbac.Enabled || len(rbac.CursorKey) != 32 {
		t.Fatal("installer must enable custom RBAC with a 32-byte cursor key")
	}
}
