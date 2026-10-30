package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// Cache purge/prewarm are base CDN functions: a fresh native install must run
// the cache control runtime on the shared Agent streams of the single-node
// NATS (scripts/native-runtime/native-nats-profile.json).
func TestNativeInstallerEnablesCacheControlRuntime(t *testing.T) {
	script, err := os.ReadFile("../../../../scripts/install-control.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	block := text[strings.Index(text, "\nwrite_environment() {\n"):]
	block = block[:strings.Index(block, "\n}\n")]
	secrets := text[strings.Index(text, "\ngenerate_runtime_secrets() {\n"):]
	secrets = secrets[:strings.Index(secrets, "\n}\n")]
	if !strings.Contains(secrets, "  CACHE_CONTROL_CURSOR_KEY_BASE64=$(openssl rand -base64 32 | tr -d '\\n')") {
		t.Fatal("installer does not generate CACHE_CONTROL_CURSOR_KEY_BASE64")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	replacer := strings.NewReplacer(
		"${CACHE_CONTROL_CURSOR_KEY_BASE64}", base64.StdEncoding.EncodeToString(raw),
		"${NATS_URL}", "nats://127.0.0.1:4222",
	)
	environment := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "CACHE_CONTROL_") {
			continue
		}
		resolved := replacer.Replace(line)
		if strings.Contains(resolved, "${") {
			t.Fatalf("installer setting has an unbound placeholder: %s", line)
		}
		name, value, _ := strings.Cut(resolved, "=")
		environment[name] = value
	}
	config, err := loadCacheControlProductionConfigFromEnv(mapAccountRecoveryEnv(environment))
	defer config.clearSecrets()
	if err != nil {
		t.Fatalf("installer cache control environment rejected: %v", err)
	}
	worker := config.Runtime.Worker
	if !config.Runtime.Enabled || len(config.Runtime.CursorKey) != 32 ||
		config.NATSURL != "nats://127.0.0.1:4222" ||
		worker.CommandStream != "AGENT_COMMANDS" || worker.StatusStream != "AGENT_DEPLOYMENT_STATUS" ||
		worker.CommandSubjectPrefix != "cdnca.agent.commands.cache" ||
		worker.StatusSubjectPrefix != "cdnca.agent.deployment-status.cache" ||
		worker.DLQSubjectPrefix != "cdnca.agent.deployment-status.cache-dlq" ||
		worker.Durable != "control_api_cache_status" || worker.Replicas != 1 {
		t.Fatalf("installer must enable cache control on the shared single-node Agent streams: %#v", worker)
	}
	// The worker binds only to node leases written by the presence runtime.
	if !strings.Contains(block, "\nNODE_PRESENCE_NATS_URL=${NATS_URL}\n") ||
		!strings.Contains(block, "\nNODE_PRESENCE_REDIS_URL=${REDIS_URL}\n") {
		t.Fatal("cache control requires node presence in the installer environment")
	}
}
