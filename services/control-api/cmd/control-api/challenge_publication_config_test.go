package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadChallengePolicyRuntimeConfigRequiresBoundFactEncryptionKey(t *testing.T) {
	t.Setenv("CHALLENGE_POLICY_RUNTIME_ENABLED", "true")
	t.Setenv("CHALLENGE_POLICY_CURSOR_KEY_ID", "challenge-cursor-v1")
	t.Setenv("CHALLENGE_POLICY_CURSOR_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("CHALLENGE_POLICY_FACT_KEK_ID", "challenge-fact-kek-v1")
	t.Setenv("CHALLENGE_POLICY_FACT_KEK_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	config, err := loadChallengePolicyRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer config.clear()
	if !config.Enabled || config.CursorKeyID != "challenge-cursor-v1" ||
		config.FactKeyID != "challenge-fact-kek-v1" || len(config.FactKey) != 32 {
		t.Fatalf("challenge policy config = %+v", config)
	}
}

func TestLoadChallengePolicyRuntimeConfigRejectsInvalidFactEncryptionKey(t *testing.T) {
	t.Setenv("CHALLENGE_POLICY_RUNTIME_ENABLED", "true")
	t.Setenv("CHALLENGE_POLICY_CURSOR_KEY_ID", "challenge-cursor-v1")
	t.Setenv("CHALLENGE_POLICY_CURSOR_KEY_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("CHALLENGE_POLICY_FACT_KEK_ID", "challenge-fact-kek-v1")
	t.Setenv("CHALLENGE_POLICY_FACT_KEK_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 31)))

	if _, err := loadChallengePolicyRuntimeConfig(); err == nil || !strings.Contains(err.Error(), "exactly 32 bytes") {
		t.Fatalf("invalid challenge fact KEK error = %v", err)
	}

	t.Setenv("CHALLENGE_POLICY_FACT_KEK_BASE64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("CHALLENGE_POLICY_FACT_KEK_ID", " challenge-fact-kek-v1")
	if _, err := loadChallengePolicyRuntimeConfig(); err == nil || !strings.Contains(err.Error(), "KEK_ID") {
		t.Fatalf("invalid challenge fact KEK ID error = %v", err)
	}
}
