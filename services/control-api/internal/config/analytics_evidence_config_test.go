package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID", "analytics/test-key-v1")
	os.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)))
	os.Exit(m.Run())
}

func TestLoadAnalyticsEvidenceWrappingKey(t *testing.T) {
	setRequiredConfig(t)
	setValidAnalyticsIngestConfig(t)
	wantKey := bytes.Repeat([]byte{23}, 32)
	t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID", "analytics/evidence-key-v1")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64", base64.StdEncoding.EncodeToString(wantKey))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AnalyticsIngest.IsolationWrappingKeyID != "analytics/evidence-key-v1" ||
		!bytes.Equal(cfg.AnalyticsIngest.IsolationWrappingKey, wantKey) {
		t.Fatalf("loaded analytics evidence key ID=%q length=%d",
			cfg.AnalyticsIngest.IsolationWrappingKeyID, len(cfg.AnalyticsIngest.IsolationWrappingKey))
	}
}

func TestLoadAnalyticsEvidenceWrappingKeyIDValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "missing"},
		{name: "leading whitespace", value: " evidence-key-v1"},
		{name: "trailing whitespace", value: "evidence-key-v1 "},
		{name: "control character", value: "evidence\x07key-v1"},
		{name: "more than 128 bytes", value: strings.Repeat("k", 129)},
	} {
		t.Run(test.name, func(t *testing.T) {
			setRequiredConfig(t)
			setValidAnalyticsIngestConfig(t)
			t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID", test.value)
			t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64",
				base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)))

			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID") {
				t.Fatalf("Load() key ID error = %v", err)
			}
		})
	}
}

func TestLoadAnalyticsEvidenceWrappingKeyBase64Validation(t *testing.T) {
	canonical := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32))
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "missing"},
		{name: "noncanonical", value: canonical[:4] + "\n" + canonical[4:]},
		{name: "invalid", value: "%%%"},
		{name: "wrong length", value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 31))},
	} {
		t.Run(test.name, func(t *testing.T) {
			setRequiredConfig(t)
			setValidAnalyticsIngestConfig(t)
			t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID", "analytics/evidence-key-v1")
			t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64", test.value)

			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64") {
				t.Fatalf("Load() key error = %v", err)
			}
		})
	}
}

func TestLoadDisabledAnalyticsIngestDoesNotReadEvidenceWrappingKey(t *testing.T) {
	setRequiredConfig(t)
	t.Setenv("ANALYTICS_INGEST_ENABLED", "false")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID", " invalid\x07key ")
	t.Setenv("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64", "not-base64")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() disabled analytics ingest error = %v", err)
	}
	if cfg.AnalyticsIngest.IsolationWrappingKeyID != "" || cfg.AnalyticsIngest.IsolationWrappingKey != nil {
		t.Fatal("disabled analytics ingest read evidence wrapping key configuration")
	}
}
