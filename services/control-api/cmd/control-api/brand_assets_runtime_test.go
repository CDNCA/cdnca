package main

import (
	"context"
	"testing"
)

func TestLoadBrandAssetRuntimeConfigDisabled(t *testing.T) {
	t.Setenv("BRAND_ASSET_RUNTIME_ENABLED", "false")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_ENDPOINT", "not-an-endpoint")
	config, err := loadBrandAssetRuntimeConfig()
	if err != nil || config.Enabled {
		t.Fatalf("loadBrandAssetRuntimeConfig(disabled) = (%+v, %v)", config, err)
	}
}

func TestLoadBrandAssetRuntimeConfigRequiresObjectStore(t *testing.T) {
	t.Setenv("BRAND_ASSET_RUNTIME_ENABLED", "true")
	if config, err := loadBrandAssetRuntimeConfig(); err == nil || config.Enabled {
		t.Fatalf("loadBrandAssetRuntimeConfig() = (%+v, %v), want fail closed", config, err)
	}
}

func TestLoadBrandAssetRuntimeConfigMapsObjectStore(t *testing.T) {
	setValidBrandAssetRuntimeEnvironment(t)
	config, err := loadBrandAssetRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.ObjectStore.Endpoint != "http://127.0.0.1:19000" ||
		config.ObjectStore.Region != "us-east-1" || config.ObjectStore.Bucket != "brand-assets" ||
		config.ObjectStore.Prefix != "brand-assets" || config.ObjectStore.MaxAttempts != 3 {
		t.Fatalf("unexpected brand asset config: %s", config.ObjectStore.String())
	}
	credentials, err := config.ObjectStore.Credentials.Retrieve(context.Background())
	if err != nil || credentials.AccessKeyID != "brand-access" || credentials.SecretAccessKey != "brand-secret" ||
		credentials.SessionToken != "brand-session" {
		t.Fatalf("unexpected object store credentials: id=%q token=%q err=%v", credentials.AccessKeyID, credentials.SessionToken, err)
	}
}

func setValidBrandAssetRuntimeEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("BRAND_ASSET_RUNTIME_ENABLED", "true")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_ENDPOINT", "http://127.0.0.1:19000")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_REGION", "us-east-1")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_BUCKET", "brand-assets")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_PREFIX", "brand-assets")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_ACCESS_KEY_ID", "brand-access")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_SECRET_ACCESS_KEY", "brand-secret")
	t.Setenv("BRAND_ASSET_OBJECT_STORE_SESSION_TOKEN", "brand-session")
}
