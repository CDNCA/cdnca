package signerrevocationconsumer

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestLoadOfflineRoot(t *testing.T) {
	publicKey := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_KEY_ID", "")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_GENERATION", "")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_PUBLIC_KEY_BASE64", "")
	if _, configured, err := LoadOfflineRoot(); configured || err != nil {
		t.Fatalf("unset = %v, %v", configured, err)
	}
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_KEY_ID", "cdnca-offline-root")
	if _, configured, err := LoadOfflineRoot(); !configured || err == nil {
		t.Fatal("partial pin accepted")
	}
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_GENERATION", "2")
	t.Setenv(consumerEnvPrefix+"OFFLINE_ROOT_PUBLIC_KEY_BASE64", base64.RawURLEncoding.EncodeToString(publicKey))
	root, configured, err := LoadOfflineRoot()
	if !configured || err != nil || root.Generation != 2 || !root.PublicKey.Equal(publicKey) {
		t.Fatalf("root = %#v, %v", root, err)
	}
	if config := root.TrustConfig(); config.OfflineRootKeyID != "cdnca-offline-root" || config.OfflineRootGeneration != 2 {
		t.Fatalf("trust config = %#v", config)
	}
}
