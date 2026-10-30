package pluginuihttp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The developer SDK verifier (docs/developer/examples/plugin-ui-sdk) is
// checked against this vector: same signature domain, message layout and
// context encoding as forward. CDNCA_WRITE_SDK_VECTOR=1 rewrites it.
const sdkVectorPath = "../../../../docs/developer/examples/plugin-ui-sdk/proxy-vector.json"

func TestDeveloperSDKProxyVector(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	signer := Signer{InstallationID: uuid.MustParse("0199aaaa-0000-7000-8000-000000000001"),
		PrivateKey: ed25519.NewKeyFromSeed(seed)}
	issued := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	siteID := uuid.MustParse("0199aaaa-0000-7000-8000-000000000003")
	callContext := Context{Schema: ContextSchema, InstallationID: signer.InstallationID, PluginID: "acme.reports",
		PageID: "report", UserID: uuid.MustParse("0199aaaa-0000-7000-8000-000000000002"), DisplayName: "管理员",
		Role: "admin", TenantScopeID: uuid.MustParse("0199aaaa-0000-7000-8000-000000000004"), SiteID: &siteID,
		Locale: "zh-CN", RequestID: "req-1", Nonce: "AAAAAAAAAAAAAAAAAAAAAA", IssuedAt: issued,
		ExpiresAt: issued.Add(proxyContextTTL)}
	encoded, err := json.Marshal(callContext)
	if err != nil {
		t.Fatal(err)
	}
	contextHeader := base64.RawURLEncoding.EncodeToString(encoded)
	body := []byte(`{"range":"7d"}`)
	target := "/reports/run?site=1"
	signature := ed25519.Sign(signer.PrivateKey, SignatureMessage("POST", target, body, contextHeader))
	vector := map[string]any{
		"public_key": signer.PublicKey(), "key_id": signer.KeyID(), "api_base_path": "/v1",
		"method": "POST", "path_with_query": "/v1" + target, "body": string(body),
		"headers": map[string]string{"X-Cdnca-Plugin-Context": contextHeader,
			"X-Cdnca-Plugin-Signature": base64.RawURLEncoding.EncodeToString(signature), "X-Cdnca-Plugin-Key-Id": signer.KeyID()},
		"now": issued.Add(10 * time.Second).Format(time.RFC3339),
	}
	want, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if os.Getenv("CDNCA_WRITE_SDK_VECTOR") == "1" {
		if err := os.WriteFile(sdkVectorPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(sdkVectorPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("developer SDK vector is stale (CDNCA_WRITE_SDK_VECTOR=1 go test -run TestDeveloperSDKProxyVector): %v", err)
	}
}
