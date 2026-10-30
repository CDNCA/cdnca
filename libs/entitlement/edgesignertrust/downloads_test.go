package edgesignertrust

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

)

func artifactPEM(t *testing.T, label string) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(testKey(label).Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestPublishDownloadsRefreshesArtifactTrust(t *testing.T) {
	dir := t.TempDir()
	current, _ := json.Marshal(artifactTrustDocument{Version: 1, Keys: []artifactTrustEntry{
		{KeyID: "release-old", PublicKeyPEM: artifactPEM(t, "release old")},
		{KeyID: "edge-publish", PublicKeyPEM: artifactPEM(t, "control publisher")},
		{KeyID: "release-renamed", PublicKeyPEM: artifactPEM(t, "release renamed")},
	}})
	if err := os.WriteFile(filepath.Join(dir, artifactTrustName), current, 0o644); err != nil {
		t.Fatal(err)
	}
	renamed, _ := ParsePublicKeyPEM(artifactPEM(t, "release renamed"))
	renamedPrint, _ := PublicKeySHA256(renamed)
	document := Document{Schema: DocumentSchema, Revision: 1, IssuedAt: "2026-10-17T08:00:00Z",
		TrustedKeys: []TrustedKey{{KeyID: "release-new", PublicKeyPEM: artifactPEM(t, "release")},
			{KeyID: "edge-publish", PublicKeyPEM: artifactPEM(t, "someone else")}},
		RevokedKeys: []RevokedKey{
			{KeyID: "release-old", RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"},
			{KeyID: "x-old-name", PublicKeySHA256: renamedPrint, RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"}}}
	document, err := Normalize(document)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Sign(document, "offline-root", 1, testKey("root"))
	if err != nil {
		t.Fatal(err)
	}
	conflicts, err := PublishDownloads(dir, encoded)
	if err != nil || len(conflicts) != 1 || conflicts[0] != "edge-publish" {
		t.Fatalf("publish = %v, %v", conflicts, err)
	}
	rendered, _ := os.ReadFile(filepath.Join(dir, artifactTrustName))
	var result artifactTrustDocument
	if err := json.Unmarshal(rendered, &result); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, key := range result.Keys {
		ids = append(ids, key.KeyID)
	}
	if strings.Join(ids, ",") != "edge-publish,release-new" || result.Keys[0].PublicKeyPEM != artifactPEM(t, "control publisher") {
		t.Fatalf("artifacts.json keys = %v", ids)
	}
	published, _ := os.ReadFile(filepath.Join(dir, signerTrustName))
	if string(published) != string(encoded) {
		t.Fatal("signer-trust.json is not the exact document")
	}
	info, _ := os.Stat(filepath.Join(dir, artifactTrustName))
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if _, err := PublishDownloads(dir, encoded); err != nil {
		t.Fatalf("idempotent publish: %v", err)
	}
	everything := document
	everything.Revision = 2
	everything.TrustedKeys = []TrustedKey{}
	everything.RevokedKeys = append(everything.RevokedKeys, RevokedKey{KeyID: "edge-publish",
		RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"}, RevokedKey{KeyID: "release-new",
		RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"})
	everything, _ = Normalize(everything)
	allRevoked, _ := Sign(everything, "offline-root", 1, testKey("root"))
	copies, _, err := PublishDownloadCopies(dir, allRevoked)
	if err == nil || len(copies) != 2 || copies[0] != (DownloadCopy{Name: signerTrustName, Status: DownloadCopySkipped,
		Reason: "artifact_trust_failed"}) || copies[1] != (DownloadCopy{Name: artifactTrustName, Status: DownloadCopyFailed,
		Reason: "every_key_revoked"}) {
		t.Fatalf("a document revoking every key: %+v %v", copies, err)
	}
	copies, _, err = PublishDownloadCopies(dir, encoded)
	if err != nil || copies[0].Status != DownloadCopyUnchanged || copies[1].Status != DownloadCopyUnchanged {
		t.Fatalf("unchanged copies = %+v %v", copies, err)
	}
}

func TestDownloadsSkipInstallationBanKeys(t *testing.T) {
	document := Document{Schema: DocumentSchema, Revision: 1, IssuedAt: "2026-10-17T08:00:00Z",
		TrustedKeys: []TrustedKey{
			{KeyID: "license-lease-1", PublicKeyPEM: artifactPEM(t, "lease"), Usage: UsageInstallationBan},
			{KeyID: "release-new", PublicKeyPEM: artifactPEM(t, "release")},
		}, RevokedKeys: []RevokedKey{}}
	current := `{"version":1,"keys":[{"key_id":"release-old","public_key_pem":` + mustJSON(t, artifactPEM(t, "old")) + `}]}`
	encoded, _, err := RenderArtifactTrust([]byte(current), document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "license-lease-1") || !strings.Contains(string(encoded), "release-new") {
		t.Fatalf("artifact trust = %s", encoded)
	}
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
