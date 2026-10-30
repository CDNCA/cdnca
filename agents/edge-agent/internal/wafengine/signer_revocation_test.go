package wafengine

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
)

// A revoked platform release key stops an already installed extension from
// loading: the next Prepare re-verifies, finds no trusted signer and leaves
// the gate absent (CRS sites fall back to self-developed detection), and a
// new item signed by it is refused (signature_invalid). The revocation
// arrives the way production delivers it: a control-signed node signer trust
// bundle applied by gatewayclient.SignerTrustRuntime to the same TrustStore
// the manager reads (cmd/edge-agent waf_engine.go).
func TestRevokedSignerDisablesInstalledExtension(t *testing.T) {
	f := newFixture(t, true)
	controlSeed := sha256.Sum256([]byte("control publisher"))
	control := ed25519.NewKeyFromSeed(controlSeed[:])
	trust, err := gatewayclient.NewTrustStore(map[string]crypto.PublicKey{
		f.signer.KeyID: f.signer.Private.Public(), "edge-publish": control.Public()})
	if err != nil {
		t.Fatal(err)
	}
	signerTrust, err := gatewayclient.NewSignerTrustRuntime(filepath.Join(t.TempDir(), "signer-trust"), "node-1", trust, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.useManager(Trust{ReleaseKey: trust.Ed25519Key, Revoked: trust.RevokedEd25519})
	f.installDefault()
	if gate, err := f.manager.Prepare(context.Background(), "v1", f.release); err != nil || gate.ModulePath == "" {
		t.Fatalf("not revoked: gate=%+v err=%v", gate, err)
	}

	rootSeed := sha256.Sum256([]byte("offline root"))
	document, err := edgesignertrust.Normalize(edgesignertrust.Document{Schema: edgesignertrust.DocumentSchema, Revision: 1,
		IssuedAt: "2026-10-17T08:00:00Z", TrustedKeys: []edgesignertrust.TrustedKey{},
		RevokedKeys: []edgesignertrust.RevokedKey{{KeyID: f.signer.KeyID, RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"}}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := edgesignertrust.Sign(document, "offline-root", 1, ed25519.NewKeyFromSeed(rootSeed[:]))
	if err != nil {
		t.Fatal(err)
	}
	bundleDoc, err := edgesignertrust.NewBundle("node-1", signed, "edge-publish", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := edgesignertrust.BundleSigningPayload(bundleDoc)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := edgesignertrust.SealBundle(bundleDoc, ed25519.Sign(control, payload))
	if err != nil {
		t.Fatal(err)
	}
	if receipt := signerTrust.Apply(wire); receipt.Result != edgesignertrust.ResultApplied || receipt.Revision != 1 {
		t.Fatalf("receipt = %#v", receipt)
	}

	gate, err := f.manager.Prepare(context.Background(), "v1", f.release)
	if err != nil || gate.ModulePath != "" || len(f.gate()) != 0 {
		t.Fatalf("revoked signer still gated: %+v err=%v gate=%v", gate, err, f.gate())
	}
	if status := f.manager.Status(); status.State != StateDegraded || status.Reason != ReasonSignature {
		t.Fatalf("status = %+v", status)
	}
	err = f.install(bundle(t, []enginemoduletest.Signer{f.signer}, enginemoduletest.Options{Version: "3.0.18-1.0.4-1"}), "3.0.18-1.0.4-1")
	if artifactset.RejectReason(err) != artifactset.ReasonSignatureInvalid {
		t.Fatalf("new item by revoked signer: %v", err)
	}
}
