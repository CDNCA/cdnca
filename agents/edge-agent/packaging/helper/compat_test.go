package helper

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

// A helper binary refreshed by an upgrade takes over the state the helper
// installed before it left behind. testdata/compat/state-<ref>.json is that
// state as the helper of <ref> wrote it (generate.sh runs <ref>'s own code):
// 86c4d871 is the helper on installed nodes (every released helper so far).
func TestCurrentHelperTakesOverOlderHelperState(t *testing.T) {
	for _, ref := range []string{"86c4d871"} {
		t.Run(ref, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "compat", "state-"+ref+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var state struct {
				PackagePrivate string           `json:"package_private"`
				ReceiptKeyID   string           `json:"receipt_key_id"`
				Baseline       protocol.Receipt `json:"baseline"`
				V2Active       protocol.Receipt `json:"v2_active"`
				V3Active       protocol.Receipt `json:"v3_active"`
				RolledBack     protocol.Receipt `json:"rolled_back"`
				Entries        []struct {
					Path, Kind, Content, Target string
					Mode                        uint32
				} `json:"entries"`
			}
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			for _, entry := range state.Entries {
				path := filepath.Join(root, entry.Path)
				switch entry.Kind {
				case "dir":
					err = os.Mkdir(path, os.FileMode(entry.Mode))
				case "symlink":
					err = os.Symlink(entry.Target, path)
				case "file":
					var content []byte
					if content, err = base64.StdEncoding.DecodeString(entry.Content); err == nil {
						err = os.WriteFile(path, content, os.FileMode(entry.Mode))
					}
				default:
					t.Fatalf("unknown entry kind %q", entry.Kind)
				}
				if err == nil && entry.Kind != "symlink" {
					err = os.Chmod(path, os.FileMode(entry.Mode))
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			keyConfig := KeyConfig{
				PrivatePath: filepath.Join(root, "helper-state", "receipt-key.json"),
				PublicPath:  filepath.Join(root, "etc", "helper-receipt-public.json"),
				OwnerUID:    uid, OwnerGID: gid, AgentGID: gid,
			}
			// The receipt key and the public pin the Agent trusts are read as written.
			key, err := LoadReceiptKeyPair(keyConfig)
			if err != nil || key.KeyID != state.ReceiptKeyID {
				t.Fatalf("old receipt key: %v, %q", err, key.KeyID)
			}
			pin, err := LoadReceiptPublicPin(keyConfig)
			if err != nil || !publicPinMatches(pin, key) {
				t.Fatalf("old receipt pin: %v", err)
			}
			// key-init on the old state keeps the key (EnsureReceiptKey is what a
			// new helper runs at every start).
			if again, err := EnsureReceiptKey(keyConfig, key.KeyID); err != nil || !again.PrivateKey.Equal(key.PrivateKey) {
				t.Fatalf("key-init over the old key: %v", err)
			}
			packagePrivate, err := base64.StdEncoding.DecodeString(state.PackagePrivate)
			if err != nil {
				t.Fatal(err)
			}
			public := key.PrivateKey.Public().(ed25519.PublicKey)
			fixture := &serviceFixture{
				t: t, paths: RuntimePaths{
					StateDirectory:   filepath.Join(root, "helper-state"),
					ReleaseRoot:      filepath.Join(root, "usr", "lib", "cdnca-edge-agent"),
					AcceptedManifest: filepath.Join(root, "var", "lib", "cdnca-edge-agent-packaging", "accepted-manifest"),
				},
				packagePrivate: ed25519.PrivateKey(packagePrivate),
				packagePublic:  ed25519.PrivateKey(packagePrivate).Public().(ed25519.PublicKey),
				receiptPrivate: key.PrivateKey, receiptPublic: public, receiptKeyID: key.KeyID,
				receiptPublicKeys: map[string]ed25519.PublicKey{key.KeyID: public},
				now:               time.Date(2026, 11, 9, 4, 0, 0, 0, time.UTC), uid: uid, gid: gid,
			}
			fixture.runner = &serviceRunner{paths: fixture.paths}
			fixture.service = fixture.newService()

			// The old journal and current record read back unchanged.
			current := fixture.current()
			fixture.verifyReceipt(current)
			if current.CurrentVersion != "1.0.1" || current.ReleaseSequence != state.RolledBack.ReleaseSequence {
				t.Fatalf("current over old state = %+v", current)
			}
			// v3 state is a ratchet: v2 requests stay refused, as with the old helper.
			if refused := fixture.handle(fixture.inspectRequest("txn-compat-v2"), nil); refused.ErrorCode != protocol.ErrorProtocol {
				t.Fatalf("v2 inspect over v3 state = %#v", refused)
			}
			for transaction, phase := range map[string]string{"txn-compat-v3": "rolled_back"} {
				inspect := fixture.inspectRequest(transaction)
				inspect.ProtocolVersion = protocol.JournalV3Version
				inspected := fixture.handle(inspect, nil)
				if !inspected.OK || inspected.TransactionStatus == nil || string(inspected.TransactionStatus.Phase) != phase {
					t.Fatalf("inspect %s = %#v", transaction, inspected)
				}
			}
			// Replaying the old rollback returns the receipt the old helper signed.
			v3Release := fixture.release(3, "1.0.2")
			replayed := fixture.handle(fixture.rollbackRequest("txn-compat-v3", v3Release, state.V3Active, state.V2Active), nil)
			if !replayed.OK || replayed.Receipt == nil || *replayed.Receipt != state.RolledBack {
				t.Fatalf("rollback replay = %#v, want %+v", replayed, state.RolledBack)
			}
			if fixture.runner.rollbackCalls != 0 {
				t.Fatalf("replay ran the rollback script %d times", fixture.runner.rollbackCalls)
			}
			// And it keeps working: upgrade and roll back with the old key and journal.
			next := fixture.release(4, "1.0.3")
			upgraded := fixture.activateV3("txn-compat-next", 4, protocol.ActionUpgrade, next, current)
			fixture.verifyReceipt(upgraded)
			back := fixture.handle(fixture.rollbackRequest("txn-compat-next", next, upgraded, current), nil)
			if !back.OK || back.Receipt == nil || back.Receipt.CurrentVersion != "1.0.1" || back.Receipt.Status != "rolled_back" {
				t.Fatalf("rollback after takeover = %#v", back)
			}
			fixture.verifyReceipt(*back.Receipt)
			if stale := fixture.handle(fixture.prepareRequest("txn-compat-stale", fixture.release(3, "1.0.2"), *back.Receipt), fixture.artifact(fixture.release(3, "1.0.2"))); stale.OK {
				t.Fatalf("old release sequence accepted after takeover: %#v", stale)
			}
		})
	}
}
