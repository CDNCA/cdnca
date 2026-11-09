package helper

// Copied into an OLDER helper source tree by testdata/compat/generate.sh and
// run there: drives that release's helper Service through a v2 install, a v3
// install and a v2 rollback (the journal, current record and transaction
// staging an installed helper leaves behind) and serializes the whole state
// tree plus the receipt key files. compat_test.go in the current tree
// rebuilds it and makes the current helper take it over. Not compiled in the
// current tree (Go ignores testdata).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

type exportedEntry struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Mode    uint32 `json:"mode"`
	Content string `json:"content,omitempty"`
	Target  string `json:"target,omitempty"`
}

type exportedState struct {
	PackagePrivate string           `json:"package_private"`
	ReceiptKeyID   string           `json:"receipt_key_id"`
	Baseline       protocol.Receipt `json:"baseline"`
	V2Active       protocol.Receipt `json:"v2_active"`
	V3Active       protocol.Receipt `json:"v3_active"`
	RolledBack     protocol.Receipt `json:"rolled_back"`
	Entries        []exportedEntry  `json:"entries"`
}

func TestExportHelperStateForCompat(t *testing.T) {
	output := os.Getenv("CDNCA_HELPER_COMPAT_OUT")
	if output == "" {
		t.Skip("CDNCA_HELPER_COMPAT_OUT is not set")
	}
	fixture := newServiceFixture(t)
	root := filepath.Dir(fixture.paths.StateDirectory)
	// The receipt key files as key-init writes them, then the service signs with them.
	keyConfig := KeyConfig{
		PrivatePath: filepath.Join(fixture.paths.StateDirectory, "receipt-key.json"),
		PublicPath:  filepath.Join(root, "etc", "helper-receipt-public.json"),
		OwnerUID:    fixture.uid, OwnerGID: fixture.gid, AgentGID: fixture.gid,
	}
	for _, directory := range []string{fixture.paths.StateDirectory, filepath.Dir(keyConfig.PublicPath)} {
		if err := os.MkdirAll(directory, stateDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, stateDirMode); err != nil {
			t.Fatal(err)
		}
	}
	key, err := EnsureReceiptKey(keyConfig, "helper-compat-old")
	if err != nil {
		t.Fatal(err)
	}
	fixture.receiptKeyID, fixture.receiptPrivate = key.KeyID, key.PrivateKey
	fixture.receiptPublic = key.PrivateKey.Public().(ed25519.PublicKey)
	fixture.receiptPublicKeys = map[string]ed25519.PublicKey{key.KeyID: fixture.receiptPublic}
	fixture.service = fixture.newService()

	baseline := fixture.current()
	v2 := fixture.release(2, "1.0.1")
	prepared := fixture.handle(fixture.prepareRequest("txn-compat-v2", v2, baseline), fixture.artifact(v2))
	if !prepared.OK || prepared.PreparedAck == nil {
		t.Fatalf("v2 prepare = %#v", prepared)
	}
	if marked := fixture.handle(fixture.markInstallingRequest(*prepared.PreparedAck), nil); !marked.OK {
		t.Fatalf("v4 mark = %#v", marked)
	}
	activated := fixture.handle(fixture.activateRequest(*prepared.PreparedAck), nil)
	if !activated.OK || activated.Receipt == nil {
		t.Fatalf("v2 activate = %#v", activated)
	}
	v3Release := fixture.release(3, "1.0.2")
	v3 := fixture.activateV3("txn-compat-v3", 3, protocol.ActionUpgrade, v3Release, *activated.Receipt)
	rolled := fixture.handle(fixture.rollbackRequest("txn-compat-v3", v3Release, v3, *activated.Receipt), nil)
	if !rolled.OK || rolled.Receipt == nil {
		t.Fatalf("v1 rollback = %#v", rolled)
	}

	state := exportedState{
		PackagePrivate: base64.StdEncoding.EncodeToString(fixture.packagePrivate),
		ReceiptKeyID:   key.KeyID, Baseline: baseline, V2Active: *activated.Receipt, V3Active: v3, RolledBack: *rolled.Receipt,
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == root {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		entry := exportedEntry{Path: relative, Mode: uint32(info.Mode().Perm())}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			entry.Kind = "symlink"
			entry.Target, err = os.Readlink(path)
		case info.IsDir():
			entry.Kind = "dir"
		case info.Mode().IsRegular():
			entry.Kind = "file"
			var content []byte
			content, err = os.ReadFile(path)
			entry.Content = base64.StdEncoding.EncodeToString(content)
		default:
			t.Fatalf("unexpected state member %s", path)
		}
		state.Entries = append(state.Entries, entry)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(state, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
