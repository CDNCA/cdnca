package originauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// The sealed per-node snapshot also yields one worker-readable secret object
// per rule (dynamic routing D5b): 0440 under a 0750 directory, the
// credential inline, the policy file and the agent's key copy unchanged;
// two revisions kept, withdrawn rules removed, a revision never rewritten.
func TestSecretObjectsFromSealedSnapshot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &site09Runtime{}
	installer, err := NewProductionSnapshotInstaller(filepath.Join(root, "policy"), filepath.Join(root, "credentials"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"relative", filepath.Join(root, "policy"), filepath.Join(root, "credentials")} {
		if installer.WithSecretObjects(SecretObjectDir{Root: bad, GID: -1}) == nil {
			t.Fatalf("secret root %q accepted", bad)
		}
	}
	dir := SecretObjectDir{Root: filepath.Join(root, "secret-objects"), GID: -1}
	if err := installer.WithSecretObjects(dir); err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate := site09Recipient(t)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	scopeID, tenantID, nodeID := uuid.New(), uuid.New(), uuid.New()
	ruleA, ruleB, refA, refB, refA2 := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	install := func(revision uint64, rules []productionSnapshotRule, credentials []productionSnapshotCredential) error {
		_, err := installer.Install(t.Context(), site09EncryptedSnapshot(t, signer, recipientPublic, recipientPrivate,
			scopeID, tenantID, nodeID, revision, rules, credentials))
		return err
	}
	if err := install(1, []productionSnapshotRule{site09Rule(ruleA, uuid.New(), 1, refA), site09Rule(ruleB, uuid.New(), 1, refB)},
		[]productionSnapshotCredential{site09Credential(refA, ProviderS3, "AKIA-A"), site09Credential(refB, ProviderS3, "AKIA-B")}); err != nil {
		t.Fatal(err)
	}
	read := func(rule uuid.UUID, revision uint64) SecretObject {
		t.Helper()
		path := dir.Path(rule.String(), revision)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o440 {
			t.Fatalf("%s: %v %v", path, info, err)
		}
		if parent, _ := os.Stat(filepath.Dir(path)); parent.Mode().Perm() != 0o750 {
			t.Fatalf("directory mode %v", parent.Mode())
		}
		raw, _ := os.ReadFile(path)
		var object SecretObject
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	object := read(ruleA, 1)
	if object.Schema != SecretObjectSchema || object.RuleID != ruleA.String() || object.Revision != 1 ||
		object.Rule.CurrentKey.KeyID != refA.String() || object.Rule.CurrentKey.Credential.AccessKeyID != "AKIA-A" ||
		object.Rule.Endpoint.Host != "s3.us-east-1.amazonaws.com" || object.Rule.PreviousKey != nil {
		t.Fatalf("object %+v", object)
	}
	// The policy file still has no credential (v7 contract unchanged).
	policy, _ := os.ReadFile(filepath.Join(root, "policy", "current.json"))
	if bytes.Contains(policy, []byte("AKIA-A")) || bytes.Contains(policy, []byte("site09-secret")) {
		t.Fatal("credential in the policy file")
	}

	// Rotation: rule A previous key = refA, current = refA2; rule B withdrawn.
	rotated := site09Rule(ruleA, uuid.New(), 1, refA2)
	rotatedPrevious := refA.String()
	rotated.PreviousCredentialRevisionRef, rotated.ActivateCurrentAtUnix = &rotatedPrevious, 1_800_000_000
	for revision := uint64(2); revision <= 3; revision++ {
		if err := install(revision, []productionSnapshotRule{rotated},
			[]productionSnapshotCredential{site09Credential(refA, ProviderS3, "AKIA-A"), site09Credential(refA2, ProviderS3, "AKIA-A2")}); err != nil {
			t.Fatal(err)
		}
	}
	object = read(ruleA, 3)
	if object.Rule.PreviousKey == nil || object.Rule.PreviousKey.Credential.AccessKeyID != "AKIA-A" ||
		object.Rule.CurrentKey.Credential.AccessKeyID != "AKIA-A2" || object.Rule.ActivateCurrentAtUnix != 1_800_000_000 {
		t.Fatalf("rotated %+v", object.Rule)
	}
	read(ruleA, 2)
	if _, err := os.Stat(dir.Path(ruleA.String(), 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("third-newest revision kept")
	}
	if _, err := os.Stat(filepath.Join(dir.Root, ruleB.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("withdrawn rule kept")
	}
	// A revision never changes under its number.
	changed := SecretObject{Schema: SecretObjectSchema, RuleID: ruleA.String(), Revision: 3, Rule: object.Rule}
	changed.Rule.SignatureTTLSeconds++
	if err := dir.Write([]SecretObject{changed}); !errors.Is(err, ErrSecretObject) {
		t.Fatalf("rewrite of revision 3: %v", err)
	}
}
