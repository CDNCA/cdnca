package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type site13BundleSigner struct {
	private ed25519.PrivateKey
}

func (signer site13BundleSigner) SigningKeyID() string { return "error-page-signing-v1" }
func (signer site13BundleSigner) SigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer site13BundleSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type site13BundleStore struct {
	ref   ObjectRef
	info  ObjectInfo
	body  []byte
	opens int
}

func (store *site13BundleStore) Capabilities() ObjectStoreCapabilities {
	return ObjectStoreCapabilities{ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true, ImmutableReads: true, PreservesStagingAlias: true}
}
func (*site13BundleStore) PutStaging(context.Context, ObjectRef, []byte, string) (ObjectInfo, error) {
	return ObjectInfo{}, ErrUnavailable
}
func (store *site13BundleStore) Open(_ context.Context, ref ObjectRef, token string) (io.ReadCloser, error) {
	if ref != store.ref || token != store.info.ImmutableToken {
		return nil, ErrConflict
	}
	store.opens++
	return io.NopCloser(bytes.NewReader(store.body)), nil
}
func (*site13BundleStore) Finalize(context.Context, ObjectRef, ObjectRef, ObjectInfo) (ObjectInfo, error) {
	return ObjectInfo{}, ErrUnavailable
}
func (store *site13BundleStore) Stat(_ context.Context, ref ObjectRef) (ObjectInfo, error) {
	if ref != store.ref {
		return ObjectInfo{}, ErrObjectNotFound
	}
	return store.info, nil
}
func (*site13BundleStore) Delete(context.Context, ObjectRef) error { return ErrUnavailable }

func TestSITE13ProductionBundleBuildsFromImmutableContentAddressedObject(t *testing.T) {
	tenantID, scopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	body := []byte("production error page\n")
	digest := sha256.Sum256(body)
	digestHex := strings.Repeat("0", 64)
	digestHex = fmtSHA256(digest)
	asset := Asset{
		ID: uuid.New(), ScopeID: scopeID, TenantID: &tenantID, MIMEType: "text/plain",
		SizeBytes: int64(len(body)), SHA256: digestHex, Status: StatusReady, Revision: 4,
		storageObjectKey: "error-pages/objects/" + scopeID.String() + "/" + digestHex,
		objectState:      "final",
	}
	ref := assetObjectRef(asset, asset.storageObjectKey)
	store := &site13BundleStore{ref: ref, body: body, info: ObjectInfo{
		Size: int64(len(body)), SHA256: digestHex, MIMEType: asset.MIMEType, ImmutableToken: "sha256:" + digestHex,
	}}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	compiler, err := NewProductionBundleCompiler(store, site13BundleSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	request := ProductionBundleRequest{
		TenantID: tenantID, ScopeID: scopeID, SiteID: siteID, Category: CategoryEdgeRoute,
		Revision: 7, RuleID: uuid.NewString(), Match: SnapshotMatch{Codes: []int{404}}, Asset: asset,
	}
	artifact, err := compiler.Build(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if store.opens != 1 || artifact.MediaType != ProductionBundleMediaType || artifact.SigningKeyID != "error-page-signing-v1" ||
		artifact.SHA256 != fmtSHA256(sha256.Sum256(artifact.WireBytes)) || !ed25519.Verify(private.Public().(ed25519.PublicKey), artifact.WireBytes, artifact.Signature) {
		t.Fatalf("artifact=%+v opens=%d", artifact, store.opens)
	}
	var document ProductionBundleDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	if document.Binding.TenantID != tenantID.String() || document.Binding.SiteID != siteID.String() ||
		document.Binding.Category != CategoryEdgeRoute || document.Binding.Revision != 7 ||
		document.Binding.AssetSHA256 != digestHex || !bytes.Equal(document.Resource.Body, body) ||
		document.Resource.SHA256 != digestHex {
		t.Fatalf("document=%+v", document)
	}
}

func TestSITE13ProductionBundleRejectsUnreadyOrMismatchedObject(t *testing.T) {
	tenantID, scopeID, siteID := uuid.New(), uuid.New(), uuid.New()
	body := []byte("safe\n")
	digest := sha256.Sum256(body)
	digestHex := fmtSHA256(digest)
	asset := Asset{ID: uuid.New(), ScopeID: scopeID, TenantID: &tenantID, MIMEType: "text/plain", SizeBytes: int64(len(body)), SHA256: digestHex,
		Status: StatusReady, storageObjectKey: "error-pages/objects/" + scopeID.String() + "/" + digestHex, objectState: "final"}
	ref := assetObjectRef(asset, asset.storageObjectKey)
	store := &site13BundleStore{ref: ref, body: body, info: ObjectInfo{Size: int64(len(body)), SHA256: digestHex, MIMEType: "text/plain", ImmutableToken: "sha256:" + digestHex}}
	compiler, err := NewProductionBundleCompiler(store, site13BundleSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	base := ProductionBundleRequest{TenantID: tenantID, ScopeID: scopeID, SiteID: siteID, Category: CategoryEdgeRoute, Revision: 1,
		RuleID: uuid.NewString(), Match: SnapshotMatch{Codes: []int{404}}, Asset: asset}
	for name, mutate := range map[string]func(*ProductionBundleRequest){
		"tenant":   func(request *ProductionBundleRequest) { request.TenantID = uuid.New() },
		"scope":    func(request *ProductionBundleRequest) { request.ScopeID = uuid.New() },
		"site":     func(request *ProductionBundleRequest) { request.SiteID = uuid.Nil },
		"category": func(request *ProductionBundleRequest) { request.Category = "unknown" },
		"revision": func(request *ProductionBundleRequest) { request.Revision = 0 },
		"digest":   func(request *ProductionBundleRequest) { request.Asset.SHA256 = strings.Repeat("0", 64) },
		"status":   func(request *ProductionBundleRequest) { request.Asset.Status = StatusStaged },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := compiler.Build(t.Context(), request); err == nil {
				t.Fatal("invalid production bundle source was accepted")
			}
		})
	}
}

func fmtSHA256(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, sha256.Size*2)
	for index, item := range value {
		encoded[index*2] = digits[item>>4]
		encoded[index*2+1] = digits[item&0x0f]
	}
	return string(encoded)
}
