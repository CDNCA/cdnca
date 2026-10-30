package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/uuid"
)

type site13SnapshotStore struct {
	objects map[string]struct {
		info ObjectInfo
		body []byte
	}
}

func (*site13SnapshotStore) Capabilities() ObjectStoreCapabilities {
	return ObjectStoreCapabilities{ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true, ImmutableReads: true, PreservesStagingAlias: true}
}
func (*site13SnapshotStore) PutStaging(context.Context, ObjectRef, []byte, string) (ObjectInfo, error) {
	return ObjectInfo{}, ErrUnavailable
}
func (store *site13SnapshotStore) Open(_ context.Context, ref ObjectRef, token string) (io.ReadCloser, error) {
	object, found := store.objects[site13SnapshotObjectKey(ref)]
	if !found || token != object.info.ImmutableToken {
		return nil, ErrConflict
	}
	return io.NopCloser(bytes.NewReader(object.body)), nil
}
func (*site13SnapshotStore) Finalize(context.Context, ObjectRef, ObjectRef, ObjectInfo) (ObjectInfo, error) {
	return ObjectInfo{}, ErrUnavailable
}
func (store *site13SnapshotStore) Stat(_ context.Context, ref ObjectRef) (ObjectInfo, error) {
	object, found := store.objects[site13SnapshotObjectKey(ref)]
	if !found {
		return ObjectInfo{}, ErrObjectNotFound
	}
	return object.info, nil
}
func (*site13SnapshotStore) Delete(context.Context, ObjectRef) error { return ErrUnavailable }

func TestSITE13AggregateSnapshotKeepsGlobalAndEveryTenantSiteInCanonicalOrder(t *testing.T) {
	tenantID, scopeID, platformScopeID := uuid.New(), uuid.New(), uuid.New()
	siteA, siteB, otherSite := uuid.New(), uuid.New(), uuid.New()
	globalBody, siteABody, siteBBody := []byte("global\n"), []byte("site-a\n"), []byte("site-b\n")
	global := site13SnapshotRule(t, uuid.NewString(), CategoryNoHost, 400, globalBody)
	ruleA := site13SnapshotRule(t, uuid.NewString(), CategoryEdgeRoute, 404, siteABody)
	ruleB := site13SnapshotRule(t, uuid.NewString(), CategoryOriginResponse, 503, siteBBody)
	other := site13SnapshotRule(t, uuid.NewString(), CategoryEdgeRoute, 404, []byte("other\n"))
	snapshot := Snapshot{
		Schema: SchemaV1, Version: "control-73", Revision: 73,
		Global: SnapshotScope{Rules: []SnapshotRule{global}},
		Sites: []SnapshotSite{
			{SiteKey: siteB.String(), Rules: []SnapshotRule{ruleB}},
			{SiteKey: otherSite.String(), Rules: []SnapshotRule{other}},
			{SiteKey: siteA.String(), Rules: []SnapshotRule{ruleA}},
		},
	}
	store := &site13SnapshotStore{objects: make(map[string]struct {
		info ObjectInfo
		body []byte
	})}
	site13PutSnapshotObject(store, platformScopeID, nil, global.Resource, globalBody)
	site13PutSnapshotObject(store, scopeID, &tenantID, ruleA.Resource, siteABody)
	site13PutSnapshotObject(store, scopeID, &tenantID, ruleB.Resource, siteBBody)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x74}, ed25519.SeedSize))
	compiler, err := NewProductionSnapshotCompiler(store, site13BundleSigner{private: private})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.buildSelected(t.Context(), productionSnapshotSource{
		TenantID: tenantID, ScopeID: scopeID, PlatformScopeID: platformScopeID,
		SiteIDs: map[string]struct{}{siteA.String(): {}, siteB.String(): {}}, Policy: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	var document ProductionSnapshotDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	if document.Binding != (ProductionSnapshotBinding{
		TenantID: tenantID.String(), ConfigurationScopeID: scopeID.String(), PublicationRevision: 73,
	}) || len(document.Global.Rules) != 1 || len(document.Sites) != 2 ||
		document.Sites[0].SiteKey > document.Sites[1].SiteKey || document.Sites[0].SiteKey == otherSite.String() ||
		document.Sites[1].SiteKey == otherSite.String() || !bytes.Equal(document.Global.Rules[0].Resource.Body, globalBody) ||
		artifact.SHA256 != fmtSHA256(sha256.Sum256(artifact.WireBytes)) ||
		!ed25519.Verify(private.Public().(ed25519.PublicKey), artifact.WireBytes, artifact.Signature) {
		t.Fatalf("artifact=%+v document=%+v", artifact, document)
	}
}

func site13SnapshotRule(t *testing.T, id, category string, status int, body []byte) SnapshotRule {
	t.Helper()
	digest := fmtSHA256(sha256.Sum256(body))
	return SnapshotRule{ID: id, Category: category, Match: SnapshotMatch{Codes: []int{status}},
		Resource: SnapshotResource{MIMEType: "text/plain", Size: int64(len(body)), SHA256: digest, File: "sha256/" + digest}}
}

func site13PutSnapshotObject(store *site13SnapshotStore, scopeID uuid.UUID, tenantID *uuid.UUID, resource SnapshotResource, body []byte) {
	ref := ObjectRef{TenantID: tenantID, ScopeID: scopeID, LogicalKey: "error-pages/objects/" + scopeID.String() + "/" + resource.SHA256}
	store.objects[site13SnapshotObjectKey(ref)] = struct {
		info ObjectInfo
		body []byte
	}{info: ObjectInfo{Size: resource.Size, SHA256: resource.SHA256, MIMEType: resource.MIMEType, ImmutableToken: "sha256:" + resource.SHA256}, body: bytes.Clone(body)}
}

func site13SnapshotObjectKey(ref ObjectRef) string {
	tenant := "platform"
	if ref.TenantID != nil {
		tenant = ref.TenantID.String()
	}
	return tenant + "/" + ref.ScopeID.String() + "/" + ref.LogicalKey
}
