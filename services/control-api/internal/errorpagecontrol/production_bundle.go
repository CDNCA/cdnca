package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"

	"github.com/google/uuid"
)

const (
	ProductionBundleSchema    = "cdnca.edge.error-page-bundle/v1"
	ProductionBundleMediaType = "application/vnd.cdnca.edge-error-page-bundle+json;version=1"
)

var productionBundleIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type ProductionBundleSigner interface {
	SigningKeyID() string
	SigningPublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
}

type ProductionBundleBinding struct {
	TenantID    string `json:"tenant_id"`
	SiteID      string `json:"site_id"`
	Category    string `json:"category"`
	Revision    uint64 `json:"revision"`
	AssetSHA256 string `json:"asset_sha256"`
}

type ProductionBundleResource struct {
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
	Body     []byte `json:"body"`
}

type ProductionBundleDocument struct {
	Schema   string                   `json:"schema"`
	Binding  ProductionBundleBinding  `json:"binding"`
	RuleID   string                   `json:"rule_id"`
	Match    SnapshotMatch            `json:"match"`
	Resource ProductionBundleResource `json:"resource"`
}

type ProductionBundleRequest struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
	SiteID   uuid.UUID
	Category string
	Revision uint64
	RuleID   string
	Match    SnapshotMatch
	Asset    Asset
}

type ProductionBundleArtifact struct {
	WireBytes    []byte
	SHA256       string
	Signature    []byte
	SigningKeyID string
	MediaType    string
}

type ProductionBundleCompiler struct {
	store  ContentStore
	signer ProductionBundleSigner
}

func NewProductionBundleCompiler(store ContentStore, signer ProductionBundleSigner) (*ProductionBundleCompiler, error) {
	if store == nil || signer == nil || !store.Capabilities().runtimeReady() ||
		!productionBundleIdentifier.MatchString(signer.SigningKeyID()) || len(signer.SigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidStore
	}
	return &ProductionBundleCompiler{store: store, signer: signer}, nil
}

func (compiler *ProductionBundleCompiler) Build(ctx context.Context, request ProductionBundleRequest) (ProductionBundleArtifact, error) {
	if compiler == nil || compiler.store == nil || compiler.signer == nil || ctx == nil ||
		request.TenantID == uuid.Nil || request.ScopeID == uuid.Nil || request.SiteID == uuid.Nil || request.Revision == 0 ||
		!productionBundleIdentifier.MatchString(request.RuleID) || !validCategory(request.Category) ||
		request.Category == CategoryNoHost || request.Category == CategoryUnknownSite || !validProductionBundleMatch(request.Category, request.Match) {
		return ProductionBundleArtifact{}, ErrInvalidInput
	}
	asset := request.Asset
	if asset.ID == uuid.Nil || asset.TenantID == nil || *asset.TenantID != request.TenantID || asset.ScopeID != request.ScopeID ||
		asset.Status != StatusReady || asset.objectState != "final" || asset.DeletedAt != nil ||
		asset.storageObjectKey != "error-pages/objects/"+request.ScopeID.String()+"/"+asset.SHA256 {
		return ProductionBundleArtifact{}, ErrConflict
	}
	ref := assetObjectRef(asset, asset.storageObjectKey)
	info, err := compiler.store.Stat(ctx, ref)
	if err != nil {
		return ProductionBundleArtifact{}, wrapUnavailable("stat production error page object", err)
	}
	if validateObjectInfo(asset, info) != nil || info.ImmutableToken != "sha256:"+asset.SHA256 {
		return ProductionBundleArtifact{}, ErrConflict
	}
	reader, err := compiler.store.Open(ctx, ref, info.ImmutableToken)
	if err != nil {
		return ProductionBundleArtifact{}, wrapUnavailable("open production error page object", err)
	}
	body, readErr := readProductionBundleBody(reader, asset.SizeBytes)
	if readErr != nil {
		return ProductionBundleArtifact{}, readErr
	}
	if digestBytes(body) != asset.SHA256 || validateStaticBody(asset.MIMEType, body) != nil {
		return ProductionBundleArtifact{}, ErrUnsafeContent
	}
	document := ProductionBundleDocument{
		Schema: ProductionBundleSchema,
		Binding: ProductionBundleBinding{
			TenantID: request.TenantID.String(), SiteID: request.SiteID.String(), Category: request.Category,
			Revision: request.Revision, AssetSHA256: asset.SHA256,
		},
		RuleID: request.RuleID, Match: request.Match,
		Resource: ProductionBundleResource{MIMEType: asset.MIMEType, Size: asset.SizeBytes, SHA256: asset.SHA256, Body: body},
	}
	wire, err := json.Marshal(document)
	if err != nil || len(wire) == 0 || int64(len(wire)) > MaxEdgePolicyBytes {
		return ProductionBundleArtifact{}, ErrInvalidInput
	}
	signature, err := compiler.signer.Sign(ctx, wire)
	publicKey := compiler.signer.SigningPublicKey()
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, wire, signature) {
		return ProductionBundleArtifact{}, ErrUnavailable
	}
	digest := sha256.Sum256(wire)
	return ProductionBundleArtifact{
		WireBytes: append([]byte(nil), wire...), SHA256: hex.EncodeToString(digest[:]),
		Signature: append([]byte(nil), signature...), SigningKeyID: compiler.signer.SigningKeyID(), MediaType: ProductionBundleMediaType,
	}, nil
}

func validProductionBundleMatch(category string, match SnapshotMatch) bool {
	if len(match.Codes) == 1 && len(match.Ranges) == 0 {
		return categoryAllowsRange(category, match.Codes[0], match.Codes[0])
	}
	if len(match.Codes) == 0 && len(match.Ranges) == 1 {
		return categoryAllowsRange(category, match.Ranges[0].From, match.Ranges[0].To)
	}
	return false
}

func readProductionBundleBody(reader io.ReadCloser, size int64) ([]byte, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return nil, wrapUnavailable("read production error page object", err)
	}
	if int64(len(body)) != size {
		return nil, ErrConflict
	}
	return bytes.Clone(body), nil
}
