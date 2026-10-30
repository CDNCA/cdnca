package errorpage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	ProductionBundleSchema            = "cdnca.edge.error-page-bundle/v1"
	ProductionBundleMediaType         = "application/vnd.cdnca.edge-error-page-bundle+json;version=1"
	ActivationReceiptSchema           = "cdnca.edge.error-page-activation-receipt/v1"
	ActivationStateActivated          = "activated"
	ActivationStateFailed             = "failed"
	ActivationReasonBundleIntegrity   = "bundle_integrity_failed"
	ActivationReasonBindingMismatch   = "binding_mismatch"
	ActivationReasonPayloadInvalid    = "payload_invalid"
	ActivationReasonPrecheckFailed    = "precheck_failed"
	ActivationReasonActivationFailed  = "activation_failed"
	ActivationReasonHealthFailed      = "health_failed"
	ActivationReasonRollbackFailed    = "rollback_failed"
	ActivationReasonPublicationFailed = "publication_failed"
)

var ErrInvalidProductionBundle = errors.New("invalid signed production error page bundle")

type ProductionBundleBinding struct {
	TenantID    string   `json:"tenant_id"`
	SiteID      string   `json:"site_id"`
	Category    Category `json:"category"`
	Revision    uint64   `json:"revision"`
	AssetSHA256 string   `json:"asset_sha256"`
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
	Match    StatusMatch              `json:"match"`
	Resource ProductionBundleResource `json:"resource"`
}

type SignedProductionBundle struct {
	WireBytes    []byte
	SHA256       string
	Signature    []byte
	SigningKeyID string
}

type ProductionBundleKeyResolver interface {
	ResolveProductionBundleKey(context.Context, string) (ed25519.PublicKey, error)
}

type ActivationReceipt struct {
	Schema                 string                  `json:"schema"`
	State                  string                  `json:"state"`
	ReasonCode             string                  `json:"reason_code,omitempty"`
	Binding                ProductionBundleBinding `json:"binding"`
	BundleSHA256           string                  `json:"bundle_sha256"`
	ActiveDigest           string                  `json:"active_digest"`
	PreviousDigest         string                  `json:"previous_digest,omitempty"`
	RunningConfigUnchanged bool                    `json:"running_config_unchanged"`
}

type ReconcileReceipt struct {
	RemovedOrphans  int
	CurrentRevision uint64
	LKGRevision     uint64
}

type ProductionBundleInstaller struct {
	publisher *Publisher
	keys      ProductionBundleKeyResolver
}

func NewProductionBundleInstaller(publisher *Publisher, keys ProductionBundleKeyResolver) (*ProductionBundleInstaller, error) {
	if publisher == nil || publisher.runtime == nil || keys == nil {
		return nil, ErrInvalidProductionBundle
	}
	return &ProductionBundleInstaller{publisher: publisher, keys: keys}, nil
}

func (installer *ProductionBundleInstaller) Install(ctx context.Context, bundle SignedProductionBundle, expected ProductionBundleBinding) (ActivationReceipt, error) {
	receipt := ActivationReceipt{Schema: ActivationReceiptSchema, State: ActivationStateFailed, Binding: expected,
		BundleSHA256: bundle.SHA256, RunningConfigUnchanged: true}
	if installer == nil || installer.publisher == nil || installer.keys == nil || ctx == nil || !validProductionBinding(expected) ||
		len(bundle.WireBytes) == 0 || len(bundle.WireBytes) > MaxArtifactBytes || !validDigest(bundle.SHA256) ||
		len(bundle.Signature) != ed25519.SignatureSize || !identifierPattern.MatchString(bundle.SigningKeyID) {
		receipt.ReasonCode = ActivationReasonBundleIntegrity
		return receipt, ErrInvalidProductionBundle
	}
	digest := sha256.Sum256(bundle.WireBytes)
	if hex.EncodeToString(digest[:]) != bundle.SHA256 {
		receipt.ReasonCode = ActivationReasonBundleIntegrity
		return receipt, ErrInvalidProductionBundle
	}
	key, err := installer.keys.ResolveProductionBundleKey(ctx, bundle.SigningKeyID)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, bundle.WireBytes, bundle.Signature) {
		receipt.ReasonCode = ActivationReasonBundleIntegrity
		return receipt, ErrInvalidProductionBundle
	}
	document, err := decodeProductionBundle(bundle.WireBytes)
	if err != nil {
		receipt.ReasonCode = ActivationReasonPayloadInvalid
		return receipt, err
	}
	if document.Binding != expected {
		receipt.ReasonCode = ActivationReasonBindingMismatch
		return receipt, ErrInvalidProductionBundle
	}
	policy, err := productionBundlePolicy(document)
	if err != nil {
		receipt.ReasonCode = ActivationReasonPayloadInvalid
		return receipt, err
	}
	result, err := installer.publisher.Apply(ctx, policy)
	if err != nil {
		receipt.ReasonCode = productionBundleFailureReason(err)
		return receipt, err
	}
	receipt.State = ActivationStateActivated
	receipt.ReasonCode = ""
	receipt.ActiveDigest = result.Digest
	receipt.PreviousDigest = result.PreviousDigest
	receipt.RunningConfigUnchanged = !result.Changed
	return receipt, nil
}

func (installer *ProductionBundleInstaller) Reconcile(ctx context.Context) (ReconcileReceipt, error) {
	if installer == nil || installer.publisher == nil || ctx == nil {
		return ReconcileReceipt{}, ErrInvalidProductionBundle
	}
	if err := ctx.Err(); err != nil {
		return ReconcileReceipt{}, err
	}
	removed, err := installer.publisher.reconcileProductionBundleOrphans()
	if err != nil {
		return ReconcileReceipt{}, err
	}
	receipt := ReconcileReceipt{RemovedOrphans: removed}
	if current, found, err := installer.publisher.Current(); err != nil {
		return ReconcileReceipt{}, err
	} else if found {
		receipt.CurrentRevision = current.Revision
	}
	if lkg, found, err := installer.publisher.LKG(); err != nil {
		return ReconcileReceipt{}, err
	} else if found {
		receipt.LKGRevision = lkg.Revision
	}
	return receipt, nil
}

func decodeProductionBundle(raw []byte) (ProductionBundleDocument, error) {
	if edgeconfig.RejectDuplicateJSONKeys(raw) != nil {
		return ProductionBundleDocument{}, ErrInvalidProductionBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ProductionBundleDocument
	if err := decoder.Decode(&document); err != nil {
		return ProductionBundleDocument{}, ErrInvalidProductionBundle
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ProductionBundleDocument{}, ErrInvalidProductionBundle
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ProductionBundleDocument{}, ErrInvalidProductionBundle
	}
	return document, nil
}

func productionBundlePolicy(document ProductionBundleDocument) (Policy, error) {
	if document.Schema != ProductionBundleSchema || !validProductionBinding(document.Binding) ||
		!identifierPattern.MatchString(document.RuleID) || document.Resource.MIMEType == "" ||
		document.Resource.Size != int64(len(document.Resource.Body)) || document.Resource.Size < 1 ||
		document.Resource.Size > MaxResourceBytes || document.Resource.SHA256 != document.Binding.AssetSHA256 ||
		document.Resource.SHA256 != digestProductionResource(document.Resource.Body) {
		return Policy{}, ErrInvalidProductionBundle
	}
	inline := string(document.Resource.Body)
	rule := Rule{ID: document.RuleID, Category: document.Binding.Category, Match: document.Match,
		Resource: Resource{MIMEType: document.Resource.MIMEType, Size: document.Resource.Size, SHA256: document.Resource.SHA256, Inline: &inline}}
	policy := Policy{Schema: SchemaV1, Version: fmt.Sprintf("production-%d", document.Binding.Revision), Revision: document.Binding.Revision,
		Global: Scope{Rules: []Rule{}}, Sites: []SiteScope{{SiteKey: document.Binding.SiteID, Rules: []Rule{rule}}}}
	if _, err := Compile(policy, ""); err != nil {
		return Policy{}, ErrInvalidProductionBundle
	}
	return policy, nil
}

func validProductionBinding(binding ProductionBundleBinding) bool {
	tenantID, tenantErr := uuid.Parse(binding.TenantID)
	siteID, siteErr := uuid.Parse(binding.SiteID)
	return tenantErr == nil && siteErr == nil && tenantID != uuid.Nil && siteID != uuid.Nil &&
		tenantID.String() == binding.TenantID && siteID.String() == binding.SiteID && binding.Revision > 0 && validDigest(binding.AssetSHA256) &&
		(binding.Category == CategoryOriginResponse || binding.Category == CategoryEdgeRoute || binding.Category == CategoryEdgeConnect)
}

func productionBundleFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrPrecheck):
		return ActivationReasonPrecheckFailed
	case errors.Is(err, ErrActivate):
		return ActivationReasonActivationFailed
	case errors.Is(err, ErrHealth):
		return ActivationReasonHealthFailed
	case errors.Is(err, ErrRollback):
		return ActivationReasonRollbackFailed
	default:
		return ActivationReasonPublicationFailed
	}
}

func digestProductionResource(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
