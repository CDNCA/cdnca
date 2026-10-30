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
	ProductionSnapshotSchema                  = "cdnca.edge.error-page-snapshot/v1"
	ProductionSnapshotMediaType               = "application/vnd.cdnca.edge-error-page-snapshot+json;version=1"
	ProductionSnapshotActivationReceiptSchema = "cdnca.edge.error-page-snapshot-activation-receipt/v1"
)

type ProductionSnapshotBinding struct {
	TenantID             string `json:"tenant_id"`
	ConfigurationScopeID string `json:"configuration_scope_id"`
	PublicationRevision  uint64 `json:"publication_revision"`
}

type ProductionSnapshotResource struct {
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
	Body     []byte `json:"body"`
}

type ProductionSnapshotRule struct {
	ID       string                     `json:"id"`
	Category Category                   `json:"category"`
	Match    StatusMatch                `json:"match"`
	Resource ProductionSnapshotResource `json:"resource"`
}

type ProductionSnapshotScope struct {
	Rules []ProductionSnapshotRule `json:"rules"`
}

type ProductionSnapshotSite struct {
	SiteKey string                   `json:"site_key"`
	Rules   []ProductionSnapshotRule `json:"rules"`
}

type ProductionSnapshotDocument struct {
	Schema  string                    `json:"schema"`
	Binding ProductionSnapshotBinding `json:"binding"`
	Global  ProductionSnapshotScope   `json:"global"`
	Sites   []ProductionSnapshotSite  `json:"sites"`
	// Slots (errpage-3, ERROR_PAGE_SLOTS) mirror control's
	// errorpagecontrol.ProductionSnapshotSlot: the node pages of the
	// platform's error page slots. Dynamic routing nodes serve them from the
	// site objects' node pages; the snapshot only records them.
	Slots []ProductionSnapshotSlot `json:"slots,omitempty"`
}

type ProductionSnapshotSlot struct {
	Key      string                     `json:"key"`
	Category string                     `json:"category"`
	Status   int                        `json:"status"`
	Region   string                     `json:"region,omitempty"`
	NodeID   string                     `json:"node_id,omitempty"`
	Resource ProductionSnapshotResource `json:"resource"`
}

type SignedProductionSnapshot struct {
	WireBytes    []byte
	SHA256       string
	Signature    []byte
	SigningKeyID string
}

type ProductionSnapshotActivationReceipt struct {
	Schema                 string                    `json:"schema"`
	State                  string                    `json:"state"`
	ReasonCode             string                    `json:"reason_code,omitempty"`
	Binding                ProductionSnapshotBinding `json:"binding"`
	BundleSHA256           string                    `json:"bundle_sha256"`
	ActiveDigest           string                    `json:"active_digest"`
	PreviousDigest         string                    `json:"previous_digest,omitempty"`
	RunningConfigUnchanged bool                      `json:"running_config_unchanged"`
}

type ProductionSnapshotInstaller struct {
	publisher *Publisher
	keys      ProductionBundleKeyResolver
}

func NewProductionSnapshotInstaller(publisher *Publisher, keys ProductionBundleKeyResolver) (*ProductionSnapshotInstaller, error) {
	if publisher == nil || publisher.runtime == nil || keys == nil {
		return nil, ErrInvalidProductionBundle
	}
	return &ProductionSnapshotInstaller{publisher: publisher, keys: keys}, nil
}

func (installer *ProductionSnapshotInstaller) Install(
	ctx context.Context,
	bundle SignedProductionSnapshot,
	expected ProductionSnapshotBinding,
) (ProductionSnapshotActivationReceipt, error) {
	receipt := ProductionSnapshotActivationReceipt{
		Schema: ProductionSnapshotActivationReceiptSchema, State: ActivationStateFailed, Binding: expected,
		BundleSHA256: bundle.SHA256, RunningConfigUnchanged: true,
	}
	if installer == nil || installer.publisher == nil || installer.keys == nil || ctx == nil || !validProductionSnapshotBinding(expected) ||
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
	document, err := decodeProductionSnapshot(bundle.WireBytes)
	if err != nil {
		receipt.ReasonCode = ActivationReasonPayloadInvalid
		return receipt, err
	}
	if document.Binding != expected {
		receipt.ReasonCode = ActivationReasonBindingMismatch
		return receipt, ErrInvalidProductionBundle
	}
	policy, err := productionSnapshotPolicy(document)
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

func (installer *ProductionSnapshotInstaller) Reconcile(ctx context.Context) (ReconcileReceipt, error) {
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

func DecodeProductionSnapshotBinding(raw []byte) (ProductionSnapshotBinding, error) {
	document, err := decodeProductionSnapshot(raw)
	if err != nil || document.Schema != ProductionSnapshotSchema || !validProductionSnapshotBinding(document.Binding) {
		return ProductionSnapshotBinding{}, ErrInvalidProductionBundle
	}
	return document.Binding, nil
}

func decodeProductionSnapshot(raw []byte) (ProductionSnapshotDocument, error) {
	if edgeconfig.RejectDuplicateJSONKeys(raw) != nil {
		return ProductionSnapshotDocument{}, ErrInvalidProductionBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ProductionSnapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return ProductionSnapshotDocument{}, ErrInvalidProductionBundle
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ProductionSnapshotDocument{}, ErrInvalidProductionBundle
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ProductionSnapshotDocument{}, ErrInvalidProductionBundle
	}
	return document, nil
}

func productionSnapshotPolicy(document ProductionSnapshotDocument) (Policy, error) {
	if document.Schema != ProductionSnapshotSchema || !validProductionSnapshotBinding(document.Binding) ||
		len(document.Sites) > MaxSites || len(document.Global.Rules) > MaxRulesPerScope {
		return Policy{}, ErrInvalidProductionBundle
	}
	policy := Policy{
		Schema: SchemaV1, Version: fmt.Sprintf("production-%d", document.Binding.PublicationRevision),
		Revision: document.Binding.PublicationRevision, Global: productionSnapshotScope(document.Global),
		Sites: make([]SiteScope, len(document.Sites)),
	}
	seenSites := make(map[string]struct{}, len(document.Sites))
	for index, site := range document.Sites {
		siteID, err := uuid.Parse(site.SiteKey)
		if err != nil || siteID == uuid.Nil || siteID.String() != site.SiteKey || len(site.Rules) > MaxRulesPerScope {
			return Policy{}, ErrInvalidProductionBundle
		}
		if _, duplicate := seenSites[site.SiteKey]; duplicate {
			return Policy{}, ErrInvalidProductionBundle
		}
		seenSites[site.SiteKey] = struct{}{}
		policy.Sites[index] = SiteScope{SiteKey: site.SiteKey, Rules: productionSnapshotRules(site.Rules)}
	}
	if _, err := Compile(policy, ""); err != nil {
		return Policy{}, ErrInvalidProductionBundle
	}
	return policy, nil
}

func productionSnapshotScope(scope ProductionSnapshotScope) Scope {
	return Scope{Rules: productionSnapshotRules(scope.Rules)}
}

func productionSnapshotRules(rules []ProductionSnapshotRule) []Rule {
	result := make([]Rule, len(rules))
	for index, rule := range rules {
		inline := string(rule.Resource.Body)
		result[index] = Rule{ID: rule.ID, Category: rule.Category, Match: rule.Match,
			Resource: Resource{MIMEType: rule.Resource.MIMEType, Size: rule.Resource.Size, SHA256: rule.Resource.SHA256, Inline: &inline}}
	}
	return result
}

func validProductionSnapshotBinding(binding ProductionSnapshotBinding) bool {
	tenantID, tenantErr := uuid.Parse(binding.TenantID)
	scopeID, scopeErr := uuid.Parse(binding.ConfigurationScopeID)
	return tenantErr == nil && scopeErr == nil && tenantID != uuid.Nil && scopeID != uuid.Nil &&
		tenantID.String() == binding.TenantID && scopeID.String() == binding.ConfigurationScopeID && binding.PublicationRevision > 0
}
