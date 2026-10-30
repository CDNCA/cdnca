package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ProductionCandidateRequest struct {
	TenantID   uuid.UUID
	ScopeID    uuid.UUID
	SiteID     uuid.UUID
	Category   string
	StatusCode int
}

type ProductionCandidateArtifact struct {
	ProductionBundleArtifact
	Binding          ProductionBundleBinding
	RuleID           string
	SourceScopeID    uuid.UUID
	SigningPublicKey ed25519.PublicKey
}

type ProductionCandidateCompiler struct {
	store  ContentStore
	signer ProductionBundleSigner
}

type productionCandidate struct {
	scopeKind        string
	scopeID, ruleID  uuid.UUID
	tenantID, siteID *uuid.UUID
	revision         uint64
	category         string
	codeFrom, codeTo int
	asset            Asset
}

func NewProductionCandidateCompiler(store ContentStore, signer ProductionBundleSigner) (*ProductionCandidateCompiler, error) {
	if store == nil || signer == nil || !store.Capabilities().runtimeReady() ||
		!productionBundleIdentifier.MatchString(signer.SigningKeyID()) || len(signer.SigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidStore
	}
	return &ProductionCandidateCompiler{store: store, signer: signer}, nil
}

func (compiler *ProductionCandidateCompiler) Build(
	ctx context.Context,
	tx pgx.Tx,
	request ProductionCandidateRequest,
) (ProductionCandidateArtifact, error) {
	if compiler == nil || ctx == nil || tx == nil || !validProductionCandidateRequest(request) {
		return ProductionCandidateArtifact{}, ErrInvalidInput
	}
	candidates, err := loadProductionCandidates(ctx, tx, request)
	if err != nil {
		return ProductionCandidateArtifact{}, err
	}
	selected, err := chooseProductionCandidate(request, candidates)
	if err != nil {
		return ProductionCandidateArtifact{}, err
	}
	return compiler.buildSelected(ctx, request, selected)
}

func chooseProductionCandidate(request ProductionCandidateRequest, candidates []productionCandidate) (productionCandidate, error) {
	if !validProductionCandidateRequest(request) {
		return productionCandidate{}, ErrInvalidInput
	}
	eligible := make([]productionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ruleID == uuid.Nil || candidate.revision == 0 || candidate.category != request.Category ||
			request.StatusCode < candidate.codeFrom || request.StatusCode > candidate.codeTo ||
			candidate.asset.ID == uuid.Nil || candidate.asset.Status != StatusReady || candidate.asset.objectState != "final" ||
			candidate.asset.DeletedAt != nil {
			continue
		}
		switch candidate.scopeKind {
		case "tenant":
			if candidate.scopeID != request.ScopeID || candidate.tenantID == nil || *candidate.tenantID != request.TenantID ||
				candidate.siteID == nil || *candidate.siteID != request.SiteID || candidate.asset.ScopeID != request.ScopeID ||
				candidate.asset.TenantID == nil || *candidate.asset.TenantID != request.TenantID {
				continue
			}
		case "platform":
			if candidate.tenantID != nil || candidate.siteID != nil || candidate.asset.TenantID != nil ||
				candidate.asset.ScopeID != candidate.scopeID {
				continue
			}
		default:
			continue
		}
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return productionCandidate{}, ErrNotFound
	}
	sort.Slice(eligible, func(left, right int) bool {
		leftSite := eligible[left].scopeKind == "tenant"
		rightSite := eligible[right].scopeKind == "tenant"
		if leftSite != rightSite {
			return leftSite
		}
		leftWidth := eligible[left].codeTo - eligible[left].codeFrom
		rightWidth := eligible[right].codeTo - eligible[right].codeFrom
		if leftWidth != rightWidth {
			return leftWidth < rightWidth
		}
		return bytes.Compare(eligible[left].ruleID[:], eligible[right].ruleID[:]) < 0
	})
	return eligible[0], nil
}

func (compiler *ProductionCandidateCompiler) buildSelected(
	ctx context.Context,
	request ProductionCandidateRequest,
	candidate productionCandidate,
) (ProductionCandidateArtifact, error) {
	selected, err := chooseProductionCandidate(request, []productionCandidate{candidate})
	if err != nil {
		return ProductionCandidateArtifact{}, err
	}
	asset := selected.asset
	if asset.storageObjectKey != "error-pages/objects/"+asset.ScopeID.String()+"/"+asset.SHA256 {
		return ProductionCandidateArtifact{}, ErrConflict
	}
	ref := assetObjectRef(asset, asset.storageObjectKey)
	info, err := compiler.store.Stat(ctx, ref)
	if err != nil {
		return ProductionCandidateArtifact{}, wrapUnavailable("stat production error page candidate", err)
	}
	if validateObjectInfo(asset, info) != nil || info.ImmutableToken != "sha256:"+asset.SHA256 {
		return ProductionCandidateArtifact{}, ErrConflict
	}
	reader, err := compiler.store.Open(ctx, ref, info.ImmutableToken)
	if err != nil {
		return ProductionCandidateArtifact{}, wrapUnavailable("open production error page candidate", err)
	}
	body, err := readProductionBundleBody(reader, asset.SizeBytes)
	if err != nil {
		return ProductionCandidateArtifact{}, err
	}
	if digestBytes(body) != asset.SHA256 || validateStaticBody(asset.MIMEType, body) != nil {
		return ProductionCandidateArtifact{}, ErrUnsafeContent
	}
	match := SnapshotMatch{}
	if selected.codeFrom == selected.codeTo {
		match.Codes = []int{selected.codeFrom}
	} else {
		match.Ranges = []SnapshotRange{{From: selected.codeFrom, To: selected.codeTo}}
	}
	document := ProductionBundleDocument{
		Schema: ProductionBundleSchema,
		Binding: ProductionBundleBinding{
			TenantID: request.TenantID.String(), SiteID: request.SiteID.String(), Category: request.Category,
			Revision: selected.revision, AssetSHA256: asset.SHA256,
		},
		RuleID: selected.ruleID.String(), Match: match,
		Resource: ProductionBundleResource{MIMEType: asset.MIMEType, Size: asset.SizeBytes, SHA256: asset.SHA256, Body: body},
	}
	wire, err := json.Marshal(document)
	if err != nil || len(wire) == 0 || int64(len(wire)) > MaxEdgePolicyBytes {
		return ProductionCandidateArtifact{}, ErrInvalidInput
	}
	signature, err := compiler.signer.Sign(ctx, wire)
	publicKey := append(ed25519.PublicKey(nil), compiler.signer.SigningPublicKey()...)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(publicKey, wire, signature) {
		return ProductionCandidateArtifact{}, ErrUnavailable
	}
	digest := sha256.Sum256(wire)
	return ProductionCandidateArtifact{
		ProductionBundleArtifact: ProductionBundleArtifact{
			WireBytes: bytes.Clone(wire), SHA256: hex.EncodeToString(digest[:]), Signature: bytes.Clone(signature),
			SigningKeyID: compiler.signer.SigningKeyID(), MediaType: ProductionBundleMediaType,
		},
		Binding: document.Binding, RuleID: document.RuleID, SourceScopeID: asset.ScopeID, SigningPublicKey: publicKey,
	}, nil
}

func loadProductionCandidates(ctx context.Context, tx pgx.Tx, request ProductionCandidateRequest) ([]productionCandidate, error) {
	rows, err := tx.Query(ctx, `
		SELECT identity.scope_kind,identity.scope_id,identity.tenant_id,identity.site_id,identity.id,
		       current.revision,current.category,current.code_from,current.code_to,
		       asset.id,asset.scope_id,asset.tenant_id,asset.mime_type,asset.size_bytes,encode(asset.sha256,'hex'),
		       asset.status,asset.scan_status,asset.revision,asset.created_by_user_id,asset.created_at,asset.updated_at,
		       asset.deleted_at,asset.staging_object_key,asset.storage_object_key,asset.object_state
		FROM sites target_site
		JOIN access_scopes target_scope ON target_scope.id=target_site.scope_id
		JOIN error_page_rules identity ON (
			(identity.scope_kind='site' AND identity.scope_id=target_scope.id AND identity.tenant_id=target_scope.tenant_id
			 AND identity.site_id=target_site.id) OR
			(identity.scope_kind='global' AND identity.tenant_id IS NULL AND identity.site_id IS NULL)
		)
		JOIN access_scopes source_scope ON source_scope.id=identity.scope_id
		JOIN LATERAL (
			SELECT revision.* FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true
		JOIN error_page_assets asset ON asset.id=current.asset_id AND asset.scope_id=identity.scope_id
		WHERE target_site.id=$1 AND target_site.scope_id=$2 AND target_site.deleted_at IS NULL
		  AND target_scope.kind='tenant' AND target_scope.tenant_id=$3
		  AND current.enabled AND NOT current.deleted AND current.category=$4
		  AND $5 BETWEEN current.code_from AND current.code_to
		  AND asset.status='ready' AND asset.scan_status='passed' AND asset.object_state='final' AND asset.deleted_at IS NULL
		  AND ((identity.scope_kind='site' AND source_scope.kind='tenant') OR
		       (identity.scope_kind='global' AND source_scope.kind='platform'))
		ORDER BY CASE identity.scope_kind WHEN 'site' THEN 0 ELSE 1 END,current.priority,identity.id
		LIMIT 64`, request.SiteID, request.ScopeID, request.TenantID, request.Category, request.StatusCode)
	if err != nil {
		return nil, fmt.Errorf("load production error page candidates: %w", err)
	}
	defer rows.Close()
	var candidates []productionCandidate
	for rows.Next() {
		var candidate productionCandidate
		var revision int64
		var assetRevision int64
		if err := rows.Scan(
			&candidate.scopeKind, &candidate.scopeID, &candidate.tenantID, &candidate.siteID, &candidate.ruleID,
			&revision, &candidate.category, &candidate.codeFrom, &candidate.codeTo,
			&candidate.asset.ID, &candidate.asset.ScopeID, &candidate.asset.TenantID, &candidate.asset.MIMEType,
			&candidate.asset.SizeBytes, &candidate.asset.SHA256, &candidate.asset.Status, &candidate.asset.ScanStatus,
			&assetRevision, &candidate.asset.CreatedBy, &candidate.asset.CreatedAt, &candidate.asset.UpdatedAt,
			&candidate.asset.DeletedAt, &candidate.asset.stagingObjectKey, &candidate.asset.storageObjectKey,
			&candidate.asset.objectState,
		); err != nil {
			return nil, fmt.Errorf("scan production error page candidate: %w", err)
		}
		if revision < 1 || assetRevision < 1 {
			return nil, ErrConflict
		}
		candidate.revision = uint64(revision)
		candidate.asset.Revision = assetRevision
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate production error page candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil, ErrNotFound
	}
	return candidates, nil
}

func validProductionCandidateRequest(request ProductionCandidateRequest) bool {
	return request.TenantID != uuid.Nil && request.ScopeID != uuid.Nil && request.SiteID != uuid.Nil &&
		request.StatusCode >= 400 && request.StatusCode <= 599 &&
		(request.Category == CategoryOriginResponse || request.Category == CategoryEdgeRoute || request.Category == CategoryEdgeConnect)
}
