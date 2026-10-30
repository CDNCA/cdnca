package acmedispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidStore           = errors.New("invalid ACME dispatch certificate store")
	ErrInvalidInput           = errors.New("invalid ACME dispatch certificate input")
	ErrConflict               = errors.New("ACME dispatch certificate conflict")
	ErrUnsupportedKeyMaterial = errors.New("unsupported ACME certificate key material")
)

type OperationFencer interface {
	FenceTx(context.Context, pgx.Tx, acmeworker.OperationLease) (acmeworker.OperationLease, time.Time, error)
}

type CertificateImporter interface {
	ImportACMEInTx(context.Context, pgx.Tx, certificateasset.ACMEImportRequest) (certificateasset.ImportResult, error)
}

type KeyMaterialLoader interface {
	LoadOpaquePrivateKey(
		context.Context,
		pgx.Tx,
		uuid.UUID,
		string,
		[]byte,
	) (certificateasset.OpaquePrivateKey, error)
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type CertificateStore struct {
	pool     *pgxpool.Pool
	fencer   OperationFencer
	importer CertificateImporter
	keys     KeyMaterialLoader
	auditor  AuditAppender
}

func NewCertificateStore(
	pool *pgxpool.Pool,
	fencer OperationFencer,
	importer CertificateImporter,
	keys KeyMaterialLoader,
) (*CertificateStore, error) {
	return NewCertificateStoreWithAudit(pool, fencer, importer, keys, audit.New(pool))
}

func NewCertificateStoreWithAudit(
	pool *pgxpool.Pool,
	fencer OperationFencer,
	importer CertificateImporter,
	keys KeyMaterialLoader,
	auditor AuditAppender,
) (*CertificateStore, error) {
	if pool == nil || fencer == nil || importer == nil || keys == nil || auditor == nil {
		return nil, ErrInvalidStore
	}
	return &CertificateStore{pool: pool, fencer: fencer, importer: importer, keys: keys, auditor: auditor}, nil
}

func (s *CertificateStore) Save(
	ctx context.Context,
	lease acmeworker.OperationLease,
	certificate acmeworker.IssuedCertificate,
) error {
	prepared, err := prepareSave(lease, certificate)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin ACME certificate save: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	current, databaseNow, err := s.fencer.FenceTx(ctx, tx, lease)
	if err != nil {
		return fmt.Errorf("fence ACME certificate save: %w", err)
	}
	if !sameLease(current, lease) || current.State.Status != acmeworker.OperationActive ||
		current.State.Phase != acmeworker.PhaseFinalizing || current.State.AccountURI == "" ||
		current.State.OrderURL == "" || len(current.State.AuthorizationURLs) == 0 {
		return ErrConflict
	}

	var status, orderName, orderRemark string
	var revision int64
	var renewalOfOrderID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT status,revision,name,remark,renewal_of_order_id FROM certificate_orders
		WHERE scope_id=$1 AND id=$2 FOR UPDATE`, lease.ScopeID, lease.Request.CertificateOrderID).
		Scan(&status, &revision, &orderName, &orderRemark, &renewalOfOrderID); err != nil {
		return fmt.Errorf("lock ACME certificate order: %w", err)
	}
	if status == "issued" {
		if err := validateIssuedReplay(ctx, tx, current, prepared); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if !validCertificateWindow(databaseNow, prepared.notBefore, prepared.notAfter) {
		return ErrConflict
	}
	if status == "validating" {
		result, err := tx.Exec(ctx, `UPDATE certificate_orders SET
			status='issuing',revision=revision+1,updated_at=$4
			WHERE scope_id=$1 AND id=$2 AND status='validating' AND revision=$3`,
			lease.ScopeID, lease.Request.CertificateOrderID, revision, databaseNow)
		if err != nil {
			return fmt.Errorf("advance ACME certificate order to issuing: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		actorID := lease.Request.ActorUserID
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: lease.ScopeID, ActorUserID: &actorID,
			Action: "certificate.order.transition", ResourceType: "certificate_order",
			ResourceID: lease.Request.CertificateOrderID.String(),
			RequestID:  "acme-order-finalize:" + lease.Request.CertificateOrderID.String(), Result: "success",
			Payload: map[string]any{
				"from_status": "validating", "to_status": "issuing",
				"operation": "begin_issuance", "reason": "acme_authorizations_ready",
			},
		}); err != nil {
			return fmt.Errorf("audit ACME certificate order transition: %w", err)
		}
		revision++
		status = "issuing"
	}
	if status != "issuing" {
		return ErrConflict
	}

	opaqueKey, err := s.keys.LoadOpaquePrivateKey(
		ctx, tx, lease.ScopeID, lease.Request.CertificateKeyRef, prepared.publicKeySPKIDER,
	)
	if err != nil {
		return fmt.Errorf("load ACME certificate key material: %w", err)
	}
	if opaqueKey.KeyReference != lease.Request.CertificateKeyRef ||
		!bytes.Equal(opaqueKey.PublicKeySPKIDER, prepared.publicKeySPKIDER) {
		return ErrConflict
	}
	orderID := lease.Request.CertificateOrderID
	// The certificate carries the order's 名称/备注 (CERT-04); unnamed orders
	// keep the generated name.
	assetName := orderName
	if assetName == "" {
		assetName = "ACME " + orderID.String()
	}
	// The order's actor is a tenant member, or a platform member who ordered
	// for the tenant (migration 531): import under the scope they act in.
	actorScopeID, actorScopeKind := lease.ScopeID, certificateasset.ScopeTenant
	if err := tx.QueryRow(ctx, `SELECT scope.id,scope.kind FROM memberships membership
		JOIN access_scopes scope ON scope.id=membership.scope_id
		WHERE membership.user_id=$2 AND membership.status='active'
		  AND (scope.id=$1 OR scope.kind='platform')
		ORDER BY scope.id=$1 DESC LIMIT 1`, lease.ScopeID, lease.Request.ActorUserID).
		Scan(&actorScopeID, &actorScopeKind); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("resolve ACME certificate actor scope: %w", err)
	}
	// CERT-RENEW-LIFECYCLE-01 B: a renewal is a new version of the
	// certificate it renews (its parent order's asset, same tenant), never a
	// separate certificate, so the sites bound to it move on activation. The
	// asset keeps its name and remark.
	var renewedAssetID *uuid.UUID
	var renewedAssetRevision int64
	if renewalOfOrderID != nil {
		var assetID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT asset.id,asset.revision FROM certificate_orders parent
			JOIN certificate_assets asset ON asset.tenant_scope_id=parent.scope_id AND asset.id=parent.issued_asset_id
			  AND asset.source='acme' AND asset.deleted_at IS NULL
			WHERE parent.scope_id=$1 AND parent.id=$2 FOR UPDATE OF asset`, lease.ScopeID, *renewalOfOrderID).
			Scan(&assetID, &renewedAssetRevision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict // the renewed certificate is gone
			}
			return fmt.Errorf("lock renewed ACME certificate asset: %w", err)
		}
		renewedAssetID, orderRemark = &assetID, ""
	}
	imported, err := s.importer.ImportACMEInTx(ctx, tx, certificateasset.ACMEImportRequest{
		Actor: certificateasset.Actor{
			UserID: lease.Request.ActorUserID, ScopeID: actorScopeID, ScopeKind: actorScopeKind,
		},
		Import: certificateasset.ImportRequest{
			TenantScopeID:    lease.ScopeID,
			AssetID:          renewedAssetID,
			ExpectedRevision: renewedAssetRevision,
			Name:             assetName,
			Remark:           orderRemark,
			Source:           certificateasset.SourceACME,
			ACMEOrderID:      &orderID,
			CertificatePEM:   append([]byte(nil), certificate.CertificatePEM...),
			OpaquePrivateKey: &opaqueKey,
			IdempotencyKey:   "acme-order:" + orderID.String(),
			RequestID:        "acme-order-finalize:" + orderID.String(),
		},
	})
	if err != nil {
		return fmt.Errorf("import ACME certificate asset: %w", err)
	}

	authorizationDigest := digestAuthorizationURLs(current.State.AuthorizationURLs)
	result, err := tx.Exec(ctx, `UPDATE certificate_orders SET
		status='issued',not_after=$4,failure_code=NULL,failure_reason=NULL,issued_asset_id=$5,issued_asset_version_id=$6,
		issued_at=$7,leaf_fingerprint_sha256=$8,leaf_spki_sha256=$9,acme_directory_url=$10,
		acme_account_key_ref=$11,certificate_key_ref=$12,external_order_url=$13,
		authorization_urls_sha256=$14,certificate_url=$15,revision=revision+1,
		updated_by_user_id=$16,updated_at=$7
		WHERE scope_id=$1 AND id=$2 AND status='issuing' AND revision=$3`,
		lease.ScopeID, orderID, revision, prepared.notAfter, imported.Asset.ID, imported.Version.ID,
		databaseNow, prepared.leafFingerprint[:], prepared.publicKeyDigest[:], lease.Request.DirectoryURL,
		lease.Request.AccountKeyRef, lease.Request.CertificateKeyRef, current.State.OrderURL,
		authorizationDigest[:], certificate.CertificateURL, lease.Request.ActorUserID)
	if err != nil {
		return fmt.Errorf("finalize ACME certificate order: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	actorID := lease.Request.ActorUserID
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: lease.ScopeID, ActorUserID: &actorID,
		Action: "certificate.order.finalize_issued", ResourceType: "certificate_order",
		ResourceID: orderID.String(), RequestID: "acme-order-finalize:" + orderID.String(), Result: "success",
		Payload: map[string]any{
			"asset_id": imported.Asset.ID, "asset_version_id": imported.Version.ID,
			"leaf_fingerprint_sha256": certificate.LeafFingerprint,
			"certificate_spki_sha256": certificate.PublicKeySPKISHA256,
		},
	}); err != nil {
		return fmt.Errorf("audit ACME certificate order: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit ACME certificate save: %w", err)
	}
	return nil
}

func (s *CertificateStore) Load(
	ctx context.Context,
	scopeID uuid.UUID,
	operationID string,
) (acmeworker.IssuedCertificate, bool, error) {
	orderID, err := uuid.Parse(operationID)
	if scopeID == uuid.Nil || err != nil || orderID == uuid.Nil || operationID != orderID.String() {
		return acmeworker.IssuedCertificate{}, false, ErrInvalidInput
	}
	var certificate acmeworker.IssuedCertificate
	var requestDigest, fingerprint, spkiDigest []byte
	err = s.pool.QueryRow(ctx, `SELECT operation.request_digest,certificate_order.certificate_key_ref,
		version.certificate_pem,certificate_order.certificate_url,version.serial_number,version.sans,
		version.not_before,version.not_after,certificate_order.leaf_fingerprint_sha256,
		certificate_order.leaf_spki_sha256
		FROM acme_issuance_operations operation
		JOIN certificate_orders certificate_order
		  ON certificate_order.scope_id=operation.tenant_scope_id
		 AND certificate_order.id=operation.certificate_order_id
		JOIN certificate_asset_versions version
		  ON version.tenant_scope_id=certificate_order.scope_id
		 AND version.asset_id=certificate_order.issued_asset_id
		 AND version.id=certificate_order.issued_asset_version_id
		WHERE operation.tenant_scope_id=$1 AND operation.operation_id=$2
		  AND operation.certificate_order_id=$3
		  AND certificate_order.status IN ('issued','deploying','active','renewal_due','revoked')`,
		scopeID, operationID, orderID).Scan(
		&requestDigest, &certificate.CertificateKeyRef, &certificate.CertificatePEM,
		&certificate.CertificateURL, &certificate.SerialNumber, &certificate.DNSNames,
		&certificate.NotBefore, &certificate.NotAfter, &fingerprint, &spkiDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return acmeworker.IssuedCertificate{}, false, nil
	}
	if err != nil {
		return acmeworker.IssuedCertificate{}, false, fmt.Errorf("load ACME certificate: %w", err)
	}
	chain, _, err := parseCertificatePEM(certificate.CertificatePEM)
	if err != nil || len(requestDigest) != sha256.Size || len(fingerprint) != sha256.Size || len(spkiDigest) != sha256.Size {
		return acmeworker.IssuedCertificate{}, false, ErrConflict
	}
	certificate.RequestDigest = "sha256:" + hex.EncodeToString(requestDigest)
	certificate.LeafFingerprint = "sha256:" + hex.EncodeToString(fingerprint)
	certificate.PublicKeySPKISHA256 = "sha256:" + hex.EncodeToString(spkiDigest)
	certificate.LeafDER = append([]byte(nil), chain[0].Raw...)
	certificate.ChainDER = make([][]byte, len(chain))
	for index, item := range chain {
		certificate.ChainDER[index] = append([]byte(nil), item.Raw...)
	}
	return certificate, true, nil
}

type preparedSave struct {
	leafFingerprint  [sha256.Size]byte
	publicKeyDigest  [sha256.Size]byte
	publicKeySPKIDER []byte
	certificatePEM   []byte
	certificateURL   string
	notBefore        time.Time
	notAfter         time.Time
}

func prepareSave(
	lease acmeworker.OperationLease,
	certificate acmeworker.IssuedCertificate,
) (preparedSave, error) {
	if lease.TenantID == uuid.Nil || lease.ScopeID == uuid.Nil || lease.OperationID == "" ||
		lease.Token == uuid.Nil || lease.Revision < 1 || lease.Request.TenantID != lease.TenantID ||
		lease.Request.ScopeID != lease.ScopeID || lease.Request.OperationID != lease.OperationID ||
		lease.Request.CertificateOrderID == uuid.Nil || lease.OperationID != lease.Request.CertificateOrderID.String() ||
		lease.Request.ActorUserID == uuid.Nil || certificate.RequestDigest != lease.Digest ||
		certificate.CertificateKeyRef != lease.Request.CertificateKeyRef || len(certificate.CertificatePEM) == 0 ||
		!validHTTPSURL(certificate.CertificateURL) || !slices.Equal(certificate.DNSNames, lease.Request.Domains) ||
		certificate.NotAfter.IsZero() || !certificate.NotAfter.After(certificate.NotBefore) {
		return preparedSave{}, ErrInvalidInput
	}
	chain, canonical, err := parseCertificatePEM(certificate.CertificatePEM)
	if err != nil || !bytes.Equal(canonical, certificate.CertificatePEM) || len(chain) == 0 {
		return preparedSave{}, ErrInvalidInput
	}
	leaf := chain[0]
	leafDNSNames := slices.Clone(leaf.DNSNames)
	certificateDNSNames := slices.Clone(certificate.DNSNames)
	slices.Sort(leafDNSNames)
	slices.Sort(certificateDNSNames)
	publicDER := leaf.RawSubjectPublicKeyInfo
	fingerprint := sha256.Sum256(leaf.Raw)
	publicDigest := sha256.Sum256(publicDER)
	if certificate.LeafFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) ||
		certificate.PublicKeySPKISHA256 != "sha256:"+hex.EncodeToString(publicDigest[:]) ||
		!leaf.NotBefore.UTC().Equal(certificate.NotBefore.UTC()) ||
		!leaf.NotAfter.UTC().Equal(certificate.NotAfter.UTC()) ||
		!slices.Equal(leafDNSNames, certificateDNSNames) {
		return preparedSave{}, ErrConflict
	}
	return preparedSave{
		leafFingerprint: fingerprint, publicKeyDigest: publicDigest,
		publicKeySPKIDER: append([]byte(nil), publicDER...),
		certificatePEM:   append([]byte(nil), canonical...),
		certificateURL:   certificate.CertificateURL,
		notBefore:        certificate.NotBefore.UTC(),
		notAfter:         certificate.NotAfter.UTC(),
	}, nil
}

func validCertificateWindow(now, notBefore, notAfter time.Time) bool {
	if now.IsZero() || notBefore.IsZero() || notAfter.IsZero() || !notAfter.After(notBefore) {
		return false
	}
	now = now.UTC()
	return !now.Before(notBefore.UTC().Add(-time.Minute)) && now.Before(notAfter.UTC())
}

func validateIssuedReplay(
	ctx context.Context,
	tx pgx.Tx,
	lease acmeworker.OperationLease,
	prepared preparedSave,
) error {
	var fingerprint, spkiDigest, certificatePEM []byte
	var keyRef, directoryURL, accountKeyRef, orderURL, certificateURL string
	var authorizationDigest []byte
	var notAfter time.Time
	err := tx.QueryRow(ctx, `SELECT certificate_order.leaf_fingerprint_sha256,
		certificate_order.leaf_spki_sha256,certificate_order.certificate_key_ref,
		certificate_order.acme_directory_url,certificate_order.acme_account_key_ref,
		certificate_order.external_order_url,certificate_order.authorization_urls_sha256,
		certificate_order.certificate_url,certificate_order.not_after,version.certificate_pem
		FROM certificate_orders certificate_order
		JOIN certificate_asset_versions version
		  ON version.tenant_scope_id=certificate_order.scope_id
		 AND version.asset_id=certificate_order.issued_asset_id
		 AND version.id=certificate_order.issued_asset_version_id
		WHERE certificate_order.scope_id=$1 AND certificate_order.id=$2`,
		lease.ScopeID, lease.Request.CertificateOrderID).Scan(
		&fingerprint, &spkiDigest, &keyRef, &directoryURL, &accountKeyRef, &orderURL,
		&authorizationDigest, &certificateURL, &notAfter, &certificatePEM,
	)
	if err != nil {
		return fmt.Errorf("load issued ACME replay: %w", err)
	}
	expectedAuthorizationDigest := digestAuthorizationURLs(lease.State.AuthorizationURLs)
	if !bytes.Equal(fingerprint, prepared.leafFingerprint[:]) ||
		!bytes.Equal(spkiDigest, prepared.publicKeyDigest[:]) ||
		keyRef != lease.Request.CertificateKeyRef || directoryURL != lease.Request.DirectoryURL ||
		accountKeyRef != lease.Request.AccountKeyRef || orderURL != lease.State.OrderURL ||
		!bytes.Equal(authorizationDigest, expectedAuthorizationDigest[:]) ||
		certificateURL != prepared.certificateURL || !bytes.Equal(certificatePEM, prepared.certificatePEM) ||
		!notAfter.Equal(prepared.notAfter) {
		return ErrConflict
	}
	return nil
}

func digestAuthorizationURLs(values []string) [sha256.Size]byte {
	ordered := append([]string(nil), values...)
	slices.Sort(ordered)
	hash := sha256.New()
	for _, value := range ordered {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func parseCertificatePEM(value []byte) ([]*x509.Certificate, []byte, error) {
	remaining := value
	certificates := make([]*x509.Certificate, 0, 3)
	canonical := make([]byte, 0, len(value))
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) >= 10 {
			return nil, nil, ErrInvalidInput
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, ErrInvalidInput
		}
		certificates = append(certificates, certificate)
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, nil, ErrInvalidInput
	}
	return certificates, canonical, nil
}

func validHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && !strings.ContainsAny(value, "\r\n\x00")
}

func sameLease(left, right acmeworker.OperationLease) bool {
	return left.TenantID == right.TenantID && left.ScopeID == right.ScopeID && left.OperationID == right.OperationID &&
		left.Token == right.Token && left.Revision == right.Revision && left.Digest == right.Digest &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.Request.TenantID == right.Request.TenantID &&
		left.Request.ScopeID == right.Request.ScopeID &&
		left.Request.OperationID == right.Request.OperationID &&
		left.Request.CertificateOrderID == right.Request.CertificateOrderID &&
		left.Request.ActorUserID == right.Request.ActorUserID &&
		left.Request.ProviderID == right.Request.ProviderID && left.Request.ZoneID == right.Request.ZoneID &&
		left.Request.ProviderRef == right.Request.ProviderRef &&
		left.Request.DirectoryURL == right.Request.DirectoryURL &&
		left.Request.AccountKeyRef == right.Request.AccountKeyRef &&
		left.Request.CertificateKeyRef == right.Request.CertificateKeyRef &&
		left.Request.AcceptTerms == right.Request.AcceptTerms &&
		left.Request.ChallengeType == right.Request.ChallengeType &&
		slices.Equal(left.Request.Contacts, right.Request.Contacts) &&
		slices.Equal(left.Request.Domains, right.Request.Domains)
}
