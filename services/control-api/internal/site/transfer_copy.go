package site

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 网站更换所属用户 S2/S3：随站复制 HTTP 策略、缓存策略、
// 证书（目标租户重新封装）、WAF/CC/ACL 规则库副本；解除并提示重新配置的是
// 自动防御、JS 挑战（四层转发 506 起与网站解耦，属套餐/租户资源，不随站）。

// Transfer copy / release items (TransferResult.Copied / Released).
const (
	TransferItemHTTPPolicy  = "http_policy"
	TransferItemCache       = "cache_policy"
	TransferItemCertificate = "certificate"
	TransferItemWAF         = "waf_policy"
	TransferItemCC          = "cc_policy"
	TransferItemACL         = "acl_policy"
	TransferItemAutoDefense = "auto_defense"
	TransferItemChallenge   = "js_challenge"
)

// TransferCertificates loads and re-imports a site's certificate (the site
// store has no private key envelope of its own). Nil: certificates are not
// carried (Released then names the certificate).
type TransferCertificates interface {
	LoadForSiteTransferTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID,
		domains []string) (*certificateasset.SiteTransferCertificate, error)
	CopyForSiteTransferTx(ctx context.Context, tx pgx.Tx, actor certificateasset.Actor,
		certificate *certificateasset.SiteTransferCertificate, request certificateasset.SiteTransferCopyRequest) (uuid.UUID, error)
}

// WithTransferCertificates sets the certificate store Transfer uses.
func (s *Store) WithTransferCertificates(certificates TransferCertificates) *Store {
	s.certificates = certificates
	return s
}

// transferSnapshot is what the old site had, read before it is deleted.
type transferSnapshot struct {
	httpPolicy    *httppolicycontrol.Config
	cache         *cachecontrol.PolicyDocument
	certificate   *certificateasset.SiteTransferCertificate
	policies      map[string]uuid.UUID // kind -> bound security library
	autoDefense   bool
	challenge     bool
	certificateNo string // why the certificate is not carried ("" when it is)
}

func (s *Store) readTransferSnapshot(ctx context.Context, tx pgx.Tx, current Site) (transferSnapshot, error) {
	var snapshot transferSnapshot
	config, found, err := httppolicycontrol.SiteConfigTx(ctx, tx, current.ScopeID, current.ID)
	if err != nil {
		return snapshot, err
	}
	if found {
		snapshot.httpPolicy = &config
	}
	document, found, err := cachecontrol.SiteDocumentTx(ctx, tx, current.ScopeID, current.ID)
	if err != nil {
		return snapshot, err
	}
	if found {
		snapshot.cache = &document
	}
	rows, err := tx.Query(ctx, `SELECT binding.policy_kind,binding.policy_id FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.scope_id=binding.tenant_scope_id AND policy.id=binding.policy_id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND policy.deleted_at IS NULL
		ORDER BY binding.policy_kind`, current.ScopeID, current.ID)
	if err != nil {
		return snapshot, err
	}
	snapshot.policies = map[string]uuid.UUID{}
	for rows.Next() {
		var kind string
		var id uuid.UUID
		if err := rows.Scan(&kind, &id); err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.policies[kind] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	if err := tx.QueryRow(ctx, `SELECT
		false, -- cdncaCE: no automatic defense module
		EXISTS(SELECT 1 FROM challenge_policies WHERE tenant_scope_id=$1 AND site_id=$2 AND deleted_at IS NULL)`,
		current.ScopeID, current.ID).Scan(&snapshot.autoDefense, &snapshot.challenge); err != nil {
		return snapshot, err
	}
	snapshot.certificateNo = "none"
	if bound, err := siteCertificateBound(ctx, tx, current.ID); err != nil {
		return snapshot, err
	} else if bound && s.certificates == nil {
		snapshot.certificateNo = "unavailable"
	} else if bound {
		certificate, err := s.certificates.LoadForSiteTransferTx(ctx, tx, current.ScopeID, current.ID, current.Domains)
		if err != nil {
			return snapshot, err
		}
		snapshot.certificateNo = certificate.Skipped
		if certificate.Skipped == "" {
			snapshot.certificate = certificate
		}
	}
	return snapshot, nil
}

// close zeroes the loaded private key.
func (snapshot *transferSnapshot) close() {
	snapshot.certificate.Close()
}

// carriesHTTPS: the new site keeps HTTPS only with the certificate.
func (snapshot transferSnapshot) carriesHTTPS() bool {
	return snapshot.certificate != nil
}

// copyTransferSnapshot writes the snapshot onto the new site (in the site
// create's tx, after createTx) and returns what was copied and released.
func (s *Store) copyTransferSnapshot(ctx context.Context, tx pgx.Tx, actor Actor, current Site, site Site,
	snapshot transferSnapshot, requestID string, now time.Time) (copied, released []string, err error) {
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, site.ScopeID).Scan(&tenantID); err != nil {
		return nil, nil, err
	}
	owner := *site.Owner
	if snapshot.httpPolicy != nil {
		// The new owner's 默认设置 may already have created one (createTx).
		if _, err := httppolicycontrol.CreateForNewSiteTx(ctx, tx, actor.ScopeID, actor.UserID, site.ScopeID, tenantID,
			site.ID, owner.ID, *snapshot.httpPolicy, now); errors.Is(err, httppolicycontrol.ErrConflict) {
			released = append(released, TransferItemHTTPPolicy)
		} else if err != nil {
			return nil, nil, err
		} else {
			copied = append(copied, TransferItemHTTPPolicy)
		}
	}
	if snapshot.cache != nil {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$2)`,
			site.ScopeID, site.ID).Scan(&exists); err != nil {
			return nil, nil, err
		}
		if exists {
			released = append(released, TransferItemCache)
		} else if _, err := cachecontrol.CreateForNewSiteTx(ctx, tx, s.auditor, cachecontrol.Actor{
			UserID: actor.UserID, ScopeID: site.ScopeID, ActorScopeID: actor.ScopeID,
		}, tenantID, site.ID, *snapshot.cache, requestID, now); err != nil {
			return nil, nil, err
		} else {
			copied = append(copied, TransferItemCache)
		}
	}
	if snapshot.certificate != nil {
		if _, err := s.certificates.CopyForSiteTransferTx(ctx, tx, certificateasset.Actor{UserID: actor.UserID,
			ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind, SessionID: actor.SessionID}, snapshot.certificate,
			certificateasset.SiteTransferCopyRequest{ToScopeID: site.ScopeID, ToSiteID: site.ID, ToOwnerID: owner.ID,
				KeyPrefix: "site-transfer-" + site.ID.String(), RequestID: requestID}); err != nil {
			return nil, nil, err
		}
		copied = append(copied, TransferItemCertificate)
	} else if snapshot.certificateNo != "none" {
		released = append(released, TransferItemCertificate)
	}
	policyActor := securitypolicy.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind}
	for _, kind := range []string{securitypolicy.KindWAF, securitypolicy.KindCC, securitypolicy.KindACL} {
		source, ok := snapshot.policies[kind]
		if !ok {
			continue
		}
		item := map[string]string{securitypolicy.KindWAF: TransferItemWAF, securitypolicy.KindCC: TransferItemCC,
			securitypolicy.KindACL: TransferItemACL}[kind]
		var bound bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_policy_site_bindings
			WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_kind=$3)`, site.ScopeID, site.ID, kind).Scan(&bound); err != nil {
			return nil, nil, err
		}
		// Already bound from the new owner's 默认设置, or the new package lacks
		// the feature: not carried.
		if bound || packageDenies(ctx, tx, site.ScopeID, site.ID, kind, now) {
			released = append(released, item)
			continue
		}
		policy, err := securitypolicy.CopyForSiteTx(ctx, tx, policyActor, securitypolicy.SiteCopyRequest{
			ScopeID: site.ScopeID, OwnerID: owner.ID, Kind: kind, SourceID: &source, SiteID: site.ID,
			SiteName: site.Domain, SourceScopeID: current.ScopeID, SourceOwnerID: current.ownerID}, now)
		if errors.Is(err, securitypolicy.ErrSiteCopyUnusable) || errors.Is(err, securitypolicy.ErrIPListUnavailable) {
			// A subscribed library, or one naming the old tenant's IP lists.
			released = append(released, item)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if err := securitybinding.AttachNewSiteTx(ctx, tx, site.ScopeID, site.ID, policy.ID, kind, now); err != nil {
			return nil, nil, err
		}
		copied = append(copied, item)
	}
	// S3: released, the administrator configures them again on the new site.
	if snapshot.autoDefense {
		released = append(released, TransferItemAutoDefense)
	}
	if snapshot.challenge {
		released = append(released, TransferItemChallenge)
	}
	return copied, released, nil
}
