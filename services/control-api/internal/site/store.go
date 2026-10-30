package site

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/marketmanaged"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool         *pgxpool.Pool
	auditor      *audit.Log
	guard        *entitlementguard.Guard
	now          func() time.Time
	certificates TransferCertificates
	// nodeOfflineAfter: the presence cutoff of access_readiness line_group.
	nodeOfflineAfter time.Duration
}

type rowScanner interface {
	Scan(dest ...any) error
}

type storedWrite struct {
	Replayed     bool
	ResourceID   uuid.UUID
	ResponseBody []byte
}

type storedBatchWrite struct {
	Found        bool
	ResponseBody []byte
}

type storedOriginWrite struct {
	Found        bool
	ResponseBody []byte
}

func decodeStoredSite(encoded []byte, destination *Site) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		return err
	}
	if _, exists := fields["origin_pool"]; !exists {
		return deriveStoredOriginPool(destination)
	}
	return normalizeOriginPool(&destination.OriginPool)
}

func deriveStoredOriginPool(item *Site) error {
	origins := make([]Origin, 0, len(item.Origins))
	for _, raw := range item.Origins {
		_, host, port, err := originFromLegacy(raw)
		if err != nil {
			return err
		}
		origins = append(origins, Origin{Host: host, Port: port, Weight: 1, Enabled: true})
	}
	pool := defaultOriginPool(origins)
	if err := normalizeOriginPool(&pool); err != nil {
		return err
	}
	item.OriginPool = pool
	return nil
}

func validateStoredBatchSites(result *BatchActionResult) error {
	for index := range result.Items {
		item := result.Items[index].Site
		if item == nil {
			continue
		}
		if item.OriginPool.BalanceMethod == "" {
			if err := deriveStoredOriginPool(item); err != nil {
				return err
			}
			continue
		}
		if err := normalizeOriginPool(&item.OriginPool); err != nil {
			return err
		}
	}
	return nil
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now, nil)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time, trust *entitlementguard.TrustStore) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		pool: pool, auditor: audit.New(pool), guard: entitlementguard.NewGuard(pool, now, trust), now: now,
	}
}

func (s *Store) Create(
	ctx context.Context,
	actor Actor,
	request CreateRequest,
	siteID uuid.UUID,
	digest [32]byte,
) (WriteResult, error) {
	var result WriteResult
	var denial error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.createTx(ctx, tx, actor, request, siteID, digest, &result, &denial)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("create site: %w", err)
	}
	if denial != nil {
		return WriteResult{}, fmt.Errorf("create site: %w", denial)
	}
	return result, nil
}

// createTx is the site create inside tx (Create, Transfer). An entitlement
// denial is reported through denial with a nil error (nothing written).
func (s *Store) createTx(ctx context.Context, tx pgx.Tx, actor Actor, request CreateRequest, siteID uuid.UUID,
	digest [32]byte, result *WriteResult, denial *error) error {
	{
		if err := authorizeTargetScope(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		if !request.preauthorized {
			if err := authorizeAutomaticMutation(ctx, tx, actor, request.TargetScopeID); err != nil {
				return err
			}
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "site.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored site create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if err := domaintrust.CheckSiteDomainsTx(ctx, tx, actor.ScopeKind, request.TargetScopeID,
			request.Fields.Domains); err != nil {
			return err
		}
		if err := s.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
			AuditScopeID: request.TargetScopeID,
			ActorUserID:  actor.UserID,
			ResourceID:   siteID,
			RequestID:    request.RequestID,
			Operation:    "site.create",
			ExpansionDelta: func() int64 {
				if request.Fields.Enabled {
					return int64(len(request.Fields.Domains))
				}
				return 0
			}(),
		}); err != nil {
			if entitlementguard.IsDenial(err) {
				*denial = err
				return nil
			}
			return err
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, "site.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored site create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		displayID, err := allocateSiteDisplayID(ctx, tx, request.TargetScopeID, s.now().UTC())
		if err != nil {
			return err
		}
		cnameIntent, err := prepareCNAMEWriteIntent(ctx, tx, actor, request.OwnerUserID, request.TargetScopeID, siteID,
			&request.Fields, 1, request.IdempotencyKey, request.RequestID)
		if err != nil {
			return err
		}
		if err := checkPackageSiteChange(ctx, tx, request.TargetScopeID, request.OwnerUserID, siteID, request.Fields, s.now().UTC()); err != nil {
			return err
		}
		var cnameMode, cnameDomain, cnameHostname, cnameState any
		var cnameTaskID any
		var cnameRevision any
		if cnameIntent != nil {
			request.Fields.PackageSubscriptionID = cnameIntent.nullablePackageSubscription()
			request.Fields.CNAME = ""
			cnameMode = cnameIntent.mode
			cnameDomain = cnameIntent.domain
			cnameHostname = cnameIntent.hostname
			cnameState = "pending"
			cnameTaskID = cnameIntent.jobID
			cnameRevision = int64(1)
			if err := insertCNAMEIntentJob(ctx, tx, *cnameIntent, s.now().UTC()); err != nil {
				return err
			}
		}

		// FX07: a new site follows the system default unless the request says.
		forceHTTPS := false
		if request.Fields.ForceHTTPS != nil {
			forceHTTPS = *request.Fields.ForceHTTPS
		} else if request.Fields.HTTPSEnabled && len(request.Fields.HTTPSPorts) != 0 {
			forceHTTPS, err = systemconfig.LoadDefaultForceHTTPS(ctx, tx)
			if err != nil {
				return err
			}
		}
		redirectPort := 0
		if request.Fields.HTTPSRedirectPort != nil {
			redirectPort = *request.Fields.HTTPSRedirectPort
		}
		// the platform's website defaults (load balancing,
		// HSTS) reach new sites; before, they were stored and never read.
		creationDefaults, err := systemconfig.LoadWebsiteCreationDefaults(ctx, tx)
		if err != nil {
			return err
		}
		if request.defaultPool && validBalanceMethod(creationDefaults.LoadBalancing) {
			pool := *request.OriginPool
			pool.BalanceMethod = creationDefaults.LoadBalancing
			request.OriginPool = &pool
		}
		// ge-tls: a new site's TLS follows the system default (网站默认 >
		// HTTPS > SSL / OCSP stapling) unless the request says.
		tls, err := createSiteTLSProfile(ctx, tx, &request.Fields)
		if err != nil {
			return err
		}
		if actor.ScopeKind != "platform" {
			request.Fields.IsDefault = false // the platform's setting
		}
		// REF-ROLE-L2-CREATE: 网站级 L2 is the platform's, as on update; a
		// tenant's new site follows the package (no off/custom of its own).
		request.OriginPool = tenantCreatePool(actor, request.OriginPool)
		if request.Fields.IsDefault {
			if err := s.switchDefaultSite(ctx, tx, actor, siteID, true, request.RequestID, ""); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO sites (
				id, display_id, scope_id, owner_user_id, domain, http_ports, https_ports,
				origins, origin_hosts, cname, https_enabled, enabled, status,
				is_default, package_id, package_name, group_id,
				group_name, region_id, region_name, node_group_id, node_group_name,
				package_subscription_id,cname_mode,cname_domain,cname_hostname2,cname_state,
				cname_task_id,cname_current_revision,cname_lkg_revision,tls_protocols,
					ipv6_enabled, ipv6_runtime_state, ipv6_runtime_source_revision,
				created_by_user_id,updated_by_user_id,force_https,https_redirect_port,cache_shared_across_domains,
				tls_cipher_preset,tls_ocsp_stapling,tls_client_auth,tls_client_ca_pem,cache_status_header,
				http2_enabled,http3_enabled,tls_prefer_server_ciphers,tls_cipher_suites
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
				$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,NULL,$30,$31,$32,0,$33,$33,$34,$35,
				COALESCE($36::boolean,false),$37,$38,$39,NULLIF($40,''),COALESCE($41::boolean,true),
				COALESCE($42::boolean,true),COALESCE($43::boolean,true),$44::boolean,$45::text[]
			)`,
			siteID,
			displayID,
			request.TargetScopeID,
			request.OwnerUserID,
			request.Fields.Domain,
			request.Fields.HTTPPorts,
			request.Fields.HTTPSPorts,
			request.Fields.Origins,
			request.Fields.originHosts,
			request.Fields.CNAME,
			request.Fields.HTTPSEnabled,
			request.Fields.Enabled,
			request.Fields.Status,
			request.Fields.IsDefault,
			request.Fields.PackageID,
			nullableText(request.Fields.PackageName),
			request.Fields.GroupID,
			nullableText(request.Fields.GroupName),
			request.Fields.RegionID,
			nullableText(request.Fields.RegionName),
			request.Fields.NodeGroupID,
			nullableText(request.Fields.NodeGroupName),
			request.Fields.PackageSubscriptionID,
			cnameMode, cnameDomain, cnameHostname, cnameState, cnameTaskID, cnameRevision,
			request.Fields.TLSProtocols,
			request.Fields.IPv6Enabled, initialIPv6RuntimeState(request.Fields.IPv6Enabled), actor.UserID,
			forceHTTPS, redirectPort, request.Fields.CacheSharedAcrossDomains,
			tls.cipherPreset, tls.ocspStapling, tls.clientAuth, tls.clientCAPEM,
			request.Fields.CacheStatusHeader,
			request.Fields.HTTP2Enabled, request.Fields.HTTP3Enabled, request.Fields.TLSPreferServerCiphers,
			tls.cipherSuites,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrDomainConflict
			}
			return siteTLSProfileViolation(err)
		}
		if err := insertOriginPool(ctx, tx, siteID, *request.OriginPool, s.now().UTC()); err != nil {
			return err
		}
		hsts := creationDefaults.HSTSEnabled
		if request.Fields.hstsDefault != nil {
			hsts = *request.Fields.hstsDefault // the owner's 默认设置 > HSTS
		}
		access := map[string]any{}
		if hsts && request.Fields.HTTPSEnabled && len(request.Fields.HTTPSPorts) != 0 {
			access["hsts"] = map[string]any{
				"max_age_seconds": systemconfig.DefaultHSTSMaxAgeSeconds, "include_subdomains": false, "preload": false}
		}
		// 默认设置 > Gzip：开为平台默认的压缩类型（系统设置 > 网站默认 > Gzip 类型），关为站点显式关闭。
		// 平台未配置压缩类型时，开启无可压缩对象，保持节点默认。
		if gzip := request.Fields.gzipDefault; gzip != nil && (!*gzip || len(creationDefaults.GzipTypes) != 0) {
			compression := map[string]any{"enabled": *gzip, "types": []string{}, "min_length_bytes": 0}
			if *gzip {
				compression["types"], compression["min_length_bytes"] = canonicalGzipTypes(creationDefaults.GzipTypes), siteDefaultGzipMinLength
			}
			access["compression"] = compression
		}
		if len(access) != 0 {
			encoded, err := json.Marshal(access)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_access_settings(scope_id,site_id,settings,updated_by_user_id,updated_at)
				VALUES($1,$2,$3,$4,$5)`, request.TargetScopeID, siteID, string(encoded), actor.UserID, s.now().UTC()); err != nil {
				return err
			}
		}
		if err := appendSiteDomainFacts(ctx, tx, request.TargetScopeID, siteID, 1, nil,
			request.Fields.Domains, actor, request.RequestID, s.now().UTC()); err != nil {
			return err
		}
		if cnameIntent != nil {
			if err := insertCNAMEIntentFact(ctx, tx, *cnameIntent, s.now().UTC()); err != nil {
				return err
			}
		}
		if request.DNSProviderID != nil {
			err := enqueueSiteAutoDNS(ctx, tx, request.TargetScopeID, siteID, *request.DNSProviderID, s.now().UTC())
			// 默认设置里的账号已停用/吊销/删除：不添加记录，建站照常（请求里点名的账号仍拒绝）。
			if err != nil && !(request.dnsProviderDefaulted && errors.Is(err, ErrAutoDNSProvider)) {
				return err
			}
		}
		// 默认设置复制快照（fp-site5b）：规则库复制并绑定、HTTP 策略随站点创建。
		if err := request.userDefaults.copySiteDefaults(ctx, tx, actor, request, siteID, s.now().UTC()); err != nil {
			return err
		}
		// 网站缓存 / 条件源站默认文档（fp-site6）：写成新站自己的缓存策略与条件源站，随 site.create 发布。
		if err := request.userDefaults.copySiteDefaultDocuments(ctx, tx, s.auditor, actor, request, siteID, s.now().UTC()); err != nil {
			return err
		}
		item, err := selectSite(ctx, tx, siteID)
		if err != nil {
			return err
		}
		result.Site = item
		if err := enqueueAutomaticMutation(ctx, tx, actor, request.TargetScopeID, item.ID,
			"site.create", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      request.TargetScopeID,
			ActorUserID:  &actor.UserID,
			Action:       "site.create",
			ResourceType: "site",
			ResourceID:   item.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Payload: automaticAuditPayload(actor, request.TargetScopeID, "site.create", map[string]any{
				"version": item.Revision, "status": item.Status,
			}),
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site.create", request.IdempotencyKey, item.ID, 201, item)
	}
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	var denial error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		if err := lockEdgeConfigurationScope(ctx, tx, targetScopeID); err != nil {
			return err
		}
		scopeID, deleted, currentlyEnabled, locked, _, err := s.lockSite(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if scopeID != targetScopeID {
			return ErrNotFound
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "site.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored site update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if locked && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if deleted {
			return ErrNotFound
		}
		currentDomains, err := selectActiveSiteDomains(ctx, tx, scopeID, request.ID)
		if err != nil {
			return err
		}
		var cacheSharedBefore, defaultBefore, cacheStatusBefore bool
		var tlsBefore siteTLSAudit
		if err := tx.QueryRow(ctx, `SELECT cache_shared_across_domains,cache_status_header,tls_protocols,tls_cipher_preset,tls_ocsp_stapling,
			tls_client_auth,COALESCE(encode(sha256(convert_to(tls_client_ca_pem,'UTF8')),'hex'),''),is_default,
			http2_enabled,http3_enabled,tls_prefer_server_ciphers,tls_cipher_suites FROM sites WHERE id=$1`,
			request.ID).Scan(&cacheSharedBefore, &cacheStatusBefore, &tlsBefore.Protocols, &tlsBefore.CipherPreset, &tlsBefore.OCSPStapling,
			&tlsBefore.ClientAuth, &tlsBefore.ClientCASHA256, &defaultBefore,
			&tlsBefore.HTTP2, &tlsBefore.HTTP3, &tlsBefore.PreferServerCiphers, &tlsBefore.CipherSuites); err != nil {
			return err
		}
		if currentlyEnabled && !request.Fields.Enabled {
			if err := marketmanaged.GuardScope(ctx, tx, actor.UserID, scopeID); err != nil {
				return err
			}
		}
		if err := domaintrust.CheckSiteDomainsTx(ctx, tx, actor.ScopeKind, scopeID,
			addedDomains(currentDomains, request.Fields.Domains)); err != nil {
			return err
		}
		if request.Fields.Enabled {
			delta := int64(0)
			if !currentlyEnabled {
				delta = int64(len(request.Fields.Domains))
			} else if len(request.Fields.Domains) > len(currentDomains) {
				delta = int64(len(request.Fields.Domains) - len(currentDomains))
			}
			if err := s.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
				AuditScopeID:   scopeID,
				ActorUserID:    actor.UserID,
				ResourceID:     request.ID,
				RequestID:      request.RequestID,
				Operation:      "site.update",
				ExpansionDelta: delta,
			}); err != nil {
				if entitlementguard.IsDenial(err) {
					denial = err
					return nil
				}
				return err
			}
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, scopeID, "site.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored site update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		// 默认站点 after every check that may end the write without error
		// (an entitlement denial commits): the previous default is only
		// cleared when this update goes through
		if actor.ScopeKind != "platform" {
			request.Fields.IsDefault = defaultBefore // the platform's setting
		}
		if request.Fields.IsDefault != defaultBefore {
			if err := s.switchDefaultSite(ctx, tx, actor, request.ID, request.Fields.IsDefault, request.RequestID, request.SourceIP); err != nil {
				return err
			}
		}

		currentPool, err := selectOriginPool(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		compatibilityOrigins, _ := originCompatibility(currentPool)
		if !slices.Equal(request.Fields.Origins, compatibilityOrigins) {
			if !defaultOnlyOriginPool(currentPool) {
				return ErrOriginSectionConflict
			}
			currentPool = defaultOriginPool(request.Fields.originItems)
			if err := replaceOriginPool(ctx, tx, request.ID, currentPool, s.now().UTC()); err != nil {
				return err
			}
		}
		request.Fields.Origins, request.Fields.originHosts = originCompatibility(currentPool)
		ownerID, err := preservePackageBinding(ctx, tx, scopeID, request.ID, &request.Fields)
		if err != nil {
			return err
		}
		cnameIntent, err := prepareCNAMEWriteIntent(ctx, tx, actor, uuid.Nil, scopeID, request.ID,
			&request.Fields, request.ExpectedRevision+1, request.IdempotencyKey, request.RequestID)
		if err != nil {
			return err
		}
		before := SiteFields{Domains: currentDomains}
		var forceBefore bool
		if err := tx.QueryRow(ctx, `SELECT http_ports,https_ports,package_subscription_id,https_enabled,force_https FROM sites WHERE id=$1`,
			request.ID).Scan(&before.HTTPPorts, &before.HTTPSPorts, &before.PackageSubscriptionID, &before.HTTPSEnabled, &forceBefore); err != nil {
			return err
		}
		if err := checkHTTPSCertificate(ctx, tx, request.ID, before.HTTPSEnabled, forceBefore, request.Fields); err != nil {
			return err
		}
		if !packageContraction(before, request.Fields) {
			if err := checkPackageSiteChange(ctx, tx, scopeID, ownerID, request.ID, request.Fields, s.now().UTC()); err != nil {
				return err
			}
		}
		var cnameTaskID any
		if cnameIntent != nil {
			request.Fields.PackageSubscriptionID = cnameIntent.nullablePackageSubscription()
			cnameTaskID = cnameIntent.jobID
			if err := insertCNAMEIntentJob(ctx, tx, *cnameIntent, s.now().UTC()); err != nil {
				return err
			}
		}

		item, err := scanSite(tx.QueryRow(ctx, `
			UPDATE sites SET
				domain = $2, http_ports = $3, https_ports = $4, origins = $5,
				origin_hosts=$6,
				cname=CASE WHEN $20::uuid IS NOT NULL OR cname_mode IS NOT NULL THEN cname ELSE $7 END,
				https_enabled=$8,enabled=$9,
				status = $10, is_default = $11, package_id = $12,
				package_name = $13, group_id = $14, group_name = $15,
				package_subscription_id=$16,
				cname_mode=CASE WHEN $20::uuid IS NULL THEN cname_mode ELSE $17 END,
				cname_domain=CASE WHEN $20::uuid IS NULL THEN cname_domain ELSE $18 END,
				cname_hostname2=CASE WHEN $20::uuid IS NULL THEN cname_hostname2 ELSE $19 END,
				cname_state=CASE WHEN $20::uuid IS NULL THEN cname_state ELSE 'pending' END,
					cname_task_id=COALESCE($20,cname_task_id),
					cname_current_revision=CASE WHEN $20::uuid IS NULL THEN cname_current_revision ELSE COALESCE(cname_current_revision,0)+1 END,
					ipv6_enabled = $25,
					ipv6_runtime_state = CASE WHEN ipv6_enabled = $25 THEN ipv6_runtime_state ELSE 'pending' END,
					tls_protocols=COALESCE($24::text[],tls_protocols),
					-- Forced HTTPS ends with HTTPS; a redirect port ends with its port.
					force_https=CASE WHEN NOT $8 OR cardinality($4::text[])=0 THEN false
						ELSE COALESCE($26::boolean,force_https) END,
					https_redirect_port=CASE WHEN COALESCE($27::integer,https_redirect_port)::text=ANY($4::text[])
						THEN COALESCE($27::integer,https_redirect_port) ELSE 0 END,
					cache_shared_across_domains=COALESCE($28::boolean,cache_shared_across_domains),
					cache_status_header=COALESCE($33::boolean,cache_status_header),
					tls_cipher_preset=COALESCE($29::text,tls_cipher_preset),
					tls_cipher_suites=CASE WHEN $29::text IS NULL THEN tls_cipher_suites ELSE $38::text[] END,
					tls_ocsp_stapling=COALESCE($30::boolean,tls_ocsp_stapling),
					tls_client_auth=COALESCE($31::text,tls_client_auth),
					tls_client_ca_pem=CASE WHEN $32::text IS NULL THEN tls_client_ca_pem ELSE NULLIF($32::text,'') END,
					http2_enabled=COALESCE($34::boolean,http2_enabled),
					http3_enabled=COALESCE($35::boolean,http3_enabled),
					tls_prefer_server_ciphers=CASE WHEN $37::boolean THEN NULL
						ELSE COALESCE($36::boolean,tls_prefer_server_ciphers) END,
				revision=revision+1,updated_by_user_id=$21,updated_at=$22
			WHERE id=$1 AND revision=$23 AND deleted_at IS NULL
			RETURNING `+siteColumns("sites")+`,
			          (SELECT display_name FROM users WHERE id = sites.owner_user_id),
			          (SELECT display_id::text FROM users WHERE id = sites.owner_user_id)`,
			request.ID,
			request.Fields.Domain,
			request.Fields.HTTPPorts,
			request.Fields.HTTPSPorts,
			request.Fields.Origins,
			request.Fields.originHosts,
			request.Fields.CNAME,
			request.Fields.HTTPSEnabled,
			request.Fields.Enabled,
			request.Fields.Status,
			request.Fields.IsDefault,
			request.Fields.PackageID,
			nullableText(request.Fields.PackageName),
			request.Fields.GroupID,
			nullableText(request.Fields.GroupName),
			request.Fields.PackageSubscriptionID,
			func() string {
				if cnameIntent != nil {
					return cnameIntent.mode
				}
				return ""
			}(),
			func() any {
				if cnameIntent != nil {
					return cnameIntent.domain
				}
				return nil
			}(),
			func() any {
				if cnameIntent != nil {
					return cnameIntent.hostname
				}
				return nil
			}(), cnameTaskID,
			actor.UserID,
			s.now().UTC(),
			request.ExpectedRevision,
			func() []string {
				if request.Fields.tlsProtocolsDefaulted {
					return nil // keep the stored protocols
				}
				return request.Fields.TLSProtocols
			}(),
			request.Fields.IPv6Enabled,
			request.Fields.ForceHTTPS, request.Fields.HTTPSRedirectPort, request.Fields.CacheSharedAcrossDomains,
			request.Fields.TLSCipherPreset, request.Fields.TLSOCSPStapling, request.Fields.TLSClientAuth,
			request.Fields.TLSClientCAPEM, request.Fields.CacheStatusHeader,
			request.Fields.HTTP2Enabled, request.Fields.HTTP3Enabled, request.Fields.TLSPreferServerCiphers,
			request.Fields.TLSPreferServerCiphersReset, request.Fields.TLSCipherSuites,
		))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			if isUniqueViolation(err) {
				return ErrDomainConflict
			}
			return siteTLSProfileViolation(err)
		}
		if cnameIntent != nil {
			if err := insertCNAMEIntentFact(ctx, tx, *cnameIntent, s.now().UTC()); err != nil {
				return err
			}
		}
		if err := appendSiteDomainFacts(ctx, tx, scopeID, request.ID, item.Revision, currentDomains,
			request.Fields.Domains, actor, request.RequestID, s.now().UTC()); err != nil {
			return err
		}
		item.Domains = append([]string(nil), request.Fields.Domains...)
		item.Domain = item.Domains[0]
		if item.HTTPSCertificateBound, err = siteCertificateBound(ctx, tx, item.ID); err != nil {
			return err
		}
		result.Site = item
		if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, item.ID,
			"site.update", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      scopeID,
			ActorUserID:  &actor.UserID,
			Action:       "site.update",
			ResourceType: "site",
			ResourceID:   item.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Payload: automaticAuditPayload(actor, scopeID, "site.update", map[string]any{
				"version": item.Revision, "status": item.Status,
			}),
		}); err != nil {
			return err
		}
		if tlsAfter := siteTLSAuditOf(item); !reflect.DeepEqual(tlsAfter, tlsBefore) {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "site.tls_profile.update",
				ResourceType: "site", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
				Payload: map[string]any{
					"ip": request.SourceIP, "site_domain": item.Domain, "version": item.Revision,
					"actor_scope_id": actor.ScopeID.String(), "target_scope_id": scopeID.String(),
					"changes": tlsBefore.changes(tlsAfter),
				},
			}); err != nil {
				return err
			}
		}
		if item.CacheSharedAcrossDomains != cacheSharedBefore {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID:      scopeID,
				ActorUserID:  &actor.UserID,
				Action:       "site.cache_sharing.update",
				ResourceType: "site",
				ResourceID:   item.ID.String(),
				RequestID:    request.RequestID,
				Result:       "success",
				Payload: map[string]any{
					"ip": request.SourceIP, "site_domain": item.Domain, "version": item.Revision,
					"actor_scope_id": actor.ScopeID.String(), "target_scope_id": scopeID.String(),
					"changes": map[string]any{"cache_shared_across_domains": map[string]any{
						"from": cacheSharedBefore, "to": item.CacheSharedAcrossDomains,
					}},
				},
			}); err != nil {
				return err
			}
		}
		if item.CacheStatusHeader != cacheStatusBefore {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID:      scopeID,
				ActorUserID:  &actor.UserID,
				Action:       "site.cache_status_header.update",
				ResourceType: "site",
				ResourceID:   item.ID.String(),
				RequestID:    request.RequestID,
				Result:       "success",
				Payload: map[string]any{
					"ip": request.SourceIP, "site_domain": item.Domain, "version": item.Revision,
					"actor_scope_id": actor.ScopeID.String(), "target_scope_id": scopeID.String(),
					"changes": map[string]any{"cache_status_header": map[string]any{
						"from": cacheStatusBefore, "to": item.CacheStatusHeader,
					}},
				},
			}); err != nil {
				return err
			}
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site.update", request.IdempotencyKey, item.ID, 200, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update site: %w", claimSuspendedError(err))
	}
	if denial != nil {
		return WriteResult{}, fmt.Errorf("update site: %w", denial)
	}
	return result, nil
}

func (s *Store) UpdateOrigin(
	ctx context.Context,
	actor Actor,
	request UpdateOriginRequest,
	digest [32]byte,
) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		if err := lockEdgeConfigurationScope(ctx, tx, targetScopeID); err != nil {
			return err
		}
		scopeID, deleted, _, locked, currentRevision, err := s.lockSite(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if scopeID != targetScopeID {
			return ErrNotFound
		}
		stored, err := s.claimOriginWrite(ctx, tx, actor, request.ID, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if stored.Found {
			if err := decodeStoredSite(stored.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored site origin response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if locked && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if deleted {
			return ErrNotFound
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}

		previous, err := selectOriginPool(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		// 网站级 L2 配置 is the platform's (仅管理员可设): a
		// tenant's write keeps the stored one
		if actor.ScopeKind != "platform" {
			request.Pool.L2Mode, request.Pool.L2ConfigID = previous.L2Mode, previous.L2ConfigID
		}
		if err := checkOriginAuthHTTPS(ctx, tx, request.ID, request.Pool); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := replaceOriginPool(ctx, tx, request.ID, request.Pool, now); err != nil {
			return err
		}
		origins, hosts := originCompatibility(request.Pool)
		item, err := scanSite(tx.QueryRow(ctx, `
			UPDATE sites SET
				origins = $2, origin_hosts = $3, revision = revision + 1,
				updated_by_user_id = $4, updated_at = $5
			WHERE id = $1 AND revision = $6 AND deleted_at IS NULL
			RETURNING `+siteColumns("sites")+`,
			          (SELECT display_name FROM users WHERE id = sites.owner_user_id),
			          (SELECT display_id::text FROM users WHERE id = sites.owner_user_id)`,
			request.ID, origins, hosts, actor.UserID, now, request.ExpectedRevision))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		if item.HTTPSCertificateBound, err = siteCertificateBound(ctx, tx, item.ID); err != nil {
			return err
		}
		result.Site = item
		if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, item.ID,
			"site.origin.update", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      scopeID,
			ActorUserID:  &actor.UserID,
			Action:       "site.origin.update",
			ResourceType: "site",
			ResourceID:   request.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Changes:      originForwardingChanges(previous, request.Pool),
			Payload: automaticAuditPayload(actor, scopeID, "site.origin.update", map[string]any{
				"from_version":        request.ExpectedRevision,
				"to_version":          item.Revision,
				"from_balance_method": previous.BalanceMethod,
				"to_balance_method":   request.Pool.BalanceMethod,
				"from_origin_count":   len(previous.Origins),
				"to_origin_count":     len(request.Pool.Origins),
				"from_enabled_count":  enabledOriginCount(previous),
				"to_enabled_count":    enabledOriginCount(request.Pool),
			}),
		}); err != nil {
			return err
		}
		return s.completeOriginWrite(ctx, tx, actor, request.IdempotencyKey, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update site origin pool: %w", err)
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (DeleteResult, error) {
	var result DeleteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.deleteTx(ctx, tx, actor, request, digest, &result)
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete site: %w", err)
	}
	return result, nil
}

// deleteTx is the site delete inside tx (Delete, Transfer).
func (s *Store) deleteTx(ctx context.Context, tx pgx.Tx, actor Actor, request DeleteRequest, digest [32]byte,
	result *DeleteResult) error {
	{
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if !request.preauthorized {
			if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
				return err
			}
		}
		scopeID, deleted, _, locked, _, err := s.lockSite(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if scopeID != targetScopeID {
			return ErrNotFound
		}
		if !deleted && locked && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		write, err := s.claimWrite(ctx, tx, actor.UserID, scopeID, "site.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			result.Replayed = true
			return nil
		}
		if deleted {
			return ErrNotFound
		}
		if err := marketmanaged.GuardScope(ctx, tx, actor.UserID, scopeID); err != nil {
			return err
		}
		currentDomains, err := selectActiveSiteDomains(ctx, tx, scopeID, request.ID)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		command, err := tx.Exec(ctx, `
			UPDATE sites
			SET deleted_at = $2, updated_at = $2, updated_by_user_id = $3, revision = revision + 1
			WHERE id = $1 AND revision = $4 AND deleted_at IS NULL`,
			request.ID, now, actor.UserID, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() == 0 {
			return ErrRevisionConflict
		}
		if err := appendSiteDomainFacts(ctx, tx, scopeID, request.ID, request.ExpectedRevision+1,
			currentDomains, nil, actor, request.RequestID, now); err != nil {
			return err
		}
		if err := cancelSiteCNAMEJobs(ctx, tx, actor, request.RequestID, scopeID, request.ID, now, cancelBackgroundJob); err != nil {
			return err
		}
		if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, request.ID,
			"site.delete", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      scopeID,
			ActorUserID:  &actor.UserID,
			Action:       "site.delete",
			ResourceType: "site",
			ResourceID:   request.ID.String(),
			RequestID:    request.RequestID,
			Result:       "success",
			Payload: automaticAuditPayload(actor, scopeID, "site.delete", map[string]any{
				"deleted_version": request.ExpectedRevision + 1,
			}),
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site.delete", request.IdempotencyKey, request.ID, 204, nil)
	}
}

func (s *Store) BatchAction(
	ctx context.Context,
	actor Actor,
	request BatchActionRequest,
	digest [32]byte,
) (BatchActionResult, error) {
	result := BatchActionResult{Items: make([]BatchActionItemResult, len(request.Items))}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		authorizationScopes, err := batchMutationScopes(ctx, tx, actor, request.Items)
		if err != nil {
			return err
		}
		if len(authorizationScopes) > 0 {
			if err := authorizeAutomaticMutations(ctx, tx, actor, authorizationScopes); err != nil {
				return err
			}
		}
		if request.Action == BatchActionSetProtocols {
			// the single-site update's lock order: configuration scope before
			// site rows (the protocol columns advance the scope revision)
			for _, scopeID := range authorizationScopes {
				if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
					return err
				}
			}
		}
		stored, err := s.claimBatchWrite(ctx, tx, actor, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if stored.Found {
			if err := json.Unmarshal(stored.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored site batch response: %w", err)
			}
			if err := validateStoredBatchSites(&result); err != nil {
				return fmt.Errorf("decode stored site batch response: %w", err)
			}
			result.Replayed = true
			return nil
		}

		type batchEntry struct {
			index   int
			request BatchActionItem
			current *Site
		}
		entries := make([]batchEntry, len(request.Items))
		for index, item := range request.Items {
			entries[index] = batchEntry{index: index, request: item}
			result.Items[index] = BatchActionItemResult{ID: item.ID}
		}
		lockOrder := append([]batchEntry(nil), entries...)
		sort.Slice(lockOrder, func(i, j int) bool {
			return lockOrder[i].request.ID.String() < lockOrder[j].request.ID.String()
		})
		currentByID := make(map[uuid.UUID]Site, len(lockOrder))
		for _, entry := range lockOrder {
			current, err := lockBatchSite(ctx, tx, actor, entry.request.ID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return err
			}
			currentByID[entry.request.ID] = current
		}
		for index := range entries {
			if current, found := currentByID[entries[index].request.ID]; found {
				entries[index].current = &current
			}
		}
		// Audit streams use per-scope advisory locks. Process after all site locks
		// and in scope order so cross-tenant platform batches cannot deadlock.
		sort.Slice(entries, func(i, j int) bool {
			leftScope, rightScope := actor.ScopeID, actor.ScopeID
			if entries[i].current != nil {
				leftScope = entries[i].current.ScopeID
			}
			if entries[j].current != nil {
				rightScope = entries[j].current.ScopeID
			}
			if leftScope != rightScope {
				return leftScope.String() < rightScope.String()
			}
			return entries[i].request.ID.String() < entries[j].request.ID.String()
		})

		changedScopes := make(map[uuid.UUID]struct{})
		// set_protocols: the first updated site of each scope (entries are in
		// scope, then site order)
		protocolScopes := make(map[uuid.UUID]uuid.UUID)
		for _, entry := range entries {
			itemResult := &result.Items[entry.index]
			auditScopeID := actor.ScopeID
			if entry.current == nil {
				setBatchFailure(itemResult, "site_not_found")
				if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, nil); err != nil {
					return err
				}
				continue
			}
			current := *entry.current
			auditScopeID = current.ScopeID
			if current.Lock.Locked && actor.ScopeKind == "tenant" {
				setBatchFailure(itemResult, "site_locked")
				if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
					return err
				}
				continue
			}
			if current.Revision != entry.request.ExpectedRevision {
				setBatchFailure(itemResult, "version_conflict")
				if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
					return err
				}
				continue
			}
			if request.Action == BatchActionDisable || request.Action == BatchActionDelete {
				if err := marketmanaged.GuardScope(ctx, tx, actor.UserID, current.ScopeID); errors.Is(err, marketmanaged.ErrManaged) {
					setBatchFailure(itemResult, "market_managed")
					if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
						return err
					}
					continue
				} else if err != nil {
					return err
				}
			}
			if request.Action == BatchActionRegenerateCNAME {
				fields, failureCode := batchCNAMERegenerationFields(current)
				if failureCode != "" {
					setBatchFailure(itemResult, failureCode)
					if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
						return err
					}
					continue
				}
				intent, err := prepareCNAMEWriteIntent(ctx, tx, actor, current.ownerID, current.ScopeID,
					current.ID, &fields, current.Revision+1,
					cnameBatchIntentKey(request.IdempotencyKey, current.ID), request.RequestID)
				if err != nil {
					switch {
					case errors.Is(err, ErrPermissionDenied):
						setBatchFailure(itemResult, "permission_denied")
					case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrNotFound):
						setBatchFailure(itemResult, "cname_not_regenerable")
					default:
						return err
					}
					if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
						return err
					}
					continue
				}
				if intent == nil {
					return ErrInvalidInput
				}
				now := s.now().UTC()
				if err := insertCNAMEIntentJob(ctx, tx, *intent, now); err != nil {
					return err
				}
				updated, err := scanSite(tx.QueryRow(ctx, `
					UPDATE sites SET
						package_subscription_id=$2,cname_mode=$3,cname_domain=$4,cname_hostname2=$5,
						cname_state='pending',cname_task_id=$6,
						cname_current_revision=COALESCE(cname_current_revision,0)+1,
						revision=revision+1,updated_by_user_id=$7,updated_at=$8
					WHERE id=$1 AND revision=$9 AND scope_id=$10 AND deleted_at IS NULL
					RETURNING `+siteColumns("sites")+`,
					          (SELECT display_name FROM users WHERE id=sites.owner_user_id),
					          (SELECT display_id::text FROM users WHERE id=sites.owner_user_id)`,
					// 写意图的取值：默认区域的投影把 cname_domain 记成 ''，意图记真实域名，
					// 412/479 触发器按意图匹配（与编辑路径一致），否则报 P1134。
					current.ID, fields.PackageSubscriptionID, intent.mode, intent.domain,
					intent.hostname, intent.jobID, actor.UserID, now,
					entry.request.ExpectedRevision, current.ScopeID))
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrRevisionConflict
				}
				if err != nil {
					return err
				}
				if err := insertCNAMEIntentFact(ctx, tx, *intent, now); err != nil {
					return err
				}
				itemResult.Status = "queued"
				itemResult.Site = &updated
				if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
					return err
				}
				continue
			}

			if request.Action == BatchActionSetProtocols {
				updated, err := s.setBatchSiteProtocols(ctx, tx, actor, request, current)
				if err != nil {
					return err
				}
				itemResult.Status = "updated"
				itemResult.Site = &updated
				if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
					return err
				}
				if _, found := protocolScopes[current.ScopeID]; !found {
					protocolScopes[current.ScopeID] = current.ID
				}
				continue
			}

			if request.Action == BatchActionEnable {
				if suspended, err := domaintrust.HasOpenSuspension(ctx, tx, current.ScopeID, current.ID); err != nil {
					return err
				} else if suspended {
					setBatchFailure(itemResult, "site_domain_claim_suspended")
					if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
						return err
					}
					continue
				}
				delta := int64(0)
				if !current.Enabled {
					delta = int64(len(current.Domains))
				}
				if err := s.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
					AuditScopeID:   current.ScopeID,
					ActorUserID:    actor.UserID,
					ResourceID:     current.ID,
					RequestID:      request.RequestID,
					Operation:      "site.batch.enable",
					ExpansionDelta: delta,
				}); err != nil {
					if !entitlementguard.IsDenial(err) {
						return err
					}
					setBatchFailure(itemResult, batchErrorCode(err))
					if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
						return err
					}
					continue
				}
				// Same package admission as a single-site update that enables the
				// site (PJ-C01): an expired or suspended subscription, or a
				// configuration over its limits, cannot be switched back on.
				if current.PackageSubscriptionID != nil {
					fields := SiteFields{Domains: current.Domains, HTTPPorts: current.HTTPPorts,
						HTTPSPorts: current.HTTPSPorts, Enabled: true, PackageSubscriptionID: current.PackageSubscriptionID}
					if err := checkPackageSiteChange(ctx, tx, current.ScopeID, current.ownerID, current.ID, fields, s.now().UTC()); err != nil {
						code, ok := batchPackageFailure(err)
						if !ok {
							return err
						}
						setBatchFailure(itemResult, code)
						if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
							return err
						}
						continue
					}
				}
			}

			now := s.now().UTC()
			if request.Action == BatchActionDelete {
				command, err := tx.Exec(ctx, `
					UPDATE sites SET
						deleted_at = $2, updated_at = $2, updated_by_user_id = $3,
						revision = revision + 1
					WHERE id = $1 AND revision = $4 AND deleted_at IS NULL`,
					current.ID, now, actor.UserID, entry.request.ExpectedRevision)
				if err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					return ErrRevisionConflict
				}
				if err := appendSiteDomainFacts(ctx, tx, current.ScopeID, current.ID,
					entry.request.ExpectedRevision+1, current.Domains, nil, actor, request.RequestID, now); err != nil {
					return err
				}
				if err := cancelSiteCNAMEJobs(ctx, tx, actor, request.RequestID, current.ScopeID, current.ID, now, cancelBackgroundJob); err != nil {
					return err
				}
				itemResult.Status = "deleted"
			} else {
				enabled := request.Action == BatchActionEnable
				status := StatusDisabled
				if enabled {
					status = StatusActive
				}
				updated, err := scanSite(tx.QueryRow(ctx, `
					UPDATE sites SET
						enabled = $2, status = $3, revision = revision + 1,
						updated_by_user_id = $4, updated_at = $5
					WHERE id = $1 AND revision = $6 AND deleted_at IS NULL
					RETURNING `+siteColumns("sites")+`,
					          (SELECT display_name FROM users WHERE id = sites.owner_user_id),
					          (SELECT display_id::text FROM users WHERE id = sites.owner_user_id)`,
					current.ID, enabled, status, actor.UserID, now, entry.request.ExpectedRevision))
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrRevisionConflict
				}
				if err != nil {
					return err
				}
				itemResult.Status = "updated"
				itemResult.Site = &updated
			}
			if err := s.appendBatchAudit(ctx, tx, actor, auditScopeID, request, entry.request, itemResult, &current); err != nil {
				return err
			}
			changedScopes[current.ScopeID] = struct{}{}
		}
		orderedChangedScopes := make([]uuid.UUID, 0, len(changedScopes))
		for scopeID := range changedScopes {
			orderedChangedScopes = append(orderedChangedScopes, scopeID)
		}
		sort.Slice(orderedChangedScopes, func(i, j int) bool {
			return orderedChangedScopes[i].String() < orderedChangedScopes[j].String()
		})
		for _, scopeID := range orderedChangedScopes {
			if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, uuid.Nil,
				"site.batch."+request.Action, request.RequestID); err != nil {
				return err
			}
		}
		// set_protocols republishes like a single-site update (site.update);
		// one request per scope, at the scope revision after every site.
		orderedProtocolScopes := make([]uuid.UUID, 0, len(protocolScopes))
		for scopeID := range protocolScopes {
			orderedProtocolScopes = append(orderedProtocolScopes, scopeID)
		}
		sort.Slice(orderedProtocolScopes, func(i, j int) bool {
			return orderedProtocolScopes[i].String() < orderedProtocolScopes[j].String()
		})
		for _, scopeID := range orderedProtocolScopes {
			if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, protocolScopes[scopeID],
				"site.update", request.RequestID); err != nil {
				return err
			}
		}
		return s.completeBatchWrite(ctx, tx, actor, request.IdempotencyKey, result)
	})
	if err != nil {
		return BatchActionResult{}, fmt.Errorf("batch action sites: %w", claimSuspendedError(err))
	}
	return result, nil
}

// setBatchSiteProtocols writes the protocol columns of one locked site at
// its expected revision (the caller checked it) and records the TLS change
// as a single-site update does (site.tls_profile.update).
func (s *Store) setBatchSiteProtocols(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request BatchActionRequest,
	current Site,
) (Site, error) {
	protocols := request.Protocols
	updated, err := scanSite(tx.QueryRow(ctx, `
		UPDATE sites SET
			http2_enabled=COALESCE($2::boolean,http2_enabled),
			http3_enabled=COALESCE($3::boolean,http3_enabled),
			tls_prefer_server_ciphers=CASE WHEN $5::boolean THEN NULL
				ELSE COALESCE($4::boolean,tls_prefer_server_ciphers) END,
			revision=revision+1,updated_by_user_id=$6,updated_at=$7
		WHERE id=$1 AND revision=$8 AND scope_id=$9 AND deleted_at IS NULL
		RETURNING `+siteColumns("sites")+`,
		          (SELECT display_name FROM users WHERE id=sites.owner_user_id),
		          (SELECT display_id::text FROM users WHERE id=sites.owner_user_id)`,
		current.ID, protocols.HTTP2Enabled, protocols.HTTP3Enabled, protocols.TLSPreferServerCiphers,
		protocols.TLSPreferServerCiphersReset, actor.UserID, s.now().UTC(), current.Revision, current.ScopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Site{}, ErrRevisionConflict
	}
	if err != nil {
		return Site{}, siteTLSProfileViolation(err)
	}
	before, after := siteTLSAuditOf(current), siteTLSAuditOf(updated)
	if reflect.DeepEqual(before, after) {
		return updated, nil
	}
	return updated, s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "site.tls_profile.update",
		ResourceType: "site", ResourceID: updated.ID.String(), RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"site_domain": updated.Domain, "version": updated.Revision,
			"actor_scope_id": actor.ScopeID.String(), "target_scope_id": current.ScopeID.String(),
			"changes": before.changes(after),
		},
	})
}

func (s *Store) appendBatchAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	scopeID uuid.UUID,
	request BatchActionRequest,
	item BatchActionItem,
	result *BatchActionItemResult,
	previous *Site,
) error {
	payload := map[string]any{
		"action":           request.Action,
		"expected_version": item.ExpectedRevision,
		"status":           result.Status,
	}
	payload = automaticAuditPayload(actor, scopeID, "site.batch."+request.Action, payload)
	if request.Protocols != nil {
		payload["protocols"] = request.Protocols
	}
	auditResult := "success"
	if result.Error != nil {
		auditResult = "failure"
		payload["error_code"] = result.Error.Code
	}
	if previous != nil {
		payload["from_enabled"] = previous.Enabled
		payload["from_status"] = previous.Status
		payload["from_version"] = previous.Revision
	}
	if result.Site != nil {
		payload["to_enabled"] = result.Site.Enabled
		payload["to_status"] = result.Site.Status
		payload["to_version"] = result.Site.Revision
	} else if result.Status == "deleted" {
		payload["deleted_version"] = item.ExpectedRevision + 1
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      scopeID,
		ActorUserID:  &actor.UserID,
		Action:       "site.batch." + request.Action,
		ResourceType: "site",
		ResourceID:   item.ID.String(),
		RequestID:    request.RequestID,
		Result:       auditResult,
		Payload:      payload,
	})
}

func authorizeAutomaticMutation(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID) error {
	err := edgeautopublish.AuthorizeMutationTx(ctx, tx, edgeautopublish.Actor{
		UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
	}, targetScopeID, edgeautopublish.PermissionSitesManage)
	if errors.Is(err, edgeautopublish.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return err
}

// lockEdgeConfigurationScope takes the publication lock order (configuration scope
// before resource rows). Site writes bump the scope revision through the
// sites/site_origin_pools/site_origins triggers (021); without this lock the
// site row is held while waiting on the scope row, the reverse of every
// scope-first writer.
func lockEdgeConfigurationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID)
	return err
}

func authorizeAutomaticMutations(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeIDs []uuid.UUID) error {
	err := edgeautopublish.AuthorizeMutationsTx(ctx, tx, edgeautopublish.Actor{
		UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
	}, targetScopeIDs, edgeautopublish.PermissionSitesManage)
	if errors.Is(err, edgeautopublish.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return err
}

func mutationTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, resourceID uuid.UUID) (uuid.UUID, error) {
	if actor.ScopeKind == "tenant" {
		return actor.ScopeID, nil
	}
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, resourceID).Scan(&scopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, err
	}
	return scopeID, nil
}

func batchMutationScopes(ctx context.Context, tx pgx.Tx, actor Actor, items []BatchActionItem) ([]uuid.UUID, error) {
	if actor.ScopeKind == "tenant" {
		return []uuid.UUID{actor.ScopeID}, nil
	}
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT scope_id FROM sites WHERE id=ANY($1::uuid[]) ORDER BY scope_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scopes := make([]uuid.UUID, 0)
	for rows.Next() {
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeID); err != nil {
			return nil, err
		}
		scopes = append(scopes, scopeID)
	}
	return scopes, rows.Err()
}

func enqueueAutomaticMutation(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	operation, requestID string,
) error {
	_, err := edgeautopublish.EnqueueTx(ctx, tx, edgeautopublish.EnqueueInput{
		Actor:         edgeautopublish.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind},
		TargetScopeID: targetScopeID, SourceKind: edgeautopublish.SourceSite,
		SourceResourceID: resourceID, Operation: operation, Reason: edgeautopublish.ReasonResourceMutation,
		Permission: edgeautopublish.PermissionSitesManage, SourceRequestID: requestID,
	})
	return err
}

func automaticAuditPayload(actor Actor, targetScopeID uuid.UUID, operation string, payload map[string]any) map[string]any {
	payload["actor_scope_id"] = actor.ScopeID.String()
	payload["target_scope_id"] = targetScopeID.String()
	payload["operation"] = operation
	payload["reason"] = edgeautopublish.ReasonResourceMutation
	return payload
}

func (s *Store) claimBatchWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
	digest [32]byte,
) (storedBatchWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedBatchWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO site_batch_write_requests (
			id, actor_user_id, actor_scope_id, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (actor_scope_id, actor_user_id, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, key, digest[:], s.now().UTC())
	if err != nil {
		return storedBatchWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedBatchWrite{}, nil
	}
	var existingDigest, responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, response_body, completed_at
		FROM site_batch_write_requests
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND idempotency_key = $3`,
		actor.ScopeID, actor.UserID, key).Scan(&existingDigest, &responseBody, &completedAt); err != nil {
		return storedBatchWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil || len(responseBody) == 0 {
		return storedBatchWrite{}, ErrIdempotencyConflict
	}
	return storedBatchWrite{Found: true, ResponseBody: responseBody}, nil
}

func (s *Store) completeBatchWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
	response BatchActionResult,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE site_batch_write_requests
		SET response_body = $4, completed_at = $5
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actor.ScopeID, actor.UserID, key, string(encoded), s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Store) claimOriginWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	siteID uuid.UUID,
	key string,
	digest [32]byte,
) (storedOriginWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedOriginWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO site_origin_write_requests (
			id, actor_scope_id, actor_user_id, site_id, idempotency_key, request_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (actor_scope_id, actor_user_id, idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, siteID, key, digest[:], s.now().UTC())
	if err != nil {
		return storedOriginWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedOriginWrite{}, nil
	}
	var existingDigest, responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, response_body, completed_at
		FROM site_origin_write_requests
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND idempotency_key = $3`,
		actor.ScopeID, actor.UserID, key).Scan(&existingDigest, &responseBody, &completedAt); err != nil {
		return storedOriginWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil || len(responseBody) == 0 {
		return storedOriginWrite{}, ErrIdempotencyConflict
	}
	return storedOriginWrite{Found: true, ResponseBody: responseBody}, nil
}

func (s *Store) completeOriginWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
	item Site,
) error {
	encoded, err := json.Marshal(item)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE site_origin_write_requests
		SET response_body = $4, completed_at = $5
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actor.ScopeID, actor.UserID, key, string(encoded), s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func insertOriginPool(
	ctx context.Context,
	tx pgx.Tx,
	siteID uuid.UUID,
	pool OriginPool,
	updatedAt time.Time,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO site_origin_pools (
			site_id, balance_method, failover_tries, connect_timeout_ms, read_timeout_ms,
			keepalive_enabled, keepalive_idle_timeout_ms, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		siteID, pool.BalanceMethod, pool.FailoverTries, pool.ConnectTimeoutMS, pool.ReadTimeoutMS,
		pool.KeepaliveEnabled, pool.KeepaliveIdleTimeoutMS, updatedAt); err != nil {
		return err
	}
	if err := updateOriginForwarding(ctx, tx, siteID, pool); err != nil {
		return err
	}
	return insertOriginRows(ctx, tx, siteID, pool.Origins)
}

// checkOriginAuthHTTPS refuses a pool that would break an enabled origin
// authentication rule: its source position must remain the same host on
// 443 and the pool HTTPS. With the site's origin
// auth switched off (490) the rules sign nothing and are not checked; the
// write switching it back on is.
func checkOriginAuthHTTPS(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, pool OriginPool) error {
	if !boolValue(pool.OriginAuthEnabled, true) {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT identity.source_position, revision.endpoint
		FROM origin_auth_rules identity
		JOIN LATERAL (SELECT enabled, deleted, endpoint FROM origin_auth_rule_revisions current_revision
			WHERE current_revision.rule_id=identity.id ORDER BY current_revision.revision DESC LIMIT 1) revision ON true
		WHERE identity.site_id=$1 AND revision.enabled AND NOT revision.deleted`, siteID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var position int
		var endpoint string
		if err := rows.Scan(&position, &endpoint); err != nil {
			return err
		}
		if pool.Scheme != OriginSchemeHTTPS || position < 1 || position > len(pool.Origins) ||
			pool.Origins[position-1].Port != 443 || endpoint != "https://"+pool.Origins[position-1].Host {
			return ErrOriginAuthRequiresHTTPS
		}
	}
	return rows.Err()
}

// updateOriginForwarding writes the pool's forwarding settings (367); the
// CA digest is computed by the database from the stored text.
func updateOriginForwarding(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, pool OriginPool) error {
	var hashKey, stickySource, stickyName, requestHost, sni, caPEM *string
	if pool.HashKey != "" {
		hashKey = &pool.HashKey
	}
	if pool.Sticky != nil {
		stickySource, stickyName = &pool.Sticky.Source, &pool.Sticky.Name
	}
	if pool.RequestHost.Mode == OriginRequestHostCustom {
		requestHost = &pool.RequestHost.Value
	}
	if pool.TLS.SNI != "" {
		sni = &pool.TLS.SNI
	}
	if pool.TLS.CAPEM != "" {
		caPEM = &pool.TLS.CAPEM
	}
	websocket := OriginWebSocket{Enabled: true}
	if pool.WebSocket != nil {
		websocket = *pool.WebSocket
	}
	allowed := websocket.AllowedOrigins
	if allowed == nil {
		allowed = []string{}
	}
	proxies := pool.TrustedProxyCIDRs
	if proxies == nil {
		proxies = []string{}
	}
	redirect := OriginFollowRedirect{MaxHops: DefaultFollowRedirectHops}
	if pool.FollowRedirect != nil {
		redirect = *pool.FollowRedirect
	}
	command, err := tx.Exec(ctx, `
		UPDATE site_origin_pools SET
			hash_key = $2, sticky_source = $3, sticky_name = $4, request_host_mode = $5, request_host = $6,
			origin_scheme = $7, https_port = $8, tls_sni = $9, tls_trust = $10, tls_ca_pem = $11,
			tls_ca_sha256 = CASE WHEN $11::text IS NULL THEN NULL ELSE sha256(convert_to($11::text, 'UTF8')) END,
			follow_port = $12, websocket_enabled = $13, websocket_allowed_origins = $14,
			trusted_proxy_cidrs = $15::text[]::cidr[], failback_mode = $16, health_check_path = $17,
			follow_redirect = $18, follow_redirect_max_hops = $19, follow_redirect_cross_origin = $20,
			search_engine_origin = NULLIF($21, ''), acme_passthrough = $22, response_buffering = $23,
			request_buffering = $24, l2_mode = $25, l2_config_id = $26, http_port = $27, origin_auth_enabled = $28
		WHERE site_id = $1`,
		siteID, hashKey, stickySource, stickyName, pool.RequestHost.Mode, requestHost,
		pool.Scheme, pool.HTTPSPort, sni, pool.TLS.Trust, caPEM,
		pool.FollowPort, websocket.Enabled, allowed, proxies, failbackMode(pool), healthCheckPath(pool),
		redirect.Enabled, redirect.MaxHops, redirect.CrossOrigin,
		pool.SearchEngineOrigin, pool.ACMEPassthrough, boolValue(pool.ResponseBuffering, true),
		boolValue(pool.RequestBuffering, true), siteL2Mode(pool.L2Mode), pool.L2ConfigID,
		originHTTPPort(pool), boolValue(pool.OriginAuthEnabled, true))
	if err != nil {
		if isL2ConfigReferenceViolation(err) {
			return ErrInvalidInput
		}
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrNotFound
	}
	if caPEM != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO site_origin_trust_bundles (sha256, pem)
			VALUES (sha256(convert_to($1::text, 'UTF8')), $1)
			ON CONFLICT (sha256) DO NOTHING`, *caPEM); err != nil {
			return err
		}
	}
	return nil
}

func allocateSiteDisplayID(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, updatedAt time.Time) (int64, error) {
	var displayID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at)
		VALUES($1,2,$2)
		ON CONFLICT(scope_id) DO UPDATE SET
			next_value=site_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1`, scopeID, updatedAt).Scan(&displayID); err != nil {
		return 0, fmt.Errorf("allocate site display ID: %w", err)
	}
	return displayID, nil
}

func replaceOriginPool(
	ctx context.Context,
	tx pgx.Tx,
	siteID uuid.UUID,
	pool OriginPool,
	updatedAt time.Time,
) error {
	command, err := tx.Exec(ctx, `
		UPDATE site_origin_pools SET
			balance_method = $2, failover_tries = $3, connect_timeout_ms = $4,
			read_timeout_ms = $5, keepalive_enabled = $6, keepalive_idle_timeout_ms = $7, updated_at = $8
		WHERE site_id = $1`,
		siteID, pool.BalanceMethod, pool.FailoverTries, pool.ConnectTimeoutMS, pool.ReadTimeoutMS,
		pool.KeepaliveEnabled, pool.KeepaliveIdleTimeoutMS, updatedAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err := updateOriginForwarding(ctx, tx, siteID, pool); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM site_origins WHERE site_id = $1`, siteID); err != nil {
		return err
	}
	return insertOriginRows(ctx, tx, siteID, pool.Origins)
}

func originHTTPPort(pool OriginPool) int {
	if pool.HTTPPort == 0 {
		return 80
	}
	return pool.HTTPPort
}

func failbackMode(pool OriginPool) string {
	if pool.FailbackMode == "" {
		return FailbackAuto
	}
	return pool.FailbackMode
}

func healthCheckPath(pool OriginPool) string {
	if pool.HealthCheckPath == "" {
		return "/"
	}
	return pool.HealthCheckPath
}

func insertOriginRows(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, origins []Origin) error {
	for index, origin := range origins {
		if _, err := tx.Exec(ctx, `
			INSERT INTO site_origins (site_id, position, host, port, weight, enabled, level, max_conns, port_inherited)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			siteID, index+1, origin.Host, origin.Port, origin.Weight, origin.Enabled, origin.Level, origin.MaxConns,
			origin.PortInherited); err != nil {
			return err
		}
	}
	return nil
}

func selectOriginPool(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (OriginPool, error) {
	var pool OriginPool
	var hashKey, stickySource, stickyName, requestHost, sni, caPEM *string
	websocket := OriginWebSocket{}
	var redirect OriginFollowRedirect
	var responseBuffering, requestBuffering, originAuth bool
	if err := tx.QueryRow(ctx, `
		SELECT balance_method, failover_tries, connect_timeout_ms, read_timeout_ms,
		       keepalive_enabled, keepalive_idle_timeout_ms,
		       hash_key, sticky_source, sticky_name, request_host_mode, request_host,
		       origin_scheme, https_port, tls_sni, tls_trust, tls_ca_pem,
		       follow_port, websocket_enabled, websocket_allowed_origins,
		       trusted_proxy_cidrs::text[], failback_mode, health_check_path,
		       follow_redirect, follow_redirect_max_hops, follow_redirect_cross_origin,
		       COALESCE(search_engine_origin, ''), acme_passthrough, response_buffering, request_buffering,
		       l2_mode, l2_config_id, http_port, origin_auth_enabled
		FROM site_origin_pools
		WHERE site_id = $1`, siteID).Scan(
		&pool.BalanceMethod, &pool.FailoverTries, &pool.ConnectTimeoutMS, &pool.ReadTimeoutMS,
		&pool.KeepaliveEnabled, &pool.KeepaliveIdleTimeoutMS,
		&hashKey, &stickySource, &stickyName, &pool.RequestHost.Mode, &requestHost,
		&pool.Scheme, &pool.HTTPSPort, &sni, &pool.TLS.Trust, &caPEM,
		&pool.FollowPort, &websocket.Enabled, &websocket.AllowedOrigins,
		&pool.TrustedProxyCIDRs, &pool.FailbackMode, &pool.HealthCheckPath,
		&redirect.Enabled, &redirect.MaxHops, &redirect.CrossOrigin,
		&pool.SearchEngineOrigin, &pool.ACMEPassthrough, &responseBuffering, &requestBuffering,
		&pool.L2Mode, &pool.L2ConfigID, &pool.HTTPPort, &originAuth,
	); err != nil {
		return OriginPool{}, err
	}
	pool.OriginAuthEnabled = &originAuth
	pool.ResponseBuffering, pool.RequestBuffering = &responseBuffering, &requestBuffering
	pool.FollowRedirect = &redirect
	if hashKey != nil {
		pool.HashKey = *hashKey
	}
	if stickySource != nil && stickyName != nil {
		pool.Sticky = &OriginSticky{Source: *stickySource, Name: *stickyName}
	}
	if requestHost != nil {
		pool.RequestHost.Value = *requestHost
	}
	if sni != nil {
		pool.TLS.SNI = *sni
	}
	if caPEM != nil {
		pool.TLS.CAPEM = *caPEM
	}
	pool.WebSocket = &websocket
	rows, err := tx.Query(ctx, `
		SELECT host, port, weight, enabled, level, max_conns, port_inherited
		FROM site_origins
		WHERE site_id = $1
		ORDER BY position`, siteID)
	if err != nil {
		return OriginPool{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var origin Origin
		if err := rows.Scan(&origin.Host, &origin.Port, &origin.Weight, &origin.Enabled, &origin.Level, &origin.MaxConns,
			&origin.PortInherited); err != nil {
			return OriginPool{}, err
		}
		pool.Origins = append(pool.Origins, origin)
	}
	if err := rows.Err(); err != nil {
		return OriginPool{}, err
	}
	return pool, nil
}

func selectSite(ctx context.Context, tx pgx.Tx, siteID uuid.UUID) (Site, error) {
	return scanSite(tx.QueryRow(ctx, `
		SELECT `+siteColumns("s")+`, u.display_name, u.display_id::text
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		WHERE s.id = $1`, siteID))
}

func originCompatibility(pool OriginPool) ([]string, []string) {
	origins := make([]string, len(pool.Origins))
	hosts := make([]string, len(pool.Origins))
	for index, origin := range pool.Origins {
		origins[index] = originCompatibilityEndpoint(origin)
		hosts[index] = origin.Host
	}
	return origins, hosts
}

func defaultOnlyOriginPool(pool OriginPool) bool {
	if pool.BalanceMethod != BalanceRoundRobin || pool.FailoverTries != 1 ||
		pool.ConnectTimeoutMS != 3000 || pool.ReadTimeoutMS != 30000 ||
		!pool.KeepsDefaultOriginReuse() {
		return false
	}
	for _, origin := range pool.Origins {
		if origin.Weight != 1 || !origin.Enabled {
			return false
		}
	}
	return true
}

func enabledOriginCount(pool OriginPool) int {
	count := 0
	for _, origin := range pool.Origins {
		if origin.Enabled {
			count++
		}
	}
	return count
}

func lockBatchSite(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (Site, error) {
	query := `
		SELECT ` + siteColumns("s") + `, u.display_name, u.display_id::text
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		WHERE s.id = $1 AND s.deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND s.scope_id = $2"
		args = append(args, actor.ScopeID)
	}
	query += " FOR UPDATE OF s"
	item, err := scanSite(tx.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Site{}, ErrNotFound
	}
	if err != nil {
		return Site{}, err
	}
	return item, nil
}

func setBatchFailure(result *BatchActionItemResult, code string) {
	result.Status = "failed"
	result.Error = &BatchItemError{Code: code}
}

func batchErrorCode(err error) string {
	switch {
	case errors.Is(err, entitlementguard.ErrUnavailable):
		return "entitlement_unavailable"
	case errors.Is(err, entitlementguard.ErrStateDenied):
		return "entitlement_state_denied"
	case errors.Is(err, entitlementguard.ErrFeatureDenied):
		return "entitlement_feature_denied"
	case errors.Is(err, entitlementguard.ErrQuotaDenied):
		return "entitlement_quota_denied"
	case errors.Is(err, entitlementguard.ErrQuotaExceeded):
		return "entitlement_quota_exceeded"
	default:
		return "internal_error"
	}
}

func (s *Store) changeLock(
	ctx context.Context,
	actor Actor,
	siteID uuid.UUID,
	expectedRevision int64,
	reason string,
	idempotencyKey string,
	requestID string,
	targetLocked bool,
	digest [32]byte,
) (WriteResult, error) {
	operation := "site.unlock"
	if targetLocked {
		operation = "site.lock"
	}
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, deleted, _, currentlyLocked, currentRevision, err := s.lockSite(ctx, tx, actor, siteID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, operation, idempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored %s response: %w", operation, err)
			}
			result.Replayed = true
			return nil
		}
		if deleted {
			return ErrNotFound
		}
		if currentRevision != expectedRevision {
			return ErrRevisionConflict
		}
		if currentlyLocked == targetLocked {
			return ErrLockStateConflict
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, scopeID, operation, idempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return fmt.Errorf("decode stored %s response: %w", operation, err)
			}
			result.Replayed = true
			return nil
		}

		now := s.now().UTC()
		var row rowScanner
		if targetLocked {
			row = tx.QueryRow(ctx, `
				UPDATE sites SET
					lock_reason = $2, locked_at = $3, locked_by_user_id = $4,
					revision = revision + 1, updated_by_user_id = $4, updated_at = $3
				WHERE id = $1 AND revision = $5 AND deleted_at IS NULL
				RETURNING `+siteColumns("sites")+`,
				          (SELECT display_name FROM users WHERE id = sites.owner_user_id),
				          (SELECT display_id::text FROM users WHERE id = sites.owner_user_id)`,
				siteID, reason, now, actor.UserID, expectedRevision)
		} else {
			row = tx.QueryRow(ctx, `
				UPDATE sites SET
					lock_reason = NULL, locked_at = NULL, locked_by_user_id = NULL,
					revision = revision + 1, updated_by_user_id = $2, updated_at = $3
				WHERE id = $1 AND revision = $4 AND deleted_at IS NULL
				RETURNING `+siteColumns("sites")+`,
				          (SELECT display_name FROM users WHERE id = sites.owner_user_id),
				          (SELECT display_id::text FROM users WHERE id = sites.owner_user_id)`,
				siteID, actor.UserID, now, expectedRevision)
		}
		item, err := scanSite(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		result.Site = item
		payload := map[string]any{"version": item.Revision, "locked": targetLocked}
		if targetLocked {
			payload["reason"] = reason
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      scopeID,
			ActorUserID:  &actor.UserID,
			Action:       operation,
			ResourceType: "site",
			ResourceID:   siteID.String(),
			RequestID:    requestID,
			Result:       "success",
			Payload:      payload,
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operation, idempotencyKey, siteID, 200, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("%s: %w", operation, err)
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, id uuid.UUID) (Site, error) {
	query := `
		SELECT ` + siteColumns("s") + `, u.display_name, u.display_id::text
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		WHERE s.id = $1 AND s.deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND s.scope_id = $2"
		args = append(args, actor.ScopeID)
	}
	item, err := scanSite(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Site{}, ErrNotFound
	}
	if err != nil {
		return Site{}, fmt.Errorf("get site: %w", err)
	}
	if err := s.projectStatusRecovery(ctx, s.pool, &item); err != nil {
		return Site{}, fmt.Errorf("project site status: %w", err)
	}
	if err := s.projectAccessReadiness(ctx, s.pool, &item); err != nil {
		return Site{}, err
	}
	return item, nil
}

func (s *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ListResult{}, fmt.Errorf("begin site list transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	where, args := listWhere(actor, filter)
	var total int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		`+where, args...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count sites: %w", err)
	}
	limitPosition := len(args) + 1
	offsetPosition := len(args) + 2
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, `
		SELECT `+siteColumns("s")+`, u.display_name, u.display_id::text
		FROM sites s
		JOIN users u ON u.id = s.owner_user_id
		`+where+`
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT $`+fmt.Sprint(limitPosition)+` OFFSET $`+fmt.Sprint(offsetPosition), args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list sites: %w", err)
	}
	defer rows.Close()
	items := make([]ListItem, 0, filter.Limit)
	scopes := make([]uuid.UUID, 0, filter.Limit)
	for rows.Next() {
		item, err := scanSite(rows)
		if err != nil {
			return ListResult{}, fmt.Errorf("scan site list item: %w", err)
		}
		items = append(items, toListItem(item))
		scopes = append(scopes, item.ScopeID)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("list sites: %w", err)
	}
	rows.Close()
	// PJ-C04: one page-wide projection (a fixed number of queries) instead of
	// re-reading every site and projecting it row by row.
	if err := s.projectListStatus(ctx, tx, items, scopes); err != nil {
		return ListResult{}, fmt.Errorf("project site status: %w", err)
	}
	ids := make([]uuid.UUID, len(items))
	for index := range items {
		ids[index] = items[index].ID
	}
	autoDNS, err := loadAutoDNSStatuses(ctx, tx, ids)
	if err != nil {
		return ListResult{}, err
	}
	for index := range items {
		items[index].AutoDNS = autoDNS[items[index].ID]
	}
	// 接入状态：一条语句读整页事实（不在请求里做解析）。
	if err := s.projectListAccessReadiness(ctx, tx, items); err != nil {
		return ListResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit site list transaction: %w", err)
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *Store) lockSite(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (uuid.UUID, bool, bool, bool, int64, error) {
	var scopeID uuid.UUID
	var deletedAt *time.Time
	var enabled bool
	var lockedAt *time.Time
	var revision int64
	query := `
		SELECT s.scope_id, s.deleted_at, s.enabled, s.locked_at, s.revision
		FROM sites s
		JOIN access_scopes scope ON scope.id = s.scope_id
		WHERE s.id = $1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND s.scope_id = $2"
		args = append(args, actor.ScopeID)
	}
	query += " FOR UPDATE OF s"
	if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &deletedAt, &enabled, &lockedAt, &revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, false, false, 0, ErrNotFound
		}
		return uuid.Nil, false, false, false, 0, err
	}
	return scopeID, deletedAt != nil, enabled, lockedAt != nil, revision, nil
}

func (s *Store) findWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	operation string,
	key string,
	digest [32]byte,
) (storedWrite, bool, error) {
	var existingDigest []byte
	var resourceID *uuid.UUID
	var responseBody []byte
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT request_digest, resource_id, response_body, completed_at
		FROM site_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
		actorUserID, operation, key,
	).Scan(&existingDigest, &resourceID, &responseBody, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || resourceID == nil || completedAt == nil {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{Replayed: true, ResourceID: *resourceID, ResponseBody: responseBody}, true, nil
}

func (s *Store) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	targetScopeID uuid.UUID,
	operation string,
	key string,
	digest [32]byte,
) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO site_write_requests (
			id, actor_user_id, target_scope_id, operation, idempotency_key, request_digest
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actorUserID, targetScopeID, operation, key, digest[:])
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	var existingDigest []byte
	var resourceID *uuid.UUID
	var responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, resource_id, response_body, completed_at
		FROM site_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
		actorUserID, operation, key,
	).Scan(&existingDigest, &resourceID, &responseBody, &completedAt); err != nil {
		return storedWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || resourceID == nil || completedAt == nil {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return storedWrite{Replayed: true, ResourceID: *resourceID, ResponseBody: responseBody}, nil
}

func (s *Store) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	operation string,
	key string,
	resourceID uuid.UUID,
	status int,
	body any,
) error {
	var encoded any
	var err error
	if body != nil {
		payload, marshalErr := json.Marshal(body)
		err = marshalErr
		if err != nil {
			return err
		}
		encoded = string(payload)
	}
	command, err := tx.Exec(ctx, `
		UPDATE site_write_requests
		SET resource_id = $4, response_status = $5, response_body = $6, completed_at = $7
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actorUserID, operation, key, resourceID, status, encoded, s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func authorizeTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, ownerID uuid.UUID) error {
	var kind string
	var ownerMember bool
	if err := tx.QueryRow(ctx, `
		SELECT scope.kind,
		       EXISTS (
		           SELECT 1 FROM memberships m
		           WHERE m.scope_id = scope.id AND m.user_id = $2 AND m.status = 'active'
		       )
		FROM access_scopes scope
		WHERE scope.id = $1`, scopeID, ownerID).Scan(&kind, &ownerMember); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidInput
		}
		return err
	}
	if kind != "tenant" || !ownerMember {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != ownerID) {
		return ErrPermissionDenied
	}
	return nil
}

func listWhere(actor Actor, filter ListFilter) (string, []any) {
	conditions := []string{"s.deleted_at IS NULL"}
	args := make([]any, 0, 18)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if actor.ScopeKind == "tenant" {
		add("s.scope_id = $%d", actor.ScopeID)
	}
	if filter.Domain != "" {
		// a positive decimal also matches the site display ID
		// exactly, alongside the domain substring.
		if displayID, err := strconv.ParseInt(filter.Domain, 10, 64); err == nil && displayID > 0 &&
			strconv.FormatInt(displayID, 10) == filter.Domain {
			args = append(args, filter.Domain, displayID)
			conditions = append(conditions, fmt.Sprintf("(position($%d in lower(s.domain)) > 0 OR s.display_id = $%d)",
				len(args)-1, len(args)))
		} else {
			add("position($%d in lower(s.domain)) > 0", filter.Domain)
		}
	}
	if len(filter.Domains) > 0 {
		add("s.domain = ANY($%d::text[])", filter.Domains)
	}
	if filter.OriginIP != "" {
		add("$%d = ANY(s.origin_hosts)", filter.OriginIP)
	}
	if len(filter.SiteIDs) > 0 {
		add("s.id = ANY($%d::uuid[])", filter.SiteIDs)
	}
	if filter.Owner != "" {
		args = append(args, strings.ToLower(filter.Owner))
		position := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(lower(u.display_name) LIKE '%%' || $%d || '%%' OR lower(u.username) LIKE '%%' || $%d || '%%' OR u.id::text = $%d)",
			position, position, position,
		))
	}
	if filter.PackageID != nil {
		add("s.package_id = $%d", *filter.PackageID)
	}
	if filter.Package != "" {
		add("position(lower($%d) in lower(COALESCE(s.package_name, ''))) > 0", filter.Package)
	}
	if filter.Site != "" {
		args = append(args, filter.Site)
		position := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(position($%d in lower(s.domain)) > 0 OR s.display_id::text = $%d)", position, position))
	}
	if filter.GroupID != nil {
		add("s.group_id = $%d", *filter.GroupID)
	}
	if filter.RegionID != nil {
		add("s.region_id = $%d", *filter.RegionID)
	}
	if filter.NodeGroupID != nil {
		add("s.node_group_id = $%d", *filter.NodeGroupID)
	}
	if filter.CNAMEDomain != "" {
		add("position($%d in lower(s.cname)) > 0", filter.CNAMEDomain)
	}
	if filter.CNAMEHostname != "" {
		add("split_part(lower(s.cname), '.', 1) = $%d", filter.CNAMEHostname)
	}
	if filter.HTTPPort != "" {
		add("$%d = ANY(s.http_ports)", filter.HTTPPort)
	}
	if filter.HTTPSPort != "" {
		add("$%d = ANY(s.https_ports)", filter.HTTPSPort)
	}
	if filter.HTTPSEnabled != nil {
		add("s.https_enabled = $%d", *filter.HTTPSEnabled)
	}
	if filter.Enabled != nil {
		add("s.enabled = $%d", *filter.Enabled)
	}
	if filter.Status != "" {
		if filter.Status == StatusLocked {
			conditions = append(conditions, "s.locked_at IS NOT NULL")
		} else {
			add("s.status = $%d", filter.Status)
		}
	}
	if filter.IsDefault != nil {
		add("s.is_default = $%d", *filter.IsDefault)
	}
	if filter.SyncStatus != "" {
		add("site_sync_status_503(s.scope_id, s.id) = $%d", filter.SyncStatus)
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func selectActiveSiteDomains(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT current.canonical_domain
		FROM (
			SELECT DISTINCT ON (canonical_domain) canonical_domain,action
			FROM site_domain_facts
			WHERE scope_id=$1 AND site_id=$2
			ORDER BY canonical_domain,global_sequence DESC
		) current
		WHERE current.action='activate'
		ORDER BY current.canonical_domain`, scopeID, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, ErrInvalidInput
	}
	return domains, nil
}

func appendSiteDomainFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, siteID uuid.UUID,
	revision int64,
	current, proposed []string,
	actor Actor,
	requestID string,
	now time.Time,
) error {
	currentSet := make(map[string]struct{}, len(current))
	proposedSet := make(map[string]struct{}, len(proposed))
	for _, domain := range current {
		currentSet[domain] = struct{}{}
	}
	for _, domain := range proposed {
		proposedSet[domain] = struct{}{}
	}
	write := func(action, domain string) error {
		_, err := tx.Exec(ctx, `INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			scopeID, siteID, revision, action, domain, actor.ScopeID, actor.UserID, requestID, now)
		if isUniqueViolation(err) {
			return ErrDomainConflict
		}
		return err
	}
	for _, domain := range current {
		if _, retained := proposedSet[domain]; !retained {
			if err := write("deactivate", domain); err != nil {
				return err
			}
		}
	}
	for _, domain := range proposed {
		if _, retained := currentSet[domain]; !retained {
			if err := write("activate", domain); err != nil {
				return err
			}
		}
	}
	return nil
}

// activeDomainsExpression: the site's active domains (its primary domain
// without domain facts), as the site's domains field shows them.
func activeDomainsExpression(alias string) string {
	return `COALESCE((
		SELECT array_agg(current.canonical_domain ORDER BY current.canonical_domain)
		FROM (
			SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
			FROM site_domain_facts fact
			WHERE fact.scope_id = ` + alias + `.scope_id AND fact.site_id = ` + alias + `.id
			ORDER BY fact.canonical_domain, fact.global_sequence DESC
		) current WHERE current.action = 'activate'
	), ARRAY[` + alias + `.domain]::text[])`
}

func siteColumns(alias string) string {
	domains := activeDomainsExpression(alias)
	originPool := `(SELECT jsonb_build_object(
		'balance_method', pool.balance_method,
		'failover_tries', pool.failover_tries,
		'connect_timeout_ms', pool.connect_timeout_ms,
		'read_timeout_ms', pool.read_timeout_ms,
		'keepalive_enabled', pool.keepalive_enabled,
		'keepalive_idle_timeout_ms', pool.keepalive_idle_timeout_ms,
		'hash_key', COALESCE(pool.hash_key, ''),
		'sticky', CASE WHEN pool.sticky_source IS NULL THEN NULL
		               ELSE jsonb_build_object('source', pool.sticky_source, 'name', pool.sticky_name) END,
		'request_host', jsonb_build_object('mode', pool.request_host_mode, 'value', COALESCE(pool.request_host, '')),
		'scheme', pool.origin_scheme,
		'http_port', pool.http_port,
		'https_port', pool.https_port,
		'tls', jsonb_build_object('sni', COALESCE(pool.tls_sni, ''), 'trust', pool.tls_trust,
		                          'ca_pem', COALESCE(pool.tls_ca_pem, '')),
		'follow_port', pool.follow_port,
		'websocket', jsonb_build_object('enabled', pool.websocket_enabled,
		                                'allowed_origins', to_jsonb(pool.websocket_allowed_origins)),
		'trusted_proxy_cidrs', to_jsonb(pool.trusted_proxy_cidrs::text[]),
		'failback_mode', pool.failback_mode,
		'health_check_path', pool.health_check_path,
		'follow_redirect', jsonb_build_object('enabled', pool.follow_redirect,
		                                      'max_hops', pool.follow_redirect_max_hops,
		                                      'cross_origin', pool.follow_redirect_cross_origin),
		'search_engine_origin', COALESCE(pool.search_engine_origin, ''),
		'acme_passthrough', pool.acme_passthrough,
		'response_buffering', pool.response_buffering,
		'request_buffering', pool.request_buffering,
		'origin_auth_enabled', pool.origin_auth_enabled,
		'l2_mode', pool.l2_mode,
		'l2_config_id', pool.l2_config_id,
		'origins', COALESCE((
			SELECT jsonb_agg(jsonb_build_object(
				'host', origin.host,
				'port', origin.port,
				'weight', origin.weight,
				'enabled', origin.enabled,
				'level', origin.level,
				'max_conns', origin.max_conns,
				'port_inherited', origin.port_inherited
			) ORDER BY origin.position)
			FROM site_origins origin
			WHERE origin.site_id = pool.site_id
		), '[]'::jsonb)
	) FROM site_origin_pools pool WHERE pool.site_id = ` + alias + `.id)`
	return strings.Join([]string{
		alias + ".id", alias + ".display_id", alias + ".scope_id", alias + ".owner_user_id", alias + ".domain", domains,
		alias + ".http_ports", alias + ".https_ports", alias + ".origins", originPool, alias + ".cname",
		alias + ".https_enabled", alias + ".enabled", alias + ".status", "site_sync_status_503(" + alias + ".scope_id, " + alias + ".id)",
		alias + ".is_default", alias + ".package_id", alias + ".package_name", alias + ".group_id",
		alias + ".group_name", alias + ".region_id", alias + ".region_name", alias + ".node_group_id",
		alias + ".node_group_name", alias + ".lock_reason", alias + ".locked_at",
		alias + ".package_subscription_id", alias + ".cname_state", alias + ".cname_task_id",
		alias + ".cname_current_revision", alias + ".cname_lkg_revision",
		alias + ".cname_mode", alias + ".cname_domain", alias + ".cname_hostname2",
		// Why the current CNAME task failed (intent or allocation job item).
		// jobstate's own end codes name the CNAME failure (cnameallocation ended.go).
		"(SELECT CASE item.error_code WHEN 'retries_exhausted' THEN 'cname_allocation_exhausted'" +
			" WHEN 'cancelled' THEN 'cname_allocation_cancelled' ELSE item.error_code END FROM background_job_items item JOIN access_scopes cname_scope ON cname_scope.id = " + alias + ".scope_id" +
			" WHERE " + alias + ".cname_state = 'failed' AND item.tenant_id = cname_scope.tenant_id AND item.job_id = " + alias + ".cname_task_id LIMIT 1)",
		"(SELECT display_name FROM users WHERE id = " + alias + ".locked_by_user_id)",
		alias + ".ipv6_enabled", alias + ".ipv6_runtime_state",
		alias + ".ipv6_runtime_source_revision",
		alias + ".tls_protocols", alias + ".force_https", alias + ".https_redirect_port",
		alias + ".cache_shared_across_domains", alias + ".cache_status_header",
		alias + ".tls_cipher_preset", alias + ".tls_ocsp_stapling", alias + ".tls_client_auth",
		"COALESCE(" + alias + ".tls_client_ca_pem,'')",
		alias + ".http2_enabled", alias + ".http3_enabled", alias + ".tls_prefer_server_ciphers", alias + ".tls_cipher_suites",
		alias + ".revision", alias + ".created_at", alias + ".updated_at",
		"(SELECT subscription.ends_at FROM package_subscriptions subscription WHERE subscription.tenant_scope_id = " +
			alias + ".scope_id AND subscription.id = " + alias + ".package_subscription_id)",
		// The package's validity for 暂不可用: only an enabled,
		// undeleted package is published.
		"(SELECT CASE WHEN subscription.deleted_at IS NOT NULL THEN 'deleted' WHEN NOT subscription.admin_enabled THEN 'disabled'" +
			" ELSE 'valid' END FROM package_subscriptions subscription WHERE subscription.tenant_scope_id = " +
			alias + ".scope_id AND subscription.id = " + alias + ".package_subscription_id)",
	}, ", ")
}

func scanSite(row rowScanner) (Site, error) {
	var item Site
	var displayID int64
	var ownerDisplayID string
	var ownerDisplayName string
	var lockReason *string
	var lockedAt *time.Time
	var lockOperatorName *string
	var originPoolJSON []byte
	var packageState *string
	if err := row.Scan(
		&item.ID,
		&displayID,
		&item.ScopeID,
		&item.ownerID,
		&item.Domain,
		&item.Domains,
		&item.HTTPPorts,
		&item.HTTPSPorts,
		&item.Origins,
		&originPoolJSON,
		&item.CNAME,
		&item.HTTPSEnabled,
		&item.Enabled,
		&item.Status,
		&item.SyncStatus,
		&item.IsDefault,
		&item.PackageID,
		&item.packageName,
		&item.GroupID,
		&item.GroupName,
		&item.RegionID,
		&item.regionName,
		&item.NodeGroupID,
		&item.nodeGroupName,
		&lockReason,
		&lockedAt,
		&item.PackageSubscriptionID,
		&item.CNAMEState,
		&item.CNAMETaskID,
		&item.CNAMECurrentRevision,
		&item.CNAMELKGRevision,
		&item.CNAMEMode,
		&item.CNAMEDomain,
		&item.CNAMEHostname,
		&item.CNAMEFailureCode,
		&lockOperatorName,
		&item.ListenerState.IPv6DesiredEnabled,
		&item.ListenerState.IPv6RuntimeState,
		&item.ipv6RuntimeRevision,
		&item.TLSProtocols,
		&item.ForceHTTPS,
		&item.HTTPSRedirectPort,
		&item.CacheSharedAcrossDomains,
		&item.CacheStatusHeader,
		&item.TLSCipherPreset,
		&item.TLSOCSPStapling,
		&item.TLSClientAuth,
		&item.TLSClientCAPEM,
		&item.HTTP2Enabled,
		&item.HTTP3Enabled,
		&item.TLSPreferServerCiphers,
		&item.TLSCipherSuites,
		&item.Revision,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.PackageExpiresAt,
		&packageState,
		&ownerDisplayName,
		&ownerDisplayID,
	); err != nil {
		return Site{}, err
	}
	item.DisplayID = strconv.FormatInt(displayID, 10)
	if err := json.Unmarshal(originPoolJSON, &item.OriginPool); err != nil || len(item.OriginPool.Origins) == 0 {
		if err == nil {
			err = errors.New("site origin pool is empty")
		}
		return Site{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerID, DisplayID: ownerDisplayID, DisplayName: ownerDisplayName}
	item.PackageUnavailableReason = packageUnavailableReason(item.PackageSubscriptionID, packageState)
	item.Lock = LockState{Locked: lockedAt != nil, Reason: lockReason, LockedAt: lockedAt}
	if lockOperatorName != nil {
		item.Lock.Operator = &LockOperator{DisplayName: *lockOperatorName}
	}
	if item.PackageID != nil && item.packageName != nil {
		item.Package = &Reference{ID: *item.PackageID, Name: *item.packageName}
	}
	if item.regionName != nil || item.nodeGroupName != nil {
		item.Region = &RegionReference{
			Name:          stringValue(item.regionName),
			NodeGroupName: stringValue(item.nodeGroupName),
		}
	}
	item.ListenPorts = mergePorts(item.HTTPPorts, item.HTTPSPorts)
	return item, nil
}

func toListItem(item Site) ListItem {
	return ListItem{
		ID:                    item.ID,
		DisplayID:             item.DisplayID,
		Revision:              item.Revision,
		Owner:                 item.Owner,
		Domain:                item.Domain,
		Domains:               item.Domains,
		ListenPorts:           item.ListenPorts,
		Origins:               item.Origins,
		CNAME:                 item.CNAME,
		PackageSubscriptionID: item.PackageSubscriptionID,
		CNAMEState:            item.CNAMEState,
		CNAMEFailureCode:      item.CNAMEFailureCode,
		CNAMEDomain:           item.CNAMEDomain,
		CNAMETaskID:           item.CNAMETaskID,
		CNAMECurrentRevision:  item.CNAMECurrentRevision,
		CNAMELKGRevision:      item.CNAMELKGRevision,
		HTTPSEnabled:          item.HTTPSEnabled,
		Package:               item.Package,
		GroupName:             item.GroupName,
		Region:                item.Region,
		Status:                item.Status,
		OperationalStatus:     projectOperationalStatus(item.Status, item.Lock.Locked),
		StatusRecovery:        item.StatusRecovery,
		ListenerState:         item.ListenerState,
		Lock:                  item.Lock,
		CreatedAt:             item.CreatedAt,

		PackageUnavailableReason: item.PackageUnavailableReason,
	}
}

type cnameWriteIntent struct {
	tenantID, scopeID, jobID, siteID, packageSubscriptionID, actorScopeID, actorUserID uuid.UUID
	actorSessionID                                                                     uuid.UUID
	mode, domain, hostname, idempotencyKey, requestID, traceID                         string
	expectedSiteRevision                                                               int64
	regenerate                                                                         bool
	digest                                                                             [32]byte
}

func (intent cnameWriteIntent) nullablePackageSubscription() *uuid.UUID {
	if intent.packageSubscriptionID == uuid.Nil {
		return nil
	}
	return &intent.packageSubscriptionID
}

func prepareCNAMEWriteIntent(ctx context.Context, tx pgx.Tx, actor Actor, ownerID, scopeID, siteID uuid.UUID,
	fields *SiteFields, expectedRevision int64, idempotencyKey, requestID string) (*cnameWriteIntent, error) {
	if expectedRevision < 1 {
		return nil, ErrInvalidInput
	}
	var tenantID uuid.UUID
	var canManageSites, canManageDNS, canManagePackages bool
	err := tx.QueryRow(ctx, `SELECT target.tenant_id,
		BOOL_OR(permission.permission_name='sites.manage' OR (actor_scope.kind='platform' AND permission.permission_name='platform.admin')),
		BOOL_OR(permission.permission_name='dns.manage' OR (actor_scope.kind='platform' AND permission.permission_name='platform.admin')),
		BOOL_OR(permission.permission_name IN ('package_subscriptions.manage','platform.admin'))
		FROM access_scopes target CROSS JOIN access_scopes actor_scope
		JOIN role_assignments assignment ON assignment.scope_id=actor_scope.id AND assignment.user_id=$2
		JOIN role_permissions permission ON permission.role_id=assignment.role_id
		WHERE target.id=$1 AND target.kind='tenant' AND actor_scope.id=$3 AND actor_scope.kind=$4
		  AND (actor_scope.kind='platform' OR actor_scope.id=target.id)
		  AND permission.permission_name IN ('sites.manage','dns.manage','package_subscriptions.manage','platform.admin')
		GROUP BY target.tenant_id`, scopeID, actor.UserID, actor.ScopeID, actor.ScopeKind).
		Scan(&tenantID, &canManageSites, &canManageDNS, &canManagePackages)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPermissionDenied
	}
	if err != nil {
		return nil, err
	}
	if !canManageSites {
		return nil, ErrPermissionDenied
	}
	if ownerID == uuid.Nil {
		if err := tx.QueryRow(ctx, `SELECT owner_user_id FROM sites WHERE scope_id=$1 AND id=$2`, scopeID, siteID).Scan(&ownerID); err != nil {
			return nil, err
		}
	}
	if fields.PackageSubscriptionID == nil && fields.PackageID == nil {
		// (migration 533): a site without a package still gets a
		// per-site CNAME in the default zone; it is not served until bound.
		return prepareNoPackageCNAMEIntent(ctx, tx, actor, tenantID, scopeID, siteID, fields,
			expectedRevision, requestID, canManageDNS)
	}
	if fields.PackageSubscriptionID == nil {
		var subscriptionID uuid.UUID
		var count int
		err := tx.QueryRow(ctx, `SELECT min(subscription.id::text)::uuid,count(*)
			FROM package_subscriptions subscription JOIN package_subscription_state_versions owner
			  ON owner.subscription_id=subscription.id AND owner.tenant_scope_id=subscription.tenant_scope_id
			 AND owner.revision=subscription.revision AND owner.owner_user_id=$3
			WHERE subscription.tenant_scope_id=$1 AND subscription.product_id=$2
			  AND subscription.lifecycle_status='active'
			  AND subscription.admin_enabled=true AND subscription.deleted_at IS NULL`, scopeID, *fields.PackageID, ownerID).Scan(&subscriptionID, &count)
		if err != nil || count != 1 {
			return nil, fieldError("package_id", "no single active subscription of this package for the site owner")
		}
		fields.PackageSubscriptionID = &subscriptionID
	}
	// Subscription changes lock both sides in UUID order. This matches scope
	// publication and addon changes, including two sites swapping packages.
	locks, err := tx.Query(ctx, `SELECT subscription.id FROM package_subscriptions subscription
		WHERE subscription.tenant_scope_id=$1 AND (subscription.id=$2 OR subscription.id=(
			SELECT package_subscription_id FROM sites WHERE scope_id=$1 AND id=$3))
		ORDER BY subscription.id FOR UPDATE OF subscription`, scopeID, *fields.PackageSubscriptionID, siteID)
	if err != nil {
		return nil, err
	}
	for locks.Next() {
	}
	locks.Close()
	if err := locks.Err(); err != nil {
		return nil, err
	}
	var subscriptionProductID uuid.UUID
	var snapshotMode, domain, hostname string
	err = tx.QueryRow(ctx, `SELECT subscription.product_id,
		subscription.product_snapshot->'spec'->'cname'->>'mode',
		subscription.product_snapshot->'spec'->'cname'->>'domain',
		subscription.product_snapshot->'spec'->'cname'->>'hostname'
		FROM package_subscriptions subscription
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2 AND subscription.lifecycle_status='active'
		  AND subscription.admin_enabled=true AND subscription.deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM package_monitor_subscription_owners owner
			WHERE owner.tenant_scope_id=subscription.tenant_scope_id AND owner.subscription_id=subscription.id
			  AND owner.owner_user_id=$3)
		  -- owners keeps the revision the package was opened at; renewals and
		  -- admin edits raise subscription.revision (acc-cd: renewed package 400).
		  AND EXISTS (SELECT 1 FROM package_subscription_state_versions state
			WHERE state.subscription_id=subscription.id AND state.tenant_scope_id=subscription.tenant_scope_id
			  AND state.revision=subscription.revision AND state.owner_user_id=$3)
		FOR UPDATE OF subscription`, scopeID, *fields.PackageSubscriptionID, ownerID).Scan(&subscriptionProductID, &snapshotMode, &domain, &hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidInput
	}
	if err != nil {
		return nil, err
	}
	if fields.PackageID != nil && *fields.PackageID != subscriptionProductID {
		return nil, fieldError("package_id", "does not match the package subscription")
	}
	fields.PackageID = &subscriptionProductID
	mode := ""
	switch snapshotMode {
	case "per_site":
		mode = "site"
	case "shared":
		mode = "package"
	default:
		return nil, ErrInvalidInput
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	// The CNAME policy follows the package subscription; a site edit may echo
	// it but not replace it (change it on the package, which regenerates).
	if fields.CNAMEMode != "" && fields.CNAMEMode != mode {
		return nil, fieldError("cname_mode", "follows the package subscription")
	}
	if fields.CNAMEDomain != "" && fields.CNAMEDomain != domain {
		return nil, fieldError("cname_domain", "follows the package subscription ("+domain+")")
	}
	if fields.CNAMEHostname != "" && fields.CNAMEHostname != hostname {
		return nil, fieldError("cname_hostname", "follows the package subscription")
	}
	var currentSubscription *uuid.UUID
	var currentMode, currentDomain, currentHostname, currentState *string
	err = tx.QueryRow(ctx, `SELECT package_subscription_id,cname_mode,cname_domain,cname_hostname2,cname_state
		FROM sites WHERE scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, siteID).Scan(&currentSubscription, &currentMode, &currentDomain, &currentHostname, &currentState)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	found := err == nil
	// The allocation projection writes cname_domain='' when the current claim
	// sits in the tenant's default zone (cnameallocation projectBoundSites,
	// validated by 412). Compare the domain that claim actually uses.
	if found && currentDomain != nil && *currentDomain == "" {
		var claimDomain string
		err = tx.QueryRow(ctx, `SELECT lower(claim.domain) FROM cname_site_bindings binding
			JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
			 AND allocation.id=binding.current_allocation_id
			JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
			JOIN dns_zones zone ON zone.scope_id=claim.tenant_scope_id AND zone.id=claim.zone_id AND zone.is_default
			WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2`, scopeID, siteID).Scan(&claimDomain)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		currentDomain = &claimDomain
	}
	samePolicy := found && currentSubscription != nil && *currentSubscription == *fields.PackageSubscriptionID &&
		stringValue(currentMode) == mode && stringValue(currentDomain) == domain && stringValue(currentHostname) == hostname
	if samePolicy && !fields.CNAMERegenerate {
		return nil, nil
	}
	if !canManageDNS {
		return nil, ErrPermissionDenied
	}
	// A new CNAME under a blocklisted zone is refused with the site write
	// (domain_blocked); cnameallocation.Allocate re-checks in the background.
	cnameNames := []string{domain}
	if hostname != "" {
		cnameNames = append(cnameNames, hostname+"."+domain)
	}
	if blockedName, blocked, err := domaintrust.BlockedDomain(ctx, tx, cnameNames); err != nil {
		return nil, err
	} else if blocked {
		return nil, &domaintrust.DomainError{Err: domaintrust.ErrDomainBlocked, Domain: blockedName}
	}
	if actor.ScopeKind == "platform" {
		if !canManagePackages || actor.SessionID == uuid.Nil {
			return nil, ErrPermissionDenied
		}
		var liveSession bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions
			WHERE id=$1 AND user_id=$2 AND scope_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp())`,
			actor.SessionID, actor.UserID, actor.ScopeID).Scan(&liveSession); err != nil {
			return nil, err
		}
		if !liveSession {
			return nil, ErrPermissionDenied
		}
	}
	if fields.CNAMERegenerate && (!samePolicy || stringValue(currentState) != "failed") {
		return nil, fieldError("cname_regenerate", "only a failed CNAME allocation can be retried")
	}
	payload, err := json.Marshal(struct {
		SiteID, Mode, Domain, Hostname, Subscription string
		Revision                                     int64
	}{
		siteID.String(), mode, domain, hostname,
		fields.PackageSubscriptionID.String(), expectedRevision})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	jobID := uuid.New()
	return &cnameWriteIntent{tenantID: tenantID, scopeID: scopeID, jobID: jobID, siteID: siteID,
		packageSubscriptionID: *fields.PackageSubscriptionID,
		actorScopeID:          actor.ScopeID, actorUserID: actor.UserID, mode: mode, domain: domain,
		actorSessionID: actor.SessionID,
		hostname:       hostname, idempotencyKey: hex.EncodeToString(digest[:]), requestID: requestID,
		traceID: requestID, expectedSiteRevision: expectedRevision,
		regenerate: samePolicy && fields.CNAMERegenerate, digest: digest}, nil
}

// prepareNoPackageCNAMEIntent: site mode, no domain (domain ”: a random-
// allocation zone, else the default zone), no explicit
// hostname. A site that already has one keeps it; a site leaving its package
// gets a new one (the package CNAME is the package's).
func prepareNoPackageCNAMEIntent(ctx context.Context, tx pgx.Tx, actor Actor, tenantID, scopeID, siteID uuid.UUID,
	fields *SiteFields, expectedRevision int64, requestID string, canManageDNS bool) (*cnameWriteIntent, error) {
	if fields.CNAMEMode != "" && fields.CNAMEMode != "site" {
		return nil, fieldError("cname_mode", "a site without a package uses a per-site CNAME")
	}
	var currentSubscription *uuid.UUID
	var currentMode, currentState, currentDomain *string
	err := tx.QueryRow(ctx, `SELECT package_subscription_id,cname_mode,cname_state,cname_domain
		FROM sites WHERE scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, siteID).Scan(&currentSubscription, &currentMode,
		&currentState, &currentDomain)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// the site's CNAME may sit in a randomly drawn zone, whose
	// domain the projection shows; an edit or regenerate echoing it back is
	// not a choice of domain (the allocation keeps the site's zone).
	echoed := fields.CNAMEDomain == "" || (currentSubscription == nil && currentDomain != nil &&
		fields.CNAMEDomain == strings.ToLower(*currentDomain))
	if !echoed || fields.CNAMEHostname != "" {
		return nil, fieldError("cname_domain", "a site without a package gets its CNAME domain automatically")
	}
	samePolicy := err == nil && currentSubscription == nil && stringValue(currentMode) == "site"
	if samePolicy && !fields.CNAMERegenerate {
		return nil, nil
	}
	// Without dns.manage the site is still written, just without a CNAME
	// (as before 533); an explicit retry needs the permission.
	if !canManageDNS && !fields.CNAMERegenerate {
		return nil, nil
	}
	if !canManageDNS {
		return nil, ErrPermissionDenied
	}
	if actor.ScopeKind == "platform" {
		if actor.SessionID == uuid.Nil {
			return nil, ErrPermissionDenied
		}
		var liveSession bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions
			WHERE id=$1 AND user_id=$2 AND scope_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp())`,
			actor.SessionID, actor.UserID, actor.ScopeID).Scan(&liveSession); err != nil {
			return nil, err
		}
		if !liveSession {
			return nil, ErrPermissionDenied
		}
	}
	if fields.CNAMERegenerate && (!samePolicy || stringValue(currentState) != "failed") {
		return nil, fieldError("cname_regenerate", "only a failed CNAME allocation can be retried")
	}
	payload, err := json.Marshal(struct {
		SiteID, Mode, Domain, Hostname, Subscription string
		Revision                                     int64
	}{siteID.String(), "site", "", "", "", expectedRevision})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return &cnameWriteIntent{tenantID: tenantID, scopeID: scopeID, jobID: uuid.New(), siteID: siteID,
		actorScopeID: actor.ScopeID, actorUserID: actor.UserID, actorSessionID: actor.SessionID, mode: "site",
		idempotencyKey: hex.EncodeToString(digest[:]), requestID: requestID, traceID: requestID,
		expectedSiteRevision: expectedRevision, regenerate: samePolicy && fields.CNAMERegenerate, digest: digest}, nil
}

func insertCNAMEIntentJob(ctx context.Context, tx pgx.Tx, intent cnameWriteIntent, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,
		request_digest,request_id,trace_id,state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at)
		VALUES($1,$2,'dns.cname.intent',$3,$4,$5,$6,$7,'queued',0,20,$8,1,$8,$8)`,
		intent.jobID, intent.tenantID, "cname_intent/"+intent.siteID.String(), intent.idempotencyKey,
		intent.digest[:], intent.requestID, intent.traceID, now)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state)
		VALUES($1,$2,1,'allocate','pending')`, intent.tenantID, intent.jobID); err != nil {
		return err
	}
	return nil
}

func insertCNAMEIntentFact(ctx context.Context, tx pgx.Tx, intent cnameWriteIntent, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_allocation_intents(tenant_id,tenant_scope_id,job_id,site_id,
		package_subscription_id,actor_scope_id,actor_user_id,mode,domain,hostname,idempotency_key,request_id,trace_id,
		expected_site_revision,regenerate,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, intent.tenantID,
		intent.scopeID, intent.jobID, intent.siteID, intent.nullablePackageSubscription(), intent.actorScopeID, intent.actorUserID, intent.mode,
		intent.domain, intent.hostname, intent.idempotencyKey, intent.requestID, intent.traceID,
		intent.expectedSiteRevision, intent.regenerate, now)
	if err != nil {
		return err
	}
	if intent.actorScopeID != intent.scopeID && intent.actorSessionID != uuid.Nil {
		_, err = tx.Exec(ctx, `INSERT INTO cname_platform_intent_sessions(tenant_id,job_id,actor_session_id,created_at)
			VALUES($1,$2,$3,$4)`, intent.tenantID, intent.jobID, intent.actorSessionID, now)
	}
	return err
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// addedDomains lists proposed domains the site does not already serve.
func addedDomains(current, proposed []string) []string {
	added := make([]string, 0, len(proposed))
	for _, domain := range proposed {
		if !slices.Contains(current, domain) {
			added = append(added, domain)
		}
	}
	return added
}

// claimSuspendedError maps the deferred 299 enable guard raised at commit.
func claimSuspendedError(err error) error {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "P3032" {
		return domaintrust.ErrClaimSuspended
	}
	// 475: a DNS reconcile task is changing the site's records right now.
	if errors.As(err, &pgErr) && pgErr.SQLState() == "P8903" {
		return ErrDNSMutationInProgress
	}
	return err
}

// siteTLSAudit is the audited TLS profile of a site; the client CA bundle
// is recorded by digest only.
type siteTLSAudit struct {
	Protocols      []string
	CipherPreset   string
	CipherSuites   []string
	OCSPStapling   bool
	ClientAuth     string
	ClientCASHA256 string
	// HTTPS protocols (migration 515); PreferServerCiphers nil is by preset.
	HTTP2, HTTP3        bool
	PreferServerCiphers *bool
}

func siteTLSAuditOf(item Site) siteTLSAudit {
	value := siteTLSAudit{Protocols: slices.Clone(item.TLSProtocols), CipherPreset: item.TLSCipherPreset,
		CipherSuites: slices.Clone(item.TLSCipherSuites),
		OCSPStapling: item.TLSOCSPStapling, ClientAuth: item.TLSClientAuth,
		HTTP2: item.HTTP2Enabled, HTTP3: item.HTTP3Enabled, PreferServerCiphers: item.TLSPreferServerCiphers}
	if item.TLSClientCAPEM != "" {
		sum := sha256.Sum256([]byte(item.TLSClientCAPEM))
		value.ClientCASHA256 = hex.EncodeToString(sum[:])
	}
	return value
}

func (before siteTLSAudit) changes(after siteTLSAudit) map[string]any {
	changes := map[string]any{}
	add := func(field string, from, to any) {
		if !reflect.DeepEqual(from, to) {
			changes[field] = map[string]any{"from": from, "to": to}
		}
	}
	add("tls_protocols", before.Protocols, after.Protocols)
	add("tls_cipher_preset", before.CipherPreset, after.CipherPreset)
	add("tls_cipher_suites", before.CipherSuites, after.CipherSuites)
	add("tls_ocsp_stapling", before.OCSPStapling, after.OCSPStapling)
	add("tls_client_auth", before.ClientAuth, after.ClientAuth)
	add("tls_client_ca_sha256", before.ClientCASHA256, after.ClientCASHA256)
	add("http2_enabled", before.HTTP2, after.HTTP2)
	add("http3_enabled", before.HTTP3, after.HTTP3)
	add("tls_prefer_server_ciphers", before.PreferServerCiphers, after.PreferServerCiphers)
	return changes
}

// siteTLSProfile is a new site's stored TLS profile.
type siteTLSProfile struct {
	cipherPreset, clientAuth, clientCAPEM string
	cipherSuites                          []string
	ocspStapling                          bool
}

// createSiteTLSProfile: the request's values, else the system default. A
// request that names neither protocols nor a cipher preset takes both from
// the system default (they come as one SSL mode there); fields.TLSProtocols
// is set to the protocols stored.
func createSiteTLSProfile(ctx context.Context, tx pgx.Tx, fields *SiteFields) (siteTLSProfile, error) {
	result := siteTLSProfile{cipherPreset: edgeconfig.TLSCipherModern, clientAuth: edgeconfig.ClientAuthOff}
	if fields.TLSCipherPreset == nil || fields.TLSOCSPStapling == nil || fields.tlsProtocolsDefaulted {
		defaults, err := systemconfig.LoadDefaultSiteTLS(ctx, tx)
		if err != nil {
			return siteTLSProfile{}, err
		}
		result.cipherPreset, result.ocspStapling = defaults.CipherPreset, defaults.OCSPStapling
		if fields.tlsProtocolsDefaulted && fields.TLSCipherPreset == nil &&
			edgeconfig.ValidateSiteTLSProtocols(defaults.Protocols) == nil {
			fields.TLSProtocols = defaults.Protocols
		}
	}
	if fields.TLSCipherPreset != nil {
		result.cipherPreset, result.cipherSuites = *fields.TLSCipherPreset, fields.TLSCipherSuites
	} else if slices.Contains(fields.TLSProtocols, "TLSv1") || slices.Contains(fields.TLSProtocols, "TLSv1.1") {
		result.cipherPreset = edgeconfig.TLSCipherLegacy // the only preset those clients can use
	}
	if fields.TLSOCSPStapling != nil {
		result.ocspStapling = *fields.TLSOCSPStapling
	}
	if fields.TLSClientAuth != nil {
		result.clientAuth = *fields.TLSClientAuth
	}
	if fields.TLSClientCAPEM != nil {
		result.clientCAPEM = *fields.TLSClientCAPEM
	}
	return result, nil
}

// siteTLSProfileViolation maps the TLS profile CHECKs of migration 367 to
// ErrTLSProfileInvalid (a combination the request alone could not show
// invalid, e.g. a preset change against stored protocols).
func siteTLSProfileViolation(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" && strings.HasPrefix(pgErr.ConstraintName, "sites_tls_") {
		return ErrTLSProfileInvalid
	}
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}

func boolCount(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

// tenantCreatePool is the pool a create stores: a non-platform actor's copy
// follows the package L2 (L2Mode package, no config), the platform's (and the
// platform automation's: transfer, supply leaf sites) is kept as sent.
func tenantCreatePool(actor Actor, pool *OriginPool) *OriginPool {
	if pool == nil || actor.ScopeKind == "platform" || pool.L2Mode == SiteL2Package && pool.L2ConfigID == nil {
		return pool
	}
	kept := *pool
	kept.L2Mode, kept.L2ConfigID = SiteL2Package, nil
	return &kept
}

// siteL2Mode: the stored L2 mode ("" from an unnormalized pool: package).
func siteL2Mode(mode string) string {
	if mode == "" {
		return SiteL2Package
	}
	return mode
}

// isL2ConfigReferenceViolation: l2_config_id names no L2 configuration of
// the site's scope (the trigger of migration 466).
func isL2ConfigReferenceViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "P4663"
}

// switchDefaultSite (默认站点, site-backend6): only a platform operator
// changes it (it answers every unknown Host in the installation). Setting
// it clears the previous default site in the same transaction (the unique
// index sites_single_default_467 holds one), audits both and republishes the
// previous one's scope so its nodes drop the fallback.
func (s *Store) switchDefaultSite(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID, enable bool,
	requestID, sourceIP string) error {
	if actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cdnca.site.default',0))`); err != nil {
		return fmt.Errorf("lock default site: %w", err)
	}
	if enable {
		var previousID, previousScope uuid.UUID
		var previousDomain string
		err := tx.QueryRow(ctx, `UPDATE sites SET is_default=false,revision=revision+1,updated_by_user_id=$2,updated_at=$3
			WHERE is_default AND deleted_at IS NULL AND id<>$1 RETURNING id,scope_id,domain`,
			siteID, actor.UserID, s.now().UTC()).Scan(&previousID, &previousScope, &previousDomain)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("clear previous default site: %w", err)
		}
		if err == nil {
			if err := enqueueAutomaticMutation(ctx, tx, actor, previousScope, previousID, "site.update", requestID); err != nil {
				return err
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: previousScope, ActorUserID: &actor.UserID, Action: "site.default.update",
				ResourceType: "site", ResourceID: previousID.String(), RequestID: requestID, Result: "success",
				Payload: map[string]any{
					"ip": sourceIP, "site_domain": previousDomain, "replaced_by": siteID.String(),
					"actor_scope_id": actor.ScopeID.String(), "target_scope_id": previousScope.String(),
					"changes": map[string]any{"is_default": map[string]any{"from": true, "to": false}},
				},
			}); err != nil {
				return err
			}
		}
	}
	var scopeID uuid.UUID
	var domain string
	if err := tx.QueryRow(ctx, `SELECT scope_id,domain FROM sites WHERE id=$1`, siteID).Scan(&scopeID, &domain); errors.Is(err, pgx.ErrNoRows) {
		return nil // a site being created: site.create records it
	} else if err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "site.default.update",
		ResourceType: "site", ResourceID: siteID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{
			"ip": sourceIP, "site_domain": domain,
			"actor_scope_id": actor.ScopeID.String(), "target_scope_id": scopeID.String(),
			"changes": map[string]any{"is_default": map[string]any{"from": !enable, "to": enable}},
		},
	})
}
