package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type storedPublication struct {
	result        PublishResult
	requestDigest []byte
}

type rowScanner interface {
	Scan(...any) error
}

func lockConfigurationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, now time.Time) (int64, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO edge_configuration_scopes (scope_id, source_revision, updated_at)
		SELECT id, 1, $2 FROM access_scopes WHERE id=$1 AND kind='tenant'
		ON CONFLICT (scope_id) DO NOTHING`, scopeID, now); err != nil {
		return 0, fmt.Errorf("%w: initialize configuration scope", ErrPersistence)
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrInvalidInput
	} else if err != nil || revision < 1 {
		return 0, fmt.Errorf("%w: lock configuration scope", ErrPersistence)
	}
	return revision, nil
}

func loadSiteFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	statusRecoverySiteIDLists ...[]uuid.UUID,
) ([]siteFact, error) {
	statusRecoverySiteIDs := optionalSiteStatusRecoveryCandidateIDs(statusRecoverySiteIDLists)
	rows, err := tx.Query(ctx, `
		SELECT site.id,site.revision,site.domain,COALESCE((
		           SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
		           FROM (
		               SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
		               FROM site_domain_facts fact
		               WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
		               ORDER BY fact.canonical_domain,fact.global_sequence DESC
		           ) current_domain WHERE current_domain.action='activate'
		       ),ARRAY[site.domain]::text[]),site.http_ports,site.https_enabled,site.https_ports,site.tls_protocols,
		       site.ipv6_enabled,site.force_https,site.https_redirect_port,site.cache_shared_across_domains,
		       site.https_redirect_status,site.https_redirect_exclude_hosts,
		       site.tls_cipher_preset,site.tls_ocsp_stapling,site.tls_client_auth,COALESCE(site.tls_client_ca_pem,''),
		       site.http2_enabled,site.http3_enabled,site.tls_prefer_server_ciphers,site.tls_cipher_suites,
		       pool.balance_method,pool.failover_tries,pool.connect_timeout_ms,pool.read_timeout_ms,
		       CASE WHEN NOT pool.keepalive_enabled THEN 0
		            WHEN pool.keepalive_idle_timeout_ms<>60000 THEN pool.keepalive_idle_timeout_ms END,
		       origin.position,origin.host,origin.port,origin.weight,origin.level,origin.max_conns,
		       COALESCE(failover.active_level,0)
		FROM sites site
		JOIN site_origin_pools pool ON pool.site_id=site.id
		JOIN site_origins origin ON origin.site_id=site.id AND origin.enabled=true
		LEFT JOIN site_origin_failover_states failover ON failover.site_id=site.id
		-- Community edition: a site needs no package. A site bound to one is
		-- published only while that package is valid (fix-nopkgpub, 10-27);
		-- the next publication withdraws it like a disabled one.
		LEFT JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled=true
		  AND (site.package_subscription_id IS NULL OR (package_subscription.id IS NOT NULL
		  AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL
		  AND package_subscription.suspended_at IS NULL))
		  -- package_expired publishes marked (package_expiry.go), never withdrawn
		  AND (site.status<>'traffic_exceeded' OR site.id=ANY($2::uuid[]))
		ORDER BY site.id,origin.position`, scopeID, statusRecoverySiteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read site facts", ErrPersistence)
	}
	defer rows.Close()
	var result []siteFact
	for rows.Next() {
		var id uuid.UUID
		var revision int64
		var domain, balance, host string
		var domains, httpPorts, httpsPorts, tlsProtocols []string
		var httpsEnabled, ipv6Enabled, forceHTTPS, cacheShared bool
		var httpsRedirectPort, httpsRedirectStatus int
		var httpsRedirectExclude []string
		var tlsCipherPreset, tlsClientAuth, tlsClientCAPEM string
		var tlsOCSPStapling, http2Enabled, http3Enabled bool
		var tlsPreferServerCiphers *bool
		var tlsCipherSuites []string
		var failover, connectTimeout, readTimeout, position, port, weight, maxConns int
		var keepaliveIdle *int
		var level, activeLevel int
		if err := rows.Scan(&id, &revision, &domain, &domains, &httpPorts, &httpsEnabled, &httpsPorts, &tlsProtocols,
			&ipv6Enabled, &forceHTTPS, &httpsRedirectPort, &cacheShared, &httpsRedirectStatus, &httpsRedirectExclude,
			&tlsCipherPreset, &tlsOCSPStapling, &tlsClientAuth, &tlsClientCAPEM,
			&http2Enabled, &http3Enabled, &tlsPreferServerCiphers, &tlsCipherSuites,
			&balance, &failover, &connectTimeout, &readTimeout, &keepaliveIdle, &position, &host, &port, &weight,
			&level, &maxConns, &activeLevel); err != nil {
			return nil, fmt.Errorf("%w: scan site facts", ErrPersistence)
		}
		tlsProtocols, err = validateSiteTLSProtocols(tlsProtocols)
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 || weight < 1 || weight > 100 || failover < 1 || failover > 255 {
			return nil, ErrInvalidInput
		}
		if len(result) == 0 || result[len(result)-1].id != id {
			result = append(result, siteFact{id: id, revision: revision, domain: domain, domains: domains,
				httpPorts: httpPorts, httpsEnabled: httpsEnabled, httpsPorts: httpsPorts, tlsProtocols: tlsProtocols,
				ipv6Enabled: ipv6Enabled, ipv6DesiredSet: true, forceHTTPS: forceHTTPS, httpsRedirectPort: httpsRedirectPort,
				httpsRedirectStatus: httpsRedirectStatus, httpsRedirectExclude: httpsRedirectExclude,
				balance: balance, failoverTries: failover, connectTimeoutMS: connectTimeout, readTimeoutMS: readTimeout,
				keepaliveIdleTimeoutMS: keepaliveIdle, cacheSharedAcrossDomains: cacheShared,
				tlsCipherPreset: tlsCipherPreset, tlsOCSPStapling: tlsOCSPStapling, tlsClientAuth: tlsClientAuth,
				tlsClientCAPEM: tlsClientCAPEM, http2Off: !http2Enabled, http3Off: !http3Enabled,
				tlsPreferServerCiphers: tlsPreferServerCiphers, tlsCipherSuites: tlsCipherSuites})
		}
		current := &result[len(result)-1]
		if current.revision != revision || current.domain != domain || !slices.Equal(current.domains, domains) ||
			!slices.Equal(current.tlsProtocols, tlsProtocols) || current.ipv6Enabled != ipv6Enabled || current.balance != balance {
			return nil, ErrInvalidInput
		}
		current.origins = append(current.origins, snapshotOrigin{Host: host, Port: uint16(port), Weight: uint8(weight)})
		current.originExtras = append(current.originExtras, originExtraFact{level: level, maxConns: maxConns})
		current.activeLevel = activeLevel
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate site facts", ErrPersistence)
	}
	rows.Close()
	siteIDs := make([]uuid.UUID, len(result))
	for index := range result {
		siteIDs[index] = result[index].id
	}
	forwarding, err := loadOriginForwardingFacts(ctx, tx, scopeID, siteIDs)
	if err != nil {
		return nil, err
	}
	access, err := loadSiteAccessSettings(ctx, tx, scopeID)
	if err != nil {
		return nil, err
	}
	for index := range result {
		if fact, ok := forwarding[result[index].id]; ok {
			result[index].forwarding = &fact
		}
		if value, exists := access[result[index].id]; exists {
			result[index].access = &value
		}
	}
	return result, nil
}

func loadCachePolicyFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sourceRevision int64) (map[uuid.UUID]*cachePolicyFact, error) {
	rows, err := tx.Query(ctx, `
		SELECT head.site_id,binding.revision,binding.edge_source_revision,
		       binding.binding_mode,binding.definition_id,binding.definition_revision,definition.source_site_id,
		       definition.schema_version,definition.mode,definition.rules,definition.query_mode,definition.query_names,
		       definition.vary_headers,definition.disk_quota_bytes,definition.extensions
		FROM cache_policy_heads head
		JOIN cache_policy_revisions binding
		  ON binding.scope_id=head.scope_id
		 AND binding.site_id=head.site_id
		 AND binding.revision=head.current_revision
		JOIN cache_policy_definition_revisions definition
		  ON definition.scope_id=binding.scope_id
		 AND definition.definition_id=binding.definition_id
		 AND definition.revision=binding.definition_revision
		WHERE head.scope_id=$1
		ORDER BY head.site_id
		FOR SHARE OF head,binding,definition`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read cache policy facts", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*cachePolicyFact)
	for rows.Next() {
		var fact cachePolicyFact
		var mode, queryMode string
		var rules, extensions []byte
		if err := rows.Scan(
			&fact.siteID, &fact.revision, &fact.edgeSourceRevision,
			&fact.bindingMode, &fact.definitionID, &fact.definitionRevision, &fact.definitionSourceSiteID,
			&fact.schemaVersion, &mode, &rules,
			&queryMode, &fact.queryNames, &fact.varyHeaders, &fact.diskQuotaBytes, &extensions,
		); err != nil {
			return nil, fmt.Errorf("%w: scan cache policy facts", ErrPersistence)
		}
		if fact.siteID == uuid.Nil || fact.revision < 1 || fact.edgeSourceRevision < 1 ||
			fact.edgeSourceRevision > sourceRevision || fact.definitionID == uuid.Nil ||
			fact.definitionRevision < 1 || fact.definitionSourceSiteID == uuid.Nil ||
			(fact.bindingMode != "inherit" && fact.bindingMode != "override") ||
			(fact.bindingMode == "override" && fact.definitionSourceSiteID != fact.siteID) || fact.diskQuotaBytes < 0 {
			return nil, fmt.Errorf("%w: validate cache policy facts", ErrPersistence)
		}
		switch mode {
		case string(edgeconfig.CacheDisabled), string(edgeconfig.CacheFollowOrigin), string(edgeconfig.CacheOverride):
			fact.mode = edgeconfig.CacheMode(mode)
		default:
			return nil, fmt.Errorf("%w: validate cache policy mode", ErrPersistence)
		}
		switch queryMode {
		case string(edgeconfig.CacheQueryPreserve), string(edgeconfig.CacheQueryIgnore), string(edgeconfig.CacheQueryInclude), string(edgeconfig.CacheQueryExclude):
			fact.queryMode = edgeconfig.CacheQueryMode(queryMode)
		default:
			return nil, fmt.Errorf("%w: validate cache query mode", ErrPersistence)
		}
		if err := decodeCachePolicyExtensions(extensions, &fact.extensions); err != nil {
			return nil, fmt.Errorf("%w: decode cache policy extensions", ErrPersistence)
		}
		fact.rules, err = decodeCachePolicyRules(rules, fact.schemaVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: decode cache policy rules", ErrPersistence)
		}
		if _, duplicate := result[fact.siteID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate cache policy fact", ErrPersistence)
		}
		result[fact.siteID] = &fact
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate cache policy facts", ErrPersistence)
	}
	return result, nil
}

// decodeCachePolicyExtensions reads a definition's extensions column (the
// keys of edgeconfig.CachePolicyDocument's v2 extensions, nothing else).
func decodeCachePolicyExtensions(content []byte, target *edgeconfig.CachePolicyDocument) error {
	var wire struct {
		StaleIfError     bool  `json:"stale_if_error"`
		BackgroundUpdate bool  `json:"background_update"`
		MinObjectBytes   int64 `json:"min_object_bytes"`
		MaxObjectBytes   int64 `json:"max_object_bytes"`
		SliceBytes       int64 `json:"slice_bytes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || anyNegative(wire.MinObjectBytes, wire.MaxObjectBytes, wire.SliceBytes) {
		return ErrInvalidInput
	}
	target.StaleIfError, target.BackgroundUpdate = wire.StaleIfError, wire.BackgroundUpdate
	target.MinObjectBytes, target.MaxObjectBytes, target.SliceBytes = wire.MinObjectBytes, wire.MaxObjectBytes, wire.SliceBytes
	return nil
}

func anyNegative(values ...int64) bool {
	for _, value := range values {
		if value < 0 {
			return true
		}
	}
	return false
}

func decodeCachePolicyRules(content []byte, schemaVersion int) ([]cachePolicyRuleFact, error) {
	if schemaVersion == cachePolicySchemaV1 {
		var wire []struct {
			Order        int      `json:"order"`
			Extensions   []string `json:"extensions,omitempty"`
			PathPrefix   string   `json:"path_prefix,omitempty"`
			StatusCodes  []int    `json:"status_codes,omitempty"`
			TTLSeconds   *int64   `json:"ttl_seconds"`
			PathRegex    string   `json:"path_regex,omitempty"`
			ContentTypes []string `json:"content_types,omitempty"`
		}
		if err := decodeCachePolicyRuleWire(content, &wire); err != nil {
			return nil, err
		}
		rules := make([]cachePolicyRuleFact, len(wire))
		for index, rule := range wire {
			if rule.TTLSeconds == nil {
				return nil, ErrInvalidInput
			}
			rules[index] = cachePolicyRuleFact{
				order: rule.Order, extensions: rule.Extensions, pathPrefix: rule.PathPrefix,
				statusCodes: rule.StatusCodes, ttlSeconds: *rule.TTLSeconds,
				pathRegex: rule.PathRegex, contentTypes: rule.ContentTypes,
			}
		}
		return rules, nil
	}
	if schemaVersion != cachePolicySchemaV2 {
		return nil, ErrInvalidInput
	}
	var wire []struct {
		Order             int                         `json:"order"`
		Extensions        []string                    `json:"extensions,omitempty"`
		PathPrefix        string                      `json:"path_prefix,omitempty"`
		StatusCodes       []int                       `json:"status_codes,omitempty"`
		Action            *edgeconfig.CacheRuleAction `json:"action"`
		TTLSeconds        *int64                      `json:"ttl_seconds"`
		BrowserTTLSeconds *int64                      `json:"browser_ttl_seconds"`
		PathRegex         string                      `json:"path_regex,omitempty"`
		ContentTypes      []string                    `json:"content_types,omitempty"`
		edgeconfig.CacheRuleExtras
	}
	if err := decodeCachePolicyRuleWire(content, &wire); err != nil {
		return nil, err
	}
	rules := make([]cachePolicyRuleFact, len(wire))
	for index, rule := range wire {
		if rule.Action == nil || rule.TTLSeconds == nil || rule.BrowserTTLSeconds == nil {
			return nil, ErrInvalidInput
		}
		rules[index] = cachePolicyRuleFact{
			order: rule.Order, extensions: rule.Extensions, pathPrefix: rule.PathPrefix,
			statusCodes: rule.StatusCodes, action: *rule.Action,
			ttlSeconds: *rule.TTLSeconds, browserTTLSeconds: *rule.BrowserTTLSeconds,
			pathRegex: rule.PathRegex, contentTypes: rule.ContentTypes, extras: rule.CacheRuleExtras,
		}
	}
	return rules, nil
}

func decodeCachePolicyRuleWire(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidInput
	}
	return nil
}

func loadSecurityBindingFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	statusRecoverySiteIDLists ...[]uuid.UUID,
) (map[uuid.UUID][]securityBindingFact, error) {
	statusRecoverySiteIDs := optionalSiteStatusRecoveryCandidateIDs(statusRecoverySiteIDLists)
	rows, err := tx.Query(ctx, `
		SELECT binding.site_id,binding.id,binding.revision,binding.policy_id,binding.policy_kind,
		       binding.active_policy_version,version.document,publication.id,publication.runtime_snapshot_sha256
		FROM security_policy_site_bindings binding
		JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
		  AND site.deleted_at IS NULL AND site.enabled=true
		  AND (site.status NOT IN ('package_expired','traffic_exceeded') OR site.id=ANY($2::uuid[]))
		JOIN security_policy_versions version
		  ON version.policy_id=binding.policy_id AND version.revision=binding.active_policy_version
		JOIN security_policy_publications publication
		  ON publication.binding_id=binding.id
		  AND publication.tenant_scope_id=binding.tenant_scope_id
		  AND publication.site_id=binding.site_id
		  AND publication.policy_id=binding.policy_id
		  AND publication.policy_kind=binding.policy_kind
		  AND publication.policy_version=binding.active_policy_version
		  -- sec-rebind (470): a detach repeats the active (library, version)
		  -- and a library bound again can be claimed at the same version:
		  -- the newest non-detach claim of it is the active publication.
		  AND publication.binding_revision=(
		      SELECT max(latest.binding_revision) FROM security_policy_publications latest
		      WHERE latest.binding_id=binding.id AND latest.policy_id=binding.policy_id
		        AND latest.policy_version=binding.active_policy_version AND NOT latest.detach)
		WHERE binding.tenant_scope_id=$1 AND binding.active_policy_version IS NOT NULL
		ORDER BY binding.site_id,binding.policy_kind
		FOR SHARE OF binding,version`, scopeID, statusRecoverySiteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read security binding facts", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID][]securityBindingFact)
	for rows.Next() {
		var fact securityBindingFact
		var policyID uuid.UUID
		var kind string
		var policyVersion int64
		var document, runtimeDigest []byte
		if err := rows.Scan(&fact.siteID, &fact.bindingID, &fact.bindingRevision, &policyID, &kind, &policyVersion, &document, &fact.publicationID, &runtimeDigest); err != nil ||
			fact.siteID == uuid.Nil || fact.bindingID == uuid.Nil || fact.publicationID == uuid.Nil || fact.bindingRevision < 1 || policyID == uuid.Nil || policyVersion < 1 || len(runtimeDigest) != sha256.Size {
			return nil, fmt.Errorf("%w: scan security binding facts", ErrPersistence)
		}
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&fact.policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return nil, fmt.Errorf("%w: decode security policy version", ErrPersistence)
		}
		if fact.policy.ID != policyID || fact.policy.ScopeID != scopeID ||
			fact.policy.Kind != kind || fact.policy.Revision != policyVersion {
			return nil, fmt.Errorf("%w: validate security policy version", ErrPersistence)
		}
		if len(runtimeDigest) != sha256.Size {
			return nil, fmt.Errorf("%w: validate security runtime digest", ErrPersistence)
		}
		copy(fact.runtimeSHA256[:], runtimeDigest)
		if compiled, err := securitypolicy.CompileRuntimeSnapshot(fact.policy, fact.siteID); err != nil || compiled.SHA256 != fact.runtimeSHA256 {
			return nil, fmt.Errorf("%w: validate security runtime digest", ErrPersistence)
		}
		bindings := result[fact.siteID]
		if len(bindings) > 0 && bindings[len(bindings)-1].policy.Kind == fact.policy.Kind {
			return nil, fmt.Errorf("%w: duplicate security binding", ErrPersistence)
		}
		result[fact.siteID] = append(bindings, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate security binding facts", ErrPersistence)
	}
	return result, nil
}

func loadChallengeBindingFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	statusRecoverySiteIDLists ...[]uuid.UUID,
) (map[uuid.UUID]*challengeBindingFact, error) {
	statusRecoverySiteIDs := optionalSiteStatusRecoveryCandidateIDs(statusRecoverySiteIDLists)
	rows, err := tx.Query(ctx, `
		SELECT binding.tenant_scope_id,binding.site_id,revision.host,revision.policy_id,revision.policy_revision,
		       revision.binding_revision,revision.secret_config_version_id
		FROM challenge_site_bindings_138 binding
		JOIN challenge_site_binding_revisions_138 revision
		  ON revision.tenant_scope_id=binding.tenant_scope_id
		 AND revision.site_id=binding.site_id
		 AND revision.binding_revision=binding.active_binding_revision
		JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
		 AND site.deleted_at IS NULL AND site.enabled=true
		 AND (site.status NOT IN ('package_expired','traffic_exceeded') OR site.id=ANY($2::uuid[]))
		WHERE binding.tenant_scope_id=$1 AND binding.active_binding_revision IS NOT NULL
		  AND revision.state IN ('candidate','active')
		ORDER BY binding.site_id
		FOR SHARE OF binding,revision`, scopeID, statusRecoverySiteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read challenge binding facts", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*challengeBindingFact)
	for rows.Next() {
		fact := new(challengeBindingFact)
		if err := rows.Scan(&fact.tenantScopeID, &fact.siteID, &fact.host, &fact.policyID, &fact.policyRevision,
			&fact.bindingRevision, &fact.secretConfigVersionID); err != nil || fact.tenantScopeID != scopeID || fact.siteID == uuid.Nil ||
			fact.policyID == uuid.Nil || fact.host == "" || fact.policyRevision < 1 ||
			fact.bindingRevision < 1 || fact.secretConfigVersionID == uuid.Nil {
			return nil, fmt.Errorf("%w: scan challenge binding facts", ErrPersistence)
		}
		if _, duplicate := result[fact.siteID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate challenge binding", ErrPersistence)
		}
		result[fact.siteID] = fact
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate challenge binding facts", ErrPersistence)
	}
	return result, nil
}

type l4ProtocolCapability struct {
	protocol string
	version  uint32
}

func loadL4V2LifecycleProtocols(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sourceRevision int64) ([]l4ProtocolCapability, error) {
	// Releases with no L4 entries still need a v2 agent to revoke previously managed listeners.
	rows, err := tx.Query(ctx, `WITH history AS (SELECT runtime_spec
		FROM l4_publish_intents
		WHERE scope_id=$1 AND configuration_source_revision <= $2
		  AND runtime_spec->>'schema_version'='cdnca.edge.l4/v2'), protocols AS (
		SELECT runtime_spec #>> '{listener,protocol}' AS protocol FROM history UNION
		SELECT listener->>'protocol' FROM history,
		LATERAL jsonb_array_elements(COALESCE(runtime_spec->'additional_listeners','[]'::jsonb)) listener)
		SELECT protocol, CASE WHEN EXISTS(SELECT 1 FROM history
		WHERE runtime_spec->'tls_passthrough'='true'::jsonb) THEN 4 WHEN EXISTS(SELECT 1 FROM history
		WHERE jsonb_array_length(COALESCE(runtime_spec->'additional_listeners','[]'::jsonb))>0) THEN 3 ELSE 2 END
		FROM protocols ORDER BY protocol`, scopeID, sourceRevision)
	if err != nil {
		return nil, fmt.Errorf("%w: read L4 v2 lifecycle protocols", ErrPersistence)
	}
	defer rows.Close()
	var protocols []l4ProtocolCapability
	for rows.Next() {
		var capability l4ProtocolCapability
		if err := rows.Scan(&capability.protocol, &capability.version); err != nil || capability.protocol != "tcp" && capability.protocol != "udp" {
			return nil, fmt.Errorf("%w: invalid L4 v2 lifecycle protocol", ErrPersistence)
		}
		protocols = append(protocols, capability)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate L4 v2 lifecycle protocols", ErrPersistence)
	}
	return protocols, nil
}

func loadStreamFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]snapshotStream, error) {
	// The platform drain limit (系统设置 > 其它配置) rides on every v2 stream;
	// at its default it is omitted and releases are unchanged.
	drainMaxMS, err := systemothersettings.L4DrainMaxMS(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("%w: read L4 drain limit", ErrPersistence)
	}
	rows, err := tx.Query(ctx, `
		SELECT forward.id,forward.revision,intent.runtime_spec,forward.package_subscription_id
		FROM l4_forwards forward
		-- Community edition: a forward needs no package (NULL); one
		-- bound to a package is published only while that package is valid.
		LEFT JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=forward.scope_id AND package_subscription.id=forward.package_subscription_id
		JOIN LATERAL (
			SELECT runtime_spec FROM l4_publish_intents
			WHERE stream_id=forward.id ORDER BY version DESC LIMIT 1
		) intent ON true
		WHERE forward.scope_id=$1 AND forward.deleted_at IS NULL AND forward.enabled=true AND forward.admin_status='normal'
		  AND (forward.package_subscription_id IS NULL OR (package_subscription.id IS NOT NULL
		  AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL
		  AND package_subscription.suspended_at IS NULL))
		ORDER BY forward.id`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read L4 facts", ErrPersistence)
	}
	defer rows.Close()
	var result []snapshotStream
	for rows.Next() {
		var id uuid.UUID
		var subscriptionID *uuid.UUID
		var item snapshotStream
		var runtimeJSON []byte
		if err := rows.Scan(&id, &item.Revision, &runtimeJSON, &subscriptionID); err != nil {
			return nil, fmt.Errorf("%w: scan L4 facts", ErrPersistence)
		}
		// 1.0.35 publishes v2 L4 runtimes only (fresh installs, no v1 rows).
		var runtimeV2 edgeconfig.L4StreamRuntimeV2
		if json.Unmarshal(runtimeJSON, &runtimeV2) != nil || runtimeV2.SchemaVersion != "cdnca.edge.l4/v2" ||
			runtimeV2.StreamID != id.String() || runtimeV2.TenantID != scopeID.String() || runtimeV2.Geo.TenantID != scopeID.String() ||
			runtimeV2.Revision != item.Revision || runtimeV2.PackageSubscriptionID != "" {
			return nil, fmt.Errorf("%w: invalid scoped L4 v2 runtime fact", ErrPersistence)
		}
		// L4_PACKAGE_ATTRIBUTION: the forward's package at this publication,
		// stamped by the node on its session facts.
		if subscriptionID != nil && *subscriptionID != uuid.Nil {
			runtimeV2.PackageSubscriptionID = subscriptionID.String()
		}
		if drainMaxMS != nil {
			limit := *drainMaxMS
			runtimeV2.DrainMaxMS = &limit
		}
		item.ID = id.String()
		item.RuntimeV2 = &runtimeV2
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate L4 facts", ErrPersistence)
	}
	return result, nil
}

func loadPublication(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string) (storedPublication, bool, error) {
	stored, err := scanStoredPublication(tx.QueryRow(ctx, `
		SELECT id,source_revision,request_digest,canonical_snapshot_sha256,artifact_sha256,
		       config_version_id,rollout_id,node_count,created_at,target_kind,
		       target_snapshot_id,target_snapshot_revision,target_resolver_sha256,target_snapshot_sha256
		FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND idempotency_key=$2`, scopeID, key), scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPublication{}, false, nil
	}
	if err != nil {
		return storedPublication{}, false, fmt.Errorf("%w: load existing publication", ErrPersistence)
	}
	return stored, true, nil
}

func scanStoredPublication(row rowScanner, scopeID uuid.UUID) (storedPublication, error) {
	var stored storedPublication
	var snapshotDigest, artifactDigest, targetDigest, resolverDigest []byte
	var targetID *uuid.UUID
	var targetRevision *int64
	err := row.Scan(
		&stored.result.PublicationID, &stored.result.SourceRevision, &stored.requestDigest,
		&snapshotDigest, &artifactDigest, &stored.result.ConfigVersionID, &stored.result.RolloutID,
		&stored.result.NodeCount, &stored.result.CreatedAt, &stored.result.TargetKind,
		&targetID, &targetRevision, &resolverDigest, &targetDigest)
	if err != nil {
		return storedPublication{}, err
	}
	if len(stored.requestDigest) != 32 || len(snapshotDigest) != 32 ||
		len(artifactDigest) != 32 || len(targetDigest) != 32 {
		return storedPublication{}, fmt.Errorf("invalid publication digest")
	}
	stored.result.ConfigurationScopeID = scopeID
	copy(stored.result.CanonicalSnapshotSHA256[:], snapshotDigest)
	copy(stored.result.ArtifactSHA256[:], artifactDigest)
	copy(stored.result.TargetSnapshotSHA256[:], targetDigest)
	if targetID != nil && targetRevision != nil {
		stored.result.TargetSnapshot = &TargetSnapshotReference{ID: *targetID, Revision: *targetRevision}
		if len(resolverDigest) != 32 {
			return storedPublication{}, fmt.Errorf("invalid target resolver digest")
		}
		copy(stored.result.TargetSnapshot.SHA256[:], resolverDigest)
	}
	return stored, nil
}

func publicationExistsForSourceRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, revision int64) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM edge_config_publications
			WHERE configuration_scope_id=$1 AND source_revision=$2 AND contract_version=1
		)`, scopeID, revision).Scan(&exists); err != nil {
		return false, fmt.Errorf("%w: read source publication", ErrPersistence)
	}
	return exists, nil
}

func publicationExistsForRequestID(ctx context.Context, tx pgx.Tx, scopeID, requestID uuid.UUID) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND request_id=$2
	)`, scopeID, requestID).Scan(&exists); err != nil {
		return false, fmt.Errorf("%w: read publication request ID", ErrPersistence)
	}
	return exists, nil
}

func insertPublication(ctx context.Context, tx pgx.Tx, result PublishResult, request normalizedPublishRequest, digest [32]byte) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO edge_config_publications (
			id,configuration_scope_id,source_revision,idempotency_key,request_digest,
			request_id,correlation_id,canonical_snapshot_sha256,artifact_sha256,
			config_version_id,rollout_id,node_count,created_at,expected_source_revision,
			actor_user_id,actor_scope_id,target_kind,target_snapshot_id,target_snapshot_revision,
			target_resolver_sha256,target_snapshot_sha256,contract_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,1)
		ON CONFLICT (configuration_scope_id,idempotency_key) DO NOTHING`,
		result.PublicationID, result.ConfigurationScopeID, result.SourceRevision, request.IdempotencyKey,
		digest[:], request.RequestUUID, request.CorrelationUUID, result.CanonicalSnapshotSHA256[:],
		result.ArtifactSHA256[:], result.ConfigVersionID, result.RolloutID, result.NodeCount, result.CreatedAt,
		request.ExpectedSourceRevision, request.Actor.UserID, request.Actor.ScopeID, result.TargetKind,
		targetReferenceID(result.TargetSnapshot), targetReferenceRevision(result.TargetSnapshot),
		targetReferenceDigest(result.TargetSnapshot), result.TargetSnapshotSHA256[:])
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && databaseError.ConstraintName == "edge_config_publications_one_contract_source_idx" {
			return ErrRevisionConflict
		}
		if errors.As(err, &databaseError) && strings.Contains(databaseError.ConstraintName, "request_id") {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("%w: persist publication", ErrPersistence)
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func targetReferenceID(reference *TargetSnapshotReference) *uuid.UUID {
	if reference == nil {
		return nil
	}
	value := reference.ID
	return &value
}

func targetReferenceRevision(reference *TargetSnapshotReference) *int64 {
	if reference == nil {
		return nil
	}
	value := reference.Revision
	return &value
}

func targetReferenceDigest(reference *TargetSnapshotReference) []byte {
	if reference == nil {
		return nil
	}
	return reference.SHA256[:]
}
