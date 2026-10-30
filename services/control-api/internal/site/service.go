package site

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return WriteResult{}, err
	}
	// Reject malformed input before any store access (the defaults lookup).
	checked := request.Fields
	if checked.HTTPSEnabled && len(checked.HTTPSPorts) == 0 {
		checked.HTTPSPorts = []string{"443"} // filled from the defaults below
	}
	if err := normalizeFields(&checked); err != nil {
		return WriteResult{}, err
	}
	if !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	// 网站列表 > 默认设置 (migration 490): the owner's defaults fill what the
	// request left out (before normalizeFields fills its own); anything the
	// request names wins.
	userDefaults, err := s.store.loadCreationUserDefaults(ctx, request.TargetScopeID, request.OwnerUserID, request.Fields.GroupID)
	if err != nil {
		return WriteResult{}, err
	}
	userDefaults.applyFields(&request.Fields)
	userDefaults.applyDNSProvider(&request)
	request.userDefaults = userDefaults
	if err := normalizeFields(&request.Fields); err != nil {
		return WriteResult{}, err
	}
	request.defaultPool = request.OriginPool == nil
	requestedPool := request.OriginPool
	if requestedPool != nil {
		pool := *requestedPool
		applyCreatePoolDefaults(userDefaults, &pool)
		// A create that leaves the load balancing out (and has no owner
		// default for it) follows the platform default like a request
		// without a pool; round_robin stands in until the store reads it.
		if pool.BalanceMethod == "" {
			pool.BalanceMethod, request.defaultPool = BalanceRoundRobin, true
		}
		requestedPool = &pool
	}
	originPool, err := normalizeCreateOriginPool(request.Fields, requestedPool)
	if err != nil {
		return WriteResult{}, err
	}
	if request.OriginPool == nil && len(userDefaults) > 0 {
		if userDefaults.applyPool(&originPool, true) {
			request.defaultPool = false
		}
		if err := normalizeOriginPool(&originPool); err != nil {
			return WriteResult{}, err
		}
	}
	request.OriginPool = &originPool
	id, err := uuid.NewV7()
	if err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID  `json:"target_scope_id"`
		OwnerUserID   uuid.UUID  `json:"owner_user_id"`
		Fields        SiteFields `json:"fields"`
		OriginPool    OriginPool `json:"origin_pool"`
		DNSProviderID *uuid.UUID `json:"dns_provider_id,omitempty"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields, originPool, request.DNSProviderID})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Create(ctx, actor, request, id, digest)
	if err != nil {
		return WriteResult{}, err
	}
	redact(&result.Site, actor.ScopeKind)
	return result, nil
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeFields(&request.Fields); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID  `json:"id"`
		ExpectedRevision int64      `json:"expected_revision"`
		Fields           SiteFields `json:"fields"`
	}{request.ID, request.ExpectedRevision, request.Fields})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Update(ctx, actor, request, digest)
	if err != nil {
		return WriteResult{}, err
	}
	redact(&result.Site, actor.ScopeKind)
	return result, nil
}

func (s *Service) UpdateOrigin(ctx context.Context, actor Actor, request UpdateOriginRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeOriginPool(&request.Pool); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID  `json:"id"`
		ExpectedRevision int64      `json:"expected_revision"`
		Pool             OriginPool `json:"origin_pool"`
	}{request.ID, request.ExpectedRevision, request.Pool})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.UpdateOrigin(ctx, actor, request, digest)
	if err != nil {
		return WriteResult{}, err
	}
	redact(&result.Site, actor.ScopeKind)
	return result, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (DeleteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return DeleteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return DeleteResult{}, err
	}
	return s.store.Delete(ctx, actor, request, digest)
}

func (s *Service) BatchAction(ctx context.Context, actor Actor, request BatchActionRequest) (BatchActionResult, error) {
	request.Action = strings.TrimSpace(request.Action)
	if !validActor(actor) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		len(request.Items) < 1 || len(request.Items) > 100 || !validBatchAction(request.Action) {
		return BatchActionResult{}, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.Items))
	for _, item := range request.Items {
		if item.ID == uuid.Nil || item.ExpectedRevision < 1 {
			return BatchActionResult{}, ErrInvalidInput
		}
		if _, exists := seen[item.ID]; exists {
			return BatchActionResult{}, ErrInvalidInput
		}
		seen[item.ID] = struct{}{}
	}
	if (request.Action == BatchActionSetProtocols) != (request.Protocols != nil) ||
		request.Protocols != nil && !validBatchProtocols(*request.Protocols) {
		return BatchActionResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		Action    string            `json:"action"`
		Items     []BatchActionItem `json:"items"`
		Protocols *BatchProtocols   `json:"protocols,omitempty"`
	}{request.Action, request.Items, request.Protocols})
	if err != nil {
		return BatchActionResult{}, err
	}
	result, err := s.store.BatchAction(ctx, actor, request, digest)
	if err != nil {
		return BatchActionResult{}, err
	}
	for index := range result.Items {
		if result.Items[index].Site != nil {
			redact(result.Items[index].Site, actor.ScopeKind)
		}
	}
	return result, nil
}

func (s *Service) Lock(ctx context.Context, actor Actor, request LockRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult{}, ErrPermissionDenied
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || !utf8.ValidString(request.Reason) || utf8.RuneCountInString(request.Reason) > 500 {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Reason           string    `json:"reason"`
	}{request.ID, request.ExpectedRevision, request.Reason})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.changeLock(ctx, actor, request.ID, request.ExpectedRevision, request.Reason,
		request.IdempotencyKey, request.RequestID, true, digest)
}

func (s *Service) Unlock(ctx context.Context, actor Actor, request UnlockRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult{}, ErrPermissionDenied
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.requestStatusRecovery(ctx, actor, StatusRecoveryRequest{
		ID: request.ID, ExpectedRevision: request.ExpectedRevision, Trigger: RecoveryTriggerUnlock,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
	}, digest)
}

func (s *Service) RequestStatusRecovery(ctx context.Context, actor Actor, request StatusRecoveryRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validRecoveryTrigger(request.Trigger) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if request.Trigger == RecoveryTriggerUnlock && actor.ScopeKind != "platform" {
		return WriteResult{}, ErrPermissionDenied
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID       `json:"id"`
		ExpectedRevision int64           `json:"expected_revision"`
		Trigger          RecoveryTrigger `json:"trigger"`
	}{request.ID, request.ExpectedRevision, request.Trigger})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.requestStatusRecovery(ctx, actor, request, digest)
}

func (s *Service) Get(ctx context.Context, actor Actor, id uuid.UUID) (Site, error) {
	if !validActor(actor) || id == uuid.Nil {
		return Site{}, ErrInvalidInput
	}
	item, err := s.store.Get(ctx, actor, id)
	if err != nil {
		return Site{}, err
	}
	redact(&item, actor.ScopeKind)
	return item, nil
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	filter, err := NormalizeListFilter(actor, filter)
	if err != nil {
		return ListResult{}, err
	}
	result, err := s.store.List(ctx, actor, filter)
	if err != nil {
		return ListResult{}, err
	}
	if actor.ScopeKind == "tenant" {
		for index := range result.Items {
			result.Items[index].Owner = nil
			result.Items[index].Region = nil
		}
	}
	return result, nil
}

func NormalizeListFilter(actor Actor, filter ListFilter) (ListFilter, error) {
	if !validActor(actor) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 ||
		len(filter.Domain) > 253 || len(filter.Owner) > 128 || len(filter.CNAMEDomain) > 253 ||
		len(filter.Package) > 128 || len(filter.Site) > 253 ||
		len(filter.CNAMEHostname) > 63 || len(filter.Domains) > 50 || len(filter.SiteIDs) > 100 ||
		(filter.Status != "" && !validStatus(filter.Status)) ||
		(filter.SyncStatus != "" && !validSyncStatus(filter.SyncStatus)) {
		return ListFilter{}, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && (strings.TrimSpace(filter.Owner) != "" || filter.RegionID != nil || filter.NodeGroupID != nil) {
		return ListFilter{}, ErrPermissionDenied
	}
	filter.Domain = strings.ToLower(strings.TrimSpace(filter.Domain))
	filter.Owner = strings.TrimSpace(filter.Owner)
	filter.Package = strings.TrimSpace(filter.Package)
	filter.Site = strings.ToLower(strings.TrimSpace(filter.Site))
	filter.CNAMEDomain = strings.ToLower(strings.TrimSpace(filter.CNAMEDomain))
	filter.CNAMEHostname = strings.ToLower(strings.TrimSpace(filter.CNAMEHostname))
	if filter.OriginIP != "" {
		ip := net.ParseIP(strings.TrimSpace(filter.OriginIP))
		if ip == nil {
			return ListFilter{}, ErrInvalidInput
		}
		filter.OriginIP = ip.String()
	}
	if filter.HTTPPort != "" && !validPort(filter.HTTPPort) {
		return ListFilter{}, ErrInvalidInput
	}
	if filter.HTTPSPort != "" && !validPort(filter.HTTPSPort) {
		return ListFilter{}, ErrInvalidInput
	}
	for index := range filter.Domains {
		domain, err := normalizeDomain(filter.Domains[index], true)
		if err != nil {
			return ListFilter{}, ErrInvalidInput
		}
		filter.Domains[index] = domain
	}
	return filter, nil
}

func normalizeActorAndTarget(actor Actor, targetScopeID, ownerUserID *uuid.UUID) error {
	if !validActor(actor) {
		return ErrInvalidInput
	}
	switch actor.ScopeKind {
	case "platform":
		if *targetScopeID == uuid.Nil || *ownerUserID == uuid.Nil {
			return ErrInvalidInput
		}
	case "tenant":
		if *targetScopeID != uuid.Nil && *targetScopeID != actor.ScopeID {
			return ErrPermissionDenied
		}
		if *ownerUserID != uuid.Nil && *ownerUserID != actor.UserID {
			return ErrPermissionDenied
		}
		*targetScopeID = actor.ScopeID
		*ownerUserID = actor.UserID
	}
	return nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func normalizeFields(fields *SiteFields) error {
	fields.tlsProtocolsDefaulted = fields.TLSProtocols == nil
	protocols, err := normalizeTLSProtocols(fields.TLSProtocols)
	if err != nil {
		return err
	}
	fields.TLSProtocols = protocols
	if err := normalizeTLSProfile(fields); err != nil {
		return err
	}
	domains := fields.Domains
	if len(domains) == 0 && fields.Domain != "" {
		domains = []string{fields.Domain}
	}
	domains, err = normalizeSiteDomains(domains)
	if err != nil {
		return fieldError("domains", "invalid")
	}
	fields.Domains = domains
	fields.Domain = domains[0]
	if fields.CNAME != "" {
		fields.CNAME, err = normalizeDomain(fields.CNAME, false)
		if err != nil {
			return fieldError("cname", "invalid")
		}
	}
	fields.CNAMEMode = strings.ToLower(strings.TrimSpace(fields.CNAMEMode))
	fields.CNAMEDomain = strings.ToLower(strings.TrimSpace(fields.CNAMEDomain))
	fields.CNAMEHostname = strings.ToLower(strings.TrimSpace(fields.CNAMEHostname))
	if fields.CNAMEMode != "" && ((fields.CNAMEMode != "site" && fields.CNAMEMode != "package") || fields.PackageSubscriptionID == nil) {
		return fieldError("cname_mode", "invalid")
	}
	if len(fields.HTTPPorts) == 0 {
		fields.HTTPPorts = []string{"80"}
	}
	fields.HTTPPorts, err = normalizePorts(fields.HTTPPorts)
	if err != nil {
		return fieldError("http_listen_ports", "invalid")
	}
	fields.HTTPSPorts, err = normalizePorts(fields.HTTPSPorts)
	if err != nil {
		return fieldError("https_listen_ports", "invalid")
	}
	if fields.HTTPSEnabled && len(fields.HTTPSPorts) == 0 {
		return fieldError("https_listen_ports", "required")
	}
	if fields.ForceHTTPS != nil && *fields.ForceHTTPS && (!fields.HTTPSEnabled || len(fields.HTTPSPorts) == 0) {
		return fieldError("force_https", "requires_https")
	}
	if port := fields.HTTPSRedirectPort; port != nil && (*port < 0 || *port > 65_535 ||
		*port != 0 && !slices.Contains(fields.HTTPSPorts, strconv.Itoa(*port))) {
		return fieldError("https_redirect_port", "not_listened")
	}
	for _, httpPort := range fields.HTTPPorts {
		for _, httpsPort := range fields.HTTPSPorts {
			if httpPort == httpsPort {
				return fieldError("https_listen_ports", "overlaps_http")
			}
		}
	}
	if len(fields.Origins) < 1 || len(fields.Origins) > 32 {
		return fieldError("origins", "count")
	}
	fields.originHosts = make([]string, 0, len(fields.Origins))
	fields.originItems = make([]Origin, 0, len(fields.Origins))
	seenOrigins := make(map[string]struct{}, len(fields.Origins))
	for index, raw := range fields.Origins {
		_, host, port, err := originFromLegacy(raw)
		if err != nil {
			return fieldError("origins", "invalid")
		}
		item := Origin{Host: host, Port: port, Weight: 1, Enabled: true}
		endpoint := originCompatibilityEndpoint(item)
		if _, exists := seenOrigins[endpoint]; exists {
			return fieldError("origins", "duplicate")
		}
		seenOrigins[endpoint] = struct{}{}
		fields.Origins[index] = endpoint
		fields.originHosts = append(fields.originHosts, host)
		fields.originItems = append(fields.originItems, item)
	}
	if fields.Status == "" {
		if fields.Enabled {
			fields.Status = StatusActive
		} else {
			fields.Status = StatusDisabled
		}
	}
	if !validStatus(fields.Status) || fields.Status == StatusLocked || (fields.Enabled && fields.Status == StatusDisabled) ||
		(!fields.Enabled && fields.Status != StatusDisabled) {
		return ErrInvalidInput
	}
	for _, value := range []*string{
		&fields.PackageName, &fields.GroupName, &fields.RegionName, &fields.NodeGroupName,
	} {
		*value = strings.TrimSpace(*value)
		if utf8.RuneCountInString(*value) > 128 {
			return ErrInvalidInput
		}
	}
	if (fields.PackageID == nil) != (fields.PackageName == "") ||
		(fields.GroupID == nil) != (fields.GroupName == "") ||
		(fields.RegionID == nil) != (fields.RegionName == "") ||
		(fields.NodeGroupID == nil) != (fields.NodeGroupName == "") {
		return ErrInvalidInput
	}
	return nil
}

// normalizeTLSProtocols: nil is the baseline; otherwise an ascending
// contiguous range of TLSv1..TLSv1.3. SSLv2/SSLv3 are refused by name.
func normalizeTLSProtocols(protocols []string) ([]string, error) {
	if protocols == nil {
		return CanonicalTLSProtocols(), nil
	}
	for _, protocol := range protocols {
		switch protocol {
		case "SSLv2", "SSLv3":
			return nil, ErrTLSLegacyProtocolBlocked
		}
	}
	if edgeconfig.ValidateSiteTLSProtocols(protocols) != nil {
		return nil, ErrTLSProtocolsInvalid
	}
	return slices.Clone(protocols), nil
}

// normalizeTLSProfile checks the profile fields the request sets. The
// combination (legacy protocols need the legacy preset, client verification
// needs a CA) is checked again on the stored row (CHECK 367), where unset
// fields have their current value.
func normalizeTLSProfile(fields *SiteFields) error {
	if fields.TLSCipherPreset != nil {
		switch *fields.TLSCipherPreset {
		case edgeconfig.TLSCipherModern, edgeconfig.TLSCipherCompatible, edgeconfig.TLSCipherLegacy:
			if fields.TLSCipherSuites != nil {
				return ErrTLSProfileInvalid
			}
		case edgeconfig.TLSCipherCustom:
			// whitelisted names only (edgeconfig.ValidateTLSCipherSuites);
			// TLSv1.2 in the protocols is checked here when the request names
			// them, and by CHECK 517 against stored ones
			if edgeconfig.ValidateTLSCipherSuites(fields.TLSCipherSuites) != nil {
				return ErrTLSProfileInvalid
			}
			if !fields.tlsProtocolsDefaulted && !slices.Contains(fields.TLSProtocols, "TLSv1.2") {
				return ErrTLSProfileInvalid
			}
		default:
			return ErrTLSProfileInvalid
		}
	} else if fields.TLSCipherSuites != nil {
		return ErrTLSProfileInvalid
	}
	if fields.TLSClientAuth != nil {
		switch *fields.TLSClientAuth {
		case edgeconfig.ClientAuthOff:
			if fields.TLSClientCAPEM != nil && *fields.TLSClientCAPEM != "" {
				return ErrTLSProfileInvalid
			}
			empty := ""
			fields.TLSClientCAPEM = &empty
		case edgeconfig.ClientAuthOptional, edgeconfig.ClientAuthRequired:
			if fields.TLSClientCAPEM == nil {
				return ErrTLSProfileInvalid
			}
		default:
			return ErrTLSProfileInvalid
		}
	} else if fields.TLSClientCAPEM != nil {
		return ErrTLSProfileInvalid
	}
	if fields.TLSClientCAPEM != nil && *fields.TLSClientCAPEM != "" {
		canonical := strings.TrimSpace(*fields.TLSClientCAPEM) + "\n"
		if edgeconfig.ValidateClientCABundle([]byte(canonical)) != nil {
			return ErrTLSProfileInvalid
		}
		fields.TLSClientCAPEM = &canonical
	}
	// "by preset" again and an explicit value at once is contradictory
	if fields.TLSPreferServerCiphersReset && fields.TLSPreferServerCiphers != nil {
		return ErrTLSProfileInvalid
	}
	if fields.TLSCipherPreset != nil && *fields.TLSCipherPreset != edgeconfig.TLSCipherLegacy && !fields.tlsProtocolsDefaulted &&
		(slices.Contains(fields.TLSProtocols, "TLSv1") || slices.Contains(fields.TLSProtocols, "TLSv1.1")) {
		return ErrTLSProfileInvalid
	}
	return nil
}

func normalizeOriginPool(pool *OriginPool) error {
	if err := expandBackupOrigins(pool); err != nil {
		return err
	}
	// 源站没单独设端口的用池级端口 (migration 490)
	inheritOriginPorts(pool)
	if !validBalanceMethod(pool.BalanceMethod) || pool.ConnectTimeoutMS < 50 || pool.ConnectTimeoutMS > 30_000 ||
		pool.ReadTimeoutMS < 100 || pool.ReadTimeoutMS > 300_000 || len(pool.Origins) < 1 || len(pool.Origins) > 32 {
		return ErrInvalidInput
	}
	if pool.KeepaliveEnabled == nil {
		// Clients and stored pools from before keepalive existed.
		enabled := true
		pool.KeepaliveEnabled = &enabled
	}
	if pool.KeepaliveIdleTimeoutMS == 0 {
		pool.KeepaliveIdleTimeoutMS = DefaultKeepaliveIdleTimeoutMS
	}
	if pool.KeepaliveIdleTimeoutMS < 1000 || pool.KeepaliveIdleTimeoutMS > 300_000 {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(pool.Origins))
	enabled := 0
	for index := range pool.Origins {
		origin := &pool.Origins[index]
		host, err := normalizeOriginHost(origin.Host)
		if err != nil || origin.Port < 1 || origin.Port > 65_535 || origin.Weight < 1 || origin.Weight > 100 {
			return ErrInvalidInput
		}
		origin.Host = host
		key := originCompatibilityEndpoint(*origin)
		if _, exists := seen[key]; exists {
			return ErrInvalidInput
		}
		seen[key] = struct{}{}
		if origin.Enabled {
			enabled++
		}
	}
	if enabled == 0 || pool.FailoverTries < 1 || pool.FailoverTries > enabled {
		return ErrInvalidInput
	}
	return normalizeOriginForwarding(pool)
}

// expandBackupOrigins turns the ordered backup list into level 1, 2, ...
// origins after the primaries (the console's one-address-per-line box).
func expandBackupOrigins(pool *OriginPool) error {
	if pool.BackupOrigins == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, origin := range pool.Origins {
		if origin.Level != 0 {
			return ErrInvalidInput
		}
		host, err := normalizeOriginHost(origin.Host)
		if err != nil {
			return ErrInvalidInput
		}
		seen[originCompatibilityEndpoint(Origin{Host: host, Port: origin.Port})] = struct{}{}
	}
	level := 0
	for _, raw := range pool.BackupOrigins {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		endpoint, host, port, err := originFromLegacy(raw)
		if err != nil {
			return ErrInvalidInput
		}
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		level++
		if level > MaxOriginLevel {
			return ErrInvalidInput
		}
		pool.Origins = append(pool.Origins, Origin{Host: host, Port: port, Weight: 1, Enabled: true, Level: level})
	}
	pool.BackupOrigins = nil
	return nil
}

// applyCreatePoolDefaults fills what a create's own origin pool left out:
// the owner's defaults first (applyPool), then for the origin timeouts the
// built-in pool's system defaults, so an omitted timeout means "default"
// instead of an invalid 0 (CU-SITE-02). Values the request names are kept.
func applyCreatePoolDefaults(defaults siteCreationUserDefaults, pool *OriginPool) {
	defaults.applyPool(pool, false)
	system := defaultOriginPool(nil)
	if pool.ConnectTimeoutMS == 0 {
		pool.ConnectTimeoutMS = system.ConnectTimeoutMS
	}
	if pool.ReadTimeoutMS == 0 {
		pool.ReadTimeoutMS = system.ReadTimeoutMS
	}
}

func normalizeCreateOriginPool(fields SiteFields, requested *OriginPool) (OriginPool, error) {
	if requested == nil {
		return defaultOriginPool(fields.originItems), nil
	}
	pool := *requested
	pool.Origins = append([]Origin(nil), requested.Origins...)
	if err := normalizeOriginPool(&pool); err != nil || len(pool.Origins) != len(fields.Origins) {
		return OriginPool{}, ErrInvalidInput
	}
	for index := range pool.Origins {
		if originCompatibilityEndpoint(pool.Origins[index]) != fields.Origins[index] {
			return OriginPool{}, ErrInvalidInput
		}
	}
	return pool, nil
}

func normalizeOriginHost(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "[]/\\?#@ \t\r\n") {
		return "", ErrInvalidInput
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return "", ErrInvalidInput
		}
		return address.String(), nil
	}
	return normalizeDomain(value, false)
}

func originFromLegacy(raw string) (string, string, int, error) {
	endpoint, host, err := normalizeOrigin(raw)
	if err != nil {
		return "", "", 0, err
	}
	host, err = normalizeOriginHost(host)
	if err != nil {
		return "", "", 0, err
	}
	port := 80
	if endpoint != host && endpoint != "["+host+"]" {
		_, rawPort, splitErr := net.SplitHostPort(endpoint)
		if splitErr != nil {
			return "", "", 0, ErrInvalidInput
		}
		port = mustAtoi(rawPort)
	}
	return originCompatibilityEndpoint(Origin{Host: host, Port: port}), host, port, nil
}

func originCompatibilityEndpoint(origin Origin) string {
	if origin.Port == 80 {
		return origin.Host
	}
	if address, err := netip.ParseAddr(origin.Host); err == nil && address.Is6() {
		return net.JoinHostPort(origin.Host, strconv.Itoa(origin.Port))
	}
	return origin.Host + ":" + strconv.Itoa(origin.Port)
}

func defaultOriginPool(origins []Origin) OriginPool {
	return OriginPool{
		Origins:          append([]Origin(nil), origins...),
		BalanceMethod:    BalanceRoundRobin,
		FailoverTries:    1,
		ConnectTimeoutMS: 3000,
		ReadTimeoutMS:    30000,

		KeepaliveEnabled:       &keepaliveEnabledDefault,
		KeepaliveIdleTimeoutMS: DefaultKeepaliveIdleTimeoutMS,
		RequestHost:            OriginRequestHost{Mode: OriginRequestHostVisitor},
		Scheme:                 OriginSchemeHTTP,
		HTTPPort:               80,
		HTTPSPort:              443,
		TLS:                    OriginTLS{Trust: OriginTrustSystem},
		WebSocket:              &OriginWebSocket{Enabled: true, AllowedOrigins: []string{}},
		TrustedProxyCIDRs:      []string{},
		OriginAuthEnabled:      &keepaliveEnabledDefault,
	}
}

// keepaliveEnabledDefault (true) is shared read-only by default pools
// (keepalive_enabled, origin_auth_enabled).
var keepaliveEnabledDefault = true

func validBalanceMethod(method string) bool {
	switch method {
	case BalanceRoundRobin, BalanceIPHash, BalanceURLHash, BalanceLeastConn, BalanceRandom, BalanceHash, BalanceSticky:
		return true
	default:
		return false
	}
}

func normalizeDomain(raw string, wildcard bool) (string, error) {
	domain := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if !wildcard && strings.HasPrefix(domain, "*.") {
		return "", ErrInvalidInput
	}
	prefix := ""
	if wildcard && strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
		if domain == "" {
			return "", ErrInvalidInput
		}
		prefix = "*."
	}
	base, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", ErrInvalidInput
	}
	base = strings.ToLower(base)
	domain = prefix + base
	if len(domain) > 253 || len(base) == 0 || strings.ContainsAny(base, "/:@ \\[]") {
		return "", ErrInvalidInput
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "", ErrInvalidInput
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidInput
			}
		}
	}
	if prefix != "" {
		if _, err := publicsuffix.EffectiveTLDPlusOne(base); err != nil {
			return "", ErrInvalidInput
		}
	}
	return domain, nil
}

func normalizeSiteDomains(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > 100 {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		domain, err := normalizeDomain(value, true)
		if err != nil {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	if len(result) == 0 {
		return nil, ErrInvalidInput
	}
	sort.Strings(result)
	return result, nil
}

func normalizePorts(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		port := strings.TrimSpace(raw)
		if !validPort(port) {
			return nil, ErrInvalidInput
		}
		port = strconv.Itoa(mustAtoi(port))
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result, nil
}

func normalizeOrigin(raw string) (string, string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "/?#@ \t\r\n") {
		return "", "", ErrInvalidInput
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), ip.String(), nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		if ip == nil || ip.To4() != nil {
			return "", "", ErrInvalidInput
		}
		return "[" + ip.String() + "]", ip.String(), nil
	}
	host := value
	port := ""
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host, port = parsedHost, parsedPort
	} else if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		host, port = parts[0], parts[1]
	}
	if port != "" && !validPort(port) {
		return "", "", ErrInvalidInput
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		host = ip.String()
		if port == "" {
			return host, host, nil
		}
		return net.JoinHostPort(host, strconv.Itoa(mustAtoi(port))), host, nil
	}
	normalizedHost, err := normalizeDomain(host, false)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	if port == "" {
		return normalizedHost, normalizedHost, nil
	}
	return normalizedHost + ":" + strconv.Itoa(mustAtoi(port)), normalizedHost, nil
}

func validPort(raw string) bool {
	port, err := strconv.Atoi(raw)
	return err == nil && port >= 1 && port <= 65535
}

func mustAtoi(raw string) int {
	value, _ := strconv.Atoi(raw)
	return value
}

func validStatus(status string) bool {
	switch status {
	case StatusActive, StatusDisabled, StatusPackageExpired, StatusTrafficExceeded,
		StatusLocked, StatusSyncing, StatusSyncFailed:
		return true
	default:
		return false
	}
}

func validSyncStatus(status string) bool {
	return status == SyncStatusSynced || status == SyncStatusPending || status == SyncStatusFailed
}

func validBatchAction(action string) bool {
	return action == BatchActionEnable || action == BatchActionDisable || action == BatchActionDelete ||
		action == BatchActionRegenerateCNAME || action == BatchActionSetProtocols
}

// validBatchProtocols: something to change, and "by preset" again excludes
// an explicit prefer value (as normalizeTLSProfile for a single site).
func validBatchProtocols(protocols BatchProtocols) bool {
	if protocols.TLSPreferServerCiphersReset && protocols.TLSPreferServerCiphers != nil {
		return false
	}
	return protocols.HTTP2Enabled != nil || protocols.HTTP3Enabled != nil ||
		protocols.TLSPreferServerCiphers != nil || protocols.TLSPreferServerCiphersReset
}

func validWriteMetadata(key, requestID string) bool {
	return len(key) >= 1 && len(key) <= 128 && len(requestID) >= 1 && len(requestID) <= 128
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

const maxSiteRuntimeV2ConfigBytes = 16 << 20

type siteRuntimeV2Config struct {
	Domains       []string                  `json:"domains"`
	Listeners     []siteRuntimeV2Listener   `json:"listeners"`
	OriginPools   []siteRuntimeV2OriginPool `json:"origin_pools"`
	DefaultPoolID string                    `json:"default_pool_id"`
	WebSocket     *bool                     `json:"websocket"`
	Range         *bool                     `json:"range"`
	L2            *siteRuntimeV2L2          `json:"l2"`
}

type siteRuntimeV2Listener struct {
	ID            string            `json:"id"`
	Position      int64             `json:"position"`
	AddressFamily string            `json:"address_family"`
	Port          int64             `json:"port"`
	Protocols     []string          `json:"protocols"`
	TLS           *siteRuntimeV2TLS `json:"tls,omitempty"`
}

type siteRuntimeV2TLS struct {
	CertificateVersionID string `json:"certificate_version_id"`
}

type siteRuntimeV2OriginPool struct {
	ID        string                `json:"id"`
	Position  int64                 `json:"position"`
	Kind      string                `json:"kind"`
	Algorithm string                `json:"algorithm"`
	Origins   []siteRuntimeV2Origin `json:"origins"`
	Retry     *siteRuntimeV2Retry   `json:"retry"`
}

type siteRuntimeV2Origin struct {
	ID       string  `json:"id"`
	Position int64   `json:"position"`
	Tier     string  `json:"tier"`
	Scheme   string  `json:"scheme"`
	Host     string  `json:"host"`
	Port     int64   `json:"port"`
	Weight   int64   `json:"weight"`
	NodeID   *string `json:"node_id,omitempty"`
	SNI      *string `json:"sni,omitempty"`
	TrustRef *string `json:"trust_ref,omitempty"`
}

type siteRuntimeV2Retry struct {
	Methods            []string `json:"methods"`
	BodylessOnly       *bool    `json:"bodyless_only"`
	ResponseNotStarted *bool    `json:"response_not_started"`
	RetryOn            []string `json:"retry_on"`
	MaxAttempts        int64    `json:"max_attempts"`
	ConnectTimeoutMS   int64    `json:"connect_timeout_ms"`
	ReadTimeoutMS      int64    `json:"read_timeout_ms"`
	TotalBudgetMS      int64    `json:"total_budget_ms"`
}

type siteRuntimeV2L2 struct {
	Enabled              *bool   `json:"enabled"`
	DirectFallbackPoolID *string `json:"direct_fallback_pool_id,omitempty"`
	ProbeIntervalMS      int64   `json:"probe_interval_ms"`
	FailureThreshold     int64   `json:"failure_threshold"`
	RecoveryThreshold    int64   `json:"recovery_threshold"`
	SingleHalfOpenProbe  *bool   `json:"single_half_open_probe"`
	MaxHops              int64   `json:"max_hops"`
}

func normalizeSiteRuntimeV2Config(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxSiteRuntimeV2ConfigBytes || !utf8.Valid(raw) {
		return nil, ErrInvalidInput
	}
	value, err := parseSiteRuntimeV2Config(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var config siteRuntimeV2Config
	if err := decoder.Decode(&config); err != nil || validateSiteRuntimeV2Config(config) != nil {
		return nil, ErrInvalidInput
	}
	return canonical, nil
}

func siteRuntimeV2MutationDigest(siteID uuid.UUID, expectedRevision int64, canonical []byte) ([32]byte, error) {
	if siteID == uuid.Nil || expectedRevision < 1 || expectedRevision > 1<<53-1 ||
		len(canonical) == 0 || len(canonical) > maxSiteRuntimeV2ConfigBytes || !utf8.Valid(canonical) || !json.Valid(canonical) {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.site-runtime-v2.mutation.v1\x00"))
	_, _ = hash.Write(siteID[:])
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(expectedRevision))
	_, _ = hash.Write(encoded[:])
	binary.BigEndian.PutUint64(encoded[:], uint64(len(canonical)))
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write(canonical)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func parseSiteRuntimeV2Config(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseSiteRuntimeV2Value(decoder)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidInput
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalidInput
	}
	return value, nil
}

func parseSiteRuntimeV2Value(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil || token == nil {
		return nil, ErrInvalidInput
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, ErrInvalidInput
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrInvalidInput
			}
			if _, duplicate := result[key]; duplicate {
				return nil, ErrInvalidInput
			}
			value, err := parseSiteRuntimeV2Value(decoder)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, ErrInvalidInput
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			value, err := parseSiteRuntimeV2Value(decoder)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, ErrInvalidInput
		}
		return result, nil
	default:
		return nil, ErrInvalidInput
	}
}

func validateSiteRuntimeV2Config(config siteRuntimeV2Config) error {
	if len(config.Domains) < 1 || len(config.Domains) > 100 || len(config.Listeners) < 1 || len(config.Listeners) > 32 ||
		len(config.OriginPools) < 1 || len(config.OriginPools) > 64 || !validSiteRuntimeV2Identifier(config.DefaultPoolID) ||
		config.WebSocket == nil || config.Range == nil || config.L2 == nil {
		return ErrInvalidInput
	}
	seenDomains := make(map[string]struct{}, len(config.Domains))
	for _, domain := range config.Domains {
		normalized, err := normalizeDomain(domain, true)
		if err != nil || normalized != domain {
			return ErrInvalidInput
		}
		if _, duplicate := seenDomains[domain]; duplicate {
			return ErrInvalidInput
		}
		seenDomains[domain] = struct{}{}
	}
	seenListeners := make(map[string]struct{}, len(config.Listeners))
	for index, listener := range config.Listeners {
		if !validSiteRuntimeV2Listener(listener, int64(index)) {
			return ErrInvalidInput
		}
		if _, duplicate := seenListeners[listener.ID]; duplicate {
			return ErrInvalidInput
		}
		seenListeners[listener.ID] = struct{}{}
	}
	pools := make(map[string]siteRuntimeV2OriginPool, len(config.OriginPools))
	for index, pool := range config.OriginPools {
		if !validSiteRuntimeV2Pool(pool, int64(index)) {
			return ErrInvalidInput
		}
		if _, duplicate := pools[pool.ID]; duplicate {
			return ErrInvalidInput
		}
		pools[pool.ID] = pool
	}
	defaultPool, exists := pools[config.DefaultPoolID]
	if !exists || !validSiteRuntimeV2L2(*config.L2, defaultPool, pools) {
		return ErrInvalidInput
	}
	return nil
}

func validSiteRuntimeV2Listener(listener siteRuntimeV2Listener, position int64) bool {
	if !validSiteRuntimeV2Identifier(listener.ID) || listener.Position != position || listener.Port < 1 || listener.Port > 65535 ||
		(listener.AddressFamily != "ipv4" && listener.AddressFamily != "ipv6" && listener.AddressFamily != "dual_stack") ||
		len(listener.Protocols) < 1 || len(listener.Protocols) > 3 {
		return false
	}
	protocolOrder := map[string]int{"http1": 1, "http2": 2, "http3": 3}
	previous := 0
	needsTLS := false
	for _, protocol := range listener.Protocols {
		current := protocolOrder[protocol]
		if current == 0 || current <= previous {
			return false
		}
		previous = current
		needsTLS = needsTLS || protocol == "http3"
	}
	if needsTLS && listener.TLS == nil {
		return false
	}
	return listener.TLS == nil || canonicalSiteRuntimeV2UUID(listener.TLS.CertificateVersionID)
}

func validSiteRuntimeV2Pool(pool siteRuntimeV2OriginPool, position int64) bool {
	if !validSiteRuntimeV2Identifier(pool.ID) || pool.Position != position ||
		(pool.Kind != "origin" && pool.Kind != "l2") || !validBalanceMethod(pool.Algorithm) ||
		len(pool.Origins) < 1 || len(pool.Origins) > 32 || pool.Retry == nil || !validSiteRuntimeV2Retry(*pool.Retry) {
		return false
	}
	seen := make(map[string]struct{}, len(pool.Origins))
	for index, origin := range pool.Origins {
		if !validSiteRuntimeV2Origin(origin, pool.Kind, int64(index)) {
			return false
		}
		if _, duplicate := seen[origin.ID]; duplicate {
			return false
		}
		seen[origin.ID] = struct{}{}
	}
	return true
}

func validSiteRuntimeV2Origin(origin siteRuntimeV2Origin, kind string, position int64) bool {
	if !validSiteRuntimeV2Identifier(origin.ID) || origin.Position != position || origin.Tier != kind ||
		(origin.Scheme != "http" && origin.Scheme != "https") || origin.Port < 1 || origin.Port > 65535 ||
		origin.Weight < 1 || origin.Weight > 100 {
		return false
	}
	normalizedHost, err := normalizeOriginHost(origin.Host)
	if err != nil || normalizedHost != origin.Host {
		return false
	}
	if origin.NodeID != nil && !canonicalSiteRuntimeV2UUID(*origin.NodeID) || kind == "l2" && origin.NodeID == nil {
		return false
	}
	if origin.SNI != nil {
		normalized, err := normalizeDomain(*origin.SNI, false)
		if err != nil || normalized != *origin.SNI {
			return false
		}
	}
	if origin.TrustRef != nil && !validSiteRuntimeV2Trust(*origin.TrustRef) {
		return false
	}
	return origin.Scheme != "https" || origin.SNI != nil && origin.TrustRef != nil
}

func validSiteRuntimeV2Retry(retry siteRuntimeV2Retry) bool {
	wantMethods := []string{"GET", "HEAD"}
	wantOutcomes := []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"}
	if len(retry.Methods) != len(wantMethods) || len(retry.RetryOn) != len(wantOutcomes) ||
		retry.BodylessOnly == nil || !*retry.BodylessOnly || retry.ResponseNotStarted == nil || !*retry.ResponseNotStarted ||
		retry.MaxAttempts < 1 || retry.MaxAttempts > 8 || retry.ConnectTimeoutMS < 10 || retry.ConnectTimeoutMS > 60000 ||
		retry.ReadTimeoutMS < 10 || retry.ReadTimeoutMS > 60000 || retry.TotalBudgetMS < 10 || retry.TotalBudgetMS > 120000 {
		return false
	}
	for index := range wantMethods {
		if retry.Methods[index] != wantMethods[index] {
			return false
		}
	}
	for index := range wantOutcomes {
		if retry.RetryOn[index] != wantOutcomes[index] {
			return false
		}
	}
	return true
}

func validSiteRuntimeV2L2(l2 siteRuntimeV2L2, defaultPool siteRuntimeV2OriginPool, pools map[string]siteRuntimeV2OriginPool) bool {
	if l2.Enabled == nil || l2.ProbeIntervalMS < 100 || l2.ProbeIntervalMS > 60000 ||
		l2.FailureThreshold < 1 || l2.FailureThreshold > 10 || l2.RecoveryThreshold < 1 || l2.RecoveryThreshold > 10 ||
		l2.SingleHalfOpenProbe == nil || !*l2.SingleHalfOpenProbe || l2.MaxHops != 1 {
		return false
	}
	if l2.DirectFallbackPoolID != nil && !validSiteRuntimeV2Identifier(*l2.DirectFallbackPoolID) {
		return false
	}
	if !*l2.Enabled {
		return l2.DirectFallbackPoolID == nil || pools[*l2.DirectFallbackPoolID].ID != ""
	}
	if defaultPool.Kind != "l2" || l2.DirectFallbackPoolID == nil || *l2.DirectFallbackPoolID == defaultPool.ID {
		return false
	}
	fallback, exists := pools[*l2.DirectFallbackPoolID]
	return exists && fallback.Kind == "origin" && len(fallback.Origins) > 0
}

func validSiteRuntimeV2Identifier(value string) bool {
	if len(value) < 1 || len(value) > 128 || !siteRuntimeV2AlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !siteRuntimeV2AlphaNumeric(value[index]) && value[index] != '.' && value[index] != '_' && value[index] != '-' {
			return false
		}
	}
	return true
}

func siteRuntimeV2AlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func canonicalSiteRuntimeV2UUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validSiteRuntimeV2Trust(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func redact(item *Site, scopeKind string) {
	item.ListenPorts = mergePorts(item.HTTPPorts, item.HTTPSPorts)
	if scopeKind == "tenant" {
		item.Owner = nil
		item.Region = nil
	}
}

func mergePorts(httpPorts, httpsPorts []string) []string {
	result := make([]string, 0, len(httpPorts)+len(httpsPorts))
	seen := make(map[string]struct{}, cap(result))
	for _, port := range append(append([]string{}, httpPorts...), httpsPorts...) {
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result
}
