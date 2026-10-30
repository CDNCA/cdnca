package dnsproviderremote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/google/uuid"
)

const (
	providerCloudflare = "cloudflare"
	providerAliyun     = "aliyun"
	providerHuawei     = "huawei"
	providerDNSPodCN   = "dnspod_cn"
	providerDNSCom     = "dns_com"
	providerDNSLA      = "dns_la"
	providerCustomHTTP = "custom_http"
	// providerPlugin is a third-party DNS provider plugin (PA-22).
	providerPlugin = "plugin"

	requestTimeout = 5 * time.Second
)

type Adapter struct {
	source    Source
	keyring   *HandleKeyring
	http      *boundedHTTPClient
	endpoints endpointSet
	now       func() time.Time
	nonce     func() string
	ready     bool
	// customHTTP overrides the custom HTTP provider's address policy and TLS
	// roots (tests only; nil in production).
	customHTTP *dnscustomhttp.Options
	// dnsComViews caches DNS.COM getView line IDs per account and domain.
	dnsComViews *dnsComViewCache
}

var _ acmeworker.DNS01Provider = (*Adapter)(nil)

func New(source Source) *Adapter {
	return newAdapter(source, nil, nil, productionEndpoints(), requestTimeout, time.Now, randomNonce)
}

func Open(ctx context.Context, source any, keyring *HandleKeyring) (*Adapter, error) {
	if ctx == nil {
		return nil, failure(CodeInvalidInput, false)
	}
	references, ok := source.(StartupSource)
	if !ok {
		return nil, failure(CodeSourceUnavailable, true)
	}
	adapter := newAdapter(references, keyring, nil, productionEndpoints(), requestTimeout, time.Now, randomNonce)
	if err := adapter.Ready(); err != nil {
		return nil, err
	}
	challenges, err := references.OutstandingRemoteTXTHandles(ctx)
	if err != nil {
		return nil, sourceFailure(ctx)
	}
	for _, challenge := range challenges {
		if err := adapter.validateOutstandingChallenge(ctx, challenge); err != nil {
			switch ErrorCodeOf(err) {
			case CodeUnsupported, CodeCancelled, CodeTimeout:
				return nil, err
			default:
				return nil, failure(CodeSourceUnavailable, false)
			}
		}
	}
	return adapter, nil
}

func (a *Adapter) validateOutstandingChallenge(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) error {
	if err := validateOutstandingChallengeIdentity(challenge); err != nil {
		return err
	}
	if challenge.TXTHandle.ProviderRef != challenge.ProviderRef {
		return failure(CodeRecordMismatch, false)
	}
	switch {
	case strings.HasPrefix(challenge.TXTHandle.RecordRef, handlePrefix):
		_, _, _, err := a.resolveHandle(ctx, challenge)
		return err
	case strings.HasPrefix(challenge.TXTHandle.RecordRef, legacyHandlePrefix):
		_, _, _, err := a.resolveLegacyHandle(ctx, challenge)
		return err
	default:
		return failure(CodeInvalidInput, false)
	}
}

func validateOutstandingChallengeIdentity(challenge acmeworker.ChallengeIdentity) error {
	if _, err := validateChallenge(challenge); err != nil {
		return err
	}
	identifier := canonicalDNSName(challenge.Identifier, false)
	if identifier == "" || identifier != challenge.Identifier ||
		challenge.RecordName != "_acme-challenge."+identifier+"." ||
		!validHTTPSReference(challenge.AuthorizationURL) || !validHTTPSReference(challenge.ChallengeURL) ||
		!validReference(challenge.Token, 512) || strings.IndexFunc(challenge.Token, unicode.IsSpace) >= 0 {
		return failure(CodeInvalidInput, false)
	}
	return nil
}

func validHTTPSReference(value string) bool {
	if !validReference(value, 4096) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func newAdapter(
	source Source,
	keyring *HandleKeyring,
	transport http.RoundTripper,
	endpoints endpointSet,
	timeout time.Duration,
	now func() time.Time,
	nonce func() string,
) *Adapter {
	if timeout <= 0 {
		timeout = requestTimeout
	}
	if now == nil {
		now = time.Now
	}
	if nonce == nil {
		nonce = randomNonce
	}
	return &Adapter{
		source: source, keyring: keyring, http: newBoundedHTTPClient(transport, timeout),
		endpoints: endpoints, now: now, nonce: nonce, dnsComViews: &dnsComViewCache{},
		ready: source != nil && keyring != nil,
	}
}

func (a *Adapter) Ready() error {
	if a == nil || !a.ready || a.http == nil {
		return failure(CodeSourceUnavailable, true)
	}
	return nil
}

func (a *Adapter) PresentTXT(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) (acmeworker.RemoteTXTHandle, error) {
	if ctx == nil {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidInput, false)
	}
	owner, err := validateChallenge(challenge)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	providerID, _ := uuid.Parse(challenge.ProviderRef)
	config, relative, err := a.resolve(ctx, ProviderLookup{
		OperationID: challenge.OperationID,
		TenantID:    challenge.TenantID, ScopeID: challenge.ScopeID, TenantScopeID: challenge.ScopeID,
		ProviderID: providerID, ZoneID: challenge.ZoneID, OwnerName: owner,
	})
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	defer clearProviderConfig(&config)
	provider, err := a.provider(config.ProviderType)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	lease, err := a.acquireProviderCredentialLease(ctx, config, owner)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	created, err := provider.present(ctx, config, owner, relative, challenge.ExactValue)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, lease.finish(ctx, a, config, owner, err)
	}
	handle, err := encodeHandle(challenge, config, created, a.keyring)
	if outcome := lease.finish(ctx, a, config, owner, err); outcome != nil {
		return acmeworker.RemoteTXTHandle{}, outcome
	}
	return handle, nil
}

// RecoverTXT resolves the unique exact TXT record after a provider create
// response was lost. It performs lookup only and never creates DNS state.
func (a *Adapter) RecoverTXT(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) (acmeworker.RemoteTXTHandle, bool, error) {
	if ctx == nil {
		return acmeworker.RemoteTXTHandle{}, false, failure(CodeInvalidInput, false)
	}
	owner, err := validateChallenge(challenge)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, false, err
	}
	providerID, _ := uuid.Parse(challenge.ProviderRef)
	config, relative, err := a.resolve(ctx, ProviderLookup{
		OperationID: challenge.OperationID,
		TenantID:    challenge.TenantID, ScopeID: challenge.ScopeID, TenantScopeID: challenge.ScopeID,
		ProviderID: providerID, ZoneID: challenge.ZoneID, OwnerName: owner,
	})
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, false, err
	}
	defer clearProviderConfig(&config)
	provider, err := a.provider(config.ProviderType)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, false, err
	}
	lease, err := a.acquireProviderCredentialLease(ctx, config, owner)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, false, err
	}
	matches, err := provider.lookupTXT(ctx, config, owner, relative, challenge.ExactValue)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, false, lease.finish(ctx, a, config, owner, err)
	}
	if len(matches) == 0 {
		return acmeworker.RemoteTXTHandle{}, false, lease.finish(ctx, a, config, owner, nil)
	}
	if len(matches) != 1 {
		return acmeworker.RemoteTXTHandle{}, false, lease.finish(
			ctx, a, config, owner, failure(CodeRecordMismatch, false),
		)
	}
	handle, err := encodeHandle(challenge, config, matches[0], a.keyring)
	if outcome := lease.finish(ctx, a, config, owner, err); outcome != nil {
		return acmeworker.RemoteTXTHandle{}, false, outcome
	}
	return handle, true, nil
}

func (a *Adapter) ObserveTXT(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) error {
	if ctx == nil {
		return failure(CodeInvalidInput, false)
	}
	if !strings.HasPrefix(challenge.TXTHandle.RecordRef, handlePrefix) {
		return failure(CodeInvalidInput, false)
	}
	decoded, config, provider, err := a.resolveHandle(ctx, challenge)
	if err != nil {
		return err
	}
	defer clearProviderConfig(&config)
	lease, err := a.acquireProviderCredentialLease(ctx, config, challenge.RecordName)
	if err != nil {
		return err
	}
	record, exists, err := provider.get(ctx, config, decoded, challenge.ExactValue)
	if err != nil {
		return lease.finish(ctx, a, config, challenge.RecordName, err)
	}
	if !exists {
		return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeRecordNotFound, true))
	}
	if !matchesRecord(record, decoded, challenge.ExactValue) {
		return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeRecordMismatch, false))
	}
	return lease.finish(ctx, a, config, challenge.RecordName, nil)
}

func (a *Adapter) DeleteTXT(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) error {
	if ctx == nil {
		return failure(CodeInvalidInput, false)
	}
	var (
		decoded  recordHandle
		config   ProviderConfig
		provider remoteProvider
		err      error
	)
	if strings.HasPrefix(challenge.TXTHandle.RecordRef, handlePrefix) {
		decoded, config, provider, err = a.resolveHandle(ctx, challenge)
	} else if strings.HasPrefix(challenge.TXTHandle.RecordRef, legacyHandlePrefix) {
		decoded, config, provider, err = a.resolveLegacyHandle(ctx, challenge)
	} else {
		return failure(CodeInvalidInput, false)
	}
	if err != nil {
		return err
	}
	defer clearProviderConfig(&config)
	lease, err := a.acquireProviderCredentialLease(ctx, config, challenge.RecordName)
	if err != nil {
		return err
	}
	record, exists, err := provider.get(ctx, config, decoded, challenge.ExactValue)
	if err != nil {
		if isCode(err, CodeRecordNotFound) {
			return lease.finish(ctx, a, config, challenge.RecordName, nil)
		}
		return lease.finish(ctx, a, config, challenge.RecordName, err)
	}
	if !exists {
		return lease.finish(ctx, a, config, challenge.RecordName, nil)
	}
	if !matchesRecord(record, decoded, challenge.ExactValue) {
		return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeRecordMismatch, false))
	}
	if deleteErr := provider.delete(ctx, config, decoded); deleteErr != nil {
		var remoteErr *Error
		if !errors.As(deleteErr, &remoteErr) || !remoteErr.Temporary || ctx.Err() != nil {
			return lease.finish(ctx, a, config, challenge.RecordName, deleteErr)
		}
		record, exists, err = provider.get(ctx, config, decoded, challenge.ExactValue)
		if err != nil {
			if isCode(err, CodeRecordNotFound) {
				return lease.finish(ctx, a, config, challenge.RecordName, nil)
			}
			return lease.finish(ctx, a, config, challenge.RecordName, err)
		}
		if !exists {
			return lease.finish(ctx, a, config, challenge.RecordName, nil)
		}
		if !matchesRecord(record, decoded, challenge.ExactValue) {
			return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeRecordMismatch, false))
		}
		return lease.finish(ctx, a, config, challenge.RecordName, deleteErr)
	}
	if err := lease.fence(ctx, a, config, challenge.RecordName); err != nil {
		return err
	}
	if huawei, ok := provider.(*huaweiProvider); ok {
		return lease.finish(ctx, a, config, challenge.RecordName,
			confirmHuaweiDeleteAbsence(ctx, config, huawei, decoded, challenge.ExactValue))
	}
	if dnsla, ok := provider.(*dnsLAProvider); ok {
		return lease.finish(ctx, a, config, challenge.RecordName,
			confirmDNSLADeleteAbsence(ctx, config, dnsla, decoded, challenge.ExactValue))
	}
	record, exists, err = provider.get(ctx, config, decoded, challenge.ExactValue)
	if err != nil {
		if isCode(err, CodeRecordNotFound) {
			return lease.finish(ctx, a, config, challenge.RecordName, nil)
		}
		return lease.finish(ctx, a, config, challenge.RecordName, err)
	}
	if !exists {
		return lease.finish(ctx, a, config, challenge.RecordName, nil)
	}
	if !matchesRecord(record, decoded, challenge.ExactValue) {
		return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeRecordMismatch, false))
	}
	return lease.finish(ctx, a, config, challenge.RecordName, failure(CodeUnavailable, true))
}

func confirmHuaweiDeleteAbsence(
	ctx context.Context,
	config ProviderConfig,
	provider *huaweiProvider,
	handle recordHandle,
	exactValue string,
) error {
	remoteID, _, expectedDigest, legacy, err := decodeHuaweiRecordID(handle.RecordID)
	if err != nil {
		return err
	}
	listed, listedValues, exists, err := provider.recordSetByOwner(ctx, config, handle.ZoneID, handle.Owner)
	if err != nil {
		return err
	}
	if exists {
		if listed.ID != remoteID {
			return failure(CodeRecordMismatch, false)
		}
		if legacy {
			if len(listedValues) != 1 || listedValues[0] != exactValue {
				return failure(CodeRecordMismatch, false)
			}
		} else if !huaweiValuesDigestMatches(expectedDigest, listedValues) {
			return failure(CodeRecordMismatch, false)
		}
	}

	path := "/v2.1/zones/" + url.PathEscape(handle.ZoneID) + "/recordsets/" + url.PathEscape(remoteID)
	response, err := provider.requestAllowNotFound(ctx, config, http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	if response.status == http.StatusNotFound {
		if exists {
			return failure(CodeUnavailable, true)
		}
		return nil
	}
	if response.status != http.StatusOK {
		return malformedProviderResponse()
	}
	var record huaweiRecordSet
	if err := decodeJSON(response.body, &record); err != nil {
		return malformedProviderResponse()
	}
	values, valid := huaweiTXTValues(record.Records)
	if record.ID != remoteID || record.ZoneID != handle.ZoneID ||
		canonicalDNSName(record.Name, true) != handle.Owner || record.Type != "TXT" {
		return failure(CodeRecordMismatch, false)
	}
	if !valid {
		return failure(CodeRecordMismatch, false)
	}
	if legacy {
		if len(values) != 1 || values[0] != exactValue {
			return failure(CodeRecordMismatch, false)
		}
	} else if !huaweiValuesDigestMatches(expectedDigest, values) {
		return failure(CodeRecordMismatch, false)
	}
	for _, value := range values {
		if value == exactValue {
			return failure(CodeUnavailable, true)
		}
	}
	return failure(CodeRecordMismatch, false)
}

func confirmDNSLADeleteAbsence(
	ctx context.Context,
	config ProviderConfig,
	provider *dnsLAProvider,
	handle recordHandle,
	exactValue string,
) error {
	_, relative, err := ownerAndRelative(handle.Owner, handle.Zone)
	if err != nil {
		return malformedProviderResponse()
	}
	query := url.Values{
		"pageIndex": {"1"}, "pageSize": {strconv.Itoa(dnsLARecordPageSize)},
		"domainId": {handle.ZoneID}, "type": {"16"}, "host": {relative},
	}
	envelope, err := provider.request(ctx, config, http.MethodGet, "/api/recordList?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	var page struct {
		Total   *int64        `json:"total"`
		Results []dnsLARecord `json:"results"`
	}
	if err := decodeJSON(envelope.Data, &page); err != nil || page.Total == nil || *page.Total < 0 ||
		len(page.Results) > dnsLARecordPageSize || int64(len(page.Results)) != *page.Total {
		return malformedProviderResponse()
	}
	seen := make(map[string]struct{}, len(page.Results))
	var targetValue string
	targetFound := false
	for _, record := range page.Results {
		recordID := string(record.ID)
		if !validReference(recordID, 256) || string(record.DomainID) != handle.ZoneID ||
			ownerFromRelative(record.Host, handle.Zone) != handle.Owner || record.Type != 16 ||
			!validExactValue(record.Data) {
			if recordID == handle.RecordID {
				return failure(CodeRecordMismatch, false)
			}
			return malformedProviderResponse()
		}
		if _, duplicate := seen[recordID]; duplicate {
			return failure(CodeRecordMismatch, false)
		}
		seen[recordID] = struct{}{}
		if recordID != handle.RecordID {
			continue
		}
		targetFound = true
		targetValue = record.Data
	}
	if !targetFound {
		return nil
	}
	if targetValue == exactValue {
		return failure(CodeUnavailable, true)
	}
	return failure(CodeRecordMismatch, false)
}

func (a *Adapter) resolve(ctx context.Context, lookup ProviderLookup) (ProviderConfig, string, error) {
	if err := a.Ready(); err != nil {
		return ProviderConfig{}, "", failure(CodeSourceUnavailable, true)
	}
	config, err := a.source.Resolve(ctx, lookup)
	if err != nil {
		clearProviderConfig(&config)
		return ProviderConfig{}, "", sourceFailure(ctx)
	}
	validated, relative, err := validateConfig(config, lookup.OwnerName)
	if err != nil {
		clearProviderConfig(&config)
		return ProviderConfig{}, "", err
	}
	if validated.TenantID != lookup.TenantID || validated.ScopeID != lookup.ScopeID ||
		validated.TenantScopeID != lookup.ScopeID || validated.ProviderID != lookup.ProviderID ||
		(validated.OperationID != "" && validated.OperationID != lookup.OperationID) ||
		(lookup.ZoneID != uuid.Nil && validated.ZoneID != lookup.ZoneID) {
		clearProviderConfig(&validated)
		return ProviderConfig{}, "", failure(CodeRecordMismatch, false)
	}
	if validated.OperationID == "" {
		validated.OperationID = lookup.OperationID
	}
	return validated, relative, nil
}

func (a *Adapter) checkCredentialFence(ctx context.Context, config ProviderConfig, owner string) error {
	if config.CredentialRevoked {
		return failure(CodeUnavailable, true)
	}
	if config.CredentialVersion == 0 {
		return nil
	}
	fenced, ok := a.source.(credentialFenceSource)
	if !ok {
		return failure(CodeUnavailable, true)
	}
	err := fenced.CheckCredentialFence(ctx, ProviderLookup{
		OperationID: config.OperationID, ActorUserID: config.ActorUserID,
		TenantID: config.TenantID, ScopeID: config.ScopeID, TenantScopeID: config.ScopeID,
		ProviderID: config.ProviderID,
		ZoneID:     config.ZoneID, OwnerName: owner,
	}, config.CredentialVersion)
	if err != nil {
		return failure(CodeUnavailable, true)
	}
	return nil
}

type activeProviderCredentialLease struct {
	release       ProviderCredentialLease
	authoritative bool
}

func (a *Adapter) acquireProviderCredentialLease(
	ctx context.Context,
	config ProviderConfig,
	owner string,
) (*activeProviderCredentialLease, error) {
	if config.CredentialRevoked {
		return nil, failure(CodeUnavailable, true)
	}
	lookup := ProviderLookup{
		OperationID: config.OperationID, ActorUserID: config.ActorUserID,
		TenantID: config.TenantID, ScopeID: config.ScopeID, TenantScopeID: config.ScopeID,
		ProviderID: config.ProviderID, ZoneID: config.ZoneID, OwnerName: owner,
	}
	if config.CredentialVersion > 0 {
		if authority, ok := a.source.(ProviderCredentialLeaseAuthority); ok {
			release, err := authority.AcquireProviderCredentialLease(ctx, lookup, config.CredentialVersion)
			if err != nil || release == nil {
				return nil, failure(CodeUnavailable, true)
			}
			return &activeProviderCredentialLease{release: release, authoritative: true}, nil
		}
	}
	if err := a.checkCredentialFence(ctx, config, owner); err != nil {
		return nil, err
	}
	return &activeProviderCredentialLease{}, nil
}

func (lease *activeProviderCredentialLease) fence(
	ctx context.Context,
	adapter *Adapter,
	config ProviderConfig,
	owner string,
) error {
	if lease != nil && lease.authoritative {
		return nil
	}
	return adapter.checkCredentialFence(ctx, config, owner)
}

func (lease *activeProviderCredentialLease) finish(
	ctx context.Context,
	adapter *Adapter,
	config ProviderConfig,
	owner string,
	outcome error,
) error {
	if lease == nil {
		return failure(CodeUnavailable, true)
	}
	if lease.release != nil {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := lease.release(releaseCtx)
		cancel()
		lease.release = nil
		if err != nil {
			return failure(CodeUnavailable, true)
		}
	}
	if lease.authoritative {
		return outcome
	}
	return adapter.finishCredentialOutcome(ctx, config, owner, outcome)
}

func (a *Adapter) finishCredentialOutcome(
	ctx context.Context,
	config ProviderConfig,
	owner string,
	outcome error,
) error {
	if err := a.checkCredentialFence(ctx, config, owner); err != nil {
		return err
	}
	return outcome
}

func (a *Adapter) resolveHandle(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) (recordHandle, ProviderConfig, remoteProvider, error) {
	if challenge.TXTHandle.ProviderRef != challenge.ProviderRef {
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeRecordMismatch, false)
	}
	payload, err := decodeHandle(challenge.TXTHandle.RecordRef, a.keyring)
	if err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	if err := bindHandlePayload(payload, challenge); err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	if !supportedProvider(payload.ProviderType) {
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeUnsupported, false)
	}
	providerID, _ := uuid.Parse(payload.ProviderID)
	zoneID, _ := uuid.Parse(payload.ManagedZoneID)
	owner, _ := validateChallenge(challenge)
	config, _, err := a.resolve(ctx, ProviderLookup{
		OperationID: challenge.OperationID,
		TenantID:    challenge.TenantID, ScopeID: challenge.ScopeID, TenantScopeID: challenge.ScopeID,
		ProviderID: providerID, ZoneID: zoneID, OwnerName: owner,
	})
	if err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	if config.ProviderType != payload.ProviderType || !digestMatches(payload.ZoneNameSHA256, config.ZoneName) {
		clearProviderConfig(&config)
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeRecordMismatch, false)
	}
	provider, err := a.provider(config.ProviderType)
	if err != nil {
		clearProviderConfig(&config)
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	return recordHandle{
		Version: 1, Provider: payload.ProviderType, Zone: config.ZoneName,
		ZoneID: payload.RemoteZoneID, RecordID: payload.RemoteRecordID, Owner: owner,
	}, config, provider, nil
}

func (a *Adapter) resolveLegacyHandle(
	ctx context.Context,
	challenge acmeworker.ChallengeIdentity,
) (recordHandle, ProviderConfig, remoteProvider, error) {
	if challenge.TXTHandle.ProviderRef != challenge.ProviderRef {
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeRecordMismatch, false)
	}
	owner, err := validateChallenge(challenge)
	if err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	decoded, err := decodeLegacyHandle(challenge.TXTHandle)
	if err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	if !supportedProvider(decoded.Provider) {
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeUnsupported, false)
	}
	if decoded.Owner != owner {
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeRecordMismatch, false)
	}
	providerID, _ := uuid.Parse(challenge.ProviderRef)
	config, _, err := a.resolve(ctx, ProviderLookup{
		OperationID: challenge.OperationID,
		TenantID:    challenge.TenantID, ScopeID: challenge.ScopeID, TenantScopeID: challenge.ScopeID,
		ProviderID: providerID, ZoneID: challenge.ZoneID, OwnerName: owner,
	})
	if err != nil {
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	if config.ProviderType != decoded.Provider || config.ZoneName != decoded.Zone {
		clearProviderConfig(&config)
		return recordHandle{}, ProviderConfig{}, nil, failure(CodeRecordMismatch, false)
	}
	provider, err := a.provider(config.ProviderType)
	if err != nil {
		clearProviderConfig(&config)
		return recordHandle{}, ProviderConfig{}, nil, err
	}
	return decoded, config, provider, nil
}

func (a *Adapter) provider(providerType string) (remoteProvider, error) {
	switch providerType {
	case providerCloudflare:
		return &cloudflareProvider{adapter: a}, nil
	case providerAliyun:
		return &aliyunProvider{adapter: a}, nil
	case providerHuawei:
		return &huaweiProvider{adapter: a}, nil
	case providerDNSPodCN:
		return &dnsPodProvider{adapter: a}, nil
	case providerDNSCom:
		return &dnsComProvider{adapter: a}, nil
	case providerDNSLA:
		return &dnsLAProvider{adapter: a}, nil
	case providerNameCom:
		return &nameComProvider{adapter: a}, nil
	case providerCustomHTTP, providerPlugin:
		return newRecordProvider(a, providerType), nil
	default:
		return nil, failure(CodeUnsupported, false)
	}
}

func randomNonce() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(value[:])
}

func validHuaweiRegion(region string) bool {
	return region == "cn-north-4" || region == "ap-southeast-3"
}

func isCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}
