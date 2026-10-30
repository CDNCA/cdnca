package dnsproviderremote

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ZoneApexResolver finds the domain a DNS account hosts for a CNAME zone
// (migration 473 dns_zones.provider_zone_apex). The zone may be a subdomain
// of the hosted domain (cdn.868yun.com under 868yun.com); provider APIs take
// only the hosted domain. Called when a zone is saved and, for zones saved
// before 473, on first use; never per request.
type ZoneApexResolver interface {
	ResolveZoneApex(ctx context.Context, providerType string, credentials map[string]string, zone string) (string, error)
}

func NewZoneApexResolver() ZoneApexResolver {
	return &providerReconcileRemote{adapter: newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)}
}

// zoneApexPageSize is the page size of every domain listing (Cloudflare
// caps /zones at 50).
const zoneApexPageSize = 50

// ResolveZoneApex lists the account's domains once and returns the longest
// one equal to zone or a dot-suffix of it. CodeZoneNotHosted: none matches.
// Custom HTTP and plugin providers have no domain list; their apex is zone.
func (remote *providerReconcileRemote) ResolveZoneApex(ctx context.Context, providerType string,
	credentials map[string]string, zone string) (string, error) {
	if remote == nil || remote.adapter == nil || ctx == nil {
		return "", failure(CodeSourceUnavailable, true)
	}
	zone = canonicalDNSName(zone, false)
	providerType = strings.TrimSpace(providerType)
	if zone == "" || credentials == nil {
		return "", failure(CodeInvalidInput, false)
	}
	if !supportedProvider(providerType) {
		return "", failure(CodeUnsupported, false)
	}
	if err := validateCredentials(providerType, credentials); err != nil {
		return "", err
	}
	if providerType == providerCustomHTTP || providerType == providerPlugin {
		return zone, nil
	}
	config := ProviderConfig{ProviderType: providerType, ZoneName: zone, Credentials: credentials}
	domains, err := remote.hostedDomains(ctx, config)
	if err != nil {
		return "", err
	}
	return longestHostedApex(zone, domains)
}

// longestHostedApex picks the most specific hosted domain covering zone.
func longestHostedApex(zone string, domains []string) (string, error) {
	best := ""
	for _, raw := range domains {
		domain := canonicalDNSName(raw, false)
		if zoneWithinApex(zone, domain) && len(domain) > len(best) {
			best = domain
		}
	}
	if best == "" {
		return "", failure(CodeZoneNotHosted, false)
	}
	return best, nil
}

// hostedDomains walks the provider's domain list page by page until the
// reported total (or an empty / short page) is reached, at most
// recoveryMaxPages pages.
func (remote *providerReconcileRemote) hostedDomains(ctx context.Context, config ProviderConfig) ([]string, error) {
	adapter := remote.adapter
	var fetch func(page int) (names []string, total int, err error)
	switch config.ProviderType {
	case providerCloudflare:
		provider := &cloudflareProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(zoneApexPageSize)}}
			envelope, err := provider.request(ctx, http.MethodGet, "/zones?"+query.Encode(), config.Credentials["api_token"], nil)
			if err != nil {
				return nil, 0, err
			}
			var zones []struct {
				Name string `json:"name"`
			}
			if decodeJSON(envelope.Result, &zones) != nil || envelope.ResultInfo == nil || envelope.ResultInfo.TotalCount == nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(zones))
			for _, zone := range zones {
				names = append(names, zone.Name)
			}
			return names, *envelope.ResultInfo.TotalCount, nil
		}
	case providerAliyun:
		provider := &aliyunProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			body, err := provider.request(ctx, config, map[string]string{"Action": "DescribeDomains",
				"PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(zoneApexPageSize)})
			if err != nil {
				return nil, 0, err
			}
			var result struct {
				TotalCount *int `json:"TotalCount"`
				Domains    struct {
					Domain []struct {
						DomainName string `json:"DomainName"`
					} `json:"Domain"`
				} `json:"Domains"`
			}
			if decodeJSON(body, &result) != nil || result.TotalCount == nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(result.Domains.Domain))
			for _, domain := range result.Domains.Domain {
				names = append(names, domain.DomainName)
			}
			return names, *result.TotalCount, nil
		}
	case providerHuawei:
		provider := &huaweiProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			query := url.Values{"type": {"public"}, "limit": {strconv.Itoa(zoneApexPageSize)},
				"offset": {strconv.Itoa((page - 1) * zoneApexPageSize)}}
			response, err := provider.request(ctx, config, http.MethodGet, "/v2/zones", query.Encode(), nil)
			if err != nil {
				return nil, 0, err
			}
			var envelope struct {
				Zones []struct {
					Name string `json:"name"`
				} `json:"zones"`
				Metadata *struct {
					TotalCount *int `json:"total_count"`
				} `json:"metadata"`
			}
			if response.status != http.StatusOK || decodeJSON(response.body, &envelope) != nil ||
				envelope.Metadata == nil || envelope.Metadata.TotalCount == nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(envelope.Zones))
			for _, zone := range envelope.Zones {
				names = append(names, zone.Name)
			}
			return names, *envelope.Metadata.TotalCount, nil
		}
	case providerDNSPodCN:
		provider := &dnsPodProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			envelope, err := provider.request(ctx, config, dnsPodDomainListPath, url.Values{
				"type": {"all"}, "offset": {strconv.Itoa((page - 1) * zoneApexPageSize)},
				"length": {strconv.Itoa(zoneApexPageSize)}})
			if isCode(err, CodeZoneNotHosted) {
				return nil, 0, nil // code 9: the account hosts no domain
			}
			if err != nil {
				return nil, 0, err
			}
			var domains []struct {
				Name string `json:"name"`
			}
			var info struct {
				Total stringID `json:"domain_total"`
			}
			if decodeJSON(envelope.Domains, &domains) != nil || decodeJSON(envelope.Info, &info) != nil {
				return nil, 0, malformedProviderResponse()
			}
			total, err := strconv.Atoi(string(info.Total))
			if err != nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(domains))
			for _, domain := range domains {
				names = append(names, domain.Name)
			}
			return names, total, nil
		}
	case providerDNSCom:
		provider := &dnsComProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			envelope, err := provider.request(ctx, config, "/api/domain/lists/", map[string]string{
				"page": strconv.Itoa(page), "paginate": strconv.Itoa(zoneApexPageSize)})
			if err != nil {
				return nil, 0, err
			}
			var list struct {
				Total *int `json:"total"`
				Data  []struct {
					Domain string `json:"domain"`
				} `json:"data"`
			}
			if decodeJSON(envelope.Data, &list) != nil || list.Total == nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(list.Data))
			for _, domain := range list.Data {
				names = append(names, domain.Domain)
			}
			return names, *list.Total, nil
		}
	case providerDNSLA:
		provider := &dnsLAProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			query := url.Values{"pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(zoneApexPageSize)}}
			envelope, err := provider.request(ctx, config, http.MethodGet, "/api/domainList?"+query.Encode(), nil)
			if err != nil {
				return nil, 0, err
			}
			var list struct {
				Total   *int `json:"total"`
				Results []struct {
					Domain string `json:"domain"`
				} `json:"results"`
			}
			if decodeJSON(envelope.Data, &list) != nil || list.Total == nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(list.Results))
			for _, domain := range list.Results {
				names = append(names, domain.Domain)
			}
			return names, *list.Total, nil
		}
	case providerNameCom:
		provider := &nameComProvider{adapter: adapter}
		fetch = func(page int) ([]string, int, error) {
			query := url.Values{"perPage": {strconv.Itoa(zoneApexPageSize)}, "page": {strconv.Itoa(page)}}
			response, err := provider.request(ctx, config, http.MethodGet, "/core/v1/domains?"+query.Encode(), nil)
			if err != nil {
				return nil, 0, err
			}
			var body struct {
				Domains []struct {
					DomainName string `json:"domainName"`
				} `json:"domains"`
				NextPage *int `json:"nextPage"`
			}
			if response.status != http.StatusOK || decodeJSON(response.body, &body) != nil {
				return nil, 0, malformedProviderResponse()
			}
			names := make([]string, 0, len(body.Domains))
			for _, domain := range body.Domains {
				names = append(names, domain.DomainName)
			}
			// name.com reports nextPage instead of a total.
			total := (page-1)*zoneApexPageSize + len(names)
			if body.NextPage != nil {
				total += zoneApexPageSize
			}
			return names, total, nil
		}
	default:
		return nil, failure(CodeUnsupported, false)
	}
	result := make([]string, 0, zoneApexPageSize)
	for page := 1; page <= recoveryMaxPages; page++ {
		names, total, err := fetch(page)
		if err != nil {
			return nil, err
		}
		if total < 0 || len(names) > zoneApexPageSize {
			return nil, malformedProviderResponse()
		}
		result = append(result, names...)
		if len(names) < zoneApexPageSize || len(result) >= total {
			return result, nil
		}
	}
	return nil, malformedProviderResponse()
}
