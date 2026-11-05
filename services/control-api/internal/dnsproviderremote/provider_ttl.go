package dnsproviderremote

import "github.com/cdnca/cdnca/services/control-api/internal/dnscheck"

// providerTTLFloors are the provider TTL floors beyond name.com's
// (ProviderMinTTL); requested TTLs below them are written at the floor and
// reported as ttl_clamped.
//   - DNSPod.com: 600 on the Free plan ("TTL Description",
//     https://docs.dnspod.com/dns/help-ttl/, read 2026-11-05; paid plans go
//     lower, the adapter does not read the domain grade).
//   - GoDaddy: "The minimum TTL is 600 seconds"
//     (https://developer.godaddy.com/en/docs/api-users/troubleshoot/dns, read 2026-11-05).
//   - Namesilo: the API reference states no floor; 3600 is the lower bound
//     go-acme/lego documents for NAMESILO_TTL ("[3600, 2592000]") and
//     Namesilo's own recommended value (read 2026-11-05).
var providerTTLFloors = map[string]uint32{
	providerClouDNS:   ClouDNSMinTTL,
	providerNamecheap: NamecheapMinTTL,
	providerJDCloud:   JDCloudMinTTL,
	providerDNSPodCom: 600,
	providerGoDaddy:   600,
	providerNamesilo:  3600,
}

// providerWrittenTTL is the TTL the provider stores for a TTL at or above its
// floor: ClouDNS takes only a fixed list of values (rounded down, so failover
// is never slower than asked); Namecheap takes at most 60000 seconds.
func providerWrittenTTL(providerType string, ttl uint32) uint32 {
	switch providerType {
	case providerClouDNS:
		return clouDNSAllowedTTL(ttl)
	case providerNamecheap:
		return min(ttl, NamecheapMaxTTL)
	}
	return ttl
}

// providerOperation is the operation as the provider stores it (TTLs passed
// through EffectiveTTL), so lookups compare records with what was written.
func providerOperation(providerType string, operation dnscheck.ProviderOperation) dnscheck.ProviderOperation {
	operation.TTL, _ = EffectiveTTL(providerType, operation.TTL)
	if operation.Action == dnscheck.ProviderUpdate {
		operation.PreviousTTL, _ = EffectiveTTL(providerType, operation.PreviousTTL)
	}
	return operation
}
