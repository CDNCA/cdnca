package dnscheck

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

const (
	maximumTTL               = 7 * 24 * 60 * 60
	maximumPropagationWindow = 7 * 24 * time.Hour
	maximumProviderRecords   = 128
)

var lookupIDNA = idna.Lookup

func NewResolverEndpoint(network, address string, port uint16) (ResolverEndpoint, error) {
	endpoint := ResolverEndpoint{Network: strings.ToLower(strings.TrimSpace(network)), Port: port}
	parsed, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return ResolverEndpoint{}, ErrInvalidInput
	}
	endpoint.Address = parsed.Unmap()
	if err := validateEndpoint(endpoint); err != nil {
		return ResolverEndpoint{}, err
	}
	return endpoint, nil
}

func NewEndpointPolicy(endpoints ...ResolverEndpoint) (EndpointPolicy, error) {
	if len(endpoints) == 0 {
		return EndpointPolicy{}, ErrInvalidInput
	}
	policy := EndpointPolicy{allowed: make(map[string]struct{}, len(endpoints))}
	for _, endpoint := range endpoints {
		if err := validateEndpoint(endpoint); err != nil {
			return EndpointPolicy{}, err
		}
		policy.allowed[endpointKey(endpoint)] = struct{}{}
	}
	return policy, nil
}

func (p EndpointPolicy) Check(endpoint ResolverEndpoint) error {
	if err := validateEndpoint(endpoint); err != nil {
		return ErrEndpointDenied
	}
	if _, ok := p.allowed[endpointKey(endpoint)]; !ok {
		return ErrEndpointDenied
	}
	return nil
}

func validateEndpoint(endpoint ResolverEndpoint) error {
	if endpoint.Network != "udp" && endpoint.Network != "tcp" {
		return ErrInvalidInput
	}
	if !endpoint.Address.IsValid() || endpoint.Address.IsUnspecified() || endpoint.Address.IsMulticast() || endpoint.Port == 0 {
		return ErrInvalidInput
	}
	return nil
}

func endpointKey(endpoint ResolverEndpoint) string {
	return endpoint.Network + "://" + netip.AddrPortFrom(endpoint.Address, endpoint.Port).String()
}

func normalizeDNSName(value string, wildcardAllowed bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "." {
		return value, nil
	}
	if value == "" || strings.ContainsAny(value, "/:@[]\\\x00") {
		return "", ErrInvalidInput
	}
	value = strings.TrimSuffix(value, ".")
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		if !wildcardAllowed {
			return "", ErrInvalidInput
		}
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || strings.Contains(value, "*") {
		return "", ErrInvalidInput
	}
	ascii, err := lookupIDNA.ToASCII(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", ErrInvalidInput
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
	}
	if wildcard {
		ascii = "*." + ascii
	}
	return ascii + ".", nil
}

func normalizeExpected(records []ExpectedRecord) ([]ExpectedRecord, error) {
	if len(records) == 0 || len(records) > 3 {
		return nil, ErrInvalidInput
	}
	result := make([]ExpectedRecord, 0, len(records))
	seenTypes := make(map[RecordType]struct{}, len(records))
	for _, record := range records {
		if _, duplicate := seenTypes[record.Type]; duplicate || !supportedRecordType(record.Type) || len(record.Values) == 0 || len(record.Values) > 32 {
			return nil, ErrInvalidInput
		}
		seenTypes[record.Type] = struct{}{}
		values := make([]string, 0, len(record.Values))
		seenValues := make(map[string]struct{}, len(record.Values))
		var weights map[string]uint32
		if len(record.Weights) > len(record.Values) {
			return nil, ErrInvalidInput
		}
		for _, value := range record.Values {
			normalized, err := normalizeRecordValue(record.Type, value)
			if err != nil {
				return nil, err
			}
			if _, duplicate := seenValues[normalized]; duplicate {
				return nil, ErrInvalidInput
			}
			seenValues[normalized] = struct{}{}
			values = append(values, normalized)
			if weight, ok := record.Weights[value]; ok {
				if weight < 1 || weight > 100 {
					return nil, ErrInvalidInput
				}
				if weights == nil {
					weights = make(map[string]uint32, len(record.Weights))
				}
				weights[normalized] = weight
			}
		}
		if record.Type == RecordCNAME && len(values) != 1 || len(weights) != len(record.Weights) {
			return nil, ErrInvalidInput
		}
		sort.Strings(values)
		result = append(result, ExpectedRecord{Type: record.Type, Values: values, Weights: weights})
	}
	if _, cname := seenTypes[RecordCNAME]; cname && len(seenTypes) != 1 {
		return nil, ErrInvalidInput
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result, nil
}

func normalizeRecordValue(recordType RecordType, value string) (string, error) {
	switch recordType {
	case RecordA:
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !address.Is4() {
			return "", ErrInvalidInput
		}
		return address.Unmap().String(), nil
	case RecordAAAA:
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !address.Is6() || address.Is4In6() {
			return "", ErrInvalidInput
		}
		return address.String(), nil
	case RecordCNAME:
		return normalizeDNSName(value, false)
	case RecordTXT:
		value = strings.TrimSpace(value)
		if value == "" || strings.IndexByte(value, 0) >= 0 || len(value) > 65535 {
			return "", ErrInvalidInput
		}
		return value, nil
	default:
		return "", ErrInvalidInput
	}
}

func supportedRecordType(recordType RecordType) bool {
	return recordType == RecordA || recordType == RecordAAAA || recordType == RecordCNAME || recordType == RecordTXT
}

func normalizeRequest(request CheckRequest, now time.Time) (CheckRequest, error) {
	if request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.Provider.ZoneID == uuid.Nil || request.Provider.Revision < 1 ||
		request.Provider.TenantID != request.TenantID || request.Provider.SiteID != request.SiteID || request.TTL == 0 || request.TTL > maximumTTL ||
		request.PropagationWindow < time.Duration(request.TTL)*time.Second || request.PropagationWindow > maximumPropagationWindow ||
		len(request.Provider.Records) > maximumProviderRecords {
		return CheckRequest{}, ErrInvalidInput
	}
	name, err := normalizeDNSName(request.Name, true)
	if err != nil {
		return CheckRequest{}, err
	}
	expected, err := normalizeExpected(request.Expected)
	if err != nil {
		return CheckRequest{}, err
	}
	request.Name = name
	request.Expected = expected
	if request.PropagationStartedAt != nil {
		started := request.PropagationStartedAt.UTC()
		if started.IsZero() || started.After(now.Add(time.Minute)) {
			return CheckRequest{}, ErrInvalidInput
		}
		request.PropagationStartedAt = &started
	}
	nameservers := make([]string, 0, len(request.AuthoritativeNS))
	seenNS := make(map[string]struct{}, len(request.AuthoritativeNS))
	for _, value := range request.AuthoritativeNS {
		ns, err := normalizeDNSName(value, false)
		if err != nil {
			return CheckRequest{}, err
		}
		if _, duplicate := seenNS[ns]; duplicate {
			return CheckRequest{}, ErrInvalidInput
		}
		seenNS[ns] = struct{}{}
		nameservers = append(nameservers, ns)
	}
	sort.Strings(nameservers)
	request.AuthoritativeNS = nameservers
	records := make([]ProviderRecord, 0, len(request.Provider.Records))
	seenIDs := make(map[string]struct{}, len(request.Provider.Records))
	for _, record := range request.Provider.Records {
		if !validProviderIdentifier(record.RecordID) || record.TTL == 0 || record.TTL > maximumTTL || !supportedRecordType(record.Type) {
			return CheckRequest{}, ErrInvalidInput
		}
		if _, duplicate := seenIDs[record.RecordID]; duplicate {
			return CheckRequest{}, ErrInvalidInput
		}
		seenIDs[record.RecordID] = struct{}{}
		record.Name, err = normalizeDNSName(record.Name, true)
		if err != nil || record.Name != request.Name {
			return CheckRequest{}, ErrInvalidInput
		}
		record.Value, err = normalizeRecordValue(record.Type, record.Value)
		if err != nil {
			return CheckRequest{}, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		left := fmt.Sprintf("%05d/%s/%s", records[i].Type, records[i].Value, records[i].RecordID)
		right := fmt.Sprintf("%05d/%s/%s", records[j].Type, records[j].Value, records[j].RecordID)
		return left < right
	})
	request.Provider.Records = records
	return request, nil
}

func normalizeResolverName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return "", ErrInvalidInput
	}
	return value, nil
}

func recordTypeKey(recordType RecordType) string {
	return strconv.FormatUint(uint64(recordType), 10)
}
