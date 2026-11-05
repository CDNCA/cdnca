package dnsproviderremote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Namecheap XML API (read 2026-11-05 from the Wayback copies of
// https://www.namecheap.com/support/api/methods/domains-dns/get-hosts/ and
// /set-hosts/, /domains/get-list/, /api/global-parameters/, /api/intro/,
// API FAQ): every call carries ApiUser, ApiKey, UserName, Command and
// ClientIp, the IPv4 source address whitelisted in the Namecheap account
// (USERNAME / API_KEY / SOURCEIP in the provider form; the operator fills in the
// control plane's egress IP). Limits: 50/min, 700/hour, 8000/day per key.
//
// setHosts replaces the whole host set ("All host records that are not
// included into the API call will be deleted"). Every write therefore reads
// the full set (getHosts), changes it and writes all of it back, then reads
// it again and checks the result. Writes to one zone are serialised in this
// process (namecheapZoneLocks). Namecheap has no version or ETag: a change
// made elsewhere (the Namecheap panel, another control-plane process)
// between our read and write is overwritten. The read-back makes such a race
// visible as an uncertain result (provider_recovery_pending) rather than a
// success, and the next reconcile pass repairs our records; it cannot bring
// back another writer's lost change. A zone holding a record type setHosts
// cannot write back faithfully (CAA, SRV, ...) is refused rather than
// rewritten without it.
//
// HostId is not documented as stable across setHosts calls, so the adapter
// names a record by a digest of owner, type and value (namecheapRecordID).
// Records have no line field: default line only. TTL 60..60000.
const (
	providerNamecheap = "namecheap"

	NamecheapMinTTL = 60
	NamecheapMaxTTL = 60000
	namecheapPath   = "/xml.response"
)

// namecheapWritableTypes are the setHosts RecordType values whose getHosts
// form (Name, Type, Address, MXPref, TTL) is everything setHosts needs.
var namecheapWritableTypes = []string{"A", "AAAA", "ALIAS", "CNAME", "MX", "MXE", "NS", "TXT", "URL", "URL301", "FRAME"}

var namecheapZoneLocks sync.Map // username + "\x00" + zone -> *sync.Mutex

type namecheapProvider struct{ adapter *Adapter }

type namecheapHost struct {
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  string `xml:"MXPref,attr"`
	TTL     string `xml:"TTL,attr"`
}

type namecheapResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Number string `xml:"Number,attr"`
	} `xml:"Errors>Error"`
	Hosts struct {
		Domain        string          `xml:"Domain,attr"`
		IsUsingOurDNS string          `xml:"IsUsingOurDNS,attr"`
		EmailType     string          `xml:"EmailType,attr"`
		Lower         []namecheapHost `xml:"host"`
		Upper         []namecheapHost `xml:"Host"`
	} `xml:"CommandResponse>DomainDNSGetHostsResult"`
	SetHosts struct {
		IsSuccess string `xml:"IsSuccess,attr"`
	} `xml:"CommandResponse>DomainDNSSetHostsResult"`
	Domains []struct {
		Name string `xml:"Name,attr"`
	} `xml:"CommandResponse>DomainGetListResult>Domain"`
}

// request sends one POST form (the key never sits in a URL) and returns the
// decoded Status="OK" answer.
func (p *namecheapProvider) request(ctx context.Context, config ProviderConfig, command string,
	parameters url.Values) (namecheapResponse, error) {
	credentials := providerCredentials(config, "username", "api_key", "source_ip")
	form := url.Values{"ApiUser": {credentials[0]}, "ApiKey": {credentials[1]}, "UserName": {credentials[0]},
		"ClientIp": {credentials[2]}, "Command": {command}}
	for name, values := range parameters {
		form[name] = values
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	headers.Set("Accept", "application/xml")
	response, err := p.adapter.http.do(ctx, http.MethodPost, p.adapter.endpoints.namecheap, namecheapPath,
		[]byte(form.Encode()), headers)
	if err != nil {
		return namecheapResponse{}, err
	}
	if err := classifyHTTP(response, p.adapter.now()); err != nil {
		return namecheapResponse{}, err
	}
	var decoded namecheapResponse
	if response.status != http.StatusOK || xml.NewDecoder(bytes.NewReader(response.body)).Decode(&decoded) != nil {
		return namecheapResponse{}, malformedProviderResponse()
	}
	if decoded.Status != "OK" || len(decoded.Errors) > 0 {
		if len(decoded.Errors) == 0 {
			return namecheapResponse{}, malformedProviderResponse()
		}
		return namecheapResponse{}, namecheapFailure(decoded.Errors[0].Number)
	}
	return decoded, nil
}

// namecheapFailure maps the documented error numbers (global parameters,
// getHosts / setHosts / getList tables).
func namecheapFailure(number string) error {
	code, err := strconv.Atoi(number)
	switch {
	case err != nil:
		return malformedProviderResponse()
	case code >= 1010000 && code <= 1019999:
		// APIUser / APIKey / ClientIp / UserName missing, invalid or locked,
		// including a ClientIp not on the account's whitelist.
		return failure(CodeCredentialsRejected, false)
	case code == 2030166:
		return failure(CodeCredentialsRejected, false)
	case code == 2019166 || code == 2016166 || code == 2030288 || code == 3011288:
		return failure(CodeZoneNotHosted, false)
	case code == 3013288 || code == 4013288:
		return failure(CodeInvalidInput, false)
	case code == 3031510 || code == 3050900 || code == 4022288 || code == 4023330 || code == 5050900 || code == 5050169:
		return failure(CodeUnavailable, true)
	}
	return malformedProviderResponse()
}

// namecheapDomain splits the hosted apex into SLD and TLD (example.co.uk:
// example / co.uk).
func namecheapDomain(zone string) (url.Values, error) {
	sld, tld, ok := strings.Cut(zone, ".")
	if !ok || sld == "" || tld == "" {
		return nil, failure(CodeInvalidInput, false)
	}
	return url.Values{"SLD": {sld}, "TLD": {tld}}, nil
}

// getHosts reads the whole host set and the domain's EmailType.
func (p *namecheapProvider) getHosts(ctx context.Context, config ProviderConfig) ([]namecheapHost, string, error) {
	domain, err := namecheapDomain(config.ZoneName)
	if err != nil {
		return nil, "", err
	}
	response, err := p.request(ctx, config, "namecheap.domains.dns.getHosts", domain)
	if err != nil {
		return nil, "", err
	}
	result := response.Hosts
	if result.Domain != "" && canonicalDNSName(result.Domain, false) != config.ZoneName {
		return nil, "", malformedProviderResponse()
	}
	if strings.EqualFold(result.IsUsingOurDNS, "false") {
		return nil, "", failure(CodeZoneNotHosted, false)
	}
	return append(result.Lower, result.Upper...), result.EmailType, nil
}

func (host namecheapHost) owner(zone string) string {
	name := strings.ToLower(host.Name)
	if name == "" || name == "@" {
		return zone + "."
	}
	return ownerFromRelative(name, zone)
}

func (host namecheapHost) recordType() string { return strings.ToUpper(host.Type) }

// value is the address as compared: host names without the root dot.
func (host namecheapHost) value() string {
	switch host.recordType() {
	case "CNAME", "MX", "NS", "ALIAS":
		return strings.TrimSuffix(strings.ToLower(host.Address), ".")
	case "TXT":
		return unquoteTXT(host.Address)
	}
	return host.Address
}

// namecheapRecordID names a record by owner, type and value.
func namecheapRecordID(owner, recordType, value string) string {
	digest := sha256.Sum256([]byte(owner + "\x00" + recordType + "\x00" + value))
	return "nc-" + hex.EncodeToString(digest[:12])
}

func (host namecheapHost) recordID(zone string) string {
	return namecheapRecordID(host.owner(zone), host.recordType(), host.value())
}
func namecheapHostKeys(hosts []namecheapHost, zone string) []string {
	keys := make([]string, 0, len(hosts))
	for _, host := range hosts {
		keys = append(keys, host.recordID(zone))
	}
	sort.Strings(keys)
	return keys
}

// rewrite replaces the host set with edit(current) under the zone lock and
// checks the result by reading it back. An unchanged set is not written.
func (p *namecheapProvider) rewrite(ctx context.Context, config ProviderConfig,
	edit func([]namecheapHost) []namecheapHost) error {
	lockValue, _ := namecheapZoneLocks.LoadOrStore(config.Credentials["username"]+"\x00"+config.ZoneName, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	current, emailType, err := p.getHosts(ctx, config)
	if err != nil {
		return err
	}
	for _, host := range current {
		if !slices.Contains(namecheapWritableTypes, host.recordType()) {
			// Writing the set back would drop or garble this record.
			return failure(CodeUnsupported, false)
		}
	}
	next := edit(slices.Clone(current))
	if slices.Equal(next, current) {
		return nil
	}
	want := namecheapHostKeys(next, config.ZoneName)
	form, err := namecheapDomain(config.ZoneName)
	if err != nil {
		return err
	}
	if emailType != "" {
		form.Set("EmailType", emailType)
	}
	for index, host := range next {
		suffix := strconv.Itoa(index + 1)
		name := host.Name
		if name == "" {
			name = "@"
		}
		form.Set("HostName"+suffix, name)
		form.Set("RecordType"+suffix, host.recordType())
		form.Set("Address"+suffix, host.Address)
		form.Set("TTL"+suffix, host.TTL)
		if host.MXPref != "" {
			form.Set("MXPref"+suffix, host.MXPref)
		}
	}
	response, err := p.request(ctx, config, "namecheap.domains.dns.setHosts", form)
	if err != nil {
		return err
	}
	if !strings.EqualFold(response.SetHosts.IsSuccess, "true") {
		return malformedProviderResponse()
	}
	written, _, err := p.getHosts(ctx, config)
	if err != nil {
		return failure(CodeUnavailable, true)
	}
	if !slices.Equal(want, namecheapHostKeys(written, config.ZoneName)) {
		// Another writer, or Namecheap normalised a value: result unknown.
		return failure(CodeUnavailable, true)
	}
	return nil
}

func namecheapRelativeName(owner, zone string) (string, error) {
	_, relative, err := ownerAndRelative(owner, zone)
	return relative, err
}

func (p *namecheapProvider) present(ctx context.Context, config ProviderConfig, owner, relative,
	exactValue string) (recordHandle, error) {
	recordID := namecheapRecordID(owner, "TXT", exactValue)
	err := p.rewrite(ctx, config, func(hosts []namecheapHost) []namecheapHost {
		for _, host := range hosts {
			if host.recordID(config.ZoneName) == recordID {
				return hosts
			}
		}
		return append(hosts, namecheapHost{Name: relative, Type: "TXT", Address: exactValue,
			TTL: strconv.Itoa(NamecheapMinTTL)})
	})
	if err != nil {
		return recordHandle{}, err
	}
	return recordHandle{Provider: providerNamecheap, Zone: config.ZoneName, ZoneID: config.ZoneName,
		RecordID: recordID, Owner: owner}, nil
}

func (p *namecheapProvider) lookupTXT(ctx context.Context, config ProviderConfig, owner, _ string,
	exactValue string) ([]recordHandle, error) {
	hosts, _, err := p.getHosts(ctx, config)
	if err != nil {
		return nil, err
	}
	matches := make([]recordHandle, 0, 1)
	for _, host := range hosts {
		if host.owner(config.ZoneName) == owner && host.recordType() == "TXT" && host.value() == exactValue {
			matches = append(matches, recordHandle{Version: 1, Provider: providerNamecheap, Zone: config.ZoneName,
				ZoneID: config.ZoneName, RecordID: host.recordID(config.ZoneName), Owner: owner})
		}
	}
	return matches, nil
}

func (p *namecheapProvider) get(ctx context.Context, config ProviderConfig, handle recordHandle, _ string) (remoteRecord, bool, error) {
	if handle.ZoneID != config.ZoneName {
		return remoteRecord{}, false, failure(CodeRecordMismatch, false)
	}
	hosts, _, err := p.getHosts(ctx, config)
	if err != nil {
		return remoteRecord{}, false, err
	}
	for _, host := range hosts {
		if host.recordID(config.ZoneName) == handle.RecordID {
			return remoteRecord{Owner: host.owner(config.ZoneName), Type: host.recordType(), Value: host.value()}, true, nil
		}
	}
	return remoteRecord{}, false, nil
}

func (p *namecheapProvider) delete(ctx context.Context, config ProviderConfig, handle recordHandle) error {
	if handle.ZoneID != config.ZoneName {
		return failure(CodeRecordMismatch, false)
	}
	return p.rewrite(ctx, config, func(hosts []namecheapHost) []namecheapHost {
		return slices.DeleteFunc(hosts, func(host namecheapHost) bool { return host.recordID(config.ZoneName) == handle.RecordID })
	})
}

func namecheapReconcileRecord(host namecheapHost, zone string) reconcileRecord {
	recordType := host.recordType()
	switch recordType {
	case "A", "AAAA", "CNAME", "TXT":
	default:
		recordType = "OTHER"
	}
	ttl, _ := strconv.ParseUint(host.TTL, 10, 32)
	return reconcileRecord{ID: host.recordID(zone), Name: host.owner(zone), Type: recordType, Value: host.Address,
		TTL: uint32(ttl), Line: LineDefault}
}

// listRecords returns the whole zone; ListZoneRecords filters the owner.
func (p *namecheapProvider) listRecords(ctx context.Context, config ProviderConfig) ([]reconcileRecord, error) {
	hosts, _, err := p.getHosts(ctx, config)
	if err != nil {
		return nil, err
	}
	converted := make([]reconcileRecord, 0, len(hosts))
	for _, host := range hosts {
		converted = append(converted, namecheapReconcileRecord(host, config.ZoneName))
	}
	return converted, nil
}

// namecheapAddresses: the operation's values a record of the owner and type
// is matched against (an update's previous and new value; the value
// otherwise). Records are named by their value, so like Huawei record sets
// an update or delete addresses the value and keeps the operation's id.
func namecheapAddresses(operation dnscheck.ProviderOperation) []string {
	values := []string{reconcileProviderValue(operation.Type, operation.Value)}
	if operation.Action == dnscheck.ProviderUpdate {
		values = append(values, reconcileProviderValue(operation.Type, operation.PreviousValue))
	}
	return values
}

func (p *namecheapProvider) reconcileLookup(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (ReconcileLookup, error) {
	hosts, _, err := p.getHosts(ctx, config)
	if err != nil {
		return ReconcileLookup{}, err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	effective := providerOperation(providerNamecheap, operation)
	values := namecheapAddresses(operation)
	converted := make([]reconcileRecord, 0, 2)
	seen := make(map[string]struct{})
	for _, host := range hosts {
		if host.owner(config.ZoneName) != operation.Name || host.recordType() != typeName {
			continue
		}
		candidate := namecheapReconcileRecord(host, config.ZoneName)
		if operation.Action != dnscheck.ProviderCreate {
			if !slices.Contains(values, host.value()) {
				continue
			}
			candidate.ID = operation.RecordID
		}
		if _, duplicate := seen[candidate.ID+"\x00"+candidate.Value]; duplicate {
			return ReconcileLookup{}, failure(CodeRecordMismatch, false)
		}
		seen[candidate.ID+"\x00"+candidate.Value] = struct{}{}
		converted = append(converted, candidate)
	}
	if operation.Action == dnscheck.ProviderUpdate && len(converted) > 1 {
		// Both values present: the update still has to drop the previous one.
		converted = slices.DeleteFunc(converted, func(record reconcileRecord) bool {
			return record.Value != reconcileProviderValue(operation.Type, operation.PreviousValue)
		})
	}
	normalized := make([]reconcileRecord, 0, len(converted))
	for _, record := range converted {
		record, err := normalizeReconcileRecord(record)
		if err != nil {
			return ReconcileLookup{}, err
		}
		normalized = append(normalized, record)
	}
	return lookupRecord(normalized, effective, fmt.Sprintf("namecheap:hosts=%d:matched=%d", len(hosts), len(normalized))), nil
}

func (p *namecheapProvider) reconcileMutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	relative, err := namecheapRelativeName(operation.Name, config.ZoneName)
	if err != nil {
		return "", err
	}
	typeName, _ := reconcileRecordType(operation.Type)
	value := reconcileProviderValue(operation.Type, operation.Value)
	drop := namecheapAddresses(operation)
	written := providerOperation(providerNamecheap, operation)
	err = p.rewrite(ctx, config, func(hosts []namecheapHost) []namecheapHost {
		hosts = slices.DeleteFunc(hosts, func(host namecheapHost) bool {
			return host.owner(config.ZoneName) == operation.Name && host.recordType() == typeName &&
				slices.Contains(drop, host.value())
		})
		if operation.Action == dnscheck.ProviderDelete {
			return hosts
		}
		return append(hosts, namecheapHost{Name: relative, Type: typeName, Address: value,
			TTL: strconv.FormatUint(uint64(written.TTL), 10)})
	})
	if err != nil {
		return "", err
	}
	if operation.Action == dnscheck.ProviderCreate {
		return namecheapRecordID(operation.Name, typeName, strings.TrimSuffix(value, ".")), nil
	}
	return operation.RecordID, nil
}

// zoneNames lists one page of the account's domains (domains.getList,
// PageSize 10..100).
func (p *namecheapProvider) zoneNames(ctx context.Context, config ProviderConfig, page, pageSize int) ([]string, error) {
	response, err := p.request(ctx, config, "namecheap.domains.getList", url.Values{
		"Page": {strconv.Itoa(page)}, "PageSize": {strconv.Itoa(pageSize)},
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(response.Domains))
	for _, domain := range response.Domains {
		names = append(names, domain.Name)
	}
	return names, nil
}

// validNamecheapClientIP: ClientIp is an IPv4 address (global parameters).
func validNamecheapClientIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}
