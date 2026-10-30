package dnsproviderremote

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type reconcileHTTPScenario string

const (
	reconcileLaterTarget        reconcileHTTPScenario = "later-target"
	reconcileDuplicateTarget    reconcileHTTPScenario = "duplicate-target"
	reconcileConflictingID      reconcileHTTPScenario = "conflicting-id"
	reconcileMetadataDrift      reconcileHTTPScenario = "metadata-drift"
	reconcileMissingMetadata    reconcileHTTPScenario = "missing-metadata"
	reconcilePostMutation       reconcileHTTPScenario = "post-mutation"
	reconcileInvalidIdentity    reconcileHTTPScenario = "invalid-identity"
	reconcileCompleteEmptyPage  reconcileHTTPScenario = "complete-empty-page"
	reconcileStableContentDrift reconcileHTTPScenario = "stable-content-drift"
	reconcileStablePageMove     reconcileHTTPScenario = "stable-page-move"
	reconcileBoundaryOverflow   reconcileHTTPScenario = "boundary-overflow"
)

var reconcileHTTPProviders = []string{
	providerCloudflare,
	providerAliyun,
	providerHuawei,
	providerDNSPodCN,
	providerDNSCom,
	providerDNSLA,
}

type reconcileHTTPFixture struct {
	t           *testing.T
	provider    string
	scenario    reconcileHTTPScenario
	cycle       int
	pageCalls   int
	mutations   int
	recordType  string
	targetValue string
}

type reconcileHTTPAuthority struct {
	snapshots []RevisionSnapshot
	loads     int
	revision  int64
	digest    [sha256.Size]byte
}

func (authority *reconcileHTTPAuthority) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	return authority.revision, nil
}

func (authority *reconcileHTTPAuthority) LoadRevision(context.Context, dnscheck.ProviderMutation) (RevisionSnapshot, error) {
	index := authority.loads
	if index >= len(authority.snapshots) {
		index = len(authority.snapshots) - 1
	}
	authority.loads++
	return cloneRevisionSnapshot(authority.snapshots[index]), nil
}

func (authority *reconcileHTTPAuthority) AcquireMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation) (MutationClaim, error) {
	snapshot, err := authority.LoadRevision(ctx, mutation)
	return MutationClaim{
		RevisionSnapshot: snapshot, ClaimID: uuid.New(), State: MutationClaimed,
		ProviderRequestID: deterministicProviderRequestID(mutation.ClientRequestID),
	}, err
}

func (authority *reconcileHTTPAuthority) ValidateMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim) error {
	current, err := authority.LoadRevision(ctx, mutation)
	if err != nil {
		return err
	}
	if !sameTestRevisionSnapshot(current, claim.RevisionSnapshot) {
		return dnscheck.ErrProviderRevisionConflict
	}
	return nil
}

func sameTestRevisionSnapshot(left, right RevisionSnapshot) bool {
	if left.Revision != right.Revision || left.SiteRevision != right.SiteRevision ||
		left.ProviderRevision != right.ProviderRevision || left.SiteConfigDigest != right.SiteConfigDigest ||
		left.OperationDigest != right.OperationDigest || left.AuthorityDigest != right.AuthorityDigest ||
		left.ProviderConfigDigest != right.ProviderConfigDigest || left.CredentialDigest != right.CredentialDigest ||
		left.Config.TenantScopeID != right.Config.TenantScopeID || left.Config.ProviderID != right.Config.ProviderID ||
		left.Config.ProviderType != right.Config.ProviderType || left.Config.ZoneID != right.Config.ZoneID ||
		left.Config.ZoneName != right.Config.ZoneName || len(left.Config.Credentials) != len(right.Config.Credentials) {
		return false
	}
	for name, value := range left.Config.Credentials {
		if right.Config.Credentials[name] != value {
			return false
		}
	}
	return true
}

func (*reconcileHTTPAuthority) MarkMutationUncertain(context.Context, dnscheck.ProviderMutation,
	MutationClaim, string) error {
	return nil
}

func (authority *reconcileHTTPAuthority) FinalizeMutationClaim(_ context.Context,
	mutation dnscheck.ProviderMutation, claim MutationClaim, outcome MutationClaimState, _, _ string) (int64, error) {
	advance := outcome == MutationSucceeded && authority.revision == mutation.ExpectedRevision
	return authority.FinalizeRevision(context.Background(), mutation, claim.RevisionSnapshot, advance)
}

func (authority *reconcileHTTPAuthority) FinalizeRevision(_ context.Context, mutation dnscheck.ProviderMutation,
	snapshot RevisionSnapshot, advance bool) (int64, error) {
	if snapshot.Revision != authority.revision || snapshot.AuthorityDigest != authority.digest {
		return 0, dnscheck.ErrProviderRevisionConflict
	}
	if advance {
		if authority.revision != mutation.ExpectedRevision {
			return 0, dnscheck.ErrProviderRevisionConflict
		}
		authority.revision++
	}
	if authority.revision != mutation.ExpectedRevision+1 {
		return 0, dnscheck.ErrProviderRevisionConflict
	}
	return authority.revision, nil
}

func cloneRevisionSnapshot(snapshot RevisionSnapshot) RevisionSnapshot {
	cloned := snapshot
	cloned.Config.Credentials = make(map[string]string, len(snapshot.Config.Credentials))
	for name, value := range snapshot.Config.Credentials {
		cloned.Config.Credentials[name] = value
	}
	return cloned
}

func TestProviderReconcileResponseLossFindsTargetOnLaterPageWithoutReplay(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		t.Run(provider, func(t *testing.T) {
			fixture, adapter, config := newReconcileHTTPAdapter(t, provider, reconcileLaterTarget)
			authority := newReconcileHTTPAuthority(config, 8)
			result, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
			if err != nil || result.RecordID != "target" || result.Revision != 8 {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if fixture.pageCalls != 2 || fixture.mutations != 0 {
				t.Fatalf("pageCalls=%d mutations=%d", fixture.pageCalls, fixture.mutations)
			}
		})
	}
}

func TestProviderReconcileCanonicalPaginationCoversAAndAAAAAndCNAME(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, record := range []struct {
			name  string
			type_ dnscheck.RecordType
			value string
		}{
			{name: "A", type_: dnscheck.RecordA, value: "192.0.2.10"},
			{name: "AAAA", type_: dnscheck.RecordAAAA, value: "2001:db8::10"},
			{name: "CNAME", type_: dnscheck.RecordCNAME, value: "edge.example.net."},
		} {
			t.Run(provider+"/"+record.name, func(t *testing.T) {
				fixture, adapter, config := newReconcileHTTPAdapter(t, provider, reconcileLaterTarget)
				fixture.recordType, fixture.targetValue = record.name, record.value
				lookup, err := (&providerReconcileRemote{adapter: adapter}).Lookup(t.Context(), config,
					dnscheck.ProviderOperation{
						Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: record.type_,
						Value: record.value, TTL: 300,
					})
				if err != nil || !lookup.TargetComplete || lookup.RecordID != "target" || fixture.pageCalls != 2 {
					t.Fatalf("Lookup()=(%+v,%v) pageCalls=%d", lookup, err, fixture.pageCalls)
				}
			})
		}
	}
}

func TestProviderReconcileCrossPageAmbiguityFailsClosed(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, scenario := range []reconcileHTTPScenario{reconcileDuplicateTarget, reconcileConflictingID} {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				fixture, adapter, config := newReconcileHTTPAdapter(t, provider, scenario)
				authority := newReconcileHTTPAuthority(config, 7)
				_, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
				if err == nil {
					t.Fatal("ambiguous paginated result succeeded")
				}
				if fixture.pageCalls != 2 || fixture.mutations != 0 {
					t.Fatalf("pageCalls=%d mutations=%d", fixture.pageCalls, fixture.mutations)
				}
			})
		}
	}
}

func TestProviderReconcileIncompletePaginationFailsClosed(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, scenario := range []reconcileHTTPScenario{reconcileMetadataDrift, reconcileMissingMetadata} {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				fixture, adapter, config := newReconcileHTTPAdapter(t, provider, scenario)
				authority := newReconcileHTTPAuthority(config, 7)
				_, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
				if err == nil {
					t.Fatal("incomplete pagination succeeded")
				}
				if fixture.mutations != 0 {
					t.Fatalf("mutations=%d", fixture.mutations)
				}
				wantPageCalls := 1
				if scenario == reconcileMetadataDrift {
					wantPageCalls = 2
				}
				if fixture.pageCalls != wantPageCalls {
					t.Fatalf("pageCalls=%d want=%d", fixture.pageCalls, wantPageCalls)
				}
			})
		}
	}
}

func TestProviderReconcileInvalidRecordIdentityFailsClosed(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		t.Run(provider, func(t *testing.T) {
			fixture, adapter, config := newReconcileHTTPAdapter(t, provider, reconcileInvalidIdentity)
			authority := newReconcileHTTPAuthority(config, 7)
			_, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
			if err == nil {
				t.Fatal("non-canonical provider identity succeeded")
			}
			if fixture.mutations != 0 {
				t.Fatalf("mutations=%d", fixture.mutations)
			}
		})
	}
}

func TestProviderReconcilePostMutationRequeriesEveryPage(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		t.Run(provider, func(t *testing.T) {
			fixture, adapter, config := newReconcileHTTPAdapter(t, provider, reconcilePostMutation)
			authority := newReconcileHTTPAuthority(config, 7)
			result, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
			if err != nil || result.RecordID != "target" || result.Revision != 8 {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			wantPageCalls := 4
			if provider == providerHuawei {
				wantPageCalls++ // the create reads the owner's record set before writing it (FX03)
			}
			if fixture.pageCalls != wantPageCalls || fixture.mutations != 1 {
				t.Fatalf("pageCalls=%d want=%d mutations=%d", fixture.pageCalls, wantPageCalls, fixture.mutations)
			}
		})
	}
}

func TestReconcileAdapterAuthorityDriftBeforeProviderMutationFailsClosed(t *testing.T) {
	for _, drift := range []string{"revision", "config", "credentials", "digest"} {
		t.Run(drift, func(t *testing.T) {
			fixture, adapter, config := newReconcileHTTPAdapter(t, providerCloudflare, reconcileCompleteEmptyPage)
			initial := revisionSnapshot(config, 7, 1)
			changed := cloneRevisionSnapshot(initial)
			switch drift {
			case "revision":
				changed.Revision++
			case "config":
				changed.Config.ProviderID = uuid.New()
			case "credentials":
				changed.Config.Credentials["api_token"] = "rotated-token"
			case "digest":
				changed.AuthorityDigest[0]++
			}
			authority := &reconcileHTTPAuthority{
				snapshots: []RevisionSnapshot{initial, changed}, revision: initial.Revision,
				digest: initial.AuthorityDigest,
			}
			_, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
			if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
				t.Fatalf("error=%v", err)
			}
			if authority.loads != 2 || fixture.mutations != 0 {
				t.Fatalf("loads=%d mutations=%d", authority.loads, fixture.mutations)
			}
		})
	}
}

func TestProviderReconcileRepeatedFullScanDetectsStableMetadataDrift(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, scenario := range []reconcileHTTPScenario{reconcileStableContentDrift, reconcileStablePageMove} {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				fixture, adapter, config := newReconcileHTTPAdapter(t, provider, scenario)
				authority := newReconcileHTTPAuthority(config, 7)
				_, err := mutateThroughReconcileAdapter(t, adapter, authority, 7)
				if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) || fixture.mutations != 0 {
					t.Fatalf("error=%v mutations=%d", err, fixture.mutations)
				}
				wantCalls := 2
				if scenario == reconcileStablePageMove {
					wantCalls = 4
				}
				if fixture.pageCalls != wantCalls {
					t.Fatalf("pageCalls=%d, want %d", fixture.pageCalls, wantCalls)
				}
			})
		}
	}
}

func TestDNSPodReconcileLookupProbesBeyondTenThousand(t *testing.T) {
	fixture, adapter, config := newReconcileHTTPAdapter(t, providerDNSPodCN, reconcileBoundaryOverflow)
	remote := &providerReconcileRemote{adapter: adapter}
	_, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{
		Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 300,
	})
	if err == nil || fixture.pageCalls != recoveryMaxPages+1 || fixture.mutations != 0 {
		t.Fatalf("Lookup() error=%v pageCalls=%d mutations=%d", err, fixture.pageCalls, fixture.mutations)
	}
}

func newReconcileHTTPAuthority(config ProviderConfig, revision int64) *reconcileHTTPAuthority {
	snapshot := revisionSnapshot(config, revision, 1)
	return &reconcileHTTPAuthority{
		snapshots: []RevisionSnapshot{snapshot}, revision: revision, digest: snapshot.AuthorityDigest,
	}
}

func revisionSnapshot(config ProviderConfig, revision int64, digestByte byte) RevisionSnapshot {
	var digest [sha256.Size]byte
	digest[0] = digestByte
	return RevisionSnapshot{Revision: revision, Config: config, AuthorityDigest: digest}
}

func mutateThroughReconcileAdapter(t *testing.T, providerAdapter *Adapter, authority RevisionAuthority,
	expectedRevision int64) (dnscheck.ProviderMutationResult, error) {
	t.Helper()
	adapter, err := NewReconcileAdapter(authority, &providerReconcileRemote{adapter: providerAdapter})
	if err != nil {
		t.Fatal(err)
	}
	return adapter.Mutate(t.Context(), dnscheck.ProviderMutation{
		ClientRequestID: "provider-http-request-1", TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
		ExpectedRevision: expectedRevision,
		Operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300,
		},
	})
}

func newReconcileHTTPAdapter(t *testing.T, provider string,
	scenario reconcileHTTPScenario) (*reconcileHTTPFixture, *Adapter, ProviderConfig) {
	t.Helper()
	fixture := &reconcileHTTPFixture{t: t, provider: provider, scenario: scenario}
	config := reconcileHTTPProviderConfig(provider)
	adapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
	return fixture, adapter, completeTestConfig(config)
}

func reconcileHTTPProviderConfig(provider string) ProviderConfig {
	config := ProviderConfig{ProviderType: provider, ZoneName: testZone}
	switch provider {
	case providerCloudflare:
		config.Credentials = map[string]string{"api_token": "provider-token"}
	case providerAliyun:
		config.Credentials = map[string]string{"access_key_id": "provider-key", "access_key_secret": "provider-secret"}
	case providerHuawei:
		config.Credentials = map[string]string{
			"access_key": "provider-key", "secret_key": "provider-secret", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		}
	case providerDNSPodCN:
		config.Credentials = map[string]string{"dp_id": "12345", "dp_key": "provider-secret"}
	case providerDNSCom:
		config.Credentials = map[string]string{"api_key": "provider-key", "api_secret": "provider-secret"}
	case providerDNSLA:
		config.Credentials = map[string]string{"api_id": "provider-id", "api_secret": "provider-secret"}
	case providerNameCom:
		config.Credentials = map[string]string{"username": "provider-user", "api_token": "provider-token"}
	case providerCustomHTTP:
		config.Credentials = map[string]string{"endpoint": "https://dns.example.net/cdnca", "secret": "provider-secret-0123"}
	case providerPlugin:
		config.Credentials = map[string]string{PluginCredentialField: "com.example.dnsplus"}
	}
	return config
}

func (fixture *reconcileHTTPFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if fixture.writeZoneResponse(w, r) {
		return
	}
	if page, ok := fixture.listPage(r); ok {
		if page == 1 {
			fixture.cycle++
		}
		fixture.pageCalls++
		records, total, metadata := fixture.page(page)
		fixture.writeListResponse(w, page, total, records, metadata)
		return
	}
	if fixture.isCreate(r) {
		fixture.mutations++
		fixture.writeCreateResponse(w)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (fixture *reconcileHTTPFixture) writeZoneResponse(w http.ResponseWriter, r *http.Request) bool {
	switch fixture.provider {
	case providerCloudflare:
		if r.Method == http.MethodGet && r.URL.Path == "/zones" {
			writeTestJSON(fixture.t, w, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-cf", "name": testZone},
			}})
			return true
		}
	case providerHuawei:
		if r.Method == http.MethodGet && r.URL.Path == "/v2/zones" {
			writeTestJSON(fixture.t, w, map[string]any{"zones": []any{
				map[string]any{"id": "zone-hw", "name": testZone + "."},
			}})
			return true
		}
	case providerDNSLA:
		if r.Method == http.MethodGet && r.URL.Path == "/api/domain" {
			writeTestJSON(fixture.t, w, map[string]any{"code": 200, "data": map[string]any{
				"id": "zone-dnsla", "domain": testZone,
			}})
			return true
		}
	}
	return false
}

func (fixture *reconcileHTTPFixture) listPage(r *http.Request) (int, bool) {
	assert := func(ok bool, field string) {
		fixture.t.Helper()
		if !ok {
			fixture.t.Errorf("%s canonical list field mismatch: %s %s", field, r.Method, r.URL.RequestURI())
		}
	}
	recordType := fixture.literalRecordType()
	switch fixture.provider {
	case providerCloudflare:
		if r.Method == http.MethodGet && r.URL.Path == "/zones/zone-cf/dns_records" {
			query := r.URL.Query()
			assert(query.Get("name") == "www.example.test." && query.Get("type") == recordType &&
				query.Get("per_page") == "100" && r.Header.Get("Authorization") == "Bearer provider-token", "cloudflare")
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			return page, true
		}
	case providerAliyun:
		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Get("Action") == "DescribeDomainRecords" {
			query := r.URL.Query()
			assert(query.Get("DomainName") == "example.test" && query.Get("RRKeyWord") == "www" &&
				query.Get("TypeKeyWord") == recordType && query.Get("PageSize") == "100" &&
				query.Get("AccessKeyId") == "provider-key" &&
				verifyRound3AliyunSignature(query, "provider-secret"), "aliyun")
			page, _ := strconv.Atoi(r.URL.Query().Get("PageNumber"))
			return page, true
		}
	case providerHuawei:
		if r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/zone-hw/recordsets" {
			query := r.URL.Query()
			assert(query.Get("name") == "www.example.test." && query.Get("type") == recordType &&
				query.Get("limit") == "100" && verifyRound3HuaweiSignature(r, "provider-key", "provider-secret") &&
				r.Header.Get("X-Project-Id") == "0123456789abcdef0123456789abcdef", "huawei")
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			return offset/recoveryPageSize + 1, true
		}
	case providerDNSPodCN:
		if r.Method == http.MethodPost && r.URL.Path == "/Record.List" {
			_ = r.ParseForm()
			offset, _ := strconv.Atoi(r.Form.Get("offset"))
			wantLength := "100"
			if fixture.scenario == reconcileBoundaryOverflow && offset == recoveryMaxItems {
				wantLength = "1"
			}
			assert(r.Form.Get("domain") == "example.test" && r.Form.Get("sub_domain") == "www" &&
				r.Form.Get("record_type") == recordType && r.Form.Get("length") == wantLength &&
				r.Form.Get("login_token") == "12345,provider-secret", "dnspod")
			return offset/recoveryPageSize + 1, true
		}
	case providerDNSCom:
		if r.Method == http.MethodGet && r.URL.Path == "/api/record/lists/" {
			query := r.URL.Query()
			assert(query.Get("domain") == "example.test" && query.Get("record") == "www" &&
				query.Get("type") == recordType && query.Get("paginate") == "100" && query.Get("page_size") == "" &&
				query.Get("api_key") == "provider-key" &&
				verifyRound3DNSComSignature(query, "provider-secret"), "dns.com")
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			return page, true
		}
	case providerDNSLA:
		if r.Method == http.MethodGet && r.URL.Path == "/api/recordList" {
			query := r.URL.Query()
			assert(query.Get("domainId") == "zone-dnsla" && query.Get("host") == "www" &&
				query.Get("type") == fixture.literalDNSLAType() && query.Get("pageSize") == "100" &&
				r.Header.Get("Authorization") == "Basic "+basicAuth("provider-id", "provider-secret"), "dns.la")
			page, _ := strconv.Atoi(r.URL.Query().Get("pageIndex"))
			return page, true
		}
	}
	return 0, false
}

func (fixture *reconcileHTTPFixture) page(page int) ([]map[string]any, int, bool) {
	if fixture.scenario == reconcileBoundaryOverflow {
		count := recoveryPageSize
		if page == recoveryMaxPages+1 {
			count = 1
		}
		records := make([]map[string]any, 0, count)
		for index := 0; index < count; index++ {
			absolute := (page-1)*recoveryPageSize + index
			records = append(records, fixture.record(
				fmt.Sprintf("boundary-%d", absolute), absolute, false, false))
		}
		return records, recoveryMaxItems + 1, true
	}
	if fixture.scenario == reconcileStableContentDrift {
		index := 1
		if fixture.cycle > 1 {
			index = 2
		}
		return []map[string]any{fixture.record("stable-filler", index, false, false)}, 1, true
	}
	if fixture.scenario == reconcileStablePageMove {
		indexes := make([]int, 0, recoveryPageSize)
		if page == 1 {
			for index := 0; index < recoveryPageSize; index++ {
				indexes = append(indexes, index)
			}
			if fixture.cycle > 1 {
				indexes[len(indexes)-1] = recoveryPageSize
			}
		} else if fixture.cycle > 1 {
			indexes = append(indexes, recoveryPageSize-1)
		} else {
			indexes = append(indexes, recoveryPageSize)
		}
		records := make([]map[string]any, 0, len(indexes))
		for _, index := range indexes {
			records = append(records, fixture.record(fmt.Sprintf("move-%d", index), index, false, false))
		}
		return records, recoveryPageSize + 1, true
	}
	if fixture.scenario == reconcilePostMutation && fixture.mutations == 0 ||
		fixture.scenario == reconcileCompleteEmptyPage || fixture.scenario == reconcileMissingMetadata {
		return nil, 0, fixture.scenario != reconcileMissingMetadata
	}
	if fixture.scenario == reconcileInvalidIdentity {
		return []map[string]any{fixture.record("target", 0, true, true)}, 1, true
	}
	records := make([]map[string]any, 0, recoveryPageSize)
	if page == 1 {
		count := recoveryPageSize
		if fixture.scenario == reconcileDuplicateTarget || fixture.scenario == reconcileConflictingID {
			count--
			id := "target"
			target := fixture.scenario == reconcileDuplicateTarget
			records = append(records, fixture.record(id, 0, target, false))
		}
		for index := 0; index < count; index++ {
			records = append(records, fixture.record(fmt.Sprintf("filler-%d", index), index+1, false, false))
		}
		return records, recoveryPageSize + 1, true
	}
	id := "target"
	if fixture.scenario == reconcileDuplicateTarget {
		id = "target-duplicate"
	}
	total := recoveryPageSize + 1
	metadata := true
	if fixture.scenario == reconcileMetadataDrift {
		total++
	}
	return []map[string]any{fixture.record(id, 0, true, false)}, total, metadata
}

func (fixture *reconcileHTTPFixture) literalRecordType() string {
	if fixture.recordType == "" {
		return "A"
	}
	return fixture.recordType
}

func (fixture *reconcileHTTPFixture) literalDNSLAType() string {
	switch fixture.literalRecordType() {
	case "AAAA":
		return "28"
	case "CNAME":
		return "5"
	default:
		return "1"
	}
}

func (fixture *reconcileHTTPFixture) record(id string, index int, target, invalid bool) map[string]any {
	return reconcileHTTPRecordForType(fixture.provider, id, index, target, invalid,
		fixture.literalRecordType(), fixture.targetValue)
}

func reconcileHTTPRecord(provider, id string, index int, target, invalid bool) map[string]any {
	return reconcileHTTPRecordForType(provider, id, index, target, invalid, "A", "192.0.2.10")
}

func reconcileHTTPRecordForType(provider, id string, index int, target, invalid bool,
	recordType, targetValue string) map[string]any {
	relative := fmt.Sprintf("other-%d", index)
	owner := relative + "." + testZone + "."
	value := fmt.Sprintf("192.0.2.%d", index%200+20)
	switch recordType {
	case "AAAA":
		value = fmt.Sprintf("2001:db8::%x", index%200+20)
	case "CNAME":
		value = fmt.Sprintf("other-%d.edge.example.net.", index)
	}
	if target {
		if targetValue == "" {
			targetValue = "192.0.2.10"
		}
		relative, owner, value = "www", "www."+testZone+".", targetValue
	}
	if invalid {
		relative, owner = "www.", "www."+testZone+".."
	}
	switch provider {
	case providerCloudflare:
		return map[string]any{"id": id, "zone_id": "zone-cf", "name": owner, "type": recordType, "content": value, "ttl": 300}
	case providerAliyun:
		return map[string]any{"RecordId": id, "RR": relative, "Type": recordType, "Value": value, "TTL": 300}
	case providerHuawei:
		return map[string]any{"id": id, "zone_id": "zone-hw", "name": owner, "type": recordType, "records": []string{value}, "ttl": 300}
	case providerDNSPodCN:
		return map[string]any{"id": id, "name": relative, "type": recordType, "value": value, "ttl": "300", "line": "默认"}
	case providerDNSCom:
		return map[string]any{"domain_id": "zone-dnscom", "record_id": id, "record": relative, "type": recordType, "value": value, "ttl": 300}
	case providerDNSLA:
		typeCode := 1
		if recordType == "AAAA" {
			typeCode = 28
		} else if recordType == "CNAME" {
			typeCode = 5
		}
		return map[string]any{"id": id, "domainId": "zone-dnsla", "host": relative, "type": typeCode, "data": value, "ttl": 300}
	default:
		return nil
	}
}

func (fixture *reconcileHTTPFixture) writeListResponse(w http.ResponseWriter, page, total int,
	records []map[string]any, metadata bool) {
	switch fixture.provider {
	case providerCloudflare:
		response := map[string]any{"success": true, "result": records}
		if metadata {
			totalPages := (total + recoveryPageSize - 1) / recoveryPageSize
			response["result_info"] = map[string]any{
				"page": page, "per_page": recoveryPageSize, "count": len(records),
				"total_count": total, "total_pages": totalPages,
			}
		}
		writeTestJSON(fixture.t, w, response)
	case providerAliyun:
		response := map[string]any{"RequestId": "request-list", "DomainRecords": map[string]any{"Record": records}}
		if metadata {
			response["TotalCount"], response["PageNumber"], response["PageSize"] = total, page, recoveryPageSize
		}
		writeTestJSON(fixture.t, w, response)
	case providerHuawei:
		response := map[string]any{"recordsets": records}
		if metadata {
			next := ""
			if page*recoveryPageSize < total {
				next = "https://dns.example/recordsets?offset=" + strconv.Itoa(page*recoveryPageSize)
			}
			response["metadata"] = map[string]any{"total_count": total}
			response["links"] = map[string]any{"next": next}
		}
		writeTestJSON(fixture.t, w, response)
	case providerDNSPodCN:
		response := map[string]any{"status": map[string]any{"code": "1"}, "records": records}
		if metadata {
			count := len(records)
			if fixture.scenario == reconcileMetadataDrift && page == 2 {
				count++
			}
			response["info"] = map[string]any{"records_num": strconv.Itoa(count)}
		}
		writeTestJSON(fixture.t, w, response)
	case providerDNSCom:
		data := map[string]any{"data": records}
		if metadata {
			data["total"] = total
		}
		writeTestJSON(fixture.t, w, map[string]any{"code": 0, "data": data})
	case providerDNSLA:
		data := map[string]any{"results": records}
		if metadata {
			data["total"] = total
		}
		writeTestJSON(fixture.t, w, map[string]any{"code": 200, "data": data})
	}
}

func (fixture *reconcileHTTPFixture) isCreate(r *http.Request) bool {
	switch fixture.provider {
	case providerCloudflare:
		return r.Method == http.MethodPost && r.URL.Path == "/zones/zone-cf/dns_records"
	case providerAliyun:
		return r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Get("Action") == "AddDomainRecord"
	case providerHuawei:
		return r.Method == http.MethodPost && r.URL.Path == "/v2.1/zones/zone-hw/recordsets"
	case providerDNSPodCN:
		return r.Method == http.MethodPost && r.URL.Path == "/Record.Create"
	case providerDNSCom:
		return r.Method == http.MethodGet && r.URL.Path == "/api/record/create/"
	case providerDNSLA:
		return r.Method == http.MethodPost && r.URL.Path == "/api/record"
	default:
		return false
	}
}

func (fixture *reconcileHTTPFixture) writeCreateResponse(w http.ResponseWriter) {
	switch fixture.provider {
	case providerCloudflare:
		writeTestJSON(fixture.t, w, map[string]any{"success": true, "result": map[string]any{"id": "target"}})
	case providerAliyun:
		writeTestJSON(fixture.t, w, map[string]any{"RequestId": "request-create", "RecordId": "target"})
	case providerHuawei:
		writeTestJSON(fixture.t, w, reconcileHTTPRecord(providerHuawei, "target", 0, true, false))
	case providerDNSPodCN:
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"}, "record": map[string]any{"id": "target"},
		})
	case providerDNSCom:
		writeTestJSON(fixture.t, w, map[string]any{
			"code": 0, "data": reconcileHTTPRecord(providerDNSCom, "target", 0, true, false),
		})
	case providerDNSLA:
		writeTestJSON(fixture.t, w, map[string]any{"code": 200, "data": map[string]any{"id": "target"}})
	}
}

func TestReconcileHTTPFixtureUsesCanonicalListQueries(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		t.Run(provider, func(t *testing.T) {
			fixture, adapter, config := newReconcileHTTPAdapter(t, provider, reconcileCompleteEmptyPage)
			remote := &providerReconcileRemote{adapter: adapter}
			_, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300,
			})
			if err != nil || fixture.pageCalls != 1 {
				t.Fatalf("pageCalls=%d error=%v", fixture.pageCalls, err)
			}
		})
	}
}

func TestHuaweiReconcileDeleteAcceptsDocumentedStatuses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{name: "empty 200", status: http.StatusOK, valid: true},
		{name: "empty 202", status: http.StatusAccepted, valid: true},
		{name: "empty 204", status: http.StatusNoContent, valid: true},
		{name: "empty 404", status: http.StatusNotFound, valid: true},
		{name: "non-empty 200", status: http.StatusOK, body: `{}`},
		{name: "non-empty 202", status: http.StatusAccepted, body: `{}`},
		{name: "non-empty 404 provider error", status: http.StatusNotFound, body: `{"error_code":"DNS.0001"}`},
		{name: "unsupported 201", status: http.StatusCreated},
	} {
		t.Run(test.name, func(t *testing.T) {
			deleteCalls := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get("X-Project-Id") != "0123456789abcdef0123456789abcdef" ||
					!verifyRound3HuaweiSignature(request, "provider-key", "provider-secret") {
					t.Errorf("invalid Huawei authentication for %s %s", request.Method, request.URL.RequestURI())
				}
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/v2/zones":
					if request.URL.Query().Get("name") != "example.test." || request.URL.Query().Get("type") != "public" {
						t.Errorf("zone query=%s", request.URL.RawQuery)
					}
					writeTestJSON(t, w, map[string]any{"zones": []any{
						map[string]any{"id": "zone-hw", "name": "example.test."},
					}})
				case request.Method == http.MethodGet && request.URL.Path == "/v2.1/zones/zone-hw/recordsets/target":
					writeTestJSON(t, w, map[string]any{"id": "target", "zone_id": "zone-hw", "name": "www.example.test.",
						"type": "A", "ttl": 300, "records": []string{"192.0.2.10"}})
				case request.Method == http.MethodDelete &&
					request.URL.Path == "/v2.1/zones/zone-hw/recordsets/target":
					deleteCalls++
					w.WriteHeader(test.status)
					_, _ = w.Write([]byte(test.body))
				default:
					t.Errorf("unexpected Huawei request %s %s", request.Method, request.URL.RequestURI())
					w.WriteHeader(http.StatusNotFound)
				}
			})
			config := reconcileHTTPProviderConfig(providerHuawei)
			adapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
			result, err := (&providerReconcileRemote{adapter: adapter}).Mutate(t.Context(), completeTestConfig(config),
				dnscheck.ProviderOperation{
					Action: dnscheck.ProviderDelete, RecordID: "target", Name: "www.example.test.",
					Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
				})
			if test.valid && (err != nil || result != "target" || deleteCalls != 1) {
				t.Fatalf("Mutate()=(%q,%v), deleteCalls=%d", result, err, deleteCalls)
			}
			if !test.valid && (ErrorCodeOf(err) != CodeInvalidResponse || deleteCalls != 1) {
				t.Fatalf("invalid status Mutate()=(%q,%v), deleteCalls=%d", result, err, deleteCalls)
			}
		})
	}
}

func TestLookupRecordOperationStateMachine(t *testing.T) {
	previous := reconcileRecord{ID: "record-1", Name: "www.example.test.", Type: "A", Value: "192.0.2.9", TTL: 300}
	desired := reconcileRecord{ID: "record-1", Name: "www.example.test.", Type: "A", Value: "192.0.2.10", TTL: 300}
	base := dnscheck.ProviderOperation{
		RecordID: "record-1", Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", PreviousValue: "192.0.2.9", TTL: 300, PreviousTTL: 300,
	}
	for _, provider := range reconcileHTTPProviders {
		for _, test := range []struct {
			name      string
			action    dnscheck.ProviderAction
			records   []reconcileRecord
			complete  bool
			conflict  bool
			ambiguous bool
			recordID  string
		}{
			{name: "create absent mutates", action: dnscheck.ProviderCreate},
			{name: "create replay", action: dnscheck.ProviderCreate, records: []reconcileRecord{desired}, complete: true, recordID: "record-1"},
			{name: "create duplicate", action: dnscheck.ProviderCreate, records: []reconcileRecord{desired, {ID: "record-2", Name: desired.Name, Type: desired.Type, Value: desired.Value, TTL: desired.TTL}}, ambiguous: true},
			{name: "update previous mutates", action: dnscheck.ProviderUpdate, records: []reconcileRecord{previous}},
			{name: "update replay", action: dnscheck.ProviderUpdate, records: []reconcileRecord{desired}, complete: true, recordID: "record-1"},
			{name: "update absent", action: dnscheck.ProviderUpdate, conflict: true},
			{name: "update wrong value", action: dnscheck.ProviderUpdate, records: []reconcileRecord{{ID: "record-1", Name: desired.Name, Type: desired.Type, Value: "192.0.2.8", TTL: 300}}, conflict: true, recordID: "record-1"},
			{name: "delete exact mutates", action: dnscheck.ProviderDelete, records: []reconcileRecord{desired}},
			{name: "delete replay", action: dnscheck.ProviderDelete, complete: true, recordID: "record-1"},
			{name: "delete wrong value", action: dnscheck.ProviderDelete, records: []reconcileRecord{previous}, conflict: true, recordID: "record-1"},
		} {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				operation := base
				operation.Action = test.action
				got := lookupRecord(test.records, operation)
				if got.TargetComplete != test.complete || got.Conflict != test.conflict ||
					got.Ambiguous != test.ambiguous || got.RecordID != test.recordID {
					t.Fatalf("lookupRecord() = %+v", got)
				}
			})
		}
	}
}

func TestProviderReconcileRejectsInvalidAuthorityAndValuesBeforeHTTP(t *testing.T) {
	tests := []struct {
		name      string
		zone      string
		operation dnscheck.ProviderOperation
	}{
		{name: "out of zone", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.other.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}},
		{name: "noncanonical owner", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "WWW.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}},
		{name: "empty owner", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}},
		{name: "noncanonical ipv4", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.000.2.10", TTL: 300}},
		{name: "noncanonical ipv6", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordAAAA, Value: "2001:0db8::1", TTL: 300}},
		{name: "cname without trailing dot", zone: "example.test", operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordCNAME, Value: "edge.example.net", TTL: 300}},
	}
	for _, provider := range reconcileHTTPProviders {
		for _, test := range tests {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				var calls atomic.Int32
				transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				})
				config := completeTestConfig(reconcileHTTPProviderConfig(provider))
				config.ZoneName = test.zone
				adapter := newAdapter(nil, nil, transport, productionEndpoints(), time.Second, nil, nil)
				remote := &providerReconcileRemote{adapter: adapter}
				_, err := remote.Lookup(t.Context(), config, test.operation)
				if err == nil || calls.Load() != 0 {
					t.Fatalf("Lookup() error=%v provider calls=%d", err, calls.Load())
				}
			})
		}
	}
}

func TestReconcileAdapterRequiresStableRepeatedLookupBeforeMutation(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		t.Run(provider, func(t *testing.T) {
			authority := newReconcileHTTPAuthority(completeTestConfig(reconcileHTTPProviderConfig(provider)), 7)
			remote := &fakeReconcileRemote{lookup: []ReconcileLookup{
				{RecordID: "scan-fingerprint-a"},
				{RecordID: "scan-fingerprint-b"},
			}}
			adapter, err := NewReconcileAdapter(authority, remote)
			if err != nil {
				t.Fatal(err)
			}
			_, err = adapter.Mutate(t.Context(), dnscheck.ProviderMutation{
				ClientRequestID: "stable-scan-" + provider, TenantID: uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7,
				Operation: dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300},
			})
			if err == nil || remote.mutate != 0 {
				t.Fatalf("Mutate() error=%v provider mutations=%d", err, remote.mutate)
			}
		})
	}
}

func TestReconcileLookupDigestIgnoresProviderOrderButPreservesPageIdentity(t *testing.T) {
	operation := dnscheck.ProviderOperation{
		Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 300,
	}
	first := reconcileRecord{
		ID: "record-1", Name: operation.Name, Type: "A", Value: "192.0.2.20", TTL: 300, Page: 1,
	}
	second := reconcileRecord{
		ID: "record-2", Name: operation.Name, Type: "A", Value: "192.0.2.21", TTL: 300, Page: 1,
	}
	forward := reconcileLookupDigest([]reconcileRecord{first, second}, operation, []string{"complete-scan"})
	reversed := reconcileLookupDigest([]reconcileRecord{second, first}, operation, []string{"complete-scan"})
	if forward != reversed {
		t.Fatal("equivalent provider record ordering changed the snapshot digest")
	}
	second.Page = 2
	if moved := reconcileLookupDigest([]reconcileRecord{first, second}, operation, []string{"complete-scan"}); moved == forward {
		t.Fatal("cross-page record movement did not change the snapshot digest")
	}
}

func TestProviderReconcileRemoteRejectsInvalidOperationBeforeHTTP(t *testing.T) {
	base := dnscheck.ProviderOperation{
		Action: dnscheck.ProviderUpdate, RecordID: "record-1", Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
		PreviousValue: "192.0.2.9", PreviousTTL: 300,
	}
	invalid := []struct {
		name      string
		operation dnscheck.ProviderOperation
	}{
		{name: "unknown action", operation: func() dnscheck.ProviderOperation {
			value := base
			value.Action = dnscheck.ProviderAction("replace")
			return value
		}()},
		{name: "zero ttl", operation: func() dnscheck.ProviderOperation {
			value := base
			value.TTL = 0
			return value
		}()},
		{name: "excessive ttl", operation: func() dnscheck.ProviderOperation {
			value := base
			value.TTL = 7*24*60*60 + 1
			return value
		}()},
		{name: "update without record id", operation: func() dnscheck.ProviderOperation {
			value := base
			value.RecordID = ""
			return value
		}()},
		{name: "delete without record id", operation: func() dnscheck.ProviderOperation {
			value := base
			value.Action = dnscheck.ProviderDelete
			value.RecordID = ""
			value.PreviousValue = ""
			value.PreviousTTL = 0
			return value
		}()},
	}
	for _, provider := range reconcileHTTPProviders {
		for _, test := range invalid {
			t.Run(provider+"/"+test.name, func(t *testing.T) {
				var calls atomic.Int32
				transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return &http.Response{
						StatusCode: http.StatusOK, Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader(`{}`)),
					}, nil
				})
				remote := &providerReconcileRemote{adapter: newAdapter(
					nil, nil, transport, productionEndpoints(), time.Second, nil, nil,
				)}
				config := completeTestConfig(reconcileHTTPProviderConfig(provider))
				_, lookupErr := remote.Lookup(t.Context(), config, test.operation)
				_, mutateErr := remote.Mutate(t.Context(), config, test.operation)
				if !isCode(lookupErr, CodeInvalidInput) || !isCode(mutateErr, CodeInvalidInput) || calls.Load() != 0 {
					t.Fatalf("Lookup/Mutate errors=(%v,%v), provider calls=%d", lookupErr, mutateErr, calls.Load())
				}
			})
		}
	}
}

func TestReconcileProviderUpdateDeleteUseRealProviderShapes(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, record := range []struct {
			name, value, previous string
			typeValue             dnscheck.RecordType
		}{
			{name: "A", typeValue: dnscheck.RecordA, value: "192.0.2.10", previous: "192.0.2.9"},
			{name: "AAAA", typeValue: dnscheck.RecordAAAA, value: "2001:db8::10", previous: "2001:db8::9"},
			{name: "CNAME", typeValue: dnscheck.RecordCNAME, value: "edge.example.net.", previous: "old.example.net."},
		} {
			for _, action := range []dnscheck.ProviderAction{
				dnscheck.ProviderCreate, dnscheck.ProviderUpdate, dnscheck.ProviderDelete,
			} {
				t.Run(provider+"/"+record.name+"/"+string(action), func(t *testing.T) {
					fixture := &reconcileMutationShapeFixture{
						t: t, provider: provider, action: action, recordType: record.name,
						value: record.value, previousValue: record.previous,
					}
					config := reconcileHTTPProviderConfig(provider)
					adapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
					remote := &providerReconcileRemote{adapter: adapter}
					operation := dnscheck.ProviderOperation{
						Action: action, RecordID: "target", Name: "www.example.test.", Type: record.typeValue,
						Value: record.value, TTL: 300, PreviousValue: record.previous, PreviousTTL: 300,
					}
					if action == dnscheck.ProviderCreate {
						operation.RecordID, operation.PreviousValue, operation.PreviousTTL = "", "", 0
					}
					if provider == providerDNSCom && action != dnscheck.ProviderCreate {
						lookup, lookupErr := remote.Lookup(t.Context(), completeTestConfig(config), operation)
						if lookupErr != nil || lookup.TargetComplete || lookup.Conflict || lookup.Ambiguous {
							t.Fatalf("DNS.COM pre-mutation lookup=(%+v,%v)", lookup, lookupErr)
						}
					}
					result, err := remote.Mutate(t.Context(), completeTestConfig(config), operation)
					if err != nil || result != "target" || fixture.mutations != 1 {
						t.Fatalf("Mutate()=(%q,%v), mutations=%d", result, err, fixture.mutations)
					}
				})
			}
		}
	}
}

func TestReconcileProviderMalformedSuccessfulMutationResponseIsUnknown(t *testing.T) {
	for _, provider := range reconcileHTTPProviders {
		for _, action := range []dnscheck.ProviderAction{
			dnscheck.ProviderCreate, dnscheck.ProviderUpdate, dnscheck.ProviderDelete,
		} {
			for _, mode := range []string{"malformed_json", "unreadable", "schema_invalid", "oversized"} {
				t.Run(provider+"/"+string(action)+"/"+mode, func(t *testing.T) {
					fixture := &reconcileMutationShapeFixture{
						t: t, provider: provider, action: action, recordType: "A",
						value: "192.0.2.10", previousValue: "192.0.2.9", malformedMode: mode,
					}
					config := reconcileHTTPProviderConfig(provider)
					providerAdapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
					operation := dnscheck.ProviderOperation{
						Action: action, RecordID: "target", Name: "www.example.test.", Type: dnscheck.RecordA,
						Value: "192.0.2.10", TTL: 300, PreviousValue: "192.0.2.9", PreviousTTL: 300,
					}
					if action == dnscheck.ProviderCreate {
						operation.RecordID, operation.PreviousValue, operation.PreviousTTL = "", "", 0
					}
					authority := &malformedAppliedAuthority{
						revision: 7, config: completeTestConfig(config),
						recoveryNotBefore: time.Now().Add(MutationVisibilityWindow),
					}
					remote := &malformedHTTPReconcileRemote{
						provider: &providerReconcileRemote{adapter: providerAdapter},
						lookups:  []ReconcileLookup{{}, {}, {TargetComplete: true, RecordID: "target"}},
					}
					adapter, err := NewReconcileAdapter(authority, remote)
					if err != nil {
						t.Fatal(err)
					}
					mutation := dnscheck.ProviderMutation{
						ClientRequestID: provider + "-" + string(action) + "-" + mode,
						TenantID:        uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(), ExpectedRevision: 7,
						Operation: operation,
					}
					_, firstErr := adapter.Mutate(t.Context(), mutation)
					var providerErr *dnscheck.ProviderError
					if !errors.As(firstErr, &providerErr) || providerErr.Class != dnscheck.ProviderErrorTransient ||
						providerErr.Code != "provider_recovery_pending" || authority.state != MutationUncertain ||
						fixture.mutations != 1 {
						t.Fatalf("first Mutate() error=%v state=%s mutations=%d", firstErr, authority.state, fixture.mutations)
					}
					if _, err := adapter.Mutate(t.Context(), mutation); err == nil || fixture.mutations != 1 || len(remote.lookups) != 1 {
						t.Fatalf("early recovery error=%v mutations=%d lookups=%d", err, fixture.mutations, len(remote.lookups))
					}
					authority.recoveryReady = true
					result, err := adapter.Mutate(t.Context(), mutation)
					if err != nil || result.RecordID != "target" || result.Revision != 8 || fixture.mutations != 1 {
						t.Fatalf("delayed recovery=(%+v,%v) mutations=%d", result, err, fixture.mutations)
					}
				})
			}
		}
	}
}

type malformedHTTPReconcileRemote struct {
	provider *providerReconcileRemote
	lookups  []ReconcileLookup
}

func (remote *malformedHTTPReconcileRemote) Lookup(context.Context, ProviderConfig,
	dnscheck.ProviderOperation) (ReconcileLookup, error) {
	if len(remote.lookups) == 0 {
		return ReconcileLookup{}, errors.New("unexpected malformed-response recovery lookup")
	}
	result := remote.lookups[0]
	remote.lookups = remote.lookups[1:]
	return result, nil
}

func (remote *malformedHTTPReconcileRemote) Mutate(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	return remote.provider.Mutate(ctx, config, operation)
}

type reconcileMutationShapeFixture struct {
	t             *testing.T
	provider      string
	action        dnscheck.ProviderAction
	recordType    string
	value         string
	previousValue string
	malformedMode string
	mutations     int
}

func (fixture *reconcileMutationShapeFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zoneFixture := &reconcileHTTPFixture{t: fixture.t, provider: fixture.provider}
	if zoneFixture.writeZoneResponse(w, r) {
		return
	}
	assert := func(ok bool, message string) {
		fixture.t.Helper()
		if !ok {
			fixture.t.Errorf("%s: %s %s", message, r.Method, r.URL.RequestURI())
		}
	}
	if fixture.provider == providerDNSCom && r.Method == http.MethodGet && r.URL.Path == "/api/record/lists/" {
		query := r.URL.Query()
		assert(query.Get("domain") == testZone && query.Get("record") == "www" &&
			query.Get("type") == fixture.recordType && query.Get("page") == "1" &&
			query.Get("paginate") == "100" && query.Get("page_size") == "" && query.Get("api_key") == "provider-key" &&
			query.Get("sign") != "", "dns.com domain-id list")
		writeTestJSON(fixture.t, w, map[string]any{"code": 0, "data": map[string]any{
			"total": 1, "data": []any{fixture.responseRecord(fixture.lookupValue())},
		}})
		return
	}
	// Huawei rewrites the owner's record set: it reads the set first
	// (by ID for update/delete, by exact name for create).
	if fixture.provider == providerHuawei && r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/v2.1/zones/zone-hw/recordsets/target":
			writeTestJSON(fixture.t, w, fixture.responseRecord(fixture.lookupValue()))
			return
		case "/v2.1/zones/zone-hw/recordsets":
			assert(r.URL.Query().Get("search_mode") == "equal", "huawei exact list")
			writeTestJSON(fixture.t, w, map[string]any{"recordsets": []any{}, "metadata": map[string]any{"total_count": 0},
				"links": map[string]any{"next": ""}})
			return
		}
	}
	if fixture.provider == providerDNSCom && r.Method == http.MethodGet && r.URL.Path == "/api/record/getOne/" {
		query := r.URL.Query()
		assert(query.Get("domain") == "zone-dnscom" && query.Get("record_id") == "target" &&
			query.Get("api_key") == "provider-key" && query.Get("sign") != "", "dns.com domain-id get")
		writeTestJSON(fixture.t, w, map[string]any{"code": 0, "data": fixture.responseRecord(fixture.lookupValue())})
		return
	}
	switch fixture.provider {
	case providerCloudflare:
		method, path := http.MethodPost, "/zones/zone-cf/dns_records"
		if fixture.action == dnscheck.ProviderUpdate {
			method, path = http.MethodPut, path+"/target"
		} else if fixture.action == dnscheck.ProviderDelete {
			method, path = http.MethodDelete, path+"/target"
		}
		assert(r.Method == method && r.URL.Path == path, "cloudflare method/path")
		assert(r.Header.Get("Authorization") == "Bearer provider-token", "cloudflare bearer")
		if fixture.action != dnscheck.ProviderDelete {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				fixture.t.Fatal(err)
			}
			assert(body["name"] == "www.example.test." && body["type"] == fixture.recordType &&
				body["content"] == fixture.providerValue() && body["ttl"] == float64(300), "cloudflare body")
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		writeTestJSON(fixture.t, w, map[string]any{"success": true, "result": map[string]any{"id": "target"}})
	case providerAliyun:
		wantAction := "AddDomainRecord"
		if fixture.action == dnscheck.ProviderUpdate {
			wantAction = "UpdateDomainRecord"
		} else if fixture.action == dnscheck.ProviderDelete {
			wantAction = "DeleteDomainRecord"
		}
		query := r.URL.Query()
		assert(r.Method == http.MethodGet && r.URL.Path == "/" && query.Get("Action") == wantAction, "aliyun action")
		assert(query.Get("AccessKeyId") == "provider-key" && query.Get("Signature") != "", "aliyun auth")
		if fixture.action == dnscheck.ProviderCreate {
			assert(query.Get("DomainName") == testZone, "aliyun create domain")
		} else {
			assert(query.Get("RecordId") == "target", "aliyun record id")
		}
		if fixture.action != dnscheck.ProviderDelete {
			assert(query.Get("RR") == "www" && query.Get("Type") == fixture.recordType &&
				query.Get("Value") == fixture.providerValue() && query.Get("TTL") == "300", "aliyun fields")
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		writeTestJSON(fixture.t, w, map[string]any{"RequestId": "request-mutate", "RecordId": "target"})
	case providerHuawei:
		method, path := http.MethodPost, "/v2.1/zones/zone-hw/recordsets"
		if fixture.action == dnscheck.ProviderUpdate {
			method, path = http.MethodPut, path+"/target"
		} else if fixture.action == dnscheck.ProviderDelete {
			method, path = http.MethodDelete, path+"/target"
		}
		assert(r.Method == method && r.URL.Path == path, "huawei method/path")
		assert(strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 ") &&
			r.Header.Get("X-Project-Id") == "0123456789abcdef0123456789abcdef", "huawei signing")
		if fixture.action != dnscheck.ProviderDelete {
			var body struct {
				Name    string   `json:"name"`
				Type    string   `json:"type"`
				TTL     uint32   `json:"ttl"`
				Records []string `json:"records"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name != "www.example.test." ||
				body.Type != fixture.recordType || body.TTL != 300 || len(body.Records) != 1 ||
				body.Records[0] != fixture.providerValue() {
				fixture.t.Errorf("huawei body=%+v", body)
			}
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		if fixture.action == dnscheck.ProviderDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeTestJSON(fixture.t, w, fixture.responseRecord(fixture.value))
	case providerDNSPodCN:
		wantPath := "/Record.Create"
		if fixture.action == dnscheck.ProviderUpdate {
			wantPath = "/Record.Modify"
		} else if fixture.action == dnscheck.ProviderDelete {
			wantPath = "/Record.Remove"
		}
		_ = r.ParseForm()
		assert(r.Method == http.MethodPost && r.URL.Path == wantPath, "dnspod method/path")
		assert(r.Form.Get("login_token") == "12345,provider-secret" && r.Form.Get("domain") == testZone, "dnspod auth/domain")
		if fixture.action != dnscheck.ProviderCreate {
			assert(r.Form.Get("record_id") == "target", "dnspod record id")
		}
		if fixture.action != dnscheck.ProviderDelete {
			assert(r.Form.Get("sub_domain") == "www" && r.Form.Get("record_type") == fixture.recordType &&
				r.Form.Get("record_line") == "默认" && r.Form.Get("value") == fixture.providerValue() &&
				r.Form.Get("ttl") == "300", "dnspod fields")
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		writeTestJSON(fixture.t, w, map[string]any{"status": map[string]any{"code": "1"}, "record": map[string]any{"id": "target"}})
	case providerDNSCom:
		wantPath := "/api/record/create/"
		if fixture.action == dnscheck.ProviderUpdate {
			wantPath = "/api/record/update/"
		} else if fixture.action == dnscheck.ProviderDelete {
			wantPath = "/api/record/operate/"
		}
		query := r.URL.Query()
		assert(r.Method == http.MethodGet && r.URL.Path == wantPath, "dns.com method/path")
		wantDomain := testZone
		if fixture.action != dnscheck.ProviderCreate {
			wantDomain = "zone-dnscom"
		}
		assert(query.Get("api_key") == "provider-key" && query.Get("sign") != "" &&
			query.Get("domain") == wantDomain, "dns.com auth/domain")
		if fixture.action != dnscheck.ProviderCreate {
			assert(query.Get("record_id") == "target", "dns.com record id")
		}
		if fixture.action != dnscheck.ProviderDelete {
			assert(query.Get("record") == "www" && query.Get("type") == fixture.recordType &&
				query.Get("value") == fixture.providerValue() && query.Get("ttl") == "300", "dns.com fields")
		} else {
			assert(query.Get("status") == "delete", "dns.com delete status")
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		writeTestJSON(fixture.t, w, map[string]any{"code": 0, "data": fixture.responseRecord(fixture.value)})
	case providerDNSLA:
		method, path := http.MethodPost, "/api/record"
		if fixture.action == dnscheck.ProviderUpdate {
			method, path = http.MethodPut, "/api/record?id=target"
		} else if fixture.action == dnscheck.ProviderDelete {
			method, path = http.MethodDelete, "/api/record?id=target"
		}
		assert(r.Method == method && r.URL.RequestURI() == path, "dns.la method/path")
		assert(r.Header.Get("Authorization") == "Basic "+basicAuth("provider-id", "provider-secret"), "dns.la basic auth")
		if fixture.action != dnscheck.ProviderDelete {
			var body struct {
				DomainID string `json:"domainId"`
				Type     int    `json:"type"`
				Host     string `json:"host"`
				Data     string `json:"data"`
				TTL      uint32 `json:"ttl"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.DomainID != "zone-dnsla" ||
				body.Type != fixture.dnsLAType() || body.Host != "www" || body.Data != fixture.providerValue() || body.TTL != 300 {
				fixture.t.Errorf("dns.la body=%+v", body)
			}
		}
		fixture.mutations++
		if fixture.writeMalformedSuccess(w) {
			return
		}
		writeTestJSON(fixture.t, w, map[string]any{"code": 200, "data": map[string]any{"id": "target"}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fixture *reconcileMutationShapeFixture) writeMalformedSuccess(w http.ResponseWriter) bool {
	if fixture.malformedMode == "" {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	switch fixture.malformedMode {
	case "malformed_json":
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{")
	case "unreadable":
		w.Header().Set("Content-Length", "128")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{")
	case "schema_invalid":
		writeTestJSON(fixture.t, w, map[string]any{})
	case "oversized":
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", responseBodyLimit+1))
	default:
		fixture.t.Fatalf("unknown malformed response mode %q", fixture.malformedMode)
	}
	return true
}

func (fixture *reconcileMutationShapeFixture) providerValue() string {
	return strings.TrimSuffix(fixture.value, ".")
}

func (fixture *reconcileMutationShapeFixture) lookupValue() string {
	if fixture.action == dnscheck.ProviderUpdate {
		return fixture.previousValue
	}
	return fixture.value
}

func (fixture *reconcileMutationShapeFixture) dnsLAType() int {
	switch fixture.recordType {
	case "AAAA":
		return 28
	case "CNAME":
		return 5
	default:
		return 1
	}
}

func (fixture *reconcileMutationShapeFixture) responseRecord(value string) map[string]any {
	providerValue := strings.TrimSuffix(value, ".")
	switch fixture.provider {
	case providerHuawei:
		return map[string]any{"id": "target", "zone_id": "zone-hw", "name": "www.example.test.",
			"type": fixture.recordType, "records": []string{providerValue}, "ttl": 300}
	case providerDNSCom:
		return map[string]any{"domain_id": "zone-dnscom", "record_id": "target", "record": "www",
			"type": fixture.recordType, "value": providerValue, "ttl": 300}
	default:
		return nil
	}
}

func verifyRound3AliyunSignature(values url.Values, secret string) bool {
	provided := values.Get("Signature")
	keys := make([]string, 0, len(values)-1)
	for key, entries := range values {
		if key != "Signature" && len(entries) == 1 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, round3RFC3986(key)+"="+round3RFC3986(values.Get(key)))
	}
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = mac.Write([]byte("GET&%2F&" + round3RFC3986(strings.Join(parts, "&"))))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return provided != "" && hmac.Equal([]byte(provided), []byte(want))
}

func round3RFC3986(value string) string {
	const digits = "0123456789ABCDEF"
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-_.~", rune(character)) {
			result.WriteByte(character)
			continue
		}
		result.WriteByte('%')
		result.WriteByte(digits[character>>4])
		result.WriteByte(digits[character&0x0f])
	}
	return result.String()
}

func verifyRound3HuaweiSignature(request *http.Request, accessKey, secretKey string) bool {
	timestamp := request.Header.Get("X-Sdk-Date")
	payloadDigest := sha256.Sum256(nil)
	canonicalURI := request.URL.EscapedPath()
	if !strings.HasSuffix(canonicalURI, "/") {
		canonicalURI += "/"
	}
	projectID := request.Header.Get("X-Project-Id")
	canonical := request.Method + "\n" + canonicalURI + "\n" + request.URL.Query().Encode() +
		"\nhost:" + request.Host + "\nx-project-id:" + projectID + "\nx-sdk-date:" + timestamp +
		"\n\nhost;x-project-id;x-sdk-date\n" + hex.EncodeToString(payloadDigest[:])
	canonicalDigest := sha256.Sum256([]byte(canonical))
	stringToSign := "SDK-HMAC-SHA256\n" + timestamp + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	want := "SDK-HMAC-SHA256 Access=" + accessKey + ", SignedHeaders=host;x-project-id;x-sdk-date, Signature=" +
		hex.EncodeToString(mac.Sum(nil))
	return request.Header.Get("Authorization") == want
}

func verifyRound3DNSComSignature(values url.Values, secret string) bool {
	keys := make([]string, 0, len(values)-1)
	for key, entries := range values {
		if key != "sign" && len(entries) == 1 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values.Get(key))
	}
	digest := md5.Sum([]byte(strings.Join(parts, "&") + secret))
	return values.Get("sign") == hex.EncodeToString(digest[:])
}

var _ http.Handler = (*reconcileHTTPFixture)(nil)
var _ http.Handler = (*reconcileMutationShapeFixture)(nil)
var _ RevisionAuthority = (*reconcileHTTPAuthority)(nil)
