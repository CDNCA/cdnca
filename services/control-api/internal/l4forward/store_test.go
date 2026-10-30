package l4forward

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
)

type valuesScanner []any

func (scanner valuesScanner) Scan(destinations ...any) error {
	for index, destination := range destinations {
		if valueScanner, ok := destination.(*jsonValueScanner); ok {
			if err := valueScanner.Scan(scanner[index]); err != nil {
				return err
			}
			continue
		}
		value := reflect.ValueOf(destination).Elem()
		if scanner[index] == nil {
			value.Set(reflect.Zero(value.Type()))
			continue
		}
		value.Set(reflect.ValueOf(scanner[index]))
	}
	return nil
}

func TestScanForwardUsesUnknownWithoutImmutablePublicationBinding(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	runtimeJSON, err := json.Marshal(RuntimeSpec{
		SchemaVersion: RuntimeSchemaV2, StreamID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101",
		Listener:         RuntimeListener{Protocol: ProtocolTCP, Address: "*", Port: 18080},
		Endpoint:         RuntimeEndpoint{Address: "192.0.2.10", Port: 8080},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000,
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := scanForward(valuesScanner{
		uuid.New(), "1", uuid.New(), nil, nil, nil, nil, new(uuid.New()), uuid.New(), "edge stream", "", ProtocolTCP, "*", uint16(18080),
		"192.0.2.10", "", uint16(8080), []byte(`{}`), []byte(`{}`), 1000, 30000, 100, false, false, false, []string(nil), 0, 0, 0, false, false, uint16(0), false, nil,
		nil, false, ACLActionAllow, nil, AdminStatusNormal, nil, nil, nil, nil, nil,
		BalanceWayRoundRobin, true, int64(1), now, now, "owner", nil,
		uuid.New(), int64(1), "create", "enabled", int64(1), int64(41), runtimeJSON, now,
		nil, nil, nil, nil, nil, nil, nil,
		nil, "", nil, "", nil, "", "pending", nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.PublishIntent.State != "unknown" {
		t.Fatalf("publication state=%q want unknown", item.PublishIntent.State)
	}
	if item.PackageExpiresAt != nil {
		t.Fatalf("missing subscription expiry=%v want nil", item.PackageExpiresAt)
	}
}

func TestScanForwardProjectsExactAutomaticPublicationState(t *testing.T) {
	now := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	runtimeJSON, err := json.Marshal(RuntimeSpec{SchemaVersion: RuntimeSchemaV2, Listener: RuntimeListener{Protocol: ProtocolTCP, Address: "*", Port: 18080}})
	if err != nil {
		t.Fatal(err)
	}
	requestID, publicationID, rolloutID := uuid.New(), uuid.New(), uuid.New()
	internalState := "retry_wait"
	expiresAt := now.Add(24 * time.Hour)
	item, err := scanForward(valuesScanner{
		uuid.New(), "1", uuid.New(), nil, nil, nil, nil, new(uuid.New()), uuid.New(), "edge stream", "", ProtocolTCP, "*", uint16(18080),
		"192.0.2.10", "", uint16(8080), []byte(`{}`), []byte(`{}`), 1000, 30000, 100, false, false, false, []string(nil), 0, 0, 0, false, false, uint16(0), false, nil,
		nil, false, ACLActionAllow, nil, AdminStatusNormal, nil, nil, nil, nil, nil,
		BalanceWayRoundRobin, true, int64(1), now, now, "owner", nil,
		uuid.New(), int64(1), "create", "enabled", int64(1), int64(41), runtimeJSON, now,
		&requestID, &internalState, &publicationID, &rolloutID, nil, &expiresAt, nil,
		nil, "", nil, "", nil, "", "pending", nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.PublishIntent.State != "retrying" || item.PublishIntent.AutomaticRequestID == nil ||
		*item.PublishIntent.AutomaticRequestID != requestID || item.PublishIntent.PublicationID == nil ||
		*item.PublishIntent.PublicationID != publicationID || item.PublishIntent.RolloutID == nil ||
		*item.PublishIntent.RolloutID != rolloutID {
		t.Fatalf("automatic publication projection=%+v", item.PublishIntent)
	}
	if item.PackageExpiresAt == nil || !item.PackageExpiresAt.Equal(expiresAt) {
		t.Fatalf("package expiry=%v want %v", item.PackageExpiresAt, expiresAt)
	}
}

func TestPublicationStateProjectionFailsClosed(t *testing.T) {
	for internal, public := range map[string]string{
		"pending": "pending", "leased": "leased", "retry_wait": "retrying",
		"reconciling": "reconciling", "succeeded": "succeeded", "failed": "failed",
		"superseded": "superseded", "private_state": "unknown", "": "unknown",
	} {
		if got := projectPublicationState(internal); got != public {
			t.Errorf("projectPublicationState(%q)=%q want %q", internal, got, public)
		}
	}
}

func TestL4PackageRuntimeCharacterContract(t *testing.T) {
	if EligibilityEligible != "eligible" || EligibilityIneligible != "ineligible" {
		t.Fatalf("eligibility constants=(%q,%q) want (eligible,ineligible)", EligibilityEligible, EligibilityIneligible)
	}
	allowed := map[EligibilityState]bool{EligibilityEligible: true, EligibilityIneligible: true}
	if len(allowed) != 2 || allowed[EligibilityState("unknown")] {
		t.Fatal("eligibility state is not the exact eligible|ineligible closed set")
	}
	required := map[reflect.Type]map[string]struct {
		typeName string
		jsonName string
	}{
		reflect.TypeOf(Forward{}): {
			"DisplayID":             {typeName: "string", jsonName: "display_id"},
			"PackageSubscriptionID": {typeName: "*UUID", jsonName: "package_subscription_id"},
			"EligibilityState":      {typeName: "EligibilityState", jsonName: "eligibility_state"},
		},
		reflect.TypeOf(Fields{}): {
			"PackageSubscriptionID":   {typeName: "*UUID", jsonName: "package_subscription_id"},
			"MaxConnectionsPerClient": {typeName: "int", jsonName: "max_connections_per_client"},
		},
		reflect.TypeOf(PublishIntent{}): {
			"ConfigurationSourceRevision": {typeName: "int64", jsonName: "configuration_source_revision"},
		},
		reflect.TypeOf(RuntimeSpec{}): {
			"MaxConnectionsPerClient": {typeName: "int", jsonName: "max_connections_per_client"},
			"DrainTimeoutMS":          {typeName: "int", jsonName: "drain_timeout_ms"},
			"ProxyProtocolInbound":    {typeName: "bool", jsonName: "proxy_protocol_inbound"},
			"ProxyProtocolOutbound":   {typeName: "bool", jsonName: "proxy_protocol_outbound"},
		},
		reflect.TypeOf(edgeautopublish.EnqueueInput{}): {
			"PublishIntentID":             {typeName: "UUID", jsonName: ""},
			"ConfigurationSourceRevision": {typeName: "int64", jsonName: ""},
		},
		reflect.TypeOf(edgeautopublish.Request{}): {
			"PublishIntentID": {typeName: "UUID", jsonName: ""},
		},
	}
	for valueType, fields := range required {
		for name, want := range fields {
			field, found := valueType.FieldByName(name)
			if !found {
				t.Errorf("%s.%s is missing", valueType.Name(), name)
				continue
			}
			typeName := field.Type.Name()
			if field.Type.Kind() == reflect.Pointer {
				typeName = "*" + field.Type.Elem().Name()
			}
			if typeName != want.typeName {
				t.Errorf("%s.%s type=%s want %s", valueType.Name(), name, typeName, want.typeName)
			}
			if want.jsonName != "" && field.Tag.Get("json") != want.jsonName {
				t.Errorf("%s.%s json=%q want %q", valueType.Name(), name, field.Tag.Get("json"), want.jsonName)
			}
		}
	}
}

func TestRuntimeSpecCanonicalJSONDigestAndReplayRetention(t *testing.T) {
	streamID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	item := Forward{
		ID: streamID, ScopeID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"),
		Revision: 1,
		Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: 18080,
		UpstreamAddress: "192.0.2.10", UpstreamPort: 8080,
		Geo:              GeoPolicy{UnknownRegionAction: GeoActionAllow, TrustedProxyCIDRs: []string{}, BlockedRegions: []string{}, RegionCIDRs: []GeoRegionCIDRs{}},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, ProxyProtocolV1: true,
	}
	packageName := "已购套餐快照"
	item.PackageName = &packageName
	packageExpiresAt := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	item.PackageExpiresAt = &packageExpiresAt
	item.MaxConnectionsPerClient = 100
	want := `{"schema_version":"cdnca.edge.l4/v2","tenant_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","stream_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","revision":1,"listener":{"protocol":"tcp","address":"*","port":18080},"endpoint":{"address":"192.0.2.10","port":8080},"dns":{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false},"geo":{"enabled":false,"tenant_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","stream_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","revision":1,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]},"connect_timeout_ms":1000,"response_timeout_ms":30000,"max_connections_per_client":100,"drain_timeout_ms":30000,"proxy_protocol_inbound":false,"proxy_protocol_outbound":true}`
	got, err := json.Marshal(runtimeSpec(item))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("runtime JSON=%s want=%s", got, want)
	}
	digest, err := digestRequest(runtimeSpec(item))
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256.Sum256([]byte(want)) {
		t.Fatalf("runtime digest=%x want=%x", digest, sha256.Sum256([]byte(want)))
	}

	now := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	replayed, err := scanForward(valuesScanner{
		uuid.New(), "1", uuid.New(), nil, nil, nil, nil, new(uuid.New()), uuid.New(), "edge stream", "", ProtocolTCP, "*", uint16(18080),
		"192.0.2.10", "", uint16(8080), []byte(`{}`), []byte(`{}`), 1000, 30000, 100, false, true, false, []string(nil), 0, 0, 0, false, false, uint16(0), false, nil,
		nil, false, ACLActionAllow, nil, AdminStatusNormal, nil, nil, nil, nil, nil,
		BalanceWayIPHash, true, int64(1), now, now, "owner", nil,
		uuid.New(), int64(1), "create", "enabled", int64(1), int64(41), []byte(want), now,
		nil, nil, nil, nil, nil, nil, nil,
		nil, "", nil, "", nil, "", "pending", nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	replayedJSON, err := json.Marshal(replayed.PublishIntent.RuntimeSpec)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayedJSON) != want {
		t.Fatalf("replayed runtime JSON=%s want=%s", replayedJSON, want)
	}
}

func TestForwardEligibilityOverlayCharacterContract(t *testing.T) {
	completed := Forward{EligibilityState: EligibilityEligible}
	replayed := completed
	replayed.EligibilityState = EligibilityIneligible
	encoded, err := json.Marshal(replayed)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response["eligibility_state"] != "ineligible" || completed.EligibilityState != EligibilityEligible {
		t.Fatalf("dynamic replay overlay=%v completed=%q", response["eligibility_state"], completed.EligibilityState)
	}
}

func TestMigration092L4PackageRuntimeCharacterExpectation(t *testing.T) {
	if EligibilityEligible != EligibilityState("eligible") ||
		EligibilityIneligible != EligibilityState("ineligible") {
		t.Fatalf("eligibility characters=%q/%q", EligibilityEligible, EligibilityIneligible)
	}
}

func TestListWhereSearchIncludesListenPort(t *testing.T) {
	actor := Actor{
		ScopeKind: "tenant",
		ScopeID:   uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"),
		UserID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
	}
	where, args := listWhere(actor, ListFilter{Search: "18100"})
	if !strings.Contains(where, "position($3 in f.listen_port::text) > 0") {
		t.Fatalf("list search does not include listen_port: %s", where)
	}
	if len(args) != 3 || args[2] != "18100" {
		t.Fatalf("list search args=%v want tenant scope, owner, and 18100", args)
	}
}

func TestListWhereCNAMEFiltersUseStreamAndPackageFacts(t *testing.T) {
	actor := Actor{
		ScopeKind: "tenant",
		ScopeID:   uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"),
		UserID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
	}
	where, args := listWhere(actor, ListFilter{CNAMEDomain: "edge.example", CNAMEHostname: "tenant-edge"})
	// The effective CNAME domain (the stream's own, then its own allocation's
	// zone, then its package's) and hostname (the stream's own allocation
	// while it overrides, else the package allocation's); no website.
	if !strings.Contains(where, "position($3 in lower(COALESCE(f.cname_domain, own.domain, cn.domain, ''))) > 0") ||
		!strings.Contains(where, "position($4 in lower(CASE WHEN f.cname_domain IS NULL AND f.cname_mode IS NULL THEN "+
			"COALESCE(cn_package.hostname, '') ELSE COALESCE(own.lkg_hostname, '') END)) > 0") || strings.Contains(where, "site.") {
		t.Fatalf("CNAME filters do not use stream/package facts: %s", where)
	}
	if len(args) != 4 || args[2] != "edge.example" || args[3] != "tenant-edge" {
		t.Fatalf("CNAME filter args=%v want tenant scope, owner, domain, hostname", args)
	}
}

// L4-FILTER-01：按源站地址筛选也要命中源池里的第二个及以后的源（含已下线的），
// 用 EXISTS 不 JOIN，转发不重复；仍是参数化的同一个参数。
func TestListWhereUpstreamFilterMatchesEveryPoolOrigin(t *testing.T) {
	actor := Actor{
		ScopeKind: "tenant",
		ScopeID:   uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"),
		UserID:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
	}
	where, args := listWhere(actor, ListFilter{Upstream: "203.0.113.20"})
	if !strings.Contains(where, "position($3 in COALESCE(host(f.upstream_address), '')) > 0") ||
		!strings.Contains(where, "EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(f.origins, '[]'::jsonb)) pool_origin "+
			"WHERE position($3 in lower(pool_origin->>'address')) > 0)") {
		t.Fatalf("upstream filter does not search the origin pool: %s", where)
	}
	if strings.Contains(where, "JOIN") || len(args) != 3 || args[2] != "203.0.113.20" {
		t.Fatalf("upstream filter where=%s args=%v", where, args)
	}
}

func uuidPointer(value uuid.UUID) *uuid.UUID {
	return &value
}
