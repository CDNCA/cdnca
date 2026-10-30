package node

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func TestNormalizeNodeManagementSettings(t *testing.T) {
	settings := DefaultNodeManagementSettings()
	settings.CacheDirectory = "  /www/server/cdnca/cache  "
	settings.LogDirectory = "  /www/server/cdnca/logs  "
	settings.IPLocation.CountryCode = " cn "
	settings.AutoDisable.ExcludedInterfaces = "eth0   eth1"
	settings.AutoDisable.DisabledPeriods = "00:00:00-03:00:00   08:00:00-22:00:00"
	settings.SecondaryIPs = []string{"198.51.100.10", "2001:0db8:0:0:0:0:0:20"}
	if err := normalizeManagementSettings(&settings); err != nil {
		t.Fatalf("normalizeManagementSettings() error = %v", err)
	}
	if settings.CacheDirectory != "/www/server/cdnca/cache" || settings.LogDirectory != "/www/server/cdnca/logs" ||
		settings.IPLocation.CountryCode != "CN" || settings.AutoDisable.ExcludedInterfaces != "eth0 eth1" ||
		settings.SecondaryIPs[1] != "2001:db8::20" {
		t.Fatalf("normalized settings = %#v", settings)
	}
}

func TestRejectInvalidNodeManagementSettings(t *testing.T) {
	tests := map[string]struct {
		mutate        func(*NodeManagementSettings)
		field, reason string
	}{
		"schema version":  {func(value *NodeManagementSettings) { value.SchemaVersion = 2 }, "schema_version", fielderr.Invalid},
		"sort":            {func(value *NodeManagementSettings) { value.Sort = -1 }, "sort", fielderr.OutOfRange},
		"node type":       {func(value *NodeManagementSettings) { value.NodeType = "origin" }, "node_type", fielderr.Invalid},
		"cache directory": {func(value *NodeManagementSettings) { value.CacheDirectory = "/a\nb" }, "cache_directory", fielderr.InvalidFormat},
		"country code":    {func(value *NodeManagementSettings) { value.IPLocation.CountryCode = "CHN" }, "ip_location", fielderr.Invalid},
		"bandwidth unit":  {func(value *NodeManagementSettings) { value.AutoDisable.BandwidthUnit = "kbps" }, "auto_disable.bandwidth_unit", fielderr.Invalid},
		"traffic day":     {func(value *NodeManagementSettings) { value.AutoDisable.TrafficFromDay = 29 }, "auto_disable.traffic_from_day", fielderr.OutOfRange},
		"traffic time":    {func(value *NodeManagementSettings) { value.AutoDisable.TrafficFromTime = "24:00:00" }, "auto_disable.traffic_from_time", fielderr.InvalidFormat},
		"traffic types":   {func(value *NodeManagementSettings) { value.AutoDisable.TrafficTypes = []string{"outbound", "outbound"} }, "auto_disable.traffic_types", fielderr.Invalid},
		"interface":       {func(value *NodeManagementSettings) { value.AutoDisable.ExcludedInterfaces = "eth0;shutdown" }, "auto_disable.excluded_interfaces", fielderr.InvalidFormat},
		"disabled period": {func(value *NodeManagementSettings) { value.AutoDisable.DisabledPeriods = "03:00:00-03:00:00" }, "auto_disable.disabled_periods", fielderr.InvalidFormat},
		"secondary IP":    {func(value *NodeManagementSettings) { value.SecondaryIPs = []string{"not-an-ip"} }, "secondary_ips[0]", fielderr.InvalidFormat},
		"duplicate IP":    {func(value *NodeManagementSettings) { value.SecondaryIPs = []string{"198.51.100.1", "198.51.100.1"} }, "secondary_ips[1]", fielderr.Duplicate},
		"302 hostname":    {func(value *NodeManagementSettings) { value.Schedule302Hostname = "a_b.example.test" }, "schedule302_hostname", fielderr.InvalidFormat},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			settings := DefaultNodeManagementSettings()
			test.mutate(&settings)
			assertNodeField(t, normalizeManagementSettings(&settings), test.field, test.reason)
		})
	}
}

func TestNormalizeUpdateFieldsLocatesField(t *testing.T) {
	text := func(value string) *string { return &value }
	settings := DefaultNodeManagementSettings()
	settings.Sort = -1
	tests := map[string]struct {
		fields        UpdateFields
		field, reason string
	}{
		"empty name":       {UpdateFields{Name: text(" ")}, "name", fielderr.Required},
		"long description": {UpdateFields{Description: text(strings.Repeat("x", 1025))}, "description", fielderr.TooLong},
		"long region":      {UpdateFields{Region: text(strings.Repeat("x", 65))}, "region", fielderr.TooLong},
		"bad ipv4":         {UpdateFields{IPv4: text("2001:db8::1")}, "ipv4", fielderr.InvalidFormat},
		"bad ipv6":         {UpdateFields{IPv6: text("198.51.100.1")}, "ipv6", fielderr.InvalidFormat},
		"admin state":      {UpdateFields{AdminState: text("bogus")}, "admin_state", fielderr.Invalid},
		"settings sort":    {UpdateFields{ManagementSettings: &settings}, "management_settings.sort", fielderr.OutOfRange},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assertNodeField(t, normalizeUpdateFields(&test.fields), test.field, test.reason)
		})
	}
	if err := normalizeUpdateFields(&UpdateFields{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty update = %v", err)
	}
}

func TestCreateNodeLocatesField(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New()}
	service := NewService(nil)
	for name, test := range map[string]struct {
		request       CreateRequest
		field, reason string
	}{
		"empty name": {CreateRequest{Name: " "}, "name", fielderr.Required},
		"bad ipv4":   {CreateRequest{Name: "n", IPv4: "x"}, "ipv4", fielderr.InvalidFormat},
		"token ttl":  {CreateRequest{Name: "n", IssueToken: true, TokenTTL: time.Second}, "enrollment_token_ttl_seconds", fielderr.OutOfRange},
	} {
		t.Run(name, func(t *testing.T) {
			test.request.IdempotencyKey, test.request.RequestID = "key-1", "request-1"
			_, err := service.CreateNode(t.Context(), actor, test.request)
			assertNodeField(t, err, test.field, test.reason)
		})
	}
}

func assertNodeField(t *testing.T, err error, field, reason string) {
	t.Helper()
	located, ok := fielderr.As(err)
	if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != field || located.Reason != reason {
		t.Fatalf("error = %v, want %s/%s", err, field, reason)
	}
}
