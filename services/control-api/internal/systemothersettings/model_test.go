package systemothersettings

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

type apiKeyStatusQuerier struct {
	raw []byte
	err error
}

func (q apiKeyStatusQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return apiKeyStatusRow{raw: q.raw, err: q.err}
}

type apiKeyStatusRow struct {
	raw []byte
	err error
}

func (row apiKeyStatusRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 1 {
		return errors.New("unexpected API key status scan")
	}
	target, ok := destinations[0].(*[]byte)
	if !ok {
		return errors.New("unexpected API key status target")
	}
	*target = append((*target)[:0], row.raw...)
	return nil
}

func TestDefaultSettingsExposeObservedBaselineControls(t *testing.T) {
	value := DefaultSettings()
	if !value.APIKeyEnabled || value.DNSProtection != "" || value.RecordRepairMode != "repair" || value.SyncBatch != 1000 || value.SyncScope != "line_group" || value.DisableFailedSyncNodes || value.ResourceRank != 100 || value.TCPFactor != 1.1 {
		t.Fatalf("unexpected defaults: %+v", value)
	}
	if !validSettings(value) {
		t.Fatalf("default settings should validate: %+v", value)
	}
}

func TestDecodeSettingsBackfillsFieldsFromLegacyRow(t *testing.T) {
	value, err := decodeSettings([]byte(`{"source_ip_header":"X-Real-IP","dns_protection":true,"sync_batch":100,"resource_rank":10,"http_proxy":"","tcp_factor":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !value.APIKeyEnabled || value.DNSProtection != "" || value.RecordRepairMode != "repair" || value.SyncBatch != 100 || value.SyncScope != "line_group" || value.DisableFailedSyncNodes || value.ResourceRank != 10 || value.TCPFactor != 1 {
		t.Fatalf("legacy row was not backfilled: %+v", value)
	}
	if !validSettings(value) {
		t.Fatalf("backfilled settings should validate: %+v", value)
	}
}

func TestAPIKeyEnabledDefaultsLegacyRowsAndFailsClosedForUnreadableStatus(t *testing.T) {
	cases := []struct {
		name  string
		query apiKeyStatusQuerier
		want  bool
		err   error
	}{
		{name: "missing row keeps established enabled state", query: apiKeyStatusQuerier{err: pgx.ErrNoRows}, want: true},
		{name: "legacy row backfills enabled state", query: apiKeyStatusQuerier{raw: []byte(`{"source_ip_header":"X-Real-IP","dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1}`)}, want: true},
		{name: "disabled row", query: apiKeyStatusQuerier{raw: []byte(`{"source_ip_header":"X-Real-IP","api_key_enabled":false,"dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1}`)}},
		{name: "malformed row fails closed", query: apiKeyStatusQuerier{raw: []byte(`{"api_key_enabled":"false"}`)}, err: ErrUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := APIKeyEnabled(t.Context(), test.query)
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Fatalf("error=%v want=%v", err, test.err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("enabled=%v error=%v want=%v", got, err, test.want)
			}
		})
	}
}

func TestValidSettingsRejectsUnknownBaselineModes(t *testing.T) {
	value := DefaultSettings()
	value.RecordRepairMode = "unknown"
	if validSettings(value) {
		t.Fatal("unknown record repair mode accepted")
	}
	value = DefaultSettings()
	value.SyncScope = "unknown"
	if validSettings(value) {
		t.Fatal("unknown sync scope accepted")
	}
}

func TestDefaultDocumentUsesCurrentResponseShape(t *testing.T) {
	encoded, err := json.Marshal(Document{Schema: Schema(), Value: DefaultSettings()})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Schema   string   `json:"schema"`
		Revision int64    `json:"revision"`
		Value    Settings `json:"value"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	t.Logf("default document: %s", encoded)
	if decoded.Schema != Schema() || decoded.Revision != 0 || !validSettings(decoded.Value) {
		t.Fatalf("default document response is not current: %s", encoded)
	}
}

func TestL4DrainMaxMSDefaultsAndCarriesTheConfiguredLimit(t *testing.T) {
	row := func(seconds string) apiKeyStatusQuerier {
		raw := `{"source_ip_header":"X-Real-IP","dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1`
		if seconds != "" {
			raw += `,"l4_drain_max_seconds":` + seconds
		}
		return apiKeyStatusQuerier{raw: []byte(raw + "}")}
	}
	cases := []struct {
		name  string
		query apiKeyStatusQuerier
		want  *int
		err   error
	}{
		{name: "missing row is the agent default", query: apiKeyStatusQuerier{err: pgx.ErrNoRows}},
		{name: "row before the setting is the default", query: row("")},
		{name: "explicit default is omitted", query: row("86400")},
		{name: "unlimited", query: row("0"), want: intPointer(0)},
		{name: "one hour", query: row("3600"), want: intPointer(3_600_000)},
		{name: "out of range fails closed", query: row("604801"), err: ErrUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := L4DrainMaxMS(t.Context(), test.query)
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Fatalf("error=%v want=%v", err, test.err)
				}
				return
			}
			if err != nil || (got == nil) != (test.want == nil) || (got != nil && *got != *test.want) {
				t.Fatalf("L4DrainMaxMS() = %v, %v want %v", got, err, test.want)
			}
		})
	}
	value := DefaultSettings()
	if value.L4DrainMaxSeconds == nil || *value.L4DrainMaxSeconds != DefaultL4DrainMaxSeconds {
		t.Fatalf("default L4 drain limit = %v", value.L4DrainMaxSeconds)
	}
	for _, seconds := range []int{-1, MaxL4DrainMaxSeconds + 1} {
		value.L4DrainMaxSeconds = intPointer(seconds)
		if validSettings(value) {
			t.Fatalf("L4 drain limit %d accepted", seconds)
		}
	}
}

func TestDomainOwnershipPolicyDefaultsAndValidates(t *testing.T) {
	value := DefaultSettings()
	if value.DomainOwnershipPolicy == nil || *value.DomainOwnershipPolicy != "wildcard_only" {
		t.Fatalf("default domain ownership policy = %v", value.DomainOwnershipPolicy)
	}
	for _, policy := range []string{"off", "wildcard_only", "all"} {
		value.DomainOwnershipPolicy = stringPointer(policy)
		if !validSettings(value) {
			t.Fatalf("policy %s rejected", policy)
		}
	}
	for _, policy := range []string{"", "ALL", "strict"} {
		value.DomainOwnershipPolicy = stringPointer(policy)
		if validSettings(value) {
			t.Fatalf("policy %q accepted", policy)
		}
	}
	decoded, err := decodeSettings([]byte(`{"sync_batch":10}`))
	if err != nil || decoded.DomainOwnershipPolicy == nil || *decoded.DomainOwnershipPolicy != "wildcard_only" {
		t.Fatalf("row before the setting decodes to %v (%v)", decoded.DomainOwnershipPolicy, err)
	}
}
