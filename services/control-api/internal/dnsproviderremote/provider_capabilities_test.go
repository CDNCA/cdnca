package dnsproviderremote

import (
	"reflect"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestProviderCapabilityMatrixIsExactAndCallerImmutable(t *testing.T) {
	want := [9]ProviderCapability{
		{ProviderType: providerAliyun, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerCloudflare, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, RetryAfterClassification: true},
		{ProviderType: providerHuawei, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerDNSPodCN, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, Weight: true, RetryAfterClassification: true},
		{ProviderType: providerDNSCom, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerDNSLA, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerNameCom, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, RetryAfterClassification: true},
		{ProviderType: providerCustomHTTP, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true},
		{ProviderType: providerPlugin, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true},
	}
	got := ProviderCapabilityMatrix()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProviderCapabilityMatrix() = %#v, want %#v", got, want)
	}
	got[0] = ProviderCapability{ProviderType: "dnsdun"}
	if next := ProviderCapabilityMatrix(); !reflect.DeepEqual(next, want) {
		t.Fatalf("caller mutated capability authority: %#v", next)
	}
	for _, capability := range ProviderCapabilityMatrix() {
		if capability.ProviderType == "dnsdun" {
			t.Fatal("unsupported legacy dnsdun appeared in capability matrix")
		}
	}
}

func TestProviderCapabilityMatrixDrivesReconcileValidation(t *testing.T) {
	for _, capability := range ProviderCapabilityMatrix() {
		t.Run(capability.ProviderType, func(t *testing.T) {
			config := completeTestConfig(reconcileHTTPProviderConfig(capability.ProviderType))
			for _, record := range []struct {
				typeName  dnscheck.RecordType
				value     string
				supported bool
			}{
				{dnscheck.RecordA, "192.0.2.10", capability.ReconcileA},
				{dnscheck.RecordAAAA, "2001:db8::10", capability.ReconcileAAAA},
				{dnscheck.RecordCNAME, "target.example.test.", capability.ReconcileCNAME},
			} {
				operation := dnscheck.ProviderOperation{
					Action: dnscheck.ProviderCreate, Name: "www.example.test.",
					Type: record.typeName, Value: record.value, TTL: 300,
				}
				err := validateProviderReconcileOperation(config, operation)
				if record.supported && err != nil {
					t.Fatalf("default %d validation error = %v", record.typeName, err)
				}
				if !record.supported && ErrorCodeOf(err) != CodeUnsupported {
					t.Fatalf("unsupported %d validation error = %v", record.typeName, err)
				}
			}

			routing := dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300, Line: "境外", Weight: 80,
			}
			err := validateProviderReconcileOperation(config, routing)
			if capability.Line && capability.Weight {
				if err != nil {
					t.Fatalf("supported routing validation error = %v", err)
				}
			} else if ErrorCodeOf(err) != CodeUnsupported {
				t.Fatalf("unsupported routing validation error = %v", err)
			}
		})
	}
}

func TestSupportedLinesFollowCapabilityAndMappings(t *testing.T) {
	want := map[string][]string{
		providerAliyun:     {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		providerCloudflare: {LineDefault},
		providerHuawei:     {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		providerDNSPodCN:   {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		// Provider-level; the plan tier narrows it (TestDNSComPlanTierLines).
		providerDNSCom:     {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		providerDNSLA:      {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		providerNameCom:    {LineDefault},
		providerCustomHTTP: {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
		providerPlugin:     {LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas},
	}
	for _, capability := range ProviderCapabilityMatrix() {
		got := SupportedLines(capability.ProviderType)
		if !reflect.DeepEqual(got, want[capability.ProviderType]) {
			t.Fatalf("SupportedLines(%s) = %v, want %v", capability.ProviderType, got, want[capability.ProviderType])
		}
		config := completeTestConfig(reconcileHTTPProviderConfig(capability.ProviderType))
		if capability.ProviderType == providerDNSCom {
			config.Credentials[DNSComPlanField] = DNSComPlanFlagship
		}
		for _, line := range []string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas} {
			operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line}
			err := validateProviderReconcileOperation(config, operation)
			if supported := slices.Contains(got, line); supported != (err == nil) {
				t.Fatalf("%s line %s: supported=%v validation=%v", capability.ProviderType, line, supported, err)
			}
		}
	}
	if SupportedLines("dnsdun") != nil {
		t.Fatal("unknown provider has lines")
	}
}
