package nodemonitoringconfig

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

func TestCompileCategoryDocumentBindsActiveRevisionAndDefaults(t *testing.T) {
	document := systemconfig.CategoryDocument{
		Category:       systemconfig.CategoryNodeMonitoring,
		HeadRevision:   9,
		ActiveRevision: 7,
		Revision:       7,
		Value: systemconfig.NodeMonitoringConfiguration{
			PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
			FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
		},
	}

	payload, err := CompileCategoryDocument(document)
	if err != nil {
		t.Fatalf("CompileCategoryDocument() error = %v", err)
	}
	var artifact Artifact
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	if artifact.SchemaVersion != SchemaVersion || artifact.ConfigRevision != 7 ||
		artifact.PortMode != "default" || artifact.CustomPort != nil ||
		artifact.ProbeIntervalMS != 10_000 || artifact.ProbeTimeoutMS != 3_000 ||
		artifact.FailureThreshold != 3 || artifact.RecoveryThreshold != 3 ||
		artifact.FailureDebounceMS != 0 || artifact.RecoveryDebounceMS != 0 ||
		!artifact.RecoveryNotificationEnabled {
		t.Fatalf("artifact = %#v", artifact)
	}
	if string(payload) != `{"schema_version":"cdnca.node-monitoring/v1","config_revision":7,"port_mode":"default","probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0,"recovery_notification_enabled":true}` {
		t.Fatalf("non-canonical payload = %s", payload)
	}
}

func TestCompileCategoryDocumentCarriesCustomProbePolicy(t *testing.T) {
	port := uint16(9443)
	document := systemconfig.CategoryDocument{
		Category:       systemconfig.CategoryNodeMonitoring,
		HeadRevision:   12,
		ActiveRevision: 12,
		Revision:       12,
		Value: systemconfig.NodeMonitoringConfiguration{
			PortMode: "custom", CustomPort: &port, ProbeIntervalMS: 15_000, ProbeTimeoutMS: 2_500,
			FailureThreshold: 4, RecoveryThreshold: 5, FailureDebounceMS: 6_000,
			RecoveryDebounceMS: 7_000, RecoveryNotificationEnabled: false,
		},
	}

	payload, err := CompileCategoryDocument(document)
	if err != nil {
		t.Fatalf("CompileCategoryDocument() error = %v", err)
	}
	var artifact Artifact
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatalf("decode artifact: %v", err)
	}
	if artifact.CustomPort == nil || *artifact.CustomPort != 9443 ||
		artifact.ProbeIntervalMS != 15_000 || artifact.ProbeTimeoutMS != 2_500 ||
		artifact.FailureThreshold != 4 || artifact.RecoveryThreshold != 5 ||
		artifact.FailureDebounceMS != 6_000 || artifact.RecoveryDebounceMS != 7_000 ||
		artifact.RecoveryNotificationEnabled {
		t.Fatalf("artifact = %#v", artifact)
	}
}

func TestCompileCategoryDocumentRejectsUnboundOrInvalidInput(t *testing.T) {
	valid := systemconfig.CategoryDocument{
		Category:       systemconfig.CategoryNodeMonitoring,
		HeadRevision:   1,
		ActiveRevision: 1,
		Revision:       1,
		Value: systemconfig.NodeMonitoringConfiguration{
			PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
			FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
		},
	}
	tests := map[string]systemconfig.CategoryDocument{
		"wrong category":    func() systemconfig.CategoryDocument { value := valid; value.Category = "resources"; return value }(),
		"inactive revision": func() systemconfig.CategoryDocument { value := valid; value.Revision = 2; return value }(),
		"missing revision": func() systemconfig.CategoryDocument {
			value := valid
			value.ActiveRevision = 0
			value.Revision = 0
			return value
		}(),
		"wrong value type": func() systemconfig.CategoryDocument { value := valid; value.Value = map[string]any{}; return value }(),
		"invalid probe policy": func() systemconfig.CategoryDocument {
			value := valid
			policy := value.Value.(systemconfig.NodeMonitoringConfiguration)
			policy.ProbeTimeoutMS = 10_001
			value.Value = policy
			return value
		}(),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileCategoryDocument(document); !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("error = %v, want ErrInvalidDocument", err)
			}
		})
	}
}
