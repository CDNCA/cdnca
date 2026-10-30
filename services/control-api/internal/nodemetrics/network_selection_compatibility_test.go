package nodemetrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkSelectionStoredJSONRequiresExpandedRollbackReader(t *testing.T) {
	// Frozen 1.0.7 shape: its strict reader cannot read this new optional field.
	// Deploy the expanded reader before Agents, and retain that reader as the
	// rollback baseline. Do not remove persisted facts to roll back to 1.0.7.
	type telemetry107 struct {
		SchemaVersion     uint8              `json:"schema_version"`
		NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
		TotalRXBytes      uint64             `json:"total_rx_bytes"`
		TotalTXBytes      uint64             `json:"total_tx_bytes"`
		SystemLoad        *SystemLoad        `json:"system_load,omitempty"`
		Disks             []DiskUsage        `json:"disks"`
	}
	value := &Telemetry{SchemaVersion: 1, NetworkInterfaces: []NetworkInterface{{Name: "eth0"}},
		NetworkSelection: &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}}}
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	legacy := json.NewDecoder(bytes.NewReader(payload))
	legacy.DisallowUnknownFields()
	if err := legacy.Decode(&telemetry107{}); err == nil || !strings.Contains(err.Error(), "network_selection") {
		t.Fatalf("legacy incompatibility evidence changed: %v", err)
	}
	var restored *Telemetry
	if err := decodeStoredTelemetry(payload, &restored); err != nil || restored.NetworkSelection.Interfaces[0] != "eth0" {
		t.Fatalf("expanded reader cannot read persisted selection: %+v, %v", restored, err)
	}
	value.NetworkSelection = nil
	payload, _ = json.Marshal(value)
	legacy = json.NewDecoder(bytes.NewReader(payload))
	legacy.DisallowUnknownFields()
	if err := legacy.Decode(&telemetry107{}); err != nil {
		t.Fatalf("old sample is no longer compatible: %v", err)
	}
}

func TestStoredNetworkSelectionRejectsUnknownOrInventedFacts(t *testing.T) {
	for _, selection := range []string{
		`{"source":"guess","interfaces":["eth0"]}`,
		`{"source":"default_route","interfaces":[]}`,
		`{"source":"default_route","interfaces":["eth9"]}`,
		`{"source":"default_route","interfaces":["eth0","eth0"]}`,
		`{"source":"unavailable","interfaces":["eth0"]}`,
		`{"source":"unavailable","interfaces":[],"extra":true}`,
	} {
		var restored *Telemetry
		payload := []byte(`{"schema_version":1,"network_interfaces":[{"name":"eth0"}],"network_selection":` + selection + `}`)
		if err := decodeStoredTelemetry(payload, &restored); err != ErrInvalidSample {
			t.Fatalf("invalid persisted selection accepted: %s, %v", selection, err)
		}
	}
}
