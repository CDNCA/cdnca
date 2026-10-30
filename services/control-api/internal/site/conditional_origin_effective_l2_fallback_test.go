package site

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConditionalOriginResponseExposesTopologyBoundEffectiveL2Fallback(t *testing.T) {
	state := withConditionalOriginEffectiveRetry(ConditionalOriginState{})
	got := state.EffectiveL2Fallback
	if !got.DirectOriginOnly || !got.WithinTotalBudget || got.ProbeIntervalMS != 10000 ||
		!got.NodeIDRequired || !got.TierRequired || !got.TopologyRevisionRequired || !got.MTLSIdentityRequired ||
		got.FailureThreshold != 3 || got.RecoveryThreshold != 3 || !got.SingleHalfOpenProbe || got.MaxHops != 1 {
		t.Fatalf("effective L2 fallback = %+v", got)
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if _, exists := response["effective_l2_fallback"]; !exists {
		t.Fatalf("response has no effective_l2_fallback: %s", encoded)
	}
}

func TestConditionalOriginWriteDocumentRejectsEffectiveL2FallbackOverride(t *testing.T) {
	document := validConditionalOriginDocument()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	body["effective_l2_fallback"] = map[string]any{
		"direct_origin_only":     true,
		"within_total_budget":    true,
		"probe_interval_ms":      10000,
		"failure_threshold":      3,
		"recovery_threshold":     3,
		"single_half_open_probe": true,
		"max_hops":               1,
	}
	encoded, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded ConditionalOriginDocument
	if err := decoder.Decode(&decoded); err == nil {
		t.Fatal("effective_l2_fallback override was accepted by the PUT document DTO")
	}
}
