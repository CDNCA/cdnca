package nodescheduler

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNormalizeLineGroupReferenceFieldsAndLegacyReplay(t *testing.T) {
	groupID := uuid.MustParse("019943c7-4c20-7d16-a3d4-f32d38c3af01")
	l2ConfigID := uuid.MustParse("019943c7-4c20-7d16-a3d4-f32d38c3af02")
	base := PutGroupRequest{
		GroupID: groupID, Name: "华东线路", Region: "华东", IPv4ResolvedValue: " V4-EDGE-01 ",
		L2ConfigID: &l2ConfigID, FailoverMode: FailoverOnlineLessThanBackupCount,
		IdempotencyKey: "reference-fields", RequestID: "reference-fields-request",
	}
	normalized, err := normalizePutRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ipv4ResolvedValue != "v4-edge-01" || normalized.l2ConfigID == nil ||
		*normalized.l2ConfigID != l2ConfigID || normalized.failoverMode != FailoverOnlineLessThanBackupCount ||
		normalized.v233ReplayEligible {
		t.Fatalf("normalized reference fields = %#v", normalized)
	}

	changed := base
	changed.FailoverMode = FailoverPrimaryOffline
	changed.IdempotencyKey = "reference-fields-changed"
	changed.RequestID = "reference-fields-changed-request"
	changedNormalized, err := normalizePutRequest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(normalized.configDigest[:], changedNormalized.configDigest[:]) ||
		bytes.Equal(normalized.requestDigest[:], changedNormalized.requestDigest[:]) {
		t.Fatal("failover mode must be bound into configuration and request digests")
	}

	legacy := PutGroupRequest{
		GroupID: groupID, Name: "兼容线路", Region: "华东",
		IdempotencyKey: "v233-compatible", RequestID: "v233-compatible-request",
	}
	legacyNormalized, err := normalizePutRequest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyNormalized.v233ReplayEligible || legacyNormalized.failoverMode != FailoverPrimaryOffline {
		t.Fatalf("legacy compatibility = %#v", legacyNormalized)
	}
	withDefaults, err := applyGroupDefaults(legacyNormalized)
	if err != nil {
		t.Fatal(err)
	}
	if withDefaults.ipv4ResolvedValue != defaultIPv4ResolvedValue(groupID) ||
		withDefaults.failoverMode != FailoverPrimaryOffline {
		t.Fatalf("defaulted reference fields = %#v", withDefaults)
	}
}

func TestNormalizeLineGroupReferenceFieldsRejectsInvalidInput(t *testing.T) {
	groupID := uuid.New()
	nilID := uuid.Nil
	tests := []struct {
		name   string
		mutate func(*PutGroupRequest)
	}{
		{name: "invalid ipv4 resolved value", mutate: func(request *PutGroupRequest) { request.IPv4ResolvedValue = "bad.value" }},
		{name: "nil l2 config", mutate: func(request *PutGroupRequest) { request.L2ConfigID = &nilID }},
		{name: "unknown failover mode", mutate: func(request *PutGroupRequest) { request.FailoverMode = "random" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := PutGroupRequest{
				GroupID: groupID, Name: "线路", IdempotencyKey: "invalid-reference", RequestID: "invalid-reference-request",
			}
			test.mutate(&request)
			if _, err := normalizePutRequest(request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v", err)
			}
		})
	}
}

// TestClassifyLineGroupL2ConfigErrors: migration 504 — a line group naming
// no live L2 topology configuration of its scope/region is invalid input
// (P5043); deleting or moving a configuration a line group or site uses is a
// reference conflict (P5044).
func TestClassifyLineGroupL2ConfigErrors(t *testing.T) {
	if err := classifyWriteError(&pgconn.PgError{Code: "P5043"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("P5043 classified as %v", err)
	}
	if err := classifyL2WriteError(&pgconn.PgError{Code: "P5044"}, true); !errors.Is(err, ErrReferenceConflict) {
		t.Fatalf("P5044 classified as %v", err)
	}
}

// TestNormalizeLineGroupAcceptsL2ConfigWithGroupID: the L2 configuration is
// an l2_topology_configs id, not a line group id, so equality with the
// group's own id is no longer a self reference.
func TestNormalizeLineGroupAcceptsL2ConfigWithGroupID(t *testing.T) {
	groupID := uuid.New()
	if _, err := normalizePutRequest(PutGroupRequest{
		GroupID: groupID, Name: "线路", L2ConfigID: &groupID,
		IdempotencyKey: "l2-config-id", RequestID: "l2-config-id-request",
	}); err != nil {
		t.Fatalf("normalize error = %v", err)
	}
}

// TestNormalizeLineGroupRejectsIntervalFailover: "interval" had no rotation
// semantics and silently ran as primary_offline; it is rejected instead of accepted as a fake setting.
func TestNormalizeLineGroupRejectsIntervalFailover(t *testing.T) {
	for _, mode := range []string{"interval", "Interval", "round_robin"} {
		_, err := normalizePutRequest(PutGroupRequest{
			GroupID: uuid.New(), Name: "线路", FailoverMode: mode,
			IdempotencyKey: "interval-" + mode, RequestID: "interval-" + mode,
		})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("failover_mode %q: err=%v, want ErrInvalidInput", mode, err)
		}
	}
}

// REGION-NORM-01（fz-x1 复现不属实）：线路组区域首尾空白在服务端去掉后保存，纯空白等于不限区域；
// 前端 required+whitespace 与此同义。端点区域按 TestNormalizePutRequestPreservesControlFreeLabelBytes 保留原字节。
func TestNormalizeLineGroupRegionTrimmed(t *testing.T) {
	for input, want := range map[string]string{" 华东 ": "华东", "　华东 ": "华东", "   ": ""} {
		normalized, err := normalizePutRequest(PutGroupRequest{GroupID: uuid.New(), Name: "线路", Region: input,
			IdempotencyKey: "region-trim", RequestID: "region-trim"})
		if err != nil || normalized.region != want {
			t.Fatalf("region %q = %q, %v", input, normalized.region, err)
		}
	}
}
