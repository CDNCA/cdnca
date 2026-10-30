package dnspropagation

import (
	"reflect"
	"testing"
)

type retryMetricRecorder struct {
	recorded []Metric
}

func (recorder *retryMetricRecorder) Record(metric Metric) {
	recorder.recorded = append(recorder.recorded, metric)
}

func TestMetricHasOnlyBoundedStableDimensions(t *testing.T) {
	typeOfMetric := reflect.TypeOf(Metric{})
	want := []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "Reason", typeOf: reflect.TypeOf(ReasonCode(""))},
		{name: "Success", typeOf: reflect.TypeOf(false)},
		{name: "AuthoritativeVotes", typeOf: reflect.TypeOf(int(0))},
		{name: "PublicVotes", typeOf: reflect.TypeOf(int(0))},
	}
	if typeOfMetric.NumField() != len(want) {
		t.Fatalf("Metric fields = %d, want only %d bounded dimensions", typeOfMetric.NumField(), len(want))
	}
	for index, expected := range want {
		field := typeOfMetric.Field(index)
		if field.Name != expected.name || field.Type != expected.typeOf {
			t.Fatalf("Metric field %d = %s %s, want %s %s", index, field.Name, field.Type,
				expected.name, expected.typeOf)
		}
	}
	for _, forbidden := range []string{"TenantID", "ScopeID", "ProviderID", "ZoneID", "OperationID", "ClientRequestID", "ProviderRequestID"} {
		if _, present := typeOfMetric.FieldByName(forbidden); present {
			t.Fatalf("Metric exposes high-cardinality field %s", forbidden)
		}
	}
}

func TestMetricsRecordBoundaryPreservesStableObservation(t *testing.T) {
	var metrics Metrics = &retryMetricRecorder{}
	metric := Metric{
		Reason: ReasonCode("authority_and_public_quorum_agree"), Success: true,
		AuthoritativeVotes: 2, PublicVotes: 3,
	}
	metrics.Record(metric)

	recorder := metrics.(*retryMetricRecorder)
	if len(recorder.recorded) != 1 || recorder.recorded[0] != metric {
		t.Fatalf("recorded metrics = %#v, want %#v", recorder.recorded, metric)
	}
}

var _ Metrics = (*retryMetricRecorder)(nil)
