package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// new_conn_rate (tcp/udp v6) is optional: unset keeps the signed artifact
// byte-identical, a value is carried to the agent, out-of-range is refused.
func TestL4NewConnRateIsOptionalAndBounded(t *testing.T) {
	unset, err := buildStreams(multiListenerBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("new_conn_rate")) {
		t.Fatal("unset new connection rate changed the signed L4 artifact")
	}
	for _, value := range []L4NewConnRateV2{
		{RatePerSecond: 1},
		{RatePerSecond: 20, Burst: 10, BanSeconds: 60},
		{RatePerSecond: L4NewConnRateMax, Burst: L4NewConnBurstMax, BanSeconds: L4NewConnBanSecondsMax},
	} {
		spec := multiListenerBundleSpec()
		rate := value
		spec.L4StreamsV2[0].NewConnRate = &rate
		bundle, err := buildStreams(spec)
		if err != nil {
			t.Fatalf("%+v: %v", value, err)
		}
		var set l4StreamSetV2
		if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil ||
			set.Streams[0].NewConnRate == nil || *set.Streams[0].NewConnRate != value {
			t.Fatalf("%+v not carried: %+v %v", value, set.Streams, err)
		}
		if !bytes.Contains(bundle.Files[L4RuntimeV2ArtifactPath],
			[]byte(`"new_conn_rate":{"rate_per_second":`)) {
			t.Fatalf("new_conn_rate wire shape changed: %s", bundle.Files[L4RuntimeV2ArtifactPath])
		}
	}
	for _, value := range []L4NewConnRateV2{
		{}, {RatePerSecond: -1}, {RatePerSecond: L4NewConnRateMax + 1},
		{RatePerSecond: 1, Burst: -1}, {RatePerSecond: 1, Burst: L4NewConnBurstMax + 1},
		{RatePerSecond: 1, BanSeconds: -1}, {RatePerSecond: 1, BanSeconds: L4NewConnBanSecondsMax + 1},
	} {
		spec := multiListenerBundleSpec()
		rate := value
		spec.L4StreamsV2[0].NewConnRate = &rate
		if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v accepted: %v", value, err)
		}
	}
}
