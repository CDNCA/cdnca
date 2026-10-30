package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// drain_max_ms is optional: unset keeps the signed artifact byte-identical to
// releases before it, a value is carried to the agent, out-of-range is refused.
func TestL4DrainMaxMSIsOptionalAndBounded(t *testing.T) {
	spec := multiListenerBundleSpec()
	unset, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("drain_max_ms")) {
		t.Fatal("unset drain limit changed the signed L4 artifact")
	}
	for _, value := range []int{0, 1_000, 86_400_000, L4DrainMaxMSMax} {
		spec := multiListenerBundleSpec()
		spec.L4StreamsV2[0].DrainMaxMS = &value
		bundle, err := buildStreams(spec)
		if err != nil {
			t.Fatalf("drain_max_ms=%d: %v", value, err)
		}
		var set l4StreamSetV2
		if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil ||
			set.Streams[0].DrainMaxMS == nil || *set.Streams[0].DrainMaxMS != value {
			t.Fatalf("drain_max_ms=%d not carried: %+v %v", value, set.Streams, err)
		}
	}
	for _, value := range []int{-1, 1, 999, L4DrainMaxMSMax + 1} {
		spec := multiListenerBundleSpec()
		spec.L4StreamsV2[0].DrainMaxMS = &value
		if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("drain_max_ms=%d accepted: %v", value, err)
		}
	}
}
