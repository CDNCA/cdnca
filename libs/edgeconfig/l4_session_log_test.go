package edgeconfig

import (
	"bytes"
	"encoding/json"
	"testing"
)

// session_log (tcp/udp v7) is optional: unset keeps the signed artifact
// byte-identical; set, it follows new_conn_rate on the wire.
func TestL4SessionLogIsOptionalAndOrdered(t *testing.T) {
	unset, err := buildStreams(multiListenerBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("session_log")) {
		t.Fatal("unset session log changed the signed L4 artifact")
	}
	spec := multiListenerBundleSpec()
	spec.L4StreamsV2[0].SessionLog = true
	spec.L4StreamsV2[0].NewConnRate = &L4NewConnRateV2{RatePerSecond: 5}
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil {
		t.Fatal(err)
	}
	carried := 0
	for _, stream := range set.Streams {
		if stream.SessionLog {
			carried++
		}
	}
	if carried != 1 {
		t.Fatalf("session_log carried on %d streams, want 1: %s", carried, bundle.Files[L4RuntimeV2ArtifactPath])
	}
	if !bytes.Contains(bundle.Files[L4RuntimeV2ArtifactPath], []byte(`"ban_seconds":0},"session_log":true`)) {
		t.Fatalf("session_log is not right after new_conn_rate: %s", bundle.Files[L4RuntimeV2ArtifactPath])
	}
}
