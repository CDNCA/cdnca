package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func toaBundleSpec() Spec {
	spec := multiListenerBundleSpec()
	spec.L4StreamsV2[0].AdditionalListeners = spec.L4StreamsV2[0].AdditionalListeners[1:] // TCP only
	return spec
}

// toa is optional (unset keeps the artifact byte-identical), TCP only, and
// excludes PROXY protocol in both directions: outbound would carry the
// client twice, and with inbound PROXY the socket peer is the proxy, not the
// client the origin wants.
func TestL4TOAIsOptionalTCPOnlyAndExcludesProxyProtocol(t *testing.T) {
	unset, err := buildStreams(toaBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte(`"toa"`)) {
		t.Fatal("unset toa changed the signed L4 artifact")
	}

	spec := toaBundleSpec()
	spec.L4StreamsV2[0].TOA = true
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatalf("toa stream rejected: %v", err)
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil || !set.Streams[0].TOA {
		t.Fatalf("toa not carried: %+v %v", set.Streams, err)
	}

	outbound := toaBundleSpec()
	outbound.L4StreamsV2[0].TOA = true
	outbound.L4StreamsV2[0].ProxyProtocolOutbound = true
	if _, err := buildStreams(outbound); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("toa with outbound PROXY protocol accepted: %v", err)
	}

	inbound := toaBundleSpec()
	inbound.L4StreamsV2[0].TOA = true
	inbound.L4StreamsV2[0].ProxyProtocolInbound = true
	inbound.L4StreamsV2[0].Geo.Enabled = true
	inbound.L4StreamsV2[0].Geo.TrustedProxyCIDRs = []string{"198.51.100.0/24"}
	inbound.L4StreamsV2[0].TOA = false
	if _, err := buildStreams(inbound); err != nil {
		t.Fatalf("inbound PROXY fixture itself is invalid: %v", err)
	}
	inbound.L4StreamsV2[0].TOA = true
	if _, err := buildStreams(inbound); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("toa with inbound PROXY protocol accepted: %v", err)
	}

	udp := toaBundleSpec()
	udp.L4StreamsV2[0].TOA = true
	udp.L4StreamsV2[0].Listener.Protocol = "udp"
	if _, err := buildStreams(udp); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("toa on a UDP listener accepted: %v", err)
	}

	extraUDP := multiListenerBundleSpec() // has a UDP additional listener
	extraUDP.L4StreamsV2[0].TOA = true
	if _, err := buildStreams(extraUDP); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("toa with a UDP additional listener accepted: %v", err)
	}
}

// docs/architecture/l4-v6-fields.md: toa is the last stream field.
func TestL4TOAIsTheLastStreamField(t *testing.T) {
	spec := toaBundleSpec()
	spec.L4StreamsV2[0].TOA = true
	spec.L4StreamsV2[0].NewConnRate = &L4NewConnRateV2{RatePerSecond: 10}
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	artifact := bundle.Files[L4RuntimeV2ArtifactPath]
	rate, toa := bytes.Index(artifact, []byte(`"new_conn_rate"`)), bytes.Index(artifact, []byte(`"toa":true}`))
	if rate < 0 || toa < rate {
		t.Fatalf("toa is not the last stream field: %s", artifact)
	}
}
