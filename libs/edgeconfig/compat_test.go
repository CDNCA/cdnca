package edgeconfig

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestBundleCodecGoldenAndStrictRoundTrip(t *testing.T) {
	bundle, err := newBundle(map[string][]byte{"nginx.conf": []byte("ok\n")})
	if err != nil {
		t.Fatalf("newBundle() error = %v", err)
	}
	encoded, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalBundle() error = %v", err)
	}
	want := `{"version":1,"manifest":{"files":[{"path":"nginx.conf","size":3,"sha256":"dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22"}]},"manifest_sha256":"460f118330081336cae2f409e3c93e60fa747f86d03d6e92a250fe37127737b3","files":{"nginx.conf":"b2sK"}}`
	if string(encoded) != want {
		t.Fatalf("wire document changed:\n got: %s\nwant: %s", encoded, want)
	}
	decoded, err := UnmarshalBundle(encoded)
	if err != nil {
		t.Fatalf("UnmarshalBundle() error = %v", err)
	}
	if decoded.ManifestSHA256 != bundle.ManifestSHA256 || !bytes.Equal(decoded.Files["nginx.conf"], bundle.Files["nginx.conf"]) {
		t.Fatalf("round trip changed bundle: %#v", decoded)
	}
	for _, content := range [][]byte{
		[]byte(`{"version":1,"version":1}`),
		append(append([]byte(nil), encoded...), []byte(` {}`)...),
		bytes.Replace(encoded, []byte(`"files"`), []byte(`"unknown"`), 1),
		bytes.Replace(encoded, []byte(`"b2sK"`), []byte(`"YmFk"`), 1),
		bytes.Replace(encoded, []byte(`"nginx.conf":"b2sK"`), []byte(`"extra.conf":"b2sK"`), 1),
		bytes.Replace(encoded, []byte(`"nginx.conf":"b2sK"`), []byte(`"nginx.conf":"b2sK","extra.conf":"b2sK"`), 1),
	} {
		if _, err := UnmarshalBundle(content); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("UnmarshalBundle(%q) error = %v, want ErrInvalidBundle", content, err)
		}
	}
}

func combinedCompatibilitySpec() Spec {
	return Spec{
		ConfigVersionID: "cfg-compat-v1",
		StateRoot:       "/var/lib/cdnca-edge",
		HealthPort:      18080,
		Sites: []Site{{
			Domain: "WWW.EXAMPLE.COM.", ListenPort: 8080, Protocol: ProtocolHTTP,
			Origins: []Origin{
				{Host: "192.0.2.20", Port: 8081, Weight: 2},
				{Host: "192.0.2.10", Port: 8080, Weight: 1},
			},
			Balance: BalanceURLHash, FailoverTries: 2,
			ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
			WebSocket: true, Range: true,
			ACL: ACLPolicy{
				Rules:         []ACLRule{{Action: ACLDeny, CIDR: "198.51.100.0/24"}},
				DefaultAction: ACLAllow,
			},
			WAF: WAFPolicy{Rules: []WAFRule{{
				Match:  WAFMatch{Method: "POST", Path: &WAFPathMatch{Kind: WAFPathExact, Value: "/blocked"}},
				Action: WAFDeny, Control: WAFStop,
			}}},
			Cache: CachePolicy{
				Mode: CacheOverride, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20,
				DefaultTTL: 60 * time.Second, StatusTTLs: []CacheStatusTTL{{Status: 404, TTL: 5 * time.Second}},
				StaleOnUpstreamError: true,
			},
		}},
	}
}
