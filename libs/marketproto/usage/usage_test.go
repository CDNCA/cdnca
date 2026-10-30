package usage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

func validReport() Report {
	return Report{Schema: SchemaV2, ReportID: uuid.New(), LeafMemberID: uuid.New(), CreatedAt: 1_800_000_000,
		Items: []Item{{GrantID: uuid.New(), BucketStart: 1_800_000_000 - 1_800_000_000%300, BytesOut: 1 << 30, Requests: 9,
			PeakBPS: 80_000_000, MaxConcurrent: 120, MaxRequests: 150, MaxQPS: 300, MaxNewCPS: 40}}}
}

func resign(t *testing.T, priv ed25519.PrivateKey, mutate func(map[string]any)) Signed {
	t.Helper()
	raw, _ := json.Marshal(validReport())
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	mutate(fields)
	payload, _ := json.Marshal(fields)
	return Signed{Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(Domain), payload...)))}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := validReport()
	signed, err := Sign(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := Verify(pub, signed)
	if err != nil || !reflect.DeepEqual(got, r) || len(raw) == 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	for m, want := range map[spec.Metric]int64{spec.MetricBandwidthPeakBPS: 80_000_000, spec.MetricConcurrentConnections: 120,
		spec.MetricConcurrentRequests: 150, spec.MetricQPS: 300, spec.MetricNewConnectionsPerSecond: 40} {
		if v, ok := got.Items[0].Peak(m); !ok || v != want {
			t.Errorf("Peak(%s) = %d, %v", m, v, ok)
		}
	}
	if _, ok := got.Items[0].Peak(spec.MetricDomains); ok {
		t.Fatal("domains is not a bucket peak")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Verify(other, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(signed.Payload)
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-3] ^= 1
	if _, _, err := Verify(pub, Signed{Payload: base64.StdEncoding.EncodeToString(tampered), Signature: signed.Signature}); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestValidateBounds(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	bad := map[string]func(*Report){
		"v1 schema":      func(r *Report) { r.Schema = "cdnca.market.usage-report/v1" },
		"no items":       func(r *Report) { r.Items = nil },
		"too many items": func(r *Report) { r.Items = make([]Item, MaxItems+1) },
		"unaligned":      func(r *Report) { r.Items[0].BucketStart++ },
		"negative peak":  func(r *Report) { r.Items[0].PeakBPS = -1 },
		"negative conc":  func(r *Report) { r.Items[0].MaxConcurrent = -1 },
		"negative reqs":  func(r *Report) { r.Items[0].MaxRequests = -1 },
		"negative qps":   func(r *Report) { r.Items[0].MaxQPS = -1 },
		"negative cps":   func(r *Report) { r.Items[0].MaxNewCPS = -1 },
		"peak above max": func(r *Report) { r.Items[0].PeakBPS = spec.MaxBandwidthBPS + 1 },
	}
	for name, mutate := range bad {
		r := validReport()
		mutate(&r)
		if _, err := Sign(r, priv); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestVerifyRejectsV1AndUnknownFields(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]func(map[string]any){
		"v1 schema":  func(f map[string]any) { f["schema"] = "cdnca.market.usage-report/v1" },
		"no schema":  func(f map[string]any) { delete(f, "schema") },
		"top level":  func(f map[string]any) { f["extra"] = 1 },
		"item field": func(f map[string]any) { f["items"].([]any)[0].(map[string]any)["max_iops"] = 1 },
	}
	for name, mutate := range cases {
		if _, _, err := Verify(pub, resign(t, priv, mutate)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// A v1-domain signature (pre-1.0.35 leaf) never verifies under v2.
	raw, _ := json.Marshal(validReport())
	v1 := Signed{Payload: base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte("cdnca.market.usage-report/v1\n"), raw...)))}
	if _, _, err := Verify(pub, v1); !errors.Is(err, ErrSignature) {
		t.Fatalf("v1 domain: %v", err)
	}
}
