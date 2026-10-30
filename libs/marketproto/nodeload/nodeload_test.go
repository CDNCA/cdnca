package nodeload

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/google/uuid"
)

const created = 1_800_000_000

func validReport() Report {
	at := int64(created - created%WindowSeconds)
	return Report{Schema: SchemaV1, ReportID: uuid.New(), LeafMemberID: uuid.New(), CreatedAt: created,
		Items: []Item{
			{NodePoolRef: "pool-a", NodeID: uuid.New(), ObservedAt: at, CPUPercent: 81.5, MemoryPercent: 40, SampleCount: 6},
			{NodePoolRef: "pool-a", NodeID: uuid.New(), ObservedAt: at, CPUPercent: 10, MemoryPercent: 69.9, SampleCount: 1},
		}}
}

func TestSignVerifyRoundTripAndTamper(t *testing.T) {
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
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Verify(other, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	tampered := r
	tampered.Items = append([]Item(nil), r.Items...)
	tampered.Items[0].CPUPercent = 1
	payload, _ := json.Marshal(tampered)
	if _, _, err := Verify(pub, Signed{Payload: base64.StdEncoding.EncodeToString(payload), Signature: signed.Signature}); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
	if _, _, err := Verify(pub, Signed{Payload: "!!", Signature: signed.Signature}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad base64: %v", err)
	}
	if _, err := Sign(r, priv[:10]); !errors.Is(err, ErrInvalid) {
		t.Fatal("short key accepted")
	}
}

// The same member key signs usage and node load; the domains keep one kind
// of report from being replayed as the other.
func TestDomainSeparationFromUsage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(validReport())
	asUsage := Signed{Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(usage.Domain), payload...)))}
	if _, _, err := Verify(pub, asUsage); !errors.Is(err, ErrSignature) {
		t.Fatalf("usage-domain signature accepted: %v", err)
	}
	if Domain == usage.Domain {
		t.Fatal("domains must differ")
	}
}

func TestValidateBounds(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	bad := map[string]func(*Report){
		"schema":        func(r *Report) { r.Schema = "cdnca.market.nodeload/v0" },
		"no report id":  func(r *Report) { r.ReportID = uuid.Nil },
		"no items":      func(r *Report) { r.Items = nil },
		"too many":      func(r *Report) { r.Items = make([]Item, MaxItems+1) },
		"no pool":       func(r *Report) { r.Items[0].NodePoolRef = "" },
		"long pool":     func(r *Report) { r.Items[0].NodePoolRef = strings.Repeat("p", MaxNodePoolRef+1) },
		"no node":       func(r *Report) { r.Items[0].NodeID = uuid.Nil },
		"unaligned":     func(r *Report) { r.Items[0].ObservedAt++ },
		"future":        func(r *Report) { r.Items[0].ObservedAt = r.CreatedAt - r.CreatedAt%60 + 120 },
		"cpu > 100":     func(r *Report) { r.Items[0].CPUPercent = 100.01 },
		"cpu < 0":       func(r *Report) { r.Items[0].CPUPercent = -0.1 },
		"cpu NaN":       func(r *Report) { r.Items[0].CPUPercent = math.NaN() },
		"mem > 100":     func(r *Report) { r.Items[0].MemoryPercent = 101 },
		"zero samples":  func(r *Report) { r.Items[0].SampleCount = 0 },
		"many samples":  func(r *Report) { r.Items[0].SampleCount = MaxSamples + 1 },
		"duplicate key": func(r *Report) { r.Items[1].NodeID = r.Items[0].NodeID },
	}
	for name, mutate := range bad {
		r := validReport()
		mutate(&r)
		if _, err := Sign(r, priv); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	edge := validReport()
	edge.Items[0].CPUPercent, edge.Items[0].MemoryPercent, edge.Items[0].SampleCount = 100, 0, MaxSamples
	if _, err := Sign(edge, priv); err != nil {
		t.Fatalf("boundaries: %v", err)
	}
}

func TestVerifyRejectsUnknownFields(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, mutate := range map[string]func(map[string]any){
		"top level": func(f map[string]any) { f["extra"] = 1 },
		"item":      func(f map[string]any) { f["items"].([]any)[0].(map[string]any)["disk_percent"] = 1 },
	} {
		raw, _ := json.Marshal(validReport())
		var fields map[string]any
		_ = json.Unmarshal(raw, &fields)
		mutate(fields)
		payload, _ := json.Marshal(fields)
		s := Signed{Payload: base64.StdEncoding.EncodeToString(payload),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(Domain), payload...)))}
		if _, _, err := Verify(pub, s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestOver(t *testing.T) {
	floor := spec.DefaultLoadFloor
	cases := []struct {
		cpu, mem float64
		want     bool
	}{{79.9, 69.9, false}, {80, 0, true}, {0, 70, true}, {100, 100, true}}
	for _, c := range cases {
		if got := (Item{CPUPercent: c.cpu, MemoryPercent: c.mem}).Over(floor); got != c.want {
			t.Errorf("Over(%v,%v) = %v", c.cpu, c.mem, got)
		}
	}
}
