package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func validGrant() Grant {
	now := time.Unix(1_800_000_000, 0)
	return Grant{
		Schema:              SchemaV2,
		GrantID:             uuid.New(),
		LeafMemberID:        uuid.New(),
		SubscriptionPath:    []uuid.UUID{uuid.New(), uuid.New()},
		DownstreamRef:       "d-0001",
		OfferSnapshotDigest: strings.Repeat("ab", 32),
		NodePoolRef:         "node-group-1",
		Allocation:          spec.Allocation{HTTPPorts: 2, WebSocket: true},
		Limits: spec.LimitSet{
			{Metric: spec.MetricDomains, Cap: 10, Action: spec.ActionRejectNew},
			{Metric: spec.MetricBandwidthPeakBPS, Cap: 100_000_000, Action: spec.ActionThrottle, SustainBuckets: 2},
			{Metric: spec.MetricMonthlyTrafficBytes, Cap: 1 << 40, Action: spec.ActionThrottle, ThrottleBPS: 1_000_000},
		},
		Tags:           spec.Tags{CCProtection: spec.CCBasic, Tenancy: spec.TenancyShared, LineClass: "CN2 GIA"},
		LoadThresholds: spec.LoadThresholds{CPUPercent: 75, MemoryPercent: 70},
		Compliance:     spec.Compliance{RequireICP: true},
		IssuedAt:       now.Unix(),
		NotBefore:      now.Unix(),
		NotAfter:       now.Add(24 * time.Hour).Unix(),
		GraceSeconds:   int64((6 * time.Hour) / time.Second),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	public, private := testKey(t)
	g := validGrant()
	signed, err := Sign(g, "market-2026-10", private)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Keyring{"market-2026-10": public}.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, g) || got.Pool() != g.SubscriptionPath[1] {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, g)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	public, private := testKey(t)
	signed, err := Sign(validGrant(), "k1", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(signed.Payload)
	var g Grant
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	g.Limits[0].Cap = 1000
	tampered, _ := json.Marshal(g)
	signed.Payload = base64.StdEncoding.EncodeToString(tampered)
	if _, err := (Keyring{"k1": public}).Verify(signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestVerifyRejectsWrongKeyAndUnknownKey(t *testing.T) {
	_, private := testKey(t)
	other, _ := testKey(t)
	signed, err := Sign(validGrant(), "k1", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Keyring{"k1": other}).Verify(signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: want ErrSignature, got %v", err)
	}
	if _, err := (Keyring{"k2": other}).Verify(signed); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: want ErrUnknownKey, got %v", err)
	}
}

func TestVerifyRejectsIncompletePayload(t *testing.T) {
	public, private := testKey(t)
	payload := []byte(`{"schema":"` + SchemaV2 + `"}`)
	signed := Signed{
		KeyID:     "k1",
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, signedMessage(payload))),
	}
	if _, err := (Keyring{"k1": public}).Verify(signed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestValidateRejectsMalformedGrants(t *testing.T) {
	dup := uuid.New()
	cases := map[string]func(*Grant){
		"schema":      func(g *Grant) { g.Schema = "other" },
		"empty path":  func(g *Grant) { g.SubscriptionPath = nil },
		"cyclic path": func(g *Grant) { g.SubscriptionPath = []uuid.UUID{dup, uuid.New(), dup} },
		"digest":      func(g *Grant) { g.OfferSnapshotDigest = "xyz" },
		"window":      func(g *Grant) { g.NotAfter = g.NotBefore },
		"long window": func(g *Grant) { g.NotAfter = g.NotBefore + int64(400*24*time.Hour/time.Second) },
		"grace":       func(g *Grant) { g.GraceSeconds = -1 },
		"allocation":  func(g *Grant) { g.Allocation.HTTPPorts = -1 },
		"limit cap":   func(g *Grant) { g.Limits[0].Cap = 0 },
		"limit order": func(g *Grant) { g.Limits[0], g.Limits[1] = g.Limits[1], g.Limits[0] },
		"node limit": func(g *Grant) {
			g.Limits = append(g.Limits, spec.Limit{Metric: spec.MetricNodeCPUPercent, Cap: 50, Action: spec.ActionRemoveNode})
		},
		"tags":            func(g *Grant) { g.Tags.Tenancy = "" },
		"load thresholds": func(g *Grant) { g.LoadThresholds.CPUPercent = 0 },
		"no node pool":    func(g *Grant) { g.NodePoolRef = "" },
	}
	for name, mutate := range cases {
		g := validGrant()
		mutate(&g)
		if err := g.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestStatusAt(t *testing.T) {
	g := validGrant()
	at := func(offset int64) Status { return g.StatusAt(time.Unix(offset, 0)) }
	if s := at(g.NotBefore - 1); s != StatusNotYetValid {
		t.Errorf("before: %s", s)
	}
	if s := at(g.NotBefore); s != StatusActive {
		t.Errorf("start: %s", s)
	}
	if s := at(g.NotAfter); s != StatusGrace {
		t.Errorf("after: %s", s)
	}
	if s := at(g.NotAfter + g.GraceSeconds); s != StatusExpired {
		t.Errorf("past grace: %s", s)
	}
}

func TestSignRejectsBadKeyID(t *testing.T) {
	_, private := testKey(t)
	if _, err := Sign(validGrant(), "Bad Key", private); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}
