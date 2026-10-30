package nodeaction

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const now = 1_800_000_000

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func ptr(id uuid.UUID) *uuid.UUID { return &id }

func valid() Report {
	node := uuid.New()
	return Report{Schema: SchemaV1, ReportID: uuid.New(), LeafMemberID: uuid.New(), CreatedAt: now, Items: []Item{
		{NodePoolRef: "pool-1", NodeID: node, At: now - 30, Source: SourceDDoS, Kind: "rate_ban", Level: 4, Count: 12},
		{NodePoolRef: "pool-1", NodeID: node, At: now - 20, Source: SourceXDP, Kind: "fallback", Level: 4, Count: 1},
		{NodePoolRef: "pool-1", NodeID: node, At: now - 10, Source: SourceAutoDefense, Kind: "kernel_ban", Level: 4, Count: 2,
			GrantID: ptr(uuid.New()), LeafSiteID: ptr(uuid.New())},
	}}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	public, private := key(t)
	r := valid()
	signed, err := Sign(r, private)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := Verify(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) || len(raw) == 0 {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, r)
	}
	if Operation != "market.node_action" {
		t.Fatalf("op %q", Operation)
	}
	if strings.Contains(string(raw), "client") {
		t.Fatal("report must not carry client addresses")
	}
}

func TestVerifyRejectsTamperWrongKeyAndUnknownField(t *testing.T) {
	public, private := key(t)
	signed, err := Sign(valid(), private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(signed.Payload)
	tampered := signed
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"count":12`, `"count":13`, 1)))
	if _, _, err := Verify(public, tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
	other, _ := key(t)
	if _, _, err := Verify(other, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["items"].([]any)[0].(map[string]any)["client"] = "203.0.113.7"
	extra, _ := json.Marshal(m)
	forged := Signed{Payload: base64.StdEncoding.EncodeToString(extra),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain), extra...)))}
	if _, _, err := Verify(public, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestValidateBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*Report){
		"schema":             func(r *Report) { r.Schema = "cdnca.market.nodeaction/v2" },
		"nil report":         func(r *Report) { r.ReportID = uuid.Nil },
		"no items":           func(r *Report) { r.Items = nil },
		"too many items":     func(r *Report) { r.Items = many(MaxItems + 1) },
		"empty pool":         func(r *Report) { r.Items[0].NodePoolRef = "" },
		"long pool":          func(r *Report) { r.Items[0].NodePoolRef = strings.Repeat("p", MaxNodePoolRef+1) },
		"nil node":           func(r *Report) { r.Items[0].NodeID = uuid.Nil },
		"future":             func(r *Report) { r.Items[0].At = now + maxSkew + 1 },
		"unknown source":     func(r *Report) { r.Items[0].Source = "waf" },
		"bad kind":           func(r *Report) { r.Items[0].Kind = "Rate-Ban" },
		"level 6":            func(r *Report) { r.Items[0].Level = 6 },
		"count 0":            func(r *Report) { r.Items[0].Count = 0 },
		"count too large":    func(r *Report) { r.Items[0].Count = MaxCount + 1 },
		"grant without site": func(r *Report) { r.Items[2].LeafSiteID = nil },
		"site without grant": func(r *Report) { r.Items[2].GrantID = nil },
		"nil site id":        func(r *Report) { r.Items[2].LeafSiteID = ptr(uuid.Nil) },
		"site on ddos":       func(r *Report) { r.Items[0].GrantID, r.Items[0].LeafSiteID = ptr(uuid.New()), ptr(uuid.New()) },
		"site below L4":      func(r *Report) { r.Items[2].Level = 3 },
		"duplicate":          func(r *Report) { r.Items = append(r.Items, r.Items[0]) },
	} {
		r := valid()
		mutate(&r)
		if err := r.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	r := valid()
	r.Items = many(MaxItems)
	if err := r.Validate(); err != nil {
		t.Fatalf("MaxItems rejected: %v", err)
	}
	_, private := key(t)
	if _, err := Sign(r, private); err != nil {
		t.Fatalf("full report exceeds payload bound: %v", err)
	}
	// Same node and time on two different sites are two items, not duplicates.
	r = valid()
	twin := r.Items[2]
	twin.LeafSiteID = ptr(uuid.New())
	r.Items = append(r.Items, twin)
	if err := r.Validate(); err != nil {
		t.Fatalf("distinct sites rejected as duplicate: %v", err)
	}
}

func many(n int) []Item {
	items := make([]Item, n)
	for i := range items {
		items[i] = Item{NodePoolRef: strings.Repeat("p", MaxNodePoolRef), NodeID: uuid.New(), At: now, Source: SourceAutoDefense,
			Kind: "xdp_drop", Level: 5, Count: MaxCount, GrantID: ptr(uuid.New()), LeafSiteID: ptr(uuid.New())}
	}
	return items
}

func TestSiteAttributableCountsOnlySiteVerdicts(t *testing.T) {
	r := valid()
	var counted int
	for _, it := range r.Items {
		if it.SiteAttributable() {
			counted++
		}
	}
	if counted != 1 || !r.Items[2].SiteAttributable() {
		t.Fatalf("only the site-attributable autodefense verdict may count (U8), got %d", counted)
	}
}
