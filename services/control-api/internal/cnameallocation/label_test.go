package cnameallocation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGenerateLabelIsDeterministicAndDomainSeparated(t *testing.T) {
	key := Key{ID: "cname-label-2026-08", Secret: []byte("0123456789abcdef0123456789abcdef")}
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	providerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	ownerID := uuid.MustParse("33333333-3333-4333-8333-333333333333")

	baseline, err := GenerateLabel(key, tenantID, providerID, ownerID, ModeSite, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := GenerateLabel(key, tenantID, providerID, ownerID, ModeSite, "example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if baseline != replay {
		t.Fatalf("stable input generated %q then %q", baseline, replay)
	}

	mutations := []struct {
		name       string
		key        Key
		tenantID   uuid.UUID
		providerID uuid.UUID
		ownerID    uuid.UUID
		mode       Mode
		domain     string
		generation uint64
	}{
		{name: "key", key: Key{ID: "cname-label-next", Secret: []byte("abcdef0123456789abcdef0123456789")}, tenantID: tenantID, providerID: providerID, ownerID: ownerID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "tenant", key: key, tenantID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), providerID: providerID, ownerID: ownerID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "provider", key: key, tenantID: tenantID, providerID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), ownerID: ownerID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "owner", key: key, tenantID: tenantID, providerID: providerID, ownerID: uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), mode: ModeSite, domain: "example.com", generation: 1},
		{name: "mode", key: key, tenantID: tenantID, providerID: providerID, ownerID: ownerID, mode: ModePackage, domain: "example.com", generation: 1},
		{name: "domain", key: key, tenantID: tenantID, providerID: providerID, ownerID: ownerID, mode: ModeSite, domain: "sub.example.com", generation: 1},
		{name: "generation", key: key, tenantID: tenantID, providerID: providerID, ownerID: ownerID, mode: ModeSite, domain: "example.com", generation: 2},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			got, err := GenerateLabel(mutation.key, mutation.tenantID, mutation.providerID, mutation.ownerID, mutation.mode, mutation.domain, mutation.generation)
			if err != nil {
				t.Fatal(err)
			}
			if got == baseline {
				t.Fatalf("%s is not bound into generated label %q", mutation.name, got)
			}
		})
	}
}

func TestGenerateLabelIsDNSLabelAndDoesNotExposeStableIdentity(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	providerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	ownerID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	label, err := GenerateLabel(
		Key{ID: "cname-label-2026-08", Secret: []byte("0123456789abcdef0123456789abcdef")},
		tenantID, providerID, ownerID, ModeSite, "example.com", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(label) {
		t.Fatalf("generated label %q is not a valid lowercase DNS label", label)
	}
	if len(label) != LabelLength {
		t.Fatalf("generated label length=%d, want %d", len(label), LabelLength)
	}
	for _, identity := range []uuid.UUID{tenantID, providerID, ownerID} {
		compact := strings.ReplaceAll(identity.String(), "-", "")
		if strings.Contains(label, identity.String()) || strings.Contains(label, compact) {
			t.Fatalf("generated label %q exposes stable identity %s", label, identity)
		}
	}
	raw := sha256.Sum256([]byte(tenantID.String() + providerID.String() + ownerID.String()))
	if label == hex.EncodeToString(raw[:]) {
		t.Fatal("generated label is a bare, offline-enumerable UUID digest")
	}
}

func TestGenerateLabelRejectsInvalidAuthority(t *testing.T) {
	validKey := Key{ID: "cname-label-2026-08", Secret: []byte("0123456789abcdef0123456789abcdef")}
	validID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tests := []struct {
		name       string
		key        Key
		tenantID   uuid.UUID
		providerID uuid.UUID
		ownerID    uuid.UUID
		mode       Mode
		domain     string
		generation uint64
	}{
		{name: "missing key id", key: Key{Secret: validKey.Secret}, tenantID: validID, providerID: validID, ownerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "empty key", key: Key{ID: validKey.ID}, tenantID: validID, providerID: validID, ownerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "short key", key: Key{ID: validKey.ID, Secret: []byte("short")}, tenantID: validID, providerID: validID, ownerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "missing tenant", key: validKey, providerID: validID, ownerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "missing provider", key: validKey, tenantID: validID, ownerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "missing owner", key: validKey, tenantID: validID, providerID: validID, mode: ModeSite, domain: "example.com", generation: 1},
		{name: "unknown mode", key: validKey, tenantID: validID, providerID: validID, ownerID: validID, mode: Mode("shared"), domain: "example.com", generation: 1},
		{name: "empty domain", key: validKey, tenantID: validID, providerID: validID, ownerID: validID, mode: ModeSite, generation: 1},
		{name: "zero generation", key: validKey, tenantID: validID, providerID: validID, ownerID: validID, mode: ModeSite, domain: "example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GenerateLabel(test.key, test.tenantID, test.providerID, test.ownerID, test.mode, test.domain, test.generation); err == nil {
				t.Fatal("GenerateLabel accepted invalid authority")
			}
		})
	}
}

var labelTestKey = Key{ID: "cname-label-2026-08", Secret: []byte("0123456789abcdef0123456789abcdef")}

func TestGenerateLabelIsEightLowercaseAlphanumerics(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z0-9]{8}$`)
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	providerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	for i := 0; i < 2000; i++ {
		ownerID := uuid.New()
		label, err := GenerateLabel(labelTestKey, tenantID, providerID, ownerID, ModePackage, "ikvm.asia", uint64(i%5+1))
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString(label) {
			t.Fatalf("label %q is not 8 chars of a-z0-9", label)
		}
		again, err := GenerateLabel(labelTestKey, tenantID, providerID, ownerID, ModePackage, "IKVM.asia.", uint64(i%5+1))
		if err != nil || again != label {
			t.Fatalf("same input produced %q then %q (err %v)", label, again, err)
		}
	}
}

// The label is the base36 encoding of the unchanged v1 HMAC input, first 8 digits.
func TestGenerateLabelIsBase36PrefixOfUnchangedHMAC(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	providerID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	ownerID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	mac := hmac.New(sha256.New, labelTestKey.Secret)
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], 3)
	for _, part := range [][]byte{[]byte(labelDomainSeparator), []byte(labelTestKey.ID), tenantID[:], providerID[:],
		ownerID[:], []byte(ModeSite), []byte("example.com"), generation[:]} {
		writeLabelPart(mac, part)
	}
	want := new(big.Int).SetBytes(mac.Sum(nil)).Text(36)[:LabelLength]
	got, err := GenerateLabel(labelTestKey, tenantID, providerID, ownerID, ModeSite, "example.com", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("label=%q, want base36 HMAC prefix %q", got, want)
	}
}

func TestBase36PrefixKeepsFixedWidth(t *testing.T) {
	if got := base36Prefix([]byte{0x01}, LabelLength); got != "00000001" {
		t.Fatalf("small digest prefix=%q, want zero padded", got)
	}
}

func TestFreeGeneratedHostnameAdvancesLabelGenerationOnCollision(t *testing.T) {
	tenantID, providerID, ownerID := uuid.New(), uuid.New(), uuid.New()
	label := func(generation uint64) string {
		value, err := GenerateLabel(labelTestKey, tenantID, providerID, ownerID, ModePackage, "ikvm.asia", generation)
		if err != nil {
			t.Fatal(err)
		}
		return value + ".ikvm.asia"
	}
	claimed := map[string]bool{label(4): true, label(5): true}
	var checked []string
	got, err := freeGeneratedHostname(labelTestKey, tenantID, providerID, ownerID, ModePackage, "ikvm.asia", 4,
		func(hostname string) (bool, error) {
			checked = append(checked, hostname)
			return claimed[hostname], nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if got != label(6) || len(checked) != 3 {
		t.Fatalf("hostname=%q after %d checks, want %q after 3", got, len(checked), label(6))
	}
	free, err := freeGeneratedHostname(labelTestKey, tenantID, providerID, ownerID, ModePackage, "ikvm.asia", 4,
		func(string) (bool, error) { return false, nil })
	if err != nil || free != label(4) {
		t.Fatalf("uncontended hostname=%q err=%v, want %q", free, err, label(4))
	}
}

func TestFreeGeneratedHostnameReportsExhaustion(t *testing.T) {
	calls := 0
	_, err := freeGeneratedHostname(labelTestKey, uuid.New(), uuid.New(), uuid.New(), ModeSite, "example.com", 1,
		func(string) (bool, error) { calls++; return true, nil })
	if calls != MaxLabelAttempts {
		t.Fatalf("checked %d candidates, want %d", calls, MaxLabelAttempts)
	}
	if failureCode(err) != FailureLabelExhausted || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("exhaustion err=%v code=%q, want %s terminal failure", err, failureCode(err), FailureLabelExhausted)
	}
	lookup := errors.New("lookup failed")
	if _, err := freeGeneratedHostname(labelTestKey, uuid.New(), uuid.New(), uuid.New(), ModeSite, "example.com", 1,
		func(string) (bool, error) { return false, lookup }); !errors.Is(err, lookup) {
		t.Fatalf("lookup error was swallowed: %v", err)
	}
}
