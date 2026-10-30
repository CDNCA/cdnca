package gatewayaddr

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

const testNode = "6f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f"

func testChange(now time.Time) Change {
	return Change{NodeID: testNode, ChangeID: "0c9b5f0e-6a51-4d3e-9a52-2f6a3c1d7b80", Revision: 3,
		Address: "gateway.cdnca.com:9443", ServerName: "gateway.cdnca.com",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix()}
}

func TestSignOpenRoundTripAndRoute(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	encoded, err := Sign(testChange(now), "edge-1", private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(id string) (ed25519.PublicKey, bool) { return public, id == "edge-1" }
	change, err := Open(encoded, testNode, trusted)
	if err != nil || change.Address != "gateway.cdnca.com:9443" || change.ServerName != "gateway.cdnca.com" || change.Revision != 3 {
		t.Fatalf("open = %+v, %v", change, err)
	}
	node, revision, err := Route(encoded)
	if err != nil || node != testNode || revision != 3 {
		t.Fatalf("route = %s %d %v", node, revision, err)
	}
	if len(Digest(encoded)) != 32 {
		t.Fatal("digest length")
	}
}

func TestOpenRejectsTamperUntrustedAndWrongNode(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	otherPublic, _, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	encoded, _ := Sign(testChange(now), "edge-1", private)
	trusted := func(string) (ed25519.PublicKey, bool) { return public, true }
	tampered := []byte(strings.Replace(string(encoded), "9443", "9444", 1))
	if _, err := Open(tampered, testNode, trusted); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := Open(encoded, testNode, func(string) (ed25519.PublicKey, bool) { return otherPublic, true }); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := Open(encoded, "7f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f", trusted); !errors.Is(err, ErrWrongNode) {
		t.Fatalf("wrong node: %v", err)
	}
}

func TestValidateRejectsBadDocuments(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	for name, mutate := range map[string]func(*Change){
		"no port":        func(c *Change) { c.Address = "gateway.cdnca.com" },
		"port zero":      func(c *Change) { c.Address = "gateway.cdnca.com:0" },
		"bad sni":        func(c *Change) { c.ServerName = "gate way" },
		"zero revision":  func(c *Change) { c.Revision = 0 },
		"bad node":       func(c *Change) { c.NodeID = "node" },
		"expiry too far": func(c *Change) { c.ExpiresAt = c.IssuedAt + int64(MaxLifetime/time.Second) + 1 },
		"expiry before":  func(c *Change) { c.ExpiresAt = c.IssuedAt },
	} {
		change := testChange(now)
		mutate(&change)
		if _, err := Sign(change, "edge-1", private); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestExpired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	change := testChange(now)
	if change.Expired(now) || !change.Expired(now.Add(25*time.Hour)) {
		t.Fatal("expiry")
	}
}
