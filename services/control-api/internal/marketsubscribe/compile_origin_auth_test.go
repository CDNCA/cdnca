package marketsubscribe

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

const (
	testAccessKey = "AKIDEXAMPLEACCESSKEY01"
	testSecretKey = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
)

func leafKey(t *testing.T) (private, public []byte) {
	t.Helper()
	private = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func originAuthRules() []originauthcontrol.SiteRule {
	at := time.Unix(1_900_000_000, 0)
	return []originauthcontrol.SiteRule{{RuleID: uuid.New(), SourcePosition: 1, Provider: "oss",
		Algorithm: "oss4-hmac-sha256", Endpoint: "https://bucket.oss-cn-hangzhou.aliyuncs.com", Bucket: "bucket",
		Region: "cn-hangzhou", Service: "oss", SignatureTTLSeconds: 300,
		Current: originauthcontrol.SiteKey{RevisionRef: uuid.New(), NotBefore: at, ExpiresAt: at.Add(time.Hour),
			Secret: originauthcontrol.CredentialSecret{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey},
			Seed:   [32]byte{7}}}}
}

// fix-mktsiteconf5: each leaf opens only its own box; nothing in the
// siteconf (what site_supply_config_revisions stores) is the credential.
func TestSealOriginAuthPerLeaf(t *testing.T) {
	alicePrivate, alicePublic := leafKey(t)
	bobPrivate, bobPublic := leafKey(t)
	alice, bob := uuid.New(), uuid.New()
	siteID := uuid.New()
	rules := originAuthRules()
	block, err := sealOriginAuth(siteID, rules, map[uuid.UUID][]byte{alice: alicePublic, bob: bobPublic})
	if err != nil {
		t.Fatal(err)
	}
	key := block.Rules[0].Current
	if len(key.Sealed) != 2 {
		t.Fatalf("boxes = %d, want one per leaf", len(key.Sealed))
	}
	aad := siteconf.OriginAuthAAD(siteID, rules[0].RuleID, key.Ref, alice)
	plaintext, err := envelope.OpenBox(siteconf.OriginAuthBoxDomain, key.Sealed[alice], aad, alicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	var secret siteconf.OriginAuthSecret
	if err := json.Unmarshal(plaintext, &secret); err != nil || secret.AccessKeyID != testAccessKey ||
		secret.SecretAccessKey != testSecretKey {
		t.Fatalf("opened secret = %+v, %v", secret, err)
	}
	// Bob's key does not open Alice's box, nor Alice's key Bob's (its AAD
	// names Bob).
	if _, err := envelope.OpenBox(siteconf.OriginAuthBoxDomain, key.Sealed[alice], aad, bobPrivate); !errors.Is(err, envelope.ErrDecrypt) {
		t.Fatalf("wrong leaf opened the box: %v", err)
	}
	if _, err := envelope.OpenBox(siteconf.OriginAuthBoxDomain, key.Sealed[bob], aad, alicePrivate); !errors.Is(err, envelope.ErrDecrypt) {
		t.Fatalf("leaf opened another leaf's box: %v", err)
	}

	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.test"}, HTTPSPorts: []int{443},
		OriginScheme: "https", Origins: []siteconf.Origin{{Host: "bucket.oss-cn-hangzhou.aliyuncs.com", Port: 443}},
		OriginAuth: block}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	stored, _ := json.Marshal(cfg)
	for _, clear := range []string{testAccessKey, testSecretKey, "access_key_id", "secret_access_key"} {
		if bytes.Contains(stored, []byte(clear)) {
			t.Fatalf("stored siteconf carries %q", clear)
		}
	}

	again, err := sealOriginAuth(siteID, originAuthRulesLike(rules), map[uuid.UUID][]byte{alice: alicePublic, bob: bobPublic})
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := cfg
	cfg2.OriginAuth = again
	if err := cfg2.Normalize(); err != nil || cfg2.Digest() != cfg.Digest() {
		t.Fatalf("recompiling the same rules changed the digest: %v", err)
	}
}

// originAuthRulesLike is rules with fresh copies of the secrets (the seal
// must not depend on the slice it was given).
func originAuthRulesLike(rules []originauthcontrol.SiteRule) []originauthcontrol.SiteRule {
	out := make([]originauthcontrol.SiteRule, len(rules))
	copy(out, rules)
	return out
}
