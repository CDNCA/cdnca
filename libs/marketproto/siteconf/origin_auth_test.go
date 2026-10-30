package siteconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/google/uuid"
)

func originAuthSample() Config {
	c := sample()
	c.Origins = append(c.Origins, Origin{Host: "bucket.oss-cn-hangzhou.aliyuncs.com", Port: 443})
	c.OriginScheme = "https"
	box := envelope.Box{Ephemeral: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 24),
		Ciphertext: bytes.Repeat([]byte{3}, 40)}
	leaf := uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-000000000001")
	c.OriginAuth = &OriginAuth{Rules: []OriginAuthRule{{
		RuleID: uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-0000000000a1"), Provider: "oss", Algorithm: "oss4-hmac-sha256",
		Endpoint: "https://bucket.oss-cn-hangzhou.aliyuncs.com", Bucket: "bucket", Region: "cn-hangzhou", Service: "oss",
		SignatureTTLSeconds: 300,
		Current: OriginAuthKey{Ref: uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-0000000000c1"), NotBefore: 1, ExpiresAt: 2,
			Sealed: map[uuid.UUID]envelope.Box{leaf: box}},
	}}}
	return c
}

func TestOriginAuthNormalizes(t *testing.T) {
	c := originAuthSample()
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil || back.Normalize() != nil || back.Digest() != c.Digest() {
		t.Fatalf("round trip changed the digest: %v", err)
	}
	empty := sample()
	empty.OriginAuth = &OriginAuth{}
	if err := empty.Normalize(); err != nil || empty.OriginAuth != nil {
		t.Fatalf("empty origin auth = %+v, %v", empty.OriginAuth, err)
	}
}

func TestOriginAuthRejectsMalformed(t *testing.T) {
	for name, mutate := range map[string]func(*OriginAuthRule){
		"endpoint not an origin": func(r *OriginAuthRule) { r.Endpoint = "https://other.example.net" },
		"plain http":             func(r *OriginAuthRule) { r.Endpoint = "http://bucket.oss-cn-hangzhou.aliyuncs.com" },
		"no box":                 func(r *OriginAuthRule) { r.Current.Sealed = nil },
		"previous without time":  func(r *OriginAuthRule) { p := r.Current; p.Ref = uuid.New(); r.Previous = &p },
		"provider":               func(r *OriginAuthRule) { r.Provider = "gcs" },
		"ttl":                    func(r *OriginAuthRule) { r.SignatureTTLSeconds = 0 },
		"duplicate key ref only": func(r *OriginAuthRule) { r.Current.Ref = uuid.Nil },
	} {
		c := originAuthSample()
		mutate(&c.OriginAuth.Rules[0])
		if err := c.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Normalize = %v", name, err)
		}
	}
	for name, c := range map[string]Config{"plain origin scheme": func() Config {
		c := originAuthSample()
		c.OriginScheme = "follow"
		return c
	}()} {
		if err := c.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Normalize = %v", name, err)
		}
	}
}
