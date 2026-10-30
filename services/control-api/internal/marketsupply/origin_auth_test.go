package marketsupply

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
)

type fakeOriginAuth struct{ invalid bool }

func (f fakeOriginAuth) ValidateSiteRule(originauthcontrol.SiteRule) error {
	if f.invalid {
		return originauthcontrol.ErrValidation
	}
	return nil
}

func (fakeOriginAuth) SetSiteSystem(context.Context, originauthcontrol.SystemSiteWrite) (bool, error) {
	return true, nil
}

func boxPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

// sealedConfig is a config whose one rule has a box for leaf only.
func sealedConfig(t *testing.T, siteID, leaf uuid.UUID, public []byte) siteconf.Config {
	t.Helper()
	ruleID, ref := uuid.New(), uuid.New()
	plaintext, _ := json.Marshal(siteconf.OriginAuthSecret{AccessKeyID: "AKIDLEAFTEST", SecretAccessKey: "leaf-secret"})
	box, err := envelope.SealBox(siteconf.OriginAuthBoxDomain, plaintext, siteconf.OriginAuthAAD(siteID, ruleID, ref, leaf), public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.test"}, HTTPSPorts: []int{443},
		OriginScheme: "https", Origins: []siteconf.Origin{{Host: "a.example.test", Port: 80},
			{Host: "bucket.oss-cn-hangzhou.aliyuncs.com", Port: 443}},
		OriginAuth: &siteconf.OriginAuth{Rules: []siteconf.OriginAuthRule{{RuleID: ruleID, Provider: "oss",
			Algorithm: "oss4-hmac-sha256", Endpoint: "https://bucket.oss-cn-hangzhou.aliyuncs.com", Bucket: "bucket",
			Region: "cn-hangzhou", Service: "oss", SignatureTTLSeconds: 300,
			Current: siteconf.OriginAuthKey{Ref: ref, NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
				Sealed: map[uuid.UUID]envelope.Box{leaf: box}}}}}}
}

// fix-mktsiteconf5: the leaf opens its own box at the leaf source position;
// a box for another leaf, a missing store or a rule the leaf cannot hold
// blocks the revision (never silently dropped).
func TestLeafOpensItsOwnOriginAuthBox(t *testing.T) {
	private, public := boxPair(t)
	otherPrivate, _ := boxPair(t)
	leaf, siteID := uuid.New(), uuid.New()
	c := sealedConfig(t, siteID, leaf, public)

	s := (&Service{}).WithOriginAuth(fakeOriginAuth{}, func() (uuid.UUID, []byte) { return leaf, private })
	rules, err := s.openOriginAuth(c, siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].SourcePosition != 2 || rules[0].Current.Secret.SecretAccessKey != "leaf-secret" {
		t.Fatalf("opened rules = %+v", rules)
	}
	originauthcontrol.ClearSiteRules(rules)
	if rules[0].Current.Secret.SecretAccessKey != "" {
		t.Fatal("ClearSiteRules left the secret")
	}
	if b := s.originAuthBlockers(c, siteID); len(b) != 0 {
		t.Fatalf("blockers = %+v", b)
	}

	for name, svc := range map[string]*Service{
		"another leaf's key": (&Service{}).WithOriginAuth(fakeOriginAuth{}, func() (uuid.UUID, []byte) { return leaf, otherPrivate }),
		"another member":     (&Service{}).WithOriginAuth(fakeOriginAuth{}, func() (uuid.UUID, []byte) { return uuid.New(), private }),
	} {
		if b := svc.originAuthBlockers(c, siteID); len(b) != 1 || b[0].Code != "origin_auth_sealed" {
			t.Errorf("%s: blockers = %+v", name, b)
		}
	}
	if b := s.originAuthBlockers(c, uuid.New()); len(b) != 1 || b[0].Code != "origin_auth_sealed" {
		t.Errorf("another site's AAD: blockers = %+v", b)
	}
	if b := (&Service{}).originAuthBlockers(c, siteID); len(b) != 1 || b[0].Code != "unsupported_origin_auth" {
		t.Errorf("no store: blockers = %+v", b)
	}
	invalid := (&Service{}).WithOriginAuth(fakeOriginAuth{invalid: true}, func() (uuid.UUID, []byte) { return leaf, private })
	if b := invalid.originAuthBlockers(c, siteID); len(b) != 1 || b[0].Code != "origin_auth_invalid" {
		t.Errorf("invalid rule: blockers = %+v", b)
	}
}

type fakeOriginAuthDelivery struct {
	status edgepublish.OriginAuthDeliveryStatus
	err    error
	calls  []tenantRef
}

func (f *fakeOriginAuthDelivery) Deliver(_ context.Context, scopeID, ownerID uuid.UUID) (edgepublish.OriginAuthDeliveryStatus, error) {
	f.calls = append(f.calls, tenantRef{scopeID: scopeID, userID: ownerID})
	return f.status, f.err
}

func (f *fakeOriginAuthDelivery) Status(context.Context, uuid.UUID) (edgepublish.OriginAuthDeliveryStatus, error) {
	return f.status, f.err
}

// fix-mktsiteconf6: a commit carrying origin auth starts its delivery to the
// nodes as the tenant owner; what has not reached them yet comes back as an
// advisory origin_auth_delivery with the reason (never the error text), a
// delivered or in-flight one says nothing, a site without origin auth starts
// nothing.
func TestLeafDeliversOriginAuthAfterTheCommit(t *testing.T) {
	_, public := boxPair(t)
	tenant := tenantRef{scopeID: uuid.New(), userID: uuid.New()}
	c := sealedConfig(t, uuid.New(), uuid.New(), public)

	if b := (&Service{}).deliverOriginAuth(t.Context(), tenant, c); b != nil {
		t.Fatalf("not wired: %+v", b)
	}
	for state, want := range map[string]string{
		edgepublish.OriginAuthDeliveryDelivering:   "",
		edgepublish.OriginAuthDeliveryDelivered:    "",
		edgepublish.OriginAuthDeliveryNone:         "",
		edgepublish.OriginAuthDeliveryWaitingNodes: edgepublish.OriginAuthDeliveryWaitingNodes,
	} {
		delivery := &fakeOriginAuthDelivery{status: edgepublish.OriginAuthDeliveryStatus{State: state}}
		s := (&Service{}).WithOriginAuthDelivery(delivery)
		b := s.deliverOriginAuth(t.Context(), tenant, c)
		if len(delivery.calls) != 1 || delivery.calls[0] != tenant {
			t.Fatalf("%s: Deliver calls = %+v", state, delivery.calls)
		}
		if want == "" && b != nil || want != "" && (len(b) != 1 || b[0].Code != "origin_auth_delivery" || b[0].Detail != want) {
			t.Errorf("%s: advisory = %+v", state, b)
		}
	}
	retrying := &fakeOriginAuthDelivery{status: edgepublish.OriginAuthDeliveryStatus{State: edgepublish.OriginAuthDeliveryRetrying,
		Reason: edgepublish.OriginAuthDeliveryCredential}}
	if b := (&Service{}).WithOriginAuthDelivery(retrying).deliverOriginAuth(t.Context(), tenant, c); len(b) != 1 ||
		b[0].Detail != edgepublish.OriginAuthDeliveryCredential {
		t.Errorf("retrying: advisory = %+v", b)
	}
	broken := &fakeOriginAuthDelivery{err: errors.New("pq: connection refused on 10.0.0.1")}
	if b := (&Service{}).WithOriginAuthDelivery(broken).deliverOriginAuth(t.Context(), tenant, c); len(b) != 1 ||
		b[0].Detail != edgepublish.OriginAuthDeliveryUnavailable {
		t.Errorf("delivery error: advisory = %+v", b)
	}
	unused := &fakeOriginAuthDelivery{}
	c.OriginAuth = nil
	if b := (&Service{}).WithOriginAuthDelivery(unused).deliverOriginAuth(t.Context(), tenant, c); b != nil || len(unused.calls) != 0 {
		t.Errorf("no origin auth: advisory %+v, calls %d", b, len(unused.calls))
	}
}
