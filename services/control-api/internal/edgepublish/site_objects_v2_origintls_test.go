package edgepublish

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func originTrustTestPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// D5b: the CA set an HTTPS endpoint's trust anchor names travels as a
// referenced object (its digest is the anchor), so the node can verify the
// origin against exactly that set.
func TestSiteObjectsV2ReferencesOriginTrustCASet(t *testing.T) {
	caPEM := originTrustTestPEM(t)
	sum := sha256.Sum256(caPEM)
	digest := hex.EncodeToString(sum[:])
	document := func(anchor string) []byte {
		t.Helper()
		var value siteRuntimeV2Document
		if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &value); err != nil {
			t.Fatal(err)
		}
		site := &value.Sites[0]
		disabled := false
		site.L2.Enabled, site.L2.DirectFallbackPoolID = &disabled, nil
		site.OriginPools = site.OriginPools[:1]
		site.DefaultPoolID = site.OriginPools[0].ID
		site.OriginPools[0].Origins[0].TrustRef = &anchor
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	canonical := document("sha256:" + digest)
	build := func(trust []byte) (siteObjectsV2, error) {
		bundle, err := buildSiteRuntimeV2Bundle(canonical, map[string][]byte{"origin-trust/" + digest + ".pem": trust}, nil, nil, nil, nil)
		if err != nil {
			return siteObjectsV2{}, err
		}
		publication, err := siteObjectsV2SourceFromBundle(bundle)
		if err != nil {
			return siteObjectsV2{}, err
		}
		return buildSiteObjectsV2(publication, goldenTenant, nil)
	}
	objects, err := build(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	site := objects.Sites[0].Site
	if anchors := site.TrustAnchors(); len(anchors) != 1 || anchors[0] != digest {
		t.Fatalf("anchors %v", anchors)
	}
	if !bytes.Equal(objects.Referenced[digest], caPEM) {
		t.Fatal("CA set not referenced")
	}
	// A CA set that is not certificates only is refused (the node would too).
	bad := append(bytes.Clone(caPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})...)
	badSum := sha256.Sum256(bad)
	canonical = document("sha256:" + hex.EncodeToString(badSum[:]))
	digest = hex.EncodeToString(badSum[:])
	if _, err := build(bad); err == nil {
		t.Fatal("invalid CA set accepted")
	}
	if !edgesite.ValidTrustAnchor("sha256:" + digest) {
		t.Fatal("anchor format")
	}
}

// f16: every HTTPS endpoint carries the v7 SNI semantics as an explicit
// sni_mode: a configured SNI is custom; without one the SNI follows the
// request Host (visitor / origin endpoint host / custom value without port).
func TestSiteObjectsV2SNIMode(t *testing.T) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	trust := edgesite.TrustSystem
	sni := "fixed.example.test"
	custom := "custom.example.test:8443"
	cases := []struct {
		name        string
		sni         *string
		requestHost *siteRuntimeV2RequestHost
		mode, value string
	}{
		{"configured", &sni, nil, edgesite.SNICustom, sni},
		{"visitor", nil, nil, edgesite.SNIVisitorHost, ""},
		{"origin", nil, &siteRuntimeV2RequestHost{Mode: edgesite.RequestHostOrigin}, edgesite.SNIOriginHost, ""},
		{"custom host", nil, &siteRuntimeV2RequestHost{Mode: edgesite.RequestHostCustom, Value: &custom}, edgesite.SNICustom, "custom.example.test"},
	}
	for _, c := range cases {
		runtime := document.Sites[0]
		runtime.OriginPools = slices.Clone(runtime.OriginPools)
		var index int
		for index = range runtime.OriginPools {
			if runtime.OriginPools[index].Kind == edgesite.PoolOrigin {
				break
			}
		}
		pool := runtime.OriginPools[index]
		pool.RequestHost, pool.FollowPort = c.requestHost, nil
		pool.Origins = []siteRuntimeV2Origin{{ID: "tls", Tier: "origin", Scheme: "https", Host: "192.0.2.10", Port: 443,
			Weight: 1, SNI: c.sni, TrustRef: &trust}, {ID: "plain", Position: 1, Tier: "origin", Scheme: "http",
			Host: "192.0.2.11", Port: 80, Weight: 1}}
		runtime.OriginPools[index] = pool
		origin, err := convertSiteOriginV2(runtime, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, converted := range origin.Pools {
			if converted.ID != pool.ID {
				continue
			}
			tls, plain := converted.Endpoints[0], converted.Endpoints[1]
			if tls.SNIMode != c.mode || tls.SNI != c.value || plain.SNIMode != "" || plain.SNI != "" {
				t.Errorf("%s: endpoints %+v", c.name, converted.Endpoints)
			}
		}
	}
}
