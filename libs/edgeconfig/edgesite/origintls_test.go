package edgesite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertificatePEM(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: isCA}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTrustAnchors(t *testing.T) {
	for anchor, valid := range map[string]bool{
		"sha256:" + digestA: true, TrustSystem: true, TrustNone: true, "": false, "NONE": false, "insecure": false,
		"sha256:" + strings.ToUpper(digestA): false, "SYSTEM": false,
	} {
		if ValidTrustAnchor(anchor) != valid {
			t.Errorf("ValidTrustAnchor(%q) = %v", anchor, !valid)
		}
	}
	if TrustAnchorDigest("sha256:"+digestA) != digestA || TrustAnchorDigest(TrustSystem) != "" || TrustAnchorDigest(TrustNone) != "" {
		t.Fatal("TrustAnchorDigest")
	}
	site := fullSite(t)
	site.Origin.Pools[1].Endpoints = append(site.Origin.Pools[1].Endpoints,
		Endpoint{ID: "origin-2", Scheme: "https", Host: "192.0.2.11", Port: 443, Weight: 1, SNI: "o.example.test", TrustAnchor: TrustSystem},
		Endpoint{ID: "origin-3", Scheme: "https", Host: "192.0.2.12", Port: 443, Weight: 1, SNI: "o.example.test", TrustAnchor: "sha256:" + digestA},
		Endpoint{ID: "origin-4", Scheme: "https", Host: "192.0.2.13", Port: 443, Weight: 1, SNI: "o.example.test", TrustAnchor: "sha256:" + digestB},
		// fix-originnoverify: "none" (不校验源站证书) names no CA set object
		Endpoint{ID: "origin-5", Scheme: "https", Host: "192.0.2.14", Port: 443, Weight: 1, SNI: "o.example.test", TrustAnchor: TrustNone})
	if _, err := Encode(site); err != nil {
		t.Fatalf("system anchor refused: %v", err)
	}
	if got := strings.Join(site.TrustAnchors(), ","); got != digestA+","+digestB {
		t.Fatalf("TrustAnchors = %s", got)
	}
}

func TestValidateCASet(t *testing.T) {
	ca, leaf := testCertificatePEM(t, true), testCertificatePEM(t, false)
	if err := ValidateCASet(ca); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCASet(append(append([]byte{}, ca...), testCertificatePEM(t, true)...)); err != nil {
		t.Fatal(err)
	}
	// A pinned (self-signed leaf) certificate is a trust anchor too (v7).
	if err := ValidateCASet(leaf); err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	for name, raw := range map[string][]byte{
		"empty": nil, "blank": []byte("\n"), "garbage block": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), "key": append(append([]byte{}, ca...), key...),
		"trailing text": append(append([]byte{}, ca...), "junk"...),
		"too large":     []byte(strings.Repeat("a", MaxCASetBytes+1)),
	} {
		if ValidateCASet(raw) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The reuse key separates every connection-level property: SNI, trust
// anchor (ADR 0009 PoC section 3), scheme and origin auth identity; it never
// holds NUL (ngx_strncasecmp stops at NUL) or a second "|" inside a field.
func TestKeepaliveKey(t *testing.T) {
	a := Endpoint{Scheme: "https", SNI: "origin.example.test", TrustAnchor: "sha256:" + digestA}
	b := a
	b.TrustAnchor = "sha256:" + digestB
	other := a
	other.SNI = "other.example.test"
	system := a
	system.TrustAnchor = TrustSystem
	plain := Endpoint{Scheme: "http"}
	auth := &OriginAuth{PoolID: "p", Secret: Ref{Kind: RefOriginAuthSecret, ID: testUUID, Revision: 2}}
	auth3 := &OriginAuth{PoolID: "p", Secret: Ref{Kind: RefOriginAuthSecret, ID: testUUID, Revision: 3}}
	keys := map[string]string{
		"a": KeepaliveKey(a, nil), "b": KeepaliveKey(b, nil), "other": KeepaliveKey(other, nil),
		"system": KeepaliveKey(system, nil), "plain": KeepaliveKey(plain, nil),
		"a auth": KeepaliveKey(a, auth), "a auth3": KeepaliveKey(a, auth3), "plain auth": KeepaliveKey(plain, auth),
	}
	seen := map[string]string{}
	for name, key := range keys {
		if previous, ok := seen[key]; ok {
			t.Errorf("%s and %s share key %q", name, previous, key)
		}
		seen[key] = name
		if strings.ContainsRune(key, 0) || strings.Count(key, "|") != 3 {
			t.Errorf("%s key %q", name, key)
		}
	}
	if keys["a"] != "https|origin.example.test|sha256:"+digestA+"|-" ||
		keys["a auth"] != "https|origin.example.test|sha256:"+digestA+"|"+testUUID+"@2" || keys["plain"] != "http||-|-" {
		t.Fatalf("keys %v", keys)
	}
	if KeepaliveKey(a, nil) != KeepaliveKey(a, nil) {
		t.Fatal("not deterministic")
	}
	site := fullSite(t)
	if site.Origin.AuthForPool("primary") == nil || site.Origin.AuthForPool("l2-topology") != nil {
		t.Fatal("AuthForPool")
	}
}

// TLSName follows sni_mode (ge-origin v7 semantics expanded by the control
// plane); without one it is v7 poolTLSName.
func TestTLSName(t *testing.T) {
	endpoint := Endpoint{Scheme: "https", Host: "192.0.2.10", Port: 8443, SNI: "fixed.example.test"}
	pool := Pool{}
	custom := &RequestHost{Mode: RequestHostCustom, Value: "custom.example.test:8443"}
	cases := []struct {
		name, mode, sni string
		host            *RequestHost
		want            string
	}{
		{"custom", SNICustom, "fixed.example.test", nil, "fixed.example.test"},
		{"origin host", SNIOriginHost, "", custom, "192.0.2.10"},
		{"visitor host", SNIVisitorHost, "", custom, "visitor.example.test"},
		{"legacy sni", "", "fixed.example.test", nil, "fixed.example.test"},
		{"legacy visitor", "", "", nil, "visitor.example.test"},
		{"legacy custom host", "", "", custom, "custom.example.test"},
		{"legacy custom v6", "", "", &RequestHost{Mode: RequestHostCustom, Value: "[2001:db8::1]:8443"}, "2001:db8::1"},
		{"legacy origin host", "", "", &RequestHost{Mode: RequestHostOrigin}, "192.0.2.10"},
	}
	for _, c := range cases {
		value, current := endpoint, pool
		value.SNIMode, value.SNI, current.RequestHost = c.mode, c.sni, c.host
		if got := current.TLSName(value, "visitor.example.test"); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// ExpandSNIModes keeps every name TLSName gives and leaves nothing implicit.
func TestExpandSNIModes(t *testing.T) {
	hosts := []*RequestHost{nil, {Mode: RequestHostOrigin}, {Mode: RequestHostCustom, Value: "c.example.test:8080"},
		{Mode: RequestHostCustom, Value: "[2001:db8::2]"}}
	want := map[string]string{"": SNIVisitorHost, RequestHostOrigin: SNIOriginHost, RequestHostCustom: SNICustom}
	for _, host := range hosts {
		for _, sni := range []string{"", "fixed.example.test"} {
			pool := Pool{RequestHost: host, Endpoints: []Endpoint{
				{Scheme: "https", Host: "192.0.2.10", SNI: sni}, {Scheme: "http", Host: "192.0.2.11"}}}
			before := pool.TLSName(pool.Endpoints[0], "v.example.test")
			pool.ExpandSNIModes()
			mode := ""
			if host != nil {
				mode = host.Mode
			}
			if sni != "" {
				mode = RequestHostCustom
			}
			if pool.Endpoints[0].SNIMode != want[mode] || pool.Endpoints[1].SNIMode != "" ||
				pool.TLSName(pool.Endpoints[0], "v.example.test") != before {
				t.Errorf("host %+v sni %q: %+v (name %q)", host, sni, pool.Endpoints, before)
			}
		}
	}
}
