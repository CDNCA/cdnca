//go:build integration

package edgepublish

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A site's stored TLS profile reaches the node. A legacy
// TLSv1..TLSv1.3 site with OCSP stapling and required client verification
// publishes the profile on its HTTPS listener, the client CA bundle as the
// release file the reference names, and keeps http3 (TLSv1.3 is in the
// range).
func TestSiteTLSProfileReachesTheNodeRelease(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	site := fixture.createSiteWithPortSets(t, "tls-profile.example.test", []string{"80"}, []string{"443"}, true)
	seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
	ca := tlsProfileClientCA(t)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET tls_protocols=ARRAY['TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'],
		tls_cipher_preset='legacy',tls_ocsp_stapling=true,tls_client_auth='required',tls_client_ca_pem=$2 WHERE id=$1`,
		site.Site.ID, ca); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "tls-profile", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	release := receivedV2Release(t, fixture, result, fixture.nodeID, key)
	document := decodeReceivedV2Document(t, release.Bundle)
	if len(document.Sites) != 1 {
		t.Fatalf("sites = %d", len(document.Sites))
	}
	var tls *siteRuntimeV2ListenerTLS
	var protocols []string
	for _, listener := range document.Sites[0].Listeners {
		if listener.TLS != nil {
			tls, protocols = listener.TLS, listener.Protocols
		}
	}
	ref := edgeconfig.ClientCARefFor([]byte(ca))
	if tls == nil || !slices.Equal(tls.Protocols, []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}) ||
		tls.CipherPreset != "legacy" || !tls.OCSPStapling || tls.ClientAuth != "required" || tls.ClientCARef != ref ||
		!slices.Contains(protocols, "http3") {
		t.Fatalf("published TLS = %+v protocols %v", tls, protocols)
	}
	// The client CA reaches the node as the publication object the ref names.
	if got := string(release.Objects[strings.TrimPrefix(ref, "sha256:")]); got != ca {
		t.Fatalf("client CA file = %q", got)
	}
	// A profile lazy certificates cannot serve keeps the site's own server.
	if document.LazyCertificates == nil {
		t.Fatal("lazy certificates off")
	}

}

// A TLSv1.2-only site drops http3 (QUIC is TLS 1.3 only) and carries no
// profile field or client CA beyond its protocols.
func TestSiteTLSProfileTLS12OnlyDropsHTTP3(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	site := fixture.createSiteWithPortSets(t, "tls12-only.example.test", []string{"80"}, []string{"443"}, true)
	seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET tls_protocols=ARRAY['TLSv1.2'] WHERE id=$1`, site.Site.ID); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "tls-profile-12", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("Publish TLSv1.2: %v", err)
	}
	bundle := receivedV2Bundle(t, fixture, result, fixture.nodeID, key)
	document := decodeReceivedV2Document(t, bundle)
	for _, listener := range document.Sites[0].Listeners {
		if listener.TLS == nil {
			continue
		}
		if slices.Contains(listener.Protocols, "http3") || listener.TLS.CipherPreset != "" || listener.TLS.ClientCARef != "" ||
			!slices.Equal(listener.TLS.Protocols, []string{"TLSv1.2"}) {
			t.Fatalf("TLSv1.2 listener = %+v %v", listener.TLS, listener.Protocols)
		}
	}
	for path := range bundle.Files {
		if len(path) > len(edgeconfig.ClientCAPrefix) && path[:len(edgeconfig.ClientCAPrefix)] == edgeconfig.ClientCAPrefix {
			t.Fatalf("client CA %s still published", path)
		}
	}
}

func tlsProfileClientCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "publish client ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
