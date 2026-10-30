package nodeisolationhttp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

func TestNodeCertificateIdentityRequiresExactVerifiedNodeLeaf(t *testing.T) {
	nodeID := uuid.New()
	uri, err := url.Parse(nodeidentity.NodeSPIFFEPrefix + nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		Raw: []byte("verified-node-leaf"), Subject: pkix.Name{CommonName: "ignored"},
		URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	valid := httptest.NewRequest("POST", "https://control.local/", nil)
	valid.TLS.PeerCertificates = []*x509.Certificate{leaf}
	valid.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
	gotNodeID, gotURI, digest, ok := nodeCertificateIdentity(valid)
	if !ok || gotNodeID != nodeID || gotURI != uri.String() || digest == ([32]byte{}) {
		t.Fatalf("identity=(%s,%q,%x,%t)", gotNodeID, gotURI, digest, ok)
	}

	for name, mutate := range map[string]func(*http.Request, *x509.Certificate, *x509.Certificate){
		"unverified": func(request *http.Request, _ *x509.Certificate, _ *x509.Certificate) {
			request.TLS.VerifiedChains = nil
		},
		"wrong URI": func(_ *http.Request, candidate *x509.Certificate, _ *x509.Certificate) {
			candidate.URIs = []*url.URL{{Scheme: "spiffe", Host: "cdn-platform", Path: "/gateway/control"}}
		},
		"multiple URI": func(_ *http.Request, candidate *x509.Certificate, _ *x509.Certificate) {
			candidate.URIs = append(candidate.URIs, uri)
		},
		"peer mismatch": func(_ *http.Request, _ *x509.Certificate, peer *x509.Certificate) {
			peer.Raw = []byte("other-leaf")
		},
		"missing client auth": func(_ *http.Request, candidate *x509.Certificate, _ *x509.Certificate) {
			candidate.ExtKeyUsage = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *leaf
			candidate.URIs = append([]*url.URL(nil), leaf.URIs...)
			peer := candidate
			request := httptest.NewRequest("POST", "https://control.local/", nil)
			request.TLS.PeerCertificates = []*x509.Certificate{&peer}
			request.TLS.VerifiedChains = [][]*x509.Certificate{{&candidate}}
			mutate(request, &candidate, &peer)
			if _, _, _, accepted := nodeCertificateIdentity(request); accepted {
				t.Fatal("invalid certificate identity accepted")
			}
		})
	}
}
