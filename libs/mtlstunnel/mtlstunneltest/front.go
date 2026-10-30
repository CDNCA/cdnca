// Package mtlstunneltest starts an in-process T1 tunnel server for tests: an
// httptest TLS server (the CDN/front stand-in) running mtlstunnel.Server.
package mtlstunneltest

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
)

type Front struct {
	// URL is the https entrance for <组件>_MTLS_TUNNEL_URL / NewClient.
	URL string
	// Roots trusts the front's certificate (the outer TLS).
	Roots *x509.CertPool
	// Upgrades counts tunnel requests that reached the server.
	Upgrades *atomic.Int64
}

// Start bridges target name → backend host:port until the test ends.
func Start(t testing.TB, targets map[string]string) Front {
	t.Helper()
	server := &mtlstunnel.Server{Targets: targets}
	upgrades := &atomic.Int64{}
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrades.Add(1)
		server.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	roots := x509.NewCertPool()
	roots.AddCert(front.Certificate())
	return Front{URL: front.URL, Roots: roots, Upgrades: upgrades}
}

// Dialer is the tunnel DialContext for originURL through front.
func (f Front) Dialer(t testing.TB, originURL, target string) mtlstunnel.DialFunc {
	t.Helper()
	client, err := mtlstunnel.NewClient(originURL, f.URL, target)
	if err != nil {
		t.Fatal(err)
	}
	client.Roots = f.Roots
	return client.DialContext
}
