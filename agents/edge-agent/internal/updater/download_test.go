package updater

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPSDownloaderUsesPinnedAddressWithoutProxy(t *testing.T) {
	content := []byte("signed artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("token") != "sensitive" {
			t.Error("query token was not delivered")
		}
		_, _ = writer.Write(content)
	}))
	defer server.Close()
	downloader, artifactURL := testHTTPSDownloader(t, server, true)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	var destination bytes.Buffer
	if err := downloader.Download(context.Background(), DownloadRequest{URL: artifactURL + "/agent?token=sensitive", MaxBytes: int64(len(content))}, &destination); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), content) {
		t.Fatalf("content = %q", destination.Bytes())
	}
}

func TestHTTPSDownloaderRejectsRedirectsOversizeAndRedactsQuery(t *testing.T) {
	secret := "do-not-log-this"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			http.Redirect(writer, request, "/ok", http.StatusFound)
		case "/large":
			_, _ = writer.Write([]byte("too large"))
		default:
			http.Error(writer, "failure", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	downloader, artifactURL := testHTTPSDownloader(t, server, false)

	for _, test := range []struct {
		path string
		max  int64
		want error
	}{
		{path: "/redirect?token=" + secret, max: 64, want: ErrDownloadPolicy},
		{path: "/large?token=" + secret, max: 3, want: ErrArtifactTooLarge},
		{path: "/error?token=" + secret, max: 64, want: ErrDownload},
	} {
		var destination bytes.Buffer
		err := downloader.Download(context.Background(), DownloadRequest{URL: artifactURL + test.path, MaxBytes: test.max}, &destination)
		if !errors.Is(err, test.want) {
			t.Fatalf("%s error = %v, want %v", test.path, err, test.want)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "token=") {
			t.Fatalf("error leaked URL query: %v", err)
		}
	}

	var destination bytes.Buffer
	if err := downloader.Download(context.Background(), DownloadRequest{URL: "http://example.test/agent", MaxBytes: 64}, &destination); !errors.Is(err, ErrDownloadPolicy) {
		t.Fatalf("plain HTTP error = %v", err)
	}
}

func testHTTPSDownloader(t *testing.T, server *httptest.Server, redirects bool) (*HTTPSDownloader, string) {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	downloader, err := NewHTTPSDownloader(HTTPSPolicy{
		Hosts:          map[string]HostPolicy{host: {Addresses: []netip.Addr{address}, Ports: []uint16{uint16(port)}}},
		AllowRedirects: redirects, MaxRedirects: 2, Timeout: 3 * time.Second, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	return downloader, server.URL
}
