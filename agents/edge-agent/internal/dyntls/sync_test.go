package dyntls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"golang.org/x/crypto/ocsp"
)

// fakeStore resolves versions to files on disk, as certstore does.
type fakeStore struct {
	files map[string][2]string // version -> chain, key paths
	calls atomic.Int64
}

func (store *fakeStore) ResolveCertificateVersion(_ context.Context, request certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	store.calls.Add(1)
	paths, ok := store.files[request.CertificateVersionID]
	if !ok {
		return certstore.ResolvedCertificateVersion{}, certstore.ErrCertificateUnavailable
	}
	chain, _ := os.ReadFile(paths[0])
	key, _ := os.ReadFile(paths[1])
	return certstore.ResolvedCertificateVersion{SiteID: request.SiteID, CertificateVersionID: request.CertificateVersionID,
		CertificatePath: paths[0], PrivateKeyPath: paths[1], CertificateSHA256: sha256.Sum256(chain), PrivateKeySHA256: sha256.Sum256(key)}, nil
}

func tlsSite(number int, version string, stapling bool) edgesite.Site {
	return edgesite.Site{SiteID: "0d4a0000-0000-4000-8000-00000000000" + string(rune('0'+number)),
		ConfigurationScopeID: "0d4a0000-0000-4000-8000-000000000001",
		Hosts:                edgesite.Hosts{Primary: "s" + string(rune('0'+number)) + ".test", Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: 443, TLS: &edgesite.TLS{CertificateVersionID: version, Protocols: []string{"TLSv1.2", "TLSv1.3"},
			OCSPStapling: stapling}}}}
}

func TestSync(t *testing.T) {
	ca := newCA(t)
	root := t.TempDir()
	store := &fakeStore{files: map[string][2]string{}}
	_, chain, key := ca.issue(t, 40, "s1.test", "s2.test")
	for index, content := range [][]byte{chain, key} {
		path := filepath.Join(root, []string{"a.crt", "a.key"}[index])
		if err := os.WriteFile(path, content, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	store.files[versionA] = [2]string{filepath.Join(root, "a.crt"), filepath.Join(root, "a.key")}
	pool := Pool{Root: filepath.Join(root, "pool"), GID: -1}
	sites := []edgesite.Site{tlsSite(1, versionA, false), tlsSite(2, versionA, true), tlsSite(3, versionB, false)}
	result, err := pool.Sync(context.Background(), store, sites)
	if err != nil {
		t.Fatal(err)
	}
	if result.Copied != 1 || len(result.Versions) != 2 || !result.Versions[0].OCSP || len(result.Versions[0].Sites) != 2 {
		t.Fatalf("sync %+v", result)
	}
	if len(result.Unavailable) != 1 || result.Unavailable[0].VersionID != versionB || !errors.Is(result.Unavailable[0].Err, certstore.ErrCertificateUnavailable) {
		t.Fatalf("unavailable %+v", result.Unavailable)
	}
	copied, _ := os.ReadFile(pool.path(versionA, ".crt"))
	if string(copied) != string(chain) {
		t.Fatal("chain not copied")
	}
	calls := store.calls.Load()
	if again, err := pool.Sync(context.Background(), store, sites[:2]); err != nil || again.Copied != 0 || store.calls.Load() != calls {
		t.Fatalf("second sync copied %d (calls %d -> %d) %v", again.Copied, calls, store.calls.Load(), err)
	}
	// A store file that no longer matches its record is refused.
	_ = os.Chmod(filepath.Join(root, "a.crt"), 0o600)
	store.files[versionB] = [2]string{filepath.Join(root, "a.crt"), filepath.Join(root, "a.key")}
	tampered := &tamperStore{fakeStore: store}
	if result, _ := pool.Sync(context.Background(), tampered, []edgesite.Site{tlsSite(3, versionB, false)}); len(result.Unavailable) != 1 {
		t.Fatalf("tampered file accepted: %+v", result)
	}
	references := Keep(result.Versions, []Version{{ID: versionB}, {ID: versionA}})
	if !slices.Equal(references.Current, []string{versionA, versionB}) || len(references.Previous) != 0 {
		t.Fatalf("keep %+v", references)
	}
}

type tamperStore struct{ *fakeStore }

func (store *tamperStore) ResolveCertificateVersion(ctx context.Context, request certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	value, err := store.fakeStore.ResolveCertificateVersion(ctx, request)
	value.CertificateSHA256[0] ^= 1
	return value, err
}

// responder answers OCSP requests for ca with status, valid for validity.
func responder(t *testing.T, ca testCA, status *atomic.Int64, validity time.Duration, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		raw, _ := io.ReadAll(request.Body)
		parsed, err := ocsp.ParseRequest(raw)
		if err != nil || status.Load() < 0 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		response, err := ocsp.CreateResponse(ca.certificate, ca.certificate, ocsp.Response{Status: int(status.Load()),
			SerialNumber: parsed.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(validity)}, crypto.Signer(ca.key))
		if err != nil {
			t.Error(err)
		}
		_, _ = writer.Write(response)
	}))
}

// issueWithResponder: a leaf that names url as its OCSP responder.
func issueWithResponder(t *testing.T, ca testCA, url string) ([]byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "ocsp.test"}, DNSNames: []string{"ocsp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), OCSPServer: []string{url},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestRefreshOCSP(t *testing.T) {
	ca := newCA(t)
	var status, hits atomic.Int64
	status.Store(int64(ocsp.Good))
	server := responder(t, ca, &status, 4*time.Hour, &hits)
	defer server.Close()
	pool := Pool{Root: filepath.Join(t.TempDir(), "pool"), GID: -1}
	chain, key := issueWithResponder(t, ca, server.URL)
	if err := pool.PutCertificate(versionA, chain, key); err != nil {
		t.Fatal(err)
	}
	_, plainChain, plainKey := ca.issue(t, 78, "plain.test") // no responder
	if err := pool.PutCertificate(versionB, plainChain, plainKey); err != nil {
		t.Fatal(err)
	}
	fetcher := HTTPFetcher{}
	versions := []Version{{ID: versionA, OCSP: true}, {ID: versionB, OCSP: true}}
	now := time.Now()
	statuses := pool.RefreshOCSP(context.Background(), fetcher, versions, now)
	if len(statuses) != 2 || !statuses[0].Stapled || statuses[0].Err != nil || statuses[1].Stapled || !errors.Is(statuses[1].Err, ErrNoResponder) {
		t.Fatalf("first refresh %+v", statuses)
	}
	if _, err := os.Stat(pool.path(versionA, ".ocsp")); err != nil {
		t.Fatal("response not stored")
	}
	// Fresh: no new fetch.
	before := hits.Load()
	pool.RefreshOCSP(context.Background(), fetcher, versions[:1], now.Add(time.Hour))
	if hits.Load() != before {
		t.Fatal("refetched a fresh response")
	}
	// Past half of its validity, responder down: the stored one stays.
	status.Store(-1)
	statuses = pool.RefreshOCSP(context.Background(), fetcher, versions[:1], now.Add(3*time.Hour))
	if hits.Load() == before || !statuses[0].Stapled || statuses[0].Err == nil {
		t.Fatalf("due refresh with responder down: %+v", statuses)
	}
	// Expired and nothing new: removed, no stapling.
	statuses = pool.RefreshOCSP(context.Background(), fetcher, versions[:1], now.Add(5*time.Hour))
	if statuses[0].Stapled {
		t.Fatalf("expired response still stapled: %+v", statuses)
	}
	if _, err := os.Stat(pool.path(versionA, ".ocsp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired response not removed")
	}
	// Revoked: a stored good response stops being stapled at once.
	status.Store(int64(ocsp.Good))
	if statuses = pool.RefreshOCSP(context.Background(), fetcher, versions[:1], time.Now()); !statuses[0].Stapled {
		t.Fatalf("refetch %+v", statuses)
	}
	status.Store(int64(ocsp.Revoked))
	statuses = pool.RefreshOCSP(context.Background(), fetcher, versions[:1], time.Now().Add(3*time.Hour))
	if statuses[0].Stapled || !errors.Is(statuses[0].Err, ErrRevoked) {
		t.Fatalf("revoked answer: %+v", statuses)
	}
	if _, err := os.Stat(pool.path(versionA, ".ocsp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("good response kept after a revoked answer")
	}
	// Stapling turned off: the response goes.
	status.Store(int64(ocsp.Good))
	pool.RefreshOCSP(context.Background(), fetcher, versions[:1], time.Now())
	pool.RefreshOCSP(context.Background(), fetcher, []Version{{ID: versionA}}, time.Now())
	if _, err := os.Stat(pool.path(versionA, ".ocsp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("response kept after stapling was turned off")
	}
}
