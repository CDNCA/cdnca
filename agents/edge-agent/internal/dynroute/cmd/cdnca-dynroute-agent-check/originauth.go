package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Origin auth on the agent runtime (D13-b2 交接 3): a site object binds its
// HTTPS pool to a secret object the installer writes (SecretObjectDir of the
// runtime, worker readable); the bucket receives the request with the Go
// signer's Authorization, Host = the bucket's name, verified TLS to it.
const (
	bucketPort = 19814
	bucketHost = "examplebucket.s3.us-east-1.amazonaws.com"
	authRuleID = "0d130000-0000-4000-8000-0000000000e1"
)

type bucketRequest struct {
	host, sni, auth, method, uri string
	header                       http.Header
}

func checkOriginAuth(h *harness, ca *authority, others ...edgesite.Site) {
	var mu sync.Mutex
	var received []bucketRequest
	chain, keyPEM, _ := ca.issue(bucketHost)
	certificate, err := tls.X509KeyPair(chain, keyPEM)
	var listener net.Listener
	if err == nil {
		listener, err = tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bucketPort), &tls.Config{Certificates: []tls.Certificate{certificate}})
	}
	check("origin-auth-bucket", err == nil, "%v", err)
	if err != nil {
		return
	}
	defer listener.Close()
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			mu.Lock()
			received = append(received, bucketRequest{host: request.Host, sni: request.TLS.ServerName, auth: request.Header.Get("Authorization"),
				method: request.Method, uri: request.RequestURI, header: request.Header.Clone()})
			mu.Unlock()
			fmt.Fprintf(writer, "bucket %s\n", request.RequestURI)
		}))
	}()
	last := func() (bucketRequest, int) {
		mu.Lock()
		defer mu.Unlock()
		if len(received) == 0 {
			return bucketRequest{}, 0
		}
		return received[len(received)-1], len(received)
	}

	// the CA set object the endpoint's trust anchor names
	anchor := edgesite.Digest(ca.pem)
	if err := siteObjects.Put(anchor, ca.pem); err != nil {
		check("origin-auth-ca-object", false, "%v", err)
		return
	}
	now := time.Now()
	object := originauth.SecretObject{Schema: originauth.SecretObjectSchema, RuleID: authRuleID, Revision: 1, Rule: originauth.SecretRule{
		RuleID: authRuleID, Provider: originauth.ProviderS3, Algorithm: originauth.AlgorithmS3,
		Endpoint: originauth.Endpoint{Scheme: "https", Host: bucketHost, Port: 443}, PathPrefix: "/", Region: "us-east-1", Service: "s3",
		SignatureTTLSeconds: 600, CurrentKey: originauth.SecretKey{KeyID: "key-1", Credential: originauth.Credential{
			SchemaVersion: originauth.CredentialVersion, Provider: originauth.ProviderS3, AccessKeyID: "AKIA-D13-1",
			SecretAccessKey: "d13-test-secret", NotBeforeUnix: now.Add(-time.Hour).Unix(), ExpiresAtUnix: now.Add(24 * time.Hour).Unix()}}}}
	err = h.runtime.OriginAuthSecrets().Write([]originauth.SecretObject{object})
	check("origin-auth-secret-written", err == nil, "%v", err)

	site := makeSite(9, "private.d13.test", 1, portPlain)
	retry := site.Origin.Pools[0].Retry
	site.Origin.Pools = []edgesite.Pool{{ID: "bucket", Kind: edgesite.PoolOrigin, Algorithm: "round_robin", Retry: retry,
		Endpoints: []edgesite.Endpoint{{ID: "b", Scheme: "https", Host: "127.0.0.1", Port: bucketPort, Weight: 1, SNI: bucketHost,
			TrustAnchor: "sha256:" + anchor}}}}
	site.Origin.DefaultPoolID = "bucket"
	site.Origin.Auth = []edgesite.OriginAuth{{PoolID: "bucket", Endpoint: "https://" + bucketHost,
		Secret: edgesite.Ref{Kind: edgesite.RefOriginAuthSecret, ID: authRuleID, Revision: 1}}}
	h.apply("origin-auth-apply", append(append([]edgesite.Site{}, others...), site)...)

	r := fetch(portPlain, "private.d13.test", "/dir/object.txt?versionId=3", nil, nil)
	got, count := last()
	want, err := expectedAuthorization(object, got)
	check("origin-auth-signed", r.status == 200 && count == 1 && err == nil && got.auth != "" && got.auth == want,
		"%d count %d\n  got:  %s\n  want: %s %v", r.status, count, got.auth, want, err)
	check("origin-auth-bucket-host", got.host == bucketHost && got.sni == bucketHost, "host %q sni %q", got.host, got.sni)
	r = fetch(portPlain, "private.d13.test", "/dir/object.txt", map[string]string{"Authorization": "Bearer client"}, nil)
	_, after := last()
	check("origin-auth-client-auth-refused", r.status == 403 && after == count, "%d bucket requests %d -> %d", r.status, count, after)

	// a revision without its secret object: refused, not sent unsigned
	site.Revision = 2
	site.Origin.Auth[0].Secret.Revision = 2
	h.apply("origin-auth-missing-secret-apply", append(append([]edgesite.Site{}, others...), site)...)
	r = fetch(portPlain, "private.d13.test", "/dir/object.txt", nil, nil)
	_, after = last()
	check("origin-auth-missing-secret-refused", r.status >= 500 && after == count, "%d bucket requests %d -> %d", r.status, count, after)
	h.apply("origin-auth-remove", others...)
}

// expectedAuthorization is the Go signer's Authorization for the request
// the bucket received, at the time the edge signed it (X-Amz-Date).
func expectedAuthorization(object originauth.SecretObject, got bucketRequest) (string, error) {
	directory, err := os.MkdirTemp("", "d13-signer-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	raw, _ := json.Marshal(object.Rule.CurrentKey.Credential)
	file := filepath.Join(directory, "credential.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		return "", err
	}
	rule := object.Rule
	policy, _ := json.Marshal(originauth.Policy{SchemaVersion: originauth.SchemaVersion, PolicyVersion: 1, Rules: []originauth.Rule{{
		RuleID: rule.RuleID, Provider: rule.Provider, Algorithm: rule.Algorithm, Endpoint: "https://" + rule.Endpoint.Host,
		PathPrefix: rule.PathPrefix, Region: rule.Region, Service: rule.Service, SignatureTTLSeconds: rule.SignatureTTLSeconds,
		CurrentKey: originauth.KeyRef{KeyID: "k", SecretFile: file}}}})
	_, compiled, err := originauth.CompileJSON(policy)
	if err != nil {
		return "", err
	}
	at, err := time.Parse("20060102T150405Z", got.header.Get("X-Amz-Date"))
	if err != nil {
		return "", err
	}
	signer, err := originauth.NewSigner(compiled, func() time.Time { return at })
	if err != nil {
		return "", err
	}
	request, _ := http.NewRequest(got.method, "https://"+rule.Endpoint.Host+got.uri, nil)
	if err := signer.Sign(rule.RuleID, request); err != nil {
		return "", err
	}
	return request.Header.Get("Authorization"), nil
}
