// Command cdnca-originauth-dynroute-check is the dynamic routing D5b origin
// auth acceptance against a real OpenResty (tests/dynroute-originauth/run.sh
// runs it in the node runtime image, one --rm --network none container):
// a site object binds a pool to an origin auth secret object; the worker
// signs each request (dynroute/cdnca_originauth.lua, the v7 engine's
// signer) and the mock HTTPS bucket receives exactly what the Go signer
// (tested against each provider's SDK vectors) produces for the same
// request and time. Also: the request goes over verified TLS to the bucket
// name, client auth headers and bodies are refused, a missing secret or a
// plain endpoint in a signed pool never sends an unsigned request, a new
// secret revision is used without a reload.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

var (
	luaRoot = flag.String("lua", "/t/lua", "node Lua tree (dynroute/, originauth/)")
	state   = flag.String("state", "/tmp/d5b-auth", "state directory")
)

var failures int

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, name, fmt.Sprintf(format, args...))
}

type provider struct {
	name, algorithm, endpoint, bucket, region, service, pool string
	port                                                     int
	ruleID                                                   string
}

var providers = []provider{
	{originauth.ProviderS3, originauth.AlgorithmS3, "examplebucket.s3.us-east-1.amazonaws.com", "", "us-east-1", "s3", "s3", 19501,
		"0d5b0000-0000-4000-8000-0000000000a1"},
	{originauth.ProviderOSS, originauth.AlgorithmOSS, "bucket.oss-cn-hangzhou.aliyuncs.com", "bucket", "cn-hangzhou", "oss", "oss", 19502,
		"0d5b0000-0000-4000-8000-0000000000a2"},
	{originauth.ProviderCOS, originauth.AlgorithmCOS, "testbucket-125000000.cos.ap-guangzhou.myqcloud.com", "", "ap-guangzhou", "cos", "cos", 19503,
		"0d5b0000-0000-4000-8000-0000000000a3"},
}

type received struct {
	host, sni, auth, method, uri string
	header                       http.Header
}

type bucket struct {
	mu       sync.Mutex
	requests []received
}

func (b *bucket) last() (received, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.requests) == 0 {
		return received{}, 0
	}
	return b.requests[len(b.requests)-1], len(b.requests)
}

func (b *bucket) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.requests)
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA() ca {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "d5b bucket CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return ca{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c ca) leaf(name string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serve(c ca, p provider) *bucket {
	b := &bucket{}
	listener, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.port), &tls.Config{Certificates: []tls.Certificate{c.leaf(p.endpoint)}})
	if err != nil {
		panic(err)
	}
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.requests = append(b.requests, received{host: r.Host, sni: r.TLS.ServerName, auth: r.Header.Get("Authorization"),
			method: r.Method, uri: r.RequestURI, header: r.Header.Clone()})
		b.mu.Unlock()
		fmt.Fprintf(w, "bucket %s %s\n", p.name, r.RequestURI)
	}))
	return b
}

func credential(p provider, access string, now time.Time) originauth.Credential {
	return originauth.Credential{SchemaVersion: originauth.CredentialVersion, Provider: p.name, AccessKeyID: access,
		SecretAccessKey: "d5b-test-secret-" + p.name, NotBeforeUnix: now.Add(-time.Hour).Unix(), ExpiresAtUnix: now.Add(24 * time.Hour).Unix()}
}

func secretObject(p provider, revision uint64, access string, now time.Time) originauth.SecretObject {
	return originauth.SecretObject{Schema: originauth.SecretObjectSchema, RuleID: p.ruleID, Revision: revision, Rule: originauth.SecretRule{
		RuleID: p.ruleID, Provider: p.name, Algorithm: p.algorithm, Endpoint: originauth.Endpoint{Scheme: "https", Host: p.endpoint, Port: 443},
		Bucket: p.bucket, PathPrefix: "/", Region: p.region, Service: p.service, SignatureTTLSeconds: 600,
		CurrentKey: originauth.SecretKey{KeyID: "key-" + strconv.FormatUint(revision, 10), Credential: credential(p, access, now)}}}
}

// expectedAuthorization is the Go signer's Authorization for the request the
// bucket received, at the time the edge signed it.
func expectedAuthorization(p provider, object originauth.SecretObject, got received, rangeValue string) (string, error) {
	directory, err := os.MkdirTemp(*state, "signer-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(object.Rule.CurrentKey.Credential)
	file := filepath.Join(directory, "credential.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		return "", err
	}
	policy, _ := json.Marshal(originauth.Policy{SchemaVersion: originauth.SchemaVersion, PolicyVersion: 1, Rules: []originauth.Rule{{
		RuleID: p.ruleID, Provider: p.name, Algorithm: p.algorithm, Endpoint: "https://" + p.endpoint, Bucket: p.bucket, PathPrefix: "/",
		Region: p.region, Service: p.service, SignatureTTLSeconds: 600, CurrentKey: originauth.KeyRef{KeyID: "k", SecretFile: file}}}})
	_, compiled, err := originauth.CompileJSON(policy)
	if err != nil {
		return "", err
	}
	at := signedAt(p.name, got.header)
	signer, err := originauth.NewSigner(compiled, func() time.Time { return at })
	if err != nil {
		return "", err
	}
	request, _ := http.NewRequest(got.method, "https://"+p.endpoint+got.uri, nil)
	if rangeValue != "" {
		request.Header.Set("Range", rangeValue)
	}
	if err := signer.Sign(p.ruleID, request); err != nil {
		return "", err
	}
	return request.Header.Get("Authorization"), nil
}

func signedAt(name string, header http.Header) time.Time {
	switch name {
	case originauth.ProviderS3, originauth.ProviderOSS:
		field := "X-Amz-Date"
		if name == originauth.ProviderOSS {
			field = "X-Oss-Date"
		}
		value, _ := time.Parse("20060102T150405Z", header.Get(field))
		return value
	default:
		match := regexp.MustCompile(`q-sign-time=(\d+);`).FindStringSubmatch(header.Get("Authorization"))
		if match == nil {
			return time.Time{}
		}
		seconds, _ := strconv.ParseInt(match[1], 10, 64)
		return time.Unix(seconds, 0).UTC()
	}
}

func openresty(args ...string) error {
	output, err := exec.Command("openresty", append([]string{"-p", *state + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

var client = &http.Client{Timeout: 10 * time.Second}

func get(query string, header http.Header, body string) (int, string) {
	method := http.MethodGet
	var reader io.Reader
	if body != "" {
		method, reader = http.MethodPost, strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, "http://127.0.0.1:8080/dir/object.txt?versionId=3&"+query, reader)
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, strings.TrimSpace(string(raw))
}

func main() {
	flag.Parse()
	now := time.Now()
	authority := newCA()
	_ = os.RemoveAll(*state)
	for _, directory := range []string{"logs", "objects", "index", "run"} {
		if err := os.MkdirAll(filepath.Join(*state, directory), 0o755); err != nil {
			panic(err)
		}
	}
	// The bucket CA is a CA set object, so the signed request also goes over
	// verified TLS (cdnca_origintls) to the bucket's name.
	digest := writeObject(authority.pem)
	buckets := map[string]*bucket{}
	objects := map[string]originauth.SecretObject{}
	// The workers (nginx's default user nobody) read secret objects through
	// the worker group, as the agent sets it on a node.
	dir := originauth.SecretObjectDir{Root: filepath.Join(*state, "secrets"), GID: workerGID()}
	var initial []originauth.SecretObject
	for _, p := range providers {
		buckets[p.name] = serve(authority, p)
		objects[p.name] = secretObject(p, 1, "AKIA-"+strings.ToUpper(p.name)+"-1", now)
		initial = append(initial, objects[p.name])
	}
	if err := dir.Write(initial); err != nil {
		panic(err)
	}
	conf, _ := os.ReadFile("/t/nginx.conf")
	rendered := strings.NewReplacer("__LUA__", *luaRoot, "__STATE__", *state, "__ANCHOR__", "sha256:"+digest).Replace(string(conf))
	if err := os.WriteFile(filepath.Join(*state, "nginx.conf"), []byte(rendered), 0o644); err != nil {
		panic(err)
	}
	if err := openresty(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer openresty("-s", "stop")
	time.Sleep(300 * time.Millisecond)

	for _, p := range providers {
		status, body := get("pool="+p.pool, http.Header{"Range": {"bytes=0-9"}}, "")
		got, _ := buckets[p.name].last()
		want, err := expectedAuthorization(p, objects[p.name], got, "bytes=0-9")
		check("SIGN-"+strings.ToUpper(p.name), status == 200 && err == nil && got.auth != "" && got.auth == want,
			"status=%d body=%q signer_err=%v\n  got:  %s\n  want: %s", status, body, err, got.auth, want)
		check("HOST-"+strings.ToUpper(p.name), got.host == p.endpoint && got.sni == p.endpoint,
			"Host=%q SNI=%q（签名覆盖桶域名，回源 TLS 校验该名字）", got.host, got.sni)
		check("SECRET-NOT-IN-HEADERS-"+strings.ToUpper(p.name), !strings.Contains(fmt.Sprint(got.header), "d5b-test-secret"),
			"SecretAccessKey 不出现在发往源站的请求里")
	}
	s3 := providers[0]
	before := buckets[s3.name].count()
	status, _ := get("pool=s3", http.Header{"Authorization": {"Bearer client"}}, "")
	check("CLIENT-AUTH-REFUSED", status == 403 && buckets[s3.name].count() == before, "客户端自带 Authorization：%d，源站未收到", status)
	status, _ = get("pool=s3", nil, "body")
	check("BODY-REFUSED", status == 403 && buckets[s3.name].count() == before, "带体请求：%d，源站未收到", status)
	status, _ = get("pool=missing", nil, "")
	check("SECRET-MISSING-503", status == 503 && buckets[s3.name].count() == before, "机密对象缺失：%d，不发未签名请求", status)
	status, _ = get("pool=plain", nil, "")
	check("PLAIN-POOL-REFUSED", status == 502 && buckets[s3.name].count() == before, "签名池里有明文端点：%d，不明文发签名", status)
	status, _ = get("pool=unsigned", nil, "")
	got, _ := buckets[s3.name].last()
	check("UNBOUND-POOL-UNSIGNED", status == 200 && got.auth == "" && buckets[s3.name].count() == before+1, "未绑定的池不签名：%d auth=%q", status, got.auth)

	// Credential rotation: a new publication revision is a new object and a
	// new site object revision (here: the stand-in's pool "s3r2"); no reload.
	rotated := secretObject(s3, 2, "AKIA-S3-2", now)
	if err := dir.Write([]originauth.SecretObject{objects[s3.name], rotated, objects["oss"], objects["cos"]}); err != nil {
		panic(err)
	}
	status, _ = get("pool=s3r2", nil, "")
	got, _ = buckets[s3.name].last()
	want, err := expectedAuthorization(s3, rotated, got, "")
	check("ROTATE-NO-RELOAD", status == 200 && err == nil && got.auth == want && strings.Contains(got.auth, "AKIA-S3-2"),
		"新修订号机密对象不 reload 即生效：%d %s", status, got.auth)
	status, _ = get("pool=s3", nil, "")
	got, _ = buckets[s3.name].last()
	check("OLD-REVISION-KEPT", status == 200 && strings.Contains(got.auth, "AKIA-S3-1"), "上一修订仍可用（上一代站点对象）：%d", status)

	fullEntry(s3, rotated, digest, buckets[s3.name])

	log, _ := os.ReadFile(filepath.Join(*state, "logs", "error.log"))
	check("NO-SECRET-IN-ERROR-LOG", !strings.Contains(string(log), "d5b-test-secret"), "error.log 不含凭据")
	fmt.Printf("RESULT dynroute-originauth failures=%d\n", failures)
	if failures != 0 {
		lines := strings.Split(strings.TrimSpace(string(log)), "\n")
		for _, line := range lines[max(0, len(lines)-15):] {
			if strings.Contains(line, "cdnca") || strings.Contains(line, "error") {
				fmt.Println("error.log:", line)
			}
		}
		os.Exit(1)
	}
}

func writeObject(content []byte) string {
	sum := sha256Hex(content)
	path := filepath.Join(*state, "objects", "sha256", sum[:2], sum[2:4])
	if err := os.MkdirAll(path, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(path, sum), content, 0o444); err != nil {
		panic(err)
	}
	return sum
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

// fullEntry: the same signing reached through the dynamic routing entry
// (D5a): a site object with the s3 pool bound to its secret is activated in
// the D3 index; cdnca_site selects it by Host, cdnca_origin.access chooses
// the pool and calls cdnca_originauth.sign before the balancer, and a
// conditional route to an unbound pool sends no signature.
func fullEntry(p provider, object originauth.SecretObject, anchor string, b *bucket) {
	const siteID, tenant = "0d5b0000-0000-4000-8000-000000000010", "0d5b0000-0000-4000-8000-000000000011"
	endpoint := edgesite.Endpoint{ID: "e", Scheme: "https", Host: "127.0.0.1", Port: p.port, Weight: 1, SNI: p.endpoint,
		TrustAnchor: "sha256:" + anchor}
	retry := edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 3000}
	site := edgesite.Site{Schema: edgesite.Schema, ConfigurationScopeID: siteID, TenantID: tenant, SiteID: siteID, Revision: 1,
		Hosts:     edgesite.Hosts{Primary: "signed.test", Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: 8081, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "signed",
			Pools: []edgesite.Pool{
				{ID: "signed", Kind: edgesite.PoolOrigin, Algorithm: "round_robin", Endpoints: []edgesite.Endpoint{endpoint}, Retry: retry},
				{ID: "unsigned", Kind: edgesite.PoolOrigin, Algorithm: "round_robin", Endpoints: []edgesite.Endpoint{endpoint}, Retry: retry},
			},
			Routes: []edgesite.Route{{ID: "free", Priority: 1, PathPrefix: "/free", PoolID: "unsigned"}},
			Auth: []edgesite.OriginAuth{{PoolID: "signed", Endpoint: "https://" + p.endpoint,
				Secret: edgesite.Ref{Kind: edgesite.RefOriginAuthSecret, ID: object.RuleID, Revision: int64(object.Revision)}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
			CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{}}
	raw, err := edgesite.Encode(site)
	if err != nil {
		check("ENTRY-SITE-OBJECT", false, "%v", err)
		return
	}
	decoded, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		check("ENTRY-SITE-OBJECT", false, "%v", err)
		return
	}
	activator := &siteindex.Activator{Control: siteindex.NewControl(filepath.Join(*state, "run", "cdnca-site-admin.sock")),
		Files:   siteindex.Files{Root: filepath.Join(*state, "index"), Access: siteindex.Access{GID: workerGID()}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*state, "objects"), Access: siteindex.Access{GID: workerGID()}}}
	if _, err := activator.Activate(context.Background(), []siteindex.Object{decoded}); err != nil {
		check("ENTRY-ACTIVATE", false, "%v", err)
		return
	}
	entry := func(path string, header http.Header) int {
		request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8081"+path, nil)
		request.Host = "signed.test"
		for name, values := range header {
			request.Header[name] = values
		}
		response, err := client.Do(request)
		if err != nil {
			return 0
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	status := entry("/dir/object.txt?versionId=3", http.Header{"Range": {"bytes=0-9"}})
	got, _ := b.last()
	want, err := expectedAuthorization(p, object, got, "bytes=0-9")
	check("ENTRY-SIGNED", status == 200 && err == nil && got.auth != "" && got.auth == want && got.host == p.endpoint && got.sni == p.endpoint,
		"完整入口（选站→cdnca_origin.access 签名→balancer）：%d host=%q sni=%q\n  got:  %s\n  want: %s", status, got.host, got.sni, got.auth, want)
	before := b.count()
	status = entry("/dir/object.txt", http.Header{"Authorization": {"Bearer client"}})
	check("ENTRY-CLIENT-AUTH-REFUSED", status == 403 && b.count() == before, "完整入口客户端自带 Authorization：%d", status)
	status = entry("/free/x", nil)
	got, _ = b.last()
	check("ENTRY-UNBOUND-ROUTE-UNSIGNED", status == 200 && got.auth == "" && b.count() == before+1,
		"条件回源到未绑定的池不签名：%d auth=%q", status, got.auth)
}
