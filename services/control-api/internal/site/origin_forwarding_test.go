package site

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

func forwardingPool() OriginPool {
	pool := defaultOriginPool([]Origin{
		{Host: "192.0.2.10", Port: 80, Weight: 1, Enabled: true},
		{Host: "origin.example.com", Port: 8080, Weight: 2, Enabled: true},
	})
	return pool
}

func testCAPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestNormalizeOriginForwardingDefaults(t *testing.T) {
	pool := forwardingPool()
	pool.RequestHost, pool.Scheme, pool.HTTPSPort, pool.TLS, pool.WebSocket = OriginRequestHost{}, "", 0, OriginTLS{}, nil
	if err := normalizeOriginPool(&pool); err != nil {
		t.Fatal(err)
	}
	if pool.RequestHost.Mode != OriginRequestHostVisitor || pool.Scheme != OriginSchemeHTTP || pool.HTTPSPort != 443 ||
		pool.TLS.Trust != OriginTrustSystem || pool.WebSocket == nil || !pool.WebSocket.Enabled {
		t.Fatalf("defaults: %+v", pool)
	}
}

func TestNormalizeOriginForwardingRejects(t *testing.T) {
	ca := testCAPEM(t, true)
	leaf := testCAPEM(t, false)
	for name, change := range map[string]func(*OriginPool){
		"hash without key":           func(p *OriginPool) { p.BalanceMethod = BalanceHash },
		"hash key with upstream var": func(p *OriginPool) { p.BalanceMethod, p.HashKey = BalanceHash, "$upstream_addr" },
		"hash key with injection":    func(p *OriginPool) { p.BalanceMethod, p.HashKey = BalanceHash, "$uri; return 200" },
		"key without hash":           func(p *OriginPool) { p.HashKey = "$uri" },
		"sticky without name":        func(p *OriginPool) { p.BalanceMethod, p.Sticky = BalanceSticky, &OriginSticky{Source: "cookie"} },
		"sticky bad source": func(p *OriginPool) {
			p.BalanceMethod, p.Sticky = BalanceSticky, &OriginSticky{Source: "path", Name: "x"}
		},
		"custom host empty": func(p *OriginPool) { p.RequestHost = OriginRequestHost{Mode: OriginRequestHostCustom} },
		"custom host with variable": func(p *OriginPool) {
			p.RequestHost = OriginRequestHost{Mode: OriginRequestHostCustom, Value: "$http_x"}
		},
		"visitor host with value": func(p *OriginPool) {
			p.RequestHost = OriginRequestHost{Mode: OriginRequestHostVisitor, Value: "a.test"}
		},
		"http with SNI":          func(p *OriginPool) { p.TLS.SNI = "a.test" },
		"http with https port":   func(p *OriginPool) { p.HTTPSPort = 8443 },
		"https with http port":   func(p *OriginPool) { p.Scheme, p.HTTPPort = OriginSchemeHTTPS, 8080 },
		"http port out of range": func(p *OriginPool) { p.HTTPPort = 65_536 },
		"visitor port with value": func(p *OriginPool) {
			p.RequestHost = OriginRequestHost{Mode: OriginRequestHostVisitorPort, Value: "a.test"}
		},
		"custom trust without CA": func(p *OriginPool) { p.Scheme, p.TLS.Trust = OriginSchemeHTTPS, OriginTrustCustom },
		"custom trust with leaf": func(p *OriginPool) {
			p.Scheme, p.TLS = OriginSchemeHTTPS, OriginTLS{Trust: OriginTrustCustom, CAPEM: leaf}
		},
		"system trust with CA": func(p *OriginPool) {
			p.Scheme, p.TLS = OriginSchemeHTTPS, OriginTLS{Trust: OriginTrustSystem, CAPEM: ca}
		},
		// fix-originnoverify: 不校验源站证书 carries no CA and needs HTTPS/follow
		"no verification with CA": func(p *OriginPool) {
			p.Scheme, p.TLS = OriginSchemeHTTPS, OriginTLS{Trust: OriginTrustNone, CAPEM: ca}
		},
		"http with no verification": func(p *OriginPool) { p.TLS.Trust = OriginTrustNone },
		"unknown trust":             func(p *OriginPool) { p.Scheme, p.TLS.Trust = OriginSchemeHTTPS, "insecure" },
		"follow port and protocol with ports": func(p *OriginPool) {
			p.Scheme, p.FollowPort, p.HTTPSPort = OriginSchemeFollow, true, 8443
		},
		"follow port sticky": func(p *OriginPool) {
			p.BalanceMethod, p.Sticky, p.FollowPort = BalanceSticky, &OriginSticky{Source: "cookie", Name: "s"}, true
		},
		"only backups":               func(p *OriginPool) { p.Origins[0].Level, p.Origins[1].Level = 1, 2 },
		"level out of range":         func(p *OriginPool) { p.Origins[1].Level = MaxOriginLevel + 1 },
		"negative level":             func(p *OriginPool) { p.Origins[1].Level = -1 },
		"unknown failback mode":      func(p *OriginPool) { p.FailbackMode = "later" },
		"health path without slash":  func(p *OriginPool) { p.HealthCheckPath = "health" },
		"max conns negative":         func(p *OriginPool) { p.Origins[0].MaxConns = -1 },
		"trust every client":         func(p *OriginPool) { p.TrustedProxyCIDRs = []string{"0.0.0.0/0"} },
		"websocket off with origins": func(p *OriginPool) { p.WebSocket = &OriginWebSocket{AllowedOrigins: []string{"https://a.test"}} },
		"websocket origin with path": func(p *OriginPool) { p.WebSocket.AllowedOrigins = []string{"https://a.test/x"} },
		"origin host mixed with hash": func(p *OriginPool) {
			p.RequestHost.Mode, p.BalanceMethod, p.HashKey = OriginRequestHostOrigin, BalanceHash, "$uri"
		},
	} {
		t.Run(name, func(t *testing.T) {
			pool := forwardingPool()
			change(&pool)
			if err := normalizeOriginPool(&pool); err == nil {
				t.Fatalf("accepted %+v", pool)
			}
		})
	}
}

// fix-originnoverify: HTTPS and follow pools may choose not to verify the
// origin certificate (源站自签证书时选); the SNI is still normalized.
func TestNormalizeOriginForwardingAcceptsNoVerify(t *testing.T) {
	for _, scheme := range []string{OriginSchemeHTTPS, OriginSchemeFollow} {
		pool := forwardingPool()
		pool.Scheme, pool.TLS = scheme, OriginTLS{SNI: "Origin.Example.com", Trust: OriginTrustNone}
		if err := normalizeOriginPool(&pool); err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		if pool.TLS.Trust != OriginTrustNone || pool.TLS.CAPEM != "" || pool.TLS.SNI != "origin.example.com" {
			t.Fatalf("%s: %+v", scheme, pool.TLS)
		}
	}
}

func TestNormalizeOriginForwardingCanonicalizes(t *testing.T) {
	ca := testCAPEM(t, true)
	pool := forwardingPool()
	pool.BalanceMethod, pool.Sticky = BalanceSticky, &OriginSticky{Source: OriginStickyHeader, Name: "X-Route"}
	pool.RequestHost = OriginRequestHost{Mode: OriginRequestHostCustom, Value: " Bucket.Example.COM:8080 "}
	pool.Scheme, pool.HTTPSPort = OriginSchemeFollow, 8443
	pool.TLS = OriginTLS{SNI: "Origin.Example.com", Trust: OriginTrustCustom, CAPEM: "\n" + ca + "\n"}
	pool.WebSocket = &OriginWebSocket{Enabled: true, AllowedOrigins: []string{"https://B.test", "https://a.test:8443", "https://b.test"}}
	pool.TrustedProxyCIDRs = []string{"10.1.2.3/8", "2001:db8::1", "10.0.0.0/8"}
	pool.Origins[1].MaxConns = 300
	if err := normalizeOriginPool(&pool); err != nil {
		t.Fatal(err)
	}
	if pool.Sticky.Name != "x-route" || pool.RequestHost.Value != "bucket.example.com:8080" || pool.TLS.SNI != "origin.example.com" ||
		pool.TLS.CAPEM != ca || strings.Join(pool.WebSocket.AllowedOrigins, ",") != "https://a.test:8443,https://b.test" ||
		strings.Join(pool.TrustedProxyCIDRs, ",") != "10.0.0.0/8,2001:db8::1/128" {
		t.Fatalf("not canonical: %+v %+v %+v", pool, pool.TLS, pool.WebSocket)
	}
}

// fix-originnoverify: switching to 不校验源站证书 is in the audit changes.
func TestOriginForwardingAuditChangesRecordNoVerify(t *testing.T) {
	before := forwardingPool()
	before.Scheme = OriginSchemeHTTPS
	after := before
	after.TLS = OriginTLS{Trust: OriginTrustNone}
	for _, change := range originForwardingChanges(before, after) {
		if change.Field == "tls_trust" && change.Before == OriginTrustSystem && change.After == OriginTrustNone {
			return
		}
	}
	t.Fatalf("changes %+v", originForwardingChanges(before, after))
}

func TestOriginForwardingAuditChangesHideTheCA(t *testing.T) {
	before := forwardingPool()
	after := forwardingPool()
	after.Scheme, after.TLS = OriginSchemeHTTPS, OriginTLS{Trust: OriginTrustCustom, CAPEM: testCAPEM(t, true)}
	after.Origins[1].Level = 1
	changes := originForwardingChanges(before, after)
	fields := map[string]any{}
	for _, change := range changes {
		fields[change.Field] = change.After
	}
	if fields["scheme"] != OriginSchemeHTTPS || fields["tls_trust"] != OriginTrustCustom || fields["backup_origins"] != 1 ||
		!strings.HasPrefix(fields["tls_ca"].(string), "sha256:") {
		t.Fatalf("changes %+v", changes)
	}
}

func TestNormalizeConditionalOriginHosts(t *testing.T) {
	hosts, err := normalizeConditionalOriginHosts([]string{"B.example.com", "*.example.com", "b.example.com"})
	if err != nil || strings.Join(hosts, ",") != "*.example.com,b.example.com" {
		t.Fatalf("%v %v", hosts, err)
	}
	if _, err := normalizeConditionalOriginHosts([]string{"bad host"}); err == nil {
		t.Fatal("accepted an invalid host")
	}
}

func TestNormalizeOriginPoolLevelsWithEveryBalanceMethod(t *testing.T) {
	for _, method := range []string{BalanceIPHash, BalanceURLHash, BalanceRandom, BalanceHash} {
		pool := forwardingPool()
		pool.BalanceMethod, pool.Origins[1].Level = method, 2
		if method == BalanceHash {
			pool.HashKey = "$uri"
		}
		if err := normalizeOriginPool(&pool); err != nil {
			t.Fatalf("%s with a backup level: %v", method, err)
		}
	}
}

func TestNormalizeOriginPoolBackupOrigins(t *testing.T) {
	pool := forwardingPool()
	pool.BackupOrigins = []string{" 198.51.100.7:8080 ", "", "backup.example.com", "198.51.100.7:8080", "192.0.2.10", "[2001:db8::5]:81"}
	if err := normalizeOriginPool(&pool); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, origin := range pool.Origins[2:] {
		got = append(got, originCompatibilityEndpoint(origin)+"@"+string(rune('0'+origin.Level)))
	}
	// blank ignored, the repeat and the primary dropped, levels in order
	if strings.Join(got, ",") != "198.51.100.7:8080@1,backup.example.com@2,[2001:db8::5]:81@3" || pool.BackupOrigins != nil {
		t.Fatalf("backups %v (%+v)", got, pool.Origins)
	}
	for name, change := range map[string]func(*OriginPool){
		"bad address":        func(p *OriginPool) { p.BackupOrigins = []string{"http://x.test/"} },
		"levels and list":    func(p *OriginPool) { p.Origins[1].Level, p.BackupOrigins = 1, []string{"x.test"} },
		"more than 15 lines": func(p *OriginPool) { p.BackupOrigins = sixteenBackups() },
	} {
		pool := forwardingPool()
		change(&pool)
		if err := normalizeOriginPool(&pool); err == nil {
			t.Fatalf("%s accepted %+v", name, pool.Origins)
		}
	}
}

func sixteenBackups() []string {
	var lines []string
	for index := range 16 {
		lines = append(lines, "b"+string(rune('a'+index))+".example.com")
	}
	return lines
}

// tp-b3a-be (migration 490): the competitor's 跟随协议和端口, 访问域名+端口,
// pool HTTP/HTTPS 回源端口 and the site's origin auth switch.
func TestNormalizeOriginForwardingParity(t *testing.T) {
	pool := forwardingPool()
	pool.Scheme, pool.FollowPort = OriginSchemeFollow, true
	pool.RequestHost = OriginRequestHost{Mode: OriginRequestHostVisitorPort}
	if err := normalizeOriginPool(&pool); err != nil {
		t.Fatalf("follow protocol and port: %v", err)
	}
	if pool.HTTPPort != 80 || pool.HTTPSPort != 443 || pool.OriginAuthEnabled == nil || !*pool.OriginAuthEnabled {
		t.Fatalf("defaults: %+v", pool)
	}

	// origins without their own port take the pool's: HTTP for http/follow, HTTPS for https
	for _, test := range []struct {
		scheme          string
		httpPort, https int
		want            int
	}{{OriginSchemeHTTP, 8080, 0, 8080}, {OriginSchemeFollow, 8081, 8443, 8081}, {OriginSchemeHTTPS, 0, 8443, 8443}} {
		pool := forwardingPool()
		pool.Scheme, pool.HTTPPort, pool.HTTPSPort = test.scheme, test.httpPort, test.https
		pool.Origins[0].PortInherited, pool.Origins[0].Port = true, 1
		if err := normalizeOriginPool(&pool); err != nil {
			t.Fatalf("%s: %v", test.scheme, err)
		}
		if pool.Origins[0].Port != test.want || pool.Origins[1].Port != 8080 {
			t.Fatalf("%s: ports %d %d, want %d and the origin's own 8080", test.scheme, pool.Origins[0].Port, pool.Origins[1].Port, test.want)
		}
	}

	off := false
	before, after := forwardingPool(), forwardingPool()
	after.OriginAuthEnabled, after.HTTPPort = &off, 8080
	after.Origins[0].PortInherited = true
	fields := map[string]any{}
	for _, change := range originForwardingChanges(before, after) {
		fields[change.Field] = change.After
	}
	if fields["origin_auth_enabled"] != false || fields["http_port"] != 8080 || fields["port_inherited_origins"] != 1 {
		t.Fatalf("audit changes: %+v", fields)
	}
}
