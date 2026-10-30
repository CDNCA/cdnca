//go:build scale

// G8-c：单节点大规模证书库（docs/architecture/million-sites-benchmark.md §5.5）。
// 只在 -tags scale 下跑：CDNCA_SCALE_CERTIFICATES 个站点（默认 10000），每站
// 一张独立 P-256 证书，1/3 站点 3 个域名；按 CDNCA_SCALE_CERTIFICATE_BATCH
// （默认 500）个站点一条命令批量导入，再测规模下的单站激活/轮换、引用、
// 全量解析、重启与回收的耗时和内存。
package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type scaleIssuer struct {
	key          *ecdsa.PrivateKey
	intermediate *x509.Certificate
	chainSuffix  []byte
	serial       int64
}

func newScaleIssuer(t *testing.T) *scaleIssuer {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scale root"},
		NotBefore: testNow.Add(-24 * time.Hour), NotAfter: testNow.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "scale intermediate"},
		NotBefore: testNow.Add(-12 * time.Hour), NotAfter: testNow.Add(36 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, _ := x509.ParseCertificate(der)
	return &scaleIssuer{key: key, intermediate: intermediate, chainSuffix: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 10}
}

func (issuer *scaleIssuer) binding(t *testing.T, siteID string, domains []string) Binding {
	t.Helper()
	issuer.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(issuer.serial), Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains,
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.intermediate, key.Public(), issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuer.chainSuffix...)
	return Binding{SiteID: siteID, Domains: domains, CertificateChainPEM: string(chain),
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))}
}

func scaleEnv(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

func scaleDomains(index int) []string {
	name := fmt.Sprintf("s%06d.example.test", index)
	if index%3 == 0 {
		return []string{"api." + name, name, "www." + name}
	}
	return []string{name}
}

func scaleHeapMiB() float64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return float64(stats.HeapInuse) / (1 << 20)
}

func scaleMaxRSSMiB() float64 {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	if runtime.GOOS == "darwin" {
		return float64(usage.Maxrss) / (1 << 20) // bytes
	}
	return float64(usage.Maxrss) / (1 << 10) // KiB
}

func TestScaleCertificateStore(t *testing.T) {
	total := scaleEnv("CDNCA_SCALE_CERTIFICATES", 10000)
	batch := scaleEnv("CDNCA_SCALE_CERTIFICATE_BATCH", 500)
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	issuer := newScaleIssuer(t)
	site := func(index int) string { return fmt.Sprintf("site-%06d", index) }
	revisions := map[string]uint64{}
	command := 0
	apply := func(indexes []int) time.Duration {
		t.Helper()
		command++
		bundle := Bundle{SchemaVersion: SchemaVersion, VersionID: fmt.Sprintf("scale-%06d", command)}
		versions := map[string]uint64{}
		for _, index := range indexes {
			revisions[site(index)]++
			versions[site(index)] = revisions[site(index)]
			bundle.Bindings = append(bundle.Bindings, issuer.binding(t, site(index), scaleDomains(index)))
		}
		activation := activationFor(bundle, fmt.Sprintf("event-%06d", command), 1, versions)
		start := time.Now()
		if _, err := manager.ApplyWithActivation(t.Context(), bundle, activation); err != nil {
			t.Fatalf("command %d (%d sites): %v", command, len(indexes), err)
		}
		return time.Since(start)
	}
	single := func(index int) time.Duration { return apply([]int{index}) }

	emptySingle := single(total + 1)
	t.Logf("single-site activation on an empty node: %v", emptySingle)

	bulkStart := time.Now()
	var firstBatch, lastBatch time.Duration
	for start := 0; start < total; start += batch {
		indexes := make([]int, 0, batch)
		for index := start; index < min(start+batch, total); index++ {
			indexes = append(indexes, index)
		}
		elapsed := apply(indexes)
		if start == 0 {
			firstBatch = elapsed
		}
		lastBatch = elapsed
	}
	t.Logf("bulk import %d sites in %d-site commands: %v (first command %v, last %v)",
		total, batch, time.Since(bulkStart).Round(time.Millisecond), firstBatch.Round(time.Millisecond), lastBatch.Round(time.Millisecond))
	t.Logf("after import: heap in use %.1f MiB, max RSS %.1f MiB", scaleHeapMiB(), scaleMaxRSSMiB())

	t.Logf("single-site activation with %d sites: %v (new site)", total, single(total+2))
	t.Logf("single-site rotation with %d sites: %v", total, single(total/2))

	current := make([]string, 0, total+3)
	for name, revision := range revisions {
		current = append(current, testCertificateVersionID(name, revision))
	}
	start := time.Now()
	if err := manager.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: current}); err != nil {
		t.Fatal(err)
	}
	t.Logf("set %d current references: %v", len(current), time.Since(start).Round(time.Millisecond))

	resolveAll := func(target *Manager) (int, time.Duration) {
		calls := 0
		start := time.Now()
		for index := 0; index < total; index++ {
			for _, domain := range scaleDomains(index) {
				calls++
				if _, err := target.ResolveCertificateVersion(t.Context(), CertificateResolveRequest{
					TenantScopeID: testTenantScopeID, SiteID: site(index),
					CertificateVersionID: testCertificateVersionID(site(index), revisions[site(index)]), Domain: domain,
				}); err != nil {
					t.Fatalf("resolve %s %s: %v", site(index), domain, err)
				}
			}
		}
		return calls, time.Since(start)
	}
	calls, elapsed := resolveAll(manager)
	t.Logf("resolve every site domain (%d calls): %v (%v per call)", calls, elapsed.Round(time.Millisecond), elapsed/time.Duration(calls))

	restartStart := time.Now()
	restarted, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Logf("restart and recover with %d sites: %v", total, time.Since(restartStart).Round(time.Millisecond))
	calls, elapsed = resolveAll(restarted)
	t.Logf("resolve every site domain after restart (cold cache, %d calls): %v", calls, elapsed.Round(time.Millisecond))

	// Rotate 100 sites, then drop their old versions from the references.
	rotated := make([]int, 0, 100)
	for index := 0; index < min(100, total); index++ {
		rotated = append(rotated, index*max(1, total/100))
	}
	manager = restarted
	rotationStart := time.Now()
	for _, index := range rotated {
		single(index)
	}
	t.Logf("rotate %d sites one command each: %v", len(rotated), time.Since(rotationStart).Round(time.Millisecond))
	current = current[:0]
	for name, revision := range revisions {
		current = append(current, testCertificateVersionID(name, revision))
	}
	start = time.Now()
	if err := restarted.SetCertificateVersionReferences(t.Context(), CertificateVersionReferences{Current: current}); err != nil {
		t.Fatal(err)
	}
	t.Logf("set references dropping %d rotated versions (collect): %v", len(rotated), time.Since(start).Round(time.Millisecond))
	key := siteKey(testTenantScopeID, site(rotated[0]))
	if record, _, _ := restarted.store.readSiteRecord(key); len(record.Retained) != 0 {
		t.Fatalf("rotated site kept %d versions after collection", len(record.Retained))
	}

	files, bytes := 0, int64(0)
	_ = filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			if info, infoErr := entry.Info(); infoErr == nil {
				files++
				bytes += info.Size()
			}
		}
		return nil
	})
	releases, _ := os.ReadDir(restarted.store.versions)
	t.Logf("state root: %d files, %.1f MiB of content, %d probe releases kept", files, float64(bytes)/(1<<20), len(releases))
	t.Logf("end: heap in use %.1f MiB, max RSS %.1f MiB", scaleHeapMiB(), scaleMaxRSSMiB())
}
