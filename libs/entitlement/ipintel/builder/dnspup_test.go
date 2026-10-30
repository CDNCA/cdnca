package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

// testdata/dnspup-snapshot.ndjson.gz was written by dnspup's exporter
// (branch feat/ip-intel-export, TestIPIntelExportMatchesIPInfo) over a
// seeded PostgreSQL with ip2region / 0701 libraries and manual
// corrections; every row equals dnspup's live ip-info answer.
const dnspupFixtureRelease = "ipx-97e2645f8a560d5db29affa6"

func dnspupFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "dnspup-snapshot.ndjson.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dnspupNDJSON(t *testing.T) string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(dnspupFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func gz(t *testing.T, text string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, _ = writer.Write([]byte(text))
	_ = writer.Close()
	return buffer.Bytes()
}

// uploaded copies data into a temp dir under name, as an operator upload.
func uploaded(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileSourceBuildSignLookup(t *testing.T) {
	path := uploaded(t, "dnspup-ipintel-"+dnspupFixtureRelease+".ndjson.gz", dnspupFixture(t))
	fileSource, err := NewFileSource(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	var source Source = fileSource
	collection, err := source.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if collection.SourceRelease != dnspupFixtureRelease || collection.DataUpdatedAt.IsZero() || len(collection.Sources) != 10 ||
		!strings.Contains(collection.Notice, "X4B (Mathew Heard)") || !strings.Contains(collection.Notice, "ip2region") {
		t.Fatalf("collection = %+v", collection)
	}
	generatedAt := collection.DataUpdatedAt.Add(2 * time.Hour).Truncate(time.Second)
	artifact, err := Compile(collection, CompileRequest{Revision: 9, BuildID: "ipintel-20261017-000009", GeneratedAt: generatedAt})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	release, err := format.NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := format.Sign(context.Background(), release, testKeySigner{private}, generatedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := format.VerifyEd25519(signed, private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	table, err := format.VerifyArtifact(signed.Release, artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Release.SourceRelease != dnspupFixtureRelease {
		t.Fatalf("release = %+v", signed.Release)
	}
	cases := []struct {
		addr string
		want format.Attrs
	}{
		// 电信：ip2region 福州覆盖 DB-IP 深圳
		{"1.0.1.9", format.Attrs{Tags: format.TagCNTelecom, ASN: 4134, Country: "CN", Province: 350000, City: 350100}},
		{"36.100.1.1", format.Attrs{Tags: format.TagCNTelecom, ASN: 4134, Country: "CN", Province: 440000, City: 440300}},
		// 联通 + 人工纠错（首条命中：天津）
		{"58.16.1.200", format.Attrs{Tags: format.TagCNUnicom, ASN: 4837, Country: "CN", Province: 120000, City: 120100}},
		// 移动：无 ASN，运营商来自 ip2region ISP
		{"111.0.1.1", format.Attrs{Tags: format.TagCNMobile, Country: "CN", Province: 440000, City: 440300}},
		// 人工审核纠错（重庆）
		{"36.96.7.9", format.Attrs{Tags: format.TagCNTelecom, ASN: 4812, Country: "CN", Province: 500000, City: 500100}},
		// 国内 IDC（阿里云）
		{"47.96.1.1", format.Attrs{Tags: format.TagIDCCN, ASN: 37963, Country: "CN", Province: 330000, City: 330100}},
		// 境外 IDC 与同国家非 IDC
		{"3.1.1.1", format.Attrs{Tags: format.TagIDCGlobal, ASN: 16509, Country: "US"}},
		{"3.200.1.1", format.Attrs{Country: "US"}},
		{"5.9.1.1", format.Attrs{Tags: format.TagIDCGlobal, ASN: 24940, Country: "DE"}},
		{"45.76.1.1", format.Attrs{Tags: format.TagIDCGlobal}},
		// IPv6
		{"240e:1::1", format.Attrs{Tags: format.TagCNTelecom, ASN: 4134, Country: "CN", Province: 440000}},
		{"2408:8000::1", format.Attrs{Tags: format.TagCNUnicom, ASN: 4837, Country: "CN", Province: 110000, City: 110100}},
		{"2408:8000:1::5", format.Attrs{Tags: format.TagCNUnicom, ASN: 4837, Country: "CN", Province: 440000, City: 440100}},
		{"2a01:4f8::1", format.Attrs{Tags: format.TagIDCGlobal, ASN: 24940, Country: "DE"}},
		{"::ffff:58.16.1.200", format.Attrs{Tags: format.TagCNUnicom, ASN: 4837, Country: "CN", Province: 120000, City: 120100}},
	}
	for _, tc := range cases {
		if got, found := table.Lookup(netip.MustParseAddr(tc.addr)); !found || got != tc.want {
			t.Errorf("Lookup(%s) = %+v found=%v, want %+v", tc.addr, got, found, tc.want)
		}
	}
	for _, addr := range []string{"9.9.9.9", "192.168.1.1", "185.220.101.1", "45.77.1.1", "2001:db8::1"} {
		if got, found := table.Lookup(netip.MustParseAddr(addr)); found {
			t.Errorf("Lookup(%s) = %+v, want not found", addr, got)
		}
	}
	licenses := map[string]string{}
	for _, item := range table.Metadata.Sources {
		licenses[item.ID] = item.License
		if item.Attribution == "" && item.License != "CC0-1.0" && item.License != "WTFPL" {
			t.Errorf("source %s lost its attribution", item.ID)
		}
	}
	if licenses["ip2region-v4"] != "LicenseRef-ip2region-commercial" || licenses["supplemental-0701"] != "LicenseRef-dnspup-supplemental-0701" ||
		licenses["manual-corrections"] != "LicenseRef-dnspup-manual" || licenses["dnspup-ip-library"] != "LicenseRef-dnspup" ||
		licenses["geo"] != "CC-BY-4.0" || licenses["x4bnet-risk"] != "MIT" {
		t.Fatalf("licenses = %v", licenses)
	}
	// Deterministic: the same file builds the same artifact.
	again, err := source.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(again, CompileRequest{Revision: 9, BuildID: "ipintel-20261017-000009", GeneratedAt: generatedAt})
	if err != nil || !bytes.Equal(second.Bytes, artifact.Bytes) || Fingerprint(again) != Fingerprint(collection) {
		t.Fatalf("rebuild differs: %v", err)
	}
}

func TestFileSourceRejectsBadUploads(t *testing.T) {
	fixture := dnspupFixture(t)
	for name, path := range map[string]string{
		"missing":       filepath.Join(t.TempDir(), "absent.ndjson.gz"),
		"directory":     t.TempDir(),
		"wrong release": uploaded(t, "dnspup-ipintel-ipx-000000000000000000000000.ndjson.gz", fixture),
		"truncated":     uploaded(t, "upload.gz", fixture[:len(fixture)/2]),
		"not gzip":      uploaded(t, "upload.gz", []byte(dnspupNDJSON(t))),
	} {
		if _, err := NewFileSource(path, 0); !errors.Is(err, ErrSource) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := NewFileSource(uploaded(t, "upload.gz", fixture), int64(len(fixture)-1)); !errors.Is(err, ErrSource) {
		t.Errorf("size limit: %v", err)
	}
	// Any name works when it does not claim a release.
	if _, err := NewFileSource(uploaded(t, "ipintel-upload.gz", fixture), 0); err != nil {
		t.Fatal(err)
	}
	// Replaced on disk by a broken file: the next Collect fails (caller keeps the last library).
	path := uploaded(t, "ipintel.gz", fixture)
	source, err := NewFileSource(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fixture[:100], 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Collect(context.Background()); !errors.Is(err, ErrSource) {
		t.Fatalf("replaced file: %v", err)
	}
}

type testKeySigner struct{ private ed25519.PrivateKey }

func (testKeySigner) KeyID() string { return "license-test-key" }
func (signer testKeySigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestDnspupSnapshotRejections(t *testing.T) {
	valid := dnspupNDJSON(t)
	lines := strings.Split(strings.TrimSuffix(valid, "\n"), "\n")
	withoutEnd := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	cases := map[string]string{
		"truncated":           withoutEnd,
		"row count":           strings.Replace(valid, `"rows":161`, `"rows":160`, 1),
		"end release":         strings.Replace(valid, `"type":"end","release":"`+dnspupFixtureRelease, `"type":"end","release":"ipx-other`, 1),
		"data after end":      valid + `{"type":"prefix","prefix":"9.9.9.0/24","asn":1,"source_id":"dnspup-ip-library"}` + "\n",
		"unlisted source":     strings.Replace(valid, `"source_id":"dnspup-ip-library"}`, `"source_id":"itdog"}`, 1),
		"host bits":           strings.Replace(valid, `"prefix":"45.76.0.0/16"`, `"prefix":"45.76.0.1/16"`, 1),
		"unknown field":       strings.Replace(valid, `"source_id":"dnspup-ip-library"}`, `"source_id":"dnspup-ip-library","extra":1}`, 1),
		"region w/o name":     strings.Replace(valid, `"province":350000,"city":350100`, `"province":350000,"city":350199`, 1),
		"schema":              strings.Replace(valid, DnspupExportSchema, "dnspup.ip-intel.export/v9", 1),
		"commercial source":   strings.Replace(valid, `"license":"CC-BY-4.0","attribution":"IP Geolocation by DB-IP`, `"license":"LicenseRef-ip2region-commercial","attribution":"IP Geolocation by DB-IP`, 1),
		"denied source id":    strings.Replace(valid, `{"id":"x4bnet-risk"`, `{"id":"itdog"`, 1),
		"wrong licence ref":   strings.Replace(valid, `"license":"LicenseRef-dnspup-manual"`, `"license":"LicenseRef-dnspup"`, 1),
		"unknown licence ref": strings.Replace(valid, `"license":"LicenseRef-dnspup-manual"`, `"license":"LicenseRef-other"`, 1),
		"missing attrib":      strings.Replace(valid, `"attribution":"IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0"`, `"attribution":""`, 1),
	}
	for name, text := range cases {
		if text == valid {
			t.Fatalf("%s: mutation did not apply", name)
		}
		_, _, err := ParseDnspupSnapshot(bytes.NewReader(gz(t, text)), 1<<30)
		if !errors.Is(err, ErrSource) && !errors.Is(err, ErrLicense) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, name := range []string{"commercial source", "denied source id", "missing attrib", "wrong licence ref", "unknown licence ref"} {
		if _, _, err := ParseDnspupSnapshot(bytes.NewReader(gz(t, cases[name])), 1<<30); !errors.Is(err, ErrLicense) {
			t.Errorf("%s: want ErrLicense, got %v", name, err)
		}
	}
	// gzip stream cut mid-way.
	fixture := dnspupFixture(t)
	if _, _, err := ParseDnspupSnapshot(bytes.NewReader(fixture[:len(fixture)-10]), 1<<30); !errors.Is(err, ErrSource) {
		t.Errorf("cut gzip: %v", err)
	}
	if _, _, err := ParseDnspupSnapshot(bytes.NewReader(fixture), 100); !errors.Is(err, ErrSource) {
		t.Errorf("size limit: %v", err)
	}
	if _, _, err := ParseDnspupSnapshot(bytes.NewReader([]byte(valid)), 1<<30); !errors.Is(err, ErrSource) {
		t.Errorf("not gzip: %v", err)
	}
}

func TestCompileRejectsNonRedistributable(t *testing.T) {
	collection, err := loadFixture(t).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, license := range []string{"LicenseRef-ip2region", "", "GPL-3.0-only", "CC-BY-SA-4.0"} {
		bad := collection
		bad.Sources = append([]format.Source(nil), collection.Sources...)
		bad.Sources[0].License = license
		if _, err := Compile(bad, CompileRequest{Revision: 1, BuildID: "b1", GeneratedAt: fixtureNow}); !errors.Is(err, ErrLicense) {
			t.Errorf("license %q: %v", license, err)
		}
	}
}

// IP 库不按时间过期，新库替换旧库即可：上游数据再旧也照常
// 构建，签出的库在任何时刻都是就绪的。
func TestCompileAcceptsOldDataAndNeverGoesStale(t *testing.T) {
	collection, err := loadFixture(t).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old := collection
	old.DataUpdatedAt = fixtureNow.Add(-400 * 24 * time.Hour)
	artifact, err := Compile(old, CompileRequest{Revision: 1, BuildID: "b1", GeneratedAt: fixtureNow})
	if err != nil {
		t.Fatalf("old data: %v", err)
	}
	release, err := format.NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !release.Fresh(fixtureNow.Add(10 * 365 * 24 * time.Hour)) {
		t.Fatalf("library went stale: stale_after=%d", release.StaleAfter)
	}
}
