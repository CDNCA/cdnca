package rulecatalog

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
)

// crs/rules.json is the waf_set:crs_rules body generated from the pinned
// OWASP CRS source (edge/openresty/modsecurity/sources.lock.json) by
// TestCRSRulesBundleMatchesSource: every REQUEST-9xx rule file plus the data
// files they reference.
//
//go:embed crs/rules.json
var crsRulesJSON []byte

var (
	crsRulesOnce  sync.Once
	crsRulesValue WAFEngineBundle
)

// CRSRulesBundle returns a copy of the embedded CRS rule-text bundle.
func CRSRulesBundle() *WAFEngineBundle {
	crsRulesOnce.Do(func() {
		if err := json.Unmarshal(crsRulesJSON, &crsRulesValue); err != nil {
			panic("embedded CRS rules bundle is invalid: " + err.Error())
		}
		if _, err := DecodeWAFEngineBundle(crsRulesValue); err != nil {
			panic("embedded CRS rules bundle is invalid")
		}
	})
	value := crsRulesValue
	value.Files = append([]WAFEngineFile(nil), crsRulesValue.Files...)
	return &value
}

// BuildWAFEngineBundle packs rule files into a bundle (names sorted, gzip at
// best compression without name or time so the bytes depend on content only).
func BuildWAFEngineBundle(version string, files map[string][]byte) (WAFEngineBundle, error) {
	bundle := WAFEngineBundle{Engine: WAFEngineCRS, Version: version, Files: make([]WAFEngineFile, 0, len(files))}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var compressed bytes.Buffer
		writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
		if err != nil {
			return WAFEngineBundle{}, err
		}
		if _, err := writer.Write(files[name]); err != nil {
			return WAFEngineBundle{}, err
		}
		if err := writer.Close(); err != nil {
			return WAFEngineBundle{}, err
		}
		sum := sha256.Sum256(files[name])
		bundle.Files = append(bundle.Files, WAFEngineFile{Name: name, SHA256: hex.EncodeToString(sum[:]),
			Gzip: base64.RawStdEncoding.EncodeToString(compressed.Bytes())})
	}
	if _, err := DecodeWAFEngineBundle(bundle); err != nil {
		return WAFEngineBundle{}, err
	}
	return bundle, nil
}
