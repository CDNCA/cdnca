package rulecatalog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

const crsSourceSHA256 = "a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550" // coreruleset v4.30.0

var crsDataReference = regexp.MustCompile(`[a-z0-9][a-z0-9-]*\.data\b`)

// crsRuleFiles extracts the request rule files and the data files they
// reference from the pinned CRS source tarball.
func crsRuleFiles(t *testing.T, source string) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != crsSourceSHA256 {
		t.Fatalf("CRS source sha256 %x is not the pinned v4.30.0 archive", sum)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	rules, data := map[string][]byte{}, map[string][]byte{}
	var license []byte
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := path.Base(header.Name)
		if header.Name == "coreruleset-4.30.0/LICENSE" && header.Typeflag == tar.TypeReg {
			if license, err = io.ReadAll(reader); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if path.Base(path.Dir(header.Name)) != "rules" || header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasPrefix(name, "REQUEST-9") && strings.HasSuffix(name, ".conf"):
			rules[name] = content
		case strings.HasSuffix(name, ".data"):
			data[name] = content
		}
	}
	// Apache-2.0: the package ships the CRS LICENSE and our NOTICE.
	files := map[string][]byte{"LICENSE": license, "NOTICE": readNotice(t)}
	for name, content := range rules {
		files[name] = content
		for _, reference := range crsDataReference.FindAllString(string(content), -1) {
			if body, ok := data[reference]; ok {
				files[reference] = body
			}
		}
	}
	return files
}

func readNotice(t *testing.T) []byte {
	t.Helper()
	notice, err := os.ReadFile("crs/NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	return notice
}

// TestCRSRulesBundleMatchesSource regenerates crs/rules.json from the pinned
// CRS source and requires byte equality. Set CDNCA_CRS_SOURCE to the
// tarball; CDNCA_CRS_UPDATE=1 rewrites the file.
func TestCRSRulesBundleMatchesSource(t *testing.T) {
	source := os.Getenv("CDNCA_CRS_SOURCE")
	if source == "" {
		t.Skip("CDNCA_CRS_SOURCE not set")
	}
	bundle, err := BuildWAFEngineBundle("4.30.0", crsRuleFiles(t, source))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(bundle, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("CDNCA_CRS_UPDATE") == "1" {
		if err := os.WriteFile("crs/rules.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	// gzip bytes may differ between Go releases; the decoded content may not.
	want, err := DecodeWAFEngineBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeWAFEngineBundle(*CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("crs/rules.json has %d files, source %d", len(got), len(want))
	}
	for name, content := range want {
		if !bytes.Equal(got[name], content) {
			t.Fatalf("crs/rules.json %s differs from the source; rerun with CDNCA_CRS_UPDATE=1", name)
		}
	}
}

func TestCRSRulesBundleIsCompleteAndTamperEvident(t *testing.T) {
	bundle := CRSRulesBundle()
	files, err := DecodeWAFEngineBundle(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"REQUEST-901-INITIALIZATION.conf", "REQUEST-905-COMMON-EXCEPTIONS.conf",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "REQUEST-941-APPLICATION-ATTACK-XSS.conf", "unix-shell.data",
		"LICENSE", "NOTICE"} {
		if len(files[name]) == 0 {
			t.Fatalf("bundle lacks %s", name)
		}
	}
	for name, content := range files {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		for _, reference := range crsDataReference.FindAllString(string(content), -1) {
			if strings.Contains(string(content), "@pmFromFile "+reference) && files[reference] == nil {
				t.Fatalf("%s references missing %s", name, reference)
			}
		}
	}
	tampered := *bundle
	tampered.Files = append([]WAFEngineFile(nil), bundle.Files...)
	tampered.Files[0].SHA256 = strings.Repeat("0", 64)
	if _, err := DecodeWAFEngineBundle(tampered); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	tampered.Files[0] = bundle.Files[0]
	tampered.Files[0].Name = "../REQUEST-901-X.conf"
	if _, err := DecodeWAFEngineBundle(tampered); err == nil {
		t.Fatal("path name accepted")
	}
	item := Item{SystemKey: "waf_set:crs_rules", Kind: KindWAFRuleSet, Name: "x", Revision: 1,
		Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Bundle: bundle, Rules: []WAFRule{}}}}
	if ValidateItem(item) == nil {
		t.Fatal("bundle mixed with rules accepted")
	}
}
