package edgeconfig

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// listenerTestRuntime serves a signed release's CRS files (files, by name)
// and the test profile pack.
func listenerTestRuntime(files map[string][]byte) ListenerSecurityRuntime {
	return ListenerSecurityRuntime{StateRoot: "/runtime", LuaRoot: "/usr/local/share/cdnca",
		CRSFiles: func() (map[string][]byte, error) {
			if files == nil {
				return nil, errors.New("no CRS files")
			}
			return files, nil
		},
		CRSProfile: func(ref CRSProfileRef) (CRSProfile, error) {
			profile := testCRSProfile(testCRSProfileSHA256)
			if ref != profile.Ref {
				return CRSProfile{}, errors.New("unknown profile")
			}
			return profile, nil
		}}
}

// signedCRSFiles is what the control plane puts in the release for the
// listeners (by CRS file name).
func signedCRSFiles(t *testing.T, listeners []SecurityListener, text *CRSRuleText) map[string][]byte {
	t.Helper()
	signed, err := ListenerCRSReleaseFiles(listeners, text, []CRSProfile{testCRSProfile(testCRSProfileSHA256)})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for path, content := range signed {
		files[strings.TrimPrefix(path, crsReleaseDir+"/")] = content
	}
	return files
}

func TestRenderListenerRuntimeSecurityRejectsUnverifiedCRSText(t *testing.T) {
	security := ListenerSecurity{Policies: []SecurityPolicy{headerWAFPolicy()}, ManagedWAF: listenerTestManagedWAF()}
	listeners := []SecurityListener{listenerTestListener(8080, security)}
	if _, err := RenderListenerRuntimeSecurity(listenerTestScope, listenerTestVersion, listeners, listenerTestRuntime(nil)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing CRS text accepted: %v", err)
	}
	signed := signedCRSFiles(t, listeners, testCRSRuleText())
	for name, mutate := range map[string]func(map[string][]byte){
		"tampered": func(files map[string][]byte) {
			files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] = append(append([]byte(nil), files["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]...), []byte("SecRuleEngine Off\n")...)
		},
		"extra": func(files map[string][]byte) {
			files["REQUEST-932-APPLICATION-ATTACK-RCE.conf"] = testCRSRuleText().Files["REQUEST-932-APPLICATION-ATTACK-RCE.conf"]
		},
		"missing": func(files map[string][]byte) { delete(files, "REQUEST-941-APPLICATION-ATTACK-XSS.conf") },
		"license": func(files map[string][]byte) { delete(files, CRSLicenseFile) },
	} {
		files := make(map[string][]byte, len(signed))
		for key, value := range signed {
			files[key] = value
		}
		mutate(files)
		if _, err := RenderListenerRuntimeSecurity(listenerTestScope, listenerTestVersion, listeners, listenerTestRuntime(files)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s CRS text accepted: %v", name, err)
		}
	}
	unknown := listenerTestRuntime(signed)
	unknown.CRSProfile = func(CRSProfileRef) (CRSProfile, error) { return CRSProfile{}, errors.New("not on this node") }
	if _, err := RenderListenerRuntimeSecurity(listenerTestScope, listenerTestVersion, listeners, unknown); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown profile accepted: %v", err)
	}
	if none, err := ListenerCRSReleaseFiles([]SecurityListener{listenerTestListener(8080, ListenerSecurity{})}, nil, nil); err != nil || len(none) != 0 {
		t.Fatalf("a release without managed WAF needs CRS files %v %v", none, err)
	}
	for _, bad := range []ListenerSecurityRuntime{{StateRoot: "relative", LuaRoot: "/l"}, {StateRoot: "/s", LuaRoot: "/l/../x"}} {
		if _, err := RenderListenerRuntimeSecurity(listenerTestScope, listenerTestVersion, listeners, bad); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("unsafe runtime paths accepted: %#v", bad)
		}
	}
	if digest, ok := ListenerCRSProfileDigest(ListenerCRSProfilePath(testCRSProfileSHA256)); !ok || digest != testCRSProfileSHA256 {
		t.Fatalf("profile path round trip = %s %v", digest, ok)
	}
	if _, ok := ListenerCRSProfileDigest("security/modsecurity/crs-profiles/../x.json"); ok {
		t.Fatal("bad profile path accepted")
	}
}

func TestMergeSecurityInitLuaKeepsOneInitBlock(t *testing.T) {
	policy := testCCV2Policy(listenerTestScope, listenerTestSite)
	canonical, err := CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	binding := &CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), Policy: policy}
	fragments, err := RenderSecurityFragments(listenerTestScope, listenerTestVersion, []SecurityListener{
		{SiteID: listenerTestSite, Domain: "cc.example.test", Port: 8080, Protocol: ProtocolHTTP, Security: ListenerSecurity{CC: binding}}})
	if err != nil {
		t.Fatal(err)
	}
	statements := "    do local cdnca_probe = 1 end\n"
	merged, err := MergeSecurityInitLua(fragments.HTTP, statements)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(merged, "init_by_lua_block") != 1 || !strings.Contains(merged, statements) ||
		!strings.Contains(merged, `require("cc").init(`) || !strings.Contains(merged, CCV2RegistryEndMarker) {
		t.Fatalf("merged init:\n%s", merged)
	}
	if unchanged, _ := MergeSecurityInitLua(fragments.HTTP, ""); unchanged != fragments.HTTP {
		t.Fatal("an empty init changed the fragment")
	}
	standalone, err := MergeSecurityInitLua("  geo $x { default 0; }\n", statements)
	if err != nil || strings.Count(standalone, "init_by_lua_block {\n") != 1 || !strings.Contains(standalone, statements) {
		t.Fatalf("standalone init: %v\n%s", err, standalone)
	}
	if _, err := MergeSecurityInitLua(fragments.HTTP+fragments.HTTP, statements); err == nil {
		t.Fatal("two init blocks accepted")
	}
}
