package http3runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const http3ReloadPatchSHA256 = "fcc2cd442e35b5e0cf15a3fa362fc3291ae8355ced463cfd5e9c06a320c7767d"

func TestOpenRestyBuildPinsHTTP3ReloadPatch(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	patchPath := filepath.Join(repoRoot, "edge/openresty/http3/patches/nginx-1.27.1-quic-reuseport-reload.patch")
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(patchBytes)
	if got := hex.EncodeToString(digest[:]); got != http3ReloadPatchSHA256 {
		t.Fatalf("reload patch sha256=%s, want %s", got, http3ReloadPatchSHA256)
	}
	patch := string(patchBytes)
	for _, fragment := range []string{
		"diff --git a/src/core/ngx_connection.c b/src/core/ngx_connection.c",
		"struct {} ngx_quic_master_state SEC(\".maps\")",
		"struct {} ngx_quic_connections SEC(\".maps\")",
		"NGX_QUIC_BPF_GROUP_RELOAD",
		"ngx_quic_bpf_get_client_connection",
		"ngx_quic_bpf_insert",
		"setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY",
	} {
		if !strings.Contains(patch, fragment) {
			t.Fatalf("reload patch missing complete QUIC dispatcher contract %q", fragment)
		}
	}
	// The 1.27.1 patch is the origin of native step 17 (its 1.31.1 port); the
	// container image and the native package both apply the locked chain.
	lockBytes, err := os.ReadFile(filepath.Join(repoRoot, "edge/openresty/native/sources.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Patches []struct {
			File   string `json:"file"`
			Origin struct {
				File   string `json:"file"`
				SHA256 string `json:"sha256"`
			} `json:"origin"`
		} `json:"patches"`
	}
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatal(err)
	}
	var port string
	for _, step := range lock.Patches {
		if step.Origin.File == "edge/openresty/http3/patches/nginx-1.27.1-quic-reuseport-reload.patch" && step.Origin.SHA256 == http3ReloadPatchSHA256 {
			port = step.File
		}
	}
	if port != "patches/17-nginx-1.31.1-quic-reuseport-reload.patch" {
		t.Fatalf("source lock has no port of the reload patch, got %q", port)
	}
	portBytes, err := os.ReadFile(filepath.Join(repoRoot, "edge/openresty/native", port))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"NGX_QUIC_BPF_GROUP_RELOAD", "ngx_quic_bpf_get_client_connection", "ngx_quic_bpf_insert"} {
		if !strings.Contains(string(portBytes), fragment) {
			t.Fatalf("ported reload patch missing QUIC dispatcher contract %q", fragment)
		}
	}
	for _, dockerfile := range []string{"edge/openresty/Dockerfile", "edge/openresty/native/Dockerfile"} {
		dockerfileBytes, err := os.ReadFile(filepath.Join(repoRoot, dockerfile))
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range []string{
			"COPY edge/openresty/native/patches /source-contract/patches",
			"RUN sh /source-contract/build-openresty.sh /source-contract",
		} {
			if !strings.Contains(string(dockerfileBytes), fragment) {
				t.Fatalf("%s missing locked patch chain contract %q", dockerfile, fragment)
			}
		}
	}
}
