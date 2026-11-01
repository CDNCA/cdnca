package nodesshinstall

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// node-cmd-lang2 (migration 610): the job's UI language reaches the installer
// as --lang zh / --lang en; an older job (language "") keeps the command it
// had before byte for byte.
func TestInstallCommandLanguage(t *testing.T) {
	const key = "nrk1.0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, ca := range []string{"", digest} {
		plain, err := InstallCommand("https://console.example.com", key, "203.0.113.7", "edge", false, true, ca, "")
		if err != nil || strings.Contains(plain, "--lang") {
			t.Fatalf("no language: %v %s", err, plain)
		}
		for _, language := range []string{"zh", "en"} {
			command, err := InstallCommand("https://console.example.com", key, "203.0.113.7", "edge", false, true, ca, language)
			if err != nil {
				t.Fatal(err)
			}
			// Same command with the flag as the installer's last argument.
			if command != plain+" --lang "+language {
				t.Fatalf("%s command:\n%s\nwant\n%s --lang %s", language, command, plain, language)
			}
		}
	}
	for _, bad := range []string{"zh-CN", "fr", "en'", " zh"} {
		if _, err := InstallCommand("https://console.example.com", key, "203.0.113.7", "", true, false, "", bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("language %q accepted", bad)
		}
	}
}

func TestCreateBodyLanguage(t *testing.T) {
	for raw, want := range map[string]string{"": "", "zh-CN": "zh", "zh": "zh", "ZH_tw": "zh", "en": "en", "en-US": "en"} {
		request, ok := createBody{Hosts: []string{"203.0.113.7"}, Language: raw}.createRequest()
		if !ok || request.Language != want {
			t.Errorf("language %q -> %q %v, want %q", raw, request.Language, ok, want)
		}
	}
	for _, raw := range []string{"fr", "english", "zhx", "e"} {
		if _, ok := (createBody{Hosts: []string{"203.0.113.7"}, Language: raw}).createRequest(); ok {
			t.Errorf("language %q accepted", raw)
		}
	}
	request, ok := createBody{Targets: []targetBody{{Host: "203.0.113.7", Username: "root", Password: "x"}}, Language: "en"}.createRequest()
	if !ok || request.Language != "en" {
		t.Fatalf("batch targets language: %q %v", request.Language, ok)
	}
	for language, want := range map[string]error{"zh": nil, "": nil, "de": ErrInvalidInput} {
		err := normalizeCreate(&CreateRequest{Targets: []Target{{Host: "203.0.113.7"}}, ControlPlane: "https://console.example.com",
			Credential: Credential{Username: "root", Password: "x"}, Language: language}, func(netip.Addr) bool { return false })
		if !errors.Is(err, want) {
			t.Errorf("normalizeCreate language %q: %v, want %v", language, err, want)
		}
	}
}
