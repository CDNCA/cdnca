package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestLoadOpenRestySecuritySecretCipherRequiresCanonicalAES256Key(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	tests := []struct {
		name  string
		value string
	}{
		{name: "missing"},
		{name: "invalid base64", value: "not-base64"},
		{name: "wrong length", value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))},
		{name: "non canonical", value: strings.TrimRight(valid, "=")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(openRestySecuritySecretKeyEnvironment, test.value)
			cipher, err := loadOpenRestySecuritySecretCipher()
			if cipher != nil || err == nil || !strings.Contains(err.Error(), openRestySecuritySecretKeyEnvironment) {
				t.Fatalf("load cipher = (%#v, %v)", cipher, err)
			}
			if test.value != "" && strings.Contains(err.Error(), test.value) {
				t.Fatal("configuration error disclosed key material")
			}
		})
	}

	t.Setenv(openRestySecuritySecretKeyEnvironment, valid)
	if cipher, err := loadOpenRestySecuritySecretCipher(); cipher == nil || err != nil {
		t.Fatalf("load valid cipher = (%#v, %v)", cipher, err)
	}
}

func TestOpenRestySecurityProductionCompositionWiresCanonicalRuntime(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"loadOpenRestySecuritySecretCipher()",
		"openrestysecurityhttp.NewRuntimeHandler(",
		"Sealer: openRestySecuritySecretCipher",
		"withOpenRestySecurityRoutes(",
	} {
		if !bytes.Contains(source, []byte(marker)) {
			t.Errorf("production composition is missing %q", marker)
		}
	}
}
