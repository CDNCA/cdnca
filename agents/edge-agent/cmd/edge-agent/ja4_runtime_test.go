package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRestyComputesJA4OnlyWithTheModule(t *testing.T) {
	directory := t.TempDir()
	fake := func(name, configure string) string {
		path := filepath.Join(directory, name)
		script := "#!/bin/sh\necho 'nginx version: openresty/1.31.1.1' >&2\necho 'configure arguments: " + configure + "' >&2\n"
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, test := range map[string]struct {
		configure string
		want      bool
	}{
		"native":             {"--prefix=/usr/local/openresty/nginx --with-http_ssl_module --add-module=/tmp/openresty-source/bundle/cdnca-ja4 --with-stream", true},
		"last argument":      {"--with-http_ssl_module --add-module=/build/bundle/cdnca-ja4", true},
		"without module":     {"--prefix=/usr/local/openresty/nginx --with-http_ssl_module --with-http_v3_module", false},
		"other module named": {"--add-module=/build/bundle/cdnca-ja4-extra --add-module=/x/not-cdnca-ja4x", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := openRestyComputesJA4(context.Background(), fake(name, test.configure)); got != test.want {
				t.Fatalf("openRestyComputesJA4 = %v, want %v", got, test.want)
			}
		})
	}
	if openRestyComputesJA4(context.Background(), filepath.Join(directory, "missing")) || openRestyComputesJA4(context.Background(), "") {
		t.Fatal("missing binary reported JA4")
	}
}
