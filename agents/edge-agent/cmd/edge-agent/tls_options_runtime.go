package main

import (
	"debug/elf"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// tlsOptionsSymbol is the function native patch 27 adds to
// ngx_http_ssl_module.c; cdnca_tls.lua calls it through LuaJIT FFI, so the
// binary exports it (-Wl,-E, ngx_lua's config).
const tlsOptionsSymbol = "ngx_http_cdnca_ssl_set_http2"

// openRestySetsSiteTLSOptions reports whether the OpenResty binary carries
// native patch 27 (the symbol is in its dynamic symbol table). The agent
// declares SITE_TLS_OPTIONS v1 only then: per site HTTP/2 off would
// otherwise refuse every handshake of that site, and an explicit
// prefer_server_ciphers ships with the same Lua.
func openRestySetsSiteTLSOptions(binary string) bool {
	return openRestyExports(binary, tlsOptionsSymbol)
}

// originHostCheckSymbol is the function native patch 29 adds to
// ngx_http_upstream.c (cdnca_origintls.set_host_check calls it by FFI).
const originHostCheckSymbol = "ngx_http_cdnca_upstream_set_ssl_host_check"

// openRestySkipsOriginHostCheck reports whether the binary carries native
// patch 29: only then may an HTTPS origin use trust anchor "none" (回源
// HTTPS 不校验源站证书); without it a self-signed origin still fails the
// host name check.
func openRestySkipsOriginHostCheck(binary string) bool {
	return openRestyExports(binary, originHostCheckSymbol)
}

func addOriginTLSNoVerifyCapability(capabilities *agentv1.AgentCapabilities, ready bool) {
	if ready {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY, ApiVersion: edgeconfig.OriginTLSNoVerifyAPIVersion,
		})
	}
}

// openRestyExports: the binary's dynamic symbol table defines function name.
func openRestyExports(binary, name string) bool {
	if binary == "" {
		return false
	}
	file, err := elf.Open(binary)
	if err != nil {
		return false
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return false
	}
	for _, symbol := range symbols {
		if symbol.Name == name && elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Section != elf.SHN_UNDEF {
			return true
		}
	}
	return false
}

func addSiteTLSOptionsCapability(capabilities *agentv1.AgentCapabilities, ready bool) {
	if ready {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS, ApiVersion: 1,
		})
	}
}
