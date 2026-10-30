package edgeconfig

import (
	"strings"
	"testing"
	"time"
)

func TestNginxListenPortRequiresSingleCanonicalUnquotedToken(t *testing.T) {
	tests := map[string]struct {
		listen string
		port   uint16
		valid  bool
	}{
		"zero":                  {listen: "0"},
		"minimum":               {listen: "1", port: 1, valid: true},
		"maximum":               {listen: "65535", port: 65535, valid: true},
		"overflow":              {listen: "65536"},
		"leading zero":          {listen: "01"},
		"IPv4 minimum":          {listen: "127.0.0.1:1", port: 1, valid: true},
		"IPv4 maximum":          {listen: "127.0.0.1:65535", port: 65535, valid: true},
		"IPv6 minimum":          {listen: "[::1]:1", port: 1, valid: true},
		"IPv6 maximum":          {listen: "[::1]:65535", port: 65535, valid: true},
		"quoted numeric":        {listen: `"19090"`},
		"comment split numeric": {listen: "# decoy\n19090"},
		"multiline numeric":     {listen: "\n19090"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			document, ok := parseNginxDirectives("server { listen " + test.listen + "; }")
			if !ok {
				t.Fatal("test fixture is not valid Nginx structure")
			}
			server, ok := uniqueNginxBlock(document, 0, []string{"server"})
			if !ok {
				t.Fatal("server block was not parsed")
			}
			listeners := document.directNamed(server, "listen")
			if len(listeners) != 1 {
				t.Fatalf("listen directives = %d, want 1", len(listeners))
			}
			port, valid := nginxListenPort(listeners[0])
			if valid != test.valid || valid && port != test.port {
				t.Fatalf("nginxListenPort() = (%d, %t), want (%d, %t)", port, valid, test.port, test.valid)
			}
		})
	}
}

func TestParseNginxDirectivesConcatenatesQuotedTokenFragments(t *testing.T) {
	document, ok := parseNginxDirectives(`ht"tp" {
	  ser"ver" {
	    lis"ten" 18081;
	    set val"ue" 19"090";
	    "listen" 18082;
	  }
	}`)
	if !ok {
		t.Fatal("valid concatenated Nginx token fragments were rejected")
	}
	httpBlock, ok := uniqueNginxBlock(document, 0, []string{"http"})
	if !ok {
		t.Fatal("fragmented http block name was not concatenated")
	}
	server, ok := uniqueNginxBlock(document, httpBlock, []string{"server"})
	if !ok {
		t.Fatal("fragmented server block name was not concatenated")
	}
	listeners := document.directNamed(server, "listen")
	if len(listeners) != 2 {
		t.Fatalf("listen directives = %d, want 2", len(listeners))
	}
	if listeners[0].nameQuoted || !listeners[0].fieldQuoted[0] || listeners[0].fields[0] != "listen" {
		t.Fatalf("fragmented listen name metadata = %#v", listeners[0])
	}
	if !listeners[1].nameQuoted {
		t.Fatal("fully quoted listen name lost its quoted-name marker")
	}
	sets := document.directNamed(server, "set")
	if len(sets) != 1 || len(sets[0].fields) != 3 || sets[0].fields[1] != "value" ||
		sets[0].fields[2] != "19090" || !sets[0].fieldQuoted[1] || !sets[0].fieldQuoted[2] {
		t.Fatalf("fragmented set fields = %#v", sets)
	}
	if _, valid := nginxListenPort(nginxDirective{
		fields: []string{"listen", sets[0].fields[2]}, fieldQuoted: []bool{false, sets[0].fieldQuoted[2]},
	}); valid {
		t.Fatal("quoted listen-value fragment was accepted as canonical")
	}
}

func TestParseNginxDirectivesRejectsResourceAmplification(t *testing.T) {
	buildTokens := func(count int) string {
		var content strings.Builder
		content.Grow(count * 2)
		for index := 0; index < count; index++ {
			content.WriteByte('x')
			if index%maxNginxFieldsPerDirective == maxNginxFieldsPerDirective-1 {
				content.WriteByte(';')
			} else {
				content.WriteByte(' ')
			}
		}
		if count%maxNginxFieldsPerDirective != 0 {
			content.WriteByte(';')
		}
		return content.String()
	}
	tests := []struct {
		name   string
		within string
		over   string
	}{
		{name: "directives", within: strings.Repeat("x;", maxNginxDirectives),
			over: strings.Repeat("x;", maxNginxDirectives+1)},
		{name: "tokens", within: buildTokens(maxNginxTokens), over: buildTokens(maxNginxTokens + 1)},
		{name: "fields", within: strings.Repeat("x ", maxNginxFieldsPerDirective) + ";",
			over: strings.Repeat("x ", maxNginxFieldsPerDirective+1) + ";"},
		{name: "token bytes", within: strings.Repeat("x", maxNginxTokenBytes) + ";",
			over: strings.Repeat("x", maxNginxTokenBytes+1) + ";"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseNginxDirectives(test.within); !ok {
				t.Fatal("input at exact boundary was rejected")
			}
			if _, ok := parseNginxDirectives(test.over); ok {
				t.Fatal("input above boundary was accepted")
			}
		})
	}
}

func TestParseNginxDirectivesHandlesLuaLongStringsAndComments(t *testing.T) {
	equals := strings.Repeat("=", 128)
	content := `http {
  init_by_lua_block {
    local value = [=[}]=]
    --[[ } ]]
	local high = [` + equals + `[ } ]===] { ]` + equals + `]
	--[` + equals + `[ } ]====] { ]` + equals + `]
    local nested = { enabled = true }
  }
  server { listen 18081; server_name example.test; }
}`
	document, ok := parseNginxDirectives(content)
	if !ok {
		t.Fatal("valid Lua long string/comment config was rejected")
	}
	httpBlock, ok := uniqueNginxBlock(document, 0, []string{"http"})
	if !ok {
		t.Fatal("http block was not indexed")
	}
	server, ok := uniqueNginxBlock(document, httpBlock, []string{"server"})
	if !ok || !hasDirectNginxDirectives(document, server,
		[]string{"listen", "18081"}, []string{"server_name", "example.test"}) {
		t.Fatal("directives after Lua block were not indexed")
	}
	for name, invalid := range map[string]string{
		"unclosed long string":  "http { init_by_lua_block { local value = [==[ } ]=] }",
		"unclosed long comment": "http { init_by_lua_block { --[==[ } ]=] }",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseNginxDirectives(invalid); ok {
				t.Fatal("unclosed Lua opaque input was accepted")
			}
		})
	}
}

func TestParseNginxDirectivesAppliesUnquotedBackslashEscapes(t *testing.T) {
	document, ok := parseNginxDirectives(`http {
	  server { listen 18081; set value\ with "tab\tvalue" "quote\"value" "slash\\value"; }
}`)
	if !ok {
		t.Fatal("escaped valid Nginx syntax was rejected")
	}
	httpBlock, ok := uniqueNginxBlock(document, 0, []string{"http"})
	if !ok {
		t.Fatal("http block was not indexed")
	}
	server, ok := uniqueNginxBlock(document, httpBlock, []string{"server"})
	if !ok || !hasDirectNginxDirectives(document, server,
		[]string{"listen", "18081"},
		[]string{"set", `value\ with`, "tab\tvalue", `quote"value`, `slash\value`}) {
		t.Fatal("Nginx escape semantics were not preserved exactly")
	}
}

func TestParseNginxDirectivesAppliesQuotedTokenSemantics(t *testing.T) {
	document, ok := parseNginxDirectives(`"http" {
  "server" {
    "listen" "18081";
    "server_name" "example.test";
    set "line\nvalue" "quote\"slash\\value";
  }
  "include" "/tmp/quoted.conf";
}`)
	if !ok || !document.hasInclude {
		t.Fatal("quoted Nginx tokens were not parsed")
	}
	httpBlock, ok := uniqueNginxBlock(document, 0, []string{"http"})
	if !ok {
		t.Fatal("quoted http block was not indexed semantically")
	}
	server, ok := uniqueNginxBlock(document, httpBlock, []string{"server"})
	if !ok || !hasDirectNginxDirectives(document, server,
		[]string{"listen", "18081"}, []string{"server_name", "example.test"},
		[]string{"set", "line\nvalue", "quote\"slash\\value"}) {
		t.Fatal("quoted/deescaped directive fields were not indexed semantically")
	}
}

func validCachePolicy(mode CacheMode) CachePolicy {
	return CachePolicy{
		Mode: mode, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20,
		DefaultTTL: 60 * time.Second,
	}
}

func TestCacheFreshnessIdentityWriterScannerUsesLuaSyntax(t *testing.T) {
	tests := map[string]struct {
		body string
		want bool
	}{
		"dot assignment":            {body: `ngx.var.cache_freshness_identity = "forged"`, want: true},
		"spaced dot assignment":     {body: `ngx . var . cache_freshness_identity = "forged"`, want: true},
		"bracket assignment":        {body: `ngx.var["cache_freshness_identity"] = "forged"`, want: true},
		"dot multi assignment":      {body: `local other; ngx.var.cache_freshness_identity, other = "forged", 1`, want: true},
		"bracket multi assignment":  {body: `local other; ngx.var["cache_freshness_identity"], other = "forged", 1`, want: true},
		"double bracket assignment": {body: `ngx["var"]["cache_freshness_identity"] = "forged"`, want: true},
		"spaced double bracket assignment": {
			body: `ngx [ 'var' ] [ "cache_freshness_identity" ] = "forged"`, want: true,
		},
		"escaped reserved bracket assignment": {
			body: `ngx["var"]["cache_freshness\095identity"] = "forged"`, want: true,
		},
		"long string LF elides first newline": {
			body: "ngx.var[ [=[\ncache_freshness_identity]=] ] = \"forged\"", want: true,
		},
		"long string CRLF elides first newline": {
			body: "ngx.var[ [==[\r\ncache_freshness_identity]==] ] = \"forged\"", want: true,
		},
		"long string CR elides first newline": {
			body: "ngx.var[ [[\rcache_freshness_identity]] ] = \"forged\"", want: true,
		},
		"wrapped var assignment": {
			body: `(ngx.var).cache_freshness_identity = "forged"`, want: true,
		},
		"parenthesized bracket assignment": {
			body: `ngx.var[("cache_freshness_identity")] = "forged"`, want: true,
		},
		"global root assignment": {
			body: `_G["ngx"].var.cache_freshness_identity = "forged"`, want: true,
		},
		"wrapped root assignment": {
			body: `(ngx).var.cache_freshness_identity = "forged"`, want: true,
		},
		"wrapped global assignment": {
			body: `(_G["ngx"]).var.cache_freshness_identity = "forged"`, want: true,
		},
		"global dot assignment": {
			body: `_G.ngx.var.cache_freshness_identity = "forged"`, want: true,
		},
		"constant concatenated key": {
			body: `ngx.var["cache_freshness_" .. "identity"] = "forged"`, want: true,
		},
		"nested constant concatenated key": {
			body: `((ngx).var)[(("cache_freshness_") .. ("identity"))] = "forged"`, want: true,
		},
		"mixed comments and spacing": {
			body: "(( _G -- root\n [ ( \"ngx\" ) ] )).var.cache_freshness_identity = \"forged\"", want: true,
		},
		"var alias assignment": {
			body: `local vars = ngx.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"root alias assignment": {
			body: `local root = ngx; root.var.cache_freshness_identity = "forged"`, want: true,
		},
		"multiple root and var aliases": {
			body: `local root, vars = ngx, ngx.var; root.var.cache_freshness_identity = "forged"; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"swapped root alias": {
			body: `local first, second = ngx, {}; second, first = first, second; second.var.cache_freshness_identity = "forged"`, want: true,
		},
		"table before var alias": {
			body: `local ignored, vars = {}, ngx.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"number before root alias": {
			body: `local ignored, root = 42, ngx; root.var.cache_freshness_identity = "forged"`, want: true,
		},
		"string before global alias": {
			body: `local ignored, global = "safe", _G; global.ngx.var.cache_freshness_identity = "forged"`, want: true,
		},
		"function call before var alias": {
			body: `local ignored, vars = make({}, 1), ngx.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"anonymous function before var alias": {
			body: `local ignored, vars = function() if true then return 1, 2 end return 3, 4 end, ngx.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"composite field lvalue before var alias": {
			body: `holder.field, vars = 0, ngx.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"composite bracket lvalue before root alias": {
			body: `holder[key], root = 0, ngx; root.var.cache_freshness_identity = "forged"`, want: true,
		},
		"mixed known and unknown tuple aliases": {
			body: `local ignored, global, root, vars = make(), _G, ngx, ngx.var; global.ngx.var.cache_freshness_identity = "forged"; root.var.cache_freshness_identity = "forged"; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"global alias dependency chain": {
			body: `local global = _G; local root = global.ngx; local vars = root.var; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"swapped global alias": {
			body: `local first, second = _G, {}; second, first = first, second; second.ngx.var.cache_freshness_identity = "forged"`, want: true,
		},
		"global alias dynamic key fails closed": {
			body: `local key = "ngx"; local global = _G; global[key].var.cache_freshness_identity = "forged"`, want: true,
		},
		"dynamic global alias construction fails closed": {
			body: `local key = "ngx"; local root = _G[key]; root.var.cache_freshness_identity = "forged"`, want: true,
		},
		"dynamic var alias construction fails closed": {
			body: `local key = "var"; local vars = ngx[key]; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"root alias chain with dynamic key fails closed": {
			body: `local key = "cache_freshness_identity"; local root = ngx; local next = root; next.var[key] = "forged"`, want: true,
		},
		"var alias after reassignment": {
			body: `local vars = ngx.var; vars = {}; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"alias chain dynamic key fails closed": {
			body: `local key = "cache_freshness_identity"; local first = ngx.var; local second = first; second[key] = "forged"`, want: true,
		},
		"dynamic direct key fails closed": {
			body: `local key = "cache_freshness_identity"; ngx.var[key] = "forged"`, want: true,
		},
		"opaque var alias fallback fails closed": {
			body: `local vars = ngx.var or {}; vars.cache_freshness_identity = "forged"`, want: true,
		},
		"call mediated direct var root fails closed": {
			body: `put(ngx.var, "cache_freshness_identity", "forged")`, want: true,
		},
		"call mediated alias root fails closed": {
			body: `local vars = ngx.var; put(vars, "cache_freshness_identity", "forged")`, want: true,
		},
		"newline call mediated root fails closed": {
			body: "put\n(ngx.var, \"cache_freshness_identity\", \"forged\")", want: true,
		},
		"parenthesized callable root fails closed": {
			body: "(put)\n(ngx.var, \"cache_freshness_identity\", \"forged\")", want: true,
		},
		"IIFE var projection fails closed": {
			body: `local vars = (function() return ngx.var end)(); vars.cache_freshness_identity = "forged"`, want: true,
		},
		"multi return var projection fails closed": {
			body: `local ignored, vars = project(nil, ngx.var); vars.cache_freshness_identity = "forged"`, want: true,
		},
		"getfenv protected environment fails closed": {
			body: `getfenv(0)["ngx"]["var"]["cache_freshness_identity"] = "forged"`, want: true,
		},
		"getfenv alias protected environment fails closed": {
			body: `local env = getfenv(0); env.ngx.var.cache_freshness_identity = "forged"`, want: true,
		},
		"loadstring protected writer fails closed": {
			body: `loadstring('ngx.var.cache_freshness_identity = "forged"')()`, want: true,
		},
		"global loadstring protected writer fails closed": {
			body: `_G["loadstring"]('ngx.var.cache_freshness_identity = "forged"')()`, want: true,
		},
		"wrapped unrelated field": {
			body: `(ngx).var.cache_freshness_other = "safe"`, want: false,
		},
		"parenthesized var unrelated field": {
			body: `(ngx.var).cache_freshness_other = "safe"`, want: false,
		},
		"parenthesized var protected field": {
			body: `(ngx.var).cache_freshness_identity = "forged"`, want: true,
		},
		"alias unrelated field": {
			body: `local vars = ngx.var; vars.cache_freshness_other = "safe"`, want: false,
		},
		"root alias unrelated field": {
			body: `local root = ngx; root.var.cache_freshness_other = "safe"`, want: false,
		},
		"mixed tuple aliases unrelated fields": {
			body: `local ignored, global, root, vars = {}, _G, ngx, ngx.var; global.ngx.var.cache_freshness_other = "safe"; root.var.cache_freshness_other = "safe"; vars.cache_freshness_other = "safe"`, want: false,
		},
		"computed global aliases fail closed": {
			body: `local key = "unknown"; local root, vars = _G[key], ngx[key]; root.var.cache_freshness_other = "safe"; vars.cache_freshness_other = "safe"`, want: true,
		},
		"constant unrelated key": {
			body: `ngx.var["cache_freshness_" .. "other"] = "safe"`, want: false,
		},
		"unrelated field fallback": {
			body: `local value = ngx.var.cache_freshness_other or ""`, want: false,
		},
		"call mediated unrelated value": {
			body: `consume(ngx.var.cache_freshness_other)`, want: false,
		},
		"long string internal newline remains unrelated": {
			body: "ngx.var[ [=[cache_freshness_\nidentity]=] ] = \"safe\"", want: false,
		},
		"dynamic primitive string decoy": {
			body: `local value = "getfenv(0) loadstring"`, want: false,
		},
		"dynamic primitive static field decoy": {
			body: `local value = metadata.getfenv`, want: false,
		},
		"IIFE assignment": {
			body: `(function() ngx.var.cache_freshness_identity = "forged" end)()`, want: true,
		},
		"table function assignment": {
			body: `local writers = {function() ngx.var.cache_freshness_identity = "forged" end}; writers[1]()`, want: true,
		},
		"quoted decoy":       {body: `local value = 'ngx.var.cache_freshness_identity = "forged"'`, want: false},
		"line comment decoy": {body: "-- ngx.var.cache_freshness_identity = \"forged\"\nreturn", want: false},
		"long string decoy":  {body: `local value = [=[ngx.var.cache_freshness_identity = "forged"]=]`, want: false},
		"long comment decoy": {body: `--[=[ngx.var.cache_freshness_identity = "forged"]=]`, want: false},
		"unrelated escaped bracket decoy": {
			body: `ngx.var["cache_freshness\095other"] = "safe"`, want: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			document, ok := parseNginxDirectives("http { access_by_lua_block {\n" + test.body + "\n} }")
			if !ok {
				t.Fatal("test fixture is not valid Nginx/Lua structure")
			}
			if got := hasUnexpectedCacheFreshnessIdentityWrite(document); got != test.want {
				t.Fatalf("unexpected writer = %t, want %t", got, test.want)
			}
		})
	}
}

func TestCacheFreshnessIdentityReferenceTracksTupleAndGlobalAliases(t *testing.T) {
	for name, test := range map[string]struct {
		body string
		want bool
	}{
		"var after unknown tuple value": {
			body: `local ignored, vars = {}, ngx.var; local value = vars.cache_freshness_identity`, want: true,
		},
		"global alias chain": {
			body: `local global = _G; local root = global.ngx; local value = root.var.cache_freshness_identity`, want: true,
		},
		"mixed tuple alias": {
			body: `local ignored, global, root, vars = make(), _G, ngx, ngx.var; local value = global.ngx.var.cache_freshness_identity`, want: true,
		},
		"alias after anonymous function": {
			body: `local ignored, vars = function() return 1, 2 end, ngx.var; local value = vars.cache_freshness_identity`, want: true,
		},
		"alias after composite lvalue": {
			body: `holder.field, vars = 0, ngx.var; local value = vars.cache_freshness_identity`, want: true,
		},
		"dynamic global alias construction": {
			body: `local key = "ngx"; local root = _G[key]; local value = root.var.cache_freshness_identity`, want: true,
		},
		"dynamic var alias construction": {
			body: `local key = "var"; local vars = ngx[key]; local value = vars.cache_freshness_identity`, want: true,
		},
		"opaque var alias fallback": {
			body: `local vars = ngx.var or {}; local value = vars.cache_freshness_identity`, want: true,
		},
		"call mediated var root": {
			body: `consume(ngx.var)`, want: true,
		},
		"newline call mediated var root": {
			body: "consume\n(ngx.var)", want: true,
		},
		"IIFE var projection": {
			body: `local vars = (function() return ngx.var end)(); local value = vars.cache_freshness_identity`, want: true,
		},
		"getfenv protected environment": {
			body: `local value = getfenv(0)["ngx"]["var"]["cache_freshness_identity"]`, want: true,
		},
		"loadstring protected reference": {
			body: `loadstring("return ngx.var.cache_freshness_identity")()`, want: true,
		},
		"unrelated aliased field": {
			body: `local ignored, vars = {}, ngx.var; local value = vars.cache_freshness_other`, want: false,
		},
		"wrapped unrelated field": {
			body: `(ngx).var.cache_freshness_other = "safe"`, want: false,
		},
		"parenthesized var unrelated field": {
			body: `local value = (ngx.var).cache_freshness_other`, want: false,
		},
		"long string first newline unrelated field": {
			body: "local value = ngx.var[ [=[\ncache_freshness_other]=] ]", want: false,
		},
		"computed global alias field fails closed": {
			body: `local key = "unknown"; local root = _G[key]; local value = root.var.cache_freshness_other`, want: true,
		},
		"quoted alias decoy": {
			body: `local value = "local ignored, vars = {}, ngx.var; vars.cache_freshness_identity"`, want: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := cacheFreshnessLuaIdentityReference(test.body); got != test.want {
				t.Fatalf("identity reference = %t, want %t", got, test.want)
			}
		})
	}
}

func TestCacheFreshnessLuaScannerComplexityPolicy(t *testing.T) {
	const (
		maxWork    = 131_072
		maxNesting = 32
	)
	withinWork := strings.Repeat("safe ", maxWork)
	for name, scan := range map[string]func(string) bool{
		"writer":    cacheFreshnessLuaIdentityAssignment,
		"reference": cacheFreshnessLuaIdentityReference,
	} {
		t.Run(name, func(t *testing.T) {
			if scan(withinWork) {
				t.Fatal("exact work boundary was rejected")
			}
			if !scan(withinWork + "safe ") {
				t.Fatal("work overage was accepted")
			}
			withinDepth := strings.Repeat("(", maxNesting) +
				"ngx.var.cache_freshness_other" + strings.Repeat(")", maxNesting)
			if scan(withinDepth) {
				t.Fatal("exact nesting boundary was rejected")
			}
			overDepth := "(" + withinDepth + ")"
			if !scan(overDepth) {
				t.Fatal("nesting overage was accepted")
			}
			manyAssignments := "local values = {" + strings.Repeat("safe=1,", 256) + "}"
			if !scan(manyAssignments) {
				t.Fatal("quadratic assignment table was accepted")
			}
		})
	}
}

func TestCacheFreshnessLuaDirectAccessComplexityPolicy(t *testing.T) {
	withinWork := strings.Repeat("safe ", 131_072)
	if count, valid := cacheFreshnessLuaDirectAccessCount(withinWork); !valid || count != 0 {
		t.Fatalf("exact direct-access work boundary = (%d, %t)", count, valid)
	}
	if count, valid := cacheFreshnessLuaDirectAccessCount(withinWork + "safe "); valid || count != 0 {
		t.Fatalf("direct-access work overage = (%d, %t)", count, valid)
	}
}

func TestCacheFreshnessLuaDynamicExecutionPrimitivesFailClosed(t *testing.T) {
	for name, body := range map[string]string{
		"getfenv":                    `getfenv(0)`,
		"setfenv":                    `setfenv(0, {})`,
		"load":                       `load("return 1")`,
		"loadstring":                 `loadstring("return 1")`,
		"loadfile":                   `loadfile("fixture.lua")`,
		"dofile":                     `dofile("fixture.lua")`,
		"global alias":               `local global = _G; global["loadstring"]("return 1")`,
		"parenthesized global":       `(_G).loadstring("return 1")()`,
		"parenthesized global alias": `local global = _G; (global).load("return 1")`,
		"debug getfenv":              `debug.getfenv(0)`,
		"debug setfenv":              `debug.setfenv(0, {})`,
		"global debug getfenv":       `_G.debug.getfenv(0)`,
		"nested global load":         `_G._G.load("return 1")`,
		"parenthesized global debug": `((_G).debug).setfenv(0, {})`,
		"debug alias getfenv": `local d = debug; local env = d.getfenv(0); ` +
			`env.ngx.var.cache_freshness_identity = "forged"`,
		"global debug alias getfenv": `local global = _G; local d = global.debug; ` +
			`local env = d.getfenv(0); env.ngx.var.cache_freshness_identity = "forged"`,
		"nested global alias loadstring":    `local global = _G._G; global.loadstring("return 1")()`,
		"computed global loadstring":        `local key = "loadstring"; _G[key]("return 1")()`,
		"computed wrapped global load":      `local key = "load"; ((_G))[key]("return 1")()`,
		"computed global alias loadfile":    `local global = _G; local key = "loadfile"; global[key]("fixture.lua")`,
		"computed debug alias getfenv":      `local d = debug; local key = "getfenv"; d[key](0)`,
		"nested package global loadstring":  `_G.package.loaded._G.loadstring("return 1")()`,
		"package global loadstring":         `package.loaded._G.loadstring("return 1")()`,
		"package debug getfenv":             `package.loaded.debug.getfenv(0)`,
		"package alias global loadstring":   `local p = package; p.loaded._G.loadstring("return 1")()`,
		"loaded alias global loadstring":    `local loaded = package.loaded; loaded._G.loadstring("return 1")()`,
		"debug registry loadstring":         `debug.getregistry()._LOADED._G.loadstring("return 1")()`,
		"debug call projection":             `local d = debug; consume(d)`,
		"debug table projection":            `local d = debug; local projected = {d}`,
		"bracket package global loadstring": `package["loaded"]["_G"]["loadstring"]("return 1")()`,
		"bracket package debug getfenv":     `package["loaded"]["debug"]["getfenv"](0)`,
		"computed package registry":         `local key = "_G"; package["loaded"][key]["loadstring"]("return 1")()`,
		"bracket registry loadstring":       `debug["getregistry"]()["_LOADED"]["_G"]["loadstring"]("return 1")()`,
		"package registry alias":            `local loaded = package["loaded"]; loaded["_G"]["loadstring"]("return 1")()`,
		"unknown global projection":         `local value = _G["ordinary"]["nested"]`,
		"unknown debug projection":          `local value = debug["ordinary"]["nested"]`,
		"transitive debug call projection":  `local d = debug; local d2 = d; consume(d2)`,
		"transitive debug table projection": `local d = debug; local d2 = d; local projected = {d2}`,
		"opaque global member":              `local value = _G["ordinary"]; local nested = value["member"]`,
		"opaque global call":                `local value = _G["ordinary"]; value()`,
		"opaque debug member":               `local value = debug["ordinary"]; local nested = value["member"]`,
		"opaque debug call":                 `local value = debug["ordinary"]; value()`,
		"opaque package member":             `local value = package["ordinary"]; local nested = value["member"]`,
		"opaque package call":               `local value = package["ordinary"]; value()`,
		"opaque loaded global member":       `local value = package["loaded"]["_G"]["ordinary"]; value["member"]`,
		"opaque registry global member":     `local value = debug["getregistry"]()["_G"]["ordinary"]; value["member"]`,
		"opaque call argument":              `local value = _G["ordinary"]; consume(value)`,
		"opaque projected return":           `local value = _G["ordinary"]; local projected = project(value); projected()`,
		"opaque unkeyed table":              `local value = _G["ordinary"]; local values = {value}; values[1]()`,
		"opaque keyed table":                `local value = _G["ordinary"]; local values = {member = value}; values.member()`,
		"opaque transitive alias":           `local value = _G["ordinary"]; local second = value; local third = second; third()`,
	} {
		t.Run(name, func(t *testing.T) {
			if !cacheFreshnessLuaIdentityAssignment(body) {
				t.Fatal("identity writer scanner accepted dynamic execution")
			}
			if !cacheFreshnessLuaIdentityReference(body) {
				t.Fatal("identity reference scanner accepted dynamic execution")
			}
		})
	}
	for name, body := range map[string]string{
		"quoted names":                 `local value = "getfenv setfenv load loadstring loadfile dofile"`,
		"static fields":                `local a = metadata.getfenv; local b = metadata.loadstring`,
		"static global ordinary field": `local value = _G["ordinary"]`,
		"static debug ordinary field":  `local value = debug["ordinary"]`,
		"static table fields": `local metadata = { getfenv = "documentation", setfenv = "documentation", ` +
			`load = "documentation", loadstring = "documentation", loadfile = "documentation", dofile = "documentation" }`,
	} {
		t.Run(name, func(t *testing.T) {
			if cacheFreshnessLuaIdentityAssignment(body) {
				t.Fatal("identity writer scanner rejected a dynamic-execution decoy")
			}
			if cacheFreshnessLuaIdentityReference(body) {
				t.Fatal("identity reference scanner rejected a dynamic-execution decoy")
			}
		})
	}
}
