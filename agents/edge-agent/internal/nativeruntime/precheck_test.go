package nativeruntime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStripForInitLoad(t *testing.T) {
	conf := `user nobody nogroup;
pid /srv/shared/nginx.pid; # live pid
error_log /srv/shared/error.log notice;
daemon on;
events { worker_connections 64; }
http {
  error_log /srv/shared/http.log;
  lua_package_path "/lua/?.lua;;";
  lua_shared_dict index 10m;
  init_by_lua_block {
    -- a } in a comment
    local s = "}" .. '{' .. [[ } ]] .. [==[ }} ]==]
    --[[ } long comment ]]
    cdnca = require("cdnca").configure({ a = { b = 1 } })
  }
  init_worker_by_lua_block { require("cdnca").init_worker() }
  upstream origin { server 127.0.0.1:9000; keepalive 4; }
  map $host $site { default "x{y}"; "a.example" "${host}"; }
  server {
    listen 0.0.0.0:443 ssl;
    location / { content_by_lua_block { ngx.say("}") } }
  }
  server { listen 80; }
}
stream { server { listen 7000; proxy_pass origin; } }
`
	got, err := stripForInitLoad([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, gone := range []string{"listen", "init_worker_by_lua", "/srv/shared/nginx.pid", "/srv/shared/error.log", "daemon", "content_by_lua"} {
		if strings.Contains(text, gone) {
			t.Errorf("%q left in:\n%s", gone, text)
		}
	}
	for _, kept := range []string{"user nobody nogroup;", "events { worker_connections 64; }", "error_log /srv/shared/http.log;",
		`lua_package_path "/lua/?.lua;;";`, "lua_shared_dict index 10m;", `require("cdnca").configure({ a = { b = 1 } })`,
		"[==[ }} ]==]", "upstream origin { server 127.0.0.1:9000; keepalive 4; }", `"a.example" "${host}";`, "stream {"} {
		if !strings.Contains(text, kept) {
			t.Errorf("%q missing from:\n%s", kept, text)
		}
	}
	// The result parses again and has nothing left to strip.
	if again, err := stripForInitLoad(got); err != nil || string(again) != text {
		t.Errorf("stripping again: %v\n%s", err, again)
	}
}

// A bare ${var} argument (the live dynamic routing map lines) ends at the
// next space or ;, like nginx: its } neither ends the word nor the block.
// This conf made stripForInitLoad loop forever.
func TestStripForInitLoadVariableBraces(t *testing.T) {
	conf := `http {
  map $upstream_connect_time $cdnca_origin_connect_ms {
    ~^0\.00(?<cdnca_origin_connect_1>[1-9])$ ${cdnca_origin_connect_1}000;
    "~^(?<s>[1-9][0-9]{0,5})\.(?<f>[0-9]{3})$" ${s}${f}000;
    default -;
  }
  server { set $x ${host}y; listen 80; }
}
`
	done := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = stripForInitLoad([]byte(conf))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stripForInitLoad did not return in 5s")
	}
	text := string(got)
	for _, kept := range []string{"${cdnca_origin_connect_1}000;", "${s}${f}000;", "default -;"} {
		if !strings.Contains(text, kept) {
			t.Errorf("%q missing from:\n%s", kept, text)
		}
	}
	if strings.Contains(text, "listen") {
		t.Errorf("server{} left in:\n%s", text)
	}
}

// A variable only a server{} defines (set, set_by_lua*, auth_request_set,
// a named regex capture) that the http block itself still uses (a map, a
// log_format) stays declared once the servers are gone (the init load used to fail
// with `unknown "cdnca_security_block_page" variable`).
func TestStripForInitLoadKeepsVariablesOfDroppedServers(t *testing.T) {
	conf := `http {
  map $cdnca_security_block_page $cdnca_security_block_page_log { "1" true; default false; }
  log_format j '$cdnca_site_id ${cdnca_cap}x $cdnca_lua';
  server {
    listen 80;
    set $cdnca_security_block_page "";
    set $cdnca_site_id 1;
    set $cdnca_unused 1;
    set_by_lua_block $cdnca_lua { return "1" }
    location ~ ^/(?<cdnca_cap>[a-z]+)$ { return 200; }
  }
}
stream { server { listen 7000; set $cdnca_stream 1; } }
`
	got, err := stripForInitLoad([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, name := range []string{"cdnca_security_block_page", "cdnca_site_id", "cdnca_cap", "cdnca_lua"} {
		if !strings.Contains(text, "map $pid $"+name+` { default ""; }`) {
			t.Errorf("$%s not declared in:\n%s", name, text)
		}
	}
	for _, name := range []string{"cdnca_unused", "cdnca_stream", "cdnca_security_block_page_log"} {
		if strings.Contains(text, "$pid $"+name+" ") {
			t.Errorf("$%s declared although nothing kept uses it (or a kept map defines it):\n%s", name, text)
		}
	}
	if strings.Contains(text, "listen") {
		t.Errorf("server{} left in:\n%s", text)
	}
	if again, err := stripForInitLoad(got); err != nil || string(again) != text {
		t.Errorf("stripping again: %v\n%s", err, again)
	}
}

func TestStripForInitLoadRefusesBrokenConf(t *testing.T) {
	for _, conf := range []string{"http {", "http { } }", "http { init_by_lua_block { x = 1 }", `http { a "b; }`, "worker_processes 1",
		"http { a b }", "http { a ${b} }"} {
		if _, err := stripForInitLoad([]byte(conf)); err == nil {
			t.Errorf("%q: no error", conf)
		}
	}
}

// TestPrecheckOpenRestyReal needs a real OpenResty (the native payload's, in
// a disposable container): CDNCA_NATIVE_PRECHECK_OPENRESTY=<binary>.
func TestPrecheckOpenRestyReal(t *testing.T) {
	binary := os.Getenv("CDNCA_NATIVE_PRECHECK_OPENRESTY")
	if binary == "" {
		t.Skip("CDNCA_NATIVE_PRECHECK_OPENRESTY: a real OpenResty binary")
	}
	// The live master holds this port: the precheck must never bind it.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := held.Addr().(*net.TCPAddr).Port
	// Every case's server{} sets $cdnca_page that an http-level map uses
	// (the dynamic routing conf's shape); "undefined" uses one nothing
	// defines, which a real nginx refuses.
	for _, test := range []struct {
		name, module, http, want string
	}{
		{"good", `return { marker = "ok" }`, "", ""},
		{"syntax", `return { marker = `, "", "unexpected symbol"},
		{"error", `error("cdnca precheck boom")`, "", "cdnca precheck boom"},
		{"missing", "", "", "module 'cdnca_precheck_probe' not found"},
		{"undefined", `return { marker = "ok" }`, "map $cdnca_undefined $cdnca_undefined_log { default 0; }", `unknown "cdnca_undefined" variable`},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := t.TempDir()
			lua := filepath.Join(prefix, "lua")
			if err := os.MkdirAll(filepath.Join(prefix, "logs"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(lua, 0o755); err != nil {
				t.Fatal(err)
			}
			if test.module != "" {
				if err := os.WriteFile(filepath.Join(lua, "cdnca_precheck_probe.lua"), []byte(test.module+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			conf := filepath.Join(prefix, "nginx.conf")
			if err := os.WriteFile(conf, []byte(fmt.Sprintf(`user nobody nogroup;
pid %[1]s/nginx.pid;
error_log %[1]s/error.log notice;
events { worker_connections 64; }
http {
  lua_package_path '%[2]s/?.lua;;';
  lua_shared_dict state 1m;
  init_by_lua_block { probe = require("cdnca_precheck_probe") }
  init_worker_by_lua_block { ngx.log(ngx.ERR, "worker started") }
  map $cdnca_page $cdnca_page_log { "1" true; default false; }
  log_format j '$cdnca_page_log';
  %[4]s
  server { listen 127.0.0.1:%[3]d; set $cdnca_page ""; location / { return 200; } }
}
`, prefix, lua, port, test.http)), 0o644); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err := PrecheckOpenResty(context.Background(), binary, prefix+"/", conf, "")
			elapsed := time.Since(start)
			t.Logf("%s: %s: %v", test.name, elapsed, err)
			if elapsed > 5*time.Second {
				t.Errorf("precheck took %s", elapsed)
			}
			if test.want == "" && err != nil {
				t.Fatalf("good Lua refused: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error %v, want it to name %q", err, test.want)
			}
			// `-t` creates the configured pid file empty when it is missing
			// (it never writes into it); the load must not write a pid there.
			if live, _ := os.ReadFile(filepath.Join(prefix, "nginx.pid")); len(live) != 0 {
				t.Fatalf("the precheck wrote the live pid file: %q", live)
			}
		})
	}
}
