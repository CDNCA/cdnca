package main

// nginxConf: the dynroute contract §6 shared-server shape, two ports, one
// worker (per-worker caches and samples are then the node's). Every
// cdnca_security phase call is timed with CLOCK_MONOTONIC and summed per
// request in ngx.ctx; the log phase files the sum; /__stats reports and
// resets (port __PLAIN__+1).
const nginxConf = `worker_processes 1;
error_log logs/error.log notice;
pid logs/nginx.pid;
events { worker_connections 4096; }
http {
  access_log off;
  server_tokens off;
  uninitialized_variable_warn off;
  lua_package_path "__LUA__/dynroute/?.lua;__LUA__/?.lua;__LUA__/security/?.lua;;";
  lua_shared_dict cdnca_site_index 16m;
  lua_shared_dict cdnca_site_state 8m;
  lua_shared_dict cdnca_site_lock 1m;
  lua_shared_dict cdnca_cc_state 64m;
  lua_shared_dict cdnca_challenge_state 16m;
  lua_shared_dict cdnca_firewall_action 16m;
  init_by_lua_block {
    require("cdnca_site").configure({ objects_root = "__STATE__/site-objects", index_root = "__STATE__/site-index",
      system_max_body = 1048576, lru_items = 2 * __N__ + 100 })
    require("cdnca_security").configure({ cache_items = __N__ + 100 })
    local ffi = require "ffi"
    ffi.cdef[[typedef struct { long tv_sec; long tv_nsec; } d7_ts; int clock_gettime(int, d7_ts *);]]
    local ts = ffi.new("d7_ts")
    function d7_now() ffi.C.clock_gettime(1, ts); return tonumber(ts.tv_sec) * 1e6 + tonumber(ts.tv_nsec) / 1e3 end
    d7_samples = { total = {}, server_rewrite = {}, rewrite = {}, access = {}, header_filter = {}, log = {} }
    function d7_timed(phase, site)
      local t0 = d7_now()
      local result = require("cdnca_security")[phase](site)
      local spent = d7_now() - t0
      local ctx = ngx.ctx
      ctx.d7_us = (ctx.d7_us or 0) + spent
      ctx["d7_" .. phase] = (ctx["d7_" .. phase] or 0) + spent
      return result
    end
  }
  init_worker_by_lua_block { require("cdnca_site").init_worker() }
  server {
    listen 127.0.0.1:__SECURE__;
    listen 127.0.0.1:__PLAIN__;
    server_name _;
    server_rewrite_by_lua_block {
      local site = require("cdnca_site").route()
      if not site then return require("cdnca_site").reject_unknown() end
      return d7_timed("server_rewrite", site)
    }
    location / {
      client_max_body_size $cdnca_site_max_body;
      rewrite_by_lua_block { local site = require("cdnca_site").current() if site then return d7_timed("rewrite", site) end }
      access_by_lua_block { local site = require("cdnca_site").current() if site then return d7_timed("access", site) end }
      header_filter_by_lua_block { local site = require("cdnca_site").current() if site then d7_timed("header_filter", site) end }
      log_by_lua_block {
        local site = require("cdnca_site").current()
        if site then d7_timed("log", site) end
        if ngx.var.server_port == "__SECURE__" and ngx.status == 200 then
          local ctx = ngx.ctx
          for name, list in pairs(d7_samples) do
            list[#list + 1] = (name == "total" and ctx.d7_us or ctx["d7_" .. name]) or 0
          end
        end
      }
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header Connection "";
      proxy_pass http://127.0.0.1:__ORIGIN__;
    }
  }
  server {
    listen 127.0.0.1:18182;
    location = /__stats {
      content_by_lua_block {
        local all = d7_samples
        d7_samples = { total = {}, server_rewrite = {}, rewrite = {}, access = {}, header_filter = {}, log = {} }
        local out = {}
        for name, samples in pairs(all) do
          table.sort(samples)
          local n, sum = #samples, 0
          for _, value in ipairs(samples) do sum = sum + value end
          local function p(q) return n == 0 and 0 or samples[math.max(1, math.ceil(n * q))] end
          out[name] = string.format("p50 %.1f p90 %.1f p99 %.1f mean %.1f", p(0.5), p(0.9), p(0.99), n == 0 and 0 or sum / n)
          out.n = n
        end
        local order = { "total", "server_rewrite", "rewrite", "access", "header_filter", "log" }
        local line = { "n=" .. out.n }
        for _, name in ipairs(order) do line[#line + 1] = name .. "[" .. out[name] .. "]" end
        ngx.say(table.concat(line, " "))
      }
    }
  }
  server {
    listen unix:__STATE__/run/cdnca-site-admin.sock;
    client_max_body_size 4m;
    client_body_buffer_size 4m;
    location / { content_by_lua_block { require("cdnca_site_admin").handle() } }
    location = /__vars {
      internal;
      set $cdnca_site_id ""; set $cdnca_site_revision ""; set $cdnca_site_digest ""; set $cdnca_site_tenant "";
      set $cdnca_site_scope ""; set $cdnca_site_host ""; set $cdnca_site_port ""; set $cdnca_site_generation "";
      set $cdnca_site_state ""; set $cdnca_site_max_body "1";
      set $cdnca_security_emit ""; set $cdnca_security_type ""; set $cdnca_security_action "";
      set $cdnca_security_severity ""; set $cdnca_security_rule_id ""; set $cdnca_security_block_page "";
    }
  }
}
`
