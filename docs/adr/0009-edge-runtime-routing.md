# ADR 0009：边缘运行时按 Host/SNI 动态路由（取代每站 server{}）

- 状态：§9 已拍板（G8-c 选方案 B；HTTP/2 按端口、缓存容量软配额、上传上限加 nginx 小补丁、托管 WAF 档位 + 站点级排除）。§8.3 站点对象格式已定稿（site_runtime v8，实现 `libs/edgeconfig/siteobject`）；其余各节仍是架构与预留。
- 1.0.35 现状：动态路由（site_runtime 9）为节点唯一模式，1.0.35 为初始基线。site_runtime 7/8、站点对象 v1 根/桶/站点格式、每站 `server{}` 编译器（`siteruntimev2`）、单 scope 与 `multi_tenant_runtime` 部署路径**已于 1.0.35 删除**；下文描述它们的段落是历史决策，保留原文。
- 日期：2026-10-17
- 依据版本：7f80a5a8；OpenResty 1.31.1.1（nginx 1.31.1、ngx_lua 0.10.31rc5、lua-resty-core 0.1.34rc3，取自 `~/.cache/cdnca-release-inputs/tools/openresty-1.31.1.1.tar.gz`，与 `edge/openresty/security-release/runtime-lock.json` 一致）。
- 相关：ADR 0007/0008（插件化与规则包，plugin-arch 撰写中，本文只定挂载接口）；`docs/architecture/million-sites-benchmark.md`（G8-a 数据）；`docs/architecture/site-runtime-cert-lazy-load.md`（G8-b PoC）。
- 标注约定：文中“未核实”= 没有在本仓库代码或上述源码里找到依据，也没有实测。

## 1. 决策

1. 目标架构：节点 nginx.conf 只剩**节点级静态骨架**（端口、共享 server、一个动态 upstream、缓存 zone 池、共享字典、节点级 location、stream{}）。站点是数据：签名的站点对象写进节点对象库，Lua 按（公网端口，Host/SNI）在共享字典查站点，`balancer_by_lua` 选源。站点增删改、证书、规则包内容、源站、套餐限额变化**不 reload**。
2. 不再走“每站 server{} 的增量优化”路线。G8-c **收窄改向**（推荐，§7）：取消节点侧分片编译/分片命名/分片 server 拼接；保留并改造下发层为“站点对象 + 分桶清单 + 单签名根”，1.0.35 落地，1.0.36 动态路由原样复用。
3. 现在定死的预留（§8）：site_runtime 能力版本规划、节点对象库与共享字典格式（不引入 LMDB）、站点对象/分桶/根清单格式、规则包按站点挂载接口。

## 2. 现状：站点被编译进 nginx 指令

（本节是 ADR 撰写时的现状；`siteruntimev2` 已于 1.0.35 删除。）每站点每监听一个 `server{}`（`agents/edge-agent/internal/siteruntimev2/compiler.go:562-681`），每源站池一个 `upstream{}`（`compiler.go:477-526`），全部写进一份 nginx.conf。多 scope 时任何一个 scope 变化，`ComposedRuntime.compose` 都对**所有** scope 重新验签、准备派生 release、整份重编（`composed_runtime.go:174-260`），再整份 `nginx -t`（`deployment/openresty.go:56-60`）+ `-s reload`（`openresty.go:107`，原生 `openresty_native.go:87`）。G8-a 实测：每个 server 约 78 KiB，`nginx -t` CPU ≈ n^2.2（5000 站 64 s），reload 峰值约 3×（million-sites-benchmark.md §5.1–5.2）。

已经是数据驱动、可以原样平移的：

- HTTP 策略：`committed.json` + 不可变版本文件，worker 每 1 s 检查、失败保留 LKG（`edge/openresty/httppolicy/engine.lua:450-500`），按 `site_id` 取站点（`:889-894`）。
- 防火墙动作按站点 artifact 路径（`compiler.go:907-909`）；回源鉴权按 `rule_id`、`reload_interval`（`edge/openresty/originauth/engine.lua:642-661`）；错误页处理器按 `site_id` + 策略路径（`compiler.go:710-715`）。
- CC v2 引擎按条目读 `compiled_path` 并支持重载（`edge/openresty/ccv2/engine.lua:596-607,1650-1660`）。
- 动态回源引擎已存在：`edge/openresty/originroute/engine.lua`（4214 行）用 `ngx.balancer` 的 `set_current_peer`/`bind_to_local_addr`/`set_timeouts`/`set_more_tries`/`get_last_failure`/`recreate_request`（`:3302-3414`），支持 round_robin/ip_hash/url_hash/least_conn/random（`:32-35`）、DNS 刷新、路由匹配（`:1163`）。**它目前只被 `originbench` 基准 harness 使用**（`agents/edge-agent/internal/originbench/harness.go:86` 是 `originroute.Compile` 唯一的非测试调用方），生产站点走静态 `upstream{}`。

仍然绑死在 nginx 指令里、必须改的：

- CC v2 注册表整段 JSON 内联进 `init_by_lua_block`（`libs/edgeconfig/security_fragments.go:128-129`），每个 server 一个 `server_rewrite_by_lua_block { return require("cc").access(<entry_id>) }`（`:149`）；校验器要求（server_name, listen）与注册表条目一一对应（`cc_v2.go:540-627`，键 `ccV2ListenerKey` 在 `:629`）。
- ACL/WAF 自研规则在编译期生成内联 Lua（`config.go:1841-1960`）+ http 级 `geo` 变量（`security_fragments.go:135-140`）。
- JS 挑战每站点一个 Lua 模块实例（`listener_runtime_security.go:208-214`）；托管 WAF（CRS）每站点 `include` 一个 `modsecurity on; modsecurity_rules_file security/<site>/modsecurity.conf`（`waf_engine.go:228-231`，`listener_runtime_security.go:187`）。
- 缓存每站点一个 `proxy_cache_path … keys_zone`（`site_runtime_cache.go:161`）；套餐连接数每订阅一个 `limit_conn_zone`（`package_limits.go:42,58`）。
- 条件回源用 http 级 `map`/`geo` + `error_page 3xx = @route`（`compiler.go:627-635,803-857`）；L2 直连回退与自定义错误页用 location 级 `proxy_intercept_errors` + `error_page`（`:637-643,686-706`）。
- v7 懒加载证书是 http 级 `map $ssl_server_name` + 变量证书（`lazy_certificates.go`），证书版本变化仍要新 release + reload（million-sites-benchmark.md §8.2）。

## 3. 目标架构

### 3.1 节点级静态骨架（变化才 reload）

| 骨架项 | 何时 reload |
|---|---|
| 端口集合：每个（端口, 地址族, TLS/明文）一个共享 `server{}`；有 HTTP/3 的端口加 `listen … quic` | 端口集合变化 |
| 一个动态 `upstream cdnca_dynamic { server 0.0.0.1; balancer_by_lua_block {…} }` | 不变 |
| 缓存 zone 池（固定 N 个 `proxy_cache_path`，§4 缓存行） | 池的个数/尺寸变化 |
| 共享字典（站点索引、代指针、CC 状态、限额计数等），尺寸由节点规模档位决定 | 尺寸档位变化 |
| 托管 WAF 节点级规则包（`modsecurity_rules_file`，§9 问题 3） | 规则包版本变化 |
| 系统配置（`SiteRuntimeSystem*`）、节点级 location（健康、状态、预热、ACME overlay、市场探测） | 对应配置变化 |
| `stream{}`（四层与 mux 分发，`compose_mux.go`） | 四层监听变化（端口即身份，不在本 ADR 内动态化） |
| OpenResty / Lua 模块升级 | 升级 |

### 3.2 请求流水线（顺序固定，与 v7 现有阶段一致）

1. `ssl_client_hello_by_lua`：按 SNI 查站点，未命中拒绝握手；按站点设协议（`ngx.ssl.clienthello.set_protocols`，§4）。
2. `ssl_certificate_by_lua`：按站点证书版本取证书，worker 内 LRU 缓存解析结果（`ngx.ssl.parse_pem_*` / `set_cert` / `set_priv_key`）。
3. `server_rewrite_by_lua`：按（公网端口, Host）查站点，写 `ngx.var.cdnca_site_*`；强制 HTTPS 跳转；CC（现 `server_rewrite` 阶段，`security_fragments.go:149`）。
4. `rewrite_by_lua`：ACL/WAF 解释器、缓存新鲜度 access（现 `config.go:1855-1857` 阶段）。
5. `access_by_lua`：回源签名 → 防火墙动作 → JS 挑战 → HTTP 策略 → 套餐限额 → 缓存派发（现 `compiler.go:894-917` 顺序）。
6. `proxy_pass $cdnca_upstream_scheme://cdnca_dynamic` + `balancer_by_lua`：选池/端点、超时重试、回退池、出口绑定、keepalive。
7. `proxy_ssl_verify_by_lua`：按池信任校验源站证书（§4 回源 TLS 行）。
8. `header_filter` / `body_filter`：HTTP 策略头、错误页替换、Alt-Svc、缓存新鲜度。
9. `log_by_lua`：遥测、CC 计数、限额释放。

站点上下文放 `ngx.var`，不放 `ngx.ctx`：缓存派发用 `ngx.exec` 进命名 location，会清空请求上下文（`compiler_cache.go:16-19` 已因此拒绝“高级缓存 + HTTP 策略”）。每个阶段的 Lua 都必须能凭 `ngx.var` 重新取站点，且幂等。

### 3.3 站点查找

- 键：（公网端口, 小写 Host）。公网端口取 `ngx.var.proxy_protocol_server_port or ngx.var.server_port`，与 CC/WAF 现有做法一致（`ccv2/engine.lua:11-12`、`lua/cdnca_waf.lua:9-10`），mux 内部 unix 套接字上 `$server_port` 为空。
- 域名只有精确名与前导通配 `*.x`（`config.go:2574-2585`）。查找顺序：精确 → 依次去掉最左一个标签查 `*.<余下>`（即最长通配优先）。nginx `server_name` 语义同为“精确 > 最长前导通配”，且 `*.a.com` 不匹配 `a.com`；两者一致性用差分测试确认（§5），本文不凭记忆断言。
- 未命中：TLS 在 client hello 拒绝（与 v7 懒加载套接字的 `ssl_reject_handshake on` 一致）；明文走现有默认 server 行为——市场探测路径 204/基准对象，其余 421（`default_server.go:46-58`）。**路由必须先于探测路径判断**，否则共享 server 上的探测 location 会截走已配置站点的同路径请求。
- 跨站唯一性（同端口同域名只属于一个站点）仍在 Go 侧校验（`compose_conflicts.go`、主控），Lua 不兜底裁决。

## 4. 指令级功能改为 Lua：逐项方案与等价测试

“指令类型”取自 nginx 1.31.1 源码的指令处理函数：`*_flag_slot`/`*_off_slot`/`*_num_slot`/`*_str_slot`/`*_msec_slot` 是配置期常量，不能按请求变化；`complex_value` 接受变量。

| 功能（现状位置） | nginx 约束 | 动态路由下的做法 | 等价测试 |
|---|---|---|---|
| 选站 `server_name`（`compiler.go:593`） | 配置期 | §3.3 | 随机域名集（精确/通配/多级子域/大小写/尾点）× 随机 Host，v7 与新路由选中的站点逐条相同 |
| 证书（v7 变量证书 map） | — | 共享 server 上 `ssl_certificate_by_lua`。v7 PoC 失败的根因是 SNI 切到无 SSL_CTX 的站点 server（cert-lazy-load.md §2）；共享 server 不切 server，该根因不存在。G8-a 已实测“1 个 TLS server 按 SNI 动态证书，2000 站首/中/末握手证书正确”（benchmark §4.4 `dynamic`）。需同时去掉 certstore 64 上限（`certstore/types.go:15`、`validate.go:41`） | 复用 `TestRealOpenRestyLazyCertificates` 场景：多 SNI、通配别名、未知/无 SNI 拒绝、证书轮换不 reload 且在途连接不断 |
| `ssl_protocols`（`compiler.go:607-609`） | `ngx_conf_set_bitmask_slot`，server 级 | `ssl_client_hello_by_lua` 内 `ngx.ssl.clienthello.set_protocols`（lua-resty-core 0.1.34rc3 `ssl/clienthello.lua:315`，文档限定 client hello 阶段）。**未核实**：QUIC 连接上 client hello 回调是否触发 | 每档协议各一站同端口：openssl `s_client -tls1_2/-tls1_3` 握手结果与 v7 一致 |
| `http2 on`（`compiler.go:590-592`） | `ngx_conf_set_flag_slot`，仅 main/server 级（`v2/ngx_http_v2_module.c:76-78`）；ALPN 选择读 SNI 选中 server 的配置（`ngx_http_ssl_module.c:485-514`） | 共享 server 后只能**按端口**开关，无原生按站点手段 → §9 问题 2 | ALPN 协商结果按端口核对 |
| HTTP/3（`compiler.go:583-589`） | `listen quic` 按端口 | 端口级 `listen … quic`；`Alt-Svc` 在 header_filter 按站点加，只有宣告过的站点会被客户端尝试 h3。**未核实**：QUIC 下 `ssl_certificate_by_lua` 行为（G8-b 也未做真实 HTTP/3 握手，benchmark §8.5） | 需要 HTTP/3 客户端（本机无，benchmark §8.5）；进 1.0.36 PoC 清单 |
| 强制 HTTPS（`compiler.go:594-602`） | `if`+`return` | `server_rewrite_by_lua` `ngx.redirect`，保留 `/.well-known/acme-challenge/` 例外 | 现有 `force_https_integration_test.go` 场景双跑 |
| 源站池 `upstream{}` + 算法（`compiler.go:477-526`） | 静态 | 一个动态 upstream + 接入 `originroute/engine.lua` 的选端点逻辑。keepalive 池键 = host(SNI) + sockaddr + 本地地址（ngx_lua `ngx_http_lua_balancer.c:1464-1482`），不同 SNI/出口不会串池 | 现有 `origin_keepalive_integration_test.go`、`origin_resolver_integration_test.go` 双跑；算法分布统计对比 |
| 回源 SNI（`compiler.go:1048-1052`） | `proxy_ssl_name` 是 complex value | `balancer.set_current_peer(addr, port, host)` 第三参即 SNI（`balancer.lua:146`；ngx_lua `:942` 写 `u->ssl_name`），`set_upstream_tls`（`balancer.lua:353`） | HTTPS 源站按 SNI 返回不同证书，核对握手 SNI |
| 回源 TLS 信任 `proxy_ssl_trusted_certificate`（`compiler.go:1050`） | `ngx_conf_set_str_slot`，配置期 | `proxy_ssl_verify_by_lua_block`（ngx_lua 0.10.31rc5 已有）+ `ngx.ssl.proxysslverify` 按池信任校验。**安全约束：不得把各租户自定义 CA 合并进节点级信任库**，否则 A 的 CA 可替 B 的源站域名签证书。**未核实**：该回调能否拿到完整链并配合 lua-resty-openssl（bundle 有 1.7.1）完成链校验 | 正向：池 CA 签发的源站通过；反向：另一租户 CA 签发、域名正确的证书必须被拒 |
| 出口 IP `proxy_bind`（`compiler.go:1029-1032`） | 配置期求值 | `balancer.bind_to_local_addr`，originroute 引擎已用（`:3405-3414`，注释说明 FX30 正是 proxy_bind 在 balancer 前求值的问题） | `ingress_source_integration_test.go` 双跑 |
| 超时/重试（`compiler.go:1045-1047`） | `msec`/`num` slot | `balancer.set_timeouts`/`set_more_tries`（引擎 `:3383-3392`） | 故障注入（拒连/超时/502）核对尝试次数与总预算 |
| 条件回源（map/geo + `error_page 3xx`） | 配置期 | 引擎 `route_matches`（`:1163`） | 路由矩阵（路径前缀 × 客户端 CIDR × 节点区域）选中池一致 |
| L2 直连回退（`proxy_intercept_errors` + `error_page 502 503 504 = @fallback`） | flag slot | balancer 内按 `get_last_failure` 切回退池（引擎 `:3302`） | L2 故障注入，v7 与新运行时最终源站与状态码一致 |
| 自定义错误页（location 级 `error_page` + `proxy_intercept_errors`，`compiler.go:686-706`） | `error_page` 状态码配置期；`proxy_intercept_errors` flag | 不开 intercept；header_filter 按站点“有页的状态码”判断，命中则清 Content-Length、body_filter 丢弃源站体并输出页面；未配页的状态码源站体原样透传。**未核实**：HEAD、gzip、chunked、源站已发部分体时的行为，进 PoC | `error_page_integration_test.go` 双跑 + 源站带体 404（站点无 404 页）必须透传 |
| 缓存 zone（每站 `proxy_cache_path`） | `proxy_cache` 接受 complex value（`ngx_http_proxy_module.c:4967-5001`），zone 必须 http 级预声明 | 节点级 zone 池，站点按档位选 zone（变量），键内含站点维度。nginx `max_size` 只按 zone 生效，**站点级容量上限无原生手段** → §9 问题 2 | 两站同 URL 不串缓存；清除/预热按站点生效；`cache_integration_test.go` 双跑 |
| 缓存键 `proxy_cache_key`（`cache.go:681-690`） | complex value | 已全是变量，键前缀改由 Lua 按站点写变量 | 现有 `cache_identity_bundle_test.go` 断言改为对比两种运行时的落盘键 |
| 缓存 TTL/lock/stale（`proxy_cache_valid`、`proxy_cache_lock_*` 等，`cache.go:1338-1397`） | `valid_set_slot`/`msec_slot` 配置期 | TTL 沿用 cachefreshness guard 的做法（Lua 元数据 + 代际令牌进缓存键，`config.go:1803-1839`），骨架里 `proxy_cache_valid` 固定一份；lock/stale 等少数开关做成**有上限的命名 location 变体**用 `ngx.exec` 派发，变体数超上限就改为节点级统一值 | `cachefreshness/smoke.sh`、高级缓存规则场景双跑 |
| 套餐连接数（`limit_conn_zone` + `limit_conn n`，`package_limits.go:42,58`） | 连接数 `ngx_atoi` 配置期（`ngx_http_limit_conn_module.c:698`） | bundle 内 `lua-resty-limit-traffic` 0.09 的 `resty.limit.conn`，按订阅键计数，access 进 / log 出，超限 503；0 = 直接 503 | 并发压测核对第 n+1 个请求被拒。**未核实**：HTTP/2 多流时计数与 nginx `limit_conn` 是否一致 |
| 上传大小 `client_max_body_size`（`compiler.go:897`） | 原版是 `ngx_conf_set_off_slot` 配置期（`ngx_http_core_module.c:357-359`）；**原生补丁 23**（`edge/openresty/native/patches/23-cdnca-client-max-body-size-variable.patch`）后接受变量 | 共享 server 上写 `client_max_body_size $cdnca_site_max_body;`，变量由 `server_rewrite_by_lua`（或 map）在 find_config 前写好。语义：带体请求才求值；find_config 按 Content-Length 检查一次，读体开始时（`100 Continue` 之前）再求值一次并固定在请求体上，HTTP/1.1 chunked、HTTP/2、HTTP/3 的体过滤器（含 `proxy_request_buffering off`）都用这个值，超限 413；变量为空/非法/0/溢出时记 `invalid client_max_body_size value` 并回 **500**（路由/配置故障，不是客户端缩小上传能解决的，且绝不放宽成不限）；不含变量的写法与原版完全相同（`0` 仍为不限）。在 location rewrite 阶段才赋值的变量在 find_config 时为空，会 500（失败即拒绝）；与原版一样，未读取而直接丢弃的体不受限。1.0.35 渲染不用变量（仍每站 server{}） | `scripts/security/body-size-variable-smoke.sh`：h1/h2/h3 × 有/无 Content-Length，边界 ±1、多次读、非缓冲、空/0/负/非法/溢出 500、静态值不变、配置期重复/非法/未知变量拒绝；1.0.36 再做 v7 与新路由双跑 |
| `proxy_request_buffering on`（同上） | flag slot | 归入命名 location 变体（与缓存变体同一机制） | 流式上传与缓冲上传各一组 |
| ACL/WAF 自研规则（内联 Lua + geo） | — | 规则编译成 JSON 计划，由一个 Lua 解释器执行（同 `lua/cdnca_waf.lua` 读策略文件的模式）；CIDR 用已有实现（`ccv2/engine.lua:180-202`） | 差分模糊：随机规则集 × 随机请求，旧内联 Lua 与解释器的 action、rule_id、遥测变量逐条相同 |
| CC v2（内联注册表 + 每 server hook） | init 内联 token ≤4096（benchmark §10 缺陷 1） | 撤掉注册表；站点对象带 CC 绑定与已编译策略对象哈希，引擎按站点取（复用 reload/LKG 逻辑）。计数键前缀从 `entry_id` 改为（site_id, 端口），不兼容旧计数（按 10-17 原则直接重做） | `edge/openresty/ccv2/*_test.sh` 全部改为按站点绑定后通过 |
| JS 挑战（每站一个模块实例） | init 阶段 | 按站点懒实例化 + worker 级 LRU | `edge133_challenge_test.sh`、挑战缓存修订用例 |
| 回源鉴权凭据（master 在 init/reload 读 root-only 文件，`compiler.go:344-351`） | — | 不 reload 就进不了 master：改为 worker 可读的机密对象（§8.3 按节点加密），与 G8-b 已接受的“worker 可读私钥”同一档取舍 | `origin_auth_integration_test.go` 双跑 |
| 托管 WAF（CRS） | ModSecurity 规则在配置期合并；每站 `modsecurity_rules_file` | → §9 问题 3 | CRS 回归语料，拦截/记录结果一致 |
| 遥测 | 按监听身份清单 | log 阶段读 `ngx.var.cdnca_site_id`；身份清单改为按站点对象 | `composed_telemetry_test.go` 断言改为两种运行时字段一致 |
| WebSocket（静态 map `$cdnca_connection_upgrade*`） | map 已是变量 | 保留 map；是否加 Upgrade 由站点变量决定 | WebSocket 长连接 + 期间改站点配置，连接不断 |
| 四层 / mux | 端口即身份 | 不变（stream{} 编译 + reload） | — |

## 5. 等价测试总方法

- 预言机是 v7 编译器。按 10-17 原则 1.0.36 会删掉每站 server 的编译路径，所以**删除前**先用固定语料在真实 OpenResty 上录制金标：请求 → 响应（状态、去掉 Date 等易变头后的头、体摘要）、mock 源站收到的请求、缓存落盘键与 `X-CDN-Cache`、日志/遥测字段，存进 testdata；编译器删除后金标继续作回归基准。
- 新运行时用同一份站点事实生成站点对象，重放同一语料逐条比对。不一致只有两种结论：§6 列出的已知语义变化，或缺陷。
- 语料：现有集成场景（`real_openresty_harness_integration_test.go`、`runtime_security_parity_integration_test.go` 及 §4 各行列出的测试）+ 随机生成器（域名集、ACL/WAF 规则、路由矩阵、状态码 × 错误页配置）。
- 规模：`tests/scale/run.sh` 增加动态路由形态，测 1k/10k/100k 站的稳态内存、冷启动重建索引耗时、单站增删改从下发到生效的延迟；1 万站以上需要独立测试机（benchmark §5.7）。

## 6. 已知语义变化（需在发布说明写明）

- 未知 SNI / 无 SNI：所有 TLS 端口都拒绝握手（v7 只在懒加载套接字上如此，其它端口落到该端口第一个站点，benchmark §8.5）。
- HTTP/2、缓存容量、无长度上传：取决于 §9 问题 2 的选择。
- CC 计数与封禁状态在切换到动态路由时清零（计数键前缀改变）。

## 7. 与 G8-c 的关系

G8-c 设计见 million-sites-benchmark.md §9。逐条归类：

- 只服务于“每站 server{} 一起编译”、动态路由下作废的：节点按片编译缓存与按片稳定命名（§9.3 第 2 条）、分片 server 文本拼接、安全片段 32000 监听与 CC 合成注册表 1000 条的“按片约束”（§9.3 第 5 条）、“片 = 一份 v2 文档（≤500 站，片内整体编译）”这个单位本身。
- 与 nginx 形态无关、动态路由同样需要的：去掉 666/1000 站与 7/128 节点上限、内容只对称加密一次再按节点封装密钥、只签名/传输变化部分、按片批量读事实（去 N+1）、遥测按站点、`FindPortConflicts` O(n²)→O(n)（`port_claims.go:120`）、certstore 去 64 上限。

差别在最小单位：G8-c 的增量单位是“片”，动态路由的增量单位是**站点对象**，分桶只是清单的分层方式，不是编译单位。G8-c 尚未开工（远端只有 g8-fix/g8a-scale/g8b-certlazy 分支），现在调整没有沉没成本。

| 方案 | 1.0.35 | 1.0.36 | 作废的工作 |
|---|---|---|---|
| A 照原计划做 G8-c | 4–5 个大子任务 | 动态路由约 12 个 + 下发格式返工 2–3 个 | 节点按片缓存/命名、片文档格式 |
| **B 收窄改向（推荐）** | 3 个中大子任务：①主控站点对象/分桶/签名根 + 去各上限；②内容密钥封装 + 按哈希拉取；③节点对象库 + 薄适配器（把对象拼回现有 v2 Plan 交给 v7 编译器，节点仍整体 reload）。另加 certstore 去 64 上限（原 G8-b2，两条路线都要做） | 约 10–12 个 | 仅③里的薄适配器 |
| C 跳过 G8-c，直接动态路由 | 无 | 13–15 个 | 无，但 1.0.35 仍卡在单 scope 666 站、单次发布 7 个节点 |

子任务数是按 1.0.35 规划同口径的粗估，未做逐项拆分核算。推荐 B：1.0.35 已排满且动态路由有 5 项要先 PoC（§8.5），B 让 1.0.35 交付可发布的规模上限和增量下发，1.0.36 只换节点的消费方式；节点 reload 成本在 1.0.35 不变（`nginx -t` 是主要代价，Go 编译缓存的收益本来就小，benchmark §5.3 的 O(n²) 热点是 `FindPortConflicts`，单独修即可）。

1.0.36 动态路由子任务（粗估）：路由与站点索引、证书与 client hello、balancer 接入 originroute 引擎与回源 TLS 校验、ACL/WAF 解释器、CC/挑战/HTTP 策略/防火墙/回源鉴权改为按站点取、缓存（zone 池 + 变体 + 新鲜度）、错误页 filter、套餐限额与上传限制、托管 WAF 档位、对象库激活/健康/回滚、差分测试与金标、规模压测。缓存与 ACL/WAF 解释器最大。

## 8. 现在定死的预留

### 8.1 site_runtime 能力版本

现状：v5 回源 keepalive/强制 HTTPS/源站域名解析，v6 缓存/JS 挑战/托管 WAF，v7 懒加载证书（`edgeconfig.LazyCertificateSiteRuntimeVersion`，`libs/edgeconfig/lazy_certificates.go:14-18`；门控 `edgepublish/feature_capabilities.go:83-90`；agent 声明 `MaxSiteRuntimeVersion`，`cmd/edge-agent/daemon.go:1422`）。

| 版本 | 含义 | 发布 |
|---|---|---|
| 7 | 每站 server{} + 懒加载证书（最后一个“站点编译进 nginx”的版本） | 1.0.35 已合入 |
| 8 | 站点对象下发（根/桶/对象，§8.3 定稿），节点经适配器拼回 v2 bundle 仍编译 server{}。内层 v2 文档的 `site_runtime` 仍按功能取 2..7，只有根与 rollout 的 `required_capabilities` 是 8；`edgeconfig.MaxSiteRuntimeVersion`（agent 据此声明能力）由节点侧实现对象拉取后再提到 8 | 1.0.35（方案 B） |
| 9 | 动态路由：共享 server、站点存储、不 reload | 1.0.36 |
| 10 | 按需加载、冷站淘汰（站点对象 `placement` 字段生效） | 1.0.37 |

> 已于 1.0.35 删除：版本 7、8 及其发布路径。实际落地是 9 提前进 1.0.35 并成为唯一版本（agent 声明 `MaxSiteRuntimeVersion = DynamicRoutingSiteRuntimeVersion` = 9，拒绝 `dynamic_routing.enabled=false`）；下面“1.0.36 起删除每站 server 编译路径”“节点拒收 v7/v8 文档”两条随之在 1.0.35 完成，不存在 v7/v8 与 9 的混跑。

- 门控沿用 10-17 原则：目标节点低于所需版本直接拒绝发布并列出节点，不出降级产物；节点能力提升后自动重新发布。1.0.36 起 agent 删除每站 server 编译路径，控制面不再产出 v7/v8 文档。
- 对象 schema 名（§8.3）与能力版本解耦：能力版本说“节点能执行什么”，schema 说“文档长什么样”。
- 升级顺序：主控先于节点。节点先升到 1.0.36 而主控仍是 1.0.35 时，节点拒收 v7/v8 文档，但**不得停掉当前正在运行的 release**；1.0.36 要有这条的专门测试。
- 这些版本号与上面的期次绑定是本文提议，最终以 `proto/agent/v1/types.proto` 为准。

### 8.2 节点对象库与共享字典（不引入 LMDB）

- 对象库：`<state>/objects/sha256/<2 位>/<2 位>/<64 位摘要>`，不可变、内容寻址；agent 写入前验根签名并沿哈希链逐级校验；按代保留“当前代 + 上一代”引用到的对象，其余由 GC 回收。
- 索引（`lua_shared_dict`）：`cdnca_site_index`（键 `<端口>\0<小写域名>` → `{gen_a: 站点对象摘要, gen_b: …}`）、`cdnca_site_generation`（当前代指针、各 worker 已应用代）。每个键同时保留当前代与上一代的值：激活 = 写新值后原子改代指针；回滚 = 把指针改回上一代，立即生效。
- 写入路径：agent 经本地 unix 套接字上的管理 location 推送变更集（不对外监听），Lua 写字典后提交代指针。冷启动/字典丢失时，由一个 worker 持 `resty.lock` 从磁盘的整代索引文件重建，重建完成前不报告该代健康。reload 时 nginx 在名称、tag、尺寸都不变时复用共享内存区（`src/core/ngx_cycle.c:471-477,923-925`），所以骨架 reload 不丢索引，只有尺寸档位变化要重建。
- 站点对象本身在 worker 内按摘要缓存（`resty.lrucache`，bundle 0.15），摘要不变即命中，天然不需要失效。
- 预检与健康：agent Go 侧做与今天 `validateDocument` 同级的完整校验；Lua 读取时再校验，失败保留 LKG（与 httppolicy 同一模式）。`nginx -t` 只在骨架变化时跑。健康 = 所有 worker 报告已应用新代 + agent 对变更站点做本机 Host/SNI 探测。
- 不选 LMDB 的理由：`lua-resty-lmdb` 不在 OpenResty 1.31.1.1 的 bundle 里（tar 包 bundle 目录无此项），引入要新增 C 模块、构建、源码锁与签名链路，现有补丁已 22 个。**未核实**的是共享字典在百万键下的内存与冷启动重建耗时，列入 §8.5 测量；超标时只替换索引层（对象库与清单格式不变）。

### 8.3 站点对象、分桶与签名根（1.0.35 定稿，site_runtime v8）

> **已于 1.0.35 删除（v1 根格式）**：本节下文描述的 `cdnca.edge.site-root/v1`、`cdnca.edge.site-bucket/v1`、`cdnca.edge.site/v1`、`cdnca.edge.site-scope/v1`，“拆 v2 bundle、节点逐字节拼回再交 v7 编译器”的拼装规则（`siteobject.Build`/`Assemble`），以及根 media type `application/vnd.cdnca.edge-site-root+json;version=1`，都已删除，保留原文作历史决策记录。
>
> 1.0.35 唯一格式（动态路由，site_runtime 9；实现 `libs/edgeconfig/siteobject/root_v2.go`，站点对象见 `docs/edge/site-object-v2.md`）：根 `cdnca.edge.site-root/v2`（media type `application/vnd.cdnca.edge-site-root+json;version=2`，字段 `schema`、`configuration_scope_id`、`config_version_id`、`source_revision`、`key_epoch`、`required_capabilities`（`site_runtime` 提到 9）、`document_sha256`、`scope_sha256`、`bucket_count`、`buckets`；不再有 `bundle_manifest_sha256`）；桶 `cdnca.edge.site-bucket/v2` 指向 `cdnca.edge.site/v2` 站点对象，节点按原样激活、不拼回 bundle；scope `cdnca.edge.site-scope/v2` 列出 CRS 文件、站点引用的全部对象摘要、`system`、四层 `streams`、节点页 `node_pages`、`installation_id`。只签根、内容寻址、对象加密（HKDF info/aad 前缀与密钥信封 `cdnca.edge.site-object-key/v1` 沿用）、`FetchSiteObjects` 拉取、分桶规则与 `MaxRootIndexBytes` 不变。下文“规模边界”里由“拼回整份 v2 再编译”造成的上限（16 MiB 文档约 14,000 站等）属于 v1 方案，动态路由下不再适用；v2 的实际规模上限本节未重新实测（见 `docs/architecture/million-sites-benchmark.md`，由 d13-d 更新）。

> 已定稿。实现与唯一规范：`libs/edgeconfig/siteobject`（`format.go` 字段、`crypto.go` 加密、`build.go` 拆分、`assemble.go` 重建）。与本节文字不一致时以代码 + 测试为准，并回改本节。

**原则。** 1.0.35 的站点对象是“v2 发布产物按站点拆开”：主控照旧编出 site runtime v2 bundle，再把它拆成对象；节点把对象拼回**逐字节相同**的 bundle 交给现有 v7 编译器（节点仍整体 reload）。每次发布都变的值（`config_version_id`、`source_revision`，以及由它们派生的遥测命名空间/日志路径、`http_policy.artifact_sha256`、L4 流产物）只出现在根和拼装结果里，不进站点对象，所以没改的站点跨发布摘要不变、不重传。1.0.36 动态路由的站点对象是语义化的 `cdnca.edge.site/v2`（本节最初列出的 domains/listeners/origin/cache/security/limits/secrets/placement 等字段），按 §8.1“schema 与能力版本解耦”另行定义；根/桶/对象三级、只签根、内容寻址、加密与拉取方式原样复用。

**编码与寻址。** 所有对象是 JSON：Go `encoding/json` 按结构体字段顺序、紧凑、不做 HTML 转义、无结尾换行（`siteobject.Encode`）。对象以**明文** SHA-256（小写十六进制）寻址；读取方只需校验摘要，Go 解析器另外要求“再编码等于原字节”。`runtime`/`document`/`edge`/`targets` 等内嵌字段是原样字节（`json.RawMessage`）。

**根 `cdnca.edge.site-root/v1`**（唯一签名对象，≤1 MiB）：

| 字段 | 含义 |
|---|---|
| `schema`、`configuration_scope_id`、`config_version_id`、`source_revision` | 发布身份 |
| `key_epoch` | 对象内容密钥的代（§8.3 加密），≥1 |
| `required_capabilities` | 内层 v2 文档的 `required_capabilities`，只把 `site_runtime` 提到 8；按名字升序。节点拉取前先比对本机能力 |
| `document_sha256` | 拼出的 `site-runtime.v2.json` 的摘要（= 主控 `config_versions.canonical_snapshot` 的摘要） |
| `bundle_manifest_sha256` | 拼出的 bundle 的 `edgeconfig.ManifestDigest`。节点拼装后两项都必须相等，否则拒绝 |
| `scope_sha256` | scope 对象 |
| `bucket_count`、`buckets` | 桶数 B（2 的幂，1..4096）与按下标排列的桶摘要；空桶也是对象 |

**桶 `cdnca.edge.site-bucket/v1`**：`configuration_scope_id`、`bucket_count`、`index`、`sites: [{site_id, revision, sha256}]`（按 site_id 升序，≤4096 条）。站点所在桶 = `SHA-256(site_id 字符串)` 前 4 字节大端 mod B。B = 使平均每桶 ≤256 站的最小 2 的幂（单 scope 格式上限 4096×256 = 1,048,576 站；实际先撞根索引上限，见 §8.3 末）。B 翻倍时每桶一分为二，只重建桶和根，站点对象不变。

**站点 `cdnca.edge.site/v1`**：

| 字段 | 拼回哪里 |
|---|---|
| `configuration_scope_id`、`site_id`、`revision` | 与桶条目、`runtime` 内的 `id`/`revision` 必须一致 |
| `runtime` | v2 文档 `sites[]` 中该站的条目（规范化 JSON），去掉 `http_policy` |
| `http_policy`（可选）`{policy_id, policy_revision, edge}` | `edge` 是该站在 `http-policy.v1.json` `sites[]` 里的原样条目；文档里的绑定 `{artifact_sha256, policy_id, policy_revision}` 在拼装时生成，`artifact_sha256` = 拼出的 http-policy 文件摘要 |
| `origin_route`（可选）`{site_revision, document}` | `origin-route.v1.json` `sites[]` 的该站条目 |
| `telemetry`（scope 有遥测时必有）`{package_subscription_id?, capture}` | 遥测清单中该站每个监听一条：域名 = `runtime.domains[0]`，端口 = 各 listener，`namespace_id`/日志路径由根的 `config_version_id` 与 scope 的 `tenant_id`/`state_root` 派生，`capture` 是除 site_id/domain/listen_port 外的采集策略字段（同站各监听相同） |
| `files` `[{path, sha256}]` | 该站独占的文件对象：只有 `firewall-action/<site_id>.json` |

**scope `cdnca.edge.site-scope/v1`**：`configuration_scope_id`；`document` = v2 文档去掉 `config_version_id`、`source_revision`、`sites`（含 `schema`、`required_capabilities`、`streams`、`system`、`lazy_certificates`）；`http_policy {schema_version, policy_version}`、`origin_route {schema, targets?}`、`telemetry {tenant_id, installation_id?, state_root, source_capabilities}` 分别是三个按站文件去掉站点后的外壳（存在 ⇔ 对应文件存在）；`files` = 其余所有文件对象（CRS 规则文本、L4 流产物等，按 path 升序）。

**文件对象**：原始字节，无 schema。

**拼装规则（`siteobject.Assemble`，节点必须逐字节复现）。** `site-runtime.v2.json` = scope.document ∪ {`config_version_id`, `source_revision`, `sites`（各站 runtime 按 site_id 升序，有 http_policy 的插回绑定）} 的规范化 JSON（与主控 `writeSiteRuntimeV2CanonicalJSON` 同一写法）；`http-policy.v1.json` = `json.Marshal({schema_version, policy_version, sites:[有 http_policy 的站的 edge，按 site_id]})` + `\n`；`origin-route.v1.json` = `json.Marshal({schema, configuration_scope_id, source_revision, config_version_id, targets?, sites:[{site_id, site_revision, document}]})`（无换行）；`telemetry/identity-v1.json` = 按（端口, 域名）排序的清单 `json.Marshal` + `\n`；其余文件原样。主控每次发布都执行 `Build` → `Assemble` 自检，任何一个文件不能逐字节重建就拒绝发布（所以新增 bundle 文件种类时不会静默丢失）。

**加密（内容只加密一次，按节点只封装密钥）。** 每个 scope 一把 32 字节内容密钥（`key_epoch` 标识）。每个对象（scope/桶/站点/文件，根除外）：`key = HKDF-SHA256(ikm=内容密钥, salt=空, info="cdnca-edge-site-object-v1\0" ‖ scope_id ‖ "\0" ‖ 摘要)`，`wire = AES-256-GCM(key, nonce=12 字节 0, 明文, aad="cdnca-edge-site-object-aad-v1\0" ‖ scope_id ‖ "\0" ‖ 摘要)`。一把对象密钥只封一个明文，固定 nonce 不会重用；同一明文跨发布密文不变，只存、只传一次。代价是收敛加密：持有内容密钥者可确认某个猜测明文是否存在（只有已授权节点持有密钥，可接受）。根不含机密（只有标识与摘要），**签名、不加密**，所有目标节点共用同一份。

**每次发布下发给节点的 artifact**（走现有 `FetchArtifact`，不改 proto）：
1. 根：`kind=CONFIGURATION`，media type `application/vnd.cdnca.edge-site-root+json;version=1`，`encryption=NONE`，Ed25519 签名（平台签名密钥），所有节点同一个 artifact_id。
2. 密钥信封：`kind=CONFIGURATION`，media type `application/vnd.cdnca.edge-site-object-key+json;version=1`，HPKE（与 v2 bundle 同一套 X25519/HKDF-SHA256/AES-256-GCM 与 info/aad 绑定，`edgepublish/configuration_artifact_hpke.go`），每节点一个；明文 `cdnca.edge.site-object-key/v1` `{configuration_scope_id, config_version_id, root_sha256, key_epoch, content_key}`（`content_key` base64），`root_sha256` 必须等于根 artifact 明文摘要。

DeploymentCommand 的 `artifacts` = [根, 本节点信封]，`required_capabilities` 含 `site_runtime` 8。单次发布产物 = 1 个根 + N 个约 200 字节的信封，16 MiB/128 个的限制不再按节点数线性增长（上限改为 10001 个产物）。

**按哈希拉取对象**：节点从根出发，先拉 scope 与全部桶，再拉本地对象库没有的站点，最后拉缺的文件；每个对象用信封里的内容密钥 `Open` 并校验摘要。节点对象库布局见 §8.2；未变化的对象不再传输。

传输是 `AgentGatewayService.FetchSiteObjects`（`proto/agent/v1`）→ 网关带认证节点 ID 转发 `ControlInternalService.FetchSiteObjects`（`proto/controlinternal/v1`）→ 主控 `edgeartifact.FetchSiteObjects`：
- 请求：deployment/attempt/event、`root_sha256`、≤256 个不重复的小写摘要。网关校验格式与节点授权，回流时逐块核对请求号、对象顺序、偏移、单块上限与 `end_of_object`，乱序或提前结束即拒绝。
- 主控授权（只读事务）：deployment 属于该节点与事件、`apply` 且 `queued|delivered`、配置 `releasable|superseded`、未过截止；命令里根 artifact 的摘要 = 请求 `root_sha256`，且等于 `edge_site_object_publications.root_sha256`；每个摘要都在该发布的 `member_sha256`（发布闭包，32 字节排序拼接，进程内按 config 缓存，二分查找）里，否则 `PermissionDenied`。
- 授权事务外按请求顺序逐个读 `edge_site_objects.ciphertext`，按 artifact 分块上限切块流出。对象不可变、内容寻址，重试不需要审计行。

**主控存储**（迁移 354）：`edge_site_object_keys(scope_id, key_epoch, content_key)`、`edge_site_objects(scope_id, key_epoch, sha256, kind, ciphertext)`（主键 (scope, epoch, sha256)，发布时先批量查已有摘要，只加密/插入新对象）、`edge_site_object_publications(config_version_id → scope, key_epoch, root_sha256, member_sha256)`。1.0.35 不轮换内容密钥（`key_epoch` 恒为 1）；轮换 = 新 epoch 全量重建对象，移除的节点拿不到新 epoch 的信封。对象 GC 未做。

**规模边界（1.0.35 实际值，实测）**：
- 节点“单文档 16 MiB”（`edgeconfig.MaxConfigurationBundleFileBytes`）在 v8 下只约束**根索引** = 根 + 全部桶（`siteobject.MaxRootIndexBytes`，`Build`、`Assemble` 与节点拉完桶后都检查）：节点必须先整份持有它才能开始拉站点。站点、scope、文件对象按摘要按需拉取，不计入（各自仍有单对象 8 MiB 上限）。
- 实测根索引（每站约 146 字节）：5,000 站 0.70 MiB（B=32），50,000 站 6.97 MiB（B=256，根 17.7 KB），100,000 站 13.9 MiB；约 115,000 站撞 16 MiB。格式上限 1,048,576 站对应约 146 MiB，所以 1.0.35 的单 scope 实际上限由根索引决定。
- 同一实测里 50,000 站的真实发布产物：`site-runtime.v2.json` 59.2 MB、`telemetry/identity-v1.json` 50.3 MB、`origin-route.v1.json` 24.2 MB，站点对象合计 108.6 MB / 62,757 个；主控编译 10.9s、拆对象 9.7s、峰值内存约 1.7 GB。
- 因此 50,000 站在 1.0.35 **不能**端到端落地，卡在以下既有上限（都不是根索引）：节点 v7 编译器把拼回的 v2 文档整体解析与编译，`site-runtime.v2.json`、遥测清单等单文件仍受 16 MiB、bundle 合计 128 MiB、文件数 4,096（每个有防火墙动作的站一个文件）约束；安全片段渲染单 scope ≤32,000 个监听（控制面与节点同一函数 `edgeconfig.RenderSecurityFragmentsAt`）。按本实测夹具（文档约 1.2 KB/站）最先撞的是 16 MiB 文档，约 14,000 站；站点更复杂时更少。这些属于“拼回整份 v2 再整体编译”的 1.0.35 方案 B 固有边界，1.0.36 动态路由按站点取对象后消失，本任务不放宽。
- 主控 `config_versions.canonical_snapshot` 仍存整份 v2 文档（下游 cross-scope 校验、IPv6 灰度、挑战目标、CRS 重新发布等都读它），表上 CHECK 为 256 MiB；写入时由代码按节点文档上限 `edgeconfig.MaxSiteRuntimeDocumentBytes`（= 16 MiB）拒绝，v2 编译输入的 CHECK 同为 16 MiB（迁移 354）。遥测清单格式上限 4,194,304 条/1 GiB；HTTP 策略仍是每 scope 128 个站点（`httppolicycontrol.MaxSites`，节点 Lua 同值，是产品限制，不在本任务内）。

### 8.4 规则包按站点挂载（与 ADR 0007/0008 的接口）

用户已定：WAF/CC/ACL/挑战引擎在核心、随版本；规则内容是签名规则包；来源分系统/开发者/用户三层，需要排序与冲突检测。本文只定动态路由侧的接口，包格式、签名、分层规则由 ADR 0007/0008 定。

- 规则包是节点级、内容寻址的对象，与站点对象同一对象库；N 个站点挂同一包，节点只存一份，每个 worker 按包摘要只编译一次（缓存键 = 引擎版本 + 包摘要）。
- 站点对象 `security.mounts`：有序列表 `[{layer: system|developer|user, pack_id, version, sha256, engine, params}]` + `resolved_sha256`。
- **排序与冲突检测在主控发布时完成**，结果写进 `mounts` 的顺序与 `resolved_sha256`；节点不裁决，只按顺序执行、校验摘要。这样结果确定、可展示给用户，节点与主控不会各算一套。
- 规则包更新：Lua 引擎的包换摘要不需要 reload；托管 WAF（ModSecurity）包是节点级骨架项，换版本要 reload（§3.1），频率远低于站点变更。
- 涉及插件、规则包、IP 库下发、节点插件的实现按 BATCH 第 7 条暂不做。

### 8.5 1.0.36 开工前的 PoC 与测量

> 五项已于 10-17 完成，结果、数据与对本文的修正见 [0009-poc-results.md](0009-poc-results.md)（脚本 `tests/dynroute-poc/`）。本文 §4/§8.2/§9 与结果不一致处以结果文档为准，待实现任务开工时回改正文。

1. 共享字典 100 万键的内存与冷启动重建耗时（决定是否换索引层）。
2. QUIC 下 `ssl_client_hello_by_lua` / `ssl_certificate_by_lua` 的行为（需要 HTTP/3 客户端）。
3. `proxy_ssl_verify_by_lua` + lua-resty-openssl 按池 CA 完成链校验，含跨租户反向用例。
4. 错误页 header/body filter 替换（HEAD、gzip、chunked、部分体）。
5. 托管 WAF 档位与站点级排除（§9 问题 3 的方案 a）。

## 9. 需要用户拍板

1. **G8-c 怎么处理？** 推荐 B（§7）：取消节点分片编译，1.0.35 做站点对象下发 + 去各上限 + certstore 去 64 上限，节点经适配器仍 reload；1.0.36 动态路由。备选 C：1.0.35 不做 G8-c，所有人力进 1.0.36，代价是 1.0.35 单 scope 666 站、单次发布 7 个节点。
2. **nginx 不能按站点动态的三项，收窄功能还是加 nginx 补丁？**（已有 22 个补丁，含自研 `21-cdnca-ja4-module`、`22-cdnca-stream-toa`）
   - HTTP/2 按站点开关：推荐收窄为**按端口**开关（ALPN 由 SNI 选中 server 的配置决定，共享 server 后天然是端口级）。
   - 站点级缓存容量上限：推荐收窄为“zone 池共享 + agent 按站点用量清理”的软配额，硬上限只在 zone 级。
   - 无 Content-Length 的上传大小上限：推荐**加一个小补丁**让 `client_max_body_size` 接受变量。这是安全边界，Lua 只能按 Content-Length 早拒，chunked 上传会绕过站点上限、只受节点最大值约束。（已定加补丁，已实现为原生补丁 23，语义见 §4 上传大小行。）
3. **托管 WAF（CRS）站点级调参的形态？** ModSecurity 规则在配置期合并，现在每站一个 `modsecurity_rules_file`（`waf_engine.go:228-231`）；共享 server 下保留它就等于保留每站配置。
   - 推荐 a：规则集 × 防护等级 × 阈值做成**有限个节点级档位**（系统层规则包），站点只选档位；站点级排除在请求期用 `ctl:ruleRemoveById` 按站点变量生效。**未核实**：ModSecurity-nginx 与 Lua 阶段的先后、Lua 设的变量对 ModSecurity 是否可见，要 PoC（§8.5 第 5 项）。
   - 备选 b：开托管 WAF 的站点保留每站配置 + reload，这部分站点放弃“免 reload”。
