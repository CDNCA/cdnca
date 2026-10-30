# 节点骨架（动态路由 D2，site_runtime 9）

- 实现：`libs/edgeconfig/edgeskeleton`（Go 渲染器，唯一规范）、`edge/openresty/dynroute/cdnca_dynroute.lua`（各阶段入口，节点路径 `/usr/local/share/cdnca/dynroute/cdnca_dynroute.lua`，`lua_package_path` 根 + `dynroute.cdnca_dynroute`）。与本文不一致时以代码和测试为准。
- 依据：ADR 0009 §3.1/§3.2、[0009-poc-results.md](../adr/0009-poc-results.md)、站点对象 [site-object-v2.md](site-object-v2.md) §6 端口表。
- 状态：渲染器与入口模块已完成，并按 [dynroute-contract.md](dynroute-contract.md) §6（D3）对齐、接入 D4 TLS 入口（[dynroute-tls.md](dynroute-tls.md)）；**未接入 agent**（由 agent 调用 `Render` 与 `siteindex.Activator` 的任务做）；v7/v8 编译路径不动（D13 删）。

## 1. 输入与输出

`edgeskeleton.Render(Input) → nginx.conf`，整份主配置（main/events/http），**不含任何站点**：

| 输入 | 来源 | 变化即 reload |
|---|---|---|
| `Ports []edgesite.PortProfile` | `edgesite.PortProfiles(全部站点)`（跨站校验：同端口 TLS、HTTP/2 一致，(端口,名字) 唯一）；`FromSites` 同时给出索引键数 | 端口集合、某端口 TLS/HTTP2/HTTP3/地址族变化 |
| `IndexKeys` | Σ `len(site.IndexEntries())` | 只在跨档位时 |
| `System` | `SiteRuntimeSystem`（与 v7 同一份 main/events/http 级渲染） | 系统配置变化 |
| `Cache` | 节点缓存 zone 池：个数（≤64）、每个 keys_zone/max_size/inactive | 池变化 |
| `Paths` | 节点本地绝对路径（共享根、Lua 根、状态根 `StateRoot`：`run/cdnca-site-admin.sock`、`site-objects/`、`site-index/`、`tls-pool/`；占位证书、回源信任占位） | — |

确定性：端口先排序，渲染不读 map 顺序、时间、环境；同输入同字节（`TestRenderIsDeterministic`、1 万站重复渲染比对）。

## 2. 骨架内容

- **每端口一个共享 server**：`listen <addr>:<port> [ssl] default_server`，IPv4 `0.0.0.0`/IPv6 `[::]` 按端口地址族并集；`server_name _`。
- **TLS 端口**：`http2 on|off`（按端口）；`ssl_protocols TLSv1.2 TLSv1.3`（QUIC 要求 server 含 1.3，站点在 client hello 收窄）；占位证书（证书阶段替换；客户端见到占位证书即失效打开）；`ssl_client_hello_by_lua` / `ssl_certificate_by_lua`。
- **HTTP/3 端口**（任一站宣告 h3）：每个地址加 `listen … quic reuseport default_server` + `http3 on`。**带 `reuseport`**（v7 没带）：多 worker 时 nginx 的 QUIC BPF 辅助程序（`ngx_event_quic_bpf.c`，只对 `quic && reuseport` 生效）让同一连接的包落在同一 worker；实测不带时稳态 0.4–0.6% 新 QUIC 连接失败、reload 后约 10% 失败，带时稳态 500/500、reload 后 50/50。已知代价：每次 reload 每个 worker、每个 QUIC 套接字记一条 `[emerg] close() socket <addr> failed (9: Bad file descriptor)`（`ngx_event.c:848-857` 关闭非本 worker 的 reuseport 克隆时报），不影响服务；验收脚本把这条列为已知噪声，其他 alert/crit/emerg 仍算失败。v7 同样受“不带 reuseport”影响，留给 v7 维护方判断（D13 删除 v7）。
- **一个动态 upstream** `cdnca_dynamic { server 0.0.0.1; balancer_by_lua_block {…}; keepalive 0; }`：`keepalive 0` 关掉 nginx 按 sockaddr 的连接缓存（PoC §3 跨信任复用缺陷），复用只能走 `balancer.enable_keepalive`，键须含信任锚等连接级属性（D5 实现）。 另有 `balancer_keepalive 256`（D5a，worker 共享的 balancer 连接池）。location / 写 `proxy_next_upstream error timeout http_502 http_503 http_504` + `proxy_next_upstream_tries 0` + `proxy_next_upstream_timeout 0`：可换源的结果由 nginx 判，次数与预算由 balancer 按池设。`configure` 另带 `node_region`（主控下发的区域代号：节点密钥文档 `node_region`，能力 NODE_REGION；节点本地无区域配置）、`ingress_source_ipv4/6`、`resolvers`（`Input.Node`；resolvers 空时取系统配置）。
- **location /**：`client_max_body_size $cdnca_site_max_body`（补丁 23）、`proxy_cache $cdnca_cache_zone`（有 zone 池时；空值 = 不缓存，`ngx_http_upstream.c:1059`）、`proxy_ssl_verify on` + 回源信任占位 + `lua_upstream_skip_openssl_default_verify on` + `proxy_ssl_verify_by_lua`（三者缺一不可，PoC §3；占位里不得放任何租户 CA）、`proxy_ssl_name $cdnca_origin_sni`、`proxy_set_header Host $cdnca_origin_host`、`proxy_pass $cdnca_origin_scheme://cdnca_dynamic`。
- **缓存 zone 池** `cdnca_cache_<i>`：`<共享根>/cache/cdnca-<i>`，`levels=1:2 use_temp_path=off`；站点按变量选 zone，容量是 zone 级硬上限 + 站点软配额。
- **共享字典**（契约 §4）：`cdnca_site_index`（档位见 §4）、`cdnca_site_state` 8m、`cdnca_site_lock` 1m。
- `init_by_lua_block`：`require("dynroute.cdnca_dynroute").configure({objects_root, index_root, tls_pool_root, system_max_body})`（master 加载，模块坏了 `nginx -t` 即失败；`system_max_body` = 系统配置 `client_max_body_bytes`，无系统配置时 1 MiB = nginx 默认）；`init_worker_by_lua_block` 调 `init_worker()`（D3 冷启动 timer）。`lua_package_path` 依次 `<lua>/dynroute/?.lua`、`<lua>/?.lua`；`uninitialized_variable_warn off`。
- **`map $uri $cdnca_node_location`**：未知 Host 仍可到达的节点级路径（契约 §1.1）。当前为空——节点级 location（健康、ACME overlay、市场探测、基准对象）由各自任务连同 location 一起加。
- **控制套接字 server**（契约 §5.4）：`listen unix:<StateRoot>/run/cdnca-site-admin.sock`，`cdnca_site_admin.handle()`；其中不执行的 `location = /__cdnca_site_vars { internal; set ... }` 声明 `$cdnca_site_*`（`max_body` 默认 `1`）与各模块变量（变量 http 级全局，声明一次即可）。共享 server 里不再有 `set`。
- `client_max_body_size $cdnca_site_max_body` 在 server 级（D3 写变量在 location 选择前）。

骨架没有：任何 `server_name <站点>`、站点 upstream、站点证书、`map`/`geo`、站点级 `include`。四层 `stream{}`、健康/状态/预热/ACME/市场探测等节点级 location、托管 WAF 规则包由后续任务按同一渲染器加入（见 §6）。

## 3. Lua 入口调用约定（冻结）

骨架里每个阶段只有一行 `require("dynroute.cdnca_dynroute").<函数>()`，无参数，返回值不用。后续任务只能改函数体，**改函数名、增删阶段、改变量名都要同时改渲染器与本节**。

| 阶段（指令） | 函数 | 约定 |
|---|---|---|
| `ssl_client_hello_by_lua` | `client_hello()` | 按（`ngx.ssl.server_port()`, SNI）查索引；无 SNI / 未命中 → `ngx.exit(ngx.ERROR)` 拒绝握手（与 v7 懒加载 `ssl_reject_handshake on` 一致，TCP 为 TLS alert、QUIC 为 CRYPTO_ERROR 0x150）。站点删除/停用/吊销必须在这里判（会话恢复不进证书阶段，PoC §2）。D4 在此按站点 `set_protocols` |
| `ssl_certificate_by_lua` | `certificate()` | D4：无条件 `clear_certs` 后设站点证书；只从字典/LRU 取，不做网络 IO |
| `server_rewrite_by_lua` | `server_rewrite()` | 按（公网端口, `$host`）选站（**按 Host，不按 SNI**，SNI≠Host 不回 421）；写下表全部变量；强制 HTTPS、CC 在此 |
| `rewrite_by_lua` | `rewrite()` | 先 `cdnca_managed_waf.rewrite`（D11：托管 WAF 站点写 `$cdnca_waf_txid` 后 `ngx.exec` 进档位 location `@cdnca_waf_<key>`，ModSecurity phase 1 在那里跑，本阶段再跑一次），再 ACL/WAF 解释器（D6） |
| `access_by_lua` | `access()` | 回源签名 → 防火墙动作 → JS 挑战 → HTTP 策略 → 套餐限额 → 缓存派发 |
| `balancer_by_lua`（upstream 内） | `balancer()` | 选池/端点、`set_current_peer(addr, port, keepalive 键)`、超时重试、回退池、出口绑定；没选站就到这里 → 失败 |
| `proxy_ssl_verify_by_lua` | `proxy_ssl_verify()` | 按池信任校验对端整条链；D2 一律 `set_verify_result(27)` 拒绝 |
| `header_filter_by_lua` / `body_filter_by_lua` | `header_filter()` / `body_filter()` | 唯一入口，按固定顺序调各模块（错误页替换在最前，PoC §4）；body_filter 在 D9 过滤管线之后由 D12 采集缓冲客户端实际收到的响应体（`cdnca_telemetry.body_filter`，仅 `$cdnca_site_state=ok`，pcall 隔离） |
| `log_by_lua` | `log()` | 顺序固定：① `cdnca_limits.leave()`（D10 限额释放）→ ② `cdnca_origin.log()`（D5a 被动健康）→ ③ `cdnca_security.log()`（D7 CC 计数）→ ④ 遥测 `cdnca_telemetry.log()`（D12，最后：它读前面模块写的 `$cdnca_security_*`/`$cdnca_security_block_page`，写 access_log 用的变量；仅 `$cdnca_site_state=ok`，pcall 隔离，失败不影响其他模块）。`Input.Telemetry` 时每个共享 server 渲染四条 `access_log … if=`，变量在控制 server 的声明 location 里与其他模块变量去重后声明一次（docs/edge/dynroute-telemetry.md） |

站点上下文只放 `ngx.var`（缓存派发 `ngx.exec` 会清 `ngx.ctx`），每个阶段都能凭变量重新取站点。骨架在不执行的 `location @cdnca_variables` 里用 `set` 声明下列变量（不在 server 级 `set`：它在 SERVER_REWRITE 阶段跑，会覆盖 Lua 写的值，PoC §5），`server_rewrite()` 必须在 location 选择前写好：

| 变量 | 含义 |
|---|---|
| `cdnca_site_digest` | 选中站点对象摘要（十六进制） |
| `cdnca_site_max_body` | 站点上传上限，**总是正数**（0 = 节点系统值由 Lua 换算；补丁 23 空/0 回 500） |
| `cdnca_cache_zone` | `cdnca_cache_<i>` 或空（不缓存） |
| `cdnca_origin_scheme` | `http` / `https` |
| `cdnca_origin_host` | 回源 Host |
| `cdnca_origin_sni` | 真实回源 SNI（`proxy_ssl_name`，在 balancer 后求值覆盖 keepalive 键里的 SNI） |
| `cdnca_waf_txid` | 托管 WAF 事务 ID（站点上下文 `c1;…`，D11 写，档位 location 的 `modsecurity_transaction_id` 读；见 dynroute-managed-waf.md） |
| `cdnca_waf_engine` | `location /` 内 `set` 为 `1`（骨架带托管 WAF 时）：只有这里把请求交给档位 location |
| `cdnca_waf_pass` | `tier`：档位 location 里跑的是客户端首轮（入口 `client_pass()`），access 结束时清空 |

**索引键与就绪**：键、值、查找顺序、按端口就绪与未就绪 503 全部由 `cdnca_site`（D3）实现，见 [dynroute-contract.md](dynroute-contract.md) §2/§4；入口模块不再自己查表。

**托管 WAF 顺序（D11，与 v7 相同，PoC §5 第 5 条）**：CC（`server_rewrite`）→ ModSecurity phase 1（档位 location 的 REWRITE 处理器建事务）→ 规则计划（档位 location 的 `rewrite_by_lua`，`client_pass()` 为真）→ ModSecurity phase 2（PREACCESS，请求体）→ `access()`（防火墙动作 → 挑战 → HTTP 策略 → 回源 → 缓存派发）。`location /` 不开 ModSecurity；无托管 WAF 的站点不经档位 location。

**当前行为**：`server_rewrite()` = `cdnca_site.route()`（未就绪 503、未知 Host 且非节点级路径 421）→ `cdnca_tls.request(site)` → `cdnca_security.server_rewrite`（CC）；`rewrite()` → `cdnca_managed_waf.rewrite`（D11：托管 WAF 站点 `ngx.exec` 进档位 location，ModSecurity phase 1 在那里跑，然后本阶段再跑）→ `cdnca_security.rewrite`（ACL/WAF 规则计划）；`access()` → `cdnca_security.access`（防火墙动作 → JS 挑战 → HTTP 策略）→ `cdnca_origin.access()`（写 `$cdnca_origin_*`，含客户端地址头）→ 缓存派发；缓存变体的内部跳转不重跑安全阶段。`balancer()` → `cdnca_origin.balancer()`；`header_filter()` → TLS、回源 Location 改写、HTTP 策略响应头、缓存；`log()` → 回源、CC 计数。详见 dynroute-security.md。

**D9/D10 增补**（[dynroute-filters.md](dynroute-filters.md)、契约附录 A）：`server_rewrite()` 在 TLS 判定后先 `cdnca_limits.traffic`（站点流量超限页），CC 之后 `cdnca_limits.refuse/rate` 再 `cdnca_filters.routed()`；`access()` 第一步 `cdnca_limits.enter()`（套餐连接数）；`header_filter()` = 回源 Location 改写 → `cdnca_filters.header_filter()` 五槽（错误页 → HTTP 策略（`cdnca_security.header_filter` 注册为槽 2）→ 缓存命中头 → HSTS → Alt-Svc）；`body_filter()` → `cdnca_filters.body_filter()`；`log()` 先 `cdnca_limits.leave()`。

**智能自动防御（AD-04）**：`Input.AutoDefense` 时 http 级渲染两个定长字典 `cdnca_autodefense` 64m（agent 写的门控：站点、处置条目、平台白名单、collector 路径）与 `cdnca_autodefense_count` 32m（秒级计数，定长键 + 3 秒 TTL），控制套接字加 `location ^~ /autodefense/`（`cdnca_autodefense.admin()`）。写满时 shdict 按 LRU 淘汰，任何写都不报错。`access()` 在安全决策之后、302 调度与回源选择之前调 `cdnca_autodefense.access`（白名单 → 处置表 → 签名 IR）；`log()` 在 CC 计数之后、遥测之前调 `cdnca_autodefense.log`（pcall 隔离）。每 worker 每秒经 agent 的 unix 套接字推送一帧，失败即丢弃。验收 `edge/openresty/dynroute/autodefense_test.sh`。

**HTTP 302 调度**：`Input.Schedule302`（`Schedule302FromSites`：任一站点对象带 `schedule302`）时，每个明文共享 server 加 `set_real_ip_from 127.0.0.1/::1; real_ip_header X-Cdnca-S302-Client`、节点级 `location ^~ /_cdnca302/`（`cdnca_sched302.land`，验签后经 `@cdnca_sched302_land` 回环到同端口，Host/URI 还原为原请求并带令牌与客户端地址）；`$cdnca_node_location` 放行 `/_cdnca302/`（落地 Host 是节点地址，不是站点）；http 级 `cdnca_sched302_sizes` 字典、`sched302/` Lua 路径、`configure{schedule302_table=<state>/schedule302/table.json}`；变量 `$cdnca_sched302_{host,uri,port,token,client}`。`access()` 在安全决策（防火墙/挑战/HTTP 策略）之后、回源选择之前调 `cdnca_sched302.access`（302 即结束请求；带令牌的落地请求验签后就地服务、不再跳），`log()` 在 CC 计数之后调 `cdnca_sched302.log`（学习大小）。验收 `tests/dynroute-sched302/run.sh`。

## 4. 共享字典档位

每键一个 128 B slab 槽（16 B 键 + 32 B 值，PoC §1），档位容量按 80% 填充（余量 25%）：

| 档 | 字典 | 最多索引键 |
|---|---|---|
| 1 | 4m | 26,214 |
| 2 | 16m | 104,857 |
| 3 | 64m | 419,430 |
| 4 | 160m | 1,048,576（100 万键） |
| 5 | 640m | 4,194,304 |

`SelectIndexTier` 取能装下的最小档，超出最大档拒绝渲染。同名同尺寸 reload 保留字典内容（实测索引与就绪标记 reload 后仍在）；换档 = 改尺寸 reload = 字典清空，由 D3 从整代索引文件分片重建（每 1000 条让出）。只能用 `safe_set`/`safe_add`。

## 5. 验收与实测

- Go：`go -C libs/edgeconfig test ./edgeskeleton/`（确定性、端口形态、h2 按端口、quic、keepalive 0、变量声明、系统配置、16 类非法输入、档位、1 万站）。
- 真实 OpenResty：`ONLY=skeleton tests/dynroute-tls/run.sh`（渲染器原样输出的骨架 + D3 激活器 + D5a 回源，一个 `--rm --network none` 容器，2 worker；29 项，选中站点经 cdnca_origin 回源到 mock 源站 200）：三端口骨架（18080 明文 / 18443 TLS h2 h3 双栈 / 18444 TLS 无 h2 仅 IPv4）与 1 万站端口表 `nginx -t`；激活前 503 且握手拒绝；激活后按 SNI 出证书（h1/h2/h3、通配、IPv6）、18444 ALPN=http/1.1 且无 IPv6、其他端口的 SNI/未知 SNI/无 SNI 拒绝、未宣告 h3 的站点拒 QUIC；SNI≠Host 按 Host（Alt-Svc 随 Host 站点）；未知 Host 421；多 worker 200 个新 QUIC 连接、reload 后 1 s 内 100 个全部成功；reload 保留索引；error.log 除已知 reload 噪声外无 alert/crit/emerg/error。（原 `tests/edge-skeleton/real-openresty.sh` 按 D2 字典手工种索引，已由本用例取代并删除。）

实测（本机 arm64 Docker Desktop，机器同时有其他任务，耗时只作量级）：

| 项 | 1 万站（3 端口，42,000 索引键） | 三端口夹具 |
|---|---|---|
| 端口表 `FromSites` | 12–20 ms | — |
| 骨架渲染 `Render` | 25–37 µs | — |
| nginx.conf 大小 | 5,839 B（档位 16m） | 5,859 B（档位 4m） |
| `nginx -t`（含 docker exec 约数十 ms） | 67–127 ms | 63–139 ms |
| master VmRSS | 约 3.2 MB | — |

骨架大小与耗时只随端口数和 zone 数变化，与站点数无关；对照 v7 的 5000 站 `nginx -t` 64 s、每 server 约 78 KiB（ADR 0009 §2）。

## 6. 后续任务接口（不在 D2）

- agent：调用 `Render`（输入来自本节点全部 scope 的站点对象 + 系统配置），骨架变化才 `nginx -t` + reload；用 `siteindex.Activator` 激活（D3 已实现）；之后才把 `edgeconfig.MaxSiteRuntimeVersion` 提到 9、agent 声明 9。
- D4：证书与 client hello 协议；D5：balancer/回源 TLS/keepalive 键；D6：规则解释器；D11：托管 WAF（已做：`Input.ManagedWAF` 渲染 `load_module`、http 级节点规则、每档一个命名 location `@cdnca_waf_<key>`（`modsecurity on` + 档位规则 + `modsecurity_transaction_id $cdnca_waf_txid` + 与 location / 相同的回源体），location / 不开引擎；dynroute-managed-waf.md）；错误页 filter、缓存变体命名 location、`proxy_request_buffering` 变体、节点级 location、`stream{}`、mux 内部套接字（`proxy_protocol` 监听与 `set_real_ip_from unix:`）各自加进渲染器。
