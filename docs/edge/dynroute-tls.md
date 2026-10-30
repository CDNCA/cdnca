# 动态路由 TLS 入口（D4）

- 实现：Lua `edge/openresty/dynroute/cdnca_tls.lua`（节点路径 `/usr/local/share/cdnca/dynroute/cdnca_tls.lua`，`require("cdnca_tls")`）；Go `agents/edge-agent/internal/dyntls`（证书池、OCSP、占位证书）；站点对象字段 `libs/edgeconfig/edgesite`（`TLS`、`ClientAuth`）。与本文不一致时以代码和测试为准。
- 依据：ADR 0009 §3.2 第 1–2 步、[0009-poc-results.md](../adr/0009-poc-results.md) §2、[dynroute-contract.md](dynroute-contract.md)（D3 冻结契约，本任务未改）、BATCH-PLUGIN 第 12 条（SNI≠Host 按 Host 选站，不回 421）。
- 只依赖 `cdnca_site` 的 `lookup`/`current`/`object` 与 `$cdnca_site_*`，不写任何 `cdnca_site_*` 变量或字典。

## 1. 骨架接线（给 D2 对齐 D3 时照写）

每个 TLS 端口的共享 server：

```nginx
ssl_protocols TLSv1.2 TLSv1.3;                 # QUIC 要求含 1.3；站点在 client hello 收窄/放宽
ssl_certificate     <state>/placeholder.crt;   # dyntls.WritePlaceholder，CN/SAN fallback.invalid，永不下发
ssl_certificate_key <state>/placeholder.key;
ssl_client_hello_by_lua_block { require("cdnca_tls").client_hello() }
ssl_certificate_by_lua_block  { require("cdnca_tls").certificate() }
server_rewrite_by_lua_block {
    local site = require("cdnca_site").route()
    if not site then ... reject_unknown / 节点级 location ... return end
    require("cdnca_tls").request(site)          -- 紧跟 route()，CC 等之前
}
header_filter_by_lua_block { require("cdnca_tls").header_filter() }   -- 错误页替换之后（PoC §4 第 2 条）
```

http 级 `init_by_lua` 在 `cdnca_site.configure` 之后：`require("cdnca_tls").configure({ pool_root = "<state>/tls-pool", lru_items = N, ocsp_refresh = 60, negative_ttl = 1 })`。明文端口也调 `request()`/`header_filter()`（两者对明文是空操作），骨架不必区分。

骨架（`edgeskeleton` + `cdnca_dynroute.lua`）已按 D3 §6 对齐并接入本模块：`cdnca_dynroute.configure/client_hello/certificate/server_rewrite/header_filter` 依次委托 `cdnca_site`/`cdnca_tls`，`configure` 的 `tls_pool_root` = `<StateRoot>/tls-pool`（见 node-skeleton.md §2）。

## 2. 各阶段行为

| 阶段 | 做什么 | 失败 |
|---|---|---|
| client hello（每个连接，含会话恢复） | SNI 规范化（小写、去一个尾点）→ `cdnca_site.lookup(port, sni)`；站点在该端口必须有 TLS 监听；取证书版本（LRU）并检查有效期；QUIC 握手（ClientHello 带扩展 57）要求该站监听 `http3`；TCP 上按站点 `set_protocols`（非默认 1.2+1.3 时）与 `SSL_set_cipher_list`（`cipher_profile`）；设会话 ID 上下文 | 未知/无 SNI、未就绪、无 TLS 监听、证书缺失/未生效/过期、h3 未宣告 → `ngx.exit(ngx.ERROR)` 拒绝握手 |
| certificate | 无条件 `clear_certs` + 站点证书链与私钥（LRU）；`ocsp_stapling` 时从池读 `.ocsp`，`ngx.ocsp.validate_ocsp_response` 校验后 `set_ocsp_status_resp`；`client_auth` 时按 CA 对象摘要取 CA 链（`cdnca_site.object`）调 `ngx.ssl.verify_client(ca, depth)` | 设证书失败、CA 对象缺失 → 拒绝握手；OCSP 无效只是不 staple |
| server_rewrite `request(site)` | 按 Host 选中的站（不是 SNI 的站）检查本连接是否满足它的 TLS 设置；再执行客户端证书判定 | 见 §3 |
| header_filter | 选中站点在本端口 `http3` → `Alt-Svc: h3=":<端口>"; ma=86400`（与 v7 同值）；按 Host 站点决定 | — |

**会话 ID 上下文**（32 字节 = md5(site_id ‖ 证书版本) ‖ md5(客户端认证设置)）：OpenSSL 只在同一上下文下恢复会话。实测不设时，a.test 的 TLS 1.2 票据在 SNI=b.test 时被恢复（`resumed=true`），且恢复的连接跳过证书阶段（PoC §2）——等于用 a 的会话进 b。设了之后 TLS 1.2/1.3 都不跨站恢复（验收 `no-resume-across-sites-*`），换证书版本也开新会话。站点删除/停用后 client hello 的 `lookup` 拒绝，持票据也恢复不了。

**为什么请求期还要判 mTLS**：ngx_lua 的 `verify_client` 回调永远不终止握手（`ngx_http_lua_ssl_verify_callback` 恒返回 1，结果只体现在 `$ssl_client_verify`），所以 required 必须在请求期执行，否则失效打开。

## 3. SNI 与 Host 不一致

按 Host 选站，**不回 421**（BATCH-PLUGIN 第 12 条；与 v7 现状一致，金标 `sni-shop-host-blog-*` 相同）。只有连接本身不满足 Host 站点的 TLS 设置时回 421（只有 HTTP/2、HTTP/3 连接合并能造成），客户端会为该名字新开连接：

- HTTP/3 连接进了没宣告 h3 的站；
- 协商的 TLS 版本不在 Host 站点的 `protocols` 里（如 1.2 连接进只开 1.3 的站）；
- Host 站点要客户端证书，而握手是按 SNI 站点的另一套客户端认证做的（会话上下文后半段不等）——nginx 自己在 `ssl_verify_client` 时对 SNI≠Host 也回 421（`ngx_http_request.c`）。

客户端证书判定：required 且没发 → 496，校验失败 → 495；nginx 都用自己的 400 页（“No required SSL certificate was sent” / “The SSL certificate error”），与 `ssl_verify_client on` 相同。optional 只拒校验失败的。

Host 指向未知站点仍是 421（`cdnca_site` 的 `unknown`，与 v7 默认 server 相同），不受本节影响。

## 4. 站点对象字段（`listeners[].tls`，`cdnca.edge.site/v2`）

字段与 ge-tls（9532d64c，主控/库/页面模型的所有者）逐字节相同，规范是 `libs/edgeconfig/site_tls_profile.go` 的 `TLSProfile`（v7 渲染器与本模块执行同一份定义）：

| 字段 | 含义 | 校验 / 节点执行 |
|---|---|---|
| `certificate_version_id` | 证书版本（池文件名） | UUID |
| `protocols` | TLSv1..TLSv1.3 的**升序连续区间**（`ValidateSiteTLSProtocols`） | `http3` 要求含 TLSv1.3；含 TLSv1/1.1 要求 `cipher_preset = legacy`；节点非 1.2+1.3 时 `set_protocols` |
| `cipher_preset` | `""`=modern / `compatible` / `legacy`（写 `modern` 字样被拒，规范形是空） | 节点每个 TCP 握手 `SSL_set_cipher_list(TLSCipherList(preset))`，compatible/legacy 开 `SSL_OP_CIPHER_SERVER_PREFERENCE`（= `ssl_prefer_server_ciphers on`）；TLS 1.3 套件 OpenSSL 默认 |
| `ocsp_stapling` | 客户端请求时 staple 当前 OCSP 响应 | 响应来自证书池 `.ocsp`（§4.1） |
| `client_auth` | `optional` / `required`（`off` 写成缺省） | 证书阶段 `verify_client(CA, 3)`（= `ssl_verify_depth 3`）；请求期执行与 X-Client-* 头见 §2/§3 |
| `client_ca` | `Ref{kind: client_ca, id, revision, sha256}`，`client_auth` 开时必有 | CA PEM 包在 worker 可读对象目录（D3 §5.5），`cdnca_site.object` 读 |

mTLS 结果：**所有站点**（含明文监听、未开 mTLS 的 TLS 监听）在 `request()` 第一步删掉客户端自带的 `X-Client-Verify`、`X-Client-Cert-Fingerprint`、`X-Client-Cert-Subject`；只有开了 `client_auth` 的站再按握手结果写入（`$ssl_client_verify`、`$ssl_client_fingerprint`、`$ssl_client_s_dn`，空值不写）。这是对 v7 的安全修正：v7 只给开了 mTLS 的站写 `proxy_set_header`，其余站透传客户端的值，客户端可伪造 `X-Client-Verify: SUCCESS` 骗依赖它鉴权的源站；已登记 compare.json，v2 渲染路径由 ge-tls 同步修。

### 4.1 与 ge-tls 的分工

1. 主控、站点库、页面、v2 文档与 v7 渲染归 ge-tls；动态路由站点对象生成器（`edgepublish/site_objects_v2.go` `convertSiteListenerV2`）在 ge-tls 合入后映射 `cipher_preset/ocsp_stapling/client_auth/client_ca`，客户端 CA 作为 `client_ca` 被引用对象（ge-tls 发布时是 release 文件 `client-ca/<sha256>.pem`，摘要相同）。
2. OCSP 响应**不进站点对象**（每几小时变一次，进对象会让站点对象摘要随之变化、触发重新发布）。ge-tls 的 v7 路径用 nginx `ssl_stapling`（节点自己向 responder 取）；动态路由没有 nginx 内置取数，由 agent 按证书版本获取后写 `dyntls.Pool.PutOCSP`（校验签名、`good`、未过期后原子替换 `<pool>/<version>.ocsp`，Lua 最多 `ocsp_refresh` 秒后生效）。获取器见 §5。stapling 要求证书链里带签发者（无签发者拒绝，nginx/ngx_lua 同样按链里第二张校验）；Let's Encrypt 2025 起证书不含 OCSP URL，此时没有可取的响应、不 staple（ge-tls 已在页面说明）。
4. HSTS 不属 TLS 入口（响应头），走 HTTP 策略或 ge-access。

主控 v2 站点对象生成器（`edgepublish/site_objects_v2.go` `convertSiteListenerV2`）目前只映射 `certificate_version_id` 与 `protocols`，新字段由 ge-tls 接入时一并映射并登记覆盖表。

## 5. 证书池（`internal/dyntls`）

`<state>/tls-pool/<版本>.crt|.key|.ocsp`：目录 0750、文件 0440、组 = worker 组（与 v7 懒加载证书池同一取舍：worker 可读私钥）。`.crt/.key` 按版本不可变（同版本不同内容拒绝，先写 key 再写 crt）。

agent 侧（`internal/dyntls/sync.go`，由接 agent 激活流程的任务按此顺序调用）：

1. `Pool.Sync(ctx, certstore.Manager, sites)`：在 `siteindex.Activator.Activate` **之前**，把站点 TLS 监听引用的证书版本从 certstore（agent 私有 0400）复制进池：对站点每个名字调 `ResolveCertificateVersion`（同 v7 编译器的核对），按 certstore 记录的摘要校验文件、`ParseChain` 校验链与私钥；池里已有的版本不再复制。取不到的版本（缺失、不在有效期）列进 `Unavailable` 返回、不中断激活——节点对该站拒绝握手，与 v7 对该站 `ssl_reject_handshake` 同结果。
2. 激活成功后 `Keep(当前代版本, 上一代版本)` 同时交给 `Pool.Retain`（删其余版本及其 `.ocsp`）与 `certstore.SetCertificateVersionReferences`（让 certstore 也保留回滚目标）。
3. `Pool.RefreshOCSP(ctx, HTTPFetcher{}, versions, now)` 定时（建议每 10 分钟）跑：只处理有监听开 `ocsp_stapling` 的版本；已存响应过了一半有效期（最长 12 h）才重取；向证书 AIA 里的 responder `POST`（RFC 6960 A.1）；新响应经 `PutOCSP` 校验后替换。取数失败保留仍有效的旧响应；responder 签名的 `revoked` 立即删除（不再 staple 旧的 good）；过期删除；关掉 stapling 的版本删除；证书无 responder（LE 2025 起）返回 `ErrNoResponder`，不 staple。站点证书吊销本身由主控处理（换版本/停用），节点不据 OCSP 拒握手。
   ge-tls 在 v7 路径用 nginx 自带 `ssl_stapling` 由节点直连 responder，没有主控预取；以后若加主控预取，只需另写一个 `Fetcher`，`RefreshOCSP` 不变。

Lua 侧：worker LRU 按证书版本缓存解析结果（`parse_pem_cert/priv_key`、DER 链、有效期）；读不到的版本负缓存 `negative_ttl` 秒。版本不可变，所以没有失效问题；切换证书 = 站点对象换 `certificate_version_id`，新连接立即生效，在途连接不受影响。

## 6. 与 v7 的行为差异（已登记 `tests/edge-golden/cdnca-v7/compare.json`）

- 客户端自带的 X-Client-Verify/-Cert-Fingerprint/-Cert-Subject：v7 对未开 mTLS 的站透传到源站，动态路由一律删除（安全修正，§4）。

- 未知/无 SNI 的 alert：v7 懒加载套接字 `ssl_reject_handshake` 发 `unrecognized_name`；ngx_lua client hello 回调失败只能让 OpenSSL 发 `internal_error`（没有设 alert 的接口）。共享 server 上不能用 `ssl_reject_handshake`（会拒绝所有名字）。都是致命握手失败，客户端不重试。
- v7 非懒加载端口上未知 SNI 落到该端口第一个站点证书（ADR 0009 §6），动态路由一律拒绝（ADR 已列为已知语义变化）。
- 新增能力（v7 无）：按站点 TLSv1/1.1、套件预设、OCSP stapling、mTLS、QUIC 只服务宣告 h3 的站点。

## 7. 验收与实测

- Go：`go -C libs/edgeconfig test ./edgesite/`（TLS 字段接受/拒绝用例）、`go -C agents/edge-agent test ./internal/dyntls/`（池、OCSP 校验、回收、占位证书）。
- 真实 OpenResty：`tests/dynroute-tls/run.sh`（OpenResty 1.31.1.1 节点运行时镜像、h3probe，一个 `--rm --network none` 容器，2 worker），98 项全过（握手 71 项 + 渲染器原样骨架 27 项，骨架用例的证书经真实 certstore + `Pool.Sync` 进池，客户端 CA 在首次激活（冷启动重建）前放入、未被回收）：TLS/h2/h3 按 SNI 出证书（精确、通配、多级、大小写+尾点、IPv6）；未知/无 SNI/通配不配裸域/其他端口的名字/占位名全部拒绝握手（< 2 ms，不下发占位证书）；SNI≠Host 按 Host（h1/h2/h3）；各种合并 421；Alt-Svc 只给宣告 h3 的 Host 站；TLSv1/1.1（compatible）、1.2-only、1.3-only、modern 拒 CBC；h3 拒未宣告站点；会话票据同站恢复、不跨站；mTLS required/optional/陌生 CA 与 X-Client-* 回源头（开 mTLS 的站覆盖伪造值，未开的站与明文监听删除伪造值）；OCSP stapling 与校验；证书切换期间 8 并发约 1000 个新连接零失败、在途 h2 连接保持旧证书、新连接与 h3 立即新证书；过期/未生效/缺文件拒绝且不影响其他站；error.log 无 alert/crit/emerg/error。
- 金标：`CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check tls-sni-host,host-routing,tls-profile`：host-routing、tls-profile 相同；tls-sni-host 0 缺陷、2 项登记差异（§6 第一条）。D4 期间的替身渲染器 cdnca-d4tls 已在 D13-c 删除，证书场景走 cdnca-dynroute 的生产转换路径（证书进 tls-pool）。
- 规模：`SCALE=10000 ONLY=scale [WORKERS=1|2] [CERT_LRU=N] tests/dynroute-tls/run.sh`。1 万站各一张证书、一个 TLS 端口、8 并发新连接（TLS 1.3 握手，不发请求）。本机 arm64 Docker Desktop，测试时 load 18–48（其他任务并行），耗时只作量级：

| 情形 | LRU 命中率 | 握手 p50 / p99 | 吞吐 | 未命中加载耗时 |
|---|---|---|---|---|
| 1 worker，LRU 1 万，冷（每站一次） | 0% | 4.2 / 16 ms | 1479/s | 0.31 ms/次 |
| 1 worker，LRU 1 万，暖（每站再一次） | 100% | 2.0 / 9.2 ms | 3023/s | — |
| 1 worker，LRU 1 万，热点 1000 站 × 2 万次 | 100% | 2.3 / 9.6 ms | 2820/s | — |
| 1 worker，LRU 1 万，单客户端顺序 | 100% | 0.48 / 3.4 ms | 1415/s | — |
| 2 worker，LRU 1 万/worker，暖 | 51.5%（每 worker 各一份 LRU，首次落到另一 worker 的站要再加载一次） | 8.1 / 49 ms | 759/s | 1.45 ms/次 |
| 2 worker，热点 1000 站 | 97.5% | 6.0 / 48 ms | 931/s | — |
| 1 worker，LRU 2000 < 工作集 1 万，暖 | 0%（顺序扫描超过 LRU 容量全部淘汰） | 6.6 / 30 ms | 1000/s | 0.47 ms/次 |
| 1 worker，LRU 2000，热点 1000 站 | 95.8% | 5.7 / 38 ms | 1082/s | 0.8 ms/次 |

结论：证书 LRU 命中时握手比未命中快约一倍（加载 = 读两个文件 + 解析 PEM/私钥 + x509 有效期，0.3–1 ms）；LRU 是 worker 级，按“节点活跃站点数”而不是 worker 数配（默认 1 万/worker，每项约几 KB，几十 MB 量级）；工作集大于 LRU 时命中率按访问分布退化，冷站多的节点应配更大的 LRU 或接受首握手多 0.3–1 ms。2 worker 数据受机器高负载影响明显（单客户端顺序 p50 从 0.48 ms 变 4.2 ms），需在独立测试机复测。

## 8. 遗留

1. agent 激活流程（谁在什么时候调 `edgeskeleton.Render`、`Pool.Sync`、`siteindex.Activator.Activate`、`Retain`、`RefreshOCSP` 定时）尚未接入 daemon：属接 agent 的任务（与 D3 遗留“未接 agent daemon”同一处）。本任务提供并单测了各步，真实 OpenResty 验收直接调用它们。
2. 主控站点对象生成器映射 ge-tls 新字段：等 ge-tls 合入（字段已逐字节对齐，见 §4.1）。
3. 不做：TLS 1.3 early data / QUIC 0-RTT（当前未开）与 QUIC 连接迁移下两个 SSL 回调的行为（PoC §7 同样未覆盖）。
4. ngx_lua client hello 拒绝的 alert 只能是 internal_error（§6）；要 unrecognized_name 需改 ngx_lua（补丁），收益仅日志/诊断。
5. 节点级 location（健康、ACME overlay、市场探测、基准对象）未进骨架，`$cdnca_node_location` 表为空，未知 Host 一律 421（各自任务加）。
