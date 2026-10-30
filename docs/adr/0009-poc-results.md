# ADR 0009 §8.5 开工前 PoC 结果

- 日期：2026-10-17；基线：197697d9。
- 运行时：本仓 `edge/openresty/native/Dockerfile --target runtime` 现编的真实节点运行时（OpenResty 1.31.1.1 = nginx 1.31.1、ngx_lua 0.10.31rc5、lua-resty-core 0.1.34rc3、lua-resty-openssl 1.7.1、OpenSSL 3.5.8，补丁 01–23）；托管 WAF 用 `scripts/security/modsecurity-runtime.sh` 为 nginx 1.31.1 现编的 libmodsecurity 3.0.17 + ModSecurity-nginx 1.0.4，规则 OWASP CRS 4.30.0。
- 复跑：`tests/dynroute-poc/run.sh [build] [shdict quic origintls errorpage modsec]`（每个场景一个 `--rm --network none` 容器，结束即删；共享机器上设 `DYNROUTE_POC_WRAP` 为排队脚本）。客户端/模拟源站/测试证书是 `tests/dynroute-poc/probe`（每次运行现生成证书）。
- 环境限制：本机 arm64（Docker Desktop VM，10 vCPU / 8 GiB），测试时机器上同时有其他任务（load 10–18），**耗时类数据两次运行相差约 2 倍**，下文给区间；内存、行为类结论不受影响。
- 最后一次全量运行：5 个场景 175 PASS、0 FAIL、7 个已知差异（§4）。

| 项 | 结论 | 对设计的主要影响 |
|---|---|---|
| 1 共享字典 100 万键 | 可用，不换索引层 | 值改为二进制单摘要（128 B/键，100 万键约 122 MiB）；重建必须分片让出；字典只能用 `safe_set` |
| 2 QUIC 下 SSL 阶段 | 两个回调在 QUIC 上与 TCP 行为一致，可 yield | 只开 TLS 1.2 的站点不能宣告 h3；会话恢复不进证书回调，站点存在性检查要放 client hello |
| 3 回源 TLS 按池 CA | 可行，但要整条对端链 + 三处配置缺一不可 | 发现 keepalive 跨信任复用连接的安全缺陷，给出键含信任锚的修法 |
| 4 错误页 filter | 与 v7 逐字节等价（含部分体、chunked 截断、h2） | 必须清掉全部源站头而不是只清长度；HEAD+gzip 一处已知差异 |
| 5 托管 WAF 共享 server | §9 问题 3 方案 a 可行：PL/阈值/模式/规则集/排除都可按请求生效 | 上下文经事务 ID 传入；几项 Sec*Limit 只能节点级档位 |

## 1. 共享字典 100 万键：内存与冷启动重建

**做法**（`shdict.sh`）：单 worker、256m 字典，每次全新启动后写 10k/50k/100k 个键，量 `capacity − free_space` 与该映射在 `/proc/self/smaps` 的 Rss；5 种编码（键 = 端口+域名，或其 md5）：`json`（ADR §8.2 原样 `{gen_a,gen_b}` 十六进制）、`binary`（两个 32 B 摘要）、`md5`（16 B 键 + 两个摘要）、`single`（16 B 键 + 当前代 32 B 摘要）、`compact`（两个截断 16 B 摘要）。再把 100k 条写成“整代索引文件”（每条 u16 键长、u16 值长、键、值），清空字典后在 timer 里持 `resty.lock` 重建，同时用另一客户端对同一 worker 连续请求测卡顿。

**外推方法**：内存 = 100k 实测 + （100k−10k 的边际每键字节）× 90 万；重建 = 100k 的每条耗时 × 100 万，再按红黑树深度乘 log2(10⁶)/log2(10⁵) = 1.2 作上界。

**数据**

| 编码 | 键/值字节 | 每键占用（10k/50k/100k） | 边际每键 | 100 万键估算 | 查找（命中，µs） |
|---|---|---|---|---|---|
| json | 36 / 151 | 256 / 256 / 256 | 256 | 244 MiB | 1.3–7.8（含 cjson 解码） |
| binary | 36 / 64 | 256 / 256 / 256 | 256 | 244 MiB | 0.6–1.7 |
| md5 | 16 / 64 | 256 / 256 / 256 | 256 | 244 MiB | 0.5–2.5 |
| single | 16 / 32 | 128 / 128 / 128 | 128 | 122 MiB | 0.3–0.4 |
| compact | 16 / 32 | 128 / 128 / 128 | 128 | 122 MiB | 0.3–0.4 |

- 每键占用是台阶：节点头 = `offsetof(rbtree,color)`(32) + `offsetof(shdict_node,data)`(36) + 键 + 值（`ngx_http_lua_shdict.c:870-873`），slab 按 2 的幂取整（`ngx_slab.c:209-211`）。键+值 ≤ 60 B 落 128 B 槽，61–188 B 落 256 B 槽。Rss 每键与 slab 统计一致（256.9 / 128.1 B），没有额外隐藏开销。
- 未命中（精确 + 3 次通配探测）1.3–10.7 µs/次。
- 重建 100k 条：89–138 ms（不让出）、97–212 ms（每 1000 条 `ngx.sleep(0)`）；外推 100 万：**约 0.9–2.1 s，上界 2.5 s**。索引文件 52 B/条，100 万条约 50 MiB。
- 重建期间同 worker 请求：不让出时最大卡 98–154 ms（外推 100 万约 1–1.5 s）；每 1000 条让出时最大 14–26 ms，p50 0.03–0.06 ms，p99 0.2–1 ms；分片 5000 条时单片 9–32 ms。
- 同名同尺寸 reload 后字典内容保留；改尺寸 reload 后清空（对应 `ngx_cycle.c` 共享区复用条件）。
- 字典满时 `safe_set` 返回 `no memory`；`set` 静默淘汰最久未用的键（`forcible=true`，第一个键丢失）。

**结论**：100 万键在共享字典里可行，不需要 LMDB。ADR §8.2 写的 JSON 十六进制双代值是最贵的形态（244 MiB），且每次查找要解 JSON。

**对设计的影响**
1. 索引值改二进制：键 `md5(端口\0小写域名)`（16 B），值 = 当前代站点对象 32 B 摘要，正好 128 B 槽，100 万键约 122 MiB。上一代不放每个键里：激活时把本次变更键的旧值记入一个小字典（只含变更集），回滚 = 写回这些旧值并改回代指针；整代丢失时从上一代索引文件重建。若坚持每键双代，就是 256 B/键（244 MiB），也可接受，但没有收益。md5 碰撞由站点对象自带域名清单在读取时复核兜底。
2. 字典尺寸按“键数 × 128 B × 1.25 余量”分档（100 万键配 160m），只用 `safe_set`/`safe_add`，任何 `no memory` 都使本代激活失败；监控 `free_space`，低于余量即告警并按档位扩容（扩容 = 改尺寸 reload = 重建）。
3. 冷启动重建必须分片让出（建议 1000 条/片），并且重建完成前对未命中返回 503“未就绪”而不是 421，代健康报告在重建完成后才算。
4. 只有改尺寸才需要重建；骨架 reload 不丢索引（与 ADR 一致）。

## 2. QUIC / HTTP/3 下的 `ssl_client_hello_by_lua` 与 `ssl_certificate_by_lua`

**做法**（`quic.sh`）：一个共享 server 同端口 `listen … ssl` + `listen … quic reuseport`，`http2 on; http3 on;`，占位证书 `fallback.invalid`（证书阶段总是清掉换成站点证书）。client hello 按 SNI 查站点（精确 → 最长前导通配）、未命中 `ngx.exit(ngx.ERROR)`、按站点 `clienthello.set_protocols`；证书阶段按 SNI 取证书（worker 内缓存解析结果），轮换站点从共享字典读证书版本。客户端是 quic-go 0.54 的 h3 与 Go 的 h1/h2。用 ClientHello 里是否有 quic_transport_parameters 扩展（57）区分 QUIC/TCP 计数。

**数据**（46 项全过，h1/h2/h3 各自核对）

| 场景 | TCP（h1/h2） | QUIC（h3） |
|---|---|---|
| 两个回调各触发次数（每个新连接） | 1 / 1 | 1 / 1 |
| `ngx.ctx` 从 client hello 带到证书阶段 | 是 | 是 |
| 按 SNI 动态证书；通配 / 多级子域落最长通配；`*.w.test` 不匹配 `w.test` | 正确 | 正确 |
| 未知 SNI / 无 SNI | 握手失败（TLS alert internal_error），1.4 ms | 握手失败（CRYPTO_ERROR 0x150），1.8 ms，不是超时 |
| 两个阶段各 `ngx.sleep(0.2)` | 410 ms 完成 | 417 ms 完成 |
| 只开 TLS 1.2 的站点 | 只协商 1.2，拒绝只支持 1.3 的客户端 | **必然失败**（CRYPTO_ERROR 0x146 protocol_version） |
| 证书轮换（改字典，不 reload） | 在途连接 3 次请求保持旧证书不断；新连接立即新证书 | 同左 |
| 会话恢复（第二个连接） | 恢复成功；client hello 触发、证书回调**不触发** | 同左 |
| Alt-Svc 只给宣告过的站点 | — | header_filter 按站点加，正确 |
| SNI=a、Host=b | 按 Host 路由到 b，200 | 同左 |
| 占位证书被下发 | 0 次 | 0 次；error.log 无 alert/crit/emerg |

源码依据：QUIC 握手在 `ngx_event_quic_ssl.c:696-727` 把 `SSL_ERROR_WANT_X509_LOOKUP`/`WANT_CLIENT_HELLO_CB` 当作非致命；OpenResty 自带的 QUIC SSL yield 补丁（`ngx_config.h:21` `HAVE_QUIC_SSL_LUA_YIELD_PATCH`）让 Lua 恢复后由 `ngx_http_lua_resume_quic_ssl_handshake`（`ngx_http_lua_util.c:4634-`，调用点 `ssl_certby.c:395-399`、`ssl_client_helloby.c:397-400`）重新推进握手。`listen … quic` 要求 server 的 `ssl_protocols` 含 TLSv1.3（`ngx_http_ssl_module.c:1450-1456`）。SNI 与 Host 不一致时，nginx 只在开了客户端证书校验时回 421（`ngx_http_request.c:2464-2469`），v7 与动态路由同样按 Host 选站。

**结论**：两个回调在 QUIC 上可用，行为与 TCP 一致，包括 yield。ADR §4 HTTP/3 行与 `ssl_protocols` 行的“未核实”可以去掉。

**对设计的影响**
1. 站点协议配置只含 TLS 1.2 时，主控应拒绝该站点开 HTTP/3（或节点不给它加 Alt-Svc）；开 HTTP/3 的端口骨架 `ssl_protocols` 必须含 1.3，站点级收窄在 client hello 做。
2. 会话恢复跳过证书回调：站点删除/停用/证书吊销必须在 client hello 阶段判定（查索引），不能只放证书阶段；否则持票据的客户端在站点删除后还能恢复会话。
3. 共享 TLS server 必须配占位证书（nginx 要求 `ssl_certificate`，`ngx_lua` 证书阶段要求 server 有 SSL_CTX，`ngx_http_lua_module.c:1396-1402`），证书阶段无条件 `clear_certs`；占位证书用不可解析的名字，便于发现失效打开。
4. SNI/Host 不一致（跨站域前置）与 v7 现状相同；若要禁止，在 `server_rewrite_by_lua` 比较 SNI 站点与 Host 站点，不一致回 421，成本是一次索引查找。这是产品决定，列入 §7 待定。
5. 证书阶段允许 yield，但索引与证书应来自字典/LRU，不做网络 IO。

## 3. 回源 TLS 按源站池用各自 CA 校验

**做法**（`origintls.sh`）：两个租户各一套根 + 中间 CA；7 个 HTTPS 模拟源站（A 正常带中间、A 不发中间、A 过期、A 域名不符、B 正常、**A 的 CA 给 B 的域名签的证书**、一个地址两个虚拟主机名）。一个动态 upstream + `balancer_by_lua`，池 = （地址、SNI、信任根）。校验：`proxy_ssl_verify on` + `lua_upstream_skip_openssl_default_verify on` + `proxy_ssl_verify_by_lua_block`：取叶证书（`proxysslverify.get_verify_cert`）和对端发来的链（`ngx.ssl.get_upstream_ssl_pointer` → `SSL_get_peer_cert_chain`），用该池的 `resty.openssl.x509.store` 校验，失败 `set_verify_result(28)`。单 worker，每个用例前 reload 保证新握手。

**数据**（21 项全过）

| 用例 | 结果 |
|---|---|
| A/A、B/B 正常；回调里拿到整条链（叶+中间 = 2） | 200 |
| 反向：B 的池遇到 A 签的 B 域名证书 | 502（`certificate verify error (28)`） |
| 反向：A 的根去连 B 的真实源站 | 502 |
| 不发中间证书 / 过期 | 502（与 nginx 静态信任库同语义） |
| 链有效但域名不符 | 502（nginx 自己的 `ngx_ssl_check_host`，`ngx_http_upstream.c:1883-1888`） |
| 校验回调里 `ngx.sleep` 让出 | 200 |
| 只用叶证书校验（不取对端链） | 正常源站也 502 |
| 反模式：各租户根并进节点级 `proxy_ssl_trusted_certificate` | A 签的 B 域名证书 **200** |
| 反模式：`proxy_ssl_verify off`，Lua 照样判拒绝 | **200**（没人执行结果） |

**发现的缺陷：upstream 连接复用跨信任边界。**

| upstream / keepalive 键 | 同地址同 SNI、信任不同的两个池（先 A 后 B） | 同地址不同 SNI |
|---|---|---|
| 不写 `keepalive`（nginx 1.29.7 起默认开，`changes.xml` 1.29.7 条目；按 sockaddr 匹配，`ngx_http_upstream_keepalive_module.c:236-245`） | B 复用 A 校验过的连接，**未经校验 200** | 第二个请求拿到第一个 SNI 的连接（**错虚拟主机**） |
| 显式 `keepalive 16` | 同上，泄漏 | 同上 |
| `keepalive 0` + `balancer.enable_keepalive`，键 = SNI（ngx_lua 默认，`ngx_http_lua_balancer.c:1464-1484`） | **泄漏**（键里没有信任） | 正确分开 |
| `keepalive 0` + `enable_keepalive`，键 = `SNI#trust=<锚>`，`proxy_ssl_name $真实SNI` | B 新建连接并被拒 502；同池仍复用 | 正确分开；源站收到的 SNI 是真实域名 |

**结论**：按池信任在 Lua 里可以完整实现，跨租户反向用例都被拒。三个条件缺一不可：`proxy_ssl_verify on`（只有它让 nginx 检查 `SSL_get_verify_result` 并做主机名检查，`ngx_http_upstream.c:1873-1888`）；Lua 必须拿对端链，不能只用 `get_verify_cert` 的叶证书；任何租户 CA 都不能进节点级信任库。

**对设计的影响**
1. 动态 upstream 必须写 `keepalive 0;`（关掉 nginx 按 sockaddr 的缓存），连接复用只用 `balancer.enable_keepalive`，并把信任锚（池 CA 集的摘要）编进 `set_current_peer` 的第三参（keepalive 键），真实 SNI 用 `proxy_ssl_name $cdnca_origin_sni` 放回（它在 balancer 之后求值并覆盖 `u->ssl_name`，`ngx_http_upstream.c:1937-1949`）。键里还应包含回源鉴权身份等任何“连接级”属性。
2. ADR §4 源站池行“keepalive 池键 = host(SNI) + sockaddr + 本地地址，不同 SNI/出口不会串池”只在第 1 条前提下成立，需改写；现有 `agents/edge-agent/internal/originroute/compile.go:59-61` 的动态 upstream 没写 `keepalive 0`（目前只用于基准 harness，明文回源，未出事），转生产时必须补。v7 编译器已因同一默认值写了 `keepalive 0`（`siteruntimev2/compiler.go:527-529`；v7 编译器已于 1.0.35 删除）。
3. 节点级 `proxy_ssl_trusted_certificate` 只放占位（nginx 要求，`ngx_http_proxy_module.c:5317-5321`），不能放任何租户 CA；`proxy_ssl_verify off` 的 location 不能挂校验回调（容易误以为已校验）。
4. lua-resty-openssl 1.7.1 的 `resty.openssl.ssl` 在 nginx 1.31.1 上不可用（`auxiliary/nginx.lua` 只认写死的 nginx 版本），对端链要直接 FFI `SSL_get_peer_cert_chain`；`x509.store` 按池 CA 摘要在 worker 内缓存。
5. ngx_lua balancer 设了 peer 后不做 TLS 会话复用（`ngx_http_lua_balancer.c:831-856` 两个 TODO），所以每个新回源连接都是完整握手并重新校验——安全上是好事，性能上要靠 keepalive，规模压测时要量。
6. `$request_id` 在没被配置引用时不建索引，`ngx.var.request_id` 每次走取值函数生成新值（实测同一请求 verify 阶段与 header_filter 阶段不同；取值函数 `ngx_http_variables.c:2298-2317`）；跨阶段关联要用自己声明的变量。

## 4. 错误页用 header/body filter 替换

**做法**（`errorpage.sh`）：同一 OpenResty 里三个 server 接同一模拟源站：v7（`proxy_intercept_errors on` + `error_page 403 404 500 502 @cdnca_error_page` + content 处理器，即 `compiler.go:691-720` 与 `errorpage/handler.lua` 的形态）、过滤器方式、只清 Content-Length 的“朴素”过滤器。站点有 403/404/500/502 页，410 无页。源站夹具：正常、带长度 404、空体 404、chunked 404、gzip 编码 404、宣称 1000 字节只发 10 字节就断（404 与 200）、chunked 一块后断、410、500；另有边缘自身产生的 403 与连不上源站的 502。每个路径 × GET/HEAD × 有无 `Accept-Encoding: gzip`，用原始套接字读回逐字节比较（状态、分帧、去掉 Date/Server 后的全部头、体）；再在 h2 上比状态、体摘要与流是否被 reset。边缘开 gzip。

过滤器方式（`tests/dynroute-poc/errorpage/poc_errorpage.lua`）：header_filter 里若状态有站点页，删除除边缘自身头以外的**全部**响应头（`ngx.resp.get_headers` 遍历），写页面头与 `Content-Length = #页面`；body_filter 第一次调用就输出页面并置 `ngx.arg[2] = true`（eof），之后的源站字节丢弃。

**数据**：h1 共 12 路径 × 2 方法 × 2 编码 = 48 个组合，41 个逐字节相同，7 个是同一已知差异；h2 14 项全同；无页状态码（410）透传源站体与头。

| 情形 | v7 与过滤器 |
|---|---|
| 带长度 / 空体 / chunked / gzip 编码的源站错误体 | 都换成站点页，长度分帧，相同 |
| 源站发了部分体就断（404partial、404chunkcut） | 都输出完整站点页、分帧完整（过滤器在首块就 eof，源站断开不影响客户端），相同 |
| 200 部分体就断 | 都透传 10 字节后截断（h1 截断、h2 流 reset），相同 |
| 边缘自身 403、连不上源站 502 | 都换成站点页，相同 |
| HEAD | 都只发头、`Content-Length` = 页面长度，相同 |
| **HEAD + Accept-Encoding: gzip（7 例）** | v7：`Content-Length: 23` 无 `Content-Encoding`；过滤器：`Content-Encoding: gzip` 无长度。状态、其余头、空体相同 |
| 朴素过滤器（只清长度） | 泄漏源站 `Set-Cookie`/`ETag`；gzip 编码源站 404 换成明文页后仍带 `Content-Encoding: gzip`（客户端会解压失败）；全变 chunked |

已知差异的原因：v7 的页面由 content 处理器发出，ngx_lua 在发头前把 HEAD 标成 header_only（`ngx_http_lua_util.c:585-587`），gzip 过滤器见 header_only 直接跳过（`ngx_http_gzip_filter_module.c:230-240`）；过滤器方式下 gzip 照常判断，结果与同一请求的 GET 一致。对 HEAD 客户端无可观察的体差异，判为可接受的语义变化。

**结论**：过滤器方式与 v7 等价，ADR §4 自定义错误页行的“未核实”可以去掉，但做法要比 ADR 写的“清 Content-Length”更严格。

**对设计的影响**
1. 替换时删除全部源站头（只留边缘自身产生的头），再写页面头与精确的 Content-Length；body_filter 首块即 eof。只清 Content-Length 会泄漏源站 Cookie/ETag 并造成错误的 Content-Encoding。
2. 页面 header_filter 必须排在其他会加头的 header_filter（HTTP 策略头、Alt-Svc、安全头）之前，或者那些头列入保留名单；动态路由只有一个 header_filter 入口，由它按固定顺序调用各模块。
3. 边缘自身产生的错误（WAF/ACL 403、502/504）同样经过 header_filter，同一机制覆盖，不需要再挂 `error_page`。
4. HEAD + gzip 的差异写进发布说明的已知语义变化（§6）。

## 5. 托管 WAF（ModSecurity/CRS）在共享 server 下

**做法**（`modsec.sh`）：

- 阶段与可见性：ModSecurity-nginx 只挂三个阶段——REWRITE（建事务、phase 1）、PREACCESS（phase 2）、LOG（`ngx_http_modsecurity_module.c:569-610`）。用 phase 1/2 的记录规则与 Lua 各阶段日志对时序，用 Lua 设的请求头与事务 ID 看可见性。
- 上下文传递：`ctl:ruleRemoveById` 的 ID 在配置期解析成整数，不展开宏（`actions/ctl/rule_remove_by_id.cc:28-80`），ModSecurity 也读不到 nginx 变量。所以由 Lua 在 `server_rewrite_by_lua` 把站点参数写进 `modsecurity_transaction_id $cdnca_waf_txid;`（建事务时求值，`ngx_http_modsecurity_module.c:283-290`），格式 `s=<站点>;pl=<n>;thr=<n>;mode=<block|detect>;sets=,<集>,;ex=,<id>,…;|<随机>`，节点级规则用一条 `@rx` 解析 `UNIQUE_ID` 写进 TX：`blocking/detection_paranoia_level`、`inbound_anomaly_score_threshold`（CRS 901 只在未设置时给默认值）、模式（`ctl:ruleEngine=DetectionOnly`）、规则集开关（每个集一条 `ctl:ruleRemoveById=<区间>`）、排除（每个 CRS 规则 ID 一条 `SecRule TX:cdnca_exclude "@contains ,<id>," … ctl:ruleRemoveById=<id>`，共 398 条；另做按规则族 48 组 `skipAfter` 的分组版）。上下文缺失或格式不对 → phase 1 直接 500。
- 等价：同一组策略分别用 v7 形态（http 级一份 CRS + 每站一个小文件，即 `RenderWAFEngineGate`/`renderManagedWAFSite` 的形态）、共享 server 平铺排除、共享 server 分组排除跑同一语料，4 个站点：a（PL1 阈值 5，全站排除 SQLi 探测命中的规则、`/api/` 下排除 XSS 探测命中的规则）、b（PL2 阈值 3）、c（只检测）、d（PL1，关闭 sqli 集）。命中的规则 ID 由 c 站（只检测）实测得出：SQLi 探测 942100，XSS 探测 941100/941110/941160/941390，PL2 专属探测 920230/920320。

**数据**（46 项全过）

| 检查 | 结果 |
|---|---|
| 语料 8 类 × 4 站 × 3 种形态（干净、SQLi GET/POST 体、`/api/` 下 XSS、其他路径 XSS、`/api/../x` 穿越、`/%61pi/` 编码、PL2 专属） | 32 组全部三者一致 |
| Lua 在 `server_rewrite_by_lua` 设的请求头 | phase 1 可见 |
| Lua 在 `rewrite_by_lua` 设的请求头 | phase 1 不可见（rewrite_by_lua 默认 postpone 到 REWRITE 阶段末尾，ModSecurity 先跑） |
| 事务 ID 取到 Lua 写的变量 | 是（`UNIQUE_ID` = Lua 写的串） |
| 顺序 | ModSecurity phase 1 → phase 2 → `access_by_lua` |
| `ngx.exec` 进命名 location | ModSecurity 只建一个事务（上下文经 pool cleanup 找回，`ngx_http_modsecurity_module.c:317-335`） |
| 改策略（去掉/恢复排除、阈值 5↔1000） | 下一个请求即生效，不 reload |
| a/b 交替 6 轮 | a 的排除不泄漏给 b（ctl 只作用于本事务） |
| 站点没有 WAF 上下文 | 500（失败即拒绝） |
| 客户端伪造上下文请求头 | 无效（上下文只在事务 ID 里） |
| Lua 设的内部头 | 不送到源站 |

开销（干净请求、单 worker、每轮 2000 次，三轮交替；机器高负载，取各轮 p50）：无排除规则 0.55–1.2 ms；平铺 398 条 0.8–3.0 ms（+0.25 ms 起，负载高时更多）；分组 0.63–0.88 ms（+0.06–0.09 ms）。

内存（nginx master VmRSS，3 站与 21 站之差 / 18）：v7 形态（http 级 CRS + 每站小文件）**约 80 kB/站**——子规则集合并时把父规则的 `shared_ptr` 追加进来，不复制规则（`modsecurity/rules.h` `Rules::append`）；若每站整份 CRS 则 17.2 MB/站；共享 server 一份规则集 21.7 MB，与站点数无关。

**结论**：ADR §9 问题 3 方案 a 可行，而且比“有限个节点级档位”更细：paranoia、阈值、模式、规则集开关、按规则/按路径排除都可以按请求由站点数据决定，节点 ModSecurity 配置与站点无关，站点变更不 reload。`server_rewrite_by_lua` 写的变量与请求头对 ModSecurity 可见，`rewrite_by_lua`/`access_by_lua` 写的不可见。

**对设计的影响**
1. 上下文走 `modsecurity_transaction_id`，不走请求头（请求头会被 CRS 当输入检查，且要防伪造、防外泄）。变量必须在不会执行的 location 里用 `set` 声明，不能在 server 级 `set`（它在 SERVER_REWRITE 阶段跑，可能覆盖 Lua 写的值）。事务 ID 同时是审计日志的 `unique_id`，自带站点归属。
2. 排除规则用分组版（规则族守卫 + 每 ID 一条），由主控/规则包按 CRS 版本生成，属于节点级骨架（随 CRS 版本变，要 reload）；规则集成员也是节点级目录数据。站点只出数据。
3. 路径前缀排除在 Lua 里按 `$uri` 判断后把 ID 并进 `ex`（已验证与 v7 `t:urlDecodeUni,t:normalizePath` 的 `REQUEST_FILENAME` 判断在穿越与编码路径上一致）。
4. 做不了按请求的：`SecRequestBodyLimit`/`SecRequestBodyNoFilesLimit`/`SecRequestBodyLimitAction`/`SecArgumentsLimit`/`SecRequestBodyJsonDepthLimit`/`SecPcreMatchLimit` 都是配置期指令，`ctl` 只支持引擎、审计、体访问/处理器、按 ID/标签删规则或目标（`src/actions/ctl/` 全部动作）。这些做成节点级若干档位；上传大小上限交给补丁 23 的 `client_max_body_size $cdnca_site_max_body`；参数个数上限仍可用现有 TX 规则（`waf_managed.go:314` 的 `tx.cdnca_arguments_limit`）。允许名单 CIDR（v7 `ctl:ruleEngine=Off`，`waf_managed.go:381-382`）改成 Lua 判断后在上下文里给 `mode=off`，再加一条 `ctl:ruleEngine=Off`（PoC 未测这一条，与 detect 同一机制）。
5. ModSecurity 在所有 Lua access 逻辑（回源签名、防火墙动作、JS 挑战、HTTP 策略）之前，与 v7 相同；CC（`server_rewrite`）在 ModSecurity 之前，也与 v7 相同。
6. 内存不是动态路由的收益来源：v7 的 http 级 CRS 本来就共享；收益是站点增删改免 reload 与去掉每站 server。
7. v7 还有按规则集的计分、模式与阈值（`tx.cdnca_<集>_mode/threshold`，`waf_managed.go:395-401`），同样是 TX 变量，可以照本节办法放进事务 ID；PoC 只测了 CRS 全局阈值，按集阈值留给实现任务的等价测试。

## 6. ADR 0009 正文需要改的地方

| 位置 | 现文 | 改为 |
|---|---|---|
| §4 源站池行 | keepalive 池键 = host(SNI)+sockaddr+本地地址，不同 SNI/出口不会串池 | 仅当动态 upstream 写 `keepalive 0` 且用 `balancer.enable_keepalive` 时成立；键还须含信任锚等连接级属性（§3） |
| §4 回源 TLS 行 | 未核实能否拿到完整链 | 已验证：`get_upstream_ssl_pointer` + `SSL_get_peer_cert_chain`；`proxy_ssl_verify on` 必需（§3） |
| §4 HTTP/3、`ssl_protocols` 行 | 未核实 QUIC 下回调 | 已验证可用；只开 1.2 的站点不能开 h3（§2） |
| §4 自定义错误页行 | 清 Content-Length | 清全部源站头；HEAD+gzip 已知差异（§4） |
| §6 已知语义变化 | — | 增加：错误页 HEAD+gzip（§4） |
| §8.2 索引值 | `{gen_a, gen_b}` | 二进制单摘要 + 变更集回滚字典；只用 `safe_*`；重建分片、未就绪回 503（§1） |
| §9 问题 3 方案 a | 有限个节点级档位 | PL/阈值/模式/规则集/排除按请求；只有 Sec*Limit 走节点档位（§5） |

## 7. 待决与未覆盖

- 待定：SNI 与 Host 指向不同站点时是否回 421（§2 第 4 条；v7 现状是不拦）。
- 未覆盖：HTTP/3 的 0-RTT 与跨 SNI 会话票据；QUIC 连接迁移下的回调；回源 TLS 的 CRL/OCSP；100 万键的实测（只测到 10 万键外推）；独立压测机上的耗时数据。
