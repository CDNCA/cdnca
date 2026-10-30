# 动态路由响应过滤与站点限额（D9 / D10）

- 实现：Lua `edge/openresty/dynroute/cdnca_filters.lua`（错误页替换 + header/body_filter 统一编排 + HSTS）、`cdnca_limits.lua`（站点流量超限页、套餐连接数、套餐带宽）；入口 `cdnca_dynroute.lua` 按 §1 调用（与 D7 安全阶段组合）；站点对象字段 `libs/edgeconfig/edgesite`（`ErrorPage`、`ErrorPagesFor`、`HSTS`）；控制面 `services/control-api/internal/edgepublish/site_objects_v2_errorpages.go`。与本文不一致时以代码和测试为准。
- 依据：[0009-poc-results.md](../adr/0009-poc-results.md) §4（错误页 filter）、[dynroute-contract.md](dynroute-contract.md)（D3 冻结契约，本任务只在附录 A 增加 header_filter 编排，未改既有条款）、ADR 0009 §4 上传/套餐行、原生补丁 23。
- 上传上限不在本模块：`cdnca_site.route()` 已按 `limits.max_body_bytes`（0 = 节点系统值）写 `$cdnca_site_max_body`（契约 §1.2），骨架 `client_max_body_size $cdnca_site_max_body;`。D10 只做验收（§5）。

## 1. 阶段接线（入口 `cdnca_dynroute`，node-skeleton.md §3 约定不变）

| 阶段 | 调用（固定顺序） |
|---|---|
| `server_rewrite` | `cdnca_site.route()` → `cdnca_tls.request(site)` → `cdnca_limits.traffic(site)`（流量超限页）→ CC（`cdnca_security.server_rewrite`，有结论即返回）→ `cdnca_limits.refuse(site)`（套餐连接数 0 → 503）→ `cdnca_limits.rate(site)`（套餐带宽）→ `cdnca_filters.routed()`（最后一行） |
| `rewrite` | `cdnca_security.rewrite`（ACL/WAF 规则计划，D7） |
| `access` | `cdnca_limits.enter(site)`（第一步：套餐连接数计数）→ `cdnca_security.access`（防火墙/挑战/HTTP 策略）→ `cdnca_origin.access()` → 缓存派发 |
| `header_filter` | `cdnca_origin.header_filter()`（回源 Location/Refresh 改写，先于替换）→ `cdnca_filters.header_filter()`（§2 五个槽） |
| `body_filter` | `cdnca_filters.body_filter()` |
| `log` | `cdnca_limits.leave()` → `cdnca_origin.log()` → `cdnca_security.log`（CC 计数） |

骨架另声明（`edgeskeleton`）：字典 `cdnca_limits_conn 1m`、`cdnca_package_bandwidth 1m`；变量 `$cdnca_filters_routed`、`$cdnca_limits_conn_key`、`$cdnca_limits_rate_key`（都放变量不放 `ngx.ctx`：缓存派发 `ngx.exec` 会清 `ngx.ctx`）。

`routed()` 的位置决定哪些响应换站点页：v7 的 `error_page` 写在 location 里，server rewrite 阶段的退出（CC 429/封禁、未就绪 503、套餐 0 的 server 级 `return 503`）都不经过它，保持 nginx 默认页；location 选择起（413、rewrite/access 的退出、回源错误）才替换。

## 2. header_filter 编排（契约附录 A）

`cdnca_filters.header_filter()` 是唯一入口，按下列槽顺序执行，每槽只写自己的头：

| 槽 | 模块 | 写什么 | 替换页上 |
|---|---|---|---|
| 1 `error_page` | cdnca_filters（D9） | 决定是否替换（§3）；替换时清头并写页面头 | — |
| 2 `http_policy` | HTTP 策略（入口 `configure` 把 D7 的 `cdnca_security.header_filter` 注册为本槽） | 自定义响应头、CORS、`X-CDNCA-HTTP-Policy-Version` | **不执行**（v7 替换页走命名 location，location 级 header_filter 不作用） |
| 3 `cache_status` | cdnca_cache（D8，入口 `configure` 时 `register`） | `X-CDN-Cache`/`X-CDN-Cache-Reason`/预热回显 | 执行（v7 是 server/location 级 `add_header … always`） |
| 4 `hsts` | cdnca_filters（D9） | `Strict-Transport-Security`，只在 `$https = on`（RFC 6797 §7.2，h3 同样为 on） | 执行 |
| 5 `alt_svc` | cdnca_tls（D4） | `Alt-Svc: h3=":<端口>"; ma=86400`（站点在该端口宣告 h3） | 执行（v7 server 级 `add_header … always`） |

互不覆盖靠两条：槽 3–5 的头名只由各自的槽写；HTTP 策略不能设或删它们——两端校验（`agents/edge-agent/internal/httppolicy/compile.go`、`services/control-api/internal/httppolicycontrol/validate.go`）把 `alt-svc`、`strict-transport-security`、`x-cdn-cache` 与 `x-cdnca-*` 前缀列为保留头（原有保留：hop-by-hop、`content-length`、`location`、`refresh`、`vary`、`access-control-*`、`x-cdnca-*`）。槽 2 在槽 1 之后，所以策略头也不会被错误页替换清掉以外的方式丢失。用户可见：站点编辑 HTTP 策略的“响应头动作”帮助文字列出全部保留头（`httpPolicies.responseHeaderHint`），校验失败提示点名 Alt-Svc / Strict-Transport-Security / X-CDN-Cache（`validation_error`）；接口仍是同一个 `validation_error` 错误码。

### 2.1 站点响应规则（能力 `EDGE_RESPONSE_RULES` v1 = 55）

站点对象 `access.response_rules[]`（`edgeconfig.SiteResponseRule`，控制面站点访问设置 `GET/PUT /v1/sites/{id}/access` 的 `response_rules`）。`cdnca_filters.header_filter()` 在槽 1 之前按顺序评估，只看状态码与响应头，**不读响应体**。

| 部分 | 内容 |
|---|---|
| 条件 | `statuses[] {from,to}`（空 = 任意；精确码写 from=to，列表写多段）；`headers[] {name, op, value}`，op = `exists`/`absent`/`equals`（任一值全等）/`regex`（任一值 `ngx.re.find(..., "jo")`，回溯超限视为不匹配）；全部满足才匹配 |
| `headers` | `header_actions[] {kind: set/add/delete}` 累积，继续评估；最终若没有页面替换才应用（替换页上丢弃，与 HTTP 策略槽一致） |
| `log` | 安全日志 `type=response action=log severity=info rule_id=<id>`，继续评估；同一请求已有更早模块的记录时不覆盖 |
| `error_page` | 状态改为 `status`，换成站点该码的页（`origin_response|码`，否则 `edge_route|码`，都没有 → 内置文本页），清掉响应全部原有头；结束评估 |
| `block` | 状态改为 `status`，内置文本页（不用站点页），安全日志 `action=block severity=high`、`block_page=1`（不计套餐流量）；结束评估 |

保留头（两端校验 `edgeconfig.validateSiteResponseRules`）：分帧头、`alt-svc`、`strict-transport-security`、`x-cdn-cache`、`x-cdn-cache-reason`、`x-cdnca-*` 不可设/删。上限：32 条规则、每条 16 段状态、8 个头条件、16 个头动作，值 ≤ 1024 字节可打印 ASCII，正则 ≤ 256 字节。

**哪些响应被评估、与缓存的关系**：

- `headers` 规则对回源响应与缓存命中（HIT/STALE/UPDATING/REVALIDATED）都执行；`log`/`error_page`/`block` 只对回源响应（`origin_response` 分类）执行，缓存命中不再判定（规则后到时已缓存的对象照常返回，等过期或清缓存）；被 `error_page`/`block` 替换的响应置 `$cdnca_cache_rule_bypass=1`（`proxy_no_cache`），不入缓存，`X-CDN-Cache: BYPASS`、`X-CDN-Cache-Reason: response_rule`。
- 边缘自身生成的响应（`edge_route`/`edge_connect`：ACL/WAF/CC 拦截、413、回源失败 502/504、模块自出页 `own_page`、`routed()` 之前的 server rewrite 退出）不评估。

验收：`ONLY=response tests/dynroute-filters/run.sh`，24 项（h1/h2/h3 头改写、状态段/列表/区间、四种头条件、日志行、站点页与内置页、HEAD、边缘自身响应不评估、缓存 MISS→HIT 都改写、拦截不入缓存、规则后到不拦已缓存命中、去掉规则不 reload 即恢复）。

`register(slot, fn)` 只接受 `http_policy`、`cache_status`；`fn(site, state)`，`state.replaced` 为本响应是否是替换页。模块自己出页（直接 `ngx.print` 后退出）时先调 `cdnca_filters.own_page(kind)`，该响应永不被替换。

## 3. 错误页替换（PoC §4 做法，按 v7 `error_page` 集合判定）

替换条件（全部满足）：`routed()` 已调用；本请求非 `own_page`；状态 400–599；状态在站点任一分类有页（v7：`error_page` 列表 = 站点与全局各分类状态的并集）；分类判定同 v7 `errorpage/handler.lua classify()`（`$upstream_status`/`$upstream_header_time`：源站返回该状态 = `origin_response`；试过上游但没拿到 = `edge_connect`；没试上游 = `edge_route`）；非 `origin_response` 时响应必须是 nginx 自己的特殊响应——nginx 的错误响应总带 `Content-Length`（`ngx_http_special_response.c` `send_special_response`），Lua 模块自己打印的页没有（`ngx_http_lua_util.c` 发头前清长度），v7 的 `error_page` 也从不替换后者（真实 OpenResty 实测：`ngx.say` 后 `exit(429)`、带长度的 503 均原样）。

替换动作：`origin_response`（以及缓存命中的响应，头是存下的源站头）删除**全部**响应头（`ngx.resp.get_headers` 遍历；只清长度会泄漏 Set-Cookie/ETag 并留下错误的 Content-Encoding，PoC §4）；边缘自身错误删除 v7 handler 删的那 11 个头；写页面头（与 v7 handler 逐字节：`Content-Type`（html/plain 加 `; charset=utf-8`）、精确 `Content-Length`、`Cache-Control: no-store, max-age=0`、`Pragma`、`Expires: 0`、CSP（主题页加 `style-src '<style_hash>'`）、`Referrer-Policy`、`X-Content-Type-Options`）；body_filter 首块输出页面并 eof，其后字节丢弃。该（分类, 状态）无页、或资源对象读不出 → v7 的内置文本页（≥500 `Service temporarily unavailable.`，否则 `Request could not be completed.`），资源缺失记 ERR。

资源：页面体是站点对象引用的 `error_page_asset` 对象（`cdnca_site.object` 按摘要读并校验，worker LRU）；站点对象 `error_pages` 编码后按（站点摘要）在 worker 内建一次查表。

## 4. 站点限额（D10）

| 项 | 站点对象 | 节点行为 | 与 v7 |
|---|---|---|---|
| 流量超限页 | `traffic_limit {period, notice_html}`（ge-analytics，只在超限时存在） | server_rewrite 回 509 + 提示页（空 = `edgeconfig.DefaultSiteTrafficNoticeHTML`），任意方法，`/.well-known/acme-challenge/` 例外；标 `cdnca_security_block_page` 不计套餐流量；`own_page` 不被替换 | 逐字节同 `SiteTrafficLimitDirectives`（Lua 打印、无长度、`Cache-Control: no-store`） |
| 套餐连接数 | `limits.connections {subscription_id, max}` | `max = -1` 不限；`0` → server_rewrite 503（nginx 默认页，不替换）；`> 0`：access 第一步 `incr`（字典 `cdnca_limits_conn`，键 = 订阅 ID，同订阅各站共享），超出即回退并 503（在 location 内，站点有 503 页时替换，同 v7 `limit_conn` + `error_page`）；log 释放；`ngx.exec` 进命名 location 后不重复计数 | 计数单位同 `limit_conn`：在途请求（HTTP/2、HTTP/3 按流） |
| 套餐带宽 | `limits.connections.bandwidth_bps`（ge-analytics） | server_rewrite：在途响应数 `incr`（字典 `cdnca_package_bandwidth`，键 1 小时过期自愈），`$limit_rate = max(floor(floor(bps/8) / 在途数), 1)`；响应保持开始时的速率；log 释放 | 同 `PackageBandwidthDirective` 的取整、计数与过期 |
| 上传上限 | `limits.max_body_bytes`（0 = 节点系统值） | `$cdnca_site_max_body`（D3 route）→ `client_max_body_size`（补丁 23），带长度在 find_config、无长度在读体时判，超出 413（站点有 `edge_route` 413 页时替换，同 v7） | 拒绝语义同补丁 23 冒烟脚本 |

### 4.1 市场供给限额（ADR 0012 §6.2，ML-07，能力 `SUBSCRIPTION_LIMITS` v1）

字段都在 `limits.connections`（同订阅各站共享，0/省略 = 不限），值是叶子按 `ceil(总量 / 在线节点数)` 算好的本节点份额；任一字段出现时文档 required `subscription_limits` v1，未声明该能力的节点拒绝发布（不降级）。

| 字段 | 对应 metric | 节点行为 |
|---|---|---|
| `max` | `concurrent_requests` | 即上表"套餐连接数"：在途请求数（HTTP/2、HTTP/3 按流） |
| `max_connections` | `concurrent_connections` | access 第一步 `market_enter`：按 `$connection` 在 worker 表登记 TCP 连接（首个请求时），共享计数 `tcp\|<订阅>`（字典 `cdnca_limits_market 16m`）；每秒用 FFI 读 `r->connection->fd` + `readlink /proc/self/fd/N` 判断关闭后释放，FFI 自检失败退化为最后请求后 75 s 释放；HTTP/3（QUIC）不计；超限 503，连接不登记（下个请求重试） |
| `new_per_second` | `new_connections_per_second` | 每秒窗口 `new\|<订阅>\|<秒>`，只在登记新连接时计；超限 503 |
| `qps` | `qps` | `resty.limit.req(qps, burst qps-1)`，不延迟；超限 503 + `Retry-After: 1` |
| `bandwidth_bps` | `bandwidth_peak_bps` | 上表"套餐带宽"（按在途响应均分） |
| `stopped` | stop 处置 | server_rewrite `refuse()` 全部 503（h1/h2/h3） |

- 分钟统计：同一字典按（分钟, 订阅）记 `max_requests`/`max_connections`/`max_new_cps`/`max_qps`/`bytes_out`/`peak_bps`（字节在响应结束那一秒计入）；控制套接字 `GET /subscription-minutes` 一次取走已结束的分钟（`cdnca.edge.subscription-minute/v1`，取走即删）。agent 每 15 s 取一次，写入遥测 spool（记录类型 `subscription_minute.v1`，§4.2）。
- 四层：stream 对象 `subscription_limits {subscription_id, max_connections, new_per_second, bandwidth_bps, stopped}`，preread 计数、log 释放，超限/stop 直接关闭；带宽按在途会话均分。四层没有分钟统计。
- pause 在节点上没有表示（只摘 DNS，节点照常按硬限服务）。

### 4.2 分钟统计上行

`cdnca_limits` → agent（`/subscription-minutes`）→ 遥测 spool（`subscription_minute.v1`，确认后删）→ 网关 `TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1`（8）校验并绑定 installation → `cdnca.analytics.ingest` → 主控 analytics ingest（回执去重）→ ClickHouse `subscription_minutes_v1`（迁移 024）。

- 每条记录挂在该订阅的一个代表站点上（遥测 `package_subscription_id` 等于该订阅的活动站点里 site_id 最小的那个），网关按该站点的授权核对 `subscription_id` 与配置快照里的订阅一致；没有这样站点的订阅（未启用遥测或订阅已停用）丢弃并计数。
- event_id = sha256(节点, 订阅, 分钟)，spool 与 CH（`ReplacingMergeTree`，按 `(package_subscription_id, minute, node_id)`）都按它去重；agent 取走后、写入 spool 前崩溃会丢这几分钟（已知局限）。
- 按订阅跨节点聚合与用量报告 v2 归 ML-08。

## 5. 验收与实测

`tests/dynroute-filters/run.sh`（`ONLY=errorpage,order,upload,connections,traffic,response`）：节点运行时镜像（OpenResty 1.31.1.1 + 补丁 01–24），一个 `--rm --network none` 容器，2 worker；同一 OpenResty 里另起 v7 形态对照 server（`proxy_intercept_errors` + `error_page` + v7 `errorpage/handler.lua`，同一组页面用 agent 自己的 `errorpage.Compile` 编译）；h2/h3 客户端是 `tests/dynroute-filters/probe`（独立模块，用 HTTP/3 客户端的钉值）。最近一次（集成 0d2011171 + ge36-resp 之上，全部检查含 market/share/response）：**193 PASS / 0 FAIL / 7 KNOWN**。

- 错误页 h1 逐字节：15 个源站夹具（PoC §4 全部 + 403/500/502/503/超时）× GET/HEAD × 有无 gzip = 60 组合，53 相同，7 是 PoC §4 已知的 HEAD+gzip 差异（v7 留 `Content-Length`，过滤器方式按 GET 走 gzip，状态/其余头/空体相同）；边缘退出 403/503/404/429 与 v7 相同；模块自出页、server rewrite 退出不替换；413 替换为站点页与 v7 相同；主题 CSP；不泄漏源站头；无页站点与无页状态透传；缺资源回内置页。
- h2/h3：8 个夹具 × GET/HEAD 共 32 项，替换页完整分帧，未配页的源站截断 200 在 h2 流 reset、h3 流错误（均非完整应答）。
- 编排：普通响应五槽全在；替换页无策略头、保留缓存头/HSTS/Alt-Svc；h3 有 HSTS；明文端口无 HSTS/Alt-Svc。
- 上传：站点 1024 B 与节点系统 4096 B × h1/h2/h3 × 带长度/流式 × 上限/上限+1，24 项全对（上限放行、+1 回 413）。
- 连接数：两个站点同一订阅 max 4，20 个并发请求（每个持有 800 ms），三轮均 200×4、503×16，结束后计数归 0；`ngx.exec` 只计 1；`max = 0` 回 503。
- 带宽：800 kbit/s 订阅，400 KB 单响应 4.0 s（不限站点 4–6 ms）；两响应先后进入时第一个 4.0 s、第二个 8.0 s（半速）；结束后计数只剩探测请求自身。
- 流量超限：GET/POST 509 + 自定义页（分块、no-store）、默认页逐字节、ACME 例外进站点、h2 同样、去掉 `traffic_limit` 后不 reload 立即恢复。

D0 金标（`CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check error-pages,site-traffic-limit,package-limits`）：合入集成 420a2e5a（D7）后：error-pages **SAME**，package-limits、site-traffic-limit **0 缺陷**，豁免只剩 D12 访问日志 2 项与节点级 ACME location 1 组（实际命中 10 处）；转发头 39 项豁免已删（D7 已对齐）。v7 全量 21/21 SAME。tests/dynroute-* 其余各套全过：index 46、tls 100、cache 功能 25、origin 50、originauth 17、origintls 20、security firewall-action 2。

## 6. 与 v7 的差异（semantic_changes 之外，需知晓）

1. **HEAD + Accept-Encoding: gzip 的替换页**：v7 带 `Content-Length` 无 `Content-Encoding`，动态路由反之（PoC §4，客户端无体可见差异）。
2. **节点页状态不拦截站点源站响应（v7 同步修正）**：v7 曾把全局节点页（`no_host` 400、`unknown_site` 404，主题默认页会发布它们）的状态并入每个站点的 `error_page` 列表（`ActiveRuntime.SiteStatuses`），于是主题一启用，每个站点源站自己的 400/404 都被换成内置文本页（该分类无页）——实测确认（agent `errorpage.Compile` 后 `SiteStatuses` 含 400、404，而 `origin_response 404` 无资源）。站点对象不带节点页（`ErrorPagesFor` 过滤），源站 400/404 原样透传。定为缺陷：v7 已修（`errorpage.ReadActiveRuntime` 不再把 no_host/unknown_site 绑定计入站点状态，单测 `TestReadActiveRuntimeKeepsNodePagesOutOfSiteStatuses`），金标 error-pages 加入主题节点页与 `plain-400` 步骤后重录（回退修复时该场景 20 处差异）；动态路由本来不带节点页，两者一致，无登记项。

## 7. 站点对象字段（对接 ge-access / ge-analytics）

| 字段 | 定义 | 来源 | 状态 |
|---|---|---|---|
| `error_pages[] {category, status, rule_id, mime_type, style_hash?, asset}` | 站点有效页（站点+全局，`ErrorPagesFor`：码优先于区间、窄区间优先、站点覆盖全局；节点页不进）；`rule_id` 标识符（主题页 `theme.<分类>.<码>`）；MIME 限 html/plain/json；`style_hash` 只在 HTML | 控制面 `siteErrorPageFacts`（errorpagecontrol 生产快照 = 平台全局规则 + 主题默认页 + 站点规则） | 已实现；接发布路径随 D2/D8 |
| `hsts {max_age_seconds, include_subdomains, preload}` | 只在有 TLS 监听的站点；max_age ≤ 2 年；preload 需 includeSubDomains 且 ≥ 1 年 | **ge-access**（站点级 HSTS，nodes-dns-cert 缺失 8 / 逻辑 6：系统 `hsts_enabled` 只存不用） | 节点已执行；ge-access 未开工，控制面无字段来源（覆盖表 pending） |
| `traffic_limit {period, notice_html}` | 只在超限时存在 | **ge-analytics**（已合入：`sitetrafficlimit` + `edgeconfig.SiteTrafficLimit`） | 已接通 |
| `limits.connections {subscription_id, max, bandwidth_bps}` | 套餐连接数与带宽 | 已有（`bandwidth_bps` 由 ge-analytics 加） | 已接通 |
| `limits.connections {max_connections, new_per_second, qps, stopped}` | 市场供给限额（§4.1） | ML-07；叶子份额由 ML-08 写入隐藏套餐 | 节点已执行，控制面待 ML-08 |
| `limits.max_body_bytes` | 站点上传上限，0 = 节点系统值 | 已有（HTTP 策略 `max_upload_bytes`） | 已接通 |

ge-access 其余与本模块相关项（站点级压缩、自定义页面/维护页、域名不匹配页）：压缩是 location 级 `gzip_*` 指令，不在 header_filter；若做成站点级需要补丁或 Lua 压缩，属 ge-access 设计。维护页/域名不匹配页若作为“站点状态页”下发，可复用 `own_page` + 与 `traffic_limit` 同形的字段（在 server_rewrite 出页、不被错误页替换）。

## 8. 遗留

1. ge-access 未开工：`hsts` 无控制面来源；系统设置 `hsts_enabled` 仍是只存不用的假设置。
2. 主题节点页：`unknown_site` 已由骨架承载（`edgeskeleton.Input.UnknownSite` → `cdnca_site.configure` 在 master 读页文件，`reject_unknown` 按其状态 403/404/410/421 与 `page_headers` 回页；未配置仍回 nginx 421，金标 unknown-site/error-pages 在 cdnca-dynroute 下 0 缺陷）。生产 agent 尚无动态路由骨架装配点，由接骨架的任务把全局 unknown_site 页传入。`no_host` 仍未承载。
3. 金标豁免随 D5a（转发头）、D12（访问日志）、骨架节点级 ACME location 合入后删除。
