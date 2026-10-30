# 站点对象 cdnca.edge.site/v2（动态路由语义化站点对象）

- 实现与唯一规范：`libs/edgeconfig/edgesite`（`format.go` 字段、`rules.go` 规则计划、`validate.go` 校验、`codec.go` 编码/摘要/索引键、`ports.go` 跨站端口表）。本文与代码不一致时以代码和测试为准。
- 主控生成：`services/control-api/internal/edgepublish/site_objects_v2.go`（`buildSiteObjectsV2`），由 `site_objects_dynamic.go` 的 `dynamicRoutingPublication` 从编译好的 v2 release 直接转换（`site_objects_v2_source.go`，不再经 v8 拆分），已是唯一发布路径。
- 1.0.35 现状：动态路由（site_runtime 9）为节点唯一模式，1.0.35 为初始基线；v1 站点对象（site_runtime 8）与 `siteruntimev2` 编译器**已于 1.0.35 删除**。下面第 1 节的 v1 对照只作历史说明。
- 关系：ADR 0009 §8.1 site_runtime 9（动态路由）消费本格式；§8.3 的根/桶/对象三级、只签根、内容寻址、加密与拉取原样复用。

## 1. 与 v1（site_runtime v8，已于 1.0.35 删除）的区别

v1 站点对象是“v2 发布产物按站点拆开”，节点拼回 bundle 再编译成每站 `server{}`。v2 是**节点在请求期直接执行的数据**：没有 nginx 文本、没有发布路径、没有每站 zone/upstream 名；重内容（CC 策略、HTTP 策略、防火墙动作、错误页资源）以摘要引用，与站点对象放在同一对象库。

| | v1 `cdnca.edge.site/v1` | v2 `cdnca.edge.site/v2` |
|---|---|---|
| 内容 | v2 文档站点条目原样 + 按站文件 | 语义字段（本文 §3） |
| 安全 | 每监听一份 `security` | 每站一份；规则按端口合并（§4） |
| 回源 | runtime 池 + origin-route 文档两份，由 agent 叠加 | 叠加后的一份 |
| 缓存键 | v7 早期含 `config_version_id`（每次发布换键空间），ge-cache 起改为缓存代际 | 稳定前缀 + 缓存代际（§5，只有影响“键指向哪个对象”的变化或显式清空才换） |
| 上传上限 | 无策略时节点 http 级默认 | `limits.max_body_bytes`，0 = 节点系统值 |

## 2. 编码、摘要、上限

- 编码（`siteobject.Encode`，与已删除的 v1 相同）：`encoding/json` 按结构体字段顺序、紧凑、不做 HTML 转义、无结尾换行；寻址 = 明文 SHA-256（小写十六进制）。
- 每个列表有唯一顺序（见各字段），必填列表写 `[]` 不写 `null`，所以同一站点只有一种字节表示。`Decode` 要求：大小 ≤ `MaxObjectBytes`（2 MiB）、任何层级无未知字段、无尾随数据、再编码与原字节相同、`Validate` 通过。
- 版本：schema `cdnca.edge.site/v2`，`FormatVersion = 2`，media type `application/vnd.cdnca.edge-site+json;version=2`。老节点会误读的变化换新 schema 名，不复用。
- 上限：名字 100（主域名 + 别名）、监听 32、池 64、每池端点 32、条件回源 256、规则策略 2（ACL + WAF）、规则 4096、CC 绑定 32、错误页 64、回源鉴权 8；被引用对象 ≤ 8 MiB。按全部上限填满的站点实测 1,285,459 B（上限的 61%）。

## 3. 字段

顶层：`schema`、`configuration_scope_id`、`tenant_id`（tenants.id，缓存/挑战/遥测身份）、`site_id`、`revision`（≥1，≤2^53−1）。

| 字段 | 含义与约束 |
|---|---|
| `hosts.primary` / `hosts.aliases` | 小写 FQDN 或前导通配 `*.x`（只匹配多一级以上的子域，不匹配 `x`）；primary 是站点身份名（缓存域、遥测域、规则编译时的主机）；aliases 升序、不含 primary |
| `listeners[]` | 按 port 升序、port 唯一。`address_family` ipv4/ipv6/dual_stack；`tls` = {`certificate_version_id`, `protocols` ⊆ {TLSv1, TLSv1.1, TLSv1.2, TLSv1.3} 升序（含 1.0/1.1 须 `cipher_profile` compatible）, `cipher_profile`、`ocsp_stapling`、`client_auth`（D4，见 [dynroute-tls.md](dynroute-tls.md) §4）}；`http2`、`http3` 只能在 TLS 上；**`http3` 要求含 TLSv1.3**（QUIC 只有 1.3，PoC §2）。HTTP/1.1 总是开 |
| `force_https.redirect_port` | 必须是本站一个 TLS 端口；`/.well-known/acme-challenge/` 例外 |
| `force_https.status` / `exclude_hosts` | 跳转状态码 302/307/308（缺省 301）；不强制的本站域名（升序、非通配、不能是全部域名）|
| `access` | 站点访问处理（`edgeconfig.SiteAccess`，与 v2 文档同形，但不含 `hsts`，HSTS 走对象自身 `hsts` 字段）：`host_redirects[]`（按 source_host 升序，域名级 301/302/307/308，保留 URI，ACME 例外）、`compression`（开/关、类型升序、最小长度）、`limits`（单 IP 并发 limit_conn 按站点+客户端计数、单请求限速）、`basic_auth`（只有 SHA-256(site_id:user:pass)、排除路径前缀）、`maintenance`（状态码、类型、正文、Retry-After、放行网段）。动态路由：每请求按站点对象执行，无需 server{} |
| `traffic_limit` | 仅在网站超出自身流量上限时出现 {`period`：daily/monthly/total，`notice_html`：超限提示页，空则节点默认页}；节点对该站全部请求回 509 + 提示页，`/.well-known/acme-challenge/` 例外；用量与上限只在主控 |
| `schedule302` | HTTP 302 调度（`libs/edgeconfig/sched302.Site`）：`target` address/hostname、`keep_path`、`keep_query`、`signature_ttl_seconds` 10–3600、`https_to_http`、`extensions`（小写字母数字、升序去重）、`path_prefixes`（以 `/` 开头、升序去重）、`min_size_bytes`；站点必须有明文监听（落地走节点明文 HTTP）。签名密钥与候选节点不在站点对象里，走节点调度表 `<deployment_root>/schedule302/table.json`（ConnectResponse.sched302_table）。动态路由侧需要：共享明文 server 上的落地 location `^~ /_cdnca302/`（节点级，路由之前，不随站点）、按 `$cdnca_site_id` 在 access 阶段调用 `cdnca_sched302.access`、realip 只信回环的 `X-Cdnca-S302-Client`、log 阶段学习大小 |
| `websocket`、`range` | 布尔 |
| `cache_status_header` | 布尔，缺省为 false（迁移 472）。true：节点在响应里输出 `X-CDN-Cache`（缓存状态）和 `X-CDN-Cache-Reason`（绕过原因）；false 时两个头都不输出，但 agent 的预热请求（`$cdnca_cache_prewarm=1`）始终带上。源站返回的同名头无论开关都先清掉。节点由 `cdnca_cache.access` 写 `$cdnca_cache_show`，`add_header` 读由它门控的变量（`edgecache.HTTP`）。主控在站点攻击升级 B 级及以上时编译为 false |
| `websocket_origins` | WebSocket Origin 白名单（升序，`http(s)://host[:port]`，要求 `websocket`）：升级请求的 Origin 不在其中回 403，无 Origin 放行；缺省不校验 |
| `origin.pools[]` | 按 id 升序；`kind` origin/l2；`algorithm` round_robin/ip_hash/url_hash/least_conn/random（按权重随机）/hash（`hash_key`：白名单变量模板的一致性哈希）/sticky（`sticky` {source cookie/header/arg, name}：令牌 = SHA-256("cdnca-sticky-v1\0"站点\0池\0端点) 前 12 字节十六进制，无令牌的访客由节点下发）；`request_host` {mode origin（所选端点的主机，非默认端口时带端口）/custom（value）}，缺省为访客 Host；`follow_port` 用监听公网端口回源；`endpoints[]` 保持选择顺序：`scheme` http/https，https 必须有 `trust_anchor`（`sha256:<64hex>` 池 CA 集摘要或 `system`），`sni_mode`（custom 发送 `sni`，必填；origin_host 发所选端点主机；visitor_host 逐请求发访客 `$host`；后两者不得带 `sni`，依据 `edge/openresty/dynroute/cdnca_origintls.lua:5-7`、`libs/edgeconfig/edgesite/validate.go:335-347`；主控发布时 `Pool.ExpandSNIModes` 给每个 https 端点写明 sni_mode：有 `sni` 或 `request_host` custom 为 custom，`request_host` origin 为 origin_host，否则 visitor_host），缺省 sni_mode 时 `sni` 缺省 = 回源 Host 去端口；所选 SNI 进连接复用键，不同 SNI 不共用连接；`backup`（仅 round_robin/least_conn，至少一个主端点；主端点都不可用才用）；`max_conns`（每 worker，0 不限，≤100000）；l2 端点必须有 `node_id`、`mtls_identity_sha256`、`topology_revision`；`retry` {methods ⊆ GET/HEAD, max_attempts 1–8, 各超时}；`keepalive_idle_timeout_ms`（仅 origin 池，0 或 1000–300000）|
| `origin.default_pool_id` / `default_fallback_pool_id` | 默认池；默认池失败时的回退池 |
| `origin.routes[]` | 求值顺序（优先级降序，再按具体程度）；至少一个条件：`path_prefix`（按路径段前缀匹配规范化后的 `$uri`：`/api` 命中 `/api` 与 `/api/…`、不命中 `/apiary`；带尾斜杠 `/api/` 只命中 `/api/…`；`/` 命中全部）、`client_cidrs`（规范掩码）、`node_regions`（区域目录代号 `region_catalog.code`，节点按主控经密钥文档下发的本机区域代号判断）、`hosts`（请求 Host 精确或 `*.x`）；首个匹配生效 |
| `origin.l2` | 默认池是 l2 时必有：`direct_fallback_pool_id`（origin 池）、探测间隔/阈值；半开探测 1 个、跳数 1 固定 |
| `origin.ingress_source` | 回源出口按入口地址（FX30） |
| `origin.trusted_proxy_cidrs` | 可信代理（升序、规范掩码、不接受 /0）：对端在其中时保留并追加 X-Forwarded-For 链、保留 X-Real-IP；否则三个头一律为对端地址（X-Forwarded-Proto = 访问协议）。L2 中转池不改这些头 |
| `origin.https_pool_id` | 跟随协议：TLS 监听默认走这个全 HTTPS 的 origin 池（不得是默认池或 L2 直连回退池） |
| `origin.follow_redirect` | ge36 回源跟随跳转（省略 = 关；需节点能力 `ORIGIN_FOLLOW_REDIRECT` v1（能力号 51），不具备的节点拒绝发布并列出）：{`max_hops` 1–5（nginx 每请求内部跳转上限 10，节点自身也占用），`cross_origin`（默认 false）}。只对无请求体、非 Upgrade 的 GET/HEAD：源站 301/302/303/307/308 由节点在专用命名位置（`@cdnca_origin_follow` 与缓存变体 `_f`，不碰 `location /`、tier、错误页与条件回源回退）以 `proxy_intercept_errors` + `error_page` 重入跟随，保留方法与请求头、按原请求选源；同源 = Location 无主机或主机为访客 Host、站点域名、所选池端点地址，其他主机只在 `cross_origin` 时跟随（仍经本池端点连接、Host 改为该主机）。最终响应按原 URL 的键缓存；分片站点的缓存请求不跟随。放弃（超次数/跨源/无法解析）返回该 30x（Location 按源站地址改写为访客主机，`Cache-Control: no-store`，原响应体与其他头不保留）。聚合边缘（第三方 CDN）无对应能力：开启时投影报告 `origin.follow_redirect` 无法映射（可在供给绑定上显式忽略） |
| （节点恒做）| 源站 30x 的 Location/Refresh 若指向本池任一源站地址（带/不带端口，http/https，锚定主机），改写为访客的 `scheme://Host/…`；外站地址不改 |
| `origin.auth[]` | 按 pool_id 升序：{`pool_id`（origin 池）, `endpoint`（https URL）, `secret` 引用 `origin_auth_secret`}；凭据从不进站点对象 |
| `cache` | {`key_prefix`, `generation`, `domain`（本站名字之一）, `key_by_host`, `policy`（签名缓存策略文档，`disk_quota_bytes` 在共享 zone 池上是软配额）}，见 §5 |
| `security` | §4 |
| `http_policy` | 引用 `http_policy`：sha256 = 该站在 http-policy 快照里的条目原文 |
| `error_pages[]` | 站点**有效**错误页（站点规则 + 全局规则合并：`edgesite.ErrorPagesFor`，码优先于区间、窄区间优先、站点覆盖全局；节点页 no_host/unknown_site 不进站点），按 (category, status) 升序唯一，最多 403 条（全部合法组合）：`category` origin_response/edge_route（400–599）/edge_connect（502–504）、`rule_id`（标识符，主题页 `theme.<分类>.<码>`）、`mime_type` text/html / text/plain / application/json、`style_hash`（可选，HTML 主题页唯一 `<style>` 的 CSP 源 `sha256-…`）、`asset` 引用 `error_page_asset`（带 sha256）。节点按 v7 `error_page` 集合替换，见 [dynroute-filters.md](dynroute-filters.md) §3 |
| `hsts` | 可选 {`max_age_seconds` ≤ 2 年, `include_subdomains`, `preload`（需 includeSubDomains 且 ≥ 1 年）}；只允许有 TLS 监听的站点；节点只在 HTTPS（含 h3）响应上发（dynroute-filters.md §2 槽 4）。来源：站点访问设置 `site_access_settings` 的 HSTS（v2 文档 `site.access.hsts` 转换而来）；系统设置 `hsts_enabled` 开时新建 HTTPS 站点写入 1 年、无子域、无 preload |
| `limits.max_body_bytes` | 站点自己的上传上限（HTTP 策略 `max_upload_bytes`）；0 = 节点系统配置值。节点写进 `client_max_body_size` 变量时总是正数（补丁 23 空/0 回 500）|
| `limits.connections` | 套餐订阅连接数与带宽 {`subscription_id`, `max`：−1 不限、0 一律 503、≤65535；`bandwidth_bps`：可选，出站带宽预算 bit/s，节点按该订阅在途响应数平分为 limit_rate，超限只限速不拒绝}，同订阅各站共享 |
| `telemetry` | {`package_subscription_id`（只含启用中的订阅，可与 connections 的订阅不同）, `capture`（采集策略，同 v1）}；身份字段（租户/站点/主域名/端口）由站点本身决定 |

引用 `Ref` = {`kind`, `id`（UUID）, `revision`, `sha256`}。kind：`cc_policy`、`http_policy`、`firewall_action`、`error_page_asset`、`client_ca`（必带 sha256，内容在对象库）；`challenge_policy`、`origin_auth_secret`（无 sha256：前者由挑战机密下发按 id+版本装到节点，后者是按节点加密的机密对象，尚未实现）。

流式响应（SSE 等）：站点对象与 v2 文档都没有"关闭缓冲"字段，由源站发 `X-Accel-Buffering: no` 控制。依据（真实 OpenResty 1.31.1.1 实测）：v7 与动态路由都不 `proxy_ignore_headers`/`proxy_hide_header` 该头，nginx 原生按它关闭该响应的缓冲；不带该头时 `proxy_buffering on` 也不攒满才发，源站逐块 flush 的首块在 1 s 内到达，开 gzip（含 text/event-stream）或 proxy_cache 时同样到达。`proxy_buffering` 不接受变量，站点级开关只能按路径另生成 location，无可观测收益，不做。

## 4. 安全与规则计划（给 D6 解释器）

阶段顺序固定：CC（server_rewrite）→ 托管 WAF（ModSecurity phase 1/2）→ 规则计划（rewrite）→ 防火墙动作 → JS 挑战（access）。

- `security.cc[]`：{`ports`（升序，端口不重复出现在两个绑定里）, `policy` 引用 `cc_policy`（内容 = `edgeconfig.CanonicalCCV2Policy`，sha256 = v7 的 CompiledSHA256）, `source_sha256`}。同一策略绑定到多个端口时合并为一条。
- `security.managed_waf`：{`policy_id`, `policy_version`, `profile`（配置期上限：请求体/无文件体上限与动作、参数数、JSON 深度、PCRE 上限、检查上限动作——节点只能按档位执行，取不宽于 profile 的档）, `sets`（规则集：动作、paranoia、阈值、文件/ID）, `exclusions`（路径前缀 + 规则 ID）, `allow_cidrs`}，按请求经 ModSecurity 事务 ID 生效（PoC §5）。
- `security.challenge`、`security.firewall_action`：引用。
- `security.rules`（规则计划）：`header_overflow`（no_match/block）+ `policies[]`（≤2，kind 不重复：acl、waf）。每个 policy = {`kind`, `policy_id`, `policy_version`, `binding_revision`, `runtime_sha256`, `enabled`, `default_action`（allow/block）, `rules[]`}；rule = `edgeconfig.WAFRule`（`rule_id`, `comment`, `expires_at`, `match`, `action`, `flow`），必须已是 `NormalizeSecurityRule` 的规范形。

**解释语义（与 v7 内联 Lua 逐条等价，`edgeconfig.renderWAFBlock`）：**

1. 请求头超过 100 个：`block` → 先回 403；`no_match` → 记警告，头条件看不到任何头。
2. 各 policy 按顺序执行。每个 policy：`action = default_action`、`rule = "<policy_id>:default"`；若 `enabled`，按序检查规则，匹配且之前没有 `stop` 命中时 `action/rule` 取该规则；命中的规则 `flow = stop` 时停止扫描。即**停止前最后一个命中的规则生效**，不是第一个。
3. `block` → 403（安全事件：type = kind、action block、severity high、拦截页、rule_id = rule）；`log` → 记安全事件（action log、severity info）后继续；`allow` → 继续下一个 policy（allow 不跳过后面的 policy）。
4. match 各字段 AND：`expires_at` now < 该时刻；`host` = $host；`port` = 公网端口（proxy protocol 端口或 $server_port）；`method`；`path` exact/prefix（等于或以 value+"/" 开头）/raw_prefix；`header` exists / exact（只出现一次且值相等）；`source_cidr`；`ja4`（补丁 21 的变量等于其一）；`ip_intel`、`inspect` 按 edgeconfig 现有语义。

**按端口合并**：v7 每个监听编译一次，规则里的“端口”条件在编译时按监听解析（`compileSecurityRuleMatchesFor` 给每条规则写 `match.port = 监听端口`）。生成器比较各监听去掉端口后的规则：全相同 → 只写一份、`port = 0`（对所有端口）；不同 → 按端口顺序拼接，每条钉到自己监听的端口。只有请求端口的规则可能命中，所以每个端口“最后命中者生效”的结果不变（测试 `TestSiteObjectsV2SecurityFromProductionCompiler` 逐端口比对）。

## 5. 缓存身份（缓存代际，ge-cache 定义，v7 节点编译与动态路由共用）

- 命名空间（磁盘目录 `<state>/shared/cache/<ns>`、keys_zone 名）：v7 节点编译为 `edgeconfig.CacheSiteNamespaceID(tenant_id, site_id)` = SHA-256("cdnca-edge-cache-namespace-v2\0" ‖ tenant_id ‖ "\0" ‖ site_id)；站点生命周期内不变，不含发布版本号。
- `key_prefix` = SHA-256("cdnca-edge-cache-key-v2\0" ‖ tenant_id ‖ "\0" ‖ site_id) 前 16 字节十六进制：站点生命周期内不变。
- `generation`（缓存代际，ge-cache 定义）= `edgeconfig.CacheGeneration(domain, key_by_host, policy)` = SHA-256("cdnca-edge-cache-generation-v1\0" ‖ JSON{domain, key_by_host, schema_version, mode, rules, query_mode, query_names, vary_headers, slice_bytes}) 前 8 字节十六进制；`edgesite.CacheGeneration` 即此值。
  - **换代**：缓存域、按 host 分键、策略的模式/规则/query 投影/vary/分片大小变化（这些决定一个请求读哪个对象）。
  - **不换代**：策略 revision、磁盘软配额、stale/后台更新/锁/重新验证、对象大小上下限、无关站点改动、任何新发布（只改变对象怎么存/怎么回）。
- **清空全部缓存**不进 generation，站点对象无 flush_generation：是节点状态里的站点清空代际（共享字典 `cdnca_cache_purge`，agent 写），由 cachecontrol `purge_site` 任务下发到承载节点，立即生效、不发布；作为缓存键第三段。
- 节点缓存键：动态路由 `<key_prefix>|<generation>|<清空代际>|<host 或 domain>|<port>|<策略键>`；v7 节点编译 `v2|<tenant>|<site>|<generation>|<host 或 domain>|<port>|<策略键>`（第 4 段原为 config_version_id）。两者代际相同、键空间互不相通。
- `policy` 中 ge-cache 扩展字段（均可省略，省略 = 关/0；`mode=disabled` 时必须全部省略；校验 `edgeconfig.ValidateCachePolicyExtensions`）：
  | 字段 | 取值 | 语义（v7 与动态路由相同） |
  |---|---|---|
  | `stale_if_error` | bool | 源站出错/超时/5xx(500,502,503,504) 与更新中时回旧缓存（`proxy_cache_use_stale error timeout updating http_500..504`），并开 `proxy_cache_lock`（5s）与 `proxy_cache_revalidate`；pool inactive ≥ 24h |
  | `background_update` | bool | 需 `stale_if_error`；过期对象先回旧值、后台回源刷新（`proxy_cache_background_update`） |
  | `min_object_bytes` | 0..1TiB | 响应长度（Content-Length 或 Content-Range 总长）小于它不存，X-CDN-Cache-Reason `object_size` |
  | `max_object_bytes` | 0..1TiB，0=不限；与 min 同时给出时 min < max | 大于它不存，原因同上 |
  | `slice_bytes` | 0 或 256KiB..64MiB 且为 64KiB 倍数 | 非 0：分片缓存，每片一个对象（`slice` + `Range: $slice_range`），206 与 200 同 TTL；进 generation。动态路由的 `slice` 是配置期常量，按 256KiB/1/4/16/64MiB 五档变体执行（取不大于 slice_bytes 的最大一档，`edgecache.SliceVariantBytes`），只影响回源分片大小 |
- `policy.rules[]` 的 ge36 匹配条件（schema v1/v2 均可，可省略；需节点能力 `CACHE_RULE_MATCH` v1（能力号 52），不具备的节点拒绝发布并列出；规则在 `rules` 内，变化即换代）：
  | 字段 | 取值 | 语义 |
  |---|---|---|
  | `path_regex` | 1..256 字节；PCRE/RE2 公共子集（`edgeconfig.ValidateCachePathRegex`：拒绝嵌套无界量词、重复次数 >100、`\C` `\Q` `(?U)` `\z`、命名分组、控制字符） | 规范化 `$uri` 还须匹配它（与 `path_prefix`/`extensions` 同时满足）；节点 `lua_regex_match_limit` 100000，超限视为不匹配并记日志 |
  | `content_types` | 1..16 项，小写、升序去重；`type/subtype` 精确或以 `*` 结尾的前缀（`image/*`） | 响应头到达时判定（忽略参数）：不匹配的候选规则剔除后重新决策 TTL/浏览器过期；剔除后无缓存规则则不存，X-CDN-Cache-Reason `content_type` |
  - 每策略带条件的规则 ≤ 8 条（`MaxCacheConditionalRules`），节点计划按子集枚举候选集（≤ 2048 路由）；schema v1 中带条件的规则不参与"规则不得重叠"校验，首个匹配规则生效。
  - 聚合边缘（第三方 CDN）无对应能力：投影报告 `cache.rule_conditions` 无法映射（可在供给上显式忽略）。
- 锁与重新验证不单列字段：缓存的请求一律 `proxy_cache_lock on`（5s）与 `proxy_cache_revalidate on`（两端相同）。
- 清除/预热进度仍是节点状态，不进对象。

## 6. 节点索引与端口表

- 索引键 `edgesite.IndexKey(port, name)` = md5("<port>\0<name>")，16 字节；值 = 站点对象 32 字节摘要（128 B 共享字典槽，PoC §1）。`Site.IndexEntries()` 给出站点的全部（端口 × 名字），按端口再按名字排序。查到后用 `hosts` 复核，md5 碰撞不会串站。
- `edgesite.PortProfiles(sites)`：跨站检查——站点 ID 唯一、（端口, 名字）只属一个站、同端口所有站 TLS 一致且 HTTP/2 一致（ALPN 由端口唯一的共享 server 决定）；返回每端口 {TLS, HTTP2, HTTP3（任一站宣告 h3 即监听 QUIC）, IPv4/IPv6 并集, 站数}，即节点骨架需要的端口集合。

## 7. 摘要进根索引的形态（D2 实现）

- 根/桶沿用 v8 的形态与规则（`siteobject`：桶 = SHA-256(site_id) 前 4 字节 mod B，B 为 2 的幂、平均 ≤256 站/桶）。桶条目 `{site_id, revision, sha256}` 的 `sha256` 改为 **v2 站点对象**摘要。
- v2 根不再有 `document_sha256` / `bundle_manifest_sha256`（节点不再拼 bundle），改为指向节点级对象：端口表（`PortProfiles` 的结果）与 scope 级骨架输入（系统配置、四层 streams、托管 WAF 规则文本），这些仍由 scope 对象承载。根 schema 因此需要新名（建议 `cdnca.edge.site-root/v2`），由 D2 定稿。
- 被引用对象（CC 策略、HTTP 策略条目、防火墙动作、错误页资源）与站点对象同一对象库、同一加密方式；节点按站点对象里的摘要补拉，不在桶里列出。`buildSiteObjectsV2` 的 `Referenced` 即本 scope 的这组对象。

## 8. 与现有站点模型的字段覆盖

逐字段表在 `site_objects_v2_coverage_test.go`（`siteObjectV2Coverage`），测试保证 v8 站点模型（v2 文档站点条目、origin-route 文档、遥测条目、HTTP 策略条目）的每个字段都有去向，新增字段不登记就失败。汇总：

- 已表达：域名、监听/协议/证书版本、强制 HTTPS、WebSocket/Range、回源池/端点/算法/重试/keepalive、条件回源、L2 与 mTLS 身份、入口回源、缓存、ACL/WAF 规则、CC、托管 WAF、JS 挑战、防火墙动作、HTTP 策略、套餐连接数、上传上限、遥测。
- 固定由格式定义而丢弃：位置序号、监听 ID、重试的 bodyless_only/response_not_started/retry_on、L2 半开探测与跳数、发布路径、整份 http-policy 文件摘要。
- 不在 v8 模型里、由调用方作为事实传入：错误页（errorpagecontrol 生产快照）、回源鉴权绑定（originauthcontrol）。
- 缓存：`cache.policy` 逐字段登记（含 ge-cache 扩展 stale_if_error/background_update/min/max_object_bytes/slice_bytes），新增策略字段不登记即失败。
- 待补：证书私钥机密对象（动态证书）、回源 CA 集对象（回源 TLS）、回源鉴权凭据的按节点加密机密对象、`placement`（site_runtime 10）。
- SNI 与 Host 不一致：已定不回 421、按 Host 选站（D4 TLS 入口实现），对象格式无需字段。

## 9. 与 ADR 0009 的差异

| ADR 0009 原文 | 本格式 | 原因 |
|---|---|---|
| §8.3 schema 名 `cdnca.edge.site/v2` | `cdnca.edge.site/v2` | 命名一律 cdnca（10-18） |
| §8.3 字段名 `domains`/`secrets`/`placement` | `hosts`；机密只以 `Ref` 引用；`placement` 未加 | 机密不进站点对象；placement 属 site_runtime 10 |
| §8.2 索引键 `<端口>\0<小写域名>` → `{gen_a, gen_b}` | md5(`<端口>\0<名字>`) → 当前代 32 B 摘要 | PoC §1：128 B 槽，上一代由变更集小字典回滚 |
| §8.4 `security.mounts` | 已加（F1）：`security.mounts` + `security.resolved_sha256`，主控读 site_security_mounts；包本身经节点制品集下发（`rule_pack/<sha256>`，密封包带 key_wrap） | 节点 Apply 前 rulepackprecheck 复算摘要；WAF/ACL 引擎规则在站点策略之后执行，CC/ModSecurity 引擎的包规则未接 |
| §4 ACL/WAF 每监听编译 | 每站一份，按端口合并 | 共享 server 后监听不再是编译单位 |
| §4 缓存键前缀含发布身份 | 稳定前缀 + 缓存代际 | 避免每次发布换缓存键空间 |
| §4 CC 计数键（site_id, 端口） | 对象只给按端口的绑定；计数键由 D6 定 | 计数键是节点运行态 |

## 10. 实测（5000 站，本机 arm64，机器同时有其他任务）

`TestSiteObjectsV2FiveThousandSites`（`go test ./internal/edgepublish/ -run SiteObjectsV2FiveThousand -v`；富站点变体加 `CDNCA_SITE_OBJECTS_V2_RICH=1`，约 2 分钟，耗时主要在夹具的 v8 构建）。字节数确定、每次相同；耗时在 load 15–36 的 10 核机器上测得，只作量级参考。

| 变体 | v2 生成（5000 站） | 每站 | v2 站点对象合计 / 均值 / p50 / 最大 | v1 站点对象均值 | 被引用对象 |
|---|---|---|---|---|---|
| golden（20 站 HTTP 策略、防火墙动作、条件回源、遥测，1 scope） | 249 ms – 2.23 s（多数 270–550 ms） | 50–446 µs | 7,416,460 B / 1483 / 1442 / 1871 B | 2172 B | 1270 个，703,720 B |
| rich（生产编译器的双监听安全、缓存、上限、每 10 站 CC；5 scope × 1000） | 826 ms – 1.22 s | 165–244 µs | 16,678,500 B / 3335 / 3309 / 3576 B | 4876 B | 500 个，341,500 B |

结论：v2 站点对象比 v1 小约 32%（重内容改为引用、安全按端口合并）；生成成本远低于 v8 构建本身，5000 站在秒级以内，不构成发布瓶颈。
